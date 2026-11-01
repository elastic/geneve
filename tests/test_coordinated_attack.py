# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Starter tests for coordinated attacks and backpacks.

Members are taken from the mono_branch_* fixtures in test_emitter_queries
(not pre-built rules). The backpack goes down to the field solvers: only the
fields that a member binds and actually constrains are solved from it.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from faker import Faker
from ruamel.yaml import YAML

import tests.utils as tu
from geneve.constraints import ConflictError
from geneve.coordinated_attack import (
    AttackBackpack,
    AttackEmitter,
    CoordinatedAttack,
    Member,
    fill_backpack,
    load_story,
    parse_duration,
    schedule,
)
from geneve.events_emitter import SourceEvents
from geneve.utils import deep_merge, load_rules, random

# mono_branch / mono_doc members from tests/test_emitter_queries.py
REGSVR32 = """process where process.name == "regsvr32.exe" and host.id != null
"""
NETWORK_LOOPBACK = """network where destination.ip == "127.0.0.1" and host.id != null and user.id != null
"""
REGSVR32_UNDER_CMD = """process where process.name == "regsvr32.exe" and process.parent.name == "cmd.exe"
"""
NONZERO_PID = """process where process.pid != 0 and host.id != null
"""
# mono_branch / multi_doc (sequence): Geneve already joins its documents on user.id
CMD_SEQUENCE = """sequence by user.id
    [process where process.name : "cmd.exe"]
    [process where process.parent.name : "cmd.exe"]
"""
# the same workstation seen from itself (host.ip) and from the server it reaches (source.ip)
OUTBOUND = """network where host.ip != null and host.id != null
"""
INBOUND = """network where source.ip != null and host.id != null
"""

REGSVR_THEN_NETWORK = CoordinatedAttack(
    name="regsvr-then-network",
    roles={"ws": "host", "clerk": "user"},
    members=(
        Member(REGSVR32, {"host.id": "ws.id"}),
        Member(NETWORK_LOOPBACK, {"host.id": "ws.id", "user.id": "clerk.id"}),
    ),
)

CMD_FAMILY = CoordinatedAttack(
    name="cmd-family",
    roles={"ws": "host", "clerk": "user"},
    members=(
        Member(REGSVR32_UNDER_CMD),
        Member(NONZERO_PID, {"host.id": "ws.id"}),
        Member(CMD_SEQUENCE, {"user.id": "clerk.id"}),
    ),
)

TWO_HOSTS = CoordinatedAttack(
    name="two-hosts",
    roles={"ws": "host", "fs": "host"},
    members=(
        Member(OUTBOUND, {"host.id": "ws.id", "host.ip": "ws.ip"}),
        Member(INBOUND, {"host.id": "fs.id", "source.ip": "ws.ip"}),
    ),
)


def emit_docs(se, root, backpack=None):
    """Emit the documents of every branch of a root."""
    return [event.doc for branch in se.emit(root, complete=True, count=1, timestamp=False, backpack=backpack) for event in [*branch]]


def emit_attack(attack, backpack, schema=None):
    """Emit every member of a attack, one list of documents per member."""
    se = SourceEvents(schema)
    roots = [se.add_query(member.query, glue=member.bindings) for member in attack.members]
    return [emit_docs(se, root, backpack.view(member) if backpack else None) for member, root in zip(attack.members, roots)]


class TestCoordinatedAttack(unittest.TestCase):
    def test_bindings_are_validated(self):
        with self.assertRaisesRegex(ValueError, "unknown kind 'printer'"):
            CoordinatedAttack("bad", roles={"p": "printer"}, members=())
        with self.assertRaisesRegex(ValueError, "unknown role 'fs'"):
            CoordinatedAttack("bad", roles={"ws": "host"}, members=(Member(REGSVR32, {"host.id": "fs.id"}),))
        with self.assertRaisesRegex(ValueError, "host has no attribute 'pid'"):
            CoordinatedAttack("bad", roles={"ws": "host"}, members=(Member(REGSVR32, {"process.pid": "ws.pid"}),))

    def test_bindings_and_canonical_fields(self):
        self.assertEqual(TWO_HOSTS.bindings(), ["fs.id", "ws.id", "ws.ip"])
        self.assertEqual(TWO_HOSTS.canonical_field("ws.ip"), "host.ip")
        self.assertEqual(REGSVR_THEN_NETWORK.canonical_field("clerk.id"), "user.id")


class TestBackpack(tu.SeededTestCase, unittest.TestCase):
    def test_deterministic_across_emitters(self):
        """Same attack + seed + instance ⇒ same backpack, whatever the global random state."""
        a = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        random.seed("some other emitter")
        b = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        self.assertEqual(a, b)
        self.assertEqual(set(a.values), {"ws.id", "clerk.id"})

    def test_does_not_disturb_the_global_random_state(self):
        state = random.getstate()
        fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        self.assertEqual(random.getstate(), state)

    def test_coordination_seed_defaults_to_the_shared_generator(self):
        """Without a coordination seed the harness-controlled shared generator decides, and it is only read."""
        random.seed("harness")
        state = random.getstate()
        a = fill_backpack(REGSVR_THEN_NETWORK, instance_id="story-1")
        self.assertEqual(random.getstate(), state)  # not seeded, not advanced
        self.assertEqual(fill_backpack(REGSVR_THEN_NETWORK, instance_id="story-1"), a)  # reproducible

        random.seed("harness")  # same harness seed, same backpack
        self.assertEqual(fill_backpack(REGSVR_THEN_NETWORK, instance_id="story-1"), a)

        random.seed("another harness")  # other harness seed, other backpack
        self.assertNotEqual(fill_backpack(REGSVR_THEN_NETWORK, instance_id="story-1").values, a.values)

    def test_an_explicit_coordination_seed_wins_over_the_shared_generator(self):
        a = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        random.seed("something else")
        self.assertEqual(fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1"), a)

    def test_distinct_instances_get_distinct_backpacks(self):
        a = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        b = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-2")
        self.assertNotEqual(a.values, b.values)

    def test_values_follow_the_schema_of_the_canonical_field(self):
        schema = {"host.ip": {"type": "ip"}}
        a = fill_backpack(TWO_HOSTS, coordination_seed="lab", instance_id="story-1", schema=schema)
        b = fill_backpack(TWO_HOSTS, coordination_seed="lab", instance_id="story-1", schema=schema)
        self.assertEqual(a, b)
        self.assertIn(".", a.values["ws.ip"])  # an address, from the ip solver of host.ip
        self.assertIsInstance(a.values["ws.id"], str)
        self.assertNotEqual(a.values["ws.id"], a.values["fs.id"])  # two hosts, two identities

    def test_view_gives_each_member_its_own_fields(self):
        backpack = AttackBackpack("two-hosts", "story-1", {"ws.id": "W", "fs.id": "F", "ws.ip": "10.0.0.7"})
        outbound, inbound = TWO_HOSTS.members
        self.assertEqual(backpack.view(outbound), {"host.id": "W", "host.ip": "10.0.0.7"})
        self.assertEqual(backpack.view(inbound), {"host.id": "F", "source.ip": "10.0.0.7"})


# every role attribute there is, each bound by a member that constrains the field
EVERY_ATTRIBUTE = CoordinatedAttack(
    name="every-attribute",
    roles={"ws": "host", "clerk": "user", "c2": "ip"},
    members=(
        Member(
            "network where host.id != null and host.name != null and host.ip != null and user.id != null and user.name != null and source.ip != null",
            {
                "host.id": "ws.id",
                "host.name": "ws.name",
                "host.ip": "ws.ip",
                "user.id": "clerk.id",
                "user.name": "clerk.name",
                "source.ip": "c2.ip",
            },
        ),
    ),
)
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class TestRealisticValues(tu.SeededTestCase, unittest.TestCase):
    """Role attributes look like what they stand for, deterministically, and the solver still validates them."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.schema = tu.load_test_schema()

    def test_shapes(self):
        values = fill_backpack(EVERY_ATTRIBUTE, coordination_seed="lab", instance_id="story-1", schema=self.schema).values
        self.assertEqual(set(values), {"ws.id", "ws.name", "ws.ip", "clerk.id", "clerk.name", "c2.ip"})
        self.assertRegex(values["ws.id"], UUID4)
        self.assertRegex(values["ws.name"], r"^[a-z]+-\d+$")  # a bare hostname, no domain
        self.assertTrue(ipaddress.ip_address(values["ws.ip"]).is_private)  # a host of the organization
        self.assertRegex(values["clerk.id"], r"^\d{4,5}$")
        self.assertRegex(values["clerk.name"], r"^[a-z][a-z0-9._]*$")
        c2 = ipaddress.ip_address(values["c2.ip"])  # out on the internet
        self.assertTrue(c2.is_global, c2)
        self.assertFalse(c2.is_private, c2)
        for value in values.values():
            self.assertIsInstance(value, str)  # scalars, `host.ip` included

    def test_deterministic_whatever_the_global_state(self):
        a = fill_backpack(EVERY_ATTRIBUTE, coordination_seed="lab", instance_id="story-1", schema=self.schema)
        random.seed("perturbed")
        random.random()
        Faker().name()  # the global faker generator is consumed too
        b = fill_backpack(EVERY_ATTRIBUTE, coordination_seed="lab", instance_id="story-1", schema=self.schema)
        self.assertEqual(a, b)

    def test_does_not_disturb_the_global_state(self):
        state = random.getstate()
        fill_backpack(EVERY_ATTRIBUTE, coordination_seed="lab", instance_id="story-1", schema=self.schema)
        self.assertEqual(random.getstate(), state)

    def test_instances_and_roles_get_different_values(self):
        a = fill_backpack(EVERY_ATTRIBUTE, coordination_seed="lab", instance_id="story-1", schema=self.schema).values
        b = fill_backpack(EVERY_ATTRIBUTE, coordination_seed="lab", instance_id="story-2", schema=self.schema).values
        for binding in a:
            self.assertNotEqual(a[binding], b[binding], binding)
        c = fill_backpack(EVERY_ATTRIBUTE, coordination_seed="other lab", instance_id="story-1", schema=self.schema).values
        for binding in a:
            self.assertNotEqual(a[binding], c[binding], binding)
        two_hosts = fill_backpack(TWO_HOSTS, coordination_seed="lab", instance_id="story-1", schema=self.schema).values
        self.assertNotEqual(two_hosts["ws.id"], two_hosts["fs.id"])

    def test_values_go_through_the_solver(self):
        """The realistic value is pinned into the canonical field's solver, which emits it as is."""
        backpack = fill_backpack(EVERY_ATTRIBUTE, coordination_seed="lab", instance_id="story-1", schema=self.schema)
        ((doc,),) = emit_attack(EVERY_ATTRIBUTE, backpack, self.schema)
        self.assertEqual(doc["host"]["id"], backpack.values["ws.id"])
        self.assertEqual(doc["host"]["name"], backpack.values["ws.name"])
        self.assertEqual(doc["host"]["ip"], [backpack.values["ws.ip"]])  # array field in ECS
        self.assertEqual(doc["user"]["id"], backpack.values["clerk.id"])
        self.assertEqual(doc["user"]["name"], backpack.values["clerk.name"])
        self.assertEqual(doc["source"]["ip"], backpack.values["c2.ip"])
        # without a schema the fields are plain keywords: same realistic values, still validated
        self.assertEqual(fill_backpack(EVERY_ATTRIBUTE, coordination_seed="lab", instance_id="story-1").values, backpack.values)


class TestBackpackInSolvers(tu.SeededTestCase, unittest.TestCase):
    def test_members_share_the_backpack_entities(self):
        backpack = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        regsvr, network = emit_attack(REGSVR_THEN_NETWORK, backpack)
        self.assertEqual(len(regsvr), 1)
        self.assertEqual(len(network), 1)
        self.assertEqual(regsvr[0]["host"]["id"], backpack.values["ws.id"])
        self.assertEqual(network[0]["host"]["id"], backpack.values["ws.id"])
        self.assertEqual(network[0]["user"]["id"], backpack.values["clerk.id"])
        # what the members constrain themselves still comes from their queries
        self.assertEqual(regsvr[0]["process"]["name"], "regsvr32.exe")
        self.assertEqual(network[0]["destination"]["ip"], "127.0.0.1")

    def test_one_role_seen_through_different_fields(self):
        """The workstation is host.ip in its own events and source.ip in the server's: same address."""
        schema = {"host.ip": {"type": "ip"}, "source.ip": {"type": "ip"}}
        backpack = fill_backpack(TWO_HOSTS, coordination_seed="lab", instance_id="story-1", schema=schema)
        (outbound,), (inbound,) = emit_attack(TWO_HOSTS, backpack, schema)
        self.assertEqual(outbound["host"]["ip"], backpack.values["ws.ip"])
        self.assertEqual(inbound["source"]["ip"], backpack.values["ws.ip"])
        self.assertEqual(outbound["host"]["id"], backpack.values["ws.id"])
        self.assertEqual(inbound["host"]["id"], backpack.values["fs.id"])
        self.assertNotEqual(outbound["host"]["id"], inbound["host"]["id"])

    def test_only_bound_fields_are_taken(self):
        """REGSVR32 binds host.id only: it does not get a user.id from the backpack."""
        backpack = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        regsvr, _ = emit_attack(REGSVR_THEN_NETWORK, backpack)
        self.assertNotIn("user", regsvr[0])
        (cmd,), *_ = emit_attack(CMD_FAMILY, fill_backpack(CMD_FAMILY, coordination_seed="lab", instance_id="story-2"))
        self.assertNotIn("host", cmd)  # REGSVR32_UNDER_CMD has no bindings at all
        self.assertNotIn("user", cmd)

    def test_bound_fields_are_glued_to_members_that_do_not_mention_them(self):
        """REGSVR32_UNDER_CMD says nothing about host.id or user.id, binding them makes it carry them."""
        attack = CoordinatedAttack(
            "glued",
            roles={"ws": "host", "clerk": "user"},
            members=(Member(REGSVR32_UNDER_CMD, {"host.id": "ws.id", "user.id": "clerk.id"}),),
        )
        backpack = fill_backpack(attack, coordination_seed="lab", instance_id="story-1")
        ((cmd,),) = emit_attack(attack, backpack)
        self.assertEqual(cmd["host"]["id"], backpack.values["ws.id"])
        self.assertEqual(cmd["user"]["id"], backpack.values["clerk.id"])
        self.assertEqual(cmd["process"]["parent"]["name"], "cmd.exe")  # the query itself is untouched
        # glue is part of the IR: without a backpack the field is still there, with a value of its own
        ((free,),) = emit_attack(attack, None)
        self.assertIn("id", free["host"])
        self.assertNotEqual(free["host"]["id"], backpack.values["ws.id"])

    def test_glue_reaches_every_event_of_a_sequence(self):
        """`sequence by user.id` bound to a host too: both events carry the host, and still join on the user."""
        attack = CoordinatedAttack(
            "glued-sequence",
            roles={"ws": "host", "clerk": "user"},
            members=(Member(CMD_SEQUENCE, {"host.id": "ws.id", "user.id": "clerk.id"}),),
        )
        backpack = fill_backpack(attack, coordination_seed="lab", instance_id="story-1")
        (seq,) = emit_attack(attack, backpack)
        self.assertEqual(len(seq), 2)
        self.assertEqual({doc["host"]["id"] for doc in seq}, {backpack.values["ws.id"]})
        self.assertEqual({doc["user"]["id"] for doc in seq}, {backpack.values["clerk.id"]})

    def test_glue_on_a_field_the_query_wants_null_is_a_conflict(self):
        attack = CoordinatedAttack(
            "null-user",
            roles={"clerk": "user"},
            members=(Member('process where process.name == "regsvr32.exe" and user.id == null', {"user.id": "clerk.id"}),),
        )
        with self.assertRaises(ConflictError):
            emit_attack(attack, fill_backpack(attack, coordination_seed="lab", instance_id="story-1"))

    def test_glue_leaves_constrained_fields_alone(self):
        """Gluing host.id on REGSVR32, which already has `host.id != null`, changes nothing."""
        se = SourceEvents()
        plain = se.add_query(REGSVR32)
        glued = se.add_query(REGSVR32, glue=["host.id"])
        self.assertEqual([list(branch) for branch in plain], [list(branch) for branch in glued])

    def test_without_a_backpack_nothing_changes(self):
        backpack = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        free, _ = emit_attack(REGSVR_THEN_NETWORK, None)
        self.assertNotEqual(free[0]["host"]["id"], backpack.values["ws.id"])

    def test_sequence_join_value_comes_from_the_backpack(self):
        """`sequence by user.id` joins on a value that the backpack pre-assigns, so the join survives."""
        backpack = fill_backpack(CMD_FAMILY, coordination_seed="lab", instance_id="story-9")
        *_, seq = emit_attack(CMD_FAMILY, backpack)
        self.assertEqual(len(seq), 2)
        self.assertEqual(seq[0]["user"]["id"], backpack.values["clerk.id"])
        self.assertEqual(seq[1]["user"]["id"], backpack.values["clerk.id"])
        # without the backpack the sequence still joins, on a value of its own
        *_, free = emit_attack(CMD_FAMILY, None)
        self.assertEqual(free[0]["user"]["id"], free[1]["user"]["id"])
        self.assertNotEqual(free[0]["user"]["id"], backpack.values["clerk.id"])

    def test_one_emitter_serves_multiple_backpacks(self):
        """One SourceEvents, two stories in flight, the IR is prepared once."""
        se = SourceEvents()
        roots = [se.add_query(member.query) for member in REGSVR_THEN_NETWORK.members]
        story_1 = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        story_2 = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-2")
        for backpack in (story_1, story_2, story_1):
            for member, root in zip(REGSVR_THEN_NETWORK.members, roots):
                for doc in emit_docs(se, root, backpack.view(member)):
                    self.assertEqual(doc["host"]["id"], backpack.values["ws.id"])

    def test_backpack_value_must_satisfy_the_constraints(self):
        """A pre-assigned value that contradicts the member constraints is reported, not silently emitted."""
        attack = CoordinatedAttack("conflict", roles={"clerk": "user"}, members=(Member(REGSVR32, {"process.name": "clerk.name"}),))
        backpack = fill_backpack(attack, coordination_seed="lab", instance_id="story-1")
        self.assertNotEqual(backpack.values["clerk.name"], "regsvr32.exe")
        with self.assertRaises(ConflictError):
            emit_attack(attack, backpack)


class TestIndependentEmitters(tu.SeededTestCase, unittest.TestCase):
    """Two emitters that never talk to each other build the documents of the same attack.

    All they share is the coordinated attack, the coordination seed and the instance id.
    """

    def emitter(self, name, attack, member, instance_id, noise=0):
        """Play one emitter: own random state, own SourceEvents, own backpack, one member of the attack."""
        random.seed(f"emitter {name}")  # an unrelated random state per emitter
        se = SourceEvents()
        roots = [se.add_query(m.query) for m in attack.members]
        for _ in range(noise):  # unrelated traffic that this emitter emitted before
            for root in roots:
                emit_docs(se, root)
        backpack = fill_backpack(attack, coordination_seed="lab", instance_id=instance_id)
        return backpack, emit_docs(se, roots[member], backpack.view(attack.members[member]))

    def test_emitters_agree_on_the_attack_entities(self):
        backpack_a, (doc_a,) = self.emitter("A", REGSVR_THEN_NETWORK, member=0, instance_id="story-1")
        backpack_b, (doc_b,) = self.emitter("B", REGSVR_THEN_NETWORK, member=1, instance_id="story-1", noise=5)

        # each emitter computed its own backpack, they came out the same
        self.assertEqual(backpack_a, backpack_b)
        # the documents come from different emitters and are related through the shared entity
        self.assertEqual(doc_a["process"]["name"], "regsvr32.exe")
        self.assertEqual(doc_b["destination"]["ip"], "127.0.0.1")
        self.assertEqual(doc_a["host"]["id"], doc_b["host"]["id"])
        self.assertEqual(doc_a["host"]["id"], backpack_a.values["ws.id"])

    def test_emitters_sharing_the_harness_seed_agree_without_a_coordination_seed(self):
        """Two emitters that started from the same harness seed need no coordination seed to agree."""

        def emitter(index):
            random.seed("harness")
            se = SourceEvents()
            roots = [se.add_query(m.query) for m in REGSVR_THEN_NETWORK.members]
            backpack = fill_backpack(REGSVR_THEN_NETWORK, instance_id="story-1")
            (doc,) = emit_docs(se, roots[index], backpack.view(REGSVR_THEN_NETWORK.members[index]))
            return backpack, doc

        backpack_a, doc_a = emitter(0)
        backpack_b, doc_b = emitter(1)
        self.assertEqual(backpack_a, backpack_b)
        self.assertEqual(doc_a["host"]["id"], doc_b["host"]["id"])

    def test_emitters_serving_different_attacks_do_not_mix(self):
        _, (doc_a,) = self.emitter("A", REGSVR_THEN_NETWORK, member=0, instance_id="story-1")
        _, (doc_b,) = self.emitter("B", REGSVR_THEN_NETWORK, member=1, instance_id="story-2")
        self.assertNotEqual(doc_a["host"]["id"], doc_b["host"]["id"])

    def test_emitters_agree_on_the_sequence_join_value(self):
        """The events of a sequence are emitted by an emitter, the other members by another one."""
        backpack_a, seq = self.emitter("A", CMD_FAMILY, member=2, instance_id="story-3")
        backpack_b, (nonzero_pid,) = self.emitter("B", CMD_FAMILY, member=1, instance_id="story-3", noise=3)
        self.assertEqual(backpack_a, backpack_b)
        self.assertEqual(len(seq), 2)
        self.assertEqual({doc["user"]["id"] for doc in seq}, {backpack_b.values["clerk.id"]})
        self.assertEqual(nonzero_pid["host"]["id"], backpack_a.values["ws.id"])

    def test_emitters_in_threads_do_not_disturb_each_other(self):
        """Backpacks come from private generators, whatever happens to the shared one meanwhile."""
        expected = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        state = random.getstate()
        stop = threading.Event()
        found = []

        def noise():  # users of the shared generator: they seed it and draw from it all the time
            n = 0
            while not stop.is_set():
                random.seed(n)
                random.random()
                n += 1

        def emitter():
            for _ in range(300):
                found.append(fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1"))

        noisy = [threading.Thread(target=noise) for _ in range(2)]
        emitters = [threading.Thread(target=emitter) for _ in range(4)]
        for thread in noisy + emitters:
            thread.start()
        for thread in emitters:
            thread.join()
        stop.set()
        for thread in noisy:
            thread.join()

        self.assertEqual(len(found), 4 * 300)
        self.assertEqual([backpack for backpack in found if backpack != expected], [])
        random.setstate(state)

    def test_emitters_in_separate_processes_agree(self):
        """Nothing leaks from the interpreter: separate processes, different hash seeds, same backpack."""
        script = (
            "import json;"
            "from tests.test_coordinated_attack import REGSVR_THEN_NETWORK as g;"
            "from geneve.coordinated_attack import fill_backpack;"
            "print(json.dumps(fill_backpack(g, coordination_seed='lab', instance_id='story-1').values, sort_keys=True))"
        )
        outputs = {
            subprocess.run(
                [sys.executable, "-c", script],
                env={**os.environ, "PYTHONHASHSEED": hash_seed},
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            for hash_seed in ("1", "2", "random")
        }
        self.assertEqual(len(outputs), 1)
        in_process = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1").values
        self.assertEqual(json.loads(outputs.pop()), in_process)


# a story with a timeline: download on the workstation, then two things on the file server
TIMED = CoordinatedAttack(
    name="timed",
    roles={"ws": "host", "fs": "host", "clerk": "user"},
    members=(
        Member(REGSVR32, {"host.id": "ws.id", "user.id": "clerk.id"}, name="regsvr"),
        Member(NETWORK_LOOPBACK, {"host.id": "ws.id", "user.id": "clerk.id"}, name="network", after="regsvr", within=timedelta(minutes=2)),
        Member(CMD_SEQUENCE, {"host.id": "fs.id", "user.id": "clerk.id"}, name="cmd", after="network", within=timedelta(minutes=30)),
        Member(NONZERO_PID, {"host.id": "fs.id"}, name="pid", after="cmd", within=timedelta(minutes=10)),
    ),
)
START = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)


class TestSchedule(tu.SeededTestCase, unittest.TestCase):
    def test_members_are_validated(self):
        with self.assertRaisesRegex(ValueError, "go together"):
            Member(REGSVR32, name="a", after="b")
        with self.assertRaisesRegex(ValueError, "must be positive"):
            Member(REGSVR32, name="a", after="b", within=timedelta(0))
        with self.assertRaisesRegex(ValueError, "earlier member"):
            CoordinatedAttack(
                "bad", roles={}, members=(Member(REGSVR32, name="a", after="b", within=timedelta(1)), Member(NONZERO_PID, name="b"))
            )
        with self.assertRaisesRegex(ValueError, "duplicate name"):
            CoordinatedAttack("bad", roles={}, members=(Member(REGSVR32, name="a"), Member(NONZERO_PID, name="a")))

    def test_offsets_respect_the_windows(self):
        offsets = schedule(TIMED, coordination_seed="lab", instance_id="story-1")
        self.assertEqual(offsets["regsvr"], timedelta(0))
        self.assertLess(offsets["regsvr"], offsets["network"])
        self.assertLessEqual(offsets["network"], timedelta(minutes=2))
        self.assertLess(offsets["network"], offsets["cmd"])
        self.assertLessEqual(offsets["cmd"] - offsets["network"], timedelta(minutes=30))
        self.assertLess(offsets["cmd"], offsets["pid"])
        self.assertLessEqual(offsets["pid"] - offsets["cmd"], timedelta(minutes=10))

    def test_deterministic_and_private(self):
        a = schedule(TIMED, coordination_seed="lab", instance_id="story-1")
        state = random.getstate()
        random.seed("elsewhere")
        b = schedule(TIMED, coordination_seed="lab", instance_id="story-1")
        self.assertEqual(a, b)
        random.setstate(state)
        self.assertNotEqual(a, schedule(TIMED, coordination_seed="lab", instance_id="story-2"))


class TestAttackEmitter(tu.SeededTestCase, unittest.TestCase):
    def test_one_instance_end_to_end(self):
        events, ledger = AttackEmitter(TIMED).emit(instance_id="story-1", start=START, coordination_seed="lab")
        backpack = fill_backpack(TIMED, coordination_seed="lab", instance_id="story-1")
        offsets = schedule(TIMED, coordination_seed="lab", instance_id="story-1")

        # one entry per member, in story order, with the timeline and the document counts
        self.assertEqual([e.member for e in ledger.members], ["regsvr", "network", "cmd", "pid"])
        self.assertEqual([e.timestamp for e in ledger.members], [START + offsets[m.name] for m in TIMED.members])
        self.assertEqual([e.documents for e in ledger.members], [1, 1, 2, 1])
        self.assertEqual(ledger.expected_alerts, 4)
        self.assertEqual(len(events), 5)

        # the documents carry the roles and the timestamps of the ledger
        docs = [event.doc for event in events]
        self.assertEqual([d["host"]["id"] for d in docs], [backpack.values[r] for r in ("ws.id", "ws.id", "fs.id", "fs.id", "fs.id")])
        self.assertEqual({d["user"]["id"] for d in docs[:4]}, {backpack.values["clerk.id"]})
        self.assertEqual(docs[0]["@timestamp"], ledger.members[0].timestamp.isoformat(timespec="milliseconds"))
        self.assertEqual(docs[2]["@timestamp"], ledger.members[2].timestamp.isoformat(timespec="milliseconds"))
        self.assertLess(docs[2]["@timestamp"], docs[3]["@timestamp"])  # the two events of the sequence are 1ms apart
        self.assertEqual(docs[4]["@timestamp"], ledger.members[3].timestamp.isoformat(timespec="milliseconds"))

    def test_emitters_playing_different_members_tell_one_story(self):
        """The workstation and the file server are emitted by different emitters: same roles, same timeline."""

        def emitter(name, members):
            random.seed(f"emitter {name}")
            return AttackEmitter(TIMED).emit(instance_id="story-1", start=START, coordination_seed="lab", members=members)

        events_a, ledger_a = emitter("A", {"regsvr", "network"})
        events_b, ledger_b = emitter("B", {"cmd", "pid"})
        whole, ledger = emitter("C", None)

        self.assertEqual([e.member for e in ledger_a.members], ["regsvr", "network"])
        self.assertEqual([e.member for e in ledger_b.members], ["cmd", "pid"])
        self.assertEqual(ledger_a.members + ledger_b.members, ledger.members)  # the union is the whole ground truth
        self.assertEqual(ledger_a.expected_alerts + ledger_b.expected_alerts, ledger.expected_alerts)
        self.assertEqual({e.doc["user"]["id"] for e in events_a}, {e.doc["user"]["id"] for e in events_b if "user" in e.doc})
        self.assertEqual([e.doc["@timestamp"] for e in events_a + events_b], [e.doc["@timestamp"] for e in whole])

    def test_instances_do_not_share_roles_or_timeline(self):
        emitter = AttackEmitter(TIMED)
        _, ledger_1 = emitter.emit(instance_id="story-1", start=START, coordination_seed="lab")
        _, ledger_2 = emitter.emit(instance_id="story-2", start=START, coordination_seed="lab")
        self.assertNotEqual([e.timestamp for e in ledger_1.members][1:], [e.timestamp for e in ledger_2.members][1:])


def get_field(doc, field):
    for part in field.split("."):
        doc = doc[part]
    return doc


FAKE_RULES = [
    SimpleNamespace(rule_id="r1", name="Regsvr", type="eql", language="eql", query=REGSVR32),
    SimpleNamespace(rule_id="r2", name="Loopback", type="eql", language="eql", query=NETWORK_LOOPBACK),
    SimpleNamespace(rule_id="r3", name="Cmd sequence", type="eql", language="eql", query=CMD_SEQUENCE),
    SimpleNamespace(rule_id="r4", name="Twin", type="eql", language="eql", query=NONZERO_PID),
    SimpleNamespace(rule_id="r5", name="Twin", type="eql", language="eql", query=NONZERO_PID),
]
STORY = {
    "id": "fake-story",
    "roles": {"ws": {"kind": "host"}, "fs": {"kind": "host"}, "clerk": {"kind": "user"}},
    "members": [
        {"rule": "Regsvr", "bindings": {"host.id": "ws.id", "user.id": "clerk.id"}},
        {"rule": "Loopback", "optional": True, "bindings": {"host.id": "ws.id"}, "after": {"member": "Regsvr", "within": "2m"}},
        {"rule": "Cmd sequence", "bindings": {"host.id": "fs.id", "user.id": "clerk.id"}, "after": {"member": "Regsvr", "within": "1h"}},
    ],
}


class TestLoadStory(unittest.TestCase):
    def test_durations(self):
        self.assertEqual(parse_duration("30s"), timedelta(seconds=30))
        self.assertEqual(parse_duration("2m"), timedelta(minutes=2))
        self.assertEqual(parse_duration("1h"), timedelta(hours=1))
        self.assertEqual(parse_duration("3d"), timedelta(days=3))
        for bad in ("", "2", "m", "2 weeks", "1.5h"):
            with self.assertRaisesRegex(ValueError, "invalid duration"):
                parse_duration(bad)

    def test_required_members(self):
        attack = load_story(STORY, FAKE_RULES)
        self.assertEqual(attack.name, "fake-story")
        self.assertEqual(attack.roles, {"ws": "host", "fs": "host", "clerk": "user"})
        self.assertEqual([m.name for m in attack.members], ["Regsvr", "Cmd sequence"])
        self.assertEqual([m.rule_id for m in attack.members], ["r1", "r3"])
        self.assertEqual([m.language for m in attack.members], ["eql", "eql"])
        self.assertEqual(attack.members[1].after, "Regsvr")
        self.assertEqual(attack.members[1].within, timedelta(hours=1))
        self.assertEqual(attack.bindings(), ["clerk.id", "fs.id", "ws.id"])

    def test_optional_members(self):
        attack = load_story(STORY, FAKE_RULES, optional=True)
        self.assertEqual([m.name for m in attack.members], ["Regsvr", "Loopback", "Cmd sequence"])

    def test_unknown_or_ambiguous_rule(self):
        story = dict(STORY, members=[{"rule": "Nope"}])
        with self.assertRaisesRegex(ValueError, "0 rules named 'Nope'"):
            load_story(story, FAKE_RULES)
        story = dict(STORY, members=[{"rule": "Twin"}])
        with self.assertRaisesRegex(ValueError, "2 rules named 'Twin'"):
            load_story(story, FAKE_RULES)

    def test_loaded_story_emits(self):
        _, ledger = AttackEmitter(load_story(STORY, FAKE_RULES)).emit(instance_id="i", start=START, coordination_seed="lab")
        self.assertEqual([(e.member, e.rule_id, e.documents) for e in ledger.members], [("Regsvr", "r1", 1), ("Cmd sequence", "r3", 2)])


class TestStoryDrafts(tu.SeededTestCase, unittest.TestCase):
    """The story drafts of a rules version compile and emit with the actual pre-built rules."""

    rules_version = "9.5.9"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.base = Path(tu.root_dir) / "etc" / "coordinated_attacks" / cls.rules_version
        _, cls.rules = load_rules(tu.get_rules_package_uri(cls.rules_version), basedir=tu.root_dir)
        cls.schema = tu.load_test_schema()

    def stories(self):
        for path in sorted(self.base.glob("stories/*.yaml")):
            with open(path) as f:
                yield YAML(typ="safe").load(f)

    def test_drafts_emit_their_stories(self):
        count = 0
        for story in self.stories():
            count += 1
            with self.subTest(story=story["id"]):
                attack = load_story(story, self.rules)
                offsets = schedule(attack, coordination_seed="lab", instance_id="i")
                events, ledger = AttackEmitter(attack, schema=self.schema).emit(instance_id="i", start=START, coordination_seed="lab")
                backpack = fill_backpack(attack, coordination_seed="lab", instance_id="i", schema=self.schema)

                # ground truth: one alert per required member, as the draft expects, in story order
                self.assertEqual(ledger.expected_alerts, story["expected_alerts"])
                self.assertEqual([e.member for e in ledger.members], [m["rule"] for m in story["members"] if not m.get("optional")])
                self.assertEqual([e.timestamp for e in ledger.members], [START + offsets[m.name] for m in attack.members])
                self.assertTrue(all(e.documents >= 1 for e in ledger.members))

                # every document carries the roles its member binds, with the values of the backpack
                docs = iter(events)
                for member, entry in zip(attack.members, ledger.members):
                    for _ in range(entry.documents):
                        doc = next(docs).doc
                        for fld, binding in member.bindings.items():
                            self.assertEqual(get_field(doc, fld), backpack.values[binding], f"{member.name}: {fld}")
                        self.assertGreaterEqual(doc["@timestamp"], entry.timestamp.isoformat(timespec="milliseconds"))
        self.assertEqual(count, 7)

    def test_array_field_role_attribute(self):
        """`host.ip` is an array in ECS: the role attribute is a scalar, it pins array and scalar fields alike."""
        query = "network where host.ip != null and source.ip != null"
        attack = CoordinatedAttack(
            "t", roles={"ws": "host"}, members=(Member(query, {"host.ip": "ws.ip", "source.ip": "ws.ip"}, name="m"),)
        )
        backpack = fill_backpack(attack, coordination_seed="lab", instance_id="i", schema=self.schema)
        self.assertIsInstance(backpack.values["ws.ip"], str)
        events, _ = AttackEmitter(attack, schema=self.schema).emit(instance_id="i", start=START, coordination_seed="lab")
        self.assertEqual(events[0].doc["host"]["ip"], [backpack.values["ws.ip"]])
        self.assertEqual(events[0].doc["source"]["ip"], backpack.values["ws.ip"])

    def test_two_emitters_agree_on_the_drafts(self):
        for story in self.stories():
            with self.subTest(story=story["id"]):
                attack = load_story(story, self.rules)
                random.seed("one")
                _, ledger_a = AttackEmitter(attack, schema=self.schema).emit(instance_id="i", start=START, coordination_seed="lab")
                random.seed("two")
                _, ledger_b = AttackEmitter(attack, schema=self.schema).emit(instance_id="i", start=START, coordination_seed="lab")
                self.assertEqual(ledger_a, ledger_b)


@unittest.skipIf(os.getenv("TEST_SIGNALS_ATTACKS", "0").lower() in ("0", "false", "no", ""), "Slow online test")
class TestOnlineStoryDrafts(tu.OnlineTestCase, tu.SeededTestCase, unittest.TestCase):
    """Instances of the story drafts, indexed into a stack, trigger exactly the alerts of their ledgers.

    Opt in with TEST_SIGNALS_ATTACKS=1; the stack comes from TEST_ELASTICSEARCH_URL,
    TEST_KIBANA_URL and the credentials, see `tests.utils.OnlineTestCase`.
    """

    rules_version = "9.5.9"
    index_template = "geneve-ut-ca"
    instances = ("story-1", "story-2")

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.base = Path(tu.root_dir) / "etc" / "coordinated_attacks" / cls.rules_version
        _, cls.rules = load_rules(tu.get_rules_package_uri(cls.rules_version), basedir=tu.root_dir)
        cls.rules_by_id = {rule.rule_id: rule for rule in cls.rules}
        cls.schema = tu.load_test_schema()

    def stories(self):
        for path in sorted(self.base.glob("stories/*.yaml")):
            with open(path) as f:
                yield YAML(typ="safe").load(f)

    def kibana_rule(self, story, member, index, lookback):
        rule = self.rules_by_id[member.rule_id]
        return {
            "rule_id": member.rule_id,
            "name": f"Geneve: {member.name}",
            "description": story["id"],
            "risk_score": rule.risk_score,
            "severity": rule.severity,
            "type": rule.type,
            "query": member.query,
            "language": member.language,
            "index": [index],
            "interval": "60s",
            "from": lookback,
            "max_signals": 1000,
            "version": rule.version,
            "tags": ["Geneve", "coordinated attack"],
            "enabled": True,
        }

    def load(self, mappings, operations, kibana_rules):
        for index in self.es.indices.get(index=f"{self.index_template}-*", ignore_unavailable=True):
            self.es.indices.delete(index=index)
        self.es.cluster.put_component_template(name=self.index_template, template={"mappings": mappings})
        kwargs = {"name": self.index_template, "index_patterns": [f"{self.index_template}-*"], "composed_of": [self.index_template]}
        if not self.serverless:
            kwargs["template"] = {"settings": {"number_of_shards": 1, "number_of_replicas": 0}}
        self.es.indices.put_index_template(**kwargs)
        ret = self.es.options(request_timeout=60).bulk(operations="\n".join(operations), refresh=True)
        self.assertFalse(ret["errors"], [item for item in ret["items"] if item["create"]["status"] != 201])
        self.kb.create_detection_engine_rules(kibana_rules)

    def wait_for_alerts(self, expected, timeout=300, sleep=5):
        """Alerts of the detection rules, building blocks (the events of a sequence) excluded."""
        body = {"size": 10000, "query": {"bool": {"must_not": [{"exists": {"field": "kibana.alert.building_block_type"}}]}}}
        deadline = time.time() + timeout
        while True:
            alerts = [hit["_source"] for hit in self.kb.search_detection_engine_signals(body)["hits"]["hits"]]
            if len(alerts) >= expected or time.time() > deadline:
                return alerts
            time.sleep(sleep)

    def test_alerts_match_the_ledgers(self):
        attacks = {story["id"]: (story, load_story(story, self.rules)) for story in self.stories()}
        # every document must be in the past, inside the lookback of the rules: the stories start early enough
        # for the longest timeline to end an hour ago, and the rules look back to an hour before that start
        span = max(
            max(schedule(attack, coordination_seed="online", instance_id=instance_id).values())
            for _, attack in attacks.values()
            for instance_id in self.instances
        )
        start = datetime.now(timezone.utc) - timedelta(hours=1) - span
        lookback = f"now-{int((span + timedelta(hours=2)).total_seconds())}s"
        kibana_rules, operations, mappings, instances = [], [], {}, {}
        for story, attack in attacks.values():
            emitter = AttackEmitter(attack, schema=self.schema)
            emitter.source_events.stack_version = self.get_version()
            deep_merge(mappings, emitter.source_events.mappings())
            indices = {m.name: f"{self.index_template}-{story['id']}-{i:02d}" for i, m in enumerate(attack.members)}
            kibana_rules.extend(self.kibana_rule(story, m, indices[m.name], lookback) for m in attack.members)
            for instance_id in self.instances:
                events, ledger = emitter.emit(instance_id=instance_id, start=start, coordination_seed="online")
                backpack = fill_backpack(attack, coordination_seed="online", instance_id=instance_id, schema=self.schema)
                instances[story["id"], instance_id] = (attack, backpack, ledger)
                docs = iter(event.doc for event in events)
                for entry in ledger.members:
                    for _ in range(entry.documents):
                        operations.append(json.dumps({"create": {"_index": indices[entry.member]}}))
                        operations.append(json.dumps(next(docs)))

        self.load(mappings, operations, kibana_rules)
        expected = sum(ledger.expected_alerts for _, _, ledger in instances.values())
        alerts = self.wait_for_alerts(expected)
        self.assertEqual(len(alerts), expected)

        def plays(alert, member, backpack):
            """Is the alert about this member of this instance? Rule and role values tell."""
            if alert["kibana.alert.rule.rule_id"] != member.rule_id:
                return False
            for fld, binding in member.bindings.items():
                try:
                    value = get_field(alert, fld)
                except KeyError:
                    return False
                if value not in (backpack.values[binding], [backpack.values[binding]]):
                    return False
            return True

        # every alert belongs to one member of one instance, every member of every instance gets one alert
        seen = {key: [] for key in instances}
        for alert in alerts:
            matches = [
                (key, m.name) for key, (attack, backpack, _) in instances.items() for m in attack.members if plays(alert, m, backpack)
            ]
            self.assertEqual(len(matches), 1, f"alert of rule {alert['kibana.alert.rule.rule_id']} matches {matches}")
            seen[matches[0][0]].append(matches[0][1])
        for key, (_, _, ledger) in instances.items():
            self.assertEqual(sorted(seen[key]), sorted(entry.member for entry in ledger.members), key)


if __name__ == "__main__":
    unittest.main()
