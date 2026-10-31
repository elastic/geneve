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

import json
import os
import subprocess
import sys
import threading
import unittest

import tests.utils as tu
from geneve.constraints import ConflictError
from geneve.coordinated_attack import (
    AttackBackpack,
    CoordinatedAttack,
    Member,
    fill_backpack,
)
from geneve.events_emitter import SourceEvents
from geneve.utils import random

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


if __name__ == "__main__":
    unittest.main()
