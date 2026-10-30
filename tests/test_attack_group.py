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

"""Starter tests for attack groups and backpacks.

Members are taken from the mono_branch_* fixtures in test_emitter_queries
(not pre-built rules). The backpack goes down to the field solvers: only the
fields that a member actually constrains are solved, therefore only those
are taken from the backpack.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import unittest

import tests.utils as tu
from geneve.attack_group import AttackGroup, fill_backpack
from geneve.constraints import ConflictError
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

REGSVR_THEN_NETWORK = AttackGroup(
    name="regsvr-then-network",
    members=(REGSVR32, NETWORK_LOOPBACK),
    entities=("host.id", "user.id"),
)

CMD_FAMILY = AttackGroup(
    name="cmd-family",
    members=(REGSVR32_UNDER_CMD, NONZERO_PID, CMD_SEQUENCE),
    entities=("host.id", "user.id"),
)


def emit_docs(se, root, backpack=None):
    """Emit the documents of every branch of a root."""
    return [event.doc for branch in se.emit(root, complete=True, count=1, timestamp=False, backpack=backpack) for event in [*branch]]


def emit_group(group, backpack, schema=None):
    """Emit every member of a group, one list of documents per member."""
    se = SourceEvents(schema)
    roots = [se.add_query(query) for query in group.members]
    return [
        [event.doc for branch in se.emit(root, complete=True, count=1, timestamp=False, backpack=backpack) for event in branch]
        for root in roots
    ]


class TestBackpack(tu.SeededTestCase, unittest.TestCase):
    def test_deterministic_across_emitters(self):
        """Same group + seed + instance ⇒ same backpack, whatever the global random state."""
        a = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        random.seed("some other emitter")
        b = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        self.assertEqual(a, b)
        self.assertEqual(set(a.values), {"host.id", "user.id"})

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

    def test_values_follow_the_schema(self):
        schema = {"process.pid": {"type": "long"}, "source.ip": {"type": "ip"}}
        group = AttackGroup("typed", members=(), entities=("process.pid", "source.ip", "host.id"))
        a = fill_backpack(group, coordination_seed="lab", instance_id="story-1", schema=schema)
        b = fill_backpack(group, coordination_seed="lab", instance_id="story-1", schema=schema)
        self.assertEqual(a, b)
        self.assertIsInstance(a.values["process.pid"], int)
        self.assertTrue(0 < a.values["process.pid"] < 2**32)  # ECS bounds are honored
        self.assertIn(".", a.values["source.ip"])
        self.assertIsInstance(a.values["host.id"], str)


class TestBackpackInSolvers(tu.SeededTestCase, unittest.TestCase):
    def test_members_share_the_backpack_entities(self):
        backpack = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        regsvr, network = emit_group(REGSVR_THEN_NETWORK, backpack)
        self.assertEqual(len(regsvr), 1)
        self.assertEqual(len(network), 1)
        self.assertEqual(regsvr[0]["host"]["id"], backpack.values["host.id"])
        self.assertEqual(network[0]["host"]["id"], backpack.values["host.id"])
        self.assertEqual(network[0]["user"]["id"], backpack.values["user.id"])
        # what the members constrain themselves still comes from their queries
        self.assertEqual(regsvr[0]["process"]["name"], "regsvr32.exe")
        self.assertEqual(network[0]["destination"]["ip"], "127.0.0.1")

    def test_only_the_fields_of_the_document_are_taken(self):
        """The backpack carries host.id and user.id, a member that does not solve them does not get them."""
        backpack = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        regsvr, _ = emit_group(REGSVR_THEN_NETWORK, backpack)
        self.assertNotIn("user", regsvr[0])  # REGSVR32 has no user.id
        (cmd,), *_ = emit_group(CMD_FAMILY, fill_backpack(CMD_FAMILY, coordination_seed="lab", instance_id="story-2"))
        self.assertNotIn("host", cmd)  # REGSVR32_UNDER_CMD has no host.id
        self.assertNotIn("user", cmd)

    def test_without_a_backpack_nothing_changes(self):
        backpack = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        free, _ = emit_group(REGSVR_THEN_NETWORK, None)
        self.assertNotEqual(free[0]["host"]["id"], backpack.values["host.id"])

    def test_sequence_join_value_comes_from_the_backpack(self):
        """`sequence by user.id` joins on a value that the backpack pre-assigns, so the join survives."""
        backpack = fill_backpack(CMD_FAMILY, coordination_seed="lab", instance_id="story-9")
        *_, seq = emit_group(CMD_FAMILY, backpack)
        self.assertEqual(len(seq), 2)
        self.assertEqual(seq[0]["user"]["id"], backpack.values["user.id"])
        self.assertEqual(seq[1]["user"]["id"], backpack.values["user.id"])
        # without the backpack the sequence still joins, on a value of its own
        *_, free = emit_group(CMD_FAMILY, None)
        self.assertEqual(free[0]["user"]["id"], free[1]["user"]["id"])
        self.assertNotEqual(free[0]["user"]["id"], backpack.values["user.id"])

    def test_one_emitter_serves_multiple_backpacks(self):
        """One SourceEvents, two stories in flight, the IR is prepared once."""
        se = SourceEvents()
        roots = [se.add_query(query) for query in REGSVR_THEN_NETWORK.members]
        story_1 = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-1")
        story_2 = fill_backpack(REGSVR_THEN_NETWORK, coordination_seed="lab", instance_id="story-2")
        for backpack in (story_1, story_2, story_1):
            for root in roots:
                for doc in emit_docs(se, root, backpack):
                    self.assertEqual(doc["host"]["id"], backpack.values["host.id"])

    def test_backpack_value_must_satisfy_the_constraints(self):
        """A pre-assigned value that contradicts the member constraints is reported, not silently emitted."""
        group = AttackGroup("conflict", members=(REGSVR32,), entities=("process.name",))
        backpack = fill_backpack(group, coordination_seed="lab", instance_id="story-1")
        self.assertNotEqual(backpack.values["process.name"], "regsvr32.exe")
        with self.assertRaises(ConflictError):
            emit_group(group, backpack)


class TestIndependentEmitters(tu.SeededTestCase, unittest.TestCase):
    """Two emitters that never talk to each other build the documents of the same attack.

    All they share is the attack group, the coordination seed and the instance id.
    """

    def emitter(self, name, group, member, instance_id, noise=0):
        """Play one emitter: own random state, own SourceEvents, own backpack, one member of the group."""
        random.seed(f"emitter {name}")  # an unrelated random state per emitter
        se = SourceEvents()
        roots = [se.add_query(query) for query in group.members]
        for _ in range(noise):  # unrelated traffic that this emitter emitted before
            for root in roots:
                emit_docs(se, root)
        backpack = fill_backpack(group, coordination_seed="lab", instance_id=instance_id)
        return backpack, emit_docs(se, roots[member], backpack)

    def test_emitters_agree_on_the_attack_entities(self):
        backpack_a, (doc_a,) = self.emitter("A", REGSVR_THEN_NETWORK, member=0, instance_id="story-1")
        backpack_b, (doc_b,) = self.emitter("B", REGSVR_THEN_NETWORK, member=1, instance_id="story-1", noise=5)

        # each emitter computed its own backpack, they came out the same
        self.assertEqual(backpack_a, backpack_b)
        # the documents come from different emitters and are related through the shared entity
        self.assertEqual(doc_a["process"]["name"], "regsvr32.exe")
        self.assertEqual(doc_b["destination"]["ip"], "127.0.0.1")
        self.assertEqual(doc_a["host"]["id"], doc_b["host"]["id"])
        self.assertEqual(doc_a["host"]["id"], backpack_a.values["host.id"])

    def test_emitters_sharing_the_harness_seed_agree_without_a_coordination_seed(self):
        """Two emitters that started from the same harness seed need no coordination seed to agree."""

        def emitter(member):
            random.seed("harness")
            se = SourceEvents()
            roots = [se.add_query(query) for query in REGSVR_THEN_NETWORK.members]
            backpack = fill_backpack(REGSVR_THEN_NETWORK, instance_id="story-1")
            (doc,) = emit_docs(se, roots[member], backpack)
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
        self.assertEqual({doc["user"]["id"] for doc in seq}, {backpack_b.values["user.id"]})
        self.assertEqual(nonzero_pid["host"]["id"], backpack_a.values["host.id"])

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
            "from tests.test_attack_group import REGSVR_THEN_NETWORK as g;"
            "from geneve.attack_group import fill_backpack;"
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
