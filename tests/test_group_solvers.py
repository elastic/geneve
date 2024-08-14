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

"""Test group solvers."""

import unittest

import tests.utils as tu
from geneve.constraints import Document
from geneve.solver import Entity, solver


class TestGroupSolvers(tu.SeededTestCase, unittest.TestCase):
    maxDiff = None

    def test_double_registration(self):
        @solver.group("test")
        class TestEntity(Entity):
            def solve(self, doc, join_doc, env):
                pass

        msg = "duplicate group solver: test"
        with self.assertRaises(ValueError, msg=msg) as cm:

            @solver.group("test")
            class TestEntity2(Entity):
                def solve(self, doc, join_doc, env):
                    pass

        self.assertEqual(msg, str(cm.exception))

    def test_group(self):
        @solver.group("test.geo")
        @solver.group("test2.geo")
        class TestGeoEntity(Entity):
            def solve(self, doc, join_doc, env):
                self.emit_group(doc, {"lat": 0.0, "lon": 0.0})

        join_doc = {}
        schema = {}
        env = {}

        d = Document()
        d.append_constraint("test.geo.")
        d.append_constraint("test2.geo.")
        d.optimize(schema)

        self.assertEqual(
            {
                "test": {"geo": {"lat": 0.0, "lon": 0.0}},
                "test2": {"geo": {"lat": 0.0, "lon": 0.0}},
            },
            d.solve(join_doc, env),
        )

    def test_geo(self):
        join_doc = {}
        schema = {}
        env = {}

        d = Document()
        d.append_constraint("source.geo.")
        d.append_constraint("destination.geo.")
        d.optimize(schema)

        self.assertEqual(
            {
                "source": {
                    "geo": {
                        "city_name": "Lower Earley",
                        "country_iso_code": "GB",
                        "location": {"lat": 51.42708, "lon": -0.91979},
                        "timezone": "Europe/London",
                    }
                },
                "destination": {
                    "geo": {
                        "city_name": "Changzhi",
                        "country_iso_code": "CN",
                        "location": {"lat": 35.20889, "lon": 111.73861},
                        "timezone": "Asia/Shanghai",
                    }
                },
            },
            d.solve(join_doc, env),
        )

    def test_as(self):
        join_doc = {}
        schema = {
            "source.as.number": {"type": "long"},
            "destination.as.number": {"type": "long"},
        }
        env = {}

        d = Document()
        d.append_constraint("source.as.")
        d.append_constraint("destination.as.")
        d.optimize(schema)

        self.assertEqual(
            {
                "source": {"as": {"number": 44454, "organization": {"name": "Reeves Inc"}}},
                "destination": {"as": {"number": 2299, "organization": {"name": "Cooper Ltd"}}},
            },
            d.solve(join_doc, env),
        )

    def test_event(self):
        join_doc = {}
        schema = {
            "event.category": {"type": "keyword", "normalize": ["array"]},
            "event.type": {"type": "keyword", "normalize": ["array"]},
        }
        env = {}

        d = Document()
        d.append_constraint("event.type", "!=", "deletion")
        d.append_constraint("event.category", "==", "file")
        d.optimize(schema)

        self.assertEqual(
            [
                {"event": {"category": ["file"], "type": ["creation"]}},
                {"event": {"category": ["file"], "type": ["change"]}},
                {"event": {"category": ["file"], "type": ["access"]}},
                {"event": {"category": ["file"], "type": ["access"]}},
                {"event": {"category": ["file"], "type": ["change"]}},
                {"event": {"category": ["file"], "type": ["creation"]}},
                {"event": {"category": ["file"], "type": ["info"]}},
            ],
            [d.solve(join_doc, env) for _ in range(7)],
        )

        d = Document()
        d.append_constraint("event.type", "wildcard", ("start", "process_started"))
        d.append_constraint("event.category")
        d.optimize(schema)

        self.assertEqual(
            [
                {"event": {"category": ["authentication"], "type": ["start"]}},
                {"event": {"category": ["driver"], "type": ["start"]}},
                {"event": {"category": ["process"], "type": ["start"]}},
                {"event": {"category": ["session"], "type": ["start"]}},
                {"event": {"category": ["process"], "type": ["process_started"]}},
                {"event": {"category": ["process"], "type": ["start"]}},
                {"event": {"category": ["package"], "type": ["start"]}},
            ],
            [d.solve(join_doc, env) for _ in range(7)],
        )
