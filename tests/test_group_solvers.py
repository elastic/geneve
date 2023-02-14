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
from geneve.constraints import Constraints
from geneve.solver import emit_group, solver


class TestGroupSolvers(tu.SeededTestCase, unittest.TestCase):
    def test_group(self):
        @solver("source.geo.")
        @solver("destination.geo.")
        def solve_geo(doc, group, fields, schema, env):
            emit_group(doc, group, fields, {"lat": 0.0, "lon": 0.0})

        schema = {}
        c = Constraints()
        c.append_constraint("source.geo.")
        c.append_constraint("destination.geo.")

        self.assertEqual(
            {
                "source": {"geo": {"lat": 0.0, "lon": 0.0}},
                "destination": {"geo": {"lat": 0.0, "lon": 0.0}},
            },
            c.solve(schema),
        )

    def test_geo(self):
        schema = {}
        c = Constraints()
        c.append_constraint("source.geo.")
        c.append_constraint("destination.geo.")

        self.assertEqual(
            {
                "source": {
                    "geo": {
                        "city_name": "Thomazeau",
                        "country_iso_code": "HT",
                        "location": {"lat": 18.65297, "lon": -72.09391},
                        "timezone": "America/Port-au-Prince",
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
            c.solve(schema),
        )
