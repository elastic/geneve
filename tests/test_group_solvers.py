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
from geneve.solver import emit_group, solver


class TestGroupSolvers(tu.SeededTestCase, unittest.TestCase):
    def test_group(self):
        @solver("source.geo.")
        @solver("destination.geo.")
        def solve_geo(doc, group, fields, schema, env):
            emit_group(doc, group, {"lat": 0.0, "lon": 0.0})

        schema = {}
        d = Document()
        d.append_constraint("source.geo.")
        d.append_constraint("destination.geo.")

        self.assertEqual(
            {
                "source": {"geo": {"lat": 0.0, "lon": 0.0}},
                "destination": {"geo": {"lat": 0.0, "lon": 0.0}},
            },
            d.solve(schema),
        )

    def test_geo(self):
        schema = {}
        d = Document()
        d.append_constraint("source.geo.")
        d.append_constraint("destination.geo.")

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
            d.solve(schema),
        )

    def test_as(self):
        from geneve.solver import group_as

        schema = {
            "source.as.number": {"type": "long"},
            "destination.as.number": {"type": "long"},
        }
        c = Constraints()
        c.append_constraint("source.as.")
        c.append_constraint("destination.as.")

        self.assertEqual(
            {
                "source": {"as": {"number": 44454, "organization": {"name": "Reeves Inc"}}},
                "destination": {"as": {"number": 2299, "organization": {"name": "Cooper Ltd"}}},
            },
            c.solve(schema),
        )

    def test_os(self):
        from geneve.solver import group_os

        schema = {}
        c = Constraints()
        c.append_constraint("host.os.")

        self.assertEqual(
            {
                "host": {
                    "os": {
                        "codename": "bullseye",
                        "family": "debian",
                        "kernel": "5.10.0-20-cloud-amd64",
                        "name": "Debian GNU/Linux",
                        "platform": "debian",
                        "type": "linux",
                        "version": "11 (bullseye)",
                    }
                }
            },
            c.solve(schema),
        )
