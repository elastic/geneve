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

import importlib.util
import unittest
from pathlib import Path

SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "check-ruleset-sync.py"
SPEC = importlib.util.spec_from_file_location("check_ruleset_sync", SCRIPT_PATH)
RULESET_SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RULESET_SYNC)


class TestExpandMatrix(unittest.TestCase):
    def test_include_overwrites_added_values_on_base_combination(self):
        matrix = {
            "stack-version": ["8.2.0"],
            "schema-uri": ["./etc/ecs-v8.2.1.tar.gz"],
            "include": [
                {"python-version": "3.8", "os": "ubuntu-24.04"},
                {"python-version": "3.8", "os": "macos-latest"},
                {"python-version": "3.15", "os": "ubuntu-latest"},
                {"python-version": "3.15", "os": "macos-latest"},
            ],
        }

        checks = RULESET_SYNC.expand_matrix("Unit tests (${{ matrix.os }}/py-${{ matrix.python-version }})", matrix)

        self.assertEqual(checks, ["Unit tests (macos-latest/py-3.15)"])

    def test_exclude_and_include_replace_a_matrix_combination(self):
        matrix = {
            "python-version": ["3.8", "3.15"],
            "os": ["ubuntu-latest", "macos-latest"],
            "exclude": [{"python-version": "3.8", "os": "ubuntu-latest"}],
            "include": [{"python-version": "3.8", "os": "ubuntu-24.04"}],
        }

        checks = RULESET_SYNC.expand_matrix("Package tests (${{ matrix.os }}/py-${{ matrix.python-version }})", matrix)

        self.assertCountEqual(
            checks,
            [
                "Package tests (ubuntu-24.04/py-3.8)",
                "Package tests (macos-latest/py-3.8)",
                "Package tests (ubuntu-latest/py-3.15)",
                "Package tests (macos-latest/py-3.15)",
            ],
        )
