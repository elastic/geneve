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

"""Test util functions."""

import os
import unittest

from geneve.utils import deep_merge

from .utils import tempenv


class TestDictUtils(unittest.TestCase):
    """Test dictionary helpers."""

    def test_deep_merge(self):
        self.assertEqual(deep_merge({}, {"a": "A"}), {"a": "A"})
        self.assertEqual(deep_merge({"a": "A"}, {}), {"a": "A"})
        self.assertEqual(deep_merge({"a": "A"}, {"b": "B"}), {"a": "A", "b": "B"})
        self.assertEqual(deep_merge({"a": ["A"]}, {"a": ["A"]}), {"a": ["A"]})
        self.assertEqual(deep_merge({"a": ["A"]}, {"a": ["B"]}), {"a": ["A", "B"]})
        self.assertEqual(deep_merge({"a": ["A"]}, {"a": [{"b": "B"}]}), {"a": ["A", {"b": "B"}]})

        with self.assertRaises(ValueError, msg='Destination field already exists: a ("A" != "B")'):
            deep_merge({"a": "A"}, {"a": "B"})
        with self.assertRaises(ValueError, msg='Destination field already exists: a.b.c ("C" != "D")'):
            deep_merge({"a": {"b": {"c": "C"}}}, {"a": {"b": {"c": "D"}}})


class TestTempEnv(unittest.TestCase):
    """Test tempenv() helper."""

    def test_tempenv(self):
        with tempenv({"TEST_VAR": "value1"}):
            self.assertEqual("value1", os.environ["TEST_VAR"])
            with tempenv({"TEST_VAR": "value2"}):
                self.assertEqual("value2", os.environ["TEST_VAR"])
                with tempenv({"TEST_VAR": None}):
                    self.assertTrue("TEST_VAR" not in os.environ)
                    with tempenv({"TEST_VAR": "value3"}):
                        self.assertEqual("value3", os.environ["TEST_VAR"])
                    self.assertTrue("TEST_VAR" not in os.environ)
                self.assertEqual("value2", os.environ["TEST_VAR"])
            self.assertEqual("value1", os.environ["TEST_VAR"])
