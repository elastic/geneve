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

"""Test configuration."""

import unittest
from pathlib import Path

from geneve import config


class TestRulesOfTheHouse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config.set_path(None)

    def test_exception(self):
        msg = f"Read 'Rules of the house' at {config.__file__}"
        with self.assertRaises(ValueError, msg=msg) as cm:
            _ = config.load()
        self.assertEqual(msg, str(cm.exception))


class TestNonExistant(unittest.TestCase):
    config_path = Path(__file__).parent / "data" / "config_nonexistent.yaml"

    @classmethod
    def setUpClass(cls):
        config.set_path(cls.config_path)

    def test_cache(self):
        c1 = config.load()
        c2 = config.load()
        self.assertEqual(id(c1), id(c2))

    def test_cache_reload(self):
        c1 = config.load()
        config.set_path(self.config_path)
        c2 = config.load()
        self.assertNotEqual(id(c1), id(c2))

    def test_load(self):
        self.assertEqual({}, config.load())

    def test_save(self):
        config.save()
        self.assertEqual(False, self.config_path.exists())


class TestEmpty(unittest.TestCase):
    config_path = Path(__file__).parent / "data" / "config_empty.yaml"

    @classmethod
    def setUpClass(cls):
        config.set_path(cls.config_path)

    def test_load(self):
        self.assertEqual({}, config.load())

    def test_save(self):
        config.save()
        self.assertEqual(True, self.config_path.exists())
        self.assertEqual(0, self.config_path.stat().st_size)


class TestValues(unittest.TestCase):
    config_path = Path(__file__).parent / "data" / "config_test.yaml"

    @classmethod
    def setUpClass(cls):
        config.set_path(cls.config_path)
        cls.config_path.unlink(missing_ok=True)

    @classmethod
    def tearDownClass(cls):
        cls.config_path.unlink(missing_ok=True)

    def test_save_load(self):
        data = {
            "dictionary": {
                "string": "string value",
                "integer": 12_34,
                "float": 43.21,
                "lists": [[0, 1], [2, 3]],
            }
        }
        c1 = config.load()
        c1.update(data)
        config.save()
        config.set_path(self.config_path)
        c2 = config.load()
        self.assertNotEqual(id(c1), id(c2))
        self.assertEqual(c1, c2)
