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

"""Test stack module."""

import unittest
from pathlib import Path

from geneve import config, stack
from geneve.stack.prober_elastic_package import ElasticPackageStack
from geneve.stack.prober_geneve_test_env import GeneveTestEnvStack

from .utils import assertIdenticalFiles, tempenv


class TestStack(unittest.TestCase):
    config_file = Path(__file__).parent / "data" / "config_nonexistent.yaml"

    def tearDown(self):
        self.config_file.unlink(missing_ok=True)

    def test_config_none(self):
        config.set_path(None)
        msg = f"Read 'Rules of the house' at {config.__file__}"
        with self.assertRaises(ValueError, msg=msg) as cm:
            self.assertEqual(None, stack.configurations())
        self.assertEqual(msg, str(cm.exception))

    def test_config_nonexistent(self):
        config.set_path(Path(__file__).parent / "data" / "config_nonexistent.yaml")
        self.assertEqual([], stack.configurations())

    def test_config_empty(self):
        config.set_path(Path(__file__).parent / "data" / "config_empty.yaml")
        self.assertEqual([], stack.configurations())

    def test_geneve_test_env(self):
        self.config_file_expected = Path(__file__).parent / "data" / "config_geneve-test-env.yaml"
        self.config_file = self.config_file_expected.with_suffix(".new")
        self.config_file.unlink(missing_ok=True)
        config.set_path(self.config_file)

        with tempenv(
            {
                "TEST_ELASTICSEARCH_URL": None,
                "TEST_KIBANA_URL": None,
            }
        ):
            msg = "Invalid stack reference: geneve-test-env"
            with self.assertRaises(ValueError, msg=msg) as cm:
                self.assertEqual(None, stack.lookup("geneve-test-env"))
            self.assertEqual(msg, str(cm.exception))
            self.assertFalse(any(type(s) is GeneveTestEnvStack for s in stack.discover()))

        with tempenv(
            {
                "TEST_ELASTICSEARCH_URL": "",
                "TEST_KIBANA_URL": "",
            }
        ):
            self.assertTrue(stack.lookup("geneve-test-env"))
            self.assertTrue(any(type(s) is GeneveTestEnvStack for s in stack.discover()))
            self.assertTrue(stack.set_default(next(s for s in stack.discover() if type(s) is GeneveTestEnvStack)))
            self.assertFalse(any(type(s) is GeneveTestEnvStack for s in stack.discover()))
            config.save()
            assertIdenticalFiles(self, self.config_file_expected, self.config_file)

    def test_elastic_package(self):
        self.config_file_expected = Path(__file__).parent / "data" / "config_elastic-package.yaml"
        self.config_file = self.config_file_expected.with_suffix(".new")
        self.config_file.unlink(missing_ok=True)
        config.set_path(self.config_file)

        with tempenv(
            {
                "ELASTIC_PACKAGE_ELASTICSEARCH_HOST": None,
                "ELASTIC_PACKAGE_ELASTICSEARCH_USERNAME": None,
                "ELASTIC_PACKAGE_ELASTICSEARCH_PASSWORD": None,
                "ELASTIC_PACKAGE_CA_CERT": None,
                "ELASTIC_PACKAGE_KIBANA_HOST": None,
            }
        ):
            msg = "Invalid stack reference: elastic-package"
            with self.assertRaises(ValueError, msg=msg) as cm:
                self.assertEqual(None, stack.lookup("elastic-package"))
            self.assertEqual(msg, str(cm.exception))
            self.assertFalse(any(type(s) is ElasticPackageStack for s in stack.discover()))

        with tempenv(
            {
                "ELASTIC_PACKAGE_ELASTICSEARCH_HOST": "",
                "ELASTIC_PACKAGE_ELASTICSEARCH_USERNAME": "",
                "ELASTIC_PACKAGE_ELASTICSEARCH_PASSWORD": "",
                "ELASTIC_PACKAGE_KIBANA_HOST": "",
                "ELASTIC_PACKAGE_CA_CERT": "",
            }
        ):
            self.assertTrue(stack.lookup("elastic-package"))
            self.assertTrue(any(type(s) is ElasticPackageStack for s in stack.discover()))
            self.assertTrue(stack.set_default(next(s for s in stack.discover() if type(s) is ElasticPackageStack)))
            self.assertFalse(any(type(s) is ElasticPackageStack for s in stack.discover()))
            config.save()
            assertIdenticalFiles(self, self.config_file_expected, self.config_file)
