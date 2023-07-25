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
from shutil import make_archive

from geneve.utils import deep_merge, resource, tempdir
from geneve.utils.hdict import hdict

from .utils import data_dir, http_server, tempenv


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


class TestResource(unittest.TestCase):
    """Test resource() helper."""

    resource = data_dir / "test-package-1.2.3"
    resource_zip = data_dir / (resource.name + ".zip")
    resource_gztar = data_dir / (resource.name + ".tar.gz")

    @classmethod
    def setUpClass(cls):
        make_archive(cls.resource, "gztar", root_dir=data_dir, base_dir=cls.resource.name)
        make_archive(cls.resource, "zip", root_dir=data_dir, base_dir=cls.resource.name)

    @classmethod
    def tearDownClass(cls):
        cls.resource_gztar.unlink()
        cls.resource_zip.unlink()

    def test_dir(self):
        uri = str(self.resource)

        with resource(uri) as resource_dir:
            self.assertEqual(self.resource, resource_dir)
            manifest = resource_dir / "manifest.yml"
            self.assertTrue(manifest.exists(), msg=f"{manifest} does not exist")

    def test_local(self):
        for ext in ["tar.gz", "zip"]:
            tests = [
                (f"file://./tests/data/{self.resource.name}.{ext}", None),
                (f"file://./{self.resource.name}.{ext}", data_dir),
                (f"tests/data/{self.resource.name}.{ext}", None),
                (f"{self.resource.name}.{ext}", data_dir),
            ]

            for uri, basedir in tests:
                with self.subTest(uri=uri, basedir=basedir):
                    with resource(uri, basedir=basedir) as resource_dir:
                        manifest = resource_dir / "manifest.yml"
                        self.assertTrue(manifest.exists(), msg=f"{manifest} does not exist")

    def test_remote(self):
        with http_server(data_dir) as server:
            uri = "http://%s:%s/%s.zip" % (*server.server_address, self.resource.name)

            with resource(uri) as resource_dir:
                manifest = resource_dir / "manifest.yml"
                self.assertTrue(manifest.exists(), msg=f"{manifest} does not exist")

    def test_cached(self):
        with http_server(data_dir) as server:
            uri = "http://%s:%s/%s.zip" % (*server.server_address, self.resource.name)

            with tempdir() as cachedir:
                cached_resource = cachedir / self.resource_zip.name

                self.assertFalse(cached_resource.exists(), msg=f"{cached_resource} does exist")
                with resource(uri, cachedir=cachedir) as resource_dir:
                    manifest = resource_dir / "manifest.yml"
                    self.assertTrue(manifest.exists(), msg=f"{manifest} does not exist")
                self.assertTrue(cached_resource.exists(), msg=f"{cached_resource} does not exist")


class TestHierarchicalDict(unittest.TestCase):
    def test_key_value(self):
        d = hdict()
        d["one.two"] = 0
        d["one.three.four"] = 1
        d["one.three.five"] = 2
        self.assertEqual(0, d["one.two"])
        self.assertEqual(1, d["one.three.four"])
        self.assertEqual(2, d["one.three.five"])

    def test_groups(self):
        d = hdict()
        self.assertEqual([], list(d.groups()))

        for field in [
            "@timestamp",
            "ecs.version",
            "process.name",
            "process.thread.id",
            "process.thread.name",
            "process.tty.char_device.major",
            "process.tty.char_device.minor",
            "source.geo.",
        ]:
            d[field] = None

        self.assertEqual(
            [
                ("ecs", {"version": None}),
                ("process", {"name": None}),
                ("process.thread", {"id": None, "name": None}),
                ("process.tty.char_device", {"major": None, "minor": None}),
                ("process.tty", {}),
                ("source.geo", {}),
                ("source", {}),
                ("", {"@timestamp": None}),
            ],
            list(d.groups()),
        )

        del d["source.geo."]
        self.assertEqual(
            [
                ("ecs", {"version": None}),
                ("process", {"name": None}),
                ("process.thread", {"id": None, "name": None}),
                ("process.tty.char_device", {"major": None, "minor": None}),
                ("process.tty", {}),
                ("", {"@timestamp": None}),
            ],
            list(d.groups()),
        )

        del d["process.tty.char_device.major"]
        self.assertEqual(
            [
                ("ecs", {"version": None}),
                ("process", {"name": None}),
                ("process.thread", {"id": None, "name": None}),
                ("process.tty.char_device", {"minor": None}),
                ("process.tty", {}),
                ("", {"@timestamp": None}),
            ],
            list(d.groups()),
        )

        del d["process.thread"]
        self.assertEqual(
            [
                ("ecs", {"version": None}),
                ("process", {"name": None}),
                ("process.tty.char_device", {"minor": None}),
                ("process.tty", {}),
                ("", {"@timestamp": None}),
            ],
            list(d.groups()),
        )

        del d["@timestamp"]
        self.assertEqual(
            list(d.groups()),
            [
                ("ecs", {"version": None}),
                ("process", {"name": None}),
                ("process.tty.char_device", {"minor": None}),
                ("process.tty", {}),
                ("", {}),
            ],
        )

        del d["process.tty.char_device.minor"]
        self.assertEqual(
            [
                ("ecs", {"version": None}),
                ("process", {"name": None}),
                ("", {}),
            ],
            list(d.groups()),
        )

        d["ecs"] = None
        self.assertEqual(
            [
                ("process", {"name": None}),
                ("", {"ecs": None}),
            ],
            list(d.groups()),
        )

        del d["process.name"]
        self.assertEqual(
            [
                ("", {"ecs": None}),
            ],
            list(d.groups()),
        )

        d["ecs"] = {"version": None}
        self.assertEqual(
            [
                ("ecs", {"version": None}),
                ("", {}),
            ],
            list(d.groups()),
        )

        del d["ecs.version"]
        self.assertEqual([], list(d.groups()))
