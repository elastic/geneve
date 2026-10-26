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

"""Run the ES|QL queries and rules against the documents generated for them.

Opt-in, it needs an Elasticsearch (not Kibana) at TEST_ESQL_ES_URL, `http://127.0.0.1:29650` by default, which
is the one of the docker compose file but for the credentials, put them in the URL if any
(`http://elastic:changeme@127.0.0.1:29650`). Set TEST_ESQL_VALIDATION=1 to run it.
"""

import os
import unittest

import tests.utils as tu
from geneve.events_emitter import guess_from_query
from geneve.utils import load_rules

from . import esql_validation as ev
from .test_emitter_queries import all_queries

ES_URL = os.getenv("TEST_ESQL_ES_URL") or "http://127.0.0.1:29650"
MIN_VERSION = (8, 14)  # ES|QL is GA


@unittest.skipIf(os.getenv("TEST_ESQL_VALIDATION", "0").lower() in ("0", "false", "no", ""), "Needs an Elasticsearch, see the docstring")
class TestEsqlValidation(tu.QueryTestCase, tu.SeededTestCase, unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        from elasticsearch import Elasticsearch

        cls.es = Elasticsearch(ES_URL, request_timeout=60)
        if not cls.es.ping():
            raise unittest.SkipTest(f"Could not reach Elasticsearch: {ES_URL}")
        cls.version = cls.es.info()["version"]["number"]
        major, minor = (int(x) for x in cls.version.split(".")[:2])
        if (major, minor) < MIN_VERSION:
            raise unittest.SkipTest(f"ES|QL is not available in Elasticsearch {cls.version}")

    @classmethod
    def tearDownClass(cls):
        cls.es.close()
        super().tearDownClass()

    def assertNothingWrong(self, results):
        wrong = [r for r in results if r.status in ("failed", "error")]
        self.assertEqual([], wrong, "\n".join(f"{r.name}: {r.status}, {r.detail}" for r in wrong))

    def test_queries(self):
        queries = [query for query in all_queries() if guess_from_query(query).language == "esql"]
        self.assertGreater(len(queries), 0)
        results = [ev.validate_query(self.es, query.strip(), query, self.schema, self.stack_version) for query in queries]
        self.assertEqual([], [r for r in results if r.status == "skipped"])
        self.assertNothingWrong(results)

    def test_rules(self):
        config = tu.load_config()["emitter_rules"]
        major_minor = ".".join(self.version.split(".")[:2])
        rules_version = config["rules_versions"].get(major_minor)
        rules_uri = tu.get_test_rules_uri(rules_version, self.version)
        version, collection = load_rules(rules_uri, paths=None, basedir=tu.root_dir)
        rules = sorted((r for r in collection if getattr(r, "type", None) == "esql"), key=lambda r: r.name)
        self.assertGreater(len(rules), 0)

        results = [ev.validate_query(self.es, rule.name, rule.query, self.schema, self.stack_version, rule=rule) for rule in rules]

        report = ev.render_report("ES|QL rules validation", f"{self.version} (rules {version or 'unknown'})", results)
        (tu.root_dir / "tests" / "reports" / f"esql_validation-{major_minor}.md").write_text(report + "\n")
        self.assertNothingWrong(results)


if __name__ == "__main__":
    unittest.main()
