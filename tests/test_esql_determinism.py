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

"""With the same inputs the documents generated for ES|QL are always the same, down to the order of the fields.

The inputs are the query, the schema, the stack version, the seed and the time of the first document.
"""

import hashlib
import json
import os
import subprocess
import sys
import unittest
from datetime import datetime, timezone

import tests.utils as tu
from geneve.events_emitter import SourceEvents
from geneve.utils import random

CLOCK = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

# what the demo has plus what it doesn't: buckets of time, the documents that are recent and the integrations' fields
QUERIES = (
    'FROM logs-* | WHERE process.name == "a.exe" AND process.pid > 1024',
    'FROM logs-* | WHERE process.name IN ("cmd.exe", "powershell.exe", "bash") OR source.port < 1024',
    'FROM logs-* | WHERE process.name LIKE "FOO*" AND file.path LIKE "/home/*/.ssh/?d_*"',
    r'FROM logs-* | WHERE process.name RLIKE """(cmd|powershell)\.exe""" AND user.id RLIKE """[0-9]{3}-[a-z]+"""',
    'FROM logs-* | WHERE KQL("process.name: (cmd.exe or powershell.exe) and event.category: process")',
    'FROM logs-* | EVAL ua = TO_LOWER(user_agent.original) | WHERE ua LIKE "*fasthttp*"',
    'FROM logs-* | WHERE COALESCE(process.name, process.parent.name) == "a.exe"',
    "FROM logs-* | STATS c = COUNT(*) BY host.id | WHERE c >= 5",
    "FROM logs-* | STATS d = COUNT_DISTINCT(user.name), c = COUNT(*) BY host.id, source.ip | WHERE d >= 3 AND c >= 3",
    'FROM logs-* | WHERE user.name IN ("a", "b", "c") | STATS d = COUNT_DISTINCT(user.name) BY host.id | WHERE d >= 3',
    "FROM logs-* | STATS c = COUNT(*) BY bucket = BUCKET(@timestamp, 5 minutes), host.id | WHERE c >= 3",
    'FROM logs-* | STATS c = COUNT(*), last = MAX(@timestamp) BY host.id | EVAL ago = DATE_DIFF("minutes", last, NOW()) | WHERE c >= 3 AND ago < 10',
    'FROM logs-aws.cloudtrail-* | WHERE aws.cloudtrail.user_identity.type == "IAMUser" AND event.provider == "iam.amazonaws.com"',
)


def corpus(queries=QUERIES):
    """Return the documents of every query as the text of a JSON, the order of the fields is kept."""
    schema = tu.load_test_schema()
    result = []
    for query in queries:
        random.seed(query)
        se = SourceEvents(schema)
        se.stack_version = tu.get_stack_version()
        try:
            root = se.add_query(query)
        except NotImplementedError as e:
            result.append({"query": query, "error": str(e)})
            continue
        branches = [[event.doc for event in branch] for branch in se.emit(root, timestamp=CLOCK, complete=True, count=2)]
        result.append({"query": query, "branches": branches})
    return json.dumps(result, indent=1)


class TestEsqlDeterminism(unittest.TestCase):
    maxDiff = None

    def test_same_inputs_same_documents(self):
        first = corpus()
        self.assertEqual(first, corpus())
        data = json.loads(first)
        self.assertEqual([], [d["query"] for d in data if "error" in d])
        self.assertTrue(all(d["branches"] and all(d["branches"]) for d in data))

    def test_clock_is_the_one_given(self):
        data = json.loads(corpus(QUERIES[:1]))
        self.assertEqual("2026-01-02T03:04:05.000Z", data[0]["branches"][0][0]["@timestamp"].replace("+00:00", "Z"))

    def test_the_order_of_a_hash_does_not_matter(self):
        digests = set()
        for hash_seed in ("0", "1", "12345"):
            env = {**os.environ, "PYTHONHASHSEED": hash_seed}
            out = subprocess.run(
                [sys.executable, "-m", "tests.test_esql_determinism"], env=env, cwd=tu.root_dir, capture_output=True, text=True, check=True
            )  # noqa: S603
            digests.add(out.stdout.strip())
        self.assertEqual(1, len(digests), digests)


if __name__ == "__main__":
    print(hashlib.sha256(corpus().encode()).hexdigest())
