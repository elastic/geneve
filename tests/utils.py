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

"""Test case mixin classes."""

import hashlib
import itertools
import json
import math
import os
import subprocess
import sys
import textwrap
import time
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path

from geneve.events_emitter import SourceEvents
from geneve.utils import batched, load_schema, random

from . import jupyter

__all__ = (
    "SeededTestCase",
    "QueryTestCase",
    "OnlineTestCase",
    "SignalsTestCase",
    "assertReportUnchanged",
)

root_dir = Path(__file__).parent.parent
data_dir = root_dir / "tests" / "data"
config_file = Path(__file__).parent / "config.yaml"


def get_test_verbosity():
    env_verbose = int(os.getenv("TEST_VERBOSITY") or 0)
    cmd_verbose = sum(arg.count("v") for arg in sys.argv if arg.startswith("-") and not arg.startswith("--"))
    return cmd_verbose or env_verbose


verbose = get_test_verbosity()


@contextmanager
def tempenv(env):
    orig_env = {}
    for name, value in env.items():
        if name in os.environ:
            orig_env[name] = os.environ[name]
            if value is None:
                del os.environ[name]
        if value is not None:
            os.environ[name] = value
    try:
        yield
    finally:
        os.environ.update(orig_env)
        for name in set(env) - set(orig_env):
            os.environ.pop(name, None)


@contextmanager
def http_server(directory, timeout=10):
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    port = random.randint(1024, 65535)
    handler = partial(SimpleHTTPRequestHandler, directory=directory)
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = Thread(target=server.serve_forever)
    thread.start()

    try:
        yield server
    finally:
        server.server_close()
        server.shutdown()
        thread.join(timeout=timeout)


def get_stack_version():
    version = os.getenv("TEST_STACK_VERSION", None)

    if version in ("serverless", None):
        return version

    import semver

    return semver.VersionInfo.parse(version)


def get_test_schema_uri():
    return os.getenv("TEST_SCHEMA_URI") or "https://github.com/elastic/ecs/archive/refs/heads/main.tar.gz"


def get_test_rules_uri(rules_version=None, kibana_version=None):
    uri = os.getenv("TEST_DETECTION_RULES_URI")
    if uri:
        return uri
    if rules_version:
        return f"https://epr.elastic.co/package/security_detection_engine/{rules_version}"
    if kibana_version:
        if str(kibana_version) == "serverless":
            return "https://epr.elastic.co/search?package=security_detection_engine"
        else:
            if str(kibana_version).endswith("-SNAPSHOT"):
                kibana_version = str(kibana_version)[: -len("-SNAPSHOT")]
            return f"https://epr.elastic.co/search?package=security_detection_engine&kibana.version={kibana_version}"
    return "https://github.com/elastic/detection-rules/archive/refs/heads/main.tar.gz"


def load_config():
    from ruamel.yaml import YAML

    with open(config_file) as f:
        yaml = YAML(typ="safe")
        return yaml.load(f)


def load_test_schema():
    return load_schema(get_test_schema_uri(), "generated/ecs/ecs_flat.yml", root_dir)


def get_rule_by_id(rules, rule_id):
    for rule in rules:
        if rule["id"] == rule_id:
            return rule
    raise KeyError(f"cannot to find rule by id: {rule_id}")


def get_rule_test_data(rules, rule_id):
    return get_rule_by_id(rules, rule_id)[".test_private"]


def filter_out_test_data(rules):
    return [{k: v for k, v in rule.items() if k != ".test_private"} for rule in rules]


def diff_files(first, second):
    with subprocess.Popen(("diff", "-u", first, second), stdout=subprocess.PIPE) as p:
        try:
            out = p.communicate(timeout=30)[0]
        except subprocess.TimeoutExpired:
            p.kill()
            out = p.communicate()[0]
    return out.decode("utf-8")


def assertIdenticalFiles(tc, first, second):  # noqa: N802
    with open(first) as f:
        first_hash = hashlib.sha256(f.read().encode("utf-8")).hexdigest()
    with open(second) as f:
        second_hash = hashlib.sha256(f.read().encode("utf-8")).hexdigest()
    msg = None if verbose < 2 else "\n" + diff_files(first, second)
    tc.assertEqual(first_hash, second_hash, msg=msg)


def assertReportUnchanged(tc, nb, report):  # noqa: N802
    filename = root_dir / "tests" / "reports" / report
    old_filename = Path("{:s}.old{:s}".format(*os.path.splitext(filename)))
    new_filename = Path("{:s}.new{:s}".format(*os.path.splitext(filename)))
    if filename.exists():
        filename.rename(old_filename)
    jupyter.random.seed(report)
    nb.save(filename)
    if old_filename.exists():
        filename.rename(new_filename)
        old_filename.rename(filename)
        with tc.subTest(os.path.join("tests", "reports", report)):
            assertIdenticalFiles(tc, filename, new_filename)
            os.unlink(new_filename)


class SeededTestCase:
    """Make repeatable random choices in unit tests."""

    @classmethod
    def setUpClass(cls):
        cls.__saved_state = random.getstate()
        random.seed("setUpClass")
        super(SeededTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        random.seed("tearDownClass")
        super(SeededTestCase, cls).tearDownClass()
        random.setstate(cls.__saved_state)

    def setUp(self):
        random.seed("setUp")
        super(SeededTestCase, self).setUp()

    def tearDown(self):
        random.seed("tearDown")
        super(SeededTestCase, self).tearDown()

    def subTest(self, *args, **kwargs):  # noqa: N802
        random.seed(kwargs.pop("seed", "subTest"))
        return super(SeededTestCase, self).subTest(*args, **kwargs)


class QueryTestCase:
    stack_version = get_stack_version()

    @classmethod
    def setUpClass(cls):
        super(QueryTestCase, cls).setUpClass()
        cls.schema = load_test_schema()

    @classmethod
    def query_cell(cls, query, output, count=1, **kwargs):
        count = "" if count == 1 else f", count={count}"
        source = "emit('''\n    " + query.strip() + f"\n'''{count})"
        if not isinstance(output, str):
            output = "[[" + "],\n [".join(",\n  ".join(str(doc) for doc in branch) for branch in output) + "]]"
        return jupyter.Code(source, output, **kwargs)

    def subTest(self, query, **kwargs):  # noqa: N802
        return super(QueryTestCase, self).subTest(query, **kwargs, seed=query)

    def assertQuery(self, query, docs, count=1):  # noqa: N802
        se = SourceEvents(self.schema)
        se.stack_version = self.stack_version
        se.add_query(query, meta=query)
        branches = se.emit(timestamp=False, complete=True, count=count)
        _docs = [[event.doc for event in branch] for branch in branches]
        self.assertEqual(docs, _docs)


class OnlineTestCase:
    """Use Elasticsearch and Kibana in unit tests."""

    index_template = "geneve-ut"

    @classmethod
    def get_version(cls):
        if cls.serverless:
            return "serverless"

        import semver

        return semver.VersionInfo.parse(cls.kb.status()["version"]["number"])

    @classmethod
    def setUpClass(cls):
        super(OnlineTestCase, cls).setUpClass()

        from geneve.stack.prober_geneve_test_env import GeneveTestEnvStack

        stack = GeneveTestEnvStack()
        stack.connect()

        if not stack.es.ping():
            raise unittest.SkipTest(f"Could not reach Elasticsearch: {stack.es}")
        if not stack.kb.ping():
            raise unittest.SkipTest(f"Could not reach Kibana: {stack.kb}")

        if verbose:
            print("\n".join(stack.info()))

        stack.kb.create_siem_index()
        cls.siem_index_name = stack.kb.get_siem_index()["name"]

        build_flavor = stack.es.info()["version"].get("build_flavor")
        cls.serverless = build_flavor == "serverless"

        cls.es = stack.es
        cls.kb = stack.kb

    @classmethod
    def tearDownClass(cls):
        super(OnlineTestCase, cls).tearDownClass()

        cls.kb.close()
        cls.es.close()

    def setUp(self):
        super(OnlineTestCase, self).setUp()

        from elasticsearch import exceptions

        self.kb.delete_all_detection_engine_rules()

        if self.es.indices.exists_index_template(name=self.index_template):
            self.es.indices.delete_index_template(name=self.index_template)

        kwargs = {
            "index": self.siem_index_name,
            "query": {"match_all": {}},
        }
        try:
            self.es.delete_by_query(**kwargs)
        except exceptions.NotFoundError:
            pass


class SignalsTestCase:
    """Generate documents, load rules and documents, check triggered signals in unit tests."""

    multiplying_factor = int(os.getenv("TEST_SIGNALS_MULTI") or 0) or 1
    test_tags = ["Geneve"]

    def generate_docs_and_mappings(self, rules, asts):
        schema = load_test_schema()
        se = SourceEvents(schema)
        se.stack_version = self.get_version()

        if verbose and verbose <= 2:
            sys.stderr.write("\n  Parsing rules and creating documents: ")
            sys.stderr.flush()

        ok_rules = 0
        bulk = []
        for rule, ast in zip(rules, asts):
            if verbose and verbose <= 2 and ok_rules % 100 == 0:
                sys.stderr.write(f"{ok_rules}/{len(bulk)} ")
                sys.stderr.flush()

            with self.subTest(rule["query"]):
                try:
                    root = se.add_ast(ast, meta={"index": rule["index"][0]})
                    events = se.emit(root, complete=True, count=self.multiplying_factor)
                except Exception as e:
                    rule["enabled"] = False
                    if verbose > 2:
                        sys.stderr.write(f"{str(e)}\n")
                        sys.stderr.flush()
                    continue
                ok_rules += 1

                doc_count = 0
                for event in itertools.chain(*events):
                    bulk.append(json.dumps({"create": {"_index": event.meta["index"]}}))
                    bulk.append(json.dumps(event.doc))
                    if verbose > 2:
                        sys.stderr.write(json.dumps(event.doc, sort_keys=True) + "\n")
                        sys.stderr.flush()
                    doc_count += 1

                rule[".test_private"]["branch_count"] = len(root) * self.multiplying_factor
                rule[".test_private"]["doc_count"] = doc_count

        if verbose and verbose <= 2:
            sys.stderr.write(f"{ok_rules}/{len(bulk)} ")
            sys.stderr.flush()

        return (bulk, se.mappings())

    def load_rules_and_docs(self, rules, asts, *, docs_chunk_size=200, rules_chunk_size=50):
        docs, mappings = self.generate_docs_and_mappings(rules, asts)

        if verbose:
            sys.stderr.write("\n  Deleting any unit-test indices: ")
            sys.stderr.flush()
        for i, rule in enumerate(rules):
            if verbose and i % 100 == 0 and not i == len(rules) - 1:
                sys.stderr.write(f"{len(rules) - i} ")
                sys.stderr.flush()
            self.es.indices.delete(index=rule["index"], ignore_unavailable=True)
        if verbose:
            sys.stderr.write("0")
            sys.stderr.flush()

        kwargs = {
            "name": self.index_template,
            "template": {
                "mappings": mappings,
            },
        }
        self.es.cluster.put_component_template(**kwargs)

        kwargs = {
            "name": self.index_template,
            "index_patterns": [f"{self.index_template}-*"],
            "composed_of": [self.index_template],
        }
        if not self.serverless:
            kwargs.setdefault("template", {}).setdefault("settings", {}).update(
                {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "max_result_window": 50000,
                }
            )
        self.es.indices.put_index_template(**kwargs)

        with self.nb.chapter("## Rejected documents") as cells:
            if verbose:
                docs_to_go = len(docs)
                sys.stderr.write(f"\n  Loading documents: {docs_to_go} ")
                sys.stderr.flush()
                num_chunks = math.ceil(len(docs) / docs_chunk_size)
                prev_report_chunk = 0
            for i, chunk in enumerate(batched(docs, docs_chunk_size)):
                kwargs = {
                    "operations": "\n".join(chunk),
                }
                ret = self.es.options(request_timeout=30).bulk(**kwargs)
                for item in ret["items"]:
                    if item["create"]["status"] != 201:
                        cells.append(jupyter.Markdown(str(item["create"])))
                        if verbose > 1:
                            sys.stderr.write(f"{str(item['create'])}\n")
                            sys.stderr.flush()
                if verbose:
                    docs_to_go -= len(chunk)
                    nth_chunk = int(i / num_chunks * 14)  # 14 is just an arbitray number to give enough updates
                    if nth_chunk != prev_report_chunk or i == num_chunks - 1:
                        prev_report_chunk = nth_chunk
                        sys.stderr.write(f"{docs_to_go} ")
                        sys.stderr.flush()

        if verbose:
            rules_to_go = len(rules)
            sys.stderr.write(f"\n  Loading rules: {rules_to_go} ")
            sys.stderr.flush()
        for chunk in batched(rules, rules_chunk_size):
            self.kb.create_detection_engine_rules(filter_out_test_data(chunk))
            if verbose:
                rules_to_go -= len(chunk)
                sys.stderr.write(f"{rules_to_go} ")
                sys.stderr.flush()

        pending = {}
        for rule_id, created_rule in self.kb.find_detection_engine_rules(len(rules)).items():
            for rule in rules:
                if rule["rule_id"] == created_rule["rule_id"]:
                    rule["id"] = rule_id
                    if rule["enabled"]:
                        pending[rule_id] = created_rule
                    break
        return pending

    def wait_for_rules(self, pending, max_rules, timeout=300, sleep=5):
        start = time.time()
        successful = {}
        failed = {}
        if verbose:
            sys.stderr.write("\n  Waiting for rules execution: ")
            sys.stderr.flush()
        while (time.time() - start) < timeout:
            if verbose:
                sys.stderr.write(f"{len(pending)} ")
                sys.stderr.flush()
            self.check_rules(pending, successful, failed, max_rules)
            if pending:
                time.sleep(sleep)
            else:
                break
        if verbose:
            sys.stderr.write(f"{len(pending)} ")
            sys.stderr.flush()
        return successful, failed

    def check_rules(self, pending, successful, failed, max_rules):
        for rule_id, rule in self.kb.find_detection_engine_rules(max_rules).items():
            if "execution_summary" not in rule:
                continue
            if rule_id not in pending:
                continue

            last_execution = rule["execution_summary"]["last_execution"]
            if last_execution["status"] == "succeeded":
                self.handle_rule_success(rule_id, pending, successful, failed)
            elif last_execution["status"] == "failed":
                self.handle_rule_failure(rule_id, failed, last_execution["message"])

    def handle_rule_success(self, rule_id, pending, successful, failed):
        del pending[rule_id]
        successful[rule_id] = None
        failed.pop(rule_id, None)

    def handle_rule_failure(self, rule_id, failed, message):
        if verbose > 1:
            sys.stderr.write(f"rule failure:\n  {rule_id}\n  {message}")
            sys.stderr.flush()
        failed.setdefault(rule_id, set()).add(f"SDE says:\n> {message}")

    def check_docs(self, rule):
        kwargs = {
            "index": ",".join(rule["index"]),
            "query": {"match_all": {}},
            "sort": {
                "@timestamp": {"order": "asc"},
            },
            "size": rule[".test_private"]["doc_count"],
        }
        ret = self.es.search(**kwargs)
        return [hit["_source"] for hit in ret["hits"]["hits"]]

    def get_signals_per_rule(self, rules):
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must_not": [
                        {"exists": {"field": "signal.rule.building_block_type"}},
                    ]
                }
            },
            "aggs": {
                "signals_per_rule": {
                    "terms": {
                        "field": "signal.rule.id",
                        "size": 10000,
                    }
                }
            },
        }
        ret = self.kb.search_detection_engine_signals(body)
        signals = {}
        for bucket in ret["aggregations"]["signals_per_rule"]["buckets"]:
            branch_count = get_rule_test_data(rules, bucket["key"])["branch_count"]
            signals[bucket["key"]] = (bucket["doc_count"], branch_count)
        return signals

    def wait_for_signals(self, rules, timeout=90, sleep=5):
        if verbose:
            sys.stderr.write("\n  Waiting for signals generation: ")
            sys.stderr.flush()
        total_count = sum(rule[".test_private"]["branch_count"] for rule in rules if rule["enabled"])
        partial_count = 0
        partial_count_prev = 0
        partial_time = time.time()
        while (time.time() - partial_time) < timeout:
            if verbose:
                sys.stderr.write(f"{total_count - partial_count} ")
                sys.stderr.flush()
            signals = self.get_signals_per_rule(rules)
            partial_count = sum(branch_count for branch_count, _ in signals.values())
            if partial_count != partial_count_prev:
                partial_count_prev = partial_count
                partial_time = time.time()
            if total_count - partial_count > 0:
                time.sleep(sleep)
            else:
                break
        if verbose:
            sys.stderr.write(f"{total_count - partial_count} ")
            sys.stderr.flush()
        return signals

    @classmethod
    def query_cell(cls, query, docs, **kwargs):
        source = textwrap.dedent(query.strip())
        if docs:
            output = docs if isinstance(docs, str) else "[" + ",\n ".join(str(doc) for doc in docs) + "]"
        else:
            output = None
        return jupyter.Code(source, output, **kwargs)

    def report_rules(self, rules, rule_ids, title, *, docs_cell=True):
        prefix = "Geneve: "
        prefix_len = len(prefix)
        with self.nb.chapter(f"## {title} ({len(rule_ids)})") as cells:
            for rule in rules:
                if rule["id"] in rule_ids:
                    rule_name = rule["name"]
                    if rule_name.startswith(prefix):
                        rule_name = rule_name[prefix_len:]
                    descr = [
                        f"### {rule_name}",
                        "",
                        f"Branch count: {rule['.test_private']['branch_count']}  ",
                        f"Document count: {rule['.test_private']['doc_count']}  ",
                    ]
                    if isinstance(rule_ids, dict):
                        descr += [
                            f"Index: {rule['index'][0]}  ",
                            "Failure message(s):  ",
                        ] + [
                            ("  " + failure_message.replace(rule["id"], "<i>&lt;redacted&gt;</i>") + "  ")
                            for failure_message in rule_ids[rule["id"]]
                        ]
                    else:
                        descr.append(f'Index: {rule["index"][0]}')
                    cells.append(jupyter.Markdown("\n".join(descr)))
                    if self.multiplying_factor == 1:
                        cells.append(self.query_cell(rule["query"], None))

    def debug_rules(self, rules, rule_ids):
        lines = []
        for rule in rules:
            if rule["id"] in rule_ids:
                docs = self.check_docs(rule)
                t0 = None
                for doc in docs:
                    t0 = t0 or datetime.fromisoformat(docs[0]["@timestamp"])
                    t = datetime.fromisoformat(doc["@timestamp"])
                    doc["@timestamp"] = int((t - t0) / timedelta(milliseconds=1))
                lines.append("")
                lines.append("{:s}: {:s}".format(rule["id"], rule["name"]))
                lines.append(rule["query"].strip())
                lines.extend(json.dumps(doc, sort_keys=True) for doc in docs)
                if isinstance(rule_ids, dict):
                    lines.extend(rule_ids[rule["id"]].split("\n"))
        return "\n" + "\n".join(lines)

    def assertSignals(self, rules, rule_ids, msg, value=0):  # noqa: N802
        with self.subTest(msg):
            msg = None if verbose < 3 else self.debug_rules(rules, rule_ids)
            self.assertEqual(len(rule_ids), value, msg=msg)

    def check_signals(self, rules, pending):
        successful, failed = self.wait_for_rules(pending, len(rules))
        signals = self.wait_for_signals(rules)

        unsuccessful = set(signals) - set(successful)
        no_signals = set(successful) - set(signals)
        too_few_signals = {
            rule_id: [f"got {signals} signals, expected {expected}"]
            for rule_id, (signals, expected) in signals.items()
            if signals < expected
        }
        correct_signals = {rule_id for rule_id, (signals, expected) in signals.items() if signals == expected}
        too_many_signals = {
            rule_id: [f"got {signals} signals, expected {expected}"]
            for rule_id, (signals, expected) in signals.items()
            if signals > expected
        }

        rules = sorted(rules, key=lambda rule: rule["name"])

        self.report_rules(rules, failed, "Failed rules")
        self.report_rules(rules, unsuccessful, "Unsuccessful rules with signals")
        self.report_rules(rules, no_signals, "Rules with no signals")
        self.report_rules(rules, too_few_signals, "Rules with too few signals")
        self.report_rules(rules, too_many_signals, "Rules with too many signals")
        self.report_rules(rules, correct_signals, "Rules with the correct signals", docs_cell=False)

        self.assertSignals(rules, failed, "Failed rules", getattr(self, "ack_failed", 0))
        self.assertSignals(rules, unsuccessful, "Unsuccessful rules with signals", getattr(self, "ack_unsuccessful_with_signals", 0))
        self.assertSignals(rules, no_signals, "Rules with no signals", getattr(self, "ack_no_signals", 0))
        self.assertSignals(rules, too_few_signals, "Rules with too few signals", getattr(self, "ack_too_few_signals", 0))
        self.assertSignals(rules, too_many_signals, "Rules with too many signals", getattr(self, "ack_too_many_signals", 0))
