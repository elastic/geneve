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

"""Test emitter with rules."""

import os
import sys
import time
import traceback
import unittest

import tests.utils as tu
from geneve.events_emitter import SourceEvents, ast_from_rule
from geneve.utils import load_rules

from . import jupyter


class TestRules(tu.QueryTestCase, tu.SeededTestCase, unittest.TestCase):
    maxDiff = None
    nb = jupyter.Notebook()
    nb.cells.append(
        jupyter.Markdown(
            """
        # Documents generation from detection rules

        This report captures the error reported while generating documents from detection rules. Here you
        can learn what rules are still problematic and for which no documents can be generated at the moment.

        Curious about the inner workings? Read [here](signals_generation.md).
    """
        )
    )

    def parse_from_collection(self, collection):
        asts = []
        rules = []
        errors = {}
        for rule in collection:
            try:
                asts.append(ast_from_rule(rule))
                rules.append(rule)
            except Exception as e:
                errors.setdefault(str(e), []).append(rule)
                continue

        with self.nb.chapter("## Skipped rules") as cells:
            cells.append(None)
            for err in sorted(sorted(errors), key=lambda e: len(errors[e]), reverse=True):
                heading = [f"{len(errors[err])} rules:", ""]
                bullets = []
                for rule in sorted(errors[err], key=lambda r: r.name):
                    bullets.append(f"* {rule.name}")
                with self.nb.chapter(f"### {err} ({len(errors[err])})") as cells:
                    cells.append(jupyter.Markdown(heading + sorted(bullets)))

        return rules, asts

    def generate_docs(self, rules, asts):
        errors = {}
        stats = []
        if tu.verbose > 2:
            sys.stdout.write("\n")
        for rule, ast in zip(rules, asts):
            try:
                se = SourceEvents(self.schema)
                se.stack_version = self.stack_version
                if tu.verbose > 2:
                    sys.stdout.write(f"adding {rule.name}...")
                    sys.stdout.flush()
                if tu.verbose > 1:
                    t = time.time()
                root = se.add_ast(ast)
                if tu.verbose > 1:
                    dt = time.time() - t
                    stats.append((len(root), dt, rule.name))
                if tu.verbose > 2:
                    sys.stdout.write("\r{} branches in {:.3f}s ({})\n".format(len(root), dt, rule.name))
                    sys.stdout.flush()
                _ = se.emit(timestamp=False, complete=True)
            except Exception as e:
                if tu.verbose > 1:
                    dt = time.time() - t
                    stats.append((-1, dt, rule.name))
                if tu.verbose > 2:
                    sys.stdout.write("\r{} branches in {:.3f}s ({})\n".format(-1, dt, rule.name))
                    sys.stdout.flush()
                if tu.verbose > 3:
                    sys.stdout.write("".join(traceback.format_exception(e)))
                    sys.stdout.flush()
                errors.setdefault(str(e), []).append(rule)
                continue
        if tu.verbose > 1:
            print("\nTop 10 rules (branches, secs, name):")
            for branches, dt, name in sorted(stats, reverse=True)[:10]:
                print(f"  {branches:>6}  {dt:>6.2f}  {name}")

        prefix = "Geneve: "
        prefix_len = len(prefix)
        with self.nb.chapter("## Generation errors") as cells:
            cells.append(None)
            for err in sorted(sorted(errors), key=lambda e: len(errors[e]), reverse=True):
                heading = [f"{len(errors[err])} rules:"]
                bullets = []
                for rule in sorted(errors[err], key=lambda r: r.name):
                    rule_name = rule.name
                    if rule_name.startswith(prefix):
                        rule_name = rule_name[prefix_len:]
                    bullets.append(f"* {rule_name}")
                with self.nb.chapter(f"### {err} ({len(errors[err])})") as cells:
                    cells.append(jupyter.Markdown(heading + sorted(bullets)))

    def test_collection(self):
        config = tu.load_config()["emitter_rules"]
        stack_version = self.stack_version
        if str(stack_version) == "serverless":
            major_minor = "serverless"
        else:
            major_minor = f"{stack_version.major}.{stack_version.minor}"
        rules_version = config["rules_versions"].get(major_minor)
        rules_uri = tu.get_test_rules_uri(rules_version, stack_version)
        version, collection = load_rules(rules_uri, paths=None, basedir=tu.root_dir)
        self.nb.cells.append(jupyter.Markdown(f"Rules version: {version or 'unknown'}"))
        collection = sorted(collection, key=lambda x: x.name)
        rules, asts = self.parse_from_collection(collection)
        self.generate_docs(rules, asts)

    def test_unchanged(self):
        stack_version = self.stack_version
        if str(stack_version) == "serverless":
            major_minor = "serverless"
        else:
            major_minor = f"{stack_version.major}.{stack_version.minor}"
        tu.assertReportUnchanged(self, self.nb, f"documents_from_rules-{major_minor}.md")


@unittest.skipIf(os.getenv("TEST_SIGNALS_RULES", "0").lower() in ("0", "false", "no", ""), "Slow online test")
class TestSignalsRules(tu.SignalsTestCase, tu.OnlineTestCase, tu.SeededTestCase, unittest.TestCase):
    maxDiff = None
    nb = jupyter.Notebook()
    nb.cells.append(
        jupyter.Markdown(
            """
        # Alerts generation from detection rules

        This report captures the detection rules signals generation coverage. Here you can
        learn what rules are supported and what not and why.

        Curious about the inner workings? Read [here](signals_generation.md).
    """
        )
    )

    def parse_from_collection(self, collection):
        rules = []
        asts = []
        for i, rule in enumerate(collection):
            try:
                asts.append(ast_from_rule(rule))
            except Exception:
                continue
            index_name = "{:s}-{:04d}".format(self.index_template, i)
            rule = {k: v for k, v in vars(rule).items() if not k.startswith("__") and k != "path"}
            rule.update(
                {
                    "name": "Geneve: " + rule["name"],
                    "index": [index_name],
                    "interval": "180s",
                    "from": "now-2h",
                    "tags": self.test_tags + rule["tags"],
                    "max_signals": 1000,
                    "enabled": True,
                    ".test_private": {},  # private test data, not sent to Kibana
                }
            )
            rules.append(rule)
        return rules, asts

    def test_rules(self):
        config = tu.load_config()["emitter_rules"]
        stack_version = self.get_version()
        if str(stack_version) == "serverless":
            major_minor = "serverless"
        else:
            major_minor = f"{stack_version.major}.{stack_version.minor}"
        for k, v in config["stack_signals"].get(major_minor, {}).items():
            setattr(self, k, v)
        mf_ext = f"_{self.multiplying_factor}x" if self.multiplying_factor > 1 else ""
        rules_version = config["rules_versions"].get(major_minor)
        rules_uri = tu.get_test_rules_uri(rules_version, stack_version)
        version, collection = load_rules(rules_uri, paths=None, basedir=tu.root_dir)
        self.nb.cells.append(jupyter.Markdown(f"Rules version: {version or 'unknown'}"))
        collection = sorted(collection, key=lambda x: (x.name, x.rule_id))
        rules, asts = self.parse_from_collection(collection)
        pending = self.load_rules_and_docs(rules, asts)
        try:
            self.check_signals(rules, pending)
        except AssertionError:
            tu.assertReportUnchanged(self, self.nb, f"alerts_from_rules-{major_minor}{mf_ext}.md")
            raise
        tu.assertReportUnchanged(self, self.nb, f"alerts_from_rules-{major_minor}{mf_ext}.md")
