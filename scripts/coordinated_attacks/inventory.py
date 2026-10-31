#!/usr/bin/env python3

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

"""Inventory of the pre-built rules as Geneve sees them.

For every rule of a `security_detection_engine` package the inventory records
the metadata useful to design coordinated attacks (type, tags, tactics, techniques)
and what Geneve makes of it offline: whether it can prepare and emit the rule,
the fields it solves and, on failure, the error.

This is the deterministic first stage of the coordinated attacks pipeline, the
fact base that story proposals and feasibility assessments are built on.

Usage: inventory.py <rules-version> <output.json>
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import tests.utils as tu
from geneve.events_emitter import SourceEvents
from geneve.utils import load_rules


def inventory(rules_version, *, verbose=False):
    version, rules = load_rules(tu.get_test_rules_uri(rules_version), basedir=tu.root_dir)
    schema = tu.load_test_schema()
    records = []
    t0 = time.time()
    for i, rule in enumerate(rules):
        threat = getattr(rule, "threat", [])
        record = {
            "id": rule.rule_id,
            "name": rule.name,
            "type": getattr(rule, "type", None),
            "language": getattr(rule, "language", None),
            "index": getattr(rule, "index", None),
            "tags": getattr(rule, "tags", []),
            "tactics": sorted({t["tactic"]["name"] for t in threat}),
            "techniques": sorted({x["id"] for t in threat for x in t.get("technique", [])}),
            "building_block": bool(getattr(rule, "building_block_type", None)),
        }
        try:
            se = SourceEvents(schema)
            root = se.add_rule(rule)
            record["branches"] = len(root)
            record["fields"] = sorted(root.fields())
            se.try_emit(root)
            record["status"] = "ok"
        except Exception as e:  # noqa: BLE001
            record["status"] = "error"
            record["error"] = str(e).splitlines()[0]
        records.append(record)
        if verbose and i % 100 == 0:
            print(f"{i}/{len(rules)} {time.time() - t0:.0f}s", file=sys.stderr)
    records.sort(key=lambda r: r["id"])
    return {"rules_version": version or rules_version, "rules": records}


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    rules_version, output = sys.argv[1:]
    result = inventory(rules_version, verbose=True)
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(result, f, indent=1)
        f.write("\n")
    ok = sum(1 for r in result["rules"] if r["status"] == "ok")
    print(f"{ok} rules emit out of {len(result['rules'])}", file=sys.stderr)


if __name__ == "__main__":
    main()
