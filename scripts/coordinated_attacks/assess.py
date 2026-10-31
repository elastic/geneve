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

"""Feasibility assessment of attack story drafts against Geneve.

Joins the story drafts of a rules version with its inventory and grades each
member and each story on the tier ladder:

  T0  works today: the rule emits, the story is loaded and emitted offline
  T1  needs a small known step in Geneve
  T2  needs a Geneve feature or fix that does not exist yet
  T3  no generated document can trigger the rule

The grading is static, from the inventory. In addition every story whose
required members all emit is compiled with `load_story()` and emitted once
with `AttackEmitter`: the report shows the ledger, the backpack, and whether
each document carries the role values its member binds.

Usage: assess.py <rules-version> <output.md>
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from ruamel.yaml import YAML

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import tests.utils as tu
from geneve.coordinated_attack import AttackEmitter, fill_backpack, load_story
from geneve.utils import load_rules

TIERS = {"T0": "trivial", "T1": "incremental", "T2": "major", "T3": "impossible"}
START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def member_tier(record):
    """Tier of a rule on its own, from its inventory record."""
    if record["status"] == "ok":
        return "T0", ""
    error = record.get("error", "")
    if "machine_learning" in error or "threat_match" in error:
        return "T3", error
    if "Unsolvable constraints" in error:
        return "T2", error + " (solver limitation, the rule is satisfiable)"
    return "T2", error


def binding_state(record, field):
    if record["status"] != "ok":
        return "n/a"
    return "constrained" if field in record["fields"] else "glued"


def get_field(doc, field):
    for part in field.split("."):
        doc = doc[part]
    return doc


def emit_story(story, rules, schema):
    """Compile the story with its required members and emit one instance of it."""
    attack = load_story(story, rules)
    backpack = fill_backpack(attack, coordination_seed="assess", instance_id="story-1", schema=schema)
    events, ledger = AttackEmitter(attack, schema=schema).emit(instance_id="story-1", start=START, coordination_seed="assess")
    docs = iter(event.doc for event in events)
    carried = {}
    for member, entry in zip(attack.members, ledger.members):
        member_docs = [next(docs) for _ in range(entry.documents)]
        states = []
        for field, binding in member.bindings.items():
            values = []
            for doc in member_docs:
                try:
                    values.append(get_field(doc, field))
                except KeyError:
                    values.append(None)
            expected = backpack.values[binding]
            ok = all(v == expected or v == [expected] for v in values)
            states.append(f"`{field}`: {'pinned' if ok else f'NOT pinned {values}'}")
        carried[member.name] = ", ".join(states)
    return backpack, ledger, carried


def assess_story(story, inventory, rules, schema, out):
    members = [(m, inventory[m["rule"]]) for m in story["members"]]
    out.append(f"## {story['title']} (`{story['id']}`)\n")
    out.append(story["narrative"].strip() + "\n")
    out.append(f"Platform: {story['platform']}; size: {story['size']}; expected alerts: {story['expected_alerts']}\n")

    out.append("### Members\n")
    out.append("| Member | Stage | Host | Tier | Note |")
    out.append("|---|---|---|---|---|")
    required_tiers = []
    for member, record in members:
        tier, note = member_tier(record)
        if not member.get("optional"):
            required_tiers.append(tier)
        opt = " (optional)" if member.get("optional") else ""
        out.append(f"| {member['rule']}{opt} | {member['stage']} | {member['host']} | {tier} | {note} |")

    out.append("\n### Bindings\n")
    out.append(
        "`constrained`: the member constrains the field itself. "
        "`glued`: the member does not mention the field, the glue constraint adds it. "
        "The backpack pins both.\n"
    )
    out.append("| Member | Field | Role | State |")
    out.append("|---|---|---|---|")
    for member, record in members:
        for field, role in member["bindings"].items():
            out.append(f"| {member['rule']} | `{field}` | {role} | {binding_state(record, field)} |")

    out.append("\n### Emission\n")
    story_tier = max(required_tiers, default="T0")
    if story_tier == "T0":
        try:
            backpack, ledger, carried = emit_story(story, rules, schema)
        except Exception as e:  # noqa: BLE001
            story_tier = "T1"
            out.append(f"Loading or emitting the story failed: `{e}`\n")
        else:
            out.append(f"Backpack: `{backpack.values}`\n")
            out.append(f"Ledger of instance `{ledger.instance_id}`, {ledger.expected_alerts} alerts expected:\n")
            out.append("| Member | Rule | Offset | Docs | Bound fields |")
            out.append("|---|---|---|---|---|")
            for entry in ledger.members:
                offset = entry.timestamp - ledger.start
                out.append(f"| {entry.member} | `{entry.rule_id}` | +{offset} | {entry.documents} | {carried[entry.member]} |")
            if ledger.expected_alerts != story["expected_alerts"]:
                story_tier = "T1"
                out.append(f"\nThe draft expects {story['expected_alerts']} alerts, the ledger {ledger.expected_alerts}.\n")
    else:
        out.append("Not attempted: a required member does not emit.\n")

    out.append(f"\n**Story tier: {story_tier} ({TIERS[story_tier]})**, from the required members and the emission.\n")
    return story_tier


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    rules_version, output = sys.argv[1:]
    base = Path(__file__).resolve().parents[2] / "etc" / "coordinated_attacks" / rules_version
    with open(base / "inventory.json") as f:
        records = json.load(f)["rules"]
    inventory = {r["name"]: r for r in records}
    yaml = YAML(typ="safe")
    stories = []
    for path in sorted((base / "stories").glob("*.yaml")):
        with open(path) as f:
            stories.append(yaml.load(f))

    _, rules = load_rules(tu.get_rules_package_uri(rules_version), basedir=tu.root_dir)
    schema = tu.load_test_schema()

    out = [f"# Attack stories feasibility, rules {rules_version}\n"]
    out.append(
        "Generated by `scripts/coordinated_attacks/assess.py` from `etc/coordinated_attacks/"
        f"{rules_version}/` (inventory and story drafts). Do not edit by hand.\n"
    )
    ok = sum(1 for r in records if r["status"] == "ok")
    out.append(f"Inventory: {ok} rules emit out of {len(records)}.\n")
    tiers = {}
    for story in stories:
        tiers[story["id"]] = assess_story(story, inventory, rules, schema, out)
    out.insert(3, "| Story | Tier |\n|---|---|\n" + "\n".join(f"| {k} | {v} |" for k, v in tiers.items()) + "\n")

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        f.write("\n".join(out))


if __name__ == "__main__":
    main()
