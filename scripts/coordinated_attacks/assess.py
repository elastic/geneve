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

  T0  works today: the rule emits and every bound field is one it constrains
  T1  needs a small known step (glue constraint so the member carries the
      field, entity roles, relative timing)
  T2  needs a Geneve feature or fix that does not exist yet
  T3  no generated document can trigger the rule

The grading is static, from the inventory. In addition the T0/T1 members are
emitted once with a backpack to confirm which bound fields are really pinned.

Usage: assess.py <rules-version> <output.md>
"""

import json
import sys
from pathlib import Path

from ruamel.yaml import YAML

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import tests.utils as tu
from geneve.coordinated_attack import CoordinatedAttack, Member, fill_backpack
from geneve.events_emitter import SourceEvents
from geneve.utils import load_rules

TIERS = {"T0": "trivial", "T1": "incremental", "T2": "major", "T3": "impossible"}


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
    return "pinnable" if field in record["fields"] else "glue"


def emit_with_backpack(rules, schema, story, members):
    """Emit the feasible members once with one backpack, report what each carries."""
    # until the drafts are loaded into real attacks, one host and one user role stand for the whole story
    fields = sorted({f for m in story["members"] for f in m["bindings"] if f in ("host.id", "user.id")})
    probe = Member("", {f: f.split(".")[0] + ".id" for f in fields})
    attack = CoordinatedAttack(story["id"], roles={"host": "host", "user": "user"}, members=(probe,))
    backpack = fill_backpack(attack, coordination_seed="assess", instance_id="story-1", schema=schema)
    view = backpack.view(probe)
    se = SourceEvents(schema)
    results = {}
    for member, record in members:
        if record["status"] != "ok":
            continue
        root = se.add_rule(rules[member["rule"]], glue=[f for f in member["bindings"] if f in fields])
        docs = [event.doc for event in se.emit(root, complete=False, count=1, timestamp=False, backpack=view)]
        carried = {}
        for field in fields:
            a, b = field.split(".")
            values = {doc[a][b] for doc in docs if a in doc and b in doc[a]}
            if values:
                carried[field] = "pinned" if values == {view[field]} else f"unpinned {sorted(values)}"
        results[member["rule"]] = (len(docs), carried)
    return view, results


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
        "`pinnable`: the member constrains the field, the backpack pins it today. "
        "`glue`: the member does not constrain the field, a attack-level glue constraint is needed (T1).\n"
    )
    out.append("| Member | Field | Role | State |")
    out.append("|---|---|---|---|")
    glue = 0
    for member, record in members:
        for field, role in member["bindings"].items():
            state = binding_state(record, field)
            glue += state == "glue"
            out.append(f"| {member['rule']} | `{field}` | {role} | {state} |")
    if glue:
        required_tiers.append("T1")

    out.append("\n### Emission with a backpack\n")
    values, results = emit_with_backpack(rules, schema, story, members)
    out.append(f"Backpack: `{values}`\n")
    out.append("| Member | Docs | Carried |")
    out.append("|---|---|---|")
    for name, (count, carried) in results.items():
        out.append(f"| {name} | {count} | {carried or 'none of the backpack fields'} |")

    story_tier = max(required_tiers, default="T0")
    out.append(f"\n**Story tier: {story_tier} ({TIERS[story_tier]})**, from the required members and bindings.\n")
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

    _, rules = load_rules(tu.get_test_rules_uri(rules_version), basedir=tu.root_dir)
    rules = {r.name: r for r in rules}
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
