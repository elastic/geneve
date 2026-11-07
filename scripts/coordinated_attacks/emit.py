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

"""Emit instances of the attack stories over a time window, with noise and a ledger.

For every selected story draft of a rules version, N instances (ids
`<story id>-<k>`) are placed inside the window: each start is drawn so that
the whole timeline of the instance fits, from a private generator seeded by
(coordination seed, story id, instance id), like the backpack and the
schedule are. On top of that, `--noise` documents per member rule are
emitted without a backpack at random instants of the window: they trigger
the same rules with unrelated entities and are not in the ledger.

Two NDJSON files come out:

  --out     the documents, one `{"_index": "<prefix>-<rule id>", "_source": {...}}`
            per line, sorted by `@timestamp`: a timeline a loader can index as is,
            each rule's documents under its own index;
  --ledger  the ground truth, one line per member of every instance:
            attack, instance_id, start, member, rule_id, timestamp, documents
            and the role values (`role.attr` -> value) that member carries.

Same arguments (with an explicit `--start`) yield byte-identical files: the
shared random generator is seeded from the coordination seed, everything
else comes from private generators.

Usage: emit.py <rules-version> --out docs.ndjson --ledger ledger.ndjson
               [--stories ID|GLOB ...] [--instances N] [--noise N]
               [--start ISO-DATETIME] [--window 6h] [--coordination-seed SEED]
               [--index-prefix geneve-ca]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path
from random import Random

from ruamel.yaml import YAML

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import tests.utils as tu
from geneve.coordinated_attack import (
    AttackEmitter,
    instance_start,
    load_story,
    parse_duration,
    schedule,
)
from geneve.utils import load_rules, random


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("rules_version", help="rules package version the stories are drafted for, like 9.5.9")
    parser.add_argument("--out", required=True, type=Path, help="documents NDJSON")
    parser.add_argument("--ledger", required=True, type=Path, help="ledger NDJSON")
    parser.add_argument("--stories", nargs="*", default=["*"], metavar="ID|GLOB", help="story ids or globs (default: all the drafts)")
    parser.add_argument("--instances", type=int, default=1, metavar="N", help="instances per story (default: 1)")
    parser.add_argument("--noise", type=int, default=0, metavar="N", help="unrelated documents per member rule (default: 0)")
    parser.add_argument("--start", type=datetime.fromisoformat, metavar="ISO", help="start of the window (default: now - window)")
    parser.add_argument("--window", type=parse_duration, default="6h", metavar="DURATION", help="like 30s, 2m, 6h, 1d (default: 6h)")
    parser.add_argument("--coordination-seed", default="geneve", metavar="SEED", help="shared by the emitters of the same instances")
    parser.add_argument("--index-prefix", default="geneve-ca", metavar="PREFIX", help="index of a rule is <prefix>-<rule id>")
    args = parser.parse_args(argv)
    if args.start is None:
        args.start = datetime.now(timezone.utc) - args.window
    elif args.start.tzinfo is None:
        args.start = args.start.replace(tzinfo=timezone.utc)
    if args.instances < 1:
        parser.error("--instances must be at least 1")
    if args.noise < 0:
        parser.error("--noise must not be negative")
    return args


def load_stories(rules_version, patterns):
    base = Path(__file__).resolve().parents[2] / "etc" / "coordinated_attacks" / rules_version / "stories"
    yaml = YAML(typ="safe")
    stories = []
    for path in sorted(base.glob("*.yaml")):
        with open(path) as f:
            story = yaml.load(f)
        if any(fnmatchcase(story["id"], pattern) for pattern in patterns):
            stories.append(story)
    return stories


def emit(stories, rules, schema, args):
    """Documents of the instances and of the noise, as (timestamp, index, doc), and the ledger records."""
    seed = args.coordination_seed
    random.seed(seed)  # unbound fields and noise content come from the shared generator: same seed, same documents
    docs, ledger, roots = [], [], {}
    counts = {"stories": len(stories), "instances": 0, "story_docs": 0, "noise_docs": 0, "expected_alerts": 0, "overflowing": 0}
    for story in stories:
        attack = load_story(story, rules)
        emitter = AttackEmitter(attack, schema=schema)
        for member in attack.members:
            roots.setdefault(member.rule_id, (emitter, member))
        for k in range(1, args.instances + 1):
            instance_id = f"{attack.name}-{k}"
            start = instance_start(attack, coordination_seed=seed, instance_id=instance_id, window_start=args.start, window=args.window)
            span = max(schedule(attack, coordination_seed=seed, instance_id=instance_id).values())
            counts["overflowing"] += start + span > args.start + args.window
            events, instance = emitter.emit(instance_id=instance_id, start=start, coordination_seed=seed)
            emitted = iter(event.doc for event in events)
            for entry in instance.members:
                index = f"{args.index_prefix}-{entry.rule_id}"
                docs.extend((doc["@timestamp"], index, doc) for doc in (next(emitted) for _ in range(entry.documents)))
            ledger.extend(instance.records())
            counts["instances"] += 1
            counts["story_docs"] += len(events)
            counts["expected_alerts"] += instance.expected_alerts
    for rule_id, (emitter, member) in roots.items():
        for n in range(args.noise):
            timestamp = args.start + args.window * Random(f"{seed}\0noise\0{rule_id}\0{n}").random()
            events = list(emitter.source_events.emit(emitter.roots[member.name], timestamp=timestamp, count=1))
            docs.extend((event.doc["@timestamp"], f"{args.index_prefix}-{rule_id}", event.doc) for event in events)
            counts["noise_docs"] += len(events)
    docs.sort(key=lambda d: datetime.fromisoformat(d[0]))  # stable: documents of one emission keep their order
    return docs, ledger, counts


def main(argv=None):
    args = parse_args(argv)
    stories = load_stories(args.rules_version, args.stories)
    if not stories:
        sys.exit(f"no story of rules {args.rules_version} matches {args.stories}")
    _, rules = load_rules(tu.get_rules_package_uri(args.rules_version), basedir=tu.root_dir)
    schema = tu.load_test_schema()

    docs, ledger, counts = emit(stories, rules, schema, args)

    for path in (args.out, args.ledger):
        path.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        f.writelines(json.dumps({"_index": index, "_source": doc}) + "\n" for _, index, doc in docs)
    with open(args.ledger, "w") as f:
        f.writelines(json.dumps(record) + "\n" for record in ledger)

    end = args.start + args.window
    sys.stderr.write(
        f"window: {args.start.isoformat()} .. {end.isoformat()} ({args.window})\n"
        f"stories: {counts['stories']}, instances: {counts['instances']}"
        + (f" ({counts['overflowing']} overflowing the window)" if counts["overflowing"] else "")
        + f"\ndocuments: {len(docs)} ({counts['story_docs']} story, {counts['noise_docs']} noise) -> {args.out}\n"
        f"expected alerts: {counts['expected_alerts']} -> {args.ledger}\n"
    )


if __name__ == "__main__":
    main()
