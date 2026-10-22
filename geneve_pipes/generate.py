# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with this work for
# additional information regarding copyright ownership. Elasticsearch B.V.
# licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.

"""Generate a paced stream of source events for selected detection rules."""

from __future__ import annotations

import fnmatch
import itertools
import json
import os
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from types import SimpleNamespace

import requests
from elastic.pipes.core import Pipe
from elastic.pipes.core.errors import ConfigError
from elastic.pipes.core.util import get_node
from typing_extensions import Annotated

from geneve.events_emitter import SourceEvents, ast_from_rule
from geneve.utils import load_schema


@dataclass
class PreparedRule:
    rule_id: str
    root: object
    index_patterns: Sequence[str]


def event_categories(document):
    """Return the event categories supplied by a generated source document."""
    category = document.get("event", {}).get("category", [])
    if isinstance(category, str):
        return (category,)
    if isinstance(category, Sequence):
        return category
    return ()


def destination_for(document, rule, destinations):
    """Choose a configured data stream that the rule searches for this event."""
    for category in event_categories(document):
        destination = destinations.get(category)
        if destination and any(fnmatch.fnmatchcase(destination, pattern) for pattern in rule.index_patterns):
            return destination
    return None


def write_stats(stats_file, stats):
    """Atomically publish generation counters for an external health reporter."""
    path = Path(stats_file)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(stats))
    os.replace(temporary, path)


def fetch_rule(session, kibana_url, rule_id):
    """Fetch one rule by its stable prebuilt rule ID."""
    response = session.get(f"{kibana_url}/api/detection_engine/rules", params={"rule_id": rule_id}, timeout=30)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


@Pipe("geneve_pipes.generate")
def main(
    log: Logger,
    state: Annotated[
        dict,
        Pipe.State(None, mutable=True),
        Pipe.Help("shared Pipes state, populated with an infinite documents stream"),
    ],
    stack: Annotated[
        dict,
        Pipe.State("stack", mutable=True),
        Pipe.Help("target stack connection configuration"),
    ],
    rule_ids: Annotated[
        Sequence,
        Pipe.Config("rule-ids"),
        Pipe.Help("enabled detection-rule IDs that Geneve is allowed to generate for"),
    ],
    destinations: Annotated[
        Mapping,
        Pipe.Config("destinations"),
        Pipe.Help("event category to canonical target data-stream mapping"),
    ],
    schema_uri: Annotated[
        str,
        Pipe.Config("schema-uri"),
        Pipe.Help("ECS schema archive used to solve generated event fields"),
    ],
    triggers_per_second: Annotated[
        int,
        Pipe.Config("triggers-per-second"),
        Pipe.Help("aggregate rule-trigger attempts per second"),
    ] = 1,
    stats_file: Annotated[
        str,
        Pipe.Config("stats-file"),
        Pipe.Help("JSON file updated with generation counters"),
    ] = "/tmp/geneve-generator-stats.json",
):
    """Prepare a continuous, rate-limited source-event stream for configured rules."""

    if not rule_ids:
        raise ConfigError("rule-ids must not be empty")
    if triggers_per_second <= 0:
        raise ConfigError("triggers-per-second must be greater than 0")
    if not destinations:
        raise ConfigError("destinations must not be empty")

    api_key = get_node(stack, "credentials.api-key", shell_expand=True)
    kibana_url = get_node(stack, "kibana.url", shell_expand=True).rstrip("/")
    if not api_key:
        raise ConfigError("target stack credentials.api-key is required")

    session = requests.Session()
    session.headers.update({"Authorization": f"ApiKey {api_key}", "kbn-xsrf": "geneve-obvious-tool"})
    schema = load_schema(schema_uri, "generated/ecs/ecs_flat.yml")
    emitter = SourceEvents(schema)
    prepared = []
    stats = {
        "configured_rules": len(rule_ids),
        "prepared_rules": 0,
        "skipped_rules": 0,
        "trigger_attempts": 0,
        "generated_documents": 0,
        "generation_failures": 0,
    }
    state["generator-stats"] = stats
    write_stats(stats_file, stats)

    for rule_id in rule_ids:
        rule = fetch_rule(session, kibana_url, rule_id)
        if rule is None:
            log.warning("configured rule %s no longer exists", rule_id)
            stats["skipped_rules"] += 1
            continue
        if not rule.get("enabled"):
            log.warning("configured rule %s is not enabled", rule_id)
            stats["skipped_rules"] += 1
            continue
        try:
            root = emitter.add_ast(ast_from_rule(SimpleNamespace(**rule)))
        except Exception as error:  # noqa: BLE001
            log.warning("skipping rule %s: %s", rule_id, error)
            stats["skipped_rules"] += 1
            continue
        prepared.append(PreparedRule(rule_id, root, rule["index"]))

    if not prepared:
        raise ConfigError("none of the configured rules can generate source events")
    stats["prepared_rules"] = len(prepared)
    write_stats(stats_file, stats)

    def generate():
        interval = 1 / triggers_per_second
        due_at = time.monotonic()
        for rule in itertools.cycle(prepared):
            delay = due_at - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            stats["trigger_attempts"] += 1
            write_stats(stats_file, stats)
            try:
                events = list(emitter.emit(rule.root, complete=False, count=1))
                documents = []
                for event in events:
                    destination = destination_for(event.doc, rule, destinations)
                    if destination is None:
                        raise ValueError("no configured destination matches generated event category")
                    documents.append({"_index": destination, "_source": event.doc})
            except Exception as error:  # noqa: BLE001
                stats["generation_failures"] += 1
                log.warning("generation failed for rule %s: %s", rule.rule_id, error)
            else:
                stats["generated_documents"] += len(documents)
                yield from documents
            write_stats(stats_file, stats)
            due_at += interval
            due_at = max(due_at, time.monotonic())

    state["documents"] = generate()


if __name__ == "__main__":
    main()
