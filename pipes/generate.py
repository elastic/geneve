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

"""Generate a paced stream of source events for selected detection rules."""

from __future__ import annotations

import fnmatch
import itertools
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from logging import Logger
from pathlib import Path
from types import SimpleNamespace

from elastic.pipes.core import Pipe
from elastic.pipes.core.errors import ConfigError
from typing_extensions import Annotated

from geneve.events_emitter import SourceEvents, ast_from_rule
from geneve.utils import load_schema

READY_FILE = Path("/tmp/geneve-ready")


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


@Pipe("elastic.pipes.geneve.generate")
def main(
    log: Logger,
    state: Annotated[
        dict,
        Pipe.State(None, mutable=True),
        Pipe.Help("shared Pipes state, populated with an infinite documents stream"),
    ],
    rules: Annotated[
        Sequence[Mapping],
        Pipe.State("rules", mutable=True),
        Pipe.Help("enabled Detection Engine rules retrieved from Kibana"),
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
):
    """Prepare a continuous, rate-limited source-event stream for selected rules."""

    if not rules:
        raise ConfigError("rules state must not be empty")
    if triggers_per_second <= 0:
        raise ConfigError("triggers-per-second must be greater than 0")
    if not destinations:
        raise ConfigError("destinations must not be empty")

    schema = load_schema(schema_uri, "generated/ecs/ecs_flat.yml")
    emitter = SourceEvents(schema)
    prepared = []

    for rule in rules:
        rule_id = rule.get("rule_id")
        if not isinstance(rule_id, str):
            raise ConfigError("rules state entries must have a stable rule_id")
        if not rule.get("enabled"):
            log.warning("retrieved Detection Engine rule %s is not enabled", rule_id)
            continue
        try:
            root = emitter.add_ast(ast_from_rule(SimpleNamespace(**rule)))
            index_patterns = rule["index"]
        except Exception:
            log.exception("failed to prepare configured rule %s", rule_id)
            continue
        prepared.append(PreparedRule(rule_id, root, index_patterns))

    if not prepared:
        raise ConfigError("none of the selected rules can generate source events")
    READY_FILE.touch()

    def generate():
        interval = 1 / triggers_per_second
        due_at = time.monotonic()
        for rule in itertools.cycle(prepared):
            delay = due_at - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            try:
                events = list(emitter.emit(rule.root, complete=False, count=1))
                documents = []
                for event in events:
                    destination = destination_for(event.doc, rule, destinations)
                    if destination is None:
                        raise ValueError("no configured destination matches generated event category")
                    documents.append({"_index": destination, "_source": event.doc})
            except Exception:
                log.exception("generation failed for rule %s", rule.rule_id)
            else:
                yield from documents
            due_at += interval
            due_at = max(due_at, time.monotonic())

    state["documents"] = generate()


if __name__ == "__main__":
    main()
