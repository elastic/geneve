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

import sys
import logging
from itertools import islice

from . import version
from .events_emitter import SourceEvents
from .utils import root_dir, load_schema, load_rules

from flask import Flask, request, jsonify
app = Flask("geneve")
app.config.from_prefixed_env("GENEVE")

logging.basicConfig(level=logging.DEBUG)

rule_tags = app.config.get("RULE_TAGS", "")
if rule_tags:
    rule_tags = set(x.strip().lower() for x in rule_tags.split(",") if x.strip())
    if rule_tags:
        app.logger.info("Rule tags: {}".format(", ".join(sorted(rule_tags))))

schema_uri = app.config.get("SCHEMA_URI", "./etc/ecs-8.1.0.tar.gz")
app.logger.debug(f"Loading {schema_uri}...")
schema = load_schema(schema_uri, "generated/ecs/ecs_flat.yml", root_dir)

detection_rules_uri = app.config.get("DETECTION_RULES_URI", "./etc/detection-rules-8.1.0.tar.gz")
app.logger.debug(f"Loading {detection_rules_uri}...")
rules = load_rules(detection_rules_uri, "rules/**/*.toml", root_dir)

source_events = SourceEvents(schema)
loaded_rules = []
for rule in rules:
    if not rule_tags or rule_tags.issubset(x.lower() for x in rule.tags):
        try:
            source_events.add_rule(rule)
            loaded_rules.append(rule)
            rule.path = str(rule.path)
        except Exception as e:
            app.logger.warning(f"{e}: {rule.path}")
            continue

if not source_events:
    app.logger.error(f"Examined {len(rules)} rules, none was loaded.")
    sys.exit(1)

app.logger.info(f"Loaded {len(source_events)} rules")


@app.route("/api/v1/version", methods=["GET"])
def get_version():
    ret = {
        "version": version
    }
    return jsonify(ret)


@app.route("/api/v1/rules", methods=["GET"])
def get_rules():
    return jsonify([vars(x) for x in loaded_rules])


@app.route("/api/v1/query", methods=["GET"])
def query():
    query = request.args.get("query")
    count = request.args.get("count", default=1, type=int)
    source_events = SourceEvents(schema)
    source_events.add_query(query)
    docs = [event.doc for events in islice(source_events, count) for event in events]
    return jsonify(docs)


@app.route("/api/v1/emit", methods=["GET"])
def emit():
    count = request.args.get("count", default=1, type=int)
    docs = [event.doc for events in islice(source_events, count) for event in events]
    return jsonify(docs)
