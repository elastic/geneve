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

from pipes.generate import PreparedRule, destination_for, event_categories


def test_event_categories_accepts_strings_and_lists():
    assert event_categories({"event": {"category": "process"}}) == ("process",)
    assert event_categories({"event": {"category": ["process", "file"]}}) == ["process", "file"]


def test_destination_uses_matching_rule_index_pattern():
    rule = PreparedRule("rule-id", object(), ["logs-endpoint.events.process-*"])
    destinations = {
        "file": "logs-endpoint.events.file-default",
        "process": "logs-endpoint.events.process-default",
    }

    assert destination_for({"event": {"category": "process"}}, rule, destinations) == "logs-endpoint.events.process-default"
    assert destination_for({"event": {"category": "file"}}, rule, destinations) is None
