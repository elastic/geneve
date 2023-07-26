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

"""Event constraints solver."""

from geneve.solver import CombinedFields, Entity, solver
from geneve.utils.solution_space import transpose

# https://www.elastic.co/guide/en/ecs/8.8/ecs-allowed-values-event-category.html
event_categories = {
    "api": {"access", "admin", "allowed", "change", "creation", "deletion", "denied", "end", "info", "start", "user"},
    "authentication": {"start", "end", "info"},
    "configuration": {"access", "change", "creation", "deletion", "info"},
    "database": {"access", "change", "info", "error"},
    "driver": {"change", "end", "info", "start"},
    "email": {"info"},
    "file": {"access", "change", "creation", "deletion", "info"},
    "host": {"access", "change", "end", "info", "start"},
    "iam": {"admin", "change", "creation", "deletion", "group", "info", "user"},
    "intrusion_detection": {"allowed", "denied", "info"},
    "library": {"start"},
    "malware": {"info"},
    "network": {"access", "allowed", "connection", "denied", "end", "info", "protocol", "start"},
    "network_traffic": {"access", "allowed", "connection", "denied", "end", "info", "protocol", "start"},
    "package": {"access", "change", "deletion", "info", "installation", "start"},
    "process": {"access", "change", "end", "info", "start", "process_started", "process_stopped"},
    "registry": {"access", "change", "creation", "deletion"},
    "session": {"start", "end", "info"},
    "threat": {"indicator"},
    "vulnerability": {"info"},
    "web": {"access", "error", "info"},
}


@solver.group("event")
class EventEntity(Entity):
    ecs_constraints = {
        "category": [("wildcard", sorted(event_categories))],
        "type": [("wildcard", sorted(transpose(event_categories)))],
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        category_solver = self.fields.get("category", None)
        type_solver = self.fields.get("type", None)

        if category_solver and type_solver:
            self.fields["category & type"] = CombinedFields(category_solver, type_solver, event_categories)
            del self.fields["category"]
            del self.fields["type"]
