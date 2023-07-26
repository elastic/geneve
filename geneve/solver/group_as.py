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

"""Autonomous System constraints solver."""

from faker import Faker

from geneve.solver import Entity, solver

faker = Faker()


@solver.group("client.as")
@solver.group("destination.as")
@solver.group("server.as")
@solver.group("source.as")
@solver.group("threat.enrichments.indicator.as")
@solver.group("threat.indicator.as")
class ASEntity(Entity):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if "number" not in self.fields:
            self.fields["number"] = self.field_solver("number")

    def solve(self, doc, join_doc, env):
        entities = env.setdefault("entities", {}).setdefault("as", {})
        asn = self.fields["number"].solve_field(None, join_doc, env)
        org_name = entities.get(asn, None)
        if org_name is None:
            org_name = faker.company()
            entities[asn] = org_name
        self.emit_group(doc, {"number": asn, "organization.name": org_name})
