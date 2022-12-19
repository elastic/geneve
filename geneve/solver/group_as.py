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

from geneve.solver import emit_group, solver

faker = Faker()


@solver("client.as.")
@solver("destination.as.")
@solver("server.as.")
@solver("source.as.")
@solver("threat.enrichments.indicator.as.")
@solver("threat.indicator.as.")
def resolve_as_group(doc, group, fields, schema, env):
    entities = env.setdefault("entities", {}).setdefault("as", {})
    asn = solver.solve_field(None, group, "number", [], schema, env)
    org_name = entities.get(asn, None)
    if org_name is None:
        org_name = faker.company()
        entities[asn] = org_name
    emit_group(doc, group, {"number": asn, "organization.name": org_name})
