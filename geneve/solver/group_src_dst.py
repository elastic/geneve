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

"""Source/Destination group constraints solver."""

from faker import Faker

from geneve.solver import emit_field, emit_group, solver

faker = Faker()


@solver("source.")
@solver("destination.")
def resolve_src_dst(doc, group, fields, schema, env):
    for field, constraints in fields.items():
        if field == "mac":
            emit_field(doc, f"{group}.mac", constraints, faker.mac_address())
            continue
        if field == "domain":
            emit_field(doc, f"{group}.domain", constraints, faker.domain_name())
            continue
        solver.solve_field(doc, group, field, constraints, schema, env)
