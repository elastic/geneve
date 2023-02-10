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

"""OS group constraints solver."""

from functools import partial
from pathlib import Path

from faker import Faker
from faker_datasets import Provider, add_dataset

from geneve.solver import emit_group, solver


@add_dataset("commands", Path(__file__).parent / "datasets" / "commands.json", picker="command")
class CommandProvider(Provider):
    pass


fake = Faker()
fake.add_provider(CommandProvider)


@solver("process.entry_leader.")
@solver("process.entry_leader.parent.")
@solver("process.entry_leader.parent.session_leader.")
@solver("process.group_leader.")
@solver("process.parent.")
@solver("process.parent.group_leader.")
@solver("process.previous.")
@solver("process.session_leader.")
@solver("process.session_leader.parent.")
@solver("process.session_leader.parent.session_leader.")
def resolve_process_group(doc, group, fields, schema, env):
    match = partial(solver.match_fields, group=group, fields=fields, schema=schema)
    try:
        command = fake.command(match=match)
    except ValueError:
        print(f"fields: {fields}")
        raise
    emit_group(doc, group, fields, {k: v for k, v in command.items() if k in fields})
