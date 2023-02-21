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

"""Constraints solver helper class."""

import faker

from ..constraints import ConflictError
from ..utils import deep_merge, random

faker.generator.random = random
_max_attempts = 100000


def get_ecs_constraints(solver, field):
    while field:
        try:
            return solver.ecs_constraints[field]
        except KeyError:
            dot = field.find(".")
            if dot == -1:
                break
            field = field[dot + 1 :]
    return []


def emit_field(doc, field, value):
    if value is not None:
        for part in reversed(field.split(".")):
            value = {part: value}
        deep_merge(doc, value)


def emit_group(doc, group, values):
    group_parts = group.split(".")
    group_parts.reverse()
    for field, value in values.items():
        if value is not None:
            for part in reversed(field.split(".")):
                value = {part: value}
            for part in group_parts:
                value = {part: value}
            deep_merge(doc, value)


class solver:  # noqa: N801
    solvers = {}

    def __init__(self, name):
        if name in self.solvers:
            raise ValueError(f"duplicate solver: {name}")
        self.name = name

    def __call__(self, func):
        self.solvers[self.name] = func
        func.type = self.name
        return func

    @classmethod
    def solve_field(cls, doc, group, field, constraints, schema, environment):
        if constraints is None:
            return None
        field = f"{group}.{field}" if group else field
        field_schema = schema.get(field, {})
        field_type = field_schema.get("type", "keyword")
        field_is_array = "array" in field_schema.get("normalize", [])
        try:
            field_solver = cls.solvers[f"&{field_type}"]
        except KeyError:
            raise NotImplementedError(f"Constraints solver not implemented: {field_type}")
        constraints = constraints + get_ecs_constraints(field_solver, field)
        value = field_solver(field, constraints, field_is_array, group)(environment)["value"]
        if doc is not None:
            emit_field(doc, field, value)
        return value

    @classmethod
    def new_entity(cls, group, fields):
        return cls.solvers.get(group + ".", Entity)(group, fields)


class Entity:
    def __init__(self, group, fields):
        self.group = group
        self.fields = fields

    def solve(self, doc, schema, environment):
        for field, constraints in self.fields.items():
            solver.solve_field(doc, self.group, field, constraints, schema, environment)


class Field:
    common_constraints = ["join_value", "max_attempts", "cardinality"]
    ecs_constraints = {}
    type = None

    def __init__(self, field, constraints, is_array, group=None):
        self.field = f"{group}.{field}" if group else field
        self.value = [] if is_array else None
        self.is_array = is_array
        self.max_attempts = None
        self.cardinality = 0

        valid_constraints = self.common_constraints + getattr(self, "valid_constraints", [])

        for k, v, *flags in constraints:
            if k not in valid_constraints:
                raise NotImplementedError(f"Unsupported {self.type} '{field}' constraint: {k}")
            if k == "join_value":
                pass  # FIXME
            if k == "max_attempts":
                v = int(v)
                if v < 0:
                    raise ValueError(f"max_attempts cannot be negative: {v}")
                if self.max_attempts is None or self.max_attempts > v:
                    self.max_attempts = v
            if k == "cardinality":
                if type(v) is tuple:
                    if len(v) > 1:
                        raise ValueError(f"Too many arguments for cardinality of '{field}': {v}")
                    v = v[0]
                self.cardinality = int(v)

        if self.max_attempts is None:
            self.max_attempts = _max_attempts

    def get_history(self, environment):
        if not self.cardinality:
            return []
        return environment.setdefault("fields_history", {}).setdefault(self.field, [])

    def __call__(self, environment):
        history = self.get_history(environment)

        if not self.cardinality or len(history) < self.cardinality:
            value = self.solve(self.max_attempts + 1, environment)
            if not value["left_attempts"]:
                raise ConflictError(f"attempts exausted: {self.max_attempts}", self.field)
            del value["left_attempts"]
            if self.cardinality:
                history.append(value)
        else:
            value = random.choice(history[: self.cardinality])

        return value

    def solve(self, left_attempts, environment):
        pass


def load_solvers():
    from importlib import import_module
    from pathlib import Path

    for pattern in ("type_*.py", "group_*.py"):
        for path in Path(__file__).parent.glob(pattern):
            import_module("." + path.stem, __package__)


load_solvers()
