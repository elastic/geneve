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

import string
from functools import wraps
from itertools import chain

import faker

from ..constraints import ConflictError
from ..utils import (
    deep_merge,
    expand_wildcards,
    has_wildcards,
    load_integration_schema,
    random,
    split_path,
)
from ..utils.solution_space import product, transpose

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
        for part in reversed(split_path(field)):
            value = {part: value}
        deep_merge(doc, value)


def emit_group(doc, group, values):
    group_parts = split_path(group)
    group_parts.reverse()
    for field, value in values.items():
        if value is not None:
            for part in reversed(split_path(field)):
                value = {part: value}
            for part in group_parts:
                value = {part: value}
            deep_merge(doc, value)


class solver:  # noqa: N801
    solvers = {}

    def __init__(self, name):
        if name in self.solvers:
            if name.startswith("&"):
                raise ValueError(f"duplicate type solver: {name[1:]}")
            elif name.endswith("."):
                raise ValueError(f"duplicate group solver: {name[:-1]}")
            else:
                raise ValueError(f"duplicate (unknown) solver: {name}")
        self.name = name

    def __call__(self, func):
        self.solvers[self.name] = func
        func.type = self.name
        return func

    @classmethod
    def get_type_solver(cls, type):
        try:
            return cls.solvers["&" + type]
        except KeyError:
            raise NotImplementedError(f"Field type solver: {type}")

    @classmethod
    def get_group_solver(cls, group):
        group_parts = split_path(group)
        while group_parts:
            try:
                return cls.solvers[".".join(group_parts) + "."]
            except KeyError:
                group_parts = group_parts[:-1]
        return Entity

    @classmethod
    def new_entity(cls, group, fields, schema, stack_version=None):
        return cls.get_group_solver(group)(group, fields, schema, stack_version)

    @classmethod
    def type(cls, name):
        return cls("&" + name)

    @classmethod
    def group(cls, name):
        return cls(name + ".")

    class integration:
        def __init__(self, name):
            self.name = name

        def __call__(self, func):
            @wraps(func)
            def wrapper(group, fields, schema, stack_version):
                if self.name:
                    deep_merge(schema, load_integration_schema(self.name, stack_version))
                    self.name = None
                return func(group, fields, schema, stack_version)

            return wrapper


class Entity:
    ecs_constraints = {}

    def __init__(self, group, fields, schema, stack_version):
        self.group = group
        self.schema = schema
        self.fields = {field: self.field_solver(field, constraints) for field, constraints in fields.items()}

    def field_solver(self, field, constraints=[]):
        if constraints is not None:
            if self.group:
                field = f"{self.group}.{field}"
            field_schema = self.schema.get(field, {})
            field_type = field_schema.get("type", "keyword")
            field_is_array = "array" in field_schema.get("normalize", [])
            field_solver = solver.get_type_solver(field_type)
            field_constraints = get_ecs_constraints(self, field) + get_ecs_constraints(field_solver, field)
            return field_solver(field, constraints, field_constraints, field_is_array)

    def solve(self, doc, join_doc, environment):
        for field, solver in self.fields.items():
            if solver:
                solver.solve_field(doc, join_doc, environment)

    def emit_group(self, doc, values):
        emit_group(doc, self.group, values)


class Field:
    common_constraints = ["join_value", "max_attempts", "cardinality"]
    ecs_constraints = {}
    type = None

    def __init__(self, field, constraints, field_constraints, is_array):
        self.field = field
        self.value = [] if is_array else None
        self.is_array = is_array
        self.has_wildcards = has_wildcards(field)
        self.join_field_parts = None
        self.max_attempts = None
        self.cardinality = 0

        valid_constraints = self.common_constraints + getattr(self, "valid_constraints", [])

        for k, v, *flags in constraints + field_constraints:
            if k not in valid_constraints:
                raise NotImplementedError(f"Unsupported {self.type} '{field}' constraint: {k}")
            if k == "join_value":
                self.join_field_parts = split_path(v[1])
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
            return {}
        return environment.setdefault("fields_history", {}).setdefault(self.field, {})

    def __call__(self, join_doc, environment):
        history = self.get_history(environment)

        if self.join_field_parts:
            value = join_doc
            for part in self.join_field_parts:
                value = value[part]
            if self.cardinality:
                history[value] = None
            return {"value": value}

        if not self.cardinality or len(history) < self.cardinality:
            value = self.solve(self.max_attempts + 1, environment)
            if not value["left_attempts"]:
                raise ConflictError(f"attempts exausted: {self.max_attempts}", self.field)
            del value["left_attempts"]
            if self.cardinality:
                history[value["value"]] = None
        else:
            value = {"value": random.choice(list(history)[: self.cardinality])}

        return value

    def solve(self, left_attempts, environment):
        pass

    def solve_field(self, doc, join_doc, environment):
        value = self(join_doc, environment)["value"]
        if doc is not None:
            field = expand_wildcards(self.field, string.ascii_letters, 1, 3) if self.has_wildcards else self.field
            emit_field(doc, field, value)
        return value


class CombinedFields:
    def __init__(self, a, b, ab):
        self.fields = [a, b]
        A = set(chain(*a.value))
        B = set(chain(*b.value))
        ba = transpose(ab)
        self.solutions = sorted(set(product(A, ab)) & set(product(ba, B)))
        if not self.solutions:
            raise ConflictError("empty intersection", f"{a.field} & {b.field}")

    def solve_field(self, doc, join_doc, environment):
        values = random.choice(self.solutions)
        if doc is not None:
            for field, value in zip(self.fields, values):
                if field.is_array:
                    value = [value]
                emit_field(doc, field.field, value)
        return values


def load_solvers():
    from importlib import import_module
    from pathlib import Path

    for pattern in ("type_*.py", "group_*.py"):
        for path in Path(__file__).parent.glob(pattern):
            import_module("." + path.stem, __package__)


load_solvers()
