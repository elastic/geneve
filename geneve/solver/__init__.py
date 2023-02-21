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

from functools import wraps

import faker

from ..constraints import ConflictError
from ..utils import deep_merge, random

faker.generator.random = random
_max_attempts = 100000

ecs_constraints = {
    "as.number": [(">=", 0), ("<", 2**16)],
    "bytes": [(">=", 0), ("<", 2**32)],
    "pid": [(">", 0), ("<", 2**32)],
    "port": [(">", 0), ("<", 2**16)],
}


def get_ecs_constraints(field):
    while field:
        try:
            return ecs_constraints[field]
        except KeyError:
            dot = field.find(".")
            if dot == -1:
                break
            field = field[dot + 1 :]
    return []


def delete_by_cond(list, cond):
    for i in reversed([i for i, x in enumerate(list) if cond(x)]):
        del list[i]


def delete_use_once(list):
    def is_use_once(item):
        return len(item) > 2 and item[2] and item[2].get("use_once", False)

    delete_by_cond(list, is_use_once)


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

    def __init__(self, name, *args):
        if name in self.solvers:
            raise ValueError(f"duplicate solver: {name}")
        self.name = name
        self.valid_constraints = ("join_value", "max_attempts", "cardinality") + args

    def wrap_field_solver(self, func):
        @wraps(func)
        def _solver(field, value, constraints, environment):
            join_values = []
            max_attempts = None
            cardinality = 0
            history = []
            augmented_constraints = constraints + get_ecs_constraints(field)
            for k, v, *_ in augmented_constraints:
                if k not in self.valid_constraints:
                    raise NotImplementedError(f"Unsupported {self.name} constraint: {k}")
                if k == "join_value":
                    join_values.append(v)
                if k == "max_attempts":
                    v = int(v)
                    if v < 0:
                        raise ValueError(f"max_attempts cannot be negative: {v}")
                    if max_attempts is None or max_attempts > v:
                        max_attempts = v
                if k == "cardinality":
                    if type(v) is tuple:
                        if len(v) > 1:
                            raise ValueError(f"Too many arguments for cardinality of '{field}': {v}")
                        v = v[0]
                    cardinality = int(v)
                    history = environment.setdefault("fields_history", {}).setdefault(field, [])
            if max_attempts is None:
                max_attempts = _max_attempts
            if len(history) < cardinality:
                augmented_constraints.extend(("!=", v["value"]) for v in history)
            if not cardinality or len(history) < cardinality:
                value = func(field, value, augmented_constraints, max_attempts + 1, environment)
                if not value["left_attempts"]:
                    raise ConflictError(f"attempts exausted: {max_attempts}", field)
                del value["left_attempts"]
                if cardinality:
                    history.append(value)
            else:
                value = random.choice(history[:cardinality])
            for field, constraint in join_values:
                constraint.append_constraint(field, "==", value["value"], {"use_once": True})
            delete_use_once(constraints)
            return value

        return _solver

    def __call__(self, func):
        if not self.name.endswith("."):
            func = self.wrap_field_solver(func)
        self.solvers[self.name] = func
        return func

    @classmethod
    def solve_field(cls, doc, group, field, constraints, schema, environment):
        if constraints is None:
            return None
        field = f"{group}.{field}" if group else field
        field_schema = schema.get(field, {})
        field_type = field_schema.get("type", "keyword")
        try:
            solver = cls.solvers[field_type]
        except KeyError:
            raise NotImplementedError(f"Constraints solver not implemented: {field_type}")
        if "array" in field_schema.get("normalize", []):
            value = []
        else:
            value = None
        value = solver(field, value, constraints, environment)["value"]
        if doc is not None:
            emit_field(doc, field, value)
        return value

    @classmethod
    def solve_nogroup(cls, doc, group, fields, schema, environment):
        for field, constraints in fields.items():
            cls.solve_field(doc, group, field, constraints, schema, environment)

    @classmethod
    def solve(cls, doc, group, fields, schema, environment):
        solve_group = cls.solvers.get(group + ".", cls.solve_nogroup)
        solve_group(doc, group, fields, schema, environment)


def load_solvers():
    from importlib import import_module
    from pathlib import Path

    for pattern in ("type_*.py", "group_*.py"):
        for path in Path(__file__).parent.glob(pattern):
            import_module("." + path.stem, __package__)


load_solvers()
