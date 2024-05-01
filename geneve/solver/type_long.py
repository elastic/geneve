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

"""Constraints solver for long fields."""

from collections import namedtuple

from ..constraints import ConflictError
from ..utils import random
from . import Field, solver

NumberLimits = namedtuple("NumberLimits", ["MIN", "MAX"])

# https://www.elastic.co/guide/en/elasticsearch/reference/current/number.html
LongLimits = NumberLimits(-(2**63), 2**63 - 1)


@solver.type("long")
class LongField(Field):
    valid_constraints = ["==", "!=", ">=", "<=", ">", "<"]
    ecs_constraints = {
        "as.number": [(">=", 0), ("<", 2**16)],
        "bytes": [(">=", 0), ("<", 2**32)],
        "pid": [(">", 0), ("<", 2**32)],
        "port": [(">", 0), ("<", 2**16)],
    }

    def __init__(self, field, constraints, field_constraints, schema):
        super().__init__(field, constraints, field_constraints, schema)

        self.min_value = LongLimits.MIN
        self.max_value = LongLimits.MAX
        self.exclude_values = set()

        for k, v, *_ in constraints + field_constraints:
            if k == ">=":
                v = int(v)
                if self.min_value < v:
                    self.min_value = v
            elif k == "<=":
                v = int(v)
                if self.max_value > v:
                    self.max_value = v
            elif k == ">":
                v = int(v)
                if self.min_value < v + 1:
                    self.min_value = v + 1
            elif k == "<":
                v = int(v)
                if self.max_value > v - 1:
                    self.max_value = v - 1
        for k, v, *_ in constraints:
            if k == "==":
                v = int(v)
                if self.value is None or self.value == v:
                    self.value = v
                else:
                    raise ConflictError(f"is already {self.value}, cannot set to {v}", field, k)
            elif k == "!=":
                self.exclude_values.add(int(v))

        while self.min_value in self.exclude_values:
            self.min_value += 1
        while self.max_value in self.exclude_values:
            self.max_value -= 1
        if self.min_value > self.max_value:
            raise ConflictError(f"empty solution space, {self.min_value} <= x <= {self.max_value}", field)
        self.exclude_values = {v for v in self.exclude_values if v >= self.min_value and v <= self.max_value}
        if self.value is not None and self.value in self.exclude_values:
            if len(self.exclude_values) == 1:
                raise ConflictError(f"cannot be {self.exclude_values.pop()}", field)
            else:
                raise ConflictError(f"cannot be any of ({', '.join(str(v) for v in sorted(self.exclude_values))})", field)
        if self.value is not None and (self.value < self.min_value or self.value > self.max_value):
            raise ConflictError(f"out of boundary, {self.min_value} <= {self.value} <= {self.max_value}", field)

    def solve(self, left_attempts, environment):
        value = self.value
        history_values = self.get_history(environment)
        exclude_values = self.exclude_values | set(history_values)
        while left_attempts and (value is None or value in exclude_values):
            value = random.randint(self.min_value, self.max_value)
            left_attempts -= 1
        return {"value": value, "left_attempts": left_attempts}
