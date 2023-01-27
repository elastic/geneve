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
from . import solver

NumberLimits = namedtuple("NumberLimits", ["MIN", "MAX"])

# https://www.elastic.co/guide/en/elasticsearch/reference/current/number.html
LongLimits = NumberLimits(-(2**63), 2**63 - 1)


@solver("long", "==", "!=", ">=", "<=", ">", "<")
def solve_long_field(field, value, constraints, left_attempts, environment):
    min_value = LongLimits.MIN
    max_value = LongLimits.MAX
    exclude_values = set()

    for k, v, *_ in constraints:
        if k == ">=":
            v = int(v)
            if min_value < v:
                min_value = v
        elif k == "<=":
            v = int(v)
            if max_value > v:
                max_value = v
        elif k == ">":
            v = int(v)
            if min_value < v + 1:
                min_value = v + 1
        elif k == "<":
            v = int(v)
            if max_value > v - 1:
                max_value = v - 1
    for k, v, *_ in constraints:
        if k == "==":
            v = int(v)
            if value is None or value == v:
                value = v
            else:
                raise ConflictError(f"is already {value}, cannot set to {v}", field, k)
        elif k == "!=":
            exclude_values.add(int(v))

    while min_value in exclude_values:
        min_value += 1
    while max_value in exclude_values:
        max_value -= 1
    if min_value > max_value:
        raise ConflictError(f"empty solution space, {min_value} <= x <= {max_value}", field)
    exclude_values = {v for v in exclude_values if v >= min_value and v <= max_value}
    if value is not None and value in exclude_values:
        if len(exclude_values) == 1:
            raise ConflictError(f"cannot be {exclude_values.pop()}", field)
        else:
            raise ConflictError(f"cannot be any of ({', '.join(str(v) for v in sorted(exclude_values))})", field)
    if value is not None and (value < min_value or value > max_value):
        raise ConflictError(f"out of boundary, {min_value} <= {value} <= {max_value}", field)
    while left_attempts and (value is None or value in exclude_values):
        value = random.randint(min_value, max_value)
        left_attempts -= 1
    return {"value": value, "min": min_value, "max": max_value, "left_attempts": left_attempts}
