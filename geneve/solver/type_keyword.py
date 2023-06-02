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

"""Constraints solver for keyword fields."""

import string
from fnmatch import fnmatch

from ..constraints import ConflictError
from ..utils import random
from . import Field, solver


def expand_wildcards(value, allowed_chars):
    chars = []
    for c in list(value):
        if c == "?":
            chars.append(random.choice(allowed_chars))
        elif c == "*":
            chars.extend(random.choices(allowed_chars, k=random.randrange(1, 16)))
        else:
            chars.append(c)
    return "".join(chars)


def has_wildcards(value):
    if type(value) == str:
        return value.find("?") + value.find("*") > -2
    return False


def match_wildcards(values, wildcards):
    if type(values) != list:
        values = [values]
    return any(fnmatch(v, wc) for v in values for wc in wildcards)


@solver("&keyword")
class KeywordField(Field):
    valid_constraints = ["==", "!=", "wildcard", "not wildcard", "min_length", "allowed_chars"]

    def __init__(self, field, constraints, schema, group):
        super().__init__(field, constraints, schema, group)

        self.allowed_chars = string.ascii_letters
        self.include_wildcards = set()
        self.exclude_wildcards = set()
        self.exclude_values = set()
        self.min_length = 3

        for k, v, *_ in constraints:
            if k == "wildcard":
                if type(v) == tuple and len(v) == 1:
                    v = v[0]
                if self.is_array:
                    self.value.extend([v] if type(v) == str else v)
                elif type(v) == tuple:
                    self.include_wildcards |= set(v)
                elif self.value is None or self.value == v:
                    self.value = v
                else:
                    raise ConflictError(f"is already '{self.value}', cannot set to '{v}'", field, k)
            elif k == "not wildcard":
                values = [v] if type(v) == str else v
                for v in values:
                    self.exclude_wildcards.add(v)

        for k, v, *_ in constraints:
            if k == "min_length":
                if v >= self.min_length:
                    self.min_length = v
                else:
                    raise ConflictError(f"{v} < {self.min_length}", field, k)
            elif k == "allowed_chars":
                if set(v).issubset(set(self.allowed_chars)):
                    self.allowed_chars = v
                else:
                    raise ConflictError(f"{v} is not a subset of {self.allowed_chars}", field, k)
            elif k == "==":
                if self.is_array:
                    self.value.append(v)
                elif self.value is None or self.value == v:
                    self.value = v
                else:
                    raise ConflictError(f"is already '{self.value}', cannot set to '{v}'", field, k)
            elif k == "!=":
                self.exclude_values.add(v)

        if self.include_wildcards & self.exclude_wildcards:
            conflict_wildcards = "', '".join(sorted(self.include_wildcards & self.exclude_wildcards))
            raise ConflictError(f"wildcard(s) both included and excluded: '{conflict_wildcards}'", field)
        if self.include_wildcards:
            filtered_wildcards = {wc for wc in self.include_wildcards if not match_wildcards(wc, self.exclude_wildcards)}
            if not filtered_wildcards:
                incl_wc = "', '".join(sorted(self.include_wildcards))
                excl_wc = "', '".join(sorted(self.exclude_wildcards))
                raise ConflictError(f"filtered wildcard(s): ('{incl_wc}') are filtered out by ('{excl_wc}')", field)
            self.include_wildcards = filtered_wildcards
        if self.value is not None and set(self.value if type(self.value) == list else [self.value]) & self.exclude_values:
            if len(self.exclude_values) == 1:
                raise ConflictError(f"cannot be '{self.exclude_values.pop()}'", field)
            else:
                self.exclude_values = ", ".join(f"'{v}'" for v in sorted(self.exclude_values))
                raise ConflictError(f"cannot be any of ({self.exclude_values})", field)
        if self.value is not None and self.exclude_wildcards and match_wildcards(self.value, self.exclude_wildcards):
            if len(self.exclude_wildcards) == 1:
                raise ConflictError(f"cannot match '{self.exclude_wildcards.pop()}'", field)
            else:
                self.exclude_wildcards = "', '".join(sorted(self.exclude_wildcards))
                raise ConflictError(f"cannot match any of ('{self.exclude_wildcards}')", field)
        if self.value in (None, []):
            self.include_wildcards = sorted(self.include_wildcards)
        elif has_wildcards(self.value):
            self.include_wildcards = [self.value]
            self.value = None
        if self.value is not None and self.include_wildcards and not match_wildcards(self.value, self.include_wildcards):
            if len(self.include_wildcards) == 1:
                raise ConflictError(f"does not match '{self.include_wildcards.pop()}'", field)
            else:
                self.include_wildcards = "', '".join(sorted(self.include_wildcards))
                raise ConflictError(f"does not match any of ('{self.include_wildcards}')", field)

    def solve(self, left_attempts, environment):
        value = self.value
        history_values = {v["value"] for v in self.get_history(environment)}
        exclude_values = self.exclude_values | history_values
        while left_attempts and (
            value in (None, [])
            or set(value if self.is_array else [value]) & exclude_values  # noqa: W503
            or match_wildcards(value, self.exclude_wildcards)
        ):  # noqa: W503
            if self.include_wildcards:
                wc = random.choice(self.include_wildcards)
                v = expand_wildcards(wc, self.allowed_chars)
            else:
                v = "".join(random.choices(self.allowed_chars, k=self.min_length))
            value = [v] if self.is_array else v
            left_attempts -= 1
        return {"value": value, "left_attempts": left_attempts}
