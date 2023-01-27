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
from . import solver


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


@solver("keyword", "==", "!=", "wildcard", "not wildcard", "min_length", "allowed_chars")
def solve_keyword_field(field, value, constraints, left_attempts, environment):
    allowed_chars = string.ascii_letters
    include_wildcards = set()
    exclude_wildcards = set()
    exclude_values = set()
    min_length = 3

    for k, v, *_ in constraints:
        if k == "wildcard":
            if type(v) == tuple and len(v) == 1:
                v = v[0]
            if type(value) == list:
                value.extend([v] if type(v) == str else v)
            elif type(v) == tuple:
                include_wildcards |= set(v)
            elif value is None or value == v:
                value = v
            else:
                raise ConflictError(f"is already '{value}', cannot set to '{v}'", field, k)
        elif k == "not wildcard":
            values = [v] if type(v) == str else v
            for v in values:
                exclude_wildcards.add(v)

    for k, v, *_ in constraints:
        if k == "min_length":
            if v >= min_length:
                min_length = v
            else:
                raise ConflictError(f"{v} < {min_length}", field, k)
        elif k == "allowed_chars":
            if set(v).issubset(set(allowed_chars)):
                allowed_chars = v
            else:
                raise ConflictError(f"{v} is not a subset of {allowed_chars}", field, k)
        elif k == "==":
            if type(value) == list:
                value.append(v)
            elif value is None or value == v:
                value = v
            else:
                raise ConflictError(f"is already '{value}', cannot set to '{v}'", field, k)
        elif k == "!=":
            exclude_values.add(v)

    if include_wildcards & exclude_wildcards:
        conflict_wildcards = "', '".join(sorted(include_wildcards & exclude_wildcards))
        raise ConflictError(f"wildcard(s) both included and excluded: '{conflict_wildcards}'", field)
    if include_wildcards:
        filtered_wildcards = {wc for wc in include_wildcards if not match_wildcards(wc, exclude_wildcards)}
        if not filtered_wildcards:
            incl_wc = "', '".join(sorted(include_wildcards))
            excl_wc = "', '".join(sorted(exclude_wildcards))
            raise ConflictError(f"filtered wildcard(s): ('{incl_wc}') are filtered out by ('{excl_wc}')", field)
        include_wildcards = filtered_wildcards
    if value is not None and set(value if type(value) == list else [value]) & exclude_values:
        if len(exclude_values) == 1:
            raise ConflictError(f"cannot be '{exclude_values.pop()}'", field)
        else:
            exclude_values = ", ".join(f"'{v}'" for v in sorted(exclude_values))
            raise ConflictError(f"cannot be any of ({exclude_values})", field)
    if value is not None and exclude_wildcards and match_wildcards(value, exclude_wildcards):
        if len(exclude_wildcards) == 1:
            raise ConflictError(f"cannot match '{exclude_wildcards.pop()}'", field)
        else:
            exclude_wildcards = "', '".join(sorted(exclude_wildcards))
            raise ConflictError(f"cannot match any of ('{exclude_wildcards}')", field)
    if value in (None, []):
        include_wildcards = sorted(include_wildcards)
    elif has_wildcards(value):
        include_wildcards = [value]
        value = None
    if value is not None and include_wildcards and not match_wildcards(value, include_wildcards):
        if len(include_wildcards) == 1:
            raise ConflictError(f"does not match '{include_wildcards.pop()}'", field)
        else:
            include_wildcards = "', '".join(sorted(include_wildcards))
            raise ConflictError(f"does not match any of ('{include_wildcards}')", field)
    while left_attempts and (
        value in (None, [])
        or set(value if type(value) == list else [value]) & exclude_values  # noqa: W503
        or match_wildcards(value, exclude_wildcards)
    ):  # noqa: W503
        if include_wildcards:
            wc = random.choice(include_wildcards)
            v = expand_wildcards(wc, allowed_chars)
        else:
            v = "".join(random.choices(allowed_chars, k=min_length))
        value = [v] if type(value) == list else v
        left_attempts -= 1
    return {"value": value, "left_attempts": left_attempts}
