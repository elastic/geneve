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

"""Helpers for field value generation with constraints."""

import copy
import ipaddress
import operator
import random
import string
import time
from collections import namedtuple
from fnmatch import fnmatch
from functools import reduce, wraps
from itertools import chain, product
from typing import List

NumberLimits = namedtuple("NumberLimits", ["MIN", "MAX"])

# https://www.elastic.co/guide/en/elasticsearch/reference/current/number.html
LongLimits = NumberLimits(-(2**63), 2**63 - 1)

_max_attempts = 100000

ecs_constraints = {
    "pid": [(">", 0), ("<", 2**32)],
    "port": [(">", 0), ("<", 2**16)],
}


def get_ecs_constraints(field):
    if field in ecs_constraints:
        return ecs_constraints[field]
    field = field.split(".")[-1]
    if field in ecs_constraints:
        return ecs_constraints[field]
    return []


def has_wildcards(value):
    if type(value) == str:
        return value.find("?") + value.find("*") > -2
    return False


def match_wildcards(values, wildcards):
    if type(values) != list:
        values = [values]
    return any(fnmatch(v, wc) for v in values for wc in wildcards)


def match_nets(values, nets):
    if type(values) != list:
        values = [values]
    return any(v in net for v in values for net in nets)


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


def delete_by_cond(list, cond):
    for i in reversed([i for i, x in enumerate(list) if cond(x)]):
        del list[i]


def delete_use_once(list):
    def is_use_once(item):
        return len(item) > 2 and item[2] and item[2].get("use_once", False)

    delete_by_cond(list, is_use_once)


class ConflictError(ValueError):
    def __init__(self, msg, field, name=None):
        name = f" {name}" if name else ""
        super(ConflictError, self).__init__(f"Unsolvable constraints{name}: {field} ({msg})")


class solver:  # noqa: N801
    def __init__(self, field_type, *args):
        self.field_type = field_type
        self.valid_constraints = ("join_value", "max_attempts", "cardinality") + args

    def __call__(self, func):
        @wraps(func)
        def _solver(cls, field, value, constraints):
            join_values = []
            max_attempts = None
            cardinality = 0
            history = []
            augmented_constraints = constraints + get_ecs_constraints(field)
            for k, v, *_ in augmented_constraints:
                if k not in self.valid_constraints:
                    raise NotImplementedError(f"Unsupported {self.field_type} constraint: {k}")
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
                    history = cls.fields_history.setdefault(field, [])
            if max_attempts is None:
                max_attempts = _max_attempts
            if len(history) < cardinality:
                augmented_constraints.extend(("!=", v["value"]) for v in history)
            if not cardinality or len(history) < cardinality:
                value = func(cls, field, value, augmented_constraints, max_attempts + 1)
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


class Constraints:
    def __init__(self, field=None, name=None, value=None):
        self.fields_history = {}
        self.__constraints = {}
        if field is not None:
            self.append_constraint(field, name, value)

    def clone(self):
        c = Constraints()
        c.__constraints = copy.deepcopy(self.__constraints)
        c.fields_history = self.fields_history
        return c

    def append_constraint(self, field, name=None, value=None, flags=None):
        if field not in self.__constraints:
            if name == "==" and value is None:
                self.__constraints[field] = None
            else:
                self.__constraints[field] = []
        if self.__constraints[field] is None:
            if name != "==" or value is not None:
                raise ConflictError("cannot be non-null", field)
        else:
            if name == "==" and value is None:
                raise ConflictError("cannot be null", field)
            if name is not None and not (name == "!=" and value is None):
                self.__constraints[field].append((name, value, flags or {}))

    def extend_constraints(self, field, constraints):
        if field not in self.__constraints:
            self.__constraints[field] = copy.deepcopy(constraints)
        elif self.__constraints[field] is None:
            if constraints is not None:
                raise ConflictError("cannot be non-null", field)
        else:
            if constraints is None:
                raise ConflictError("cannot be null", field)
            self.__constraints[field].extend(constraints)

    def fields(self):
        return set(self.__constraints)

    def __iadd__(self, other):
        for field, constraints in other.__constraints.items():
            self.extend_constraints(field, constraints)
        return self

    def __add__(self, other):
        c = self.clone()
        c += other
        return c

    def __eq__(self, other):
        return self.__constraints == other.__constraints

    def __repr__(self):
        return repr(self.__constraints)

    @staticmethod
    def from_dict(other):
        c = Constraints()
        for field, constraints in other.items():
            c.extend_constraints(field, constraints)
        return c

    @solver("boolean", "==", "!=")
    def solve_boolean_constraints(self, field, value, constraints, left_attempts):
        for k, v, *_ in constraints:
            if k == "==":
                v = bool(v)
                if value is None or value == v:
                    value = v
                else:
                    raise ConflictError(f"is already {value}, cannot set to {v}", field, k)
            elif k == "!=":
                v = bool(v)
                if value is None or value != v:
                    value = not v
                else:
                    raise ConflictError(f"is already {value}, cannot set to {not v}", field, k)

        if left_attempts and value is None:
            value = random.choice((True, False))
            left_attempts -= 1
        return {"value": value, "left_attempts": left_attempts}

    @solver("long", "==", "!=", ">=", "<=", ">", "<")
    def solve_long_constraints(self, field, value, constraints, left_attempts):
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

    @solver("date", "==")
    def solve_date_constraints(self, field, value, constraints, left_attempts):
        for k, v, *_ in constraints:
            if k == "==":
                if value is None or value == v:
                    value = v
                else:
                    raise ConflictError(f"is already {value}, cannot set to {v}", field, k)

        if left_attempts and value is None:
            value = int(time.time() * 1000)
            left_attempts -= 1
        return {"value": value, "left_attempts": left_attempts}

    @solver("geo_point")
    def solve_geo_point_constraints(self, field, value, constraints, left_attempts):
        if left_attempts and value is None:
            value = [0, 0]
            left_attempts -= 1
        return {"value": value, "left_attempts": left_attempts}

    @solver("ip", "==", "!=", "in", "not in")
    def solve_ip_constraints(self, field, value, constraints, left_attempts):
        include_nets = set()
        exclude_nets = set()
        exclude_addrs = set()

        for k, v, *_ in constraints:
            if k == "==":
                v = str(v)
                try:
                    v = ipaddress.ip_address(v)
                except ValueError:
                    pass
                else:
                    if type(value) == list:
                        value.extend(v if type(v) == list else [v])
                    elif value is None or value == v:
                        value = v
                    else:
                        raise ConflictError(f"is already {value}, cannot set to {v}", field, k)
                    continue
                try:
                    include_nets.add(ipaddress.ip_network(v))
                except ValueError:
                    raise ValueError(f"Not an IP address or network: {v}")
            elif k == "!=":
                v = str(v)
                try:
                    exclude_addrs.add(ipaddress.ip_address(v))
                    continue
                except ValueError:
                    pass
                try:
                    exclude_nets.add(ipaddress.ip_network(v))
                except ValueError:
                    raise ValueError(f"Not an IP address or network: {v}")
            elif k == "in":
                values = [v] if type(v) == str else v
                for v in values:
                    try:
                        include_nets.add(ipaddress.ip_network(str(v)))
                    except ValueError:
                        raise ValueError(f"Not an IP network: {str(v)}")
            elif k == "not in":
                values = [v] if type(v) == str else v
                for v in values:
                    try:
                        exclude_nets.add(ipaddress.ip_network(str(v)))
                    except ValueError:
                        raise ValueError(f"Not an IP network: {str(v)}")

        if include_nets & exclude_nets:
            intersecting_nets = ", ".join(str(net) for net in sorted(include_nets & exclude_nets))
            raise ConflictError(f"net(s) both included and excluded: {intersecting_nets}", field)
        if value is not None and exclude_addrs and set(value if type(value) == list else [value]) & exclude_addrs:
            if len(exclude_addrs) == 1:
                raise ConflictError(f"cannot be {exclude_addrs.pop()}", field)
            else:
                exclude_addrs = ", ".join(str(v) for v in sorted(exclude_addrs))
                raise ConflictError(f"cannot be any of ({exclude_addrs})", field)
        if value is not None and exclude_nets and match_nets(value, exclude_nets):
            if len(exclude_nets) == 1:
                raise ConflictError(f"cannot be in net {exclude_nets.pop()}", field)
            else:
                exclude_nets = ", ".join(str(v) for v in sorted(exclude_nets))
                raise ConflictError(f"cannot be in any of nets ({exclude_nets})", field)
        ip_versions = sorted(ip.version for ip in include_nets | exclude_nets | exclude_addrs) or [4]
        include_nets = sorted(include_nets, key=lambda x: (x.version, x))
        while left_attempts and (
            value in (None, [])
            or set(value if type(value) == list else [value]) & exclude_addrs  # noqa: W503
            or match_nets(value, exclude_nets)
        ):  # noqa: W503
            if include_nets:
                net = random.choice(include_nets)
                v = net[random.randrange(net.num_addresses)]
            else:
                bits = 128 if random.choice(ip_versions) == 6 else 32
                v = ipaddress.ip_address(random.randrange(1, 2**bits))
            value = [v] if type(value) == list else v
            left_attempts -= 1
        value = [v.compressed for v in value] if type(value) == list else v.compressed
        return {"value": value, "left_attempts": left_attempts}

    @solver("keyword", "==", "!=", "wildcard", "not wildcard", "min_length", "allowed_chars")
    def solve_keyword_constraints(self, field, value, constraints, left_attempts):
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

    def solve_constraints(self, field, constraints, schema):
        field_type = schema.get("type", "keyword")
        solver = getattr(self, f"solve_{field_type}_constraints", None)
        if not solver:
            raise NotImplementedError(f"Constraints solver not implemented: {field_type}")
        if "array" in schema.get("normalize", []):
            value = []
        else:
            value = None
        return solver(field, value, constraints)["value"]

    def solve(self, schema):
        for field, constraints in self.__constraints.items():
            value = None
            if constraints is not None:
                field_schema = schema.get(field, {})
                value = self.solve_constraints(field, constraints, field_schema)
            yield field, value


class Branch(List[Constraints]):
    def __iter__(self):
        if not self:
            raise ValueError("Branch without constraints")
        return super(Branch, self).__iter__()

    def __mul__(self, other):
        return Branch(x + y for x in self for y in other)

    def fields(self):
        return set(chain(*(constraints.fields() for constraints in self)))

    def solve(self, schema):
        return (constraints.solve(schema) for constraints in self)


Branch.Identity = Branch([Constraints()])


class Root(List[Branch]):
    meta = None

    def __iter__(self):
        if not self:
            raise ValueError("Root without branches")
        return super(Root, self).__iter__()

    def fields(self):
        return set(["@timestamp"]) | set(chain(*(branch.fields() for branch in self)))

    def constraints(self):
        return chain(*self)

    @classmethod
    def chain(cls, roots):
        return Root(chain(*roots))

    @classmethod
    def product(cls, roots):
        return Root(reduce(operator.mul, branches, Branch.Identity) for branches in product(*roots))
