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
from copy import copy

from ..constraints import ConflictError
from ..utils.solution_space import Strings
from . import Field, solver


def get_templ(field, constraints):
    templ = Strings()
    templ.min_star_len = 1
    templ.max_star_len = 12

    for k, v, *_ in constraints:
        if k in ("==", "wildcard"):
            if not isinstance(v, (list, tuple)):
                v = [v]
            new_value = templ & v
            if not new_value:
                v = "', '".join(sorted(v))
                raise ConflictError(f"not in {templ}: ('{v}')", field)
            templ = new_value
        elif k in ("!=", "not wildcard"):
            if not isinstance(v, (list, tuple)):
                v = [v]
            new_value = templ - v
            if not new_value:
                v = "', '".join(sorted(v))
                raise ConflictError(f"excluded by {templ}: ('{v}')", field)
            templ = new_value

    return templ


@solver.type("keyword")
@solver.type("wildcard")
class KeywordField(Field):
    valid_constraints = ["==", "!=", "wildcard", "not wildcard", "min_length", "allowed_chars"]
    alphabet = string.ascii_letters

    def __init__(self, field, constraints, field_constraints, schema):
        super().__init__(field, constraints, field_constraints, schema)

        self.templ = get_templ(field, field_constraints)
        self.value = []

        for k, v, *_ in constraints:
            if k in ("==", "wildcard"):
                if not isinstance(v, (list, tuple)):
                    v = [v]
                if self.is_array or not self.value:
                    self.value.append(self.templ & v)
                else:
                    new_value = self.value[0] & v
                    if not new_value:
                        v = "', '".join(sorted(v))
                        raise ConflictError(f"not in {self.value[0]}: ('{v}')", field)
                    self.value[0] = new_value
            elif k in ("!=", "not wildcard"):
                if not isinstance(v, (list, tuple)):
                    v = [v]
                if not self.value:
                    self.value.append(copy(self.templ))
                for i, value in enumerate(self.value):
                    new_value = value - v
                    if not new_value:
                        v = "', '".join(sorted(v))
                        raise ConflictError(f"excluded by {value}: ('{v}')", field)
                    value -= v
        if not self.value:
            self.value.append(copy(self.templ))

    def solve(self, left_attempts, environment):
        value = self.value
        hist = self.get_history(environment)
        value = [(v - hist).generate(alphabet=self.alphabet, max_attempts=left_attempts - 1)[0] for v in value]
        if not self.is_array:
            value = value[0]
        return {"value": value, "left_attempts": left_attempts}
