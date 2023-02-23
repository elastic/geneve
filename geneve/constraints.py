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
import operator
from functools import reduce
from itertools import chain, product
from typing import List

from .utils.hdict import hdict


class ConflictError(ValueError):
    def __init__(self, msg, field, name=None):
        name = f" {name}" if name else ""
        super(ConflictError, self).__init__(f"Unsolvable constraints{name}: {field} ({msg})")


class Document:
    def __init__(self, field=None, name=None, value=None):
        self.environment = {}
        self.__constraints = hdict()
        if field is not None:
            self.append_constraint(field, name, value)

    def clone(self):
        doc = Document()
        doc.__constraints = copy.deepcopy(self.__constraints)
        doc.environment = self.environment
        return doc

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
        doc = self.clone()
        doc += other
        return doc

    def __eq__(self, other):
        return self.__constraints == other.__constraints

    def __repr__(self):
        return repr(self.__constraints)

    @staticmethod
    def from_dict(other):
        doc = Document()
        for field, constraints in other.items():
            doc.extend_constraints(field, constraints)
        return doc

    def solve(self, schema):
        from .solver import solver

        doc = {}
        for group, fields in self.__constraints.groups():
            solver.solve(doc, group, fields, schema, self.environment)
        return doc


class Branch(List[Document]):
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


Branch.Identity = Branch([Document()])


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
