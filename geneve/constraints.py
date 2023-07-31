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

import operator
from copy import copy
from functools import reduce
from itertools import chain, product
from typing import List

from .utils.hdict import hdict


class ConflictError(ValueError):
    def __init__(self, msg, field, name=None):
        name = f" {name}" if name else ""
        super().__init__(f"Unsolvable constraints{name}: {field} ({msg})")


class Document:
    def __init__(self, field=None, name=None, value=None):
        self.__aliases = {}
        self.__constraints = hdict()
        if field is not None:
            self.append_constraint(field, name, value)

    def clone(self):
        doc = Document()
        doc.__aliases = {k: copy(v) for k, v in self.__aliases.items()}
        doc.__constraints = copy(self.__constraints)
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
            self.__constraints[field] = copy(constraints)
        elif self.__constraints[field] is None:
            if constraints is not None:
                raise ConflictError("cannot be non-null", field)
        else:
            if constraints is None:
                raise ConflictError("cannot be null", field)
            self.__constraints[field].extend(constraints)

    def fields(self):
        return set(self.__constraints)

    def entities(self):
        return self.__entities.values()

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

    def join_fields(self, doc, fields):
        doc = doc.clone()
        for i, field in enumerate(fields):
            # remembed the field names referring to the same join field
            self.__aliases.setdefault(i, []).append(field)
            # take the first name as reference so that during generation we
            # have a proper ECS field name and type
            alias = self.__aliases[i][0]
            # concatenate all the constraints that refer to the same join field
            if field in doc.__constraints:
                self.extend_constraints(alias, doc.__constraints[field])
            else:
                self.append_constraint(alias)
            # each of the depending fields need access to the join field
            doc.append_constraint(field, "join_value", (self, alias))
        return doc

    def get_join_doc(self):
        for field, constraints in self.__constraints.items():
            for k, v, *_ in constraints or []:
                if k == "join_value":
                    return v[0]

    def optimize(self, *args, **kwargs):
        from .solver import solver

        self.__entities = {group: solver.new_entity(group, fields, *args, **kwargs) for group, fields in self.__constraints.groups()}

    def solve(self, join_doc, environment):
        doc = {}
        for entity in self.entities():
            entity.solve(doc, join_doc, environment)
        return doc


class Branch(List[Document]):
    def __iter__(self):
        if not self:
            raise ValueError("Branch without constraints")
        return super().__iter__()

    def __mul__(self, other):
        return Branch(x + y for x in self for y in other)

    def fields(self):
        return set(chain(*(constraints.fields() for constraints in self)))

    def __get_join_doc(self):
        for constraints in self:
            join_doc = constraints.get_join_doc()
            if join_doc:
                return join_doc

    def optimize(self, *args, **kwargs):
        self.join_doc = self.__get_join_doc()
        if self.join_doc:
            self.join_doc.optimize(*args, **kwargs)
        for constraints in self:
            constraints.optimize(*args, **kwargs)

    def solve(self, environment):
        join_doc = self.join_doc.solve(None, environment) if self.join_doc else None
        return (constraints.solve(join_doc, environment) for constraints in self)


Branch.Identity = Branch([Document()])


class Root(List[Branch]):
    meta = None

    def fields(self):
        return set(["@timestamp"]) | set(chain(*(branch.fields() for branch in self)))

    def constraints(self):
        return chain(*self)

    def optimize(self, *args, **kwargs):
        for branch in self:
            branch.optimize(*args, **kwargs)

    @classmethod
    def chain(cls, roots):
        return Root(chain(*roots))

    @classmethod
    def product(cls, roots):
        return Root(reduce(operator.mul, branches, Branch.Identity) for branches in product(*roots))
