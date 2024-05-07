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

"""Infinite sets."""

import itertools
import string
from fnmatch import fnmatchcase

from infinite_sets import everything

from . import expand_wildcards, has_wildcards, random


class Strings:
    min_star_len = 0
    max_star_len = 32

    def __init__(self, iterable=None, *, exclude=None):
        self.__set = everything()
        self.__exclude = None
        if iterable not in (None, everything()):
            self.__set &= {(s, has_wildcards(s)) for s in iterable}
        if self.__set and exclude:
            if not isinstance(exclude, Strings):
                exclude = Strings(exclude)
            self.__exclude = exclude

    def __copy__(self):
        obj = type(self).__new__(self.__class__)
        obj.__dict__.update(self.__dict__)
        if self.__set != everything():
            obj.__set = self.__set.copy()
        if self.__exclude is not None:
            obj.__exclude = self.__exclude.__copy__()
        return obj

    def __repr__(self):
        if self.__set == everything():
            r = str(self.__set)
        elif self.__set:
            r = "{'" + "', '".join(sorted(str(x[0]) for x in self.__set)) + "'}"
        else:
            r = "{}"
        if self.__exclude:
            return self.__class__.__name__ + f"({r}, exclude={self.__exclude})"
        else:
            return self.__class__.__name__ + f"({r})"

    def __iter__(self):
        if self.__set == everything():
            return iter(self.__set)
        return (x[0] for x in self.__set)

    def __eq__(self, other):
        if not isinstance(other, Strings):
            other = Strings(other)
        return self.__set == other.__set and (self.__exclude == other.__exclude or not (self.__exclude or other.__exclude))

    def __bool__(self):
        return bool(self.__set)

    def __contains__(self, item):
        if self.__exclude and item in self.__exclude:
            return False
        if self.__set == everything():
            return True
        item = str(item).lower()
        for value, wc in self.__set:
            value = str(value).lower()
            if item == value:
                return True
            if wc and fnmatchcase(item, value):
                return True
        return False

    def __and__(self, other):
        ss = self.__copy__()
        ss &= other
        return ss

    def __or__(self, other):
        ss = self.__copy__()
        ss |= other
        return ss

    def __sub__(self, other):
        ss = self.__copy__()
        ss -= other
        return ss

    def __rand__(self, other):
        return self.__and__(other)

    def __ror__(self, other):
        return self.__or__(other)

    def __iand__(self, other):
        if not isinstance(other, Strings):
            other = Strings(other)
        if other.__set == everything():
            return self
        if self.__set == everything():
            other = other.__copy__()
            if self.__exclude:
                other -= self.__exclude
            self.__set = other.__set
            self.__exclude = other.__exclude
            return self
        new_set = set()
        for s in self.__set:
            for o in other.__set:
                if s == o:
                    new_set.add(s)
                elif o[1] and fnmatchcase(s[0].lower(), o[0].lower()):  # o has wildcards
                    new_set.add(s)
                elif s[1] and fnmatchcase(o[0].lower(), s[0].lower()):  # s has wildcards
                    new_set.add(o)
        self.__set = new_set
        return self

    def __ior__(self, other):
        if not isinstance(other, Strings):
            other = Strings(other)
        if other.__set == everything():
            self.__set = everything()
            self.__exclude = None
            return self
        if self.__set == everything():
            if self.__exclude:
                self.__exclude -= other
            return self
        if not other.__set:
            return self
        if not self.__set:
            self.__set = other.__set.copy()
            return self
        if self.__exclude is None:
            self.__exclude = Strings({})
        new = set()
        for s in self.__set:
            for o in other.__set:
                if o[1] and fnmatchcase(s[0].lower(), o[0].lower()):  # o has wildcards
                    new.add(o)
                elif s[1] and fnmatchcase(o[0].lower(), s[0].lower()):  # s has wildcards
                    new.add(s)
                else:
                    new.add(s)
                    new.add(o)
        self.__set = new
        self.__exclude -= {x[0] for x in new}
        return self

    def __isub__(self, other):
        if not isinstance(other, Strings):
            other = Strings(other)
        if other.__set == everything():
            self.__set = set()
            self.__exclude = None
            return self
        if not self.__set or not other.__set:
            return self
        if self.__set == everything():
            if self.__exclude is None:
                self.__exclude = Strings({})
            self.__exclude |= other
            return self
        if self.__exclude is None:
            self.__exclude = Strings({})
        sub = set()
        excl = set()
        for s in self.__set:
            for o in other.__set:
                if s == o:
                    sub.add(s)
                elif o[1] and fnmatchcase(s[0].lower(), o[0].lower()):  # o has wildcards
                    sub.add(s)
                elif s[1] and fnmatchcase(o[0].lower(), s[0].lower()):  # s has wildcards
                    excl.add(o[0])
                elif s[1] and o[1]:  # both have wildcards
                    excl.add(o[0])
        self.__set -= sub
        self.__exclude |= excl
        return self

    def __mul__(self, other):
        return Strings(product(self, other))

    def __rmul__(self, other):
        return Strings(product(other, self))

    def __generate_items(self, max_attempts):
        if not self.__set:
            raise IndexError("Cannot choose from an empty set")
        if self.__exclude and not max_attempts:
            raise ValueError("`exclude` requires `max_attempts`")
        return None if self.__set == everything() else sorted(self.__set)

    def __generate_one(self, items, alphabet):
        if items is None:
            return "".join(random.choices(alphabet, k=random.randint(self.min_star_len, self.max_star_len)))
        item, has_wildcards = random.choice(items)
        if has_wildcards:
            return expand_wildcards(item, alphabet, self.min_star_len, self.max_star_len)
        return item

    def __generate(self, items, alphabet, max_attempts):
        if not self.__exclude:
            return self.__generate_one(items, alphabet)
        for _ in range(max_attempts):
            val = self.__generate_one(items, alphabet)
            if val not in self.__exclude:
                return val
        raise ValueError(f"Failed to generate after {max_attempts} attempts")

    def generate(self, *, alphabet=None, max_attempts=None, count=1):
        alphabet = alphabet or string.ascii_letters + string.digits
        items = self.__generate_items(max_attempts)
        return [self.__generate(items, alphabet, max_attempts) for _ in range(count)]

    def generator(self, *, alphabet=None, max_attempts=None):
        alphabet = alphabet or string.ascii_letters + string.digits
        items = self.__generate_items(max_attempts)
        while True:
            yield self.__generate(items, alphabet, max_attempts)


def product(A, B):
    if isinstance(B, dict):
        return ((a, b) for a in A for b in B[a])
    if isinstance(A, dict):
        return ((a, b) for b in B for a in A[b])
    return itertools.product(A, B)


def transpose(A):
    return {a: {k for k, v in A.items() if a in v} for a in set.union(*A.values())}
