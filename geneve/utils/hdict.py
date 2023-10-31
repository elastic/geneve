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

"""Hierarchical dictionary."""

from copy import copy

from . import split_path


def depth_first_keys(d, path=None):
    path = path or ()
    for k, v in d.items():
        p = path + (k,)
        if isinstance(v, dict):
            yield from depth_first_keys(v, p)
        else:
            yield ".".join(p)


def depth_first_items(d, path=None):
    path = path or ()
    for k, v in d.items():
        p = path + (k,)
        if isinstance(v, dict):
            yield from depth_first_items(v, p)
        else:
            yield ".".join(p), v


def tree_copy(tree):
    if isinstance(tree, dict):
        return {k: tree_copy(v) for k, v in tree.items()}
    return copy(tree)


class hdict:
    """Multi level dictionary with JSON path-like keys."""

    def __init__(self):
        self.__top_level = {}

    def __repr__(self):
        return repr(self.__top_level)

    def __eq__(self, other):
        return self.__top_level == other.__top_level

    def __copy__(self):
        o = hdict()
        o.__top_level = tree_copy(self.__top_level)
        return o

    def __getitem__(self, key):
        d = self.__top_level
        try:
            for part in split_path(key):
                d = d[part]
        except KeyError:
            raise KeyError(key)
        return d

    def __setitem__(self, key, value):
        d = self.__top_level
        parts = split_path(key)
        for part in parts[:-1]:
            d = d.setdefault(part, {})
        d[parts[-1]] = value

    def __delitem__(self, key):
        d = self.__top_level
        parts = split_path(key)
        try:
            for part in parts[:-1]:
                d = d[part]
        except KeyError:
            return
        del d[parts[-1]]

    def __iter__(self):
        return depth_first_keys(self.__top_level)

    def items(self):
        return depth_first_items(self.__top_level)

    def groups(self):
        groups = []
        tail = []
        for field in self:
            parts = split_path(field)[:-1]
            while parts:
                x = ".".join(parts)
                if x not in groups:
                    groups.append(x)
                parts = parts[:-1]
            tail = tail or [""]
        for group in groups + tail:
            group_dict = self[group] if group else self.__top_level
            yield group, {k: v for k, v in group_dict.items() if k and not isinstance(v, dict)}
