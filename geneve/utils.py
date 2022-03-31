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

"""Util functions."""

import functools
import os

root_dir = os.path.abspath(os.path.join(os.path.split(__file__)[0], ".."))


def deep_merge(a, b, path=None):
    """Recursively merge two dictionaries"""

    for key in b:
        if key in a:
            path = (path or []) + [str(key)]
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                deep_merge(a[key], b[key], path)
            elif isinstance(a[key], list) and isinstance(b[key], list):
                a[key].extend(x for x in b[key] if x not in a[key])
            elif a[key] != b[key]:
                raise ValueError(f"Destination field already exists: {'.'.join(path)} ('{a[key]}' != '{b[key]}')")
        else:
            a[key] = b[key]
    return a


class TreeTraverser:
    """Automatic dispatching of node accessors."""

    def __init__(self):
        self.traversers = {}

    class NodeTraverser:
        def __init__(self, traversers, node_type):
            self.traversers = traversers
            self.node_type = node_type
            self.successful = 0
            self.total = 0

        def __call__(self, func):
            if self.node_type in self.traversers:
                raise ValueError(f"Duplicate traverser for {self.node_type}: {func.__name__}")
            self.traversers[self.node_type] = self

            @functools.wraps(func)
            def traverse(*args, **kwargs):
                self.total += 1
                ret = func(*args, **kwargs)
                self.successful += 1
                return ret

            self.traverse = traverse
            return traverse

    def __call__(self, node_type):
        return self.NodeTraverser(self.traversers, node_type)

    def traverse(self, node, *args, **kwargs):
        return self.traversers[type(node)].traverse(node, *args, **kwargs)

    def get_stats(self):
        return {k.__name__: (v.successful, v.total) for k, v in self.traversers.items()}
