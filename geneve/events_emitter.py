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

"""Functions for generating event documents that would trigger a given rule."""

from collections import namedtuple
from datetime import datetime, timedelta, timezone
from itertools import chain

from .events_emitter_eql import collect_constraints as collect_constraints_eql
from .events_emitter_eql import get_ast_stats  # noqa: F401
from .solver import emit_field
from .utils import deep_merge, has_wildcards, random, remove_none_fields, split_path

__all__ = ("SourceEvents",)

default_custom_schema = {
    "file.Ext.windows.zone_identifier": {
        "type": "long",
    },
    "process.parent.Ext.real.pid": {
        "type": "long",
    },
}

QueryGuess = namedtuple("QueryGuess", ["query", "type", "language", "ast"])
Event = namedtuple("Event", ["meta", "doc"])


def ast_from_eql_query(query):
    import eql

    with eql.parser.allow_negation, eql.parser.allow_runs, eql.parser.allow_sample, eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:  # noqa: E501
        return eql.parse_query(query)


def ast_from_kql_query(query):
    from . import kql

    return kql.to_eql(query, optimize=False)  # shortcut?


def guess_from_query(query):
    exceptions = []
    try:
        return QueryGuess(query, "eql", "eql", ast_from_eql_query(query))
    except Exception as e:
        exceptions.append(("EQL", e))
    try:
        return QueryGuess(query, "query", "kuery", ast_from_kql_query(query))
    except Exception as e:
        exceptions.append(("Kuery", e))

    def rank(e):
        line = getattr(e[1], "line", -1)
        column = getattr(e[1], "column", -1)
        return (line, column)

    lang, error = sorted(exceptions, key=rank)[-1]
    raise ValueError(f"{lang} query error: {error}") from error


def ast_from_rule(rule):
    if rule.type not in ("query", "eql"):
        raise NotImplementedError(f"Unsupported rule type: {rule.type}")
    elif rule.language == "eql":
        return ast_from_eql_query(rule.query)
    elif rule.language == "kuery":
        return ast_from_kql_query(rule.query)
    else:
        raise NotImplementedError(f"Unsupported query language: {rule.language}")


def emit_mappings(fields, schema):
    mappings = {}
    for field in fields:
        try:
            field_type = schema[field]["type"]
        except KeyError:
            field_type = "keyword"
        value = {"type": field_type}
        if has_wildcards(field):
            value = {
                "dynamic_templates": [
                    {
                        field: {
                            "path_match": field,
                            "mapping": value,
                        },
                    }
                ]
            }
        else:
            for part in reversed(split_path(field)):
                value = {"properties": {part: value}}
        deep_merge(mappings, value)
    return mappings


def events_from_branch(branch, environment, timestamp, meta, corpus):
    events = []
    for doc in branch.solve(environment):
        if timestamp:
            emit_field(doc, "@timestamp", timestamp[0].isoformat(timespec="microseconds"))
            timestamp[0] += timedelta(microseconds=100)
        if corpus:
            doc = deep_merge(next(corpus), doc, overwrite=True)
        remove_none_fields(doc)
        events.append(Event(meta, doc))
    return events


def events_from_root(root, environment, timestamp, corpus):
    return [events_from_branch(branch, environment, timestamp, root.meta, corpus) for branch in root]


class SourceEvents:
    schema = {}
    corpus = None
    stack_version = None
    max_branches = 10000

    def __init__(self, schema=None, *, corpus=None):
        self.__roots = []
        self.__environment = {}

        if schema is not None:
            self.schema = schema
        if corpus:
            self.corpus = iter(corpus)

    @classmethod
    def from_ast(cls, ast, *, meta=None):
        se = SourceEvents()
        se.add_ast(ast, meta=meta)
        return se

    @classmethod
    def from_query(cls, query, *, meta=None):
        se = SourceEvents()
        se.add_query(query, meta=meta)
        return se

    @classmethod
    def from_rule(cls, rule, *, meta=None):
        se = SourceEvents()
        se.add_rule(rule, meta=meta)
        return se

    def add_ast(self, ast, *, meta=None):
        root = collect_constraints_eql(ast, max_branches=self.max_branches)
        if len(root) == 0:
            raise ValueError("Root without branches")
        root.meta = meta
        root.optimize(self.schema, self.stack_version)
        self.try_emit(root)
        self.__roots.append(root)
        return root

    def add_query(self, query, *, meta=None):
        ast = guess_from_query(query).ast
        return self.add_ast(ast, meta=meta)

    def add_rule(self, rule, *, meta=None):
        ast = ast_from_rule(rule)
        return self.add_ast(ast, meta=meta)

    def fields(self):
        return set(chain(*(root.fields() for root in self.__roots)))

    def mappings(self, root=None, *, extra_fields=[]):
        fields = self.fields() if root is None else root.fields()
        return emit_mappings(fields | set(extra_fields), self.schema)

    def roots(self):
        return iter(self.__roots)

    def emit(self, root=None, *, timestamp=True, complete=False, count=1, corpus=None):
        corpus = iter(corpus) if corpus else self.corpus
        if timestamp:
            timestamp = [datetime.now(timezone.utc).astimezone()]
        if complete:
            if root:
                events = (events_from_root(root, self.__environment, timestamp, corpus) for _ in range(count))
            else:
                events = (events_from_root(root, self.__environment, timestamp, corpus) for _ in range(count) for root in self.__roots)
        else:
            if root:
                events = (events_from_branch(random.choice(root), self.__environment, timestamp, root.meta, corpus) for _ in range(count))
            else:
                events = (
                    events_from_branch(random.choice(root), self.__environment, timestamp, root.meta, corpus)
                    for root in random.choices(self.__roots, k=count)
                )
        return chain(*events)

    def try_emit(self, root):
        state = random.getstate()
        try:
            _ = events_from_root(root, environment={}, timestamp=False, corpus=None)
        finally:
            random.setstate(state)

    def __iter__(self):
        return self

    def __next__(self):
        return self.emit()

    def __len__(self):
        return len(self.__roots)
