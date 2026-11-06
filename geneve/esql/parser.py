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

"""Parse the supported subset of ES|QL and translate it to the EQL AST.

Only `FROM` and `WHERE` are interpreted. `KEEP`, `DROP`, `SORT` and `LIMIT` are
accepted (and ignored) when they come after every `WHERE`. Everything else
raises `NotImplementedError`, so that unsupported queries are reported instead
of silently generating events that do not match.
"""

import ipaddress
import json
import re
from collections import namedtuple
from pathlib import Path

import eql
from lark import Lark, Token, Tree
from lark.exceptions import UnexpectedInput
from lark.visitors import Interpreter

from .. import kql
from ..events_emitter_eql import collect_constraints, prune_conflicts
from ..utils import has_wildcards, regex_gen
from .errors import EsqlParseError
from .lexical import (
    STRING_RE,
    assignment,
    call,
    identifiers,
    is_name,
    split_keyword,
    split_pattern,
    split_top,
    strip_comments,
)

__all__ = ("Aggregate", "EsqlQuery", "EsqlStats", "parse", "to_eql")

# `where` is the plain translation of the WHERE clauses before STATS, `stats` is None when there is no STATS
# `aliases` are the fields that an EVAL makes, that the documents do not have
EsqlQuery = namedtuple("EsqlQuery", ["sources", "metadata", "where", "stats", "aliases"], defaults=(None, ()))
# `where` is the translation of the WHERE clauses after STATS, about the aliases of the aggregates and the BY fields
# `by` are the names of the keys, `fields` those that are fields of the documents and `join` the fields of the documents that the
# keys depend on, which are the same for the documents of a group. `simple` is for the aggregates that a condition can be about:
# a count of the documents, or of the values of a field
# `expanded` are the fields of the documents that MV_EXPAND expands before STATS
EsqlStats = namedtuple("EsqlStats", ["aggregates", "by", "fields", "join", "where", "expanded"], defaults=((),))
Aggregate = namedtuple("Aggregate", ["alias", "function", "argument", "simple"])
# what a function of a field makes of it in a comparison: only the ones that the generation can undo
# `fields` are the fields of the documents that it can be made of, the first that has a value for COALESCE, and `total` is
# that it has a value whatever the fields have (a literal that is not null is where COALESCE ends)
Scalar = namedtuple("Scalar", ["function", "fields", "total"])
SCALAR_FUNCTIONS = ("to_lower", "to_string")
LITERAL_RE = re.compile(rf"{STRING_RE.pattern}|[+-]?\d+(\.\d+)?|true|false", re.IGNORECASE)
NULL_RE = re.compile("null", re.IGNORECASE)

# commands that do not change which documents match a preceding WHERE, LIMIT does
IGNORED_COMMANDS = ("KEEP", "DROP", "SORT", "LIMIT")
# aggregate functions that tell how many documents there are, VALUES just collects what they have
COUNTING_FUNCTIONS = ("count", "count_distinct")
# the time is not a field that the documents can be made to share
NOT_JOINED = ("@timestamp",)
# the names of the fields that GROK takes out of a text, in its patterns (the names are all that is not a separator)
GROK_NAMES = re.compile(r"%\{\w+:([^}:]+)(?::\w+)?\}|\(\?<([^>]+)>")
DISSECT_KEYS = re.compile(r"%\{([^}]*)\}")

# fields that describe the indexed document and are not part of its content
METADATA_FIELDS = ("_id", "_index", "_version", "_ignored", "_index_mode", "_source", "_score")

# same default as SourceEvents.max_branches
MAX_BRANCHES = 10000

POSITIVE_CONSTRAINTS = ("==", "wildcard", "in")

grammar_file = Path(__file__).parent / "esql.g"
lark_parser = Lark(grammar_file.read_text(), start="query", parser="lalr", propagate_positions=True)

field_part_re = re.compile(r"`(?:[^`]|``)+`|[^.`]+")
escape_re = re.compile(r"\\(.)", re.DOTALL)

string_escapes = {'"': '"', "\\": "\\", "n": "\n", "r": "\r", "t": "\t"}


def lark_parse(text):
    if not text.strip():
        raise EsqlParseError("No query provided", 0, 0, "")

    lines = text.splitlines() or [""]
    try:
        return lark_parser.parse(text)
    except UnexpectedInput as exc:
        line = exc.line - 1 if exc.line and exc.line > 0 else len(lines) - 1
        column = exc.column - 1 if exc.column and exc.column > 0 else len(lines[-1])
        raise EsqlParseError("Invalid syntax", line, column, "\n".join(lines[max(line - 1, 0) : line + 1])) from exc


def split_field(name):
    # a quoted name with dots (`a.b`) is the path a -> b, as Elasticsearch resolves it, and
    # the constraints collector knows nothing about quoted dots
    parts = []
    for part in field_part_re.findall(name):
        if part.startswith("`"):
            part = part[1:-1].replace("``", "`")
        parts.extend(part.split("."))
    # field names with wildcards are not plain fields
    if not all(parts) or any("*" in part or "?" in part for part in parts):
        raise NotImplementedError(f"Unsupported field name: {name}")
    return parts


def unescape(match):
    try:
        return string_escapes[match.group(1)]
    except KeyError:
        raise NotImplementedError(f"Unsupported escape sequence in string: \\{match.group(1)}") from None


def string_value(token):
    text = str(token)
    if text.startswith('"""'):
        return text[3:-3]  # triple-quoted strings have no escapes
    return escape_re.sub(unescape, text[1:-1])


class EsqlToEql(Interpreter):
    def __init__(self, text):
        self.text = text
        self.sources = []
        self.metadata_fields = []
        self.wheres = []
        self.blocking = None  # LIMIT was seen, neither a WHERE nor a STATS is allowed after it
        self.stats = None
        self.post_wheres = []
        self.evals = {}  # what the EVALs before STATS make, and the fields of the documents that they depend on
        self.made_by = {}  # the command that made each of them: EVAL, GROK or DISSECT
        self.renames = {}  # what an EVAL makes by naming a field of the documents again: the field that it is
        self.unknown_expansions = []  # what an EVAL makes that MV_EXPAND expands, of which the number of values is not known
        self.expanded = []  # the fields of the documents that MV_EXPAND expands before STATS
        self.scalars = {}  # what an EVAL makes that is a field, or TO_LOWER or TO_STRING of one: a WHERE can ask for it
        # the fields that those are, they are what the WHERE asks for and not an alias: by id, and the objects are kept
        # so that the id is not the one of another that comes after (when they are freed it can be reused)
        self.resolved = {}
        # the conditions on the first field that has a value (COALESCE), by id, to put together those that are about the same fields
        self.over = {}
        self.times = set()  # the aggregates of STATS that are the first or the last time of the documents: MIN or MAX of @timestamp
        self.recent = set()  # what an EVAL after STATS makes of one of those and now: how long ago it was
        self.overwritten = set()  # the names that an EVAL after STATS makes: they are no longer what STATS said

    @staticmethod
    def reject(tree, message):
        raise NotImplementedError(f"Unsupported {message}")

    def query(self, tree):
        self.visit_children(tree)
        if not self.wheres:
            where = eql.ast.Boolean(True)
        elif len(self.wheres) == 1:
            where = self.wheres[0]
        else:
            terms = self.merge_over(self.wheres)
            where = eql.ast.And(terms) if len(terms) > 1 else terms[0]
        stats = None
        if self.stats is not None:
            aggregates, by, fields, join = self.stats
            post_where = eql.ast.And(self.post_wheres) if len(self.post_wheres) > 1 else (self.post_wheres or [eql.ast.Boolean(True)])[0]
            stats = EsqlStats(tuple(aggregates), tuple(by), tuple(fields), tuple(join), post_where, tuple(self.expanded))
        aliases = tuple(alias for alias, depends in self.evals.items() if alias not in depends)
        return EsqlQuery(tuple(self.sources), tuple(self.metadata_fields), where, stats, aliases)

    # commands

    def from_cmd(self, tree):
        for child in tree.children:
            if isinstance(child, Tree):
                self.visit(child)

    def other_source(self, tree):
        self.reject(tree, f"source command: {str(tree.children[0]).upper()}")

    def source(self, tree):
        token = tree.children[0]
        self.sources.append(string_value(token) if token.type == "STRING" else str(token))

    def metadata(self, tree):
        self.metadata_fields.extend(str(token) for token in tree.children if token.type == "FIELD")

    def where_cmd(self, tree):
        if self.blocking:
            self.reject(tree, f"pipe before WHERE: {self.blocking}")
        expression = self.boolean(tree.children[1])
        if self.stats is not None:
            expression = self.drop_recent(expression)
            for node in expression:
                if isinstance(node, eql.ast.Field) and self.field_key(node.render()) in self.overwritten:
                    self.reject(tree, f"WHERE on a field made by EVAL after STATS: {node.render()}")
            self.post_wheres.append(expression)
            return
        for node in expression:
            if isinstance(node, eql.ast.Field) and id(node) not in self.resolved and self.field_key(node.render()) in self.evals:
                made_by = self.made_by.get(self.field_key(node.render()), "EVAL")
                self.reject(tree, f"WHERE on a field made by {made_by}: {node.render()}")
        self.wheres.append(expression)

    def other_cmd(self, tree):
        name = str(tree.children[0]).upper()
        body = str(tree.children[1]) if len(tree.children) > 1 else ""
        if name == "STATS":
            return self.stats_command(tree, strip_comments(body))
        if name == "EVAL":
            return self.eval_command(tree, strip_comments(body))
        if name in ("GROK", "DISSECT"):
            return self.extraction_command(tree, name, strip_comments(body))
        if name == "MV_EXPAND":
            return self.expand_command(tree, strip_comments(body))
        if name not in IGNORED_COMMANDS:
            self.reject(tree, f"command: {name}")
        if name == "LIMIT" and re.fullmatch(r"\s*0+\s*", strip_comments(body)):
            self.reject(tree, "LIMIT 0, no document is returned")
        if name == "LIMIT":
            self.blocking = self.blocking or name

    @staticmethod
    def field_key(name):
        """Return the name of a field as the constraints know it, with no quotes."""
        return ".".join(split_field(name))

    @staticmethod
    def field_name(name):
        base, *path = split_field(name)
        return eql.ast.Field(base, path).render()

    def dependencies(self, expression):
        """Return the fields of the documents that an expression depends on, what an EVAL makes is by what it depends on."""
        found = []
        for name in identifiers(expression):
            key = self.field_key(name)
            for field in self.evals.get(key, [key]):
                if field not in found and field not in NOT_JOINED:
                    found.append(field)
        return found

    def eval_command(self, tree, body):
        # what an EVAL makes is not a field of the documents, no WHERE can ask for it, and it is not
        # of interest after STATS (nothing asks for it, a WHERE after it is checked later)
        for item in split_top(body):
            made = assignment(item)
            if made and self.stats is not None:
                key = self.field_key(made[0])
                recent = self.is_recent(made[1])  # by what the names were before this one
                self.overwritten.add(key)
                self.times.discard(key)  # whatever it was, it is no longer what STATS made
                (self.recent.add if recent else self.recent.discard)(key)
            elif made:
                key = self.field_key(made[0])
                scalar = self.scalar_of(made[1])  # before the alias takes the place of the field that it may be made of
                self.evals[key] = self.dependencies(made[1])
                if scalar is None:
                    self.scalars.pop(key, None)
                else:
                    self.scalars[key] = scalar
                self.made_by[key] = "EVAL"
                self.renames.pop(key, None)
                if is_name(made[1]) and len(self.evals[key]) == 1:
                    self.renames[key] = self.evals[key][0]

    def extraction_command(self, tree, name, body):
        # GROK and DISSECT make fields out of what they read, as an EVAL does, if the text does not match they are null
        read, patterns = split_pattern(body)
        depends = self.dependencies(read)
        texts = STRING_RE.findall(patterns)
        if name == "DISSECT":
            texts = texts[:1]  # what follows the pattern are options, which have strings of their own
        for key in (self.field_key(made) for made in self.extracted(tree, name, texts)):
            if self.stats is not None:
                self.overwritten.add(key)
                self.times.discard(key)
                self.recent.discard(key)
            else:
                self.evals[key] = depends
                self.made_by[key] = name
                self.renames.pop(key, None)
                self.scalars.pop(key, None)

    def extracted(self, tree, name, texts):
        """Return the names of the fields that the patterns take out of a text."""
        for text in texts:
            if name == "GROK":
                for match in GROK_NAMES.finditer(text):
                    yield next(group for group in match.groups() if group)
                continue
            for key in DISSECT_KEYS.findall(text):
                key = re.sub(r"/\d+$", "", re.sub(r"->$", "", key))  # the order of what is appended, and the modifier to skip empties
                if key[:1] in ("*", "&"):
                    self.reject(tree, "DISSECT pattern with reference keys, the names of the fields are not those of the pattern")
                key = key[1:] if key[:1] == "+" else key
                if key and key[:1] != "?":
                    yield key

    def expand_command(self, tree, body):
        # the documents have one value of the field, which is one row, so it is as if nothing was expanded
        if not is_name(body):
            self.reject(tree, "MV_EXPAND of an expression")
        key = self.field_key(body.strip())
        if self.stats is not None:
            return
        if key in self.evals:
            # what GROK and DISSECT take out is one text; a rename is the field that it renames; and what the
            # functions make may be many values, how many is what STATS counts and it is not known
            if self.made_by.get(key) == "EVAL":
                if key in self.renames:
                    if self.renames[key] not in self.expanded:
                        self.expanded.append(self.renames[key])
                else:
                    self.unknown_expansions.append(key)
        elif key not in self.expanded:
            self.expanded.append(key)

    def stats_command(self, tree, body):
        if self.stats is not None:
            self.reject(tree, "second STATS")
        if self.blocking:
            self.reject(tree, f"pipe before STATS: {self.blocking}")
        if self.unknown_expansions:
            self.reject(tree, f"STATS after MV_EXPAND of a field made by EVAL: {self.unknown_expansions[0]}")
        aggregations, by = split_keyword(body, "by")
        aggregates = [self.aggregate(tree, item) for item in self.items(aggregations, body, "STATS without aggregates")]
        keys = self.items(by, body, "BY without keys") if by is not None else []
        names, fields, join = [], [], []
        for item in keys:
            name, depends = self.key(tree, item)
            if name:
                names.append(name)
            if name and is_name(item) and self.field_key(item) not in self.evals:
                fields.append(name)
            join.extend(field for field in depends if field not in join)
        self.stats = (aggregates, names, fields, join)

    @staticmethod
    def items(text, command, message):
        items = [item.strip() for item in split_top(text)]
        if not text.strip() or not all(items):
            raise EsqlParseError(f"Invalid syntax: {message}", 0, 0, command)
        return items

    def aggregate(self, tree, item):
        made = assignment(item)
        if made is None:
            self.reject(tree, "aggregate without a name")
        alias, expression = self.field_name(made[0]), made[1]
        function = call(expression)
        if function is None:
            self.reject(tree, f"aggregate {alias}, it must be a function")
        name, arguments = function[0].lower(), function[1]
        if name == "count" and arguments in ("", "*"):
            return Aggregate(alias, name, None, True)
        if (name in COUNTING_FUNCTIONS or name == "values") and is_name(arguments) and self.field_key(arguments) not in self.evals:
            if self.field_key(arguments) in METADATA_FIELDS:
                self.reject(tree, f"predicate on metadata field: {arguments}")
            return Aggregate(alias, name, self.field_name(arguments), True)
        # the time that the documents are written at, not one that an EVAL or a GROK before STATS made of it
        if name in ("min", "max") and arguments.strip() == "@timestamp" and self.field_key("@timestamp") not in self.evals:
            self.times.add(self.field_key(alias))
        return Aggregate(alias, name, None, False)

    def is_recent(self, expression):
        """Is it `DATE_DIFF("unit", <first or last time of the documents>, NOW())`, how long ago the documents were written?"""
        made = call(expression)
        if made is None or made[0].lower() != "date_diff":
            return False
        args = [arg.strip() for arg in split_top(made[1])]
        return (
            len(args) == 3
            and re.fullmatch(STRING_RE.pattern, args[0]) is not None
            and is_name(args[1])
            and self.field_key(args[1]) in self.times
            and re.fullmatch(r"now\s*\(\s*\)", args[2], re.IGNORECASE) is not None
        )

    def drop_recent(self, expression):
        """Take out of the conditions the ones that say that the documents were written not long ago: they are, as they are written now.

        `recent <= 6` (or `<`) in the terms of an AND, as the rules have them. Wherever else the alias is, it is refused.
        """
        terms = expression.terms if isinstance(expression, eql.ast.And) else [expression]

        def now(term):
            return (
                isinstance(term, eql.ast.Comparison)
                and isinstance(term.left, eql.ast.Field)
                and self.field_key(term.left.render()) in self.recent
                and term.comparator in ("<=", "<")
                and isinstance(term.right, eql.ast.Number)
                and term.right.value >= (0 if term.comparator == "<=" else 1)
            )

        kept = [eql.ast.Boolean(True) if now(term) else term for term in terms]
        return eql.ast.And(kept) if len(kept) > 1 else kept[0]

    def key(self, tree, item):
        """Return the name of a key of BY (None when it has none), and the fields of the documents that it depends on."""
        made = assignment(item)
        if made:
            return self.field_name(made[0]), self.dependencies(made[1])
        if is_name(item):
            key = self.field_key(item)
            if key in METADATA_FIELDS:
                self.reject(tree, f"predicate on metadata field: {key}")
            return self.field_name(item.strip()), self.evals.get(key, [key])
        return None, self.dependencies(item)

    # boolean expressions

    def boolean(self, tree):
        """Visit an expression that must be true, a bare boolean field means `field == true`."""
        node = self.visit(tree)
        if isinstance(node, eql.ast.Field):
            self.check_field(tree, node)
            return eql.ast.Comparison(node, "==", eql.ast.Boolean(True))
        if isinstance(node, Scalar) or (isinstance(node, eql.ast.Literal) and not isinstance(node, eql.ast.Boolean)):
            self.reject(tree, "non-boolean expression")
        return node

    def or_op(self, tree):
        left, _, right = tree.children
        left, right = self.boolean(left), self.boolean(right)
        terms = left.terms if isinstance(left, eql.ast.Or) else [left]
        return eql.ast.Or(terms + [right])

    def and_op(self, tree):
        left, _, right = tree.children
        left, right = self.boolean(left), self.boolean(right)
        terms = left.terms if isinstance(left, eql.ast.And) else [left]
        terms = self.merge_over(terms + [right])
        return eql.ast.And(terms) if len(terms) > 1 else terms[0]

    def not_op(self, tree):
        return eql.ast.Not(self.boolean(tree.children[1]))

    # predicates

    def check_field(self, tree, field):
        name = field.render()
        if name in METADATA_FIELDS:
            self.reject(tree, f"predicate on metadata field: {name}")
        return field

    def field_operand(self, tree, operand):
        operand = self.visit(operand)
        if not isinstance(operand, eql.ast.Field):
            self.reject(tree, "left operand, it must be a field")
        return self.check_field(tree, operand)

    def scalar_of(self, expression):
        """Return the Scalar that an expression is (the function is None for a field), None if it is anything else."""
        scalar = self.scalar_made_of(expression.strip())
        for field in scalar.fields if scalar else ():
            self.resolved[id(field)] = field
        return scalar

    def scalar_made_of(self, expression):
        made = call(expression)
        if made is None:
            if not is_name(expression) or expression.lower() in ("true", "false", "null"):
                return None
            key = self.field_key(expression)
            if key in self.evals:
                return self.scalars.get(key)  # an alias of what a field is
            base, *path = split_field(expression)
            return Scalar(None, (eql.ast.Field(base, path),), False)
        name, arguments = made[0].lower(), made[1].strip()
        if name in SCALAR_FUNCTIONS:
            inner = self.scalar_made_of(arguments)
            return Scalar(name, inner.fields, inner.total) if inner is not None and inner.function is None else None
        if name == "coalesce":
            fields, total = [], False
            for argument in split_top(arguments):
                argument = argument.strip()
                if NULL_RE.fullmatch(argument):
                    continue  # it is the next that is asked for
                if LITERAL_RE.fullmatch(argument):
                    total = True  # what is after a literal is never reached, and it is what is there for no field
                    break
                inner = self.scalar_made_of(argument)
                if inner is None or inner.function is not None:
                    return None
                fields.extend(inner.fields)
                if inner.total:
                    total = True
                    break
            return Scalar(None, tuple(fields), total) if fields else None
        return None

    def scalar_operand(self, tree, operand):
        """Return (fields, function, total) of the operand of a predicate, the function is None if it is a field.

        There is more than one field when it is made of the first of them that has a value (COALESCE), and `total`
        is that it has a value even if none of them has (a literal that is not null ends the COALESCE).
        """
        node = self.visit(operand)
        # before STATS only: after it what an alias makes is a key of BY, and it is what the conditions are about
        if isinstance(node, eql.ast.Field) and self.stats is None:
            node = self.scalars.get(self.field_key(node.render()), node)
        if isinstance(node, Scalar):
            return tuple(self.check_field(tree, field) for field in node.fields), node.function, node.total
        if not isinstance(node, eql.ast.Field):
            self.reject(tree, "left operand, it must be a field")
        return (self.check_field(tree, node),), None, False

    def over_fields(self, fields, build, builds=None):
        """Build a condition for each field, which has to be the one with the value: the ones before it have none."""
        terms = []
        for i, field in enumerate(fields):
            term = build(field)
            nulls = [eql.ast.IsNull(before) for before in fields[:i]]
            terms.append(eql.ast.And([term] + nulls) if nulls else term)
        if len(terms) == 1:
            return terms[0]
        expr = eql.ast.Or(terms)
        self.over[id(expr)] = (expr, fields, builds or [build])  # the expression is kept so that its id is not reused
        return expr

    def merge_over(self, terms):
        """Put together the conditions of an AND that are about the same fields.

        One that is about the first field that has a value, and another about the same, are about the same field, which is
        the one of each of the alternatives: not any of the first with any of the second (they would not agree on which).
        """
        groups = {}
        for term in terms:
            if id(term) in self.over:
                groups.setdefault(tuple(field.render() for field in self.over[id(term)][1]), []).append(term)
        merged = []
        for term in terms:
            group = groups.get(tuple(field.render() for field in self.over[id(term)][1])) if id(term) in self.over else None
            if group is None or len(group) == 1:
                merged.append(term)
            elif term is group[0]:
                fields = self.over[id(term)][1]
                builds = [build for member in group for build in self.over[id(member)][2]]
                merged.append(
                    self.over_fields(fields, lambda field, builds=builds: eql.ast.And([build(field) for build in builds]), builds)
                )
        return merged

    def literal_operand(self, tree, operand, equality=False):
        operand = self.visit(operand)
        if not isinstance(operand, eql.ast.Literal):
            self.reject(tree, "right operand, it must be a literal")
        return self.check_literal(tree, operand, equality)

    @staticmethod
    def equal(field, literal):
        """An equality, where `*` and `?` of a string are what they are and not wildcards."""
        if isinstance(literal, eql.ast.String) and has_wildcards(literal.value):
            return eql.ast.FunctionCall("_literal", [field, literal])
        return eql.ast.Comparison(field, "==", literal)

    def check_literal(self, tree, operand, equality=False):
        if isinstance(operand, eql.ast.Null):
            self.reject(tree, "NULL literal, use IS NULL or IS NOT NULL")
        if not equality and isinstance(operand, eql.ast.String) and has_wildcards(operand.value):
            self.reject(tree, f"string literal with wildcard characters: {operand.value!r}")
        return operand

    def check_pattern(self, tree, pattern):
        # the solvers expand `*` and `?` only, they don't know about character classes (a backslash is just a character)
        if "[" in pattern:
            self.reject(tree, f"LIKE pattern, character classes are not supported: {pattern!r}")

    def like_pattern(self, tree, pattern):
        """Return the pattern of a LIKE as the solvers have it: in ES|QL a backslash escapes the next character, in them it is one.

        An escaped backslash (a path of Windows) is one, what is escaped to be a literal `*` or `?` is not something that
        the solvers can be asked for.
        """
        self.check_pattern(tree, pattern)
        chars, i = [], 0
        while i < len(pattern):
            if pattern[i] == "\\":
                if pattern[i + 1 : i + 2] != "\\":
                    self.reject(tree, f"LIKE pattern, only a backslash can be escaped with a backslash: {pattern!r}")
                i += 1
            chars.append(pattern[i])
            i += 1
        return "".join(chars)

    @staticmethod
    def like_call(field, pattern):
        return eql.ast.FunctionCall("_like", [field, eql.ast.String(pattern)])

    def rlike_call(self, tree, field, pattern, lower=False):
        try:
            regex_gen.check(pattern)
        except (NotImplementedError, ValueError) as e:
            self.reject(tree, f"RLIKE pattern: {e}")
        # the string that is generated is in lowercase, which is what TO_LOWER makes of any string
        extra = [eql.ast.String("lower")] if lower else []
        return eql.ast.FunctionCall("_rlike", [field, eql.ast.String(pattern)] + extra)

    def lower_equal(self, tree, field, literal):
        """`TO_LOWER(field) == literal`: the field has the literal, which cannot have uppercase letters (None if it does)."""
        self.check_string(tree, "TO_LOWER", literal)
        return self.equal(field, literal) if literal.value == literal.value.lower() else None

    def lower_not_equal(self, tree, field, literal):
        """`TO_LOWER(field) != literal`: the field has a value, and not the literal in any case."""
        self.check_string(tree, "TO_LOWER", literal)
        if has_wildcards(literal.value):
            self.reject(tree, f"string literal with wildcard characters: {literal.value!r}")
        if literal.value != literal.value.lower():
            return self.present(field)  # what is in lowercase is never equal to it
        return eql.ast.Not(eql.ast.FunctionCall("wildcard", [field, literal]))

    @staticmethod
    def present(field):
        """True for any value of the field, and null (not false) for none: what is not is never true, whatever is above it."""
        return eql.ast.FunctionCall("_present", [field])

    def check_round_trip(self, tree, literal):
        """`TO_STRING(field)` of a typed field is how its value is written: only a literal that is written so can be equal to it."""
        self.check_string(tree, "TO_STRING", literal)
        value = literal.value
        try:
            written = str(ipaddress.ip_address(value))
        except ValueError:
            written = value
            if re.fullmatch(r"[+-]?\d+", value):
                written = str(int(value))
            elif re.fullmatch(r"[+-]?\d+(\.\d+)?([eE][+-]?\d+)?", value):
                written = None  # how a decimal number is written depends on its type
            elif value.lower() in ("true", "false"):
                written = value.lower()
        if written != value:
            self.reject(tree, f"TO_STRING comparison with a string that is not how a value of any type is written: {value!r}")

    def check_string(self, tree, function, literal):
        if not isinstance(literal, eql.ast.String):
            self.reject(tree, f"{function} comparison with something that is not a string literal")

    def lower_comparison(self, tree, op, field, right):
        if str(op) == "==":
            expr = self.lower_equal(tree, field, right)
            if expr is None:
                self.reject(tree, f"TO_LOWER comparison, it is never true for a literal with uppercase letters: {right.value!r}")
            return expr
        if str(op) == "!=":
            return self.lower_not_equal(tree, field, right)
        self.reject(tree, f"TO_LOWER comparison operator: {op}")

    def comparison(self, tree):
        left, op, right = tree.children
        fields, function, _ = self.scalar_operand(tree, left)
        right = self.literal_operand(tree, right, equality=str(op) in ("==", "!="))
        if function == "to_string":
            if str(op) not in ("==", "!="):
                self.reject(tree, f"TO_STRING comparison operator: {op}, what is compared is text and not the value")
            self.check_round_trip(tree, right)
        if len(fields) > 1 and str(op) not in ("==", "!="):
            self.reject(tree, f"COALESCE comparison operator: {op}")

        def build(field):
            if function == "to_lower":
                return self.lower_comparison(tree, op, field, right)
            if str(op) == "==":
                return self.equal(field, right)
            if str(op) == "!=":
                equal = self.equal(field, right)
                return eql.ast.Comparison(field, "!=", right) if isinstance(equal, eql.ast.Comparison) else eql.ast.Not(equal)
            return eql.ast.Comparison(field, str(op), right)

        return self.over_fields(fields, build)

    def in_expr(self, tree):
        negate = any(isinstance(child, Token) and child.type == "NOT" for child in tree.children)
        operands = [child for child in tree.children if isinstance(child, Tree)]
        fields, function, _ = self.scalar_operand(tree, operands[0])
        container = [self.literal_operand(tree, operand, equality=True) for operand in operands[1:]]
        if function == "to_string":
            for item in container:
                self.check_round_trip(tree, item)

        def build(field):
            if function == "to_lower":
                if negate:
                    return eql.ast.And([self.lower_not_equal(tree, field, item) for item in container])
                terms = [term for term in (self.lower_equal(tree, field, item) for item in container) if term is not None]
                if not terms:
                    self.reject(tree, "TO_LOWER IN, it is never true for literals with uppercase letters")
                return terms[0] if len(terms) == 1 else eql.ast.Or(terms)
            if any(isinstance(item, eql.ast.String) and has_wildcards(item.value) for item in container):
                terms = [self.equal(field, item) for item in container]
                expr = terms[0] if len(terms) == 1 else eql.ast.Or(terms)
            else:
                expr = eql.ast.InSet(field, container)
            return eql.ast.Not(expr) if negate else expr

        return self.over_fields(fields, build)

    def is_null(self, tree):
        negate = any(isinstance(child, Token) and child.type == "NOT" for child in tree.children)
        # a function of a field, or the first of some, has no value when none of them has
        fields, _, total = self.scalar_operand(tree, tree.children[0])
        if total:
            return eql.ast.Boolean(negate)  # a value for any of the fields, a null for none of them
        if negate:
            return self.over_fields(fields, eql.ast.IsNotNull)
        nulls = [eql.ast.IsNull(field) for field in fields]
        return eql.ast.And(nulls) if len(nulls) > 1 else nulls[0]

    def like_expr(self, tree):
        negate = any(isinstance(child, Token) and child.type == "NOT" for child in tree.children)
        operator = next(child for child in tree.children if isinstance(child, Token) and child.type in ("LIKE", "RLIKE"))
        left, right = (child for child in tree.children if isinstance(child, Tree))
        fields, function, _ = self.scalar_operand(tree, left)
        right = self.visit(right)
        if not isinstance(right, eql.ast.String):
            self.reject(tree, f"{operator.type} pattern, it must be a string literal")
        lower = function == "to_lower"
        if lower and right.value != right.value.lower():
            # the lowercase value of a field has no uppercase letters to match, and Elasticsearch takes a
            # regular expression that has them (even a class or one alternative of many) as never matched
            if not negate:
                self.reject(tree, f"TO_LOWER {operator.type}, it is never true for a pattern with uppercase letters: {right.value!r}")
            if operator.type == "RLIKE":
                regex_gen.check(right.value)
            return self.over_fields(fields, self.present)
        pattern = right.value if operator.type == "RLIKE" else self.like_pattern(tree, right.value)

        def build(field):
            expr = self.rlike_call(tree, field, pattern, lower) if operator.type == "RLIKE" else self.like_call(field, pattern)
            return eql.ast.Not(expr) if negate else expr

        return self.over_fields(fields, build)

    # operands

    def arith_op(self, tree):
        self.visit(tree.children[0])
        self.visit(tree.children[2])
        self.reject(tree, "arithmetic expression")

    def unary_op(self, tree):
        op, operand = tree.children
        operand = self.visit(operand)
        if isinstance(operand, eql.ast.Number):
            return eql.ast.Number(-operand.value) if str(op) == "-" else operand
        self.reject(tree, "unary operator")

    def time_literal(self, tree):
        self.reject(tree, "time literal")

    def func_star(self, tree):
        self.reject(tree, f"function: {tree.children[0]}")

    def func_call(self, tree):
        name, *args = tree.children
        name = str(name)
        # these don't take a field and string literals only, see the others below
        special = {"kql": self.function_kql, "mv_contains": self.function_mv_contains}
        if name.lower() in special:
            return special[name.lower()](tree, name.upper(), [self.visit(arg) for arg in args])
        if name.lower() in SCALAR_FUNCTIONS or name.lower() == "coalesce":
            return self.scalar_call(tree, name, [self.visit(arg) for arg in args])
        # not getattr(): lark's Interpreter answers to any unknown attribute
        functions = {
            "starts_with": self.function_starts_with,
            "ends_with": self.function_ends_with,
            "cidr_match": self.function_cidr_match,
        }
        function = functions.get(name.lower())
        if function is None:
            self.reject(tree, f"function: {name}")
        args = [self.visit(arg) for arg in args]
        if not args or not isinstance(args[0], eql.ast.Field):
            self.reject(tree, f"{name.upper()} arguments, the first must be a field")
        self.check_field(tree, args[0])
        if any(not isinstance(arg, eql.ast.String) for arg in args[1:]):
            self.reject(tree, f"{name.upper()} arguments, the others must be string literals")
        return function(tree, name.upper(), args[0], [arg.value for arg in args[1:]])

    def scalar_call(self, tree, name, args):
        """A function of a field that a predicate may be about: TO_LOWER, TO_STRING and COALESCE of fields."""
        name = name.lower()
        fields, total = [], False
        for arg in args:
            if isinstance(arg, eql.ast.Null):
                continue  # it is the next that is asked for
            if isinstance(arg, eql.ast.Literal) and name == "coalesce" and fields:
                total = True  # what is after a literal is never reached, and it is what is there for no field
                break
            node = arg
            if isinstance(arg, eql.ast.Field) and self.stats is None:
                node = self.scalars.get(self.field_key(arg.render()), arg)  # an alias of what a field is
            if isinstance(node, Scalar) and node.function is None:
                fields.extend(node.fields)
                if node.total:
                    total = True
                    break
            elif isinstance(node, eql.ast.Field):
                fields.append(node)
            else:
                self.reject(tree, f"{name.upper()} argument, it must be a field")
        if not fields or (name != "coalesce" and len(args) != 1):
            self.reject(tree, f"{name.upper()} argument, it must be a field")
        return Scalar(None if name == "coalesce" else name, tuple(fields), total)

    def function_kql(self, tree, name, args):
        if len(args) != 1 or not isinstance(args[0], eql.ast.String):
            self.reject(tree, f"{name} arguments, expected a query string")
        try:
            ast = kql.to_eql(args[0].value, optimize=False, strict_literals=True)
        except eql.EqlError as e:
            raise EsqlParseError(f"Invalid KQL query: {e}", 0, 0, args[0].value) from e
        return eql.ast.FunctionCall("_kql", [ast])

    def function_mv_contains(self, tree, name, args):
        if (
            len(args) != 2
            or not isinstance(args[0], eql.ast.Field)
            or not isinstance(args[1], eql.ast.Literal)
            or isinstance(args[1], eql.ast.Null)
        ):
            self.reject(tree, f"{name} arguments, expected a field and a literal")
        self.check_field(tree, args[0])
        # a single value is emitted, an array field gets an array of one: it contains the literal as an equal does
        return self.equal(args[0], self.check_literal(tree, args[1], equality=True))

    def function_starts_with(self, tree, name, field, values):
        return self.affix_call(tree, name, field, values, "{}*")

    def function_ends_with(self, tree, name, field, values):
        return self.affix_call(tree, name, field, values, "*{}")

    def affix_call(self, tree, name, field, values, template):
        if len(values) != 1:
            self.reject(tree, f"{name} arguments, expected a field and a string literal")
        if has_wildcards(values[0]):
            self.reject(tree, f"string literal with wildcard characters: {values[0]!r}")
        pattern = template.format(values[0])
        self.check_pattern(tree, pattern)
        return self.like_call(field, pattern)

    def function_cidr_match(self, tree, name, field, values):
        if not values:
            self.reject(tree, f"{name} arguments, expected a field and at least one string literal")
        return eql.ast.FunctionCall("cidrMatch", [field] + [eql.ast.String(value) for value in values])

    def field(self, tree):
        base, *path = split_field(str(tree.children[0]))
        return eql.ast.Field(base, path)

    def string(self, tree):
        return eql.ast.String(string_value(tree.children[0]))

    def number(self, tree):
        text = str(tree.children[0])
        return eql.ast.Number(int(text) if text.isdigit() else float(text))

    def true(self, tree):
        return eql.ast.Boolean(True)

    def false(self, tree):
        return eql.ast.Boolean(False)

    def null(self, tree):
        return eql.ast.Null()


def validate_branches(ast):
    """Reject what the solvers would turn into documents that the query does not match.

    ES|QL compares scalars exactly and returns null for multivalued fields, while the solvers
    emit one independently generated value per positive constraint on an array field. More than
    one positive constraint on a field is therefore not supported, whatever its schema is: this
    covers repeated and nested `==`, `IN` and `LIKE`, their negations, and mixes of them.
    """
    pruned = []
    token = prune_conflicts.set(pruned)  # as when the documents are made
    try:
        branches = list(collect_constraints(ast, max_branches=MAX_BRANCHES))
    finally:
        prune_conflicts.reset(token)
    if not branches:
        if pruned:
            raise pruned[0]  # what was left out was all there was
        raise NotImplementedError("Unsupported WHERE that is never true")
    for branch in branches:
        for doc in branch:
            for field, constraints in doc.items():
                positives = [c for c in constraints or [] if c[0] in POSITIVE_CONSTRAINTS]
                from_kql = sum(1 for c in positives if c[2:] and c[2].get("kql"))
                # what comes from a KQL string follows the rules of KQL, it can have many values for the
                # same field, but not together with a scalar comparison of ES|QL
                if len(positives) > from_kql and len(positives) > 1:
                    raise NotImplementedError(
                        f"Unsupported conflicting constraints on {field}: only one equality or pattern per field is supported"
                    )


def parse(text):
    """Parse a query, `where` of the result is the plain translation of its WHERE clauses, to inspect it."""
    query = EsqlToEql(text).visit(lark_parse(text))
    validate_branches(query.where)
    return query


def to_eql(text):
    """Return the AST to generate documents from.

    It is the plain translation wrapped in the private function `_esql`, so that the constraints
    collector knows where it comes from: ES|QL is stricter than EQL and the solvers check more.
    """
    query = parse(text)
    node = query.where
    if query.stats is not None:
        spec = {
            "aggregates": [list(a) for a in query.stats.aggregates],
            "by": list(query.stats.fields),
            "join": list(query.stats.join),
            "expanded": list(query.stats.expanded),
        }
        node = eql.ast.FunctionCall("_stats", [query.where, query.stats.where, eql.ast.String(json.dumps(spec))])
    return eql.ast.FunctionCall("_esql", [node])
