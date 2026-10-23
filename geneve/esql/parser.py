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

import re
from collections import namedtuple
from pathlib import Path

import eql
from lark import Lark, Token, Tree
from lark.exceptions import UnexpectedInput
from lark.visitors import Interpreter

from ..utils import has_wildcards
from .errors import EsqlParseError

__all__ = ("EsqlQuery", "parse", "to_eql")

EsqlQuery = namedtuple("EsqlQuery", ["sources", "metadata", "where"])

# commands that do not change which documents match a preceding WHERE
IGNORED_COMMANDS = ("KEEP", "DROP", "SORT", "LIMIT")

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
    parts = []
    for part in field_part_re.findall(name):
        if part.startswith("`"):
            part = part[1:-1].replace("``", "`")
        parts.append(part)
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
        self.blocking = None  # first ignorable pipe seen, no WHERE is allowed after it

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
            where = eql.ast.And(self.wheres)
        return EsqlQuery(tuple(self.sources), tuple(self.metadata_fields), where)

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
        self.wheres.append(self.visit(tree.children[1]))

    def other_cmd(self, tree):
        name = str(tree.children[0]).upper()
        if name not in IGNORED_COMMANDS:
            self.reject(tree, f"command: {name}")
        self.blocking = self.blocking or name

    # boolean expressions

    def or_op(self, tree):
        left, _, right = tree.children
        left, right = self.visit(left), self.visit(right)
        terms = left.terms if isinstance(left, eql.ast.Or) else [left]
        return eql.ast.Or(terms + [right])

    def and_op(self, tree):
        left, _, right = tree.children
        left, right = self.visit(left), self.visit(right)
        terms = left.terms if isinstance(left, eql.ast.And) else [left]
        return eql.ast.And(terms + [right])

    def not_op(self, tree):
        return eql.ast.Not(self.visit(tree.children[1]))

    # predicates

    def field_operand(self, tree, operand):
        operand = self.visit(operand)
        if not isinstance(operand, eql.ast.Field):
            self.reject(tree, "left operand, it must be a field")
        return operand

    def literal_operand(self, tree, operand):
        operand = self.visit(operand)
        if not isinstance(operand, eql.ast.Literal):
            self.reject(tree, "right operand, it must be a literal")
        if isinstance(operand, eql.ast.String) and has_wildcards(operand.value):
            self.reject(tree, f"string literal with wildcard characters: {operand.value!r}")
        return operand

    def check_pattern(self, tree, pattern):
        # the solvers expand `*` and `?` only, they don't know about escapes or character classes
        if "\\" in pattern or "[" in pattern:
            self.reject(tree, f"LIKE pattern, backslash escapes and character classes are not supported: {pattern!r}")

    @staticmethod
    def like_call(field, pattern):
        return eql.ast.FunctionCall("_like", [field, eql.ast.String(pattern)])

    def comparison(self, tree):
        left, op, right = tree.children
        left = self.field_operand(tree, left)
        right = self.literal_operand(tree, right)
        return eql.ast.Comparison(left, str(op), right)

    def in_expr(self, tree):
        negate = any(isinstance(child, Token) and child.type == "NOT" for child in tree.children)
        operands = [child for child in tree.children if isinstance(child, Tree)]
        left = self.field_operand(tree, operands[0])
        container = [self.literal_operand(tree, operand) for operand in operands[1:]]
        expr = eql.ast.InSet(left, container)
        return eql.ast.Not(expr) if negate else expr

    def is_null(self, tree):
        negate = any(isinstance(child, Token) and child.type == "NOT" for child in tree.children)
        left = self.field_operand(tree, tree.children[0])
        return eql.ast.IsNotNull(left) if negate else eql.ast.IsNull(left)

    def like_expr(self, tree):
        negate = any(isinstance(child, Token) and child.type == "NOT" for child in tree.children)
        operator = next(child for child in tree.children if isinstance(child, Token) and child.type in ("LIKE", "RLIKE"))
        left, right = (child for child in tree.children if isinstance(child, Tree))
        if operator.type == "RLIKE":
            self.reject(tree, "operator: RLIKE")
        left = self.field_operand(tree, left)
        right = self.visit(right)
        if not isinstance(right, eql.ast.String):
            self.reject(tree, "LIKE pattern, it must be a string literal")
        self.check_pattern(tree, right.value)
        expr = self.like_call(left, right.value)
        return eql.ast.Not(expr) if negate else expr

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

    def func_call(self, tree):
        name, *args = tree.children
        name = str(name)
        function = getattr(self, f"function_{name.lower()}", None)
        if function is None:
            self.reject(tree, f"function: {name}")
        args = [self.visit(arg) for arg in args]
        if not args or not isinstance(args[0], eql.ast.Field):
            self.reject(tree, f"{name.upper()} arguments, the first must be a field")
        if any(not isinstance(arg, eql.ast.String) for arg in args[1:]):
            self.reject(tree, f"{name.upper()} arguments, the others must be string literals")
        return function(tree, name.upper(), args[0], [arg.value for arg in args[1:]])

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


def parse(text):
    return EsqlToEql(text).visit(lark_parse(text))


def to_eql(text):
    return parse(text).where
