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

from ..events_emitter_eql import collect_constraints
from ..utils import has_wildcards
from .errors import EsqlParseError

__all__ = ("EsqlQuery", "parse", "to_eql")

EsqlQuery = namedtuple("EsqlQuery", ["sources", "metadata", "where"])

# commands that do not change which documents match a preceding WHERE
IGNORED_COMMANDS = ("KEEP", "DROP", "SORT", "LIMIT")

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
        self.wheres.append(self.boolean(tree.children[1]))

    def other_cmd(self, tree):
        name = str(tree.children[0]).upper()
        if name not in IGNORED_COMMANDS:
            self.reject(tree, f"command: {name}")
        if name == "LIMIT" and re.fullmatch(r"\s*0+\s*", str(tree.children[1]) if len(tree.children) > 1 else ""):
            self.reject(tree, "LIMIT 0, no document is returned")
        self.blocking = self.blocking or name

    # boolean expressions

    def boolean(self, tree):
        """Visit an expression that must be true, a bare boolean field means `field == true`."""
        node = self.visit(tree)
        if isinstance(node, eql.ast.Field):
            self.check_field(tree, node)
            return eql.ast.Comparison(node, "==", eql.ast.Boolean(True))
        if isinstance(node, eql.ast.Literal) and not isinstance(node, eql.ast.Boolean):
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
        return eql.ast.And(terms + [right])

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

    def literal_operand(self, tree, operand):
        operand = self.visit(operand)
        if not isinstance(operand, eql.ast.Literal):
            self.reject(tree, "right operand, it must be a literal")
        if isinstance(operand, eql.ast.Null):
            self.reject(tree, "NULL literal, use IS NULL or IS NOT NULL")
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
    for branch in collect_constraints(ast, max_branches=MAX_BRANCHES):
        for doc in branch:
            for field, constraints in doc.items():
                if constraints and sum(1 for name, *_ in constraints if name in POSITIVE_CONSTRAINTS) > 1:
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
    return eql.ast.FunctionCall("_esql", [parse(text).where])
