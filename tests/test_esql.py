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

"""Test the ES|QL parser and its translation to the EQL AST."""

import ipaddress
import unittest
from types import SimpleNamespace
from typing import ClassVar

import eql

import tests.utils as tu
from geneve import esql, kql
from geneve.constraints import ConflictError
from geneve.events_emitter import SourceEvents, ast_from_rule, guess_from_query
from geneve.events_emitter_eql import collect_constraints
from geneve.solver import Field, solver


def field(name):
    base, *path = name.split(".")
    return eql.ast.Field(base, path)


def like(name, pattern):
    return eql.ast.FunctionCall("_like", [field(name), eql.ast.String(pattern)])


def literal(name, value):
    return eql.ast.FunctionCall("_literal", [field(name), eql.ast.String(value)])


def where(query):
    """Return the plain translation of the WHERE clauses, to inspect it."""
    return esql.parse(query).where


class TestEsqlParser(unittest.TestCase):
    def validate(self, esql_source, eql_source):
        self.assertEqual(where(esql_source), eql.parse_expression(eql_source))

    def test_comparisons(self):
        self.validate("FROM x | WHERE a == 1", "a == 1")
        self.validate("FROM x | WHERE a != 1", "a != 1")
        self.validate("FROM x | WHERE a < 1", "a < 1")
        self.validate("FROM x | WHERE a <= 1", "a <= 1")
        self.validate("FROM x | WHERE a > 1", "a > 1")
        self.validate("FROM x | WHERE a >= 1", "a >= 1")
        self.validate('FROM x | WHERE b == "foo"', "b == 'foo'")
        self.validate("FROM x | WHERE c == true", "c == true")
        self.validate("FROM x | WHERE c == FALSE", "c == false")
        self.validate("FROM x | WHERE d == 1.5", "d == 1.5")
        self.validate("FROM x | WHERE e == -2", "e == -2")

    def test_boolean_logic(self):
        self.validate("FROM x | WHERE a == 1 AND b == 2", "a == 1 and b == 2")
        self.validate("FROM x | WHERE a == 1 OR b == 2", "a == 1 or b == 2")
        # AND binds tighter than OR
        self.validate("FROM x | WHERE a == 1 AND b == 2 OR c == 3", "a == 1 and b == 2 or c == 3")
        self.validate("FROM x | WHERE a == 1 AND (b == 2 OR c == 3)", "a == 1 and (b == 2 or c == 3)")
        # NOT binds tighter than AND
        self.assertEqual(
            where("FROM x | WHERE NOT a == 1 AND b == 2"),
            eql.ast.And([eql.ast.Not(eql.parse_expression("a == 1")), eql.parse_expression("b == 2")]),
        )
        self.assertEqual(
            where("FROM x | WHERE NOT (a == 1 OR b == 2)"),
            eql.ast.Not(eql.parse_expression("a == 1 or b == 2")),
        )

    def test_in_and_null_tests(self):
        self.validate("FROM x | WHERE a IN (1, 2)", "a in (1, 2)")
        self.validate('FROM x | WHERE a IN ("x", "y")', "a in ('x', 'y')")
        self.assertEqual(
            where("FROM x | WHERE a NOT IN (1, 2)"),
            eql.ast.Not(eql.parse_expression("a in (1, 2)")),
        )
        self.validate("FROM x | WHERE a IS NULL", "a == null")
        self.validate("FROM x | WHERE a IS NOT NULL", "a != null")

    def test_dotted_and_quoted_fields(self):
        self.validate('FROM x | WHERE process.name == "x"', "process.name == 'x'")
        self.assertEqual(
            where('FROM x | WHERE @timestamp != "x"'),
            eql.ast.Comparison(eql.ast.Field("@timestamp"), "!=", eql.ast.String("x")),
        )
        self.assertEqual(
            where('FROM x | WHERE `host name` == "x"'),
            eql.ast.Comparison(field("host name"), "==", eql.ast.String("x")),
        )
        # a quoted name with dots is the same path Elasticsearch would resolve
        self.assertEqual(
            where('FROM x | WHERE a.`b.c`.d == "x"'),
            eql.ast.Comparison(eql.ast.Field("a", ["b", "c", "d"]), "==", eql.ast.String("x")),
        )
        self.assertEqual(
            where('FROM x | WHERE `a.b` == "x"'),
            eql.ast.Comparison(eql.ast.Field("a", ["b"]), "==", eql.ast.String("x")),
        )
        for query in ("`a..b`", "`.a`", "`a.`", "`a*`", "a.`b?`", "`*`"):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported field name"):
                where(f'FROM x | WHERE {query} == "x"')

    def test_case_and_comments(self):
        expected = where("FROM x | WHERE a == 1")
        self.assertEqual(where("from x | where a == 1"), expected)
        self.assertEqual(where("From x | Where a == 1"), expected)
        self.assertEqual(where("FROM x // trailing comment\n | /* block\ncomment */ WHERE a == 1"), expected)
        self.assertEqual(where("FROM x\n| WHERE a == 1 // why not"), expected)
        self.assertEqual(where("FROM x | WHERE a == 1 AND\n  b == 2"), where("FROM x | WHERE a == 1 and b == 2"))

    def test_sources_and_metadata(self):
        query = esql.parse("FROM logs-*, other METADATA _id, _index | WHERE a == 1")
        self.assertEqual(query.sources, ("logs-*", "other"))
        self.assertEqual(query.metadata, ("_id", "_index"))
        self.assertEqual(query.where, eql.parse_expression("a == 1"))

        query = esql.parse("FROM single")
        self.assertEqual(query.sources, ("single",))
        self.assertEqual(query.metadata, ())

        query = esql.parse('FROM remote:logs-*, -logs-secret, "quoted-name"')
        self.assertEqual(query.sources, ("remote:logs-*", "-logs-secret", "quoted-name"))

    def test_no_where(self):
        self.assertEqual(where("FROM x"), eql.ast.Boolean(True))
        self.assertEqual(where("FROM x | LIMIT 10"), eql.ast.Boolean(True))

    def test_multiple_where_anded(self):
        self.validate("FROM x | WHERE a == 1 | WHERE b == 2", "a == 1 and b == 2")

    def test_ignored_pipes_after_where(self):
        self.validate("FROM x | WHERE a == 1 | KEEP a | SORT a DESC | LIMIT 5 | DROP b", "a == 1")
        self.validate('FROM x | WHERE a == 1 | KEEP a, "b|c", `d|e` | LIMIT 5', "a == 1")

    def test_limit_before_where_rejected(self):
        for query in ("FROM x | LIMIT 5 | WHERE a == 1", "FROM x | WHERE a == 1 | LIMIT 5 | WHERE b == 2"):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, r"Unsupported pipe before WHERE: LIMIT"):
                where(query)
        # these only hide columns or sort the rows, the documents that match are the same
        self.validate("FROM x | KEEP a, b | WHERE a == 1", "a == 1")
        self.validate("FROM x | DROP c | SORT a | WHERE a == 1 | KEEP a | WHERE b == 2", "a == 1 and b == 2")

    def test_limit_zero_rejected(self):
        for query in ("FROM x | WHERE a == 1 | LIMIT 0", "FROM x | LIMIT 0"):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported LIMIT 0"):
                where(query)
        self.validate("FROM x | WHERE a == 1 | LIMIT 1", "a == 1")

    def test_unsupported_command(self):
        for command in (
            "ENRICH p ON a",
            "LOOKUP JOIN idx ON a",
            "COMPLETION c = a WITH inference",
        ):
            name = command.split()[0]
            with self.subTest(command), self.assertRaisesRegex(NotImplementedError, rf"Unsupported command: {name}"):
                where(f"FROM x | WHERE a == 1 | {command}")
        with self.assertRaisesRegex(NotImplementedError, "Unsupported command: ENRICH"):
            where("from x | enrich p on a")

    def test_unsupported_source_command(self):
        for query in ("ROW a = 1", "SHOW INFO", "TS metrics"):
            name = query.split()[0]
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, rf"Unsupported source command: {name}"):
                where(query)

    def test_like(self):
        self.assertEqual(where('FROM x | WHERE a LIKE "foo*"'), like("a", "foo*"))
        self.assertEqual(where('FROM x | WHERE a LIKE "foo?"'), like("a", "foo?"))
        self.assertEqual(where('FROM x | WHERE a.b like "*foo*"'), like("a.b", "*foo*"))
        self.assertEqual(where('FROM x | WHERE a NOT LIKE "foo*"'), eql.ast.Not(like("a", "foo*")))
        self.assertEqual(
            where('FROM x | WHERE a LIKE "foo*" OR b == 1'),
            eql.ast.Or([like("a", "foo*"), eql.parse_expression("b == 1")]),
        )

    def test_like_unsupported(self):
        with self.assertRaisesRegex(NotImplementedError, "Unsupported operator: RLIKE"):
            where('FROM x | WHERE a RLIKE "foo.*"')
        with self.assertRaisesRegex(NotImplementedError, "Unsupported .*LIKE pattern.*string literal"):
            where("FROM x | WHERE a LIKE 1")

    def test_like_escapes_and_classes_rejected(self):
        for pattern in (r"foo\\*", r"a\\?b", r"a\\\\b", "[ab]*", "a[b"):
            query = f'FROM x | WHERE a LIKE "{pattern}"'
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported LIKE pattern"):
                where(query)

    def test_starts_ends_with(self):
        self.assertEqual(where('FROM x | WHERE STARTS_WITH(a, "foo")'), like("a", "foo*"))
        self.assertEqual(where('FROM x | WHERE ends_with(a.b, "foo")'), like("a.b", "*foo"))
        self.assertEqual(where('FROM x | WHERE NOT STARTS_WITH(a, "foo")'), eql.ast.Not(like("a", "foo*")))

    def test_starts_ends_with_literal_metachar_rejected(self):
        for query in (
            'STARTS_WITH(a, "f*o")',
            'ENDS_WITH(a, "f?o")',
            'STARTS_WITH(a, "a[b")',
            "STARTS_WITH(a, 1)",
            "STARTS_WITH(a, b)",
            'STARTS_WITH("a", "b")',
            "STARTS_WITH(a)",
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported"):
                where(f"FROM x | WHERE {query}")

    def test_cidr_match(self):
        self.validate('FROM x | WHERE CIDR_MATCH(source.ip, "10.0.0.0/8")', "cidrMatch(source.ip, '10.0.0.0/8')")
        self.validate(
            'FROM x | WHERE cidr_match(source.ip, "10.0.0.0/8", "192.168.0.0/16")',
            "cidrMatch(source.ip, '10.0.0.0/8', '192.168.0.0/16')",
        )
        self.assertEqual(
            where('FROM x | WHERE NOT CIDR_MATCH(source.ip, "10.0.0.0/8")'),
            eql.ast.Not(eql.parse_expression("cidrMatch(source.ip, '10.0.0.0/8')")),
        )
        for query in ("CIDR_MATCH(source.ip)", "CIDR_MATCH(source.ip, 1)", 'CIDR_MATCH("10.0.0.1", "10.0.0.0/8")'):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported"):
                where(f"FROM x | WHERE {query}")

    def test_literal_strings_with_wildcard_characters(self):
        # in an equality `*` and `?` are what they are, not wildcards
        self.assertEqual(literal("a", "f*o"), where('FROM x | WHERE a == "f*o"'))
        self.assertEqual(literal("a", "f?o"), where('FROM x | WHERE a == "f?o"'))
        self.assertEqual(eql.ast.Not(literal("a", "f?o")), where('FROM x | WHERE a != "f?o"'))
        self.assertEqual(eql.ast.Not(literal("a", "*")), where('FROM x | WHERE NOT a == "*"'))
        self.assertEqual(
            eql.ast.Or([eql.ast.Comparison(field("a"), "==", eql.ast.String("x")), literal("a", "f*")]),
            where('FROM x | WHERE a IN ("x", "f*")'),
        )
        self.assertEqual(eql.ast.Not(literal("a", "?")), where('FROM x | WHERE a NOT IN ("?")'))
        self.assertEqual(literal("a", "b*"), where('FROM x | WHERE mv_contains(a, "b*")'))
        # no other comparison makes sense
        for query in ('a < "f*"', 'a >= "?"'):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported string literal"):
                where(f"FROM x | WHERE {query}")
        # what has no wildcard characters is as it was
        self.validate('FROM x | WHERE a == "foo"', "a == 'foo'")
        self.validate('FROM x | WHERE a IN ("x", "y")', "a in ('x', 'y')")

    def test_string_escapes(self):
        def check(source, value):
            self.assertEqual(
                where(f"FROM x | WHERE a == {source}"),
                eql.ast.Comparison(field("a"), "==", eql.ast.String(value)),
            )

        check(r'"x\"y"', 'x"y')
        check(r'"x\\y"', "x\\y")
        check(r'"x\ny"', "x\ny")
        check(r'"x\ty\r"', "x\ty\r")
        check('"""x"y"""', 'x"y')
        check('"""x\\ny"""', "x\\ny")  # no escapes in triple-quoted strings
        check('"""multi\nline"""', "multi\nline")
        check('""', "")
        self.assertEqual(esql.parse(r'FROM "quo\"ted"').sources, ('quo"ted',))

    def test_string_unknown_escape_rejected(self):
        with self.assertRaisesRegex(NotImplementedError, r"Unsupported escape sequence"):
            where(r'FROM x | WHERE a == "x\qy"')

    def test_null_literals_rejected(self):
        for query in ("a == NULL", "a != NULL", "NOT (a == NULL)", "a IN (1, NULL)", "a NOT IN (NULL)", "a < null"):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported NULL literal"):
                where(f"FROM x | WHERE {query}")
        self.validate("FROM x | WHERE a IS NULL", "a == null")
        self.validate("FROM x | WHERE a IS NOT NULL", "a != null")

    def test_metadata_predicates_rejected(self):
        for query in (
            '_id == "x"',
            '_index LIKE "a*"',
            "_version > 1",
            "_ignored IS NULL",
            '`_id` IN ("a", "b")',
            'STARTS_WITH(_index, "a")',
            'CIDR_MATCH(_source, "10.0.0.0/8")',
            "NOT _score > 1",
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported predicate on metadata field"):
                where(f"FROM x METADATA _id, _index | WHERE {query}")
        # the declaration itself is fine, and so are fields that merely start like a metadata one
        self.assertEqual(esql.parse("FROM x METADATA _id").metadata, ("_id",))
        self.validate('FROM x | WHERE _idx == "x"', "_idx == 'x'")

    def test_bare_boolean_fields(self):
        flag = eql.ast.Comparison(field("flag"), "==", eql.ast.Boolean(True))
        other = eql.parse_expression("a == 1")
        self.assertEqual(where("FROM x | WHERE flag"), flag)
        self.assertEqual(where("FROM x | WHERE NOT flag"), eql.ast.Not(flag))
        self.assertEqual(where("FROM x | WHERE flag AND a == 1"), eql.ast.And([flag, other]))
        self.assertEqual(where("FROM x | WHERE a == 1 OR NOT flag"), eql.ast.Or([other, eql.ast.Not(flag)]))
        self.assertEqual(
            where("FROM x | WHERE (flag) AND (a.b)"),
            eql.ast.And([flag, eql.ast.Comparison(field("a.b"), "==", eql.ast.Boolean(True))]),
        )
        self.assertEqual(where("FROM x | WHERE true"), eql.ast.Boolean(True))
        self.assertEqual(where("FROM x | WHERE a == 1 AND NOT false"), eql.ast.And([other, eql.ast.Not(eql.ast.Boolean(False))]))

    def test_non_boolean_expressions_rejected(self):
        for query in ("1", '"x"', "NULL", "a == 1 AND 2", "NOT 1.5", "_id", "NOT `_index`"):
            with self.subTest(query), self.assertRaisesRegex(
                NotImplementedError, "Unsupported (non-boolean expression|predicate on metadata field)"
            ):
                where(f"FROM x METADATA _id | WHERE {query}")

    def test_mv_contains(self):
        eq = eql.ast.Comparison(field("event.category"), "==", eql.ast.String("iam"))
        self.assertEqual(eq, where('FROM x | WHERE MV_CONTAINS(event.category, "iam")'))
        self.assertEqual(eq, where('FROM x | WHERE mv_contains(event.category, "iam")'))
        self.assertEqual(eql.ast.Not(eq), where('FROM x | WHERE NOT mv_contains(event.category, "iam")'))
        other = eql.parse_expression("a == 1")
        self.assertEqual(eql.ast.And([eq, other]), where('FROM x | WHERE mv_contains(event.category, "iam") AND a == 1'))
        self.assertEqual(
            eql.ast.Comparison(field("n"), "==", eql.ast.Number(2)),
            where("FROM x | WHERE mv_contains(n, 2)"),
        )
        self.assertEqual(
            eql.ast.Comparison(field("b"), "==", eql.ast.Boolean(True)),
            where("FROM x | WHERE mv_contains(b, true)"),
        )

    def test_mv_contains_rejected(self):
        for query, message in (
            ("mv_contains(a, b)", "Unsupported MV_CONTAINS arguments"),
            ('mv_contains("a", "b")', "Unsupported MV_CONTAINS arguments"),
            ("mv_contains(a)", "Unsupported MV_CONTAINS arguments"),
            ('mv_contains(a, "b", "c")', "Unsupported MV_CONTAINS arguments"),
            ("mv_contains(a, NULL)", "Unsupported MV_CONTAINS arguments"),
            ('mv_contains(_id, "x")', "Unsupported predicate on metadata field"),
            ('mv_contains(a, "x") AND mv_contains(a, "y")', "Unsupported conflicting constraints on a"),
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, message):
                where(f"FROM x METADATA _id | WHERE {query}")

    def test_kql(self):
        def check(esql_query, kql_query):
            self.assertEqual(
                eql.ast.FunctionCall("_kql", [kql.to_eql(kql_query, optimize=False)]),
                where(f"FROM x | WHERE {esql_query}"),
            )

        check('KQL("event.action: creation")', "event.action: creation")
        check('kql("event.action: creation")', "event.action: creation")
        check(
            'KQL("""kibana.alert.rule.tags : "Rule Type: Higher-Order Rule" """)',
            'kibana.alert.rule.tags : "Rule Type: Higher-Order Rule" ',
        )
        check('KQL(""" event.type : "start" and not event.action : "fork" """)', ' event.type : "start" and not event.action : "fork" ')
        check('KQL("""event.action:"exec" and process.args:("-c" or "-cl")""")', 'event.action:"exec" and process.args:("-c" or "-cl")')
        node = where('FROM x | WHERE NOT KQL("a: b") AND c == 1')
        self.assertIsInstance(node, eql.ast.And)
        self.assertEqual(eql.ast.Not, type(node.terms[0]))

    def test_kql_literals(self):
        def check(kql_query, expected):
            self.assertEqual(
                eql.ast.FunctionCall("_kql", [expected]),
                where('FROM x | WHERE KQL("""' + kql_query + ' """)'),
            )

        # quoted values are literals, `?` is never a wildcard in KQL, an unquoted `*` is
        check('f:"*"', literal("f", "*"))
        check('f:"a*"', literal("f", "a*"))
        check('f:"a?"', literal("f", "a?"))
        check("f:a?", literal("f", "a?"))
        check('not f:"*"', eql.ast.Not(literal("f", "*")))
        check("f:a*", eql.ast.FunctionCall("wildcard", [field("f"), eql.ast.String("a*")]))
        check("f:*", eql.ast.IsNotNull(field("f")))
        check('f:"abc"', eql.ast.Comparison(field("f"), "==", eql.ast.String("abc")))
        check('f:("*" or "a")', eql.ast.Or([literal("f", "*"), eql.ast.Comparison(field("f"), "==", eql.ast.String("a"))]))
        with self.assertRaisesRegex(esql.EsqlParseError, "Invalid KQL query"):
            where('FROM x | WHERE KQL("f:a*b?")')

    def test_kql_strict_literals_are_opt_in(self):
        # the KQL of the rules of type query is as it was
        self.assertEqual(eql.ast.IsNotNull(field("f")), kql.to_eql('f:"*"', optimize=False))
        self.assertEqual(eql.ast.FunctionCall("wildcard", [field("f"), eql.ast.String("a*")]), kql.to_eql('f:"a*"', optimize=False))
        self.assertEqual(literal("f", "*"), kql.to_eql('f:"*"', optimize=False, strict_literals=True))

    def test_kql_rejected(self):
        for query in ("KQL()", "KQL(1)", "KQL(a)", 'KQL("a: b", "c")', 'KQL("a: b", {"case_insensitive": true})', "KQL(NULL)"):
            with self.subTest(query), self.assertRaisesRegex(
                (NotImplementedError, esql.EsqlParseError), "Unsupported KQL arguments|Invalid syntax"
            ):
                where(f"FROM x | WHERE {query}")
        with self.assertRaisesRegex(esql.EsqlParseError, "Invalid KQL query"):
            where('FROM x | WHERE KQL("a: (")')
        with self.assertRaisesRegex(esql.EsqlParseError, "Invalid KQL query"):
            where('FROM x | WHERE KQL("")')

    def test_kql_keeps_its_own_rules(self):
        # KQL allows what ES|QL scalar comparisons do not: two values for the same (array) field
        where('FROM x | WHERE KQL("process.args: a and process.args: b")')
        # but the ES|QL part of the query is still checked
        with self.assertRaisesRegex(NotImplementedError, "Unsupported conflicting constraints on tags"):
            where('FROM x | WHERE KQL("tags: a") AND tags == "b"')
        where('FROM x | WHERE KQL("tags: a") AND tags2 == "b"')

    def test_non_field_operands_rejected(self):
        for query in ("a == b", "1 == a", "LENGTH(a) > 3", "a == b + 1", "a + 1 == 2", "a == (1 + 2)", '"x" == a', "a IN (b, 1)"):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported"):
                where(f"FROM x | WHERE {query}")

    def test_unsupported_functions_rejected(self):
        for query, name in (
            ("NOW()", "NOW"),
            ("@timestamp > NOW() - 1d", "NOW"),
            ('TO_UPPER(a) == "X"', "TO_UPPER"),
            ("MV_COUNT(a) > 1", "MV_COUNT"),
            ("a == ABS(b)", "ABS"),
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, f"Unsupported function: {name}"):
                where(f"FROM x | WHERE {query}")

    def test_branch_conflicts_rejected(self):
        for query in (
            'tags == "a" AND tags == "b"',
            'tags == "a" AND tags == "a"',
            'tags LIKE "f*" AND tags LIKE "f*"',
            'tags == "a" AND (tags == "b" OR tags == "c")',
            'tags IN ("a", "b") AND tags IN ("c", "d")',
            'CIDR_MATCH(ip, "10.0.0.0/8") AND CIDR_MATCH(ip, "192.168.0.0/16")',
            'ip == "10.0.0.1" AND CIDR_MATCH(ip, "192.168.0.0/16")',
            '`a.b` == "x" AND a.b == "y"',
            'NOT (tags != "a" OR tags != "b")',
            'a == "foo" AND a LIKE "FOO*"',
            "pid == 1 AND pid == 2",
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported conflicting constraints on"):
                where(f"FROM x | WHERE {query}")
        with self.assertRaisesRegex(NotImplementedError, "Unsupported conflicting constraints"):
            where('FROM x | WHERE tags == "a" | WHERE tags == "b"')

    def test_branch_validation_accepts(self):
        for query in (
            'tags == "a" OR tags == "b"',
            'a LIKE "foo*" OR a LIKE "bar*"',
            'a == "x" AND a != "y"',
            "pid >= 1 AND pid < 10",
            'a IN ("x", "y")',
            'a LIKE "FOO*"',
            'a LIKE "foo*" AND b LIKE "bar*"',
            'a == "x" AND a IS NOT NULL',
            'CIDR_MATCH(ip, "10.0.0.0/8") AND NOT CIDR_MATCH(ip, "10.1.0.0/16")',
            'CIDR_MATCH(ip, "10.0.0.0/8") OR CIDR_MATCH(ip, "192.168.0.0/16")',
            'NOT a == "x" AND NOT a == "y"',
        ):
            with self.subTest(query):
                where(f"FROM x | WHERE {query}")

    def test_syntax_errors(self):
        for query in (
            "",
            "   \n ",
            "FROM",
            "FROM x | WHERE",
            "FROM x |",
            "FROM x | WHERE a ==",
            "FROM x | WHERE (a == 1",
            "FROM x | WHERE a == 1 AND",
        ):
            with self.subTest(query), self.assertRaises(esql.EsqlParseError) as cm:
                where(query)
            self.assertIsInstance(cm.exception.line, int)
            self.assertIsInstance(cm.exception.column, int)
            self.assertIsInstance(cm.exception, eql.EqlParseError)


def stats_summary(query):
    stats = esql.parse(query).stats
    return [(a.alias, a.function, a.argument) for a in stats.aggregates], list(stats.by)


class TestEsqlStats(unittest.TestCase):
    def test_no_stats(self):
        self.assertIsNone(esql.parse("FROM x | WHERE a == 1").stats)

    def test_stats(self):
        query = esql.parse(
            "FROM x | WHERE a == 1 | STATS c = COUNT(*), d = COUNT_DISTINCT(u), v = VALUES(f), e = COUNT(g) BY h"
            " | WHERE c >= 10 AND d >= 2 | KEEP h, c | SORT c DESC | LIMIT 5"
        )
        self.assertEqual(eql.parse_expression("a == 1"), query.where)
        self.assertEqual(
            (("c", "count", None), ("d", "count_distinct", "u"), ("v", "values", "f"), ("e", "count", "g")),
            tuple((a.alias, a.function, a.argument) for a in query.stats.aggregates),
        )
        self.assertTrue(all(a.simple for a in query.stats.aggregates))
        self.assertEqual(("h",), query.stats.by)
        self.assertEqual(("h",), query.stats.join)
        self.assertEqual(eql.parse_expression("c >= 10 and d >= 2"), query.stats.where)

    def test_stats_variants(self):
        self.assertEqual(
            ([("c", "count", None)], ["host.id", "user.name"]), stats_summary("FROM x | STATS c = COUNT() BY host.id, user.name")
        )
        self.assertEqual(([("c", "count", None)], []), stats_summary("FROM x | STATS c = count(*)"))
        self.assertEqual(
            ([("Esql.event_count", "count", None), ("`my alias`", "count_distinct", "a.b")], ["h"]),
            stats_summary("FROM x | STATS Esql.event_count = COUNT(*), `my alias` = COUNT_DISTINCT(a.b) BY h"),
        )
        query = esql.parse("FROM x | STATS Esql.event_count = COUNT(*) BY h | WHERE Esql.event_count >= 5 OR Esql.event_count == 1")
        self.assertEqual(
            eql.ast.Or([eql.parse_expression("Esql.event_count >= 5"), eql.parse_expression("Esql.event_count == 1")]),
            query.stats.where,
        )
        self.assertEqual(eql.ast.Boolean(True), esql.parse("FROM x | STATS c = COUNT(*) BY h").stats.where)
        # what comes after is not about what documents match
        query = esql.parse("FROM x | STATS c = COUNT(*) BY h | KEEP h, c | WHERE c > 1 | EVAL r = c / 2 | SORT r | LIMIT 10")
        self.assertEqual(eql.parse_expression("c > 1"), query.stats.where)
        # keep, drop and sort before it are fine
        self.assertIsNotNone(esql.parse("FROM x | WHERE a == 1 | KEEP a, h | SORT a | STATS c = COUNT(*) BY h").stats)

    def test_to_eql_carries_the_stats(self):
        import json

        text = "FROM x | WHERE a == 1 | STATS c = COUNT(*), d = COUNT_DISTINCT(u) BY h | WHERE c >= 3"
        node = esql.to_eql(text)
        self.assertEqual("_esql", node.name)
        stats = node.arguments[0]
        self.assertEqual("_stats", stats.name)
        pre, post, spec = stats.arguments
        self.assertEqual(eql.parse_expression("a == 1"), pre)
        self.assertEqual(eql.parse_expression("c >= 3"), post)
        self.assertEqual(
            {"aggregates": [["c", "count", None, True], ["d", "count_distinct", "u", True]], "by": ["h"], "join": ["h"], "expanded": []},
            json.loads(spec.value),
        )
        # the plain translation is the one of the documents before the aggregation
        self.assertEqual(eql.parse_expression("a == 1"), where(text))

    def test_other_aggregates_and_arguments_are_accepted(self):
        # what no condition asks for is not a constraint, whatever it is
        query = esql.parse(
            "FROM x | STATS m = MAX(f), n = MIN(@timestamp), t = SUM(CASE(a == 1, b, 0)), u = COUNT_DISTINCT(TO_LOWER(f)),"
            " w = COUNT_DISTINCT(f, 100), z = AVG(y), v = VALUES(f) BY h"
        )
        self.assertEqual(
            [
                ("m", "max", None, False),
                ("n", "min", None, False),
                ("t", "sum", None, False),
                ("u", "count_distinct", None, False),
                ("w", "count_distinct", None, False),
                ("z", "avg", None, False),
                ("v", "values", "f", True),
            ],
            [tuple(a) for a in query.stats.aggregates],
        )

    def test_stats_rejected(self):
        for query, message in (
            ("STATS COUNT(*) BY h", "Unsupported aggregate without a name"),
            ("STATS c = h BY h", "Unsupported aggregate c, it must be a function"),
            ("STATS c = COUNT(*) BY h | STATS d = COUNT(*)", "Unsupported second STATS"),
            ("LIMIT 5 | STATS c = COUNT(*) BY h", "Unsupported pipe before STATS: LIMIT"),
            ("STATS c = COUNT(*) BY h | LIMIT 5 | WHERE c > 1", "Unsupported pipe before WHERE: LIMIT"),
            ("ENRICH p ON f | STATS c = COUNT(*) BY h", "Unsupported command: ENRICH"),
            ("MV_EXPAND f + 1 | STATS c = COUNT(*) BY h", "Unsupported MV_EXPAND of an expression"),
            ("STATS c = COUNT(*) BY _id", "Unsupported predicate on metadata field"),
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, message):
                esql.parse(f"FROM x METADATA _id | {query}")
        for query in ("STATS", "STATS c = COUNT(*) BY", "STATS c = COUNT(*) BY ,", "STATS ,"):
            with self.subTest(query), self.assertRaises(esql.EsqlParseError):
                esql.parse(f"FROM x | {query}")

    def test_eval_before_stats(self):
        def keys(text):
            stats = esql.parse(text).stats
            return list(stats.by), list(stats.join)

        base = "STATS c = COUNT(*) BY"
        self.assertEqual((["k"], ["a", "b"]), keys(f"FROM x | EVAL k = COALESCE(a, b) | {base} k"))
        self.assertEqual((["w", "h"], ["h"]), keys(f"FROM x | EVAL w = DATE_TRUNC(30 seconds, @timestamp) | {base} w, h"))
        self.assertEqual((["k"], ["f"]), keys(f"FROM x | EVAL a = f | EVAL k = TO_LOWER(a) | {base} k"))
        self.assertEqual((["k"], ["f", "g"]), keys(f"FROM x | EVAL a = f, k = CONCAT(a, g) | {base} k"))
        self.assertEqual((["h"], ["h"]), keys(f"FROM x | {base} DATE_TRUNC(1 hour, @timestamp), h"))
        self.assertEqual((["k"], ["h"]), keys(f"FROM x | {base} k = h"))
        self.assertEqual((["k"], ["h"]), keys(f"FROM x | {base} k = TO_LOWER(h)"))
        self.assertEqual((["k"], ["ip"]), keys(f"FROM x | EVAL k = ip::STRING | {base} k"))
        self.assertEqual((["k"], ["a.b", "c d"]), keys(f'FROM x | EVAL k = CONCAT(a.b, `c d`, "literal and or not x.y") | {base} k'))
        self.assertEqual((["k"], ["f"]), keys(f'FROM x | EVAL k = CASE(f == "a" AND NOT f IS NULL, "yes", "no") | {base} k'))
        # what is not a field is not a dependency
        self.assertEqual(([], []), keys("FROM x | EVAL k = NOW() - 1 hour | STATS c = COUNT(*)"))
        # the ones before a WHERE and the ones that are not used
        self.assertEqual((["h"], ["h"]), keys(f"FROM x | EVAL k = LOWER(z) | WHERE a == 1 | {base} h"))

    def test_comments_in_the_commands(self):
        # they are everywhere in the rules, and they must not hide a name or make one up
        query = esql.parse("""FROM x
            | EVAL
                // hosts with a lot of load, k is not a field of the documents
                k = CASE(a == "x // not a comment" AND b >= 1, host.id, NULL), /* another one */
                // and the last
                z = c
            | STATS
                // how many
                d = COUNT_DISTINCT(k), /* and the key */
                e = COUNT(*) BY z // by the alias
            | WHERE d >= 2""")
        self.assertEqual(("z",), query.stats.by)
        self.assertEqual(("c",), query.stats.join)
        self.assertEqual([("d", "count_distinct", None, False), ("e", "count", None, True)], [tuple(a) for a in query.stats.aggregates])
        with self.assertRaisesRegex(NotImplementedError, "Unsupported WHERE on a field made by EVAL: k"):
            esql.parse('FROM x | EVAL /* c */ // c\n k = TO_LOWER(a) // c\n | WHERE k == "x"')

    def test_aliases_of_the_query(self):
        self.assertEqual(("k", "z"), esql.parse("FROM x | EVAL k = TO_LOWER(a), z = b | STATS c = COUNT(*) BY k").aliases)
        self.assertEqual((), esql.parse("FROM x | WHERE a == 1").aliases)
        # a field that an EVAL makes out of itself is still one of the documents
        self.assertEqual(("k",), esql.parse("FROM x | EVAL a = TO_LOWER(a), k = a").aliases)

    def test_grok_and_dissect_make_fields_like_eval_does(self):
        def keys(text):
            stats = esql.parse(text).stats
            return list(stats.by), list(stats.join)

        base = "STATS c = COUNT(*) BY"
        # the fields that a pattern extracts are made out of the one that it reads
        self.assertEqual((["k"], ["a"]), keys('FROM x | GROK a """id=(?<k>[^,}\\]]+)""" | ' + base + " k"))
        self.assertEqual((["w"], ["a.b"]), keys('FROM x | GROK a.b "%{WORD:w} %{NUMBER:n:int} %{GREEDYDATA}" | ' + base + " w"))
        self.assertEqual((["n"], ["a.b"]), keys('FROM x | GROK a.b "%{WORD:w} %{NUMBER:n:int}" | ' + base + " n"))
        self.assertEqual((["k"], ["a"]), keys('FROM x | DISSECT a "%{}id=%{k} %{+k} %{?skip}" | ' + base + " k"))
        self.assertEqual((["k"], ["z"]), keys('FROM x | EVAL u = z | GROK u "%{WORD:w}" | DISSECT w "%{k}" | ' + base + " k"))
        self.assertEqual((["k"], ["my field"]), keys('FROM x | GROK `my field` "%{WORD:k}" | ' + base + " k"))
        self.assertEqual(("k", "r"), esql.parse('FROM x | GROK a """(?<k>.)""" | EVAL r = 1 | KEEP r').aliases)
        # not used, it just goes through
        self.assertEqual(eql.parse_expression("b == 1"), esql.parse('FROM x | GROK a "%{WORD:w}" | WHERE b == 1').where)
        for command, name in (('GROK a "%{WORD:w}"', "GROK"), ('DISSECT a "%{w}"', "DISSECT"), ("EVAL w = TO_LOWER(a)", "EVAL")):
            with self.subTest(command), self.assertRaisesRegex(NotImplementedError, f"Unsupported WHERE on a field made by {name}: w"):
                esql.parse(f'FROM x | {command} | WHERE w == "x"')
        # after STATS they are not what STATS said
        with self.assertRaisesRegex(NotImplementedError, "Unsupported WHERE on a field made by EVAL after STATS: c"):
            esql.parse('FROM x | STATS c = COUNT(*) | GROK a """(?<c>.)""" | WHERE c == "x"')

    def test_grok_and_dissect_depend_on_all_that_they_read(self):
        def join(text):
            return list(esql.parse(text).stats.join)

        base = " | STATS c = COUNT(*) BY k"
        self.assertEqual(["user.name", "host.name"], join('FROM x | GROK CONCAT(user.name, host.name) "%{GREEDYDATA:k}"' + base))
        self.assertEqual(["a"], join('FROM x | GROK CONCAT(a, "-x") "%{WORD:k}"' + base))
        self.assertEqual(["a", "b"], join('FROM x | DISSECT TO_LOWER(CONCAT(a, " ", b)) "%{k} %{j}"' + base))
        self.assertEqual(["a", "b"], join('FROM x | EVAL u = CONCAT(a, b) | GROK u "(?<k>.)"' + base))
        # the strings of what is read are not the pattern
        self.assertEqual(("k",), esql.parse('FROM x | GROK CONCAT(a, "%{WORD:bad}") "%{WORD:k}"').aliases)
        self.assertEqual(("k",), esql.parse('FROM x | DISSECT CONCAT(a, "%{bad}") "%{k}" APPEND_SEPARATOR=","').aliases)
        self.assertEqual(("k", "j"), esql.parse('FROM x | DISSECT a "%{k}:%{j}" APPEND_SEPARATOR="%{notaname}"').aliases)

    def test_dissect_names_are_the_complete_ones(self):
        for name in ("first-name", "a.b", "first name", "x@y", "a-b.c-d", "Esql.x_1"):
            for pattern in (f"%{{{name}}}", f"%{{{name}->}}", f"%{{+{name}}}", f"%{{+{name}/2}}", f"x=%{{{name}}} y"):
                with self.subTest(pattern):
                    self.assertEqual((name,), esql.parse(f'FROM x | DISSECT a "{pattern}"').aliases)
        self.assertEqual((), esql.parse('FROM x | DISSECT a "%{} %{?skip} %{?} %{+} %{->}"').aliases)
        for name in ("first-name", "a b"):
            with self.subTest(name), self.assertRaisesRegex(NotImplementedError, "Unsupported WHERE on a field made by DISSECT"):
                esql.parse(f'FROM x | DISSECT a "%{{{name}}}" | WHERE `{name}` == "x"')
        # the names of the other fields are not known, so no WHERE can be told from them
        for pattern in ("%{*key}=%{&key}", "%{&key}"):
            with self.subTest(pattern), self.assertRaisesRegex(NotImplementedError, "Unsupported DISSECT pattern with reference keys"):
                esql.parse(f'FROM x | DISSECT a "{pattern}"')

    def test_grok_names_are_the_complete_ones(self):
        for pattern in ('"%{WORD:first-name}"', '"%{WORD:first-name:int}"', '"""(?<first-name>.+)"""'):
            with self.subTest(pattern):
                self.assertEqual(("first-name",), esql.parse(f"FROM x | GROK a {pattern}").aliases)
                with self.assertRaisesRegex(NotImplementedError, "Unsupported WHERE on a field made by GROK"):
                    esql.parse(f'FROM x | GROK a {pattern} | WHERE `first-name` == "x"')

    def test_mv_expand_of_what_an_eval_makes(self):
        # the number of values of what a function makes is not known, the rows that STATS counts depend on it
        for query in (
            'EVAL k = SPLIT("a,b", ",") | MV_EXPAND k | STATS c = COUNT(*)',
            'EVAL k = SPLIT(f, ",") | MV_EXPAND k | STATS c = COUNT(*) BY g',
            "EVAL u = f, k = MV_CONCAT(u, g) | MV_EXPAND k | STATS c = COUNT(*)",
        ):
            with self.subTest(query), self.assertRaisesRegex(
                NotImplementedError, "Unsupported STATS after MV_EXPAND of a field made by EVAL"
            ):
                esql.parse(f"FROM x | {query}")
        # a rename is the field that it renames, and what GROK and DISSECT extract is one text
        self.assertEqual(("f",), esql.parse("FROM x | EVAL k = f | MV_EXPAND k | STATS c = COUNT(*)").stats.expanded)
        self.assertEqual(("f",), esql.parse("FROM x | EVAL u = f, k = u | MV_EXPAND k | STATS c = COUNT(*)").stats.expanded)
        self.assertEqual((), esql.parse('FROM x | GROK f "%{WORD:k}" | MV_EXPAND k | STATS c = COUNT(*)').stats.expanded)
        # without STATS nothing is counted
        esql.parse('FROM x | EVAL k = SPLIT("a,b", ",") | MV_EXPAND k')
        # after STATS it is about what STATS made
        esql.parse('FROM x | STATS c = COUNT(*) | EVAL k = SPLIT("a,b", ",") | MV_EXPAND k')

    def test_mv_expand_goes_through(self):
        # the documents have one value, which is one row each: it does not change which documents match
        self.assertEqual(eql.parse_expression('a == "x"'), esql.parse('FROM x | MV_EXPAND a | WHERE a == "x"').where)
        self.assertEqual(
            eql.parse_expression('b == 1 and a == "x"'), esql.parse('FROM x | WHERE b == 1 | MV_EXPAND `a` | WHERE a == "x"').where
        )
        stats = esql.parse("FROM x | MV_EXPAND a | MV_EXPAND b.c | EVAL k = a | MV_EXPAND k | STATS c = COUNT(*) BY h").stats
        self.assertEqual(("a", "b.c"), stats.expanded)  # k is not a field of the documents
        stats = esql.parse("FROM x | STATS c = COUNT(*) BY h | MV_EXPAND h").stats
        self.assertEqual((), stats.expanded)

    def test_names_that_an_eval_after_stats_overwrites(self):
        for query in (
            "FROM x | STATS c = COUNT(*) | EVAL c = 0 | WHERE c >= 2",
            'FROM x | STATS c = COUNT(*) BY h | EVAL h = TO_LOWER(h) | WHERE h == "x"',
            "FROM x | STATS c = COUNT(*) BY h | EVAL r = 1, c = r | KEEP c | WHERE c > 1",
            "FROM x | STATS c = COUNT(*) | EVAL /* c */ `c` = 0 | WHERE NOT c < 2",
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported WHERE on a field made by EVAL after STATS"):
                esql.parse(query)
        # before the EVAL it is what STATS made, and what the EVAL makes of another name does not matter
        esql.parse("FROM x | STATS c = COUNT(*) BY h | WHERE c >= 2 | EVAL c = 0")
        esql.parse("FROM x | STATS c = COUNT(*) BY h | EVAL r = c * 2 | WHERE c >= 2")

    def test_limit_zero_with_comments(self):
        for query in (
            "FROM x | LIMIT 0 // nothing",
            "FROM x | LIMIT /* nothing */ 0",
            "FROM x | LIMIT 0 /* nothing */ | KEEP a",
            "FROM x | LIMIT // nothing\n 0",
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported LIMIT 0"):
                esql.parse(query)
        esql.parse("FROM x | LIMIT 10 // not 0")

    def test_eval_aliases_are_not_fields_of_the_documents(self):
        with self.assertRaisesRegex(NotImplementedError, "Unsupported WHERE on a field made by EVAL: k"):
            esql.parse('FROM x | EVAL k = TO_LOWER(a) | WHERE k == "x"')
        with self.assertRaisesRegex(NotImplementedError, "Unsupported WHERE on a field made by EVAL: `my k`"):
            esql.parse("FROM x | EVAL `my k` = a | WHERE NOT `my k` IS NULL")
        # an alias that a WHERE redefines is still one
        with self.assertRaisesRegex(NotImplementedError, "Unsupported WHERE on a field made by EVAL"):
            esql.parse('FROM x | EVAL a = TO_LOWER(a) | WHERE a == "x"')
        # unrelated fields are fine
        esql.parse('FROM x | EVAL k = TO_LOWER(a) | WHERE b == "x" | STATS c = COUNT(*) BY k')

    def test_eval_without_stats_is_unsupported(self):
        # an EVAL changes the columns, not which documents match: fine when nothing asks for what it makes
        self.assertEqual(eql.parse_expression("a == 1"), esql.parse("FROM x | EVAL k = a | WHERE a == 1 | KEEP k").where)
        self.assertEqual(eql.ast.Boolean(True), esql.parse("FROM x | EVAL k = a").where)


class TestEsqlRouting(unittest.TestCase):
    def test_guess_esql(self):
        for query in (
            "FROM idx | WHERE a == 1",
            "from idx | where a == 1",
            "  \n\tFrom idx | Where a == 1",
            "FROM idx",
        ):
            with self.subTest(query):
                guess = guess_from_query(query)
                self.assertEqual("esql", guess.type)
                self.assertEqual("esql", guess.language)
                self.assertEqual(query, guess.query)
                self.assertEqual(esql.to_eql(query), guess.ast)

    def test_guess_esql_after_comments(self):
        for query in (
            '/* comment */ FROM x | WHERE a == "foo"',
            '// comment\nFROM x | WHERE a == "foo"',
            '// one\n// two\n/* three */ // four\n  /* five\nsix */\n\tfrom x | where a == "foo"',
            '/**/FROM x | WHERE a == "foo"',
            '// comment\r\nFROM x | WHERE a == "foo"',
            'FROM/* comment */ x | WHERE a == "foo"',
            'from//comment\nx | where a == "foo"',
            'FROM/**/x | WHERE a == "foo"',
            '/* a */FROM/* b */ // c\n /* d */x | WHERE a == "foo"',
        ):
            with self.subTest(query):
                guess = guess_from_query(query)
                self.assertEqual("esql", guess.language)
                self.assertEqual(esql.to_eql('FROM x | WHERE a == "foo"'), guess.ast)
        for query in ("/* comment */ ROW a = 1", "// comment\nSHOW INFO", "show/* comment */INFO", "ROW//c\na = 1"):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported source command"):
                guess_from_query(query)

    def test_guess_kql_starting_with_from_still_kql(self):
        for query in ("from:foo", 'from: "x"', "from:foo and bar:baz", "fromage:1", "from : foo", "show :x", "row  : 1"):
            with self.subTest(query):
                guess = guess_from_query(query)
                self.assertEqual("query", guess.type)
                self.assertEqual("kuery", guess.language)

    def test_guess_others_unchanged(self):
        self.assertEqual("eql", guess_from_query('process where process.name == "a"').language)
        self.assertEqual("kuery", guess_from_query("process.name: a").language)

    def test_guess_esql_error_propagates(self):
        # no fallback to EQL or KQL: they would accept some of these as plain text
        for query in ("FROM x | ENRICH p ON b", "FROM x | LIMIT 1 | WHERE a == 1", "ROW a = 1", "SHOW INFO"):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported"):
                guess_from_query(query)
        for query in ("FROM x | WHERE", "FROM x |", "from  x | where a =="):
            with self.subTest(query), self.assertRaisesRegex(ValueError, r"ES\|QL query error"):
                guess_from_query(query)

    def test_rule_esql(self):
        rule = SimpleNamespace(type="esql", language="esql", query='FROM idx | WHERE a == "x"')
        self.assertEqual(esql.to_eql(rule.query), ast_from_rule(rule))

        for rule_type, language in (("esql", "kuery"), ("esql", "eql"), ("query", "esql"), ("eql", "esql")):
            rule = SimpleNamespace(type=rule_type, language=language, query="FROM idx | WHERE a == 1")
            with self.subTest(rule_type, language=language), self.assertRaisesRegex(NotImplementedError, "Unsupported"):
                ast_from_rule(rule)

        rule = SimpleNamespace(type="esql", language="esql", query="FROM idx | ENRICH p ON b")
        with self.assertRaisesRegex(NotImplementedError, "Unsupported command: ENRICH"):
            ast_from_rule(rule)

    def test_rule_types_unchanged(self):
        rule = SimpleNamespace(type="query", language="kuery", query="a: b")
        self.assertEqual(guess_from_query("a: b").ast, ast_from_rule(rule))
        with self.assertRaisesRegex(NotImplementedError, "Unsupported rule type: threshold"):
            ast_from_rule(SimpleNamespace(type="threshold", language="kuery", query="a: b"))
        with self.assertRaisesRegex(NotImplementedError, "Unsupported query language: lucene"):
            ast_from_rule(SimpleNamespace(type="query", language="lucene", query="a: b"))


class TestEsqlProvenance(tu.QueryTestCase, tu.SeededTestCase, unittest.TestCase):
    """The AST from to_eql() carries its ES|QL origin, so that no caller has to remember it."""

    maxDiff = None
    long_schema: ClassVar[dict] = {"n": {"type": "long"}, "m": {"type": "long"}}

    def flags(self, ast):
        """Return the flags of the constraints, as a list of {field: [flags, ...]} for each branch."""
        return [
            {field: [c[2] for c in constraints] for doc in branch for field, constraints in doc.items() if constraints}
            for branch in collect_constraints(ast)
        ]

    def test_to_eql_wraps_the_plain_tree(self):
        query = 'FROM x | WHERE a == 1 AND b LIKE "x*"'
        self.assertEqual(eql.ast.FunctionCall("_esql", [where(query)]), esql.to_eql(query))
        self.assertEqual(eql.ast.FunctionCall("_esql", [eql.ast.Boolean(True)]), esql.to_eql("FROM x"))
        self.assertIsInstance(where(query), eql.ast.And)

    def test_add_ast_checks_without_flags(self):
        se = SourceEvents(self.long_schema)
        with self.assertRaisesRegex(NotImplementedError, "Unsupported fractional number"):
            se.add_ast(esql.to_eql("FROM x | WHERE n == 1.5"))
        se = SourceEvents({"source.ip": {"type": "ip"}})
        with self.assertRaisesRegex(NotImplementedError, "Unsupported network literal"):
            se.add_ast(esql.to_eql('FROM x | WHERE source.ip == "10.0.0.0/8"'))

    def test_add_ast_from_rule_checks_without_flags(self):
        rule = SimpleNamespace(type="esql", language="esql", query="FROM x | WHERE n >= 1.5 AND n < 2")
        se = SourceEvents(self.long_schema)
        with self.assertRaisesRegex(NotImplementedError, "Unsupported fractional number"):
            se.add_ast(ast_from_rule(rule))
        rule = SimpleNamespace(type="esql", language="esql", query="FROM x | WHERE n == 2")
        se = SourceEvents(self.long_schema)
        se.add_ast(ast_from_rule(rule))
        self.assertEqual([{"n": 2}], [event.doc for event in se.emit(timestamp=False)])

    def test_other_languages_are_not_checked(self):
        for query in ("any where n >= 1.5", "n >= 1.5"):
            with self.subTest(query):
                se = SourceEvents(self.long_schema)
                se.add_ast(guess_from_query(query).ast)
                self.assertEqual(1, len(list(se.emit(timestamp=False))))
        se = SourceEvents(self.long_schema)
        se.add_ast(eql.parse_expression("n == 1.5"))
        self.assertEqual([{"n": 1}], [event.doc for event in se.emit(timestamp=False)])

    def test_case_sensitive_flag_survives(self):
        flags = self.flags(esql.to_eql('FROM x | WHERE k LIKE "x*" AND m == 1'))
        self.assertEqual([{"k": [{"case_sensitive": True, "esql": True}], "m": [{"esql": True}]}], flags)

        se = SourceEvents(self.schema)
        se.stack_version = self.stack_version
        with self.assertRaises(ConflictError):
            se.add_ast(esql.to_eql('FROM x | WHERE event.category LIKE "PRO*"'))
        se = SourceEvents(self.schema)
        se.add_ast(esql.to_eql('FROM x | WHERE process.name LIKE "FOO*"'))
        self.assertTrue(all(event.doc["process"]["name"].startswith("FOO") for event in se.emit(timestamp=False, count=10)))

    def test_kql_constraints_are_not_flagged_as_esql(self):
        flags = self.flags(esql.to_eql('FROM x | WHERE KQL("a: b and c: x*") AND d == 1'))
        self.assertEqual([{"a": [{"kql": True}], "c": [{"kql": True}], "d": [{"esql": True}]}], flags)
        flags = self.flags(esql.to_eql('FROM x | WHERE NOT KQL("a: b")'))
        self.assertEqual([{"a": [{"kql": True}]}], flags)
        # the KQL string keeps the semantics of KQL, as for the rules of type query
        se = SourceEvents(self.long_schema)
        se.add_ast(esql.to_eql('FROM x | WHERE KQL("n >= 1.5")'))
        self.assertEqual(1, len(list(se.emit(timestamp=False))))
        with self.assertRaisesRegex(NotImplementedError, "Unsupported fractional number"):
            se = SourceEvents(self.long_schema)
            se.add_ast(esql.to_eql('FROM x | WHERE KQL("m: 1") AND n >= 1.5'))

    def test_literal_constraints_are_flagged(self):
        flags = self.flags(esql.to_eql('FROM x | WHERE a == "f*o" AND b == "x"'))
        self.assertEqual([{"a": [{"literal": True, "esql": True}], "b": [{"esql": True}]}], flags)
        flags = self.flags(esql.to_eql('FROM x | WHERE KQL("f:\\"*\\"")'))
        self.assertEqual([{"f": [{"literal": True, "kql": True}]}], flags)

    def test_only_esql_constraints_are_flagged_in_mixed_trees(self):
        esql_node = esql.to_eql('FROM x | WHERE k LIKE "x*" AND m == 1')
        eql_node = eql.parse_expression("n == 2")
        for terms in ([esql_node, eql_node], [eql_node, esql_node]):
            ast = eql.ast.And(terms)
            self.assertEqual(
                [{"k": [{"case_sensitive": True, "esql": True}], "m": [{"esql": True}], "n": [{}]}],
                self.flags(ast),
            )
        # an EQL wildcard keeps its own meaning next to an ES|QL one
        ast = eql.ast.And([esql.to_eql('FROM x | WHERE k LIKE "x*"'), eql.parse_expression('wildcard(j, "Y*")')])
        self.assertEqual([{"k": [{"case_sensitive": True, "esql": True}], "j": [{}]}], self.flags(ast))

        se = SourceEvents(self.long_schema)
        se.add_ast(eql.ast.And([esql.to_eql("FROM x | WHERE m == 1"), eql.parse_expression("n == 1.5")]))
        self.assertEqual([{"m": 1, "n": 1}], [event.doc for event in se.emit(timestamp=False)])
        se = SourceEvents(self.long_schema)
        with self.assertRaisesRegex(NotImplementedError, "Unsupported fractional number"):
            se.add_ast(eql.ast.And([esql.to_eql("FROM x | WHERE n == 1.5"), eql.parse_expression("m == 1")]))

    def test_negated_trees_are_flagged_as_well(self):
        # De Morgan splits the AND in two branches, one constraint each
        ast = eql.ast.Not(esql.to_eql('FROM x | WHERE k LIKE "x*" AND m == 1'))
        self.assertEqual([{"k": [{"esql": True}]}, {"m": [{"esql": True}]}], self.flags(ast))
        ast = eql.ast.Not(eql.ast.And([esql.to_eql("FROM x | WHERE m == 1"), eql.parse_expression("n == 2")]))
        self.assertEqual([{"m": [{"esql": True}]}, {"n": [{}]}], self.flags(ast))
        ast = eql.ast.Not(eql.parse_expression("n == 2"))
        self.assertEqual([{"n": [{}]}], self.flags(ast))

        se = SourceEvents(self.long_schema)
        with self.assertRaisesRegex(NotImplementedError, "Unsupported fractional number"):
            se.add_ast(eql.ast.Not(esql.to_eql("FROM x | WHERE n == 1.5")))

    def test_no_where(self):
        se = SourceEvents(self.long_schema)
        se.add_ast(esql.to_eql("FROM x"))
        self.assertEqual([{}], [event.doc for event in se.emit(timestamp=False)])


class TestEsqlStatsEmission(tu.QueryTestCase, tu.SeededTestCase, unittest.TestCase):
    """The documents that a threshold on an aggregate asks for: a group of them, the same for the fields of BY."""

    maxDiff = None
    pre = 'FROM x | WHERE process.name == "a.exe" | STATS c = COUNT(*)'

    def branches(self, query, schema=None, **kwargs):
        se = SourceEvents(self.schema if schema is None else schema)
        se.stack_version = self.stack_version
        for key, value in kwargs.items():
            setattr(se, key, value)
        se.add_query(query)
        return [[event.doc for event in branch] for branch in se.emit(timestamp=False, complete=True, count=1)]

    def assertShared(self, docs, field, shared=True):
        values = []
        for doc in docs:
            value = doc
            for part in field.split("."):
                value = value[part]
            values.append(value)
        self.assertEqual(1 if shared else len(docs), len(set(values)), values)

    def test_count_thresholds(self):
        for condition, size in (
            (">= 5", 5),
            ("> 5", 6),
            ("== 4", 4),
            ("<= 3", 1),
            ("< 3", 1),
            (">= 3 AND c <= 10", 3),
            ("> 2 AND c < 9", 3),
            ("!= 1", 2),
            (">= 3 AND c != 3", 4),
            (">= 2.5", 3),
            ("> 2.5", 3),
        ):
            with self.subTest(condition):
                branches = self.branches(f"{self.pre} BY host.id | WHERE c {condition}")
                self.assertEqual(1, len(branches))
                docs = branches[0]
                self.assertEqual(size, len(docs))
                self.assertTrue(all(doc["process"]["name"] == "a.exe" for doc in docs), docs)
                self.assertShared(docs, "host.id")

    def test_negated_conditions(self):
        self.assertEqual(1, len(self.branches(f"{self.pre} BY host.id | WHERE NOT c >= 3")[0]))
        self.assertEqual(4, len(self.branches(f"{self.pre} BY host.id | WHERE NOT (c <= 3)")[0]))

    def test_no_condition_and_no_by(self):
        branches = self.branches(f"{self.pre} BY host.id")
        self.assertEqual(1, len(branches[0]))
        branches = self.branches(f"{self.pre} | WHERE c >= 3")
        self.assertEqual([[{"process": {"name": "a.exe"}}] * 3], branches)

    def test_several_by_fields(self):
        docs = self.branches(f"{self.pre} BY host.id, user.name, source.ip | WHERE c >= 4")[0]
        self.assertEqual(4, len(docs))
        for field in ("host.id", "user.name", "source.ip"):
            self.assertShared(docs, field)

    def test_alias_with_dots(self):
        docs = self.branches("FROM x | STATS Esql.event_count = COUNT(*) BY host.id | WHERE Esql.event_count >= 3")[0]
        self.assertEqual(3, len(docs))
        docs = self.branches("FROM x | STATS `my count` = COUNT(*) BY host.id | WHERE `my count` >= 2")[0]
        self.assertEqual(2, len(docs))

    def test_unsatisfiable_thresholds(self):
        for condition in (">= 5 AND c < 3", "== 0", "< 1", "> 4 AND c <= 4"):
            with self.subTest(condition), self.assertRaisesRegex(ValueError, "Unsolvable constraints"):
                self.branches(f"{self.pre} BY host.id | WHERE c {condition}")

    def test_too_many_documents(self):
        with self.assertRaisesRegex(NotImplementedError, "Unsupported threshold"):
            self.branches(f"{self.pre} BY host.id | WHERE c >= 100000")

    def test_disjunctions_are_branches(self):
        branches = self.branches(f"{self.pre} BY host.id | WHERE c >= 5 OR c == 2")
        self.assertEqual([5, 2], [len(docs) for docs in branches])
        se_branches = self.branches('FROM x | WHERE process.name IN ("a.exe", "b.exe") | STATS c = COUNT(*) BY host.id | WHERE c >= 3')
        self.assertEqual([3, 3], [len(docs) for docs in se_branches])
        self.assertEqual(["a.exe", "b.exe"], [docs[0]["process"]["name"] for docs in se_branches])

    def test_count_distinct(self):
        base = "FROM x | STATS c = COUNT(*), d = COUNT_DISTINCT(user.name) BY host.id"
        docs = self.branches(f"{base} | WHERE d >= 3")[0]
        self.assertEqual(3, len(docs))
        self.assertShared(docs, "user.name", shared=False)
        self.assertShared(docs, "host.id")

        docs = self.branches(f"{base} | WHERE d >= 2 AND c >= 6")[0]
        self.assertEqual(6, len(docs))
        self.assertGreaterEqual(len({doc["user"]["name"] for doc in docs}), 2)

        docs = self.branches(f"{base} | WHERE d == 1 AND c >= 4")[0]
        self.assertEqual(4, len(docs))
        self.assertShared(docs, "user.name")

        docs = self.branches(f"{base} | WHERE d <= 1")[0]
        self.assertEqual(1, len(docs))

        docs = self.branches(f"{base} | WHERE d > 3 AND c >= 2")[0]
        self.assertEqual(4, len(docs))
        self.assertShared(docs, "user.name", shared=False)

    def test_count_distinct_cannot_exceed_the_documents(self):
        base = "FROM x | STATS c = COUNT(*), d = COUNT_DISTINCT(user.name) BY host.id"
        with self.assertRaisesRegex(ValueError, "Unsolvable constraints"):
            self.branches(f"{base} | WHERE d >= 5 AND c <= 3")
        with self.assertRaisesRegex(NotImplementedError, "Unsupported"):
            self.branches(f"{base} | WHERE d >= 2 AND d <= 3 AND c >= 6")

    def test_distinct_values_are_distinct(self):
        docs = self.branches('FROM x | WHERE process.name == "a.exe" | STATS d = COUNT_DISTINCT(process.pid) BY host.id | WHERE d >= 6')[0]
        self.assertEqual(6, len(docs))
        self.assertShared(docs, "process.pid", shared=False)
        # when the query leaves no room for that many values it is said
        with self.assertRaises((ValueError, IndexError)):
            self.branches('FROM x | WHERE process.name == "a.exe" | STATS d = COUNT_DISTINCT(process.name) BY host.id | WHERE d >= 2')

    def test_the_join_document_is_flagged_too(self):
        # the document that holds what the group shares is not one of the emitted, it follows the same rules
        schema = {"b": {"type": "boolean"}, "n": {"type": "long"}}
        for value, expected in (("false", False), ("true", True)):
            docs = self.branches(f'FROM x | WHERE b == "{value}" | STATS c = COUNT(*) BY b | WHERE c >= 2', schema=schema)[0]
            self.assertEqual([{"b": expected}] * 2, docs)
        with self.assertRaisesRegex(NotImplementedError, "Unsupported value for boolean field"):
            self.branches('FROM x | WHERE b == "maybe" | STATS c = COUNT(*) BY b | WHERE c >= 2', schema=schema)
        with self.assertRaisesRegex(NotImplementedError, "Unsupported fractional number"):
            self.branches("FROM x | WHERE n >= 1.5 | STATS c = COUNT(*) BY n | WHERE c >= 2", schema=schema)

    def test_count_distinct_upper_bounds(self):
        base = "FROM x | STATS c = COUNT(*), d = COUNT_DISTINCT(user.name)"
        for condition, size, most in (
            ("c >= 5 AND d <= 2", 5, 2),
            ("c >= 6 AND d < 4", 6, 3),
            ("c >= 4 AND d <= 3", 4, 3),
            ("c >= 4 AND d <= 10", 4, 4),
        ):
            for seed in range(25):
                with self.subTest(f"{condition} {seed}"):
                    docs = self.branches(f"{base} | WHERE {condition}")[0]
                    self.assertEqual(size, len(docs))
                    self.assertLessEqual(len({doc["user"]["name"] for doc in docs}), most, docs)
        # no way to have at least some and at most some, in between, of the documents
        with self.assertRaisesRegex(NotImplementedError, "Unsupported number of different values"):
            self.branches(f"{base} | WHERE c >= 6 AND d >= 2 AND d <= 3")

    def test_excluded_counts(self):
        base = "FROM x | STATS c = COUNT(*), d = COUNT_DISTINCT(user.name)"
        for condition, size in (
            ("c != 2 AND d >= 2", 3),
            ("c != 2 AND c != 3 AND d >= 2", 4),
            ("c >= 2 AND c != 2", 3),
            ("c != 1", 2),
            ("d >= 3 AND c != 3 AND c != 4", 5),
        ):
            with self.subTest(condition):
                self.assertEqual(size, len(self.branches(f"{base} | WHERE {condition}")[0]))
        with self.assertRaisesRegex(ValueError, "Unsolvable constraints"):
            self.branches(f"{base} | WHERE c != 2 AND d >= 2 AND c <= 2")
        with self.assertRaisesRegex(NotImplementedError, "Unsupported exclusion"):
            self.branches(f"{base} | WHERE d != 2 AND c >= 3")

    def test_count_of_multivalued_fields(self):
        # the count is of the values, each document has two of them
        for aggregate in ("COUNT(process.args)", "COUNT_DISTINCT(process.args)"):
            with self.subTest(aggregate), self.assertRaisesRegex(NotImplementedError, "Unsupported .* of a field with many values"):
                self.branches(f'FROM x | WHERE KQL("process.args: a AND process.args: b") | STATS c = {aggregate} | WHERE c >= 2')
        # one value is just a document
        docs = self.branches('FROM x | WHERE KQL("process.args: a") | STATS c = COUNT(process.args) | WHERE c >= 2')[0]
        self.assertEqual([{"process": {"args": ["a"]}}] * 2, docs)

    def test_count_distinct_of_a_by_field(self):
        with self.assertRaisesRegex(NotImplementedError, "Unsupported COUNT_DISTINCT of a BY field"):
            self.branches("FROM x | STATS d = COUNT_DISTINCT(user.name) BY user.name | WHERE d >= 2")
        with self.assertRaisesRegex(NotImplementedError, "Unsupported COUNT_DISTINCT of a BY field"):
            self.branches("FROM x | EVAL k = user.name | STATS d = COUNT_DISTINCT(user.name) BY k | WHERE d >= 2")
        # one value is what a BY field has
        docs = self.branches("FROM x | STATS d = COUNT_DISTINCT(user.name), c = COUNT(*) BY user.name | WHERE d == 1 AND c >= 3")[0]
        self.assertEqual(3, len(docs))
        self.assertShared(docs, "user.name")

    def test_conditions_on_the_by_fields_follow_the_rules_of_the_query(self):
        # tags is an array in the schema: both values would be there, and the first comparison would be null
        with self.assertRaisesRegex(NotImplementedError, "Unsupported conflicting constraints on tags"):
            self.branches('FROM x | WHERE tags == "a" | STATS c = COUNT(*) BY tags | WHERE tags == "b" AND c >= 2')
        with self.assertRaisesRegex(NotImplementedError, "Unsupported conflicting constraints on tags"):
            self.branches('FROM x | WHERE tags LIKE "a*" | STATS c = COUNT(*) BY tags | WHERE tags == "b" AND c >= 2')
        docs = self.branches('FROM x | WHERE tags == "a" | STATS c = COUNT(*) BY tags | WHERE tags != "b" AND c >= 2')[0]
        self.assertEqual([{"tags": ["a"]}] * 2, docs)

    def test_time_keys_share_the_timestamp(self):
        def timestamps(query):
            se = SourceEvents(self.schema)
            se.add_query(query)
            return [[event.doc["@timestamp"] for event in branch] for branch in se.emit(timestamp=True, complete=True, count=1)]

        for bucket in ("1 millisecond", "30 seconds", "1 hour"):
            with self.subTest(bucket):
                groups = timestamps(f"FROM x | STATS c = COUNT(*) BY DATE_TRUNC({bucket}, @timestamp), host.id | WHERE c >= 3 OR c == 2")
                self.assertEqual([3, 2], [len(group) for group in groups])
                for group in groups:
                    self.assertEqual(1, len(set(group)), group)
                self.assertNotEqual(groups[0][0], groups[1][0])

    def test_other_branches_keep_increasing_timestamps(self):
        se = SourceEvents(self.schema)
        se.add_query('sequence by user.name [process where process.name == "a"] [process where process.name == "b"]')
        (branch,) = [[event.doc["@timestamp"] for event in branch] for branch in se.emit(timestamp=True, complete=True, count=1)]
        self.assertEqual(2, len(set(branch)))
        self.assertEqual(sorted(branch), branch)

    def test_count_of_a_field(self):
        docs = self.branches("FROM x | STATS c = COUNT(user.name) BY host.id | WHERE c >= 3")[0]
        self.assertEqual(3, len(docs))
        self.assertTrue(all("name" in doc["user"] for doc in docs), docs)

    def test_unreferenced_aggregates_are_not_constraints(self):
        docs = self.branches(
            f"{self.pre}, first = MIN(@timestamp), last = MAX(@timestamp), s = SUM(process.pid), a = AVG(process.pid),"
            ' u = COUNT_DISTINCT(TO_LOWER(user.name)), t = SUM(CASE(host.name == "x", 1, 0)) BY host.id | WHERE c >= 2'
        )[0]
        self.assertEqual(2, len(docs))
        self.assertShared(docs, "host.id")

    def test_eval_keys_join_the_fields_they_come_from(self):
        base = 'FROM x | WHERE process.name == "a.exe" | EVAL {eval} | STATS c = COUNT(*) BY {by} | WHERE c >= 3'
        docs = self.branches(base.format(eval="k = TO_LOWER(host.name)", by="k"))[0]
        self.assertEqual(3, len(docs))
        self.assertShared(docs, "host.name")
        self.assertTrue(all("k" not in doc for doc in docs), docs)

        docs = self.branches(base.format(eval="k = COALESCE(host.name, user.name)", by="k"))[0]
        self.assertShared(docs, "host.name")
        self.assertShared(docs, "user.name")

        docs = self.branches(base.format(eval='a = host.name, k = CONCAT(a, user.name, "-x")', by="k, source.ip"))[0]
        for field in ("host.name", "user.name", "source.ip"):
            self.assertShared(docs, field)

        # the bucket of the time is not a field of the documents, all of them are written within a few milliseconds
        docs = self.branches(base.format(eval="w = DATE_TRUNC(30 seconds, @timestamp)", by="w, host.id"))[0]
        self.assertEqual(3, len(docs))
        self.assertShared(docs, "host.id")

        docs = self.branches(base.format(eval='k = REPLACE(process.executable, "[0-9]+", "N")', by="k"))[0]
        self.assertShared(docs, "process.executable")

        # a key that is just an expression, and one with a name
        docs = self.branches("FROM x | STATS c = COUNT(*) BY TO_LOWER(host.name), g = user.name | WHERE c >= 2")[0]
        self.assertShared(docs, "host.name")
        self.assertShared(docs, "user.name")

    def test_eval_aliases_are_not_generated(self):
        query = (
            'FROM x | WHERE process.name == "a.exe"\n| EVAL\n // a flag\n k = CASE(host.name == "x", user.name, NULL)\n'
            "| STATS c = COUNT(*), d = COUNT_DISTINCT(k) BY host.id | WHERE c >= 2"
        )
        # d is not asked for, so k is not either, and it is not a field of the documents
        docs = self.branches(query)[0]
        self.assertEqual(2, len(docs))
        self.assertTrue(all("k" not in doc for doc in docs), docs)
        with self.assertRaisesRegex(NotImplementedError, "Unsupported condition on the aggregate d"):
            self.branches(query.replace("c >= 2", "c >= 2 AND d >= 1"))

    def test_mv_expand_before_stats(self):
        base = 'FROM x | MV_EXPAND process.args | WHERE process.args == "a" | STATS c = COUNT(*) BY host.id | WHERE c >= 3'
        docs = self.branches(base)[0]
        self.assertEqual(3, len(docs))
        self.assertTrue(all(doc["process"]["args"] == ["a"] for doc in docs), docs)
        self.assertShared(docs, "host.id")
        # each document would be as many rows as it has values
        with self.assertRaisesRegex(
            NotImplementedError, "Unsupported STATS over a field that MV_EXPAND expands with many values: process.args"
        ):
            self.branches(
                'FROM x | WHERE KQL("process.args: a AND process.args: b") | MV_EXPAND process.args | STATS c = COUNT(*) | WHERE c >= 2'
            )
        # when STATS is not there it does not matter
        docs = self.branches('FROM x | WHERE KQL("process.args: a AND process.args: b") | MV_EXPAND process.args')[0]
        self.assertEqual([{"process": {"args": ["a", "b"]}}], docs)

    def test_grok_before_stats(self):
        docs = self.branches('FROM x | GROK user.name """id=(?<k>[^,]+)""" | STATS c = COUNT(*) BY k | WHERE c >= 3')[0]
        self.assertEqual(3, len(docs))
        self.assertShared(docs, "user.name")
        self.assertTrue(all("k" not in doc for doc in docs), docs)
        docs = self.branches('FROM x | WHERE process.name == "a.exe" | DISSECT user.name "%{k} %{j}" | STATS c = COUNT(*) | WHERE c >= 2')[
            0
        ]
        self.assertEqual([{"process": {"name": "a.exe"}}] * 2, docs)

    def test_values_just_collect(self):
        docs = self.branches("FROM x | STATS c = COUNT(*), v = VALUES(user.name) BY host.id | WHERE c >= 3")[0]
        self.assertEqual(3, len(docs))

    def test_conditions_on_the_by_fields(self):
        docs = self.branches(f'{self.pre} BY host.id | WHERE c >= 2 AND host.id LIKE "a*"')[0]
        self.assertTrue(all(doc["host"]["id"].startswith("a") for doc in docs), docs)
        self.assertShared(docs, "host.id")
        docs = self.branches(f'{self.pre} BY host.name | WHERE c >= 2 AND host.name == "x"')[0]
        self.assertEqual([{"process": {"name": "a.exe"}, "host": {"name": "x"}}] * 2, docs)
        docs = self.branches(f"{self.pre} BY host.name | WHERE c >= 2 AND host.name IS NOT NULL")[0]
        self.assertShared(docs, "host.name")

    def test_conditions_that_are_not_about_the_aggregates(self):
        for query, message in (
            (f"{self.pre} BY host.id | WHERE other >= 1", "Unsupported field in WHERE after STATS: other"),
            (f"{self.pre}, m = MIN(user.name) BY host.id | WHERE m > 5", "Unsupported condition on the aggregate m"),
            (f"{self.pre}, t = SUM(process.pid) BY host.id | WHERE t > 5", "Unsupported condition on the aggregate t"),
            (f"{self.pre}, u = COUNT_DISTINCT(TO_LOWER(user.name)) BY host.id | WHERE u >= 2", "Unsupported condition on the aggregate u"),
            (
                "FROM x | EVAL k = user.name | STATS d = COUNT_DISTINCT(k) BY host.id | WHERE d >= 2",
                "Unsupported condition on the aggregate d",
            ),
            (
                'FROM x | EVAL w = TO_LOWER(host.name) | STATS c = COUNT(*) BY w | WHERE w == "x"',
                "Unsupported field in WHERE after STATS: w",
            ),
            (f"{self.pre} BY host.id | EVAL r = c / 2 | WHERE r >= 1", "Unsupported WHERE on a field made by EVAL after STATS: r"),
            (f'{self.pre}, v = VALUES(user.name) BY host.id | WHERE v == "x"', "Unsupported condition on the values of v"),
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, message):
                self.branches(query)

    def test_the_branches_limit_is_the_one_of_the_documents(self):
        with self.assertRaisesRegex(ValueError, "Root with too many branches"):
            self.branches(
                'FROM x | WHERE process.name IN ("a", "b", "c") | STATS c = COUNT(*) BY host.id | WHERE c >= 2 OR c == 1', max_branches=5
            )

    def test_the_documents_are_not_shared_with_other_languages(self):
        # an aggregate says nothing to the other languages, and the documents do not change for the plain ones
        docs = self.branches('FROM x | WHERE process.name == "a.exe"')
        self.assertEqual([[{"process": {"name": "a.exe"}}]], docs)


class TestEsqlEmission(tu.QueryTestCase, tu.SeededTestCase, unittest.TestCase):
    maxDiff = None

    def emit(self, query, *, schema=None, count=20):
        se = SourceEvents(schema if schema is not None else self.schema)
        se.stack_version = self.stack_version
        se.add_query(query)
        return [event.doc for event in se.emit(timestamp=False, count=count)]

    def test_source_events_from_esql(self):
        se = SourceEvents(self.schema)
        se.stack_version = self.stack_version
        root = se.add_query('FROM x | WHERE process.name == "a.exe" AND process.pid > 1000', meta="m")
        self.assertEqual("m", root.meta)
        self.assertEqual(1, len(se))
        for event in se.emit(timestamp=False, count=20):
            self.assertEqual("a.exe", event.doc["process"]["name"])
            self.assertGreater(event.doc["process"]["pid"], 1000)
            self.assertEqual("m", event.meta)

        # the default schema is empty, every field is a keyword
        se = SourceEvents.from_query('FROM x | WHERE process.name == "a.exe"')
        self.assertEqual(1, len(se))

    def test_source_events_from_esql_rule(self):
        se = SourceEvents(self.schema)
        se.stack_version = self.stack_version
        rule = SimpleNamespace(type="esql", language="esql", query='FROM x | WHERE process.name == "a.exe"')
        se.add_rule(rule, meta="r")
        events = list(se.emit(timestamp=False, count=3))
        self.assertEqual(["a.exe"] * 3, [event.doc["process"]["name"] for event in events])

    def test_emit_matches_where(self):
        se = SourceEvents(self.schema)
        se.stack_version = self.stack_version
        se.add_query('FROM x | WHERE process.name IN ("x", "y") OR process.pid IS NOT NULL')
        branches = list(se.emit(timestamp=False, complete=True, count=1))
        self.assertEqual(3, len(branches))
        docs = [[event.doc for event in branch] for branch in branches]
        self.assertEqual([[{"process": {"name": "x"}}], [{"process": {"name": "y"}}]], docs[:2])
        self.assertEqual(1, len(docs[2]))
        self.assertIn("pid", docs[2][0]["process"])

    def test_booleans_from_strings(self):
        schema = {"flag": {"type": "boolean"}}
        for query, expected in (
            ('flag == "false"', False),
            ('flag == "FALSE"', False),
            ('flag == "true"', True),
            ('flag == "True"', True),
            ('flag != "false"', True),
            ('flag != "true"', False),
            ('NOT flag == "false"', True),
            ('NOT flag != "false"', False),
            ("flag == true", True),
            ("flag == false", False),
            ("flag != true", False),
            ("flag", True),
            ("NOT flag", False),
        ):
            with self.subTest(query):
                self.assertEqual([{"flag": expected}] * 2, self.emit(f"FROM x | WHERE {query}", schema=schema, count=2))
        docs = self.emit('FROM x | WHERE flag IN ("true", "false")', schema=schema, count=2)
        se = SourceEvents(schema)
        se.add_query('FROM x | WHERE flag IN ("true", "false")')
        branches = [[event.doc for event in branch] for branch in se.emit(timestamp=False, complete=True)]
        self.assertEqual([[{"flag": True}], [{"flag": False}]], branches)
        self.assertEqual(2, len(docs))

    def test_booleans_from_other_values_rejected(self):
        schema = {"flag": {"type": "boolean"}}
        for query in (
            'flag == "maybe"',
            'flag == ""',
            "flag == 1",
            "flag != 0",
            'flag IN ("true", "maybe")',
            "flag == 1.5",
            'NOT flag == "no"',
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported value for boolean field"):
                self.emit(f"FROM x | WHERE {query}", schema=schema)

    def test_eql_booleans_are_unchanged(self):
        se = SourceEvents({"flag": {"type": "boolean"}})
        se.add_query('any where flag == "false"')
        self.assertTrue(all(isinstance(event.doc["flag"], bool) for event in se.emit(timestamp=False, count=3)))

    def test_in_respects_the_branches_limit(self):
        def values(n):
            return ", ".join(str(i) for i in range(n))

        # the default limit of SourceEvents, applied while translating
        with self.assertRaisesRegex(ValueError, r"Root with too many branches \(limit: 10000\)"):
            esql.to_eql(f"FROM x | WHERE n IN ({values(10001)})")
        self.assertEqual(10000, len(collect_constraints(esql.to_eql(f"FROM x | WHERE n IN ({values(10000)})"))))

        # the limit of the caller
        se = SourceEvents({"n": {"type": "long"}})
        se.max_branches = 3
        with self.assertRaisesRegex(ValueError, r"Root with too many branches \(limit: 3\)"):
            se.add_query("FROM x | WHERE n IN (1, 2, 3, 4)")
        se.add_query("FROM x | WHERE n IN (1, 2, 3)")
        # NOT IN is just one branch, however long
        se.add_query("FROM x | WHERE n NOT IN (1, 2, 3, 4, 5, 6)")
        self.assertEqual(2, len(se))

    def test_eql_in_respects_the_branches_limit(self):
        se = SourceEvents({"n": {"type": "long"}})
        se.max_branches = 3
        with self.assertRaisesRegex(ValueError, r"Root with too many branches \(limit: 3\)"):
            se.add_query("any where n in (1, 2, 3, 4)")
        se.add_query("any where n in (1, 2, 3)")
        self.assertEqual(1, len(se))

    def test_mv_contains_emit(self):
        docs = self.emit('FROM x | WHERE mv_contains(event.category, "configuration")', count=3)
        self.assertEqual([["configuration"]] * 3, [doc["event"]["category"] for doc in docs])
        docs = self.emit('FROM x | WHERE mv_contains(event.category, "iam") AND mv_contains(event.type, "creation")', count=3)
        self.assertEqual([{"category": ["iam"], "type": ["creation"]}] * 3, [doc["event"] for doc in docs])
        docs = self.emit('FROM x | WHERE mv_contains(event.category, "file") AND process.name == "a.exe"', count=2)
        self.assertEqual([{"event": {"category": ["file"]}, "process": {"name": "a.exe"}}] * 2, docs)
        docs = self.emit('FROM x | WHERE NOT mv_contains(process.name, "a.exe")', count=10)
        self.assertTrue(all(isinstance(doc["process"]["name"], str) and doc["process"]["name"] != "a.exe" for doc in docs), docs)

    def test_kql_emit(self):
        docs = self.emit('FROM x | WHERE KQL("event.action: creation")', count=2)
        self.assertEqual([{"event": {"action": "creation"}}] * 2, docs)
        docs = self.emit(
            'FROM x | WHERE KQL("""event.category : "process" and event.type : "start" and host.os.type : "windows" """)', count=1
        )
        self.assertEqual([{"event": {"category": ["process"], "type": ["start"]}, "host": {"os": {"type": "windows"}}}], docs)
        se = SourceEvents(self.schema)
        se.add_query('FROM x | WHERE KQL("process.args: (a or b)") AND process.name == "x.exe"')
        branches = [[event.doc for event in branch] for branch in se.emit(timestamp=False, complete=True)]
        self.assertEqual(
            [[{"process": {"args": ["a"], "name": "x.exe"}}], [{"process": {"args": ["b"], "name": "x.exe"}}]],
            branches,
        )
        docs = self.emit('FROM x | WHERE KQL("process.args: a and process.args: b")', count=1)
        self.assertEqual([{"process": {"args": ["a", "b"]}}], docs)
        docs = self.emit('FROM x | WHERE NOT KQL("process.name: a.exe") AND event.action == "start"', count=5)
        self.assertTrue(all(doc["process"]["name"] != "a.exe" for doc in docs), docs)

    def test_literal_strings_emit(self):
        docs = self.emit('FROM x | WHERE process.name == "f*o"', count=3)
        self.assertEqual([{"process": {"name": "f*o"}}] * 3, docs)
        docs = self.emit('FROM x | WHERE process.name == "a?"', count=1)
        self.assertEqual([{"process": {"name": "a?"}}], docs)
        docs = self.emit('FROM x | WHERE process.name != "*"', count=20)
        self.assertTrue(all(doc["process"]["name"] != "*" for doc in docs), docs)
        se = SourceEvents(self.schema)
        se.add_query('FROM x | WHERE process.name IN ("a*", "b", "c?")')
        branches = [[event.doc for event in branch] for branch in se.emit(timestamp=False, complete=True)]
        self.assertEqual([[{"process": {"name": "a*"}}], [{"process": {"name": "b"}}], [{"process": {"name": "c?"}}]], branches)
        docs = self.emit('FROM x | WHERE mv_contains(process.args, "*")', count=1)
        self.assertEqual([{"process": {"args": ["*"]}}], docs)
        # a literal and a wildcard on the same field are still a conflict, as they were
        with self.assertRaisesRegex(NotImplementedError, "Unsupported conflicting constraints"):
            self.emit('FROM x | WHERE process.name == "a*" AND process.name LIKE "a*"')

    def test_kql_literals_emit(self):
        for query, expected in (
            ('f:"*"', "*"),
            ('f:"a*"', "a*"),
            ('f:"a?"', "a?"),
            ("f:a?", "a?"),
        ):
            with self.subTest(query):
                docs = self.emit(f'FROM x | WHERE KQL("""{query} """)'.replace("f:", "process.name:"), count=2)
                self.assertEqual([{"process": {"name": expected}}] * 2, docs)
        docs = self.emit('FROM x | WHERE KQL("process.name:a*")', count=10)
        self.assertTrue(all(doc["process"]["name"].startswith("a") for doc in docs), docs)
        docs = self.emit('FROM x | WHERE KQL("""NOT process.name:"*" """)', count=10)
        self.assertTrue(all(doc["process"]["name"] != "*" for doc in docs), docs)
        docs = self.emit('FROM x | WHERE KQL("""process.args:"*" and process.args:"a" """)', count=1)
        self.assertEqual([{"process": {"args": ["*", "a"]}}], docs)
        se = SourceEvents(self.schema)
        se.add_query('FROM x | WHERE KQL("""process.args:("*" or "escalate")""")')
        branches = [[event.doc for event in branch] for branch in se.emit(timestamp=False, complete=True)]
        self.assertEqual([[{"process": {"args": ["*"]}}], [{"process": {"args": ["escalate"]}}]], branches)

    def test_constant_keyword_fields(self):
        docs = self.emit('FROM x | WHERE data_stream.dataset == "aws.cloudtrail"', count=2)
        self.assertEqual([{"data_stream": {"dataset": "aws.cloudtrail"}}] * 2, docs)
        docs = self.emit('FROM x | WHERE data_stream.dataset LIKE "aws.*" AND data_stream.type == "logs"', count=5)
        self.assertTrue(all(doc["data_stream"]["dataset"].startswith("aws.") for doc in docs), docs)
        self.assertEqual({"logs"}, {doc["data_stream"]["type"] for doc in docs})
        docs = self.emit('FROM x | WHERE data_stream.dataset != "a" AND data_stream.namespace == "default"', count=5)
        self.assertTrue(all(doc["data_stream"]["dataset"] != "a" for doc in docs), docs)
        docs = self.emit('FROM x | WHERE mv_contains(data_stream.type, "logs") AND process.name == "a.exe"', count=1)
        self.assertEqual([{"data_stream": {"type": "logs"}, "process": {"name": "a.exe"}}], docs)
        docs = self.emit('FROM x | WHERE KQL("data_stream.dataset: aws.cloudtrail") AND process.name == "a.exe"', count=1)
        self.assertEqual([{"data_stream": {"dataset": "aws.cloudtrail"}, "process": {"name": "a.exe"}}], docs)

        se = SourceEvents(self.schema)
        se.add_query('FROM x | WHERE data_stream.dataset IN ("a", "b")')
        branches = [[event.doc for event in branch] for branch in se.emit(timestamp=False, complete=True)]
        self.assertEqual([[{"data_stream": {"dataset": "a"}}], [{"data_stream": {"dataset": "b"}}]], branches)

    def test_constant_keyword_conflicts(self):
        for query in (
            'data_stream.dataset == "a" AND data_stream.dataset == "b"',
            'data_stream.dataset LIKE "A*" AND data_stream.dataset == "a"',
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported conflicting constraints"):
                self.emit(f"FROM x | WHERE {query}")

    def test_constant_keyword_mappings(self):
        # the value of a constant_keyword field is set in the mapping, the documents generated from different
        # branches have different values: let the index take them all
        se = SourceEvents(self.schema)
        se.add_query('FROM x | WHERE data_stream.dataset IN ("a", "b") AND process.name == "x"')
        self.assertEqual(
            {
                "@timestamp": {"type": "date"},
                "data_stream": {"properties": {"dataset": {"type": "keyword"}}},
                "process": {"properties": {"name": {"type": "keyword"}}},
            },
            se.mappings()["properties"],
        )

    def test_constant_keyword_is_unsupported_for_the_other_languages(self):
        for query in ('any where data_stream.dataset == "x"', "data_stream.dataset: x", 'any where wildcard(data_stream.dataset, "x*")'):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "^Field type solver: constant_keyword$"):
                SourceEvents(self.schema).add_query(query)
        for rule_type, language, query in (
            ("query", "kuery", "data_stream.dataset: x"),
            ("eql", "eql", 'any where data_stream.dataset == "x"'),
        ):
            rule = SimpleNamespace(type=rule_type, language=language, query=query)
            with self.subTest(rule_type), self.assertRaisesRegex(NotImplementedError, "^Field type solver: constant_keyword$"):
                SourceEvents(self.schema).add_rule(rule)

    def test_unknown_fields_take_the_type_of_the_literals(self):
        # ES|QL has typed literals, what the schema does not know is what they say
        schema = {}
        docs = self.emit("FROM x | WHERE flag != true", schema=schema, count=3)
        self.assertEqual([{"flag": False}] * 3, docs)
        docs = self.emit("FROM x | WHERE flag", schema=schema, count=1)
        self.assertEqual([{"flag": True}], docs)
        docs = self.emit("FROM x | WHERE n > 5 AND n < 8", schema=schema, count=20)
        self.assertTrue(all(isinstance(doc["n"], int) and 5 < doc["n"] < 8 for doc in docs), docs)
        docs = self.emit("FROM x | WHERE n == 2.0", schema=schema, count=1)
        self.assertEqual([{"n": 2}], docs)
        docs = self.emit('FROM x | WHERE s == "a" AND t != "b"', schema=schema, count=2)
        self.assertEqual({"s": "a"}, {k: v for k, v in docs[0].items() if k == "s"})
        self.assertIsInstance(docs[0]["t"], str)
        # mixed values say nothing, and what the schema knows is not overridden
        with self.assertRaisesRegex(NotImplementedError, "Unsupported"):
            self.emit('FROM x | WHERE (m == 1 OR m == "a") AND m > 0', schema=schema)
        docs = self.emit("FROM x | WHERE process.pid > 5", schema={"process.pid": {"type": "long"}}, count=1)
        self.assertGreater(docs[0]["process"]["pid"], 5)

        se = SourceEvents(schema)
        se.add_query('FROM x | WHERE flag != true AND n > 5 AND s == "a"')
        self.assertEqual(
            {"flag": {"type": "boolean"}, "n": {"type": "long"}, "s": {"type": "keyword"}},
            {k: v for k, v in se.mappings()["properties"].items() if k != "@timestamp"},
        )

    def test_unknown_fields_of_the_other_languages_are_as_they_were(self):
        se = SourceEvents({})
        se.add_query("any where flag == true")
        self.assertEqual({"type": "keyword"}, se.mappings()["properties"]["flag"])

    def test_negations_emit_a_value(self):
        # ES|QL returns null for a missing field, so `!=` and `NOT` must not be satisfied by omitting it
        for query in ('process.name != "a.exe"', 'NOT process.name == "a.exe"', 'process.name != "a.exe" AND NOT process.name LIKE "b*"'):
            with self.subTest(query):
                docs = self.emit(f"FROM x | WHERE {query}", count=20)
                for doc in docs:
                    self.assertIsInstance(doc["process"]["name"], str)
                    self.assertNotEqual("a.exe", doc["process"]["name"])
        docs = self.emit("FROM x | WHERE process.pid != 1", count=5)
        self.assertTrue(all(isinstance(doc["process"]["pid"], int) and doc["process"]["pid"] != 1 for doc in docs), docs)

    def test_quoted_dotted_fields_emit_paths(self):
        self.assertEqual([{"a": {"b": "x"}}] * 3, self.emit('FROM x | WHERE `a.b` == "x"', schema={}, count=3))
        self.assertEqual([{"a": {"b": {"c": {"d": "x"}}}}], self.emit('FROM x | WHERE a.`b.c`.d == "x"', schema={}, count=1))
        self.assertEqual([{"host name": "x"}], self.emit('FROM x | WHERE `host name` == "x"', schema={}, count=1))
        self.assertEqual([{"a": {"b": "x"}}], self.emit('FROM x | WHERE a.b == "x"', schema={}, count=1))

    def test_bare_boolean_fields_emit(self):
        docs = self.emit("FROM x | WHERE process.code_signature.exists", count=3)
        self.assertEqual([{"process": {"code_signature": {"exists": True}}}] * 3, docs)
        docs = self.emit("FROM x | WHERE NOT process.code_signature.exists", count=3)
        self.assertEqual([{"process": {"code_signature": {"exists": False}}}] * 3, docs)
        docs = self.emit('FROM x | WHERE process.code_signature.exists AND process.name == "a.exe"', count=1)
        self.assertEqual([{"process": {"code_signature": {"exists": True}, "name": "a.exe"}}], docs)

    def test_fractional_numbers_on_long_fields_rejected(self):
        for query in (
            "process.pid == 1.5",
            "process.pid != 1.5",
            "process.pid >= 1.5",
            "process.pid > 1.5",
            "process.pid <= 1.5",
            "process.pid < 1.5",
            "process.pid IN (1.5, 2)",
            "process.pid >= 1.5 AND process.pid < 2",
            "NOT process.pid == 1.5",
            "process.pid > -1.5",
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported fractional number"):
                self.emit(f"FROM x | WHERE {query}")

    def test_integral_numbers_on_long_fields_accepted(self):
        docs = self.emit("FROM x | WHERE process.pid == 2.0", count=3)
        self.assertEqual([{"process": {"pid": 2}}] * 3, docs)
        docs = self.emit("FROM x | WHERE process.pid >= 10.0 AND process.pid < 12.0", count=20)
        self.assertTrue(all(10 <= doc["process"]["pid"] < 12 for doc in docs), docs)
        docs = self.emit("FROM x | WHERE process.pid IN (1, 2) OR process.pid != 3", count=5)
        self.assertEqual(5, len(docs))

    def test_fractional_numbers_accepted_on_other_types(self):
        # Geneve has no float solver yet, a stand-in shows that the check belongs to long fields only
        @solver.type("test_float")
        class TestFloatField(Field):
            valid_constraints: ClassVar[list] = ["==", ">=", "<"]

            def solve(self, left_attempts, environment):
                return {"value": 1.5, "left_attempts": left_attempts}

        self.addCleanup(solver.solvers.pop, "&test_float")
        schema = {**self.schema, "test.ratio": {"type": "test_float"}}
        docs = self.emit("FROM x | WHERE test.ratio >= 1.5 AND test.ratio < 2.5", schema=schema, count=2)
        self.assertEqual([{"test": {"ratio": 1.5}}] * 2, docs)

    def test_ip_networks_rejected(self):
        for query in (
            'source.ip == "10.0.0.0/8"',
            'source.ip != "10.0.0.0/8"',
            'source.ip IN ("10.0.0.1", "10.0.0.0/8")',
            'NOT source.ip == "10.0.0.0/8"',
            'source.ip == "2001:db8::/32"',
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported network literal"):
                self.emit(f"FROM x | WHERE {query}")

    def test_ip_addresses_and_cidr_match_accepted(self):
        docs = self.emit('FROM x | WHERE source.ip == "10.0.0.1"', count=3)
        self.assertEqual([{"source": {"ip": "10.0.0.1"}}] * 3, docs)
        docs = self.emit('FROM x | WHERE source.ip IN ("10.0.0.1", "2001:db8::1")', count=2)
        self.assertEqual(2, len(docs))
        docs = self.emit('FROM x | WHERE source.ip != "10.0.0.1"', count=5)
        self.assertTrue(all(doc["source"]["ip"] != "10.0.0.1" for doc in docs), docs)

        net = ipaddress.ip_network("10.0.0.0/8")
        docs = self.emit('FROM x | WHERE CIDR_MATCH(source.ip, "10.0.0.0/8")', count=20)
        self.assertTrue(all(ipaddress.ip_address(doc["source"]["ip"]) in net for doc in docs), docs)
        docs = self.emit('FROM x | WHERE NOT CIDR_MATCH(source.ip, "10.0.0.0/8")', count=20)
        self.assertTrue(all(ipaddress.ip_address(doc["source"]["ip"]) not in net for doc in docs), docs)

    def test_paths_and_keywords_with_slashes_accepted(self):
        docs = self.emit('FROM x | WHERE file.path == "/etc/passwd"', count=2)
        self.assertEqual([{"file": {"path": "/etc/passwd"}}] * 2, docs)
        docs = self.emit('FROM x | WHERE file.path IN ("/etc/passwd", "C:/Windows/System32")', count=2)
        self.assertEqual(2, len(docs))
        docs = self.emit('FROM x | WHERE process.name == "10.0.0.0/8"', count=1)
        self.assertEqual([{"process": {"name": "10.0.0.0/8"}}], docs)
        docs = self.emit('FROM x | WHERE file.path != "/etc/passwd"', count=5)
        self.assertTrue(all(doc["file"]["path"] != "/etc/passwd" for doc in docs), docs)

    def test_eql_and_kql_are_unchanged(self):
        # the checks are for ES|QL only, the other languages keep their behaviour
        for query in ('any where source.ip == "10.0.0.0/8"', 'any where source.ip != "10.0.0.0/8"', 'source.ip: "10.0.0.0/8"'):
            with self.subTest(query):
                se = SourceEvents(self.schema)
                se.stack_version = self.stack_version
                se.add_query(query)
                docs = [event.doc for event in se.emit(timestamp=False, count=10)]
                self.assertEqual(10, len(docs))
        net = ipaddress.ip_network("10.0.0.0/8")
        se = SourceEvents(self.schema)
        se.add_query('any where source.ip == "10.0.0.0/8"')
        self.assertTrue(all(ipaddress.ip_address(event.doc["source"]["ip"]) in net for event in se.emit(timestamp=False, count=10)))

        se = SourceEvents(self.schema)
        se.add_query("any where process.pid >= 1.5")
        self.assertTrue(all(event.doc["process"]["pid"] >= 1 for event in se.emit(timestamp=False, count=10)))
        se = SourceEvents(self.schema)
        se.add_query("process.pid >= 1.5")
        self.assertEqual(10, len(list(se.emit(timestamp=False, count=10))))

    def test_keyword_solver_case_sensitive_flag(self):
        from geneve.solver.type_keyword import KeywordField

        allowed = [("wildcard", ["process", "network"])]  # shaped as the ECS constraints of a field
        flagged = [("wildcard", "PRO*", {"case_sensitive": True})]
        unflagged = [("wildcard", "PRO*", {})]
        with self.assertRaises(ConflictError):
            KeywordField("f", flagged, allowed, False)
        solver = KeywordField("f", unflagged, allowed, False)  # case is ignored without the flag
        self.assertEqual("process", solver.solve(10, {})["value"])
        solver = KeywordField("f", [("wildcard", "pro*", {"case_sensitive": True})], allowed, False)
        self.assertEqual("process", solver.solve(10, {})["value"])

    def test_like_case_sensitive_conflict(self):
        # the solver restricts event.category to lowercase ECS values, it must not turn "PRO*" into "process"
        with self.assertRaises(ConflictError):
            self.emit('FROM x | WHERE event.category LIKE "PRO*"')

    def test_like_case_sensitive_match(self):
        docs = self.emit('FROM x | WHERE event.category LIKE "pro*"')
        # event.category is an array field in ECS, a single LIKE still yields a single value
        self.assertEqual([["process"]] * 20, [doc["event"]["category"] for doc in docs])

        docs = self.emit('FROM x | WHERE process.name LIKE "FOO*"')
        self.assertEqual(20, len(docs))
        self.assertTrue(all(doc["process"]["name"].startswith("FOO") for doc in docs), docs)

        docs = self.emit('FROM x | WHERE process.name LIKE "f?o*"')
        self.assertTrue(all(doc["process"]["name"][0] == "f" and doc["process"]["name"][2] == "o" for doc in docs), docs)

    def test_not_like(self):
        docs = self.emit('FROM x | WHERE process.name NOT LIKE "FOO*"')
        self.assertFalse(any(doc["process"]["name"].startswith("FOO") for doc in docs), docs)

    def test_like_array_field_single_value(self):
        schema = {**self.schema, "tags": {"type": "keyword", "normalize": ["array"]}}
        docs = self.emit('FROM x | WHERE tags LIKE "f*"', schema=schema)
        for doc in docs:
            self.assertIsInstance(doc["tags"], list)
            self.assertEqual(1, len(doc["tags"]), doc)
            self.assertTrue(doc["tags"][0].startswith("f"), doc)


if __name__ == "__main__":
    unittest.main()
