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

import unittest

import eql

from geneve import esql


def field(name):
    base, *path = name.split(".")
    return eql.ast.Field(base, path)


def like(name, pattern):
    return eql.ast.FunctionCall("_like", [field(name), eql.ast.String(pattern)])


class TestEsqlParser(unittest.TestCase):
    def validate(self, esql_source, eql_source):
        self.assertEqual(esql.to_eql(esql_source), eql.parse_expression(eql_source))

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
            esql.to_eql("FROM x | WHERE NOT a == 1 AND b == 2"),
            eql.ast.And([eql.ast.Not(eql.parse_expression("a == 1")), eql.parse_expression("b == 2")]),
        )
        self.assertEqual(
            esql.to_eql("FROM x | WHERE NOT (a == 1 OR b == 2)"),
            eql.ast.Not(eql.parse_expression("a == 1 or b == 2")),
        )

    def test_in_and_null_tests(self):
        self.validate("FROM x | WHERE a IN (1, 2)", "a in (1, 2)")
        self.validate('FROM x | WHERE a IN ("x", "y")', "a in ('x', 'y')")
        self.assertEqual(
            esql.to_eql("FROM x | WHERE a NOT IN (1, 2)"),
            eql.ast.Not(eql.parse_expression("a in (1, 2)")),
        )
        self.validate("FROM x | WHERE a IS NULL", "a == null")
        self.validate("FROM x | WHERE a IS NOT NULL", "a != null")

    def test_dotted_and_quoted_fields(self):
        self.validate('FROM x | WHERE process.name == "x"', "process.name == 'x'")
        self.assertEqual(
            esql.to_eql('FROM x | WHERE @timestamp != "x"'),
            eql.ast.Comparison(eql.ast.Field("@timestamp"), "!=", eql.ast.String("x")),
        )
        self.assertEqual(
            esql.to_eql('FROM x | WHERE `host name` == "x"'),
            eql.ast.Comparison(field("host name"), "==", eql.ast.String("x")),
        )
        self.assertEqual(
            esql.to_eql('FROM x | WHERE a.`b.c`.d == "x"'),
            eql.ast.Comparison(eql.ast.Field("a", ["b.c", "d"]), "==", eql.ast.String("x")),
        )

    def test_case_and_comments(self):
        expected = esql.to_eql("FROM x | WHERE a == 1")
        self.assertEqual(esql.to_eql("from x | where a == 1"), expected)
        self.assertEqual(esql.to_eql("From x | Where a == 1"), expected)
        self.assertEqual(esql.to_eql("FROM x // trailing comment\n | /* block\ncomment */ WHERE a == 1"), expected)
        self.assertEqual(esql.to_eql("FROM x\n| WHERE a == 1 // why not"), expected)
        self.assertEqual(esql.to_eql("FROM x | WHERE a == 1 AND\n  b == 2"), esql.to_eql("FROM x | WHERE a == 1 and b == 2"))

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
        self.assertEqual(esql.to_eql("FROM x"), eql.ast.Boolean(True))
        self.assertEqual(esql.to_eql("FROM x | LIMIT 10"), eql.ast.Boolean(True))

    def test_multiple_where_anded(self):
        self.validate("FROM x | WHERE a == 1 | WHERE b == 2", "a == 1 and b == 2")

    def test_ignored_pipes_after_where(self):
        self.validate("FROM x | WHERE a == 1 | KEEP a | SORT a DESC | LIMIT 5 | DROP b", "a == 1")
        self.validate('FROM x | WHERE a == 1 | KEEP a, "b|c", `d|e` | LIMIT 5', "a == 1")

    def test_ignored_pipe_before_where_rejected(self):
        for query in ("FROM x | LIMIT 5 | WHERE a == 1", "FROM x | KEEP a | WHERE a == 1", "FROM x | SORT a | WHERE a == 1"):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, r"Unsupported pipe before WHERE: [A-Z]+"):
                esql.to_eql(query)

    def test_unsupported_command(self):
        for command in (
            "STATS c = COUNT(*) BY a",
            "EVAL b = a",
            'DISSECT a "%{x}"',
            'GROK a "%{WORD:x}"',
            "ENRICH p ON a",
            "MV_EXPAND a",
            "LOOKUP JOIN idx ON a",
        ):
            name = command.split()[0]
            with self.subTest(command), self.assertRaisesRegex(NotImplementedError, rf"Unsupported command: {name}"):
                esql.to_eql(f"FROM x | WHERE a == 1 | {command}")
        with self.assertRaisesRegex(NotImplementedError, "Unsupported command: STATS"):
            esql.to_eql("from x | stats c = count(*) by a")

    def test_unsupported_source_command(self):
        for query in ("ROW a = 1", "SHOW INFO", "TS metrics"):
            name = query.split()[0]
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, rf"Unsupported source command: {name}"):
                esql.to_eql(query)

    def test_like(self):
        self.assertEqual(esql.to_eql('FROM x | WHERE a LIKE "foo*"'), like("a", "foo*"))
        self.assertEqual(esql.to_eql('FROM x | WHERE a LIKE "foo?"'), like("a", "foo?"))
        self.assertEqual(esql.to_eql('FROM x | WHERE a.b like "*foo*"'), like("a.b", "*foo*"))
        self.assertEqual(esql.to_eql('FROM x | WHERE a NOT LIKE "foo*"'), eql.ast.Not(like("a", "foo*")))
        self.assertEqual(
            esql.to_eql('FROM x | WHERE a LIKE "foo*" OR b == 1'),
            eql.ast.Or([like("a", "foo*"), eql.parse_expression("b == 1")]),
        )

    def test_like_unsupported(self):
        with self.assertRaisesRegex(NotImplementedError, "Unsupported operator: RLIKE"):
            esql.to_eql('FROM x | WHERE a RLIKE "foo.*"')
        with self.assertRaisesRegex(NotImplementedError, "Unsupported .*LIKE pattern.*string literal"):
            esql.to_eql("FROM x | WHERE a LIKE 1")

    def test_like_escapes_and_classes_rejected(self):
        for pattern in (r"foo\\*", r"a\\?b", r"a\\\\b", "[ab]*", "a[b"):
            query = f'FROM x | WHERE a LIKE "{pattern}"'
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported LIKE pattern"):
                esql.to_eql(query)

    def test_starts_ends_with(self):
        self.assertEqual(esql.to_eql('FROM x | WHERE STARTS_WITH(a, "foo")'), like("a", "foo*"))
        self.assertEqual(esql.to_eql('FROM x | WHERE ends_with(a.b, "foo")'), like("a.b", "*foo"))
        self.assertEqual(esql.to_eql('FROM x | WHERE NOT STARTS_WITH(a, "foo")'), eql.ast.Not(like("a", "foo*")))

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
                esql.to_eql(f"FROM x | WHERE {query}")

    def test_cidr_match(self):
        self.validate('FROM x | WHERE CIDR_MATCH(source.ip, "10.0.0.0/8")', "cidrMatch(source.ip, '10.0.0.0/8')")
        self.validate(
            'FROM x | WHERE cidr_match(source.ip, "10.0.0.0/8", "192.168.0.0/16")',
            "cidrMatch(source.ip, '10.0.0.0/8', '192.168.0.0/16')",
        )
        self.assertEqual(
            esql.to_eql('FROM x | WHERE NOT CIDR_MATCH(source.ip, "10.0.0.0/8")'),
            eql.ast.Not(eql.parse_expression("cidrMatch(source.ip, '10.0.0.0/8')")),
        )
        for query in ("CIDR_MATCH(source.ip)", "CIDR_MATCH(source.ip, 1)", 'CIDR_MATCH("10.0.0.1", "10.0.0.0/8")'):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported"):
                esql.to_eql(f"FROM x | WHERE {query}")

    def test_literal_strings_reject_wildcards(self):
        for query in ('a == "f*o"', 'a != "f?o"', 'a IN ("x", "f*")', 'a NOT IN ("?")'):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported string literal"):
                esql.to_eql(f"FROM x | WHERE {query}")
        self.validate('FROM x | WHERE a == "foo"', "a == 'foo'")
        self.validate('FROM x | WHERE a IN ("x", "y")', "a in ('x', 'y')")

    def test_string_escapes(self):
        def check(source, value):
            self.assertEqual(
                esql.to_eql(f"FROM x | WHERE a == {source}"),
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
            esql.to_eql(r'FROM x | WHERE a == "x\qy"')

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
                esql.to_eql(query)
            self.assertIsInstance(cm.exception.line, int)
            self.assertIsInstance(cm.exception.column, int)
            self.assertIsInstance(cm.exception, eql.EqlParseError)


if __name__ == "__main__":
    unittest.main()
