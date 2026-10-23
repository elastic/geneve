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
from types import SimpleNamespace

import eql

import tests.utils as tu
from geneve import esql
from geneve.constraints import ConflictError
from geneve.events_emitter import SourceEvents, ast_from_rule, guess_from_query


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
        # a quoted name with dots is the same path Elasticsearch would resolve
        self.assertEqual(
            esql.to_eql('FROM x | WHERE a.`b.c`.d == "x"'),
            eql.ast.Comparison(eql.ast.Field("a", ["b", "c", "d"]), "==", eql.ast.String("x")),
        )
        self.assertEqual(
            esql.to_eql('FROM x | WHERE `a.b` == "x"'),
            eql.ast.Comparison(eql.ast.Field("a", ["b"]), "==", eql.ast.String("x")),
        )
        for query in ("`a..b`", "`.a`", "`a.`", "`a*`", "a.`b?`", "`*`"):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported field name"):
                esql.to_eql(f'FROM x | WHERE {query} == "x"')

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

    def test_limit_zero_rejected(self):
        for query in ("FROM x | WHERE a == 1 | LIMIT 0", "FROM x | LIMIT 0"):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported LIMIT 0"):
                esql.to_eql(query)
        self.validate("FROM x | WHERE a == 1 | LIMIT 1", "a == 1")

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

    def test_null_literals_rejected(self):
        for query in ("a == NULL", "a != NULL", "NOT (a == NULL)", "a IN (1, NULL)", "a NOT IN (NULL)", "a < null"):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported NULL literal"):
                esql.to_eql(f"FROM x | WHERE {query}")
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
                esql.to_eql(f"FROM x METADATA _id, _index | WHERE {query}")
        # the declaration itself is fine, and so are fields that merely start like a metadata one
        self.assertEqual(esql.parse("FROM x METADATA _id").metadata, ("_id",))
        self.validate('FROM x | WHERE _idx == "x"', "_idx == 'x'")

    def test_bare_boolean_fields(self):
        flag = eql.ast.Comparison(field("flag"), "==", eql.ast.Boolean(True))
        other = eql.parse_expression("a == 1")
        self.assertEqual(esql.to_eql("FROM x | WHERE flag"), flag)
        self.assertEqual(esql.to_eql("FROM x | WHERE NOT flag"), eql.ast.Not(flag))
        self.assertEqual(esql.to_eql("FROM x | WHERE flag AND a == 1"), eql.ast.And([flag, other]))
        self.assertEqual(esql.to_eql("FROM x | WHERE a == 1 OR NOT flag"), eql.ast.Or([other, eql.ast.Not(flag)]))
        self.assertEqual(
            esql.to_eql("FROM x | WHERE (flag) AND (a.b)"),
            eql.ast.And([flag, eql.ast.Comparison(field("a.b"), "==", eql.ast.Boolean(True))]),
        )
        self.assertEqual(esql.to_eql("FROM x | WHERE true"), eql.ast.Boolean(True))
        self.assertEqual(esql.to_eql("FROM x | WHERE a == 1 AND NOT false"), eql.ast.And([other, eql.ast.Not(eql.ast.Boolean(False))]))

    def test_non_boolean_expressions_rejected(self):
        for query in ("1", '"x"', "NULL", "a == 1 AND 2", "NOT 1.5", "_id", "NOT `_index`"):
            with self.subTest(query), self.assertRaisesRegex(
                NotImplementedError, "Unsupported (non-boolean expression|predicate on metadata field)"
            ):
                esql.to_eql(f"FROM x METADATA _id | WHERE {query}")

    def test_non_field_operands_rejected(self):
        for query in ("a == b", "1 == a", "LENGTH(a) > 3", "a == b + 1", "a + 1 == 2", "a == (1 + 2)", '"x" == a', "a IN (b, 1)"):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, "Unsupported"):
                esql.to_eql(f"FROM x | WHERE {query}")

    def test_unsupported_functions_rejected(self):
        for query, name in (
            ("NOW()", "NOW"),
            ("@timestamp > NOW() - 1d", "NOW"),
            ('TO_UPPER(a) == "X"', "TO_UPPER"),
            ("MV_COUNT(a) > 1", "MV_COUNT"),
            ("a == ABS(b)", "ABS"),
        ):
            with self.subTest(query), self.assertRaisesRegex(NotImplementedError, f"Unsupported function: {name}"):
                esql.to_eql(f"FROM x | WHERE {query}")

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
                esql.to_eql(f"FROM x | WHERE {query}")
        with self.assertRaisesRegex(NotImplementedError, "Unsupported conflicting constraints"):
            esql.to_eql('FROM x | WHERE tags == "a" | WHERE tags == "b"')

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
                esql.to_eql(f"FROM x | WHERE {query}")

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
        ):
            with self.subTest(query):
                guess = guess_from_query(query)
                self.assertEqual("esql", guess.language)
                self.assertEqual(esql.to_eql('FROM x | WHERE a == "foo"'), guess.ast)
        for query in ("/* comment */ ROW a = 1", "// comment\nSHOW INFO"):
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
        for query in ("FROM x | STATS c = COUNT(*) BY a", "FROM x | LIMIT 1 | WHERE a == 1", "ROW a = 1", "SHOW INFO"):
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

        rule = SimpleNamespace(type="esql", language="esql", query="FROM idx | STATS c = COUNT(*)")
        with self.assertRaisesRegex(NotImplementedError, "Unsupported command: STATS"):
            ast_from_rule(rule)

    def test_rule_types_unchanged(self):
        rule = SimpleNamespace(type="query", language="kuery", query="a: b")
        self.assertEqual(guess_from_query("a: b").ast, ast_from_rule(rule))
        with self.assertRaisesRegex(NotImplementedError, "Unsupported rule type: threshold"):
            ast_from_rule(SimpleNamespace(type="threshold", language="kuery", query="a: b"))
        with self.assertRaisesRegex(NotImplementedError, "Unsupported query language: lucene"):
            ast_from_rule(SimpleNamespace(type="query", language="lucene", query="a: b"))


class TestEsqlEmission(tu.QueryTestCase, tu.SeededTestCase, unittest.TestCase):
    maxDiff = None

    def emit(self, query, *, schema=None, count=20):
        se = SourceEvents(schema if schema is not None else self.schema)
        se.stack_version = self.stack_version
        se.add_ast(esql.to_eql(query))
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
