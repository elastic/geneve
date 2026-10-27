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

import re
import unittest

import tests.utils as tu
from geneve.utils import random, regex_gen

# the kinds of expressions that the rules have
PATTERNS = (
    "foo",
    r"foo\.exe",
    ".*foo.*",
    ".+",
    "(cmd|powershell)",
    r".*(AKIA|ASIA)[A-Z0-9]{16}.*",
    r"[0-9]{1,3}(\.[0-9]{1,3}){3}",
    r"[^@\s]+\@[^@\s]+",
    r"[a-z]{3}\.stage\.[0-9]{8}\..*",
    r"/(private/)?(tmp|var/tmp)/.*|/Users/Shared/.*",
    r".* mail\.(read|readwrite|send)(\.shared)? .*",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"[!@#$%^&*()_+={[\]|\\:;\"'<,>.?/~` \-]+",
    r"nc.{1,2}[0-9]{1,3}",
    r"\d{3}-\w+-\S+",
    "a?b*c+",
    "(a|b|c)(d|e)",
    "x{0}y",
)
UNSUPPORTED = {
    "^foo": "element AT",
    "foo$": "element AT",
    r"\bfoo": "element AT",
    "(?=foo)bar": "element ASSERT",
    r"(a)\1": "element GROUPREF",
    "(?i)foo": "flags",
}


class TestRegexGen(tu.SeededTestCase, unittest.TestCase):
    def test_matching(self):
        for pattern in PATTERNS:
            with self.subTest(pattern):
                values = regex_gen.matching(pattern)
                self.assertGreater(len(values), 0)
                for value in values:
                    self.assertIsNotNone(re.fullmatch(pattern, value, re.DOTALL), value)

    def test_not_matching(self):
        for pattern in PATTERNS:
            with self.subTest(pattern):
                value = regex_gen.not_matching(pattern)
                self.assertIsNone(re.fullmatch(pattern, value, re.DOTALL), value)
                # but if there is no other, the empty string
                self.assertTrue(value or pattern == ".+")

    def test_not_matching_what_matches_everything(self):
        for pattern in (".*", "(.*)", "[a-z]*|.*"):
            with self.subTest(pattern), self.assertRaisesRegex(NotImplementedError, "doesn't match"):
                regex_gen.not_matching(pattern)

    def test_one_value_per_alternative(self):
        values = regex_gen.matching("(cmd|powershell|bash)\\.exe")
        self.assertEqual(["cmd.exe", "powershell.exe", "bash.exe"], values)

        # every alternative is used, they are combined as few times as possible
        values = regex_gen.matching("a(bb|cc)d(ee|ff|gg)")
        self.assertEqual(["abbdee", "accdff", "abbdgg"], values)

    def test_fixed_text_is_what_it_is(self):
        self.assertEqual(["foo.exe"], regex_gen.matching(r"foo\.exe"))
        self.assertEqual(["a-b"], regex_gen.matching("a-b"))

    def test_the_least_repetitions_but_one(self):
        for pattern, length in (("a*", 1), ("a+", 1), ("a?", 1), ("a{3}", 3), ("a{2,5}", 2), ("a{0,0}", 0), ("(ab){3}", 6)):
            with self.subTest(pattern):
                self.assertEqual(length, len(regex_gen.matching(pattern)[0]))

    def test_limit(self):
        pattern = "(" + "|".join(f"alt{i}" for i in range(100)) + ")"
        self.assertEqual(regex_gen.MAX_VARIANTS, len(regex_gen.matching(pattern)))
        self.assertEqual(["alt0", "alt1"], regex_gen.matching(pattern, limit=2))

    def test_unsupported(self):
        for pattern, what in UNSUPPORTED.items():
            with self.subTest(pattern):
                with self.assertRaisesRegex(NotImplementedError, what):
                    regex_gen.check(pattern)
                with self.assertRaisesRegex(NotImplementedError, what):
                    regex_gen.matching(pattern)
                with self.assertRaisesRegex(NotImplementedError, what):
                    regex_gen.not_matching(pattern)

    def test_invalid(self):
        for pattern in ("(", "[a-", "*a", "a{2,1}"):
            with self.subTest(pattern), self.assertRaisesRegex(ValueError, "Invalid regular expression"):
                regex_gen.check(pattern)

    def test_empty_class(self):
        with self.assertRaisesRegex(ValueError, "empty"):
            regex_gen.check("[^\\x00-\\x7f]")

    def test_repeatable(self):
        random.seed("regex")
        first = [regex_gen.matching(p) for p in PATTERNS]
        random.seed("regex")
        self.assertEqual(first, [regex_gen.matching(p) for p in PATTERNS])


if __name__ == "__main__":
    unittest.main()
