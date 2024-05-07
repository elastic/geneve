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

"""Test infinite-sets module."""

import string
import unittest

import tests.utils as tu
from geneve.utils.solution_space import Strings, product, transpose

alphabet = string.printable


class TestStrings(tu.SeededTestCase, unittest.TestCase):
    def test_contains(self):
        testcases = [
            ("a", "a", True),
            ("a", "A", True),
            ("aa", "a", False),
            ("a", "aa", False),
            ("a?", "a?", True),
            ("a?", "a", False),
            ("a", "a?", False),
            ("aa", "a?", False),
            ("a?", "aa", True),
            ("ab", "a?", False),
            ("a?", "ab", True),
            ("bb", "a?", False),
            ("a?", "bb", False),
            ("a*", "a*", True),
            ("a*", "a", True),
            ("a", "a*", False),
            ("aa", "a*", False),
            ("a*", "aa", True),
            ("ab", "a*", False),
            ("a*", "ab", True),
            ("bb", "a*", False),
            ("a*", "bb", False),
        ]
        for tc in testcases:
            with self.subTest(tc):
                ret = tc[1] in Strings({tc[0]})
                self.assertEqual(ret, tc[2])

        self.assertTrue("a" in Strings())
        self.assertTrue("b" in Strings())
        self.assertTrue("a" in Strings({"a"}))
        self.assertTrue("b" not in Strings({"a"}))
        self.assertTrue("a" not in Strings({}))
        self.assertTrue("a" not in Strings(exclude={"a"}))

    def test_everything(self):
        ss = Strings()
        result = [
            "e[]@/y'h/\x0c!K(qb,2>\x0c;}",
            "vb\x0cl\\fg6\"q{'}4'~\rgCI@",
            "PIF=%7tX;_qE7;mlLD)t",
            " j[stqOBZI?amHuVA!*Q[$eY3l",
            "f?5MYceo%.",
            "22}6D_zf9zpO",
            ".{B^B\\3oBOm=O\x0c:]F\n_|rygF|jd",
        ]
        self.assertEqual(ss, Strings())
        self.assertEqual(result, ss.generate(alphabet=alphabet, count=len(result)))
        self.assertTrue(ss)

    def test_something(self):
        ss = Strings({"a", "b*", "?c"})
        result = ["a", "|c", "2c", "Ic", "a", "bh/\x0c!K(", "a"]
        self.assertNotEqual(ss, Strings())
        self.assertEqual(ss, {"a", "b*", "?c"})
        self.assertEqual(result, ss.generate(alphabet=alphabet, count=len(result)))
        self.assertTrue(ss)

    def test_nothing(self):
        ss = Strings({})
        self.assertEqual(ss, {})
        self.assertFalse(ss)

        ss = Strings({}, exclude={"a"})
        self.assertEqual(ss, {})
        self.assertFalse(ss)

        msg = "Cannot choose from an empty set"
        with self.assertRaises(IndexError, msg=msg) as cm:
            self.assertEqual(None, ss.generate(alphabet=alphabet))
        self.assertEqual(msg, str(cm.exception))

    def test_and(self):
        self.assertEqual(Strings() & Strings(), Strings())
        self.assertEqual(Strings({}) & Strings(), {})
        self.assertEqual(Strings() & {}, {})
        self.assertEqual(Strings({}) & {}, {})

        self.assertEqual(Strings({"a", "b*"}) & {"a"}, {"a"})
        self.assertEqual(Strings({"a", "b*"}) & {"b*"}, {"b*"})
        self.assertEqual(Strings({"a", "b*"}) & {"c"}, {})
        self.assertEqual(Strings() & {"a", "b"}, {"a", "b"})

        ss1 = Strings({"a", "b"})
        ss2 = Strings({"b", "c"})
        self.assertEqual(ss1 & ss2, Strings({"b"}))
        self.assertEqual(ss1 & ss2, {"b"})

        ss1 = Strings({"a", "b"})
        ss2 = {"b", "c"}
        self.assertEqual(ss1 & ss2, Strings({"b"}))
        self.assertEqual(ss1 & ss2, {"b"})

        ss1 = {"a", "b"}
        ss2 = Strings({"b", "c"})
        self.assertEqual(ss1 & ss2, Strings({"b"}))
        self.assertEqual(ss1 & ss2, {"b"})

        ss1 = {"a", "b"}
        ss2 = {"b", "c"}
        self.assertEqual(ss1 & ss2, Strings({"b"}))
        self.assertEqual(ss1 & ss2, {"b"})

        ss_ = Strings()
        ss = ss_ & {"a", "b*", "?c"}
        result = ["a", "|c", "2c", "Ic", "a", "bh/\x0c!K(", "a"]
        self.assertEqual(ss_, Strings())
        self.assertEqual(ss, {"a", "b*", "?c"})
        self.assertEqual(result, ss.generate(alphabet=alphabet, count=len(result)))

        ss = Strings()
        ss &= ("a*", "b", "*c", "d", "*e", "f*")
        ss &= ["a", "b*", "c", "*d", "e*", "*f"]
        self.assertEqual(ss, {"a", "b", "c", "d"})

        ss = Strings()
        ss &= ("a?", "b", "?c", "d", "?e", "f?")
        ss &= {"a", "b?", "c", "?d", "e?", "?f"}
        self.assertEqual(ss, [])

    def test_rand(self):
        ss_ = Strings()
        ss = {"a", "b*", "?c"} & ss_
        result = ["a", "|c", "2c", "Ic", "a", "bh/\x0c!K(", "a"]
        self.assertEqual(ss, {"a", "b*", "?c"})
        self.assertEqual(ss_, Strings())
        self.assertEqual(result, ss.generate(alphabet=alphabet, count=len(result)))

    def test_or(self):
        self.assertEqual(Strings() | Strings(), Strings())
        self.assertEqual(Strings() | {}, Strings())
        self.assertEqual(Strings({}) | Strings(), Strings())
        self.assertEqual(Strings({}) | {}, {})

        ss1 = Strings({"a", "b"})
        ss2 = Strings({"b", "c"})
        self.assertEqual(ss1 | ss2, Strings({"a", "b", "c"}))
        self.assertEqual(ss1 | ss2, {"a", "b", "c"})

        ss1 = Strings({"a", "b"})
        ss2 = {"b", "c"}
        self.assertEqual(ss1 | ss2, Strings({"a", "b", "c"}))
        self.assertEqual(ss1 | ss2, {"a", "b", "c"})

        ss1 = {"a", "b"}
        ss2 = Strings({"b", "c"})
        self.assertEqual(ss1 | ss2, Strings({"a", "b", "c"}))
        self.assertEqual(ss1 | ss2, {"a", "b", "c"})

        ss1 = {"a", "b"}
        ss2 = {"b", "c"}
        self.assertEqual(ss1 | ss2, Strings({"a", "b", "c"}))
        self.assertEqual(ss1 | ss2, {"a", "b", "c"})

        ss1 = Strings(exclude={"a"})
        ss2 = {"a"}
        self.assertEqual(ss1 | ss2, Strings())

        ss1 = Strings(exclude={"a*"})
        ss2 = {"a"}
        self.assertEqual(ss1 | ss2, Strings(exclude=Strings({"a*"}, exclude={"a"})))

        ss1 = Strings(exclude={"a"})
        ss2 = {"a*"}
        self.assertEqual(ss1 | ss2, Strings())

        ss1 = Strings(exclude={"a*"})
        ss2 = {"a*"}
        self.assertEqual(ss1 | ss2, Strings())

    def test_ror(self):
        ss_ = Strings()
        ss = {"a", "b*", "?c"} | ss_
        result = [
            "e[]@/y'h/\x0c!K(qb,2>\x0c;}",
            "vb\x0cl\\fg6\"q{'}4'~\rgCI@",
            "PIF=%7tX;_qE7;mlLD)t",
            " j[stqOBZI?amHuVA!*Q[$eY3l",
            "f?5MYceo%.",
            "22}6D_zf9zpO",
            ".{B^B\\3oBOm=O\x0c:]F\n_|rygF|jd",
        ]
        self.assertEqual(ss, Strings())
        self.assertEqual(ss_, Strings())
        self.assertEqual(result, ss.generate(alphabet=alphabet, count=len(result)))

    def test_sub(self):
        self.assertEqual(Strings() - Strings(), {})
        self.assertEqual(Strings() - Strings({}), Strings())
        self.assertEqual(Strings({}) - Strings(), {})
        self.assertEqual(Strings({}) - {}, {})

        values = [
            "FTa{LKYi\E%,:r:$oJQq*8/P0d1fZv",
            'XWI{=\n,"N/anm;<\x0c@c`E}Sg',
            "\x0c:9#1]VbN[&g*]ir!wnKG",
            "/w\x0ci9K*D\x0c9%NnfXZb0G)V&t",
            "UnJ ",
        ]
        for i, value in enumerate(values):
            with self.subTest((i, value)):
                ss = Strings()
                ss -= values[:i]
                result = ss.generate(alphabet=alphabet, max_attempts=i + 1)[0]
                self.assertEqual(value, result)

        self.assertEqual(Strings({}) - {"a"}, {})

        self.assertEqual(Strings({"a"}) - Strings(), {})
        self.assertEqual(Strings({"a"}) - {}, {"a"})
        self.assertEqual(Strings({"a"}) - {"a"}, {})
        self.assertEqual(Strings({"a", "b*"}) - Strings(), {})
        self.assertEqual(Strings({"a", "b*"}) - {"a"}, {"b*"})
        self.assertEqual(Strings({"a", "b*"}) - {"a*"}, Strings({"b*"}, exclude={"a*"}))
        self.assertEqual(Strings({"a", "b*"}) - {"b"}, Strings({"a", "b*"}, exclude={"b"}))
        self.assertEqual(Strings({"a", "b*"}) - {"*b"}, Strings({"a", "b*"}, exclude={"*b"}))
        self.assertEqual(Strings({"a", "b*"}) - {"a*", "*b"}, Strings({"b*"}, exclude={"a*", "*b"}))
        self.assertEqual(Strings({"a", "b*"}) - {"c*"}, Strings({"a", "b*"}, exclude={"c*"}))
        self.assertEqual(Strings({"a", "b*"}) - {"*"}, {})

        self.assertEqual(Strings({"a"}) - {"a*"}, {})
        self.assertEqual(Strings({"a*"}) - {"a"}, Strings({"a*"}, exclude={"a"}))
        self.assertEqual(Strings() - {"a*"} - {"a"}, Strings(exclude={"a*"}))

        self.assertEqual(Strings() - {"a"}, Strings(exclude={"a"}))
        self.assertEqual(Strings() - {"a"} & {"a"}, {})
        self.assertEqual(Strings() - {"a"} & {"a*"}, Strings({"a*"}, exclude={"a"}))
        self.assertEqual(Strings() - {"a"} & {"b*"}, {"b*"})

        self.assertEqual(Strings({"a", "b", "c"}) - {"c"}, Strings({"a", "b"}))
        self.assertEqual(Strings(exclude={"c"}) & {"a", "b", "c"}, Strings({"a", "b"}))

        self.assertEqual(Strings({"a", "b*"}) | {"c"}, {"a", "b*", "c"})
        self.assertEqual(Strings() - {"a"} | {"a"}, Strings())
        self.assertEqual(Strings() - {"a*"} | {"a"}, Strings(exclude=Strings({"a*"}, exclude={"a"})))
        self.assertEqual(Strings() - {"a*"} | {"a"}, Strings(exclude=Strings({"a*"}) - {"a"}))
        self.assertEqual(Strings() - {"a"} | {"a*"}, Strings())


class TestTranspose(tu.SeededTestCase, unittest.TestCase):
    def test_transpose(self):
        t = {
            "a": {"1", "2"},
            "b": {"2", "3"},
            "c": {"1", "3"},
        }
        u = {
            "1": {"a", "c"},
            "2": {"a", "b"},
            "3": {"b", "c"},
        }

        self.assertEqual(transpose(t), u)
        self.assertEqual(transpose(u), t)
        self.assertEqual(transpose(transpose(t)), t)
        self.assertEqual(transpose(transpose(u)), u)


class TestProduct(tu.SeededTestCase, unittest.TestCase):
    def test_product(self):
        self.assertEqual(set(product({"a", "b"}, ("1", "2"))), {("a", "1"), ("a", "2"), ("b", "1"), ("b", "2")})
        self.assertEqual(set(product(["1", "2"], {"a", "b"})), {("1", "a"), ("2", "a"), ("1", "b"), ("2", "b")})

        t = {
            "a": {"1", "2"},
            "b": {"2", "3"},
            "c": {"1", "3"},
        }
        u = {
            "1": {"a", "c"},
            "2": {"a", "b"},
            "3": {"b", "c"},
        }

        self.assertEqual(set(product({"a", "b"}, t)) & set(product(u, {"3"})), {("b", "3")})
        self.assertEqual(set(product({"b", "c"}, t)) & set(product(u, {"1", "3"})), {("b", "3"), ("c", "1"), ("c", "3")})
        self.assertEqual(set(product({"b", "c"}, t)) & set(product(u, {"1", "2"})), {("b", "2"), ("c", "1")})

    def test_product_strings(self):
        self.assertEqual(Strings({"a", "b"}) * ("1", "2"), {("a", "1"), ("a", "2"), ("b", "1"), ("b", "2")})
        self.assertEqual(["1", "2"] * Strings({"a", "b"}), {("1", "a"), ("2", "a"), ("1", "b"), ("2", "b")})

        t = {
            "a": {"1", "2"},
            "b": {"2", "3"},
            "c": {"1", "3"},
        }
        u = {
            "1": {"a", "c"},
            "2": {"a", "b"},
            "3": {"b", "c"},
        }

        self.assertEqual(Strings(t) * t, u * Strings(u))
        self.assertEqual(Strings({"a", "b"}) * t & u * Strings({"3"}), {("b", "3")})
        self.assertEqual(Strings({"b", "c"}) * t & u * Strings({"1", "3"}), {("b", "3"), ("c", "1"), ("c", "3")})
        self.assertEqual(Strings({"b", "c"}) * t & u * Strings({"1", "2"}), {("b", "2"), ("c", "1")})
