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

"""Test shelllib module."""

import os
import unittest

from geneve.utils.shelllib import ShellExpansionError, shell_expand

from .utils import tempenv


class TestShellExpand(unittest.TestCase):
    """Test shell_iterpolate()."""

    def setUp(self):
        os.environ["TEST_VAR1"] = "value1"
        os.environ["TEST_VAR2"] = "value2"

    def tearDown(self):
        del os.environ["TEST_VAR1"]
        del os.environ["TEST_VAR2"]

    def test_shell_expand(self):
        self.assertEqual(None, shell_expand(None))

        self.assertEqual("value1", shell_expand("$TEST_VAR1"))
        self.assertEqual("value1", shell_expand("${TEST_VAR1}"))

        self.assertEqual("", shell_expand("$(true)"))
        self.assertEqual("", shell_expand("$(echo $TEST_VAR3)"))
        self.assertEqual("value1", shell_expand("$(echo $TEST_VAR1)"))

        self.assertEqual(tuple(), shell_expand(tuple()))
        self.assertEqual(("value1", "value2"), shell_expand(("$TEST_VAR1", "$TEST_VAR2")))

        self.assertEqual(list(), shell_expand(list()))
        self.assertEqual(["value1", "value2"], shell_expand(["$TEST_VAR1", "$TEST_VAR2"]))

        self.assertEqual(set(), shell_expand(set()))
        self.assertEqual({"value1", "value2"}, shell_expand({"$TEST_VAR1", "$TEST_VAR2"}))

        self.assertEqual(dict(), shell_expand(dict()))
        self.assertEqual({"var1": "value1", "var2": "value2"}, shell_expand({"var1": "$TEST_VAR1", "var2": "$TEST_VAR2"}))

        self.assertEqual("xvalue1", shell_expand("x$TEST_VAR1"))
        self.assertEqual("value2x", shell_expand("${TEST_VAR2}x"))
        self.assertEqual("xy", shell_expand("x$(true)y"))

        self.assertEqual("value1value2value3", shell_expand("$TEST_VAR1${TEST_VAR2}value3"))
        self.assertEqual("value1value3value2", shell_expand("${TEST_VAR1}value3$TEST_VAR2"))
        self.assertEqual("value1value2value3", shell_expand("$TEST_VAR1$(echo $TEST_VAR2)value3"))

        self.assertEqual("", shell_expand("${TEST_VAR3:-}"))
        self.assertEqual("value0", shell_expand("${TEST_VAR3:-value0}"))
        self.assertEqual("value1", shell_expand("${TEST_VAR3:-$TEST_VAR1}"))
        self.assertEqual("value2", shell_expand("${TEST_VAR3:-${TEST_VAR2}}"))
        self.assertEqual("value3", shell_expand("${TEST_VAR3:-$(echo value3)}"))

        self.assertEqual("$TEST_VAR1", shell_expand("\$TEST_VAR1"))
        self.assertEqual("${TEST_VAR1}", shell_expand("\${TEST_VAR1}"))
        self.assertEqual("\$TEST_VAR1", shell_expand("\\\$TEST_VAR1"))
        self.assertEqual("\${TEST_VAR1}", shell_expand("\\\${TEST_VAR1}"))

        self.assertEqual("$(true)", shell_expand("\$(true)"))
        self.assertEqual("\$(true)", shell_expand("\\\$(true)"))

        # ideally this should be expanded to $(echo $TEST_VAR) but let's implement this only if needed by somebody
        self.assertEqual("$(echo value1)", shell_expand("\$(echo $TEST_VAR1)"))

        with tempenv({"TEST_VAR4": "$TEST_VAR1$TEST_VAR2"}):
            self.assertEqual("value1value2", shell_expand("$TEST_VAR4"))

    def test_shell_expand_exceptions(self):
        msg = "Environment variable is not set: TEST_VAR3"
        with self.assertRaises(ShellExpansionError, msg=msg) as cm:
            self.assertEqual(None, shell_expand("$TEST_VAR3"))
        self.assertEqual(msg, str(cm.exception))

        msg = "Environment variable is not set: TEST_VAR3"
        with self.assertRaises(ShellExpansionError, msg=msg) as cm:
            self.assertEqual(None, shell_expand("${TEST_VAR3}"))
        self.assertEqual(msg, str(cm.exception))

        msg = "Environment variable is recursively defined: TEST_VAR4"
        with self.assertRaises(ShellExpansionError, msg=msg) as cm:
            with tempenv({"TEST_VAR4": "x${TEST_VAR4}y"}):
                self.assertEqual(None, shell_expand("$TEST_VAR4"))
        self.assertEqual(msg, str(cm.exception))

        msg = "Command 'false' failed: status=1"
        with self.assertRaises(ShellExpansionError, msg=msg) as cm:
            self.assertEqual(None, shell_expand("$(false)"))
        self.assertEqual(msg, str(cm.exception))
