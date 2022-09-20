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

"""Functions for expanding variables like shell."""

import os
import re
import subprocess

_re_variable = re.compile(r"(?<!\\)\$(\w+)")
_re_variable2 = re.compile(r"(?<!\\)\${(\w+)(:-(.*)?)?}")
_re_subshell = re.compile(r"(?<!\\)\$\((.+)\)")
_re_escaped_dollar = re.compile(r"\\\$")
_re_escaped_slash = re.compile(r"\\\\")


class ShellExpansionError(Exception):
    pass


def _repl_subshell(match):
    command = match.group(1)
    p = subprocess.run(command, stdout=subprocess.PIPE, shell=True, text=True)
    if p.returncode:
        raise ShellExpansionError(f"Command '{command}' failed: status={p.returncode}")
    value = p.stdout
    while value.endswith("\n"):
        value = value[:-1]
    return value


def _repl_env_var(match):
    varname = match.group(1)
    value = os.getenv(varname, None)
    if value is None:
        if len(match.groups()) == 1 or not match.group(2):
            raise ShellExpansionError(f"Environment variable is not set: {varname}")
        value = match.group(3) or ""
    if varname in value:
        raise ShellExpansionError(f"Environment variable is recursively defined: {varname}")
    return _shell_expand_str(value)


def _shell_expand_str(value):
    value = _re_variable.sub(r"${\1}", value)
    value = _re_subshell.sub(_repl_subshell, value)
    value = _re_variable2.sub(_repl_env_var, value)
    value = _re_escaped_dollar.sub(r"$", value)
    value = _re_escaped_slash.sub(r"\\", value)
    return value


def shell_expand(value):
    if isinstance(value, dict):
        return dict((k, shell_expand(v)) for k, v in value.items())
    elif isinstance(value, set):
        return set(shell_expand(v) for v in value)
    elif isinstance(value, list):
        return list(shell_expand(v) for v in value)
    elif isinstance(value, tuple):
        return tuple(shell_expand(v) for v in value)
    elif isinstance(value, str):
        return _shell_expand_str(value)
    elif value is None:
        return None
    raise NotImplementedError(f"Type not supported: {type(value)}")
