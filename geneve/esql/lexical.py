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

"""Look at the text of a command without parsing it: its items, and the fields that it talks about.

The expressions of EVAL and STATS use more of ES|QL than the grammar knows, and what is needed of them is not
their value but what they depend on: whatever is not a field, a function or a literal is a field.
"""

import re

NAME = r"(?:[A-Za-z_@][\w@]*|`(?:[^`]|``)+`)"
DOTTED_NAME = rf"{NAME}(?:\.{NAME})*"

STRING_RE = re.compile(r'"""[\s\S]*?"""|"(?:[^"\\\n]|\\.)*"')
COMMENT_RE = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/")
IDENTIFIER_RE = re.compile(rf"(?<![\w.@`])({DOTTED_NAME})")
ASSIGNMENT_RE = re.compile(rf"\s*({DOTTED_NAME})\s*=(?!=)\s*([\s\S]*)")
CALL_RE = re.compile(r"(\w+)\s*\(([\s\S]*)\)")

# words that are not fields: operators, literals and units of time
WORDS = frozenset(
    {
        "and",
        "or",
        "not",
        "in",
        "is",
        "null",
        "true",
        "false",
        "like",
        "rlike",
        "as",
        "asc",
        "desc",
        "by",
        "on",
        "with",
        "nulls",
        "millisecond",
        "milliseconds",
        "second",
        "seconds",
        "minute",
        "minutes",
        "hour",
        "hours",
        "day",
        "days",
        "week",
        "weeks",
        "month",
        "months",
        "quarter",
        "quarters",
        "year",
        "years",
    }
)


def strip_comments(text):
    """Take the comments out of a text, but for those that are in a string."""
    return re.sub(rf"({STRING_RE.pattern})|{COMMENT_RE.pattern}", lambda match: match.group(1) or " ", text)


def top_level(text):
    """For each character, is it out of strings, quoted names, comments and brackets?"""
    mask = [False] * len(text)
    i, depth, n = 0, 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith('"""', i):
            end = text.find('"""', i + 3)
            i = n if end < 0 else end + 3
        elif c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
        elif c == "`":
            end = text.find("`", i + 1)
            i = n if end < 0 else end + 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            mask[i] = depth == 0
            i += 1
    return mask


def split_top(text, separator=","):
    """Split a text at the separators that are not in a string, a name, a comment or brackets."""
    mask = top_level(text)
    items, start = [], 0
    for i, c in enumerate(text):
        if c == separator and mask[i]:
            items.append(text[start:i])
            start = i + 1
    items.append(text[start:])
    return items


def split_keyword(text, keyword):
    """Split a text at the first keyword that is not in a string, a name, a comment or brackets."""
    mask = top_level(text)
    for match in re.finditer(rf"\b{keyword}\b", text, re.IGNORECASE):
        if mask[match.start()]:
            return text[: match.start()], text[match.end() :]
    return text, None


def assignment(item):
    """Return (name, expression) of `name = expression`, None if it is not."""
    match = ASSIGNMENT_RE.fullmatch(item)
    return (match.group(1), match.group(2).strip()) if match else None


def call(expression):
    """Return (function, arguments) of `function(arguments)`, None if it is not a call."""
    match = CALL_RE.fullmatch(expression.strip())
    return (match.group(1), match.group(2).strip()) if match else None


def is_name(text):
    return re.fullmatch(DOTTED_NAME, text.strip()) is not None


def identifiers(text):
    """Return what a text refers to as fields, in the order of appearance and without repeating them."""
    text = COMMENT_RE.sub(" ", STRING_RE.sub('""', text))
    found = []
    for match in IDENTIFIER_RE.finditer(text):
        name = match.group(1)
        if text[match.end() :].lstrip().startswith("("):
            continue  # a function
        if text[: match.start()].rstrip().endswith("::"):
            continue  # a type
        if "." not in name and name.lower() in WORDS:
            continue
        if name not in found:
            found.append(name)
    return found
