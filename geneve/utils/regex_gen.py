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

"""Generate the strings that a regular expression matches, and some that it doesn't.

The expression is parsed by the standard library, which understands the part of the syntax that the
expressions of Lucene (ES|QL's RLIKE) have in common with Python's: literals, escapes, `.`, character
classes, groups, alternations and repetitions. What is not part of it (anchors, look-arounds, back references,
flags) is not supported, `check()` says so. Like in Lucene the whole string has to match.
"""

import re
import string

try:
    from re import _constants as sre_constants
    from re import _parser as sre_parse
except ImportError:  # Python < 3.11
    import sre_constants
    import sre_parse

from . import random

# what is picked for `.`, a class or its negation: characters that are no trouble in a keyword or a command line
ALPHABET = string.ascii_letters + string.digits
PRINTABLE = [chr(c) for c in range(0x20, 0x7F)]
# how many strings are generated at most, one per alternative of the expression
MAX_VARIANTS = 20
# what is repeated at least, even if the expression allows for none (`*`, `?`)
MAX_REPEAT = 1
ATTEMPTS = 200

CATEGORIES = {
    "CATEGORY_DIGIT": lambda c: c in string.digits,
    "CATEGORY_NOT_DIGIT": lambda c: c not in string.digits,
    "CATEGORY_SPACE": lambda c: c in " \t\n\r\f\v",
    "CATEGORY_NOT_SPACE": lambda c: c not in " \t\n\r\f\v",
    "CATEGORY_WORD": lambda c: c in ALPHABET + "_",
    "CATEGORY_NOT_WORD": lambda c: c not in ALPHABET + "_",
}


class Unmatchable(Exception):
    """What cannot be matched by a string in lowercase."""


def parse(pattern):
    try:
        parsed = sre_parse.parse(pattern)
    except (re.error, sre_constants.error, RecursionError) as e:
        raise ValueError(f"Invalid regular expression {pattern!r}: {e}") from None
    # `(?i)` and the like, the only flag that is there by default is the one for unicode
    if parsed.state.flags & ~re.UNICODE:
        raise unsupported("flags", pattern)
    return parsed


def unsupported(what, pattern):
    return NotImplementedError(f"Unsupported {what} in the regular expression {pattern!r}")


def char_choices(items, pattern, lower=False):
    """Return the characters of a class, those that have no uppercase form if `lower`."""
    negate = bool(items) and str(items[0][0]) == "NEGATE"
    tests = []
    for op, av in items[1:] if negate else items:
        op = str(op)
        if op == "LITERAL":
            tests.append(lambda c, v=av: ord(c) == v)
        elif op == "RANGE":
            tests.append(lambda c, lo=av[0], hi=av[1]: lo <= ord(c) <= hi)
        elif op == "CATEGORY" and str(av) in CATEGORIES:
            tests.append(CATEGORIES[str(av)])
        else:
            raise unsupported(f"class item {op}", pattern)
    choices = [c for c in printable(lower) if any(test(c) for test in tests) != negate]
    if not choices:
        if lower and any(any(test(c) for test in tests) != negate for c in PRINTABLE):
            raise Unmatchable
        raise ValueError(f"The class of characters is empty in the regular expression {pattern!r}")
    return choices


def combine(factors):
    """Join a sequence of factors, each is the list of its variants: all of them are used at least once."""
    size = max((len(factor) for factor in factors), default=1)
    return ["".join(factor[i % len(factor)] for factor in factors) for i in range(size)]


def pick(choices, preferred=ALPHABET):
    """Pick a character, a letter or a digit if there is one."""
    likely = [c for c in choices if c in preferred]
    return random.choice(likely or choices)


def printable(lower=False):
    """Return the characters that are picked from: those that a lowercase string can have if `lower`."""
    return [c for c in PRINTABLE if not lower or c == c.lower()]


def variants_of(nodes, pattern, lower=False):
    """Return the strings that a sequence of nodes generates."""
    return combine([node_variants(op, av, pattern, lower) for op, av in nodes])


def node_variants(op, av, pattern, lower=False):
    op = str(op)
    if op == "LITERAL":
        return [chr(av)]
    if op == "NOT_LITERAL":
        return [pick([c for c in printable(lower) if ord(c) != av])]
    if op == "ANY":
        return [pick(printable(lower))]
    if op == "IN":
        return [pick(char_choices(list(av), pattern, lower))]
    if op == "CATEGORY":
        return [pick(char_choices([(op, av)], pattern, lower))]
    if op == "SUBPATTERN":
        _, add_flags, del_flags, subpattern = av
        if add_flags or del_flags:
            raise unsupported("flags", pattern)
        return variants_of(subpattern, pattern, lower)
    if op == "BRANCH":
        variants = []
        for alternative in av[1]:
            try:
                variants.extend(variants_of(alternative, pattern, lower))
            except Unmatchable:
                continue  # `[A-Z]` has no lowercase string, the other alternatives may
        if not variants:
            raise Unmatchable
        return variants
    if op in ("MAX_REPEAT", "MIN_REPEAT"):
        lo, hi, subpattern = av
        count = min(hi, max(lo, MAX_REPEAT))
        if count == 0:
            return [""]
        # each repetition has its own characters, the variants of the group are rotated through them
        try:
            repetitions = [variants_of(subpattern, pattern, lower) for _ in range(count)]
        except Unmatchable:
            if lo == 0:
                return [""]
            raise
        size = len(repetitions[0])
        return ["".join(repetition[(i + k) % size] for k, repetition in enumerate(repetitions)) for i in range(size)]
    raise unsupported(f"element {op}", pattern)


def check(pattern):
    """Raise if the expression is not valid or has what is not supported."""
    variants_of(parse(pattern), pattern)


def matching(pattern, limit=MAX_VARIANTS, lower=False):
    """Return strings that match the expression, at least one per alternative (up to a limit), in lowercase if asked."""
    try:
        variants = variants_of(parse(pattern), pattern, lower)
    except Unmatchable:
        raise NotImplementedError(f"Cannot generate a lowercase string for the regular expression {pattern!r}") from None
    compiled = re.compile(pattern, re.DOTALL)
    unique = list(dict.fromkeys(v.lower() if lower else v for v in variants))
    # Python and Lucene agree on the syntax that is supported, this is to be sure
    matches = [v for v in unique if compiled.fullmatch(v)]
    # in lowercase an alternative can be left without a match (`[A-Z]+`), the others are enough
    if not matches or (len(matches) != len(unique) and not lower):
        raise NotImplementedError(f"Cannot generate a{' lowercase' if lower else ''} string for the regular expression {pattern!r}")
    return matches[:limit]


def mutations(pattern, lower=False):
    """Return strings that are close to what the expression matches, they are the likeliest to be near misses."""
    yield ""
    try:
        base = variants_of(parse(pattern), pattern, lower)[0]
    except Unmatchable:
        return  # nothing in lowercase matches, any string is a candidate
    yield base[:-1]
    yield base + random.choice(ALPHABET)
    yield random.choice(ALPHABET) + base
    if base:
        i = random.randrange(len(base))
        yield base[:i] + random.choice(ALPHABET) + base[i + 1 :]


def not_matching(pattern, lower=False):
    """Return a string that doesn't match the expression, in lowercase if asked."""
    parsed = parse(pattern)  # fails if it is not valid
    variants_of(parsed, pattern)
    compiled = re.compile(pattern, re.DOTALL)
    candidates = list(mutations(pattern, lower))
    for _ in range(ATTEMPTS):
        candidates.append("".join(random.choices(ALPHABET, k=random.randint(1, 12))))
    # what is left, in case that what the expression matches is made of letters and digits
    candidates.extend(printable(lower))
    candidates.extend(random.choice(printable(lower)) + random.choice(ALPHABET) for _ in range(ATTEMPTS))
    if lower:
        candidates = [candidate.lower() for candidate in candidates]
    # an empty string is the last resort, it is the only one that `.+` doesn't match
    for candidate in sorted(candidates, key=lambda c: not c):
        if not compiled.fullmatch(candidate):
            return candidate
    raise NotImplementedError(f"Cannot generate a string that doesn't match the regular expression {pattern!r}")
