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

"""Functions for collecting constraints from an EQL AST."""

from __future__ import annotations

import json
import math
from itertools import chain, product
from typing import Any, NoReturn

import eql

from .constraints import Branch, ConflictError, Document, Root
from .utils import TreeTraverser, split_path

__all__ = ()

traverser = TreeTraverser()


def collect_constraints(node: eql.ast.BaseNode, negate: bool = False, max_branches: int | None = None) -> Root:
    return traverser.traverse(node, negate, max_branches)


def get_ast_stats():
    return traverser.get_stats()


def _nope(operation: Any, negate: bool) -> Any:
    negation = {
        "==": "!=",
        "!=": "==",
        ">=": "<",
        "<=": ">",
        ">": "<=",
        "<": ">=",
        cc_or_terms: cc_and_terms,
        cc_and_terms: cc_or_terms,
    }
    return operation if not negate else negation.get(operation, not operation)


@traverser(eql.ast.Field)
def cc_field(node: eql.ast.Field, value: str, negate: bool, max_branches: int) -> Root:
    doc = Document(node.render(), _nope("==", negate), value)
    return Root([Branch([doc])])


@traverser(eql.ast.Boolean)
def cc_boolean(node: eql.ast.Boolean, negate: bool, max_branches: int) -> Root:
    branches = []
    if _nope(node.value, negate):
        branches.append(Branch.Identity)
    return Root(branches)


def cc_or_terms(node: eql.ast.Or | eql.ast.And, negate: bool, max_branches: int) -> Root:
    terms = tuple(collect_constraints(term, negate, max_branches) for term in node.terms)
    if max_branches:
        nr_branches = sum(len(branches) for branches in terms)
        if nr_branches > max_branches:
            raise ValueError(f"Root with too many branches (limit: {max_branches})")
    return Root.chain(terms)


def cc_and_terms(node: eql.ast.Or | eql.ast.And, negate: bool, max_branches: int) -> Root:
    terms = tuple(collect_constraints(term, negate, max_branches) for term in node.terms)
    if max_branches:
        nr_branches = math.prod(len(branches) for branches in terms)
        if nr_branches > max_branches:
            raise ValueError(f"Root with too many branches (limit: {max_branches})")
    return Root.product(terms)


@traverser(eql.ast.Or)
def cc_or(node: eql.ast.Or, negate: bool, max_branches: int) -> Root:
    return _nope(cc_or_terms, negate)(node, negate, max_branches)


@traverser(eql.ast.And)
def cc_and(node: eql.ast.And, negate: bool, max_branches: int) -> Root:
    return _nope(cc_and_terms, negate)(node, negate, max_branches)


@traverser(eql.ast.Not)
def cc_not(node: eql.ast.Not, negate: bool, max_branches: int) -> Root:
    return collect_constraints(node.term, not negate, max_branches)


@traverser(eql.ast.IsNull)
def cc_is_null(node: eql.ast.IsNull, negate: bool, max_branches: int) -> Root:
    if not isinstance(node.expr, eql.ast.Field):
        raise NotImplementedError(f"Unsupported expression type: {type(node.expr)}")
    return cc_field(node.expr, None, negate, max_branches)


@traverser(eql.ast.IsNotNull)
def cc_is_not_null(node: eql.ast.IsNotNull, negate: bool, max_branches: int) -> Root:
    if not isinstance(node.expr, eql.ast.Field):
        raise NotImplementedError(f"Unsupported expression type: {type(node.expr)}")
    return cc_field(node.expr, None, not negate, max_branches)


@traverser(eql.ast.InSet)
def cc_in_set(node: eql.ast.InSet, negate: bool, max_branches: int) -> Root:
    if not isinstance(node.expression, eql.ast.Field):
        raise NotImplementedError(f"Unsupported expression type: {type(node.expression)}")
    branches = []
    if negate:
        field = node.expression.render()
        doc = Document()
        for term in node.container:
            doc.append_constraint(field, "!=", term.value)
        branches.append(Branch([doc]))
    else:
        if max_branches and len(node.container) > max_branches:
            raise ValueError(f"Root with too many branches (limit: {max_branches})")
        for term in node.container:
            branches.extend(cc_field(node.expression, term.value, negate, max_branches))
    return Root(branches)


@traverser(eql.ast.Comparison)
def cc_comparison(node: eql.ast.Comparison, negate: bool, max_branches: int) -> Root:
    if not isinstance(node.left, eql.ast.Field):
        raise NotImplementedError(f"Unsupported LHS type: {type(node.left)}")
    doc = Document(node.left.render(), _nope(node.comparator, negate), node.right.value)
    return Root([Branch([doc])])


@traverser(eql.ast.EventQuery)
def cc_event_query(node: eql.ast.EventQuery, negate: bool, max_branches: int) -> Root:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    if not isinstance(node.event_type, str):
        raise NotImplementedError(f"Unsupported event_type type: {type(node.event_type)}")
    root = collect_constraints(node.query, negate, max_branches)
    if node.event_type != "any":
        for c in root.constraints():
            c.append_constraint("event.category", "==", node.event_type)
    return root


@traverser(eql.ast.PipedQuery)
def cc_piped_query(node: eql.ast.PipedQuery, negate: bool, max_branches: int) -> Root:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    if node.pipes:
        raise NotImplementedError("Pipes are unsupported")
    return collect_constraints(node.first, negate, max_branches)


def cc_subquery_by(node: eql.ast.SubqueryBy, negate: bool, max_branches: int) -> list[list[tuple[Document, list[str]]]]:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    if any(not isinstance(value, eql.ast.Field) for value in node.join_values):
        raise NotImplementedError(f"Unsupported join values: {node.join_values}")
    if node.data:
        if node.data.get("fork", False):
            raise NotImplementedError(f"Unsupported fork: {node.data}")
        if node.data.get("is_negated", False):
            raise NotImplementedError(f"Unsupported is_negated: {node.data}")
    join_fields = [field.render() for field in node.join_values]
    return [[(doc, join_fields) for doc in branch] for branch in collect_constraints(node.query, negate, max_branches)]


def cc_join_branch(seq: list[tuple[Document, list[str]]]) -> Branch:
    join_doc = Document()
    docs = [join_doc.join_fields(doc, join_fields) for doc, join_fields in seq]
    return Branch(docs)


@traverser(eql.ast.Sequence)
def cc_sequence(node: eql.ast.Sequence, negate: bool, max_branches: int) -> Root:
    if negate:
        raise NotImplementedError(f"Negation of {type(node)} is not supported")
    queries = [cc_subquery_by(query, negate, max_branches) for query in node.queries]
    if node.close:
        queries.append([[(doc, []) for doc in branch] for branch in collect_constraints(node.close, negate, max_branches)])
    if max_branches:
        nr_branches = math.prod(len(branches) for branches in queries)
        if nr_branches > max_branches:
            raise ValueError(f"Root with too many branches (limit: {max_branches})")
    return Root([cc_join_branch(chain(*branches)) for branches in chain(product(*queries))])


@traverser(eql.ast.FunctionCall)
def cc_function_call(node: eql.ast.FunctionCall, negate: bool, max_branches: int) -> Root:
    fn_name = node.name.lower()
    if fn_name == "_esql":
        # its argument is a whole expression, not a field
        return cc_esql(node, negate, max_branches)
    if fn_name == "_kql":
        return cc_kql(node, negate, max_branches)
    if fn_name == "_stats":
        return cc_stats(node, negate, max_branches)
    if type(node.arguments[0]) is not eql.ast.Field:
        raise NotImplementedError(f"Unsupported argument type: {type(node.arguments[0])}")
    args_types = (eql.ast.String, eql.ast.Number)
    if any(type(arg) not in args_types for arg in node.arguments[1:]):
        wrong_types = sorted({str(type(arg)) for arg in node.arguments[1:] if type(arg) not in args_types})
        raise NotImplementedError(f"Unsupported argument type(s): {', '.join(wrong_types)}")
    if fn_name == "wildcard":
        return cc_wildcard(node, negate, max_branches)
    elif fn_name == "cidrmatch":
        return cc_function(node, negate, max_branches, "in")
    elif fn_name == "_cardinality":
        return cc_function(node, negate, max_branches, "cardinality")
    elif fn_name == "_like":
        return cc_like(node, negate, max_branches)
    elif fn_name == "_literal":
        return cc_literal(node, negate, max_branches)
    else:
        raise NotImplementedError(f"Unsupported function: {node.name}")


def cc_function(node: eql.ast.FunctionCall, negate: bool, max_branches: int, constraint_name: str) -> Root:
    field = node.arguments[0].render()
    constraint_name = constraint_name if not negate else f"not {constraint_name}"
    doc = Document(field, constraint_name, tuple(arg.value for arg in node.arguments[1:]))
    return Root([Branch([doc])])


def cc_esql(node: eql.ast.FunctionCall, negate: bool, max_branches: int) -> Root:
    # the expression comes from an ES|QL query, which is stricter than EQL: flag its constraints (and
    # only them, wherever the node sits in the tree) for the solvers that know the field types to check
    if len(node.arguments) != 1:
        raise NotImplementedError(f"Unsupported number of arguments for {node.name}: {len(node.arguments)}")
    root = collect_constraints(node.arguments[0], negate, max_branches)
    joined = {}
    for doc in root.constraints():
        doc.flag_constraints({"esql": True}, unless="kql")
        # the document of what the documents of a group share is not one of them, and it solves their fields
        for _, constraints in doc.items():  # noqa: PERF102, a Document has no values()
            for name, value, *_ in constraints or ():
                if name == "join_value":
                    joined[id(value[0])] = value[0]
    for join_doc in joined.values():
        join_doc.flag_constraints({"esql": True}, unless="kql")
    return root


# a cardinality that is never reached, all the values of the field are different
DISTINCT = 2**31
# the documents that a threshold may ask for
MAX_DOCUMENTS = 1000


def normalize_name(name: str) -> str:
    return ".".join(split_path(name))


def count_interval(field: str, constraints: Any) -> tuple[int, float, set]:
    """Return the least, the most and what is not allowed in between that the conditions on a count allow, at least one document."""
    if constraints is None:
        raise ConflictError("cannot be null", field)
    lo, hi, excluded = 1, math.inf, set()
    for name, value, *_ in constraints:
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise NotImplementedError(f"Unsupported value in the condition on {field}: {value!r}")
        if name == ">=":
            lo = max(lo, math.ceil(value))
        elif name == ">":
            lo = max(lo, math.floor(value) + 1)
        elif name == "<=":
            hi = min(hi, math.floor(value))
        elif name == "<":
            hi = min(hi, math.ceil(value) - 1)
        elif name == "==":
            lo, hi = max(lo, math.ceil(value)), min(hi, math.floor(value))
        elif name == "!=":
            excluded.add(value)
        else:
            raise NotImplementedError(f"Unsupported condition on {field}: {name}")
    while lo in excluded:
        lo += 1
    while hi in excluded:
        hi -= 1
    if lo > hi:
        raise ConflictError(f"empty solution space, {lo} <= x <= {hi}", field)
    return lo, hi, {value for value in excluded if lo < value < hi}


def cc_stats(node: eql.ast.FunctionCall, negate: bool, max_branches: int) -> Root:
    # the documents before an aggregation, in the number that its conditions ask for and related as BY asks
    if negate:
        raise NotImplementedError("Unsupported negation of STATS")
    pre, post, spec = node.arguments
    spec = json.loads(spec.value)
    aggregates = {normalize_name(alias): (function, argument, simple) for alias, function, argument, simple in spec["aggregates"]}
    by = [normalize_name(field) for field in spec["by"]]
    join = [normalize_name(field) for field in spec["join"]]
    pre_root = collect_constraints(pre, False, max_branches)
    post_root = collect_constraints(post, False, max_branches)
    if max_branches and len(pre_root) * len(post_root) > max_branches:
        raise ValueError(f"Root with too many branches (limit: {max_branches})")
    return Root([stats_branch(pre_branch, post_branch, aggregates, by, join) for pre_branch in pre_root for post_branch in post_root])


def positive_constraints(constraints: Any) -> list:
    return [c for c in constraints or [] if c[0] in ("==", "wildcard", "in")]


def stats_branch(pre_branch: Branch, post_branch: Branch, aggregates: dict, by: list, join: list) -> Branch:
    if len(pre_branch) != 1:
        raise NotImplementedError("Unsupported STATS of documents that are related")
    base = pre_branch[0]
    counts, distinct, by_conditions = [], {}, []
    for doc in post_branch:
        for field, constraints in doc.items():
            if field in aggregates:
                function, argument, simple = aggregates[field]
                if function == "values":
                    raise NotImplementedError(f"Unsupported condition on the values of {field}")
                if not simple or function not in ("count", "count_distinct"):
                    raise NotImplementedError(f"Unsupported condition on the aggregate {field}")
                lo, hi, excluded = count_interval(field, constraints)
                if function == "count":
                    counts.append((field, argument, lo, hi, excluded))
                else:
                    old_lo, old_hi, old_excluded = distinct.get(argument, (1, math.inf, set()))
                    distinct[argument] = (max(lo, old_lo), min(hi, old_hi), excluded | old_excluded)
            elif field in by:
                if constraints is None:
                    raise NotImplementedError(f"Unsupported condition on the BY field {field}: it is null")
                by_conditions.append((field, constraints))
            else:
                raise NotImplementedError(f"Unsupported field in WHERE after STATS: {field}")

    # what is counted of a field are its values, those of a document that has many are not a document
    base_constraints = dict(base.items())
    for field in {argument for _, argument, *_ in counts if argument} | set(distinct):
        if len(positive_constraints(base_constraints.get(field))) > 1:
            raise NotImplementedError(f"Unsupported aggregate of a field with many values: {field}")

    # how many documents there are, a COUNT of a field counts those that have it and all of them have it
    size = max([lo for _, _, lo, *_ in counts] + [lo for lo, *_ in distinct.values()] + [1])
    size_hi = min([hi for _, _, _, hi, _ in counts] + [math.inf])
    excluded = set().union(*(e for *_, e in counts))
    while size in excluded:
        size += 1
    if size > size_hi:
        raise ConflictError(f"empty solution space, {size} <= x <= {size_hi}", counts[0][0] if counts else "count")
    if size > MAX_DOCUMENTS:
        raise NotImplementedError(f"Unsupported threshold, {size} documents are needed (limit: {MAX_DOCUMENTS})")

    # how many different values: one for all of them, a different one for each, or not more than a number
    shared, different, capped = [], [], {}
    for field, (lo, hi, not_allowed) in distinct.items():
        if lo > hi:
            raise ConflictError(f"empty solution space, {lo} <= x <= {hi}", field)
        if not_allowed:
            raise NotImplementedError(f"Unsupported exclusion of the number of different values of {field}: {sorted(not_allowed)}")
        if hi == 1:
            shared.append(field)
        elif lo > 1 and hi < size:
            raise NotImplementedError(f"Unsupported number of different values of {field}: between {lo} and {hi} in {size} documents")
        elif lo > 1:
            different.append(field)
        elif hi < size:
            capped[field] = int(hi)
    join_fields = join + [field for field in shared if field not in join]
    for field in different:
        if field in join_fields:
            raise NotImplementedError(f"Unsupported COUNT_DISTINCT of a BY field: {field}")
    present = {argument for _, argument, *_ in counts if argument} | set(distinct)

    join_doc = Document()
    docs = []
    for _ in range(size):
        doc = base.clone()
        for field, constraints in by_conditions:
            for name, value, *flags in constraints:
                doc.append_constraint(field, name, value, flags[0] if flags else None)
        for field in different:
            doc.append_constraint(field, "cardinality", DISTINCT)
        for field, most in capped.items():
            doc.append_constraint(field, "cardinality", most)
        for field in sorted(present):
            doc.append_constraint(field)
        docs.append(doc)

    # what the conditions on the BY fields add is subject to the rules of the query as the rest is
    for field, _ in by_conditions:
        positives = positive_constraints(dict(docs[0].items()).get(field))
        from_kql = sum(1 for c in positives if c[2:] and c[2].get("kql"))
        if len(positives) > from_kql and len(positives) > 1:
            raise NotImplementedError(
                f"Unsupported conflicting constraints on {field}: only one equality or pattern per field is supported"
            )

    branch = Branch([join_doc.join_fields(doc, join_fields, unique=True) if join_fields else doc for doc in docs])
    # the time is not a field that the documents can be made to share, a bucket of it is what BY may ask for
    branch.shared_timestamp = True
    return branch


def cc_kql(node: eql.ast.FunctionCall, negate: bool, max_branches: int) -> Root:
    # the expression comes from a KQL string inside an ES|QL query, it keeps the meaning that KQL gives
    # it (no scalar comparisons for instance), mark its constraints so that ES|QL doesn't claim them
    if len(node.arguments) != 1:
        raise NotImplementedError(f"Unsupported number of arguments for {node.name}: {len(node.arguments)}")
    root = collect_constraints(node.arguments[0], negate, max_branches)
    for doc in root.constraints():
        doc.flag_constraints({"kql": True})
    return root


def cc_literal(node: eql.ast.FunctionCall, negate: bool, max_branches: int) -> Root:
    # an equality where `*` and `?` are what they are, not wildcards (a quoted value in KQL, any value in ES|QL)
    field = node.arguments[0].render()
    doc = Document()
    doc.append_constraint(field, "==" if not negate else "!=", node.arguments[1].value, {"literal": True})
    return Root([Branch([doc])])


def cc_like(node: eql.ast.FunctionCall, negate: bool, max_branches: int) -> Root:
    # case sensitive wildcard (ES|QL's LIKE), the keyword solver honours the flag
    field = node.arguments[0].render()
    pattern = node.arguments[1].value
    doc = Document()
    if negate:
        # excluding the pattern regardless of the case removes more values than needed, which is safe
        doc.append_constraint(field, "not wildcard", pattern)
    else:
        doc.append_constraint(field, "wildcard", pattern, {"case_sensitive": True})
    return Root([Branch([doc])])


def cc_wildcard(node: eql.ast.FunctionCall, negate: bool, max_branches: int) -> Root:
    field = node.arguments[0].render()
    branches = []
    if negate:
        doc = Document(field)
        for arg in node.arguments[1:]:
            doc.append_constraint(field, "not wildcard", arg.value)
        branches.append(Branch([doc]))
    else:
        for arg in node.arguments[1:]:
            doc = Document(field, "wildcard", arg.value)
            branches.append(Branch([doc]))
    return Root(branches)


@traverser(eql.ast.BaseNode)
@traverser(eql.ast.Expression)
@traverser(eql.ast.EqlNode)
@traverser(eql.ast.Literal)
@traverser(eql.ast.String)
@traverser(eql.ast.Number)
@traverser(eql.ast.Null)
@traverser(eql.ast.TimeRange)
@traverser(eql.ast.TimeUnit)
@traverser(eql.ast.MathOperation)
@traverser(eql.ast.NamedSubquery)
@traverser(eql.ast.NamedParams)
@traverser(eql.ast.Join)
@traverser(eql.ast.PipeCommand)
@traverser(eql.ast.EqlAnalytic)
@traverser(eql.ast.Definition)
@traverser(eql.ast.BaseMacro)
@traverser(eql.ast.CustomMacro)
@traverser(eql.ast.Macro)
@traverser(eql.ast.Constant)
@traverser(eql.ast.PreProcessor)
def cc_not_implemented(node: eql.ast.BaseNode, negate: bool, max_branches: int) -> NoReturn:
    raise NotImplementedError(f"Traverser not implemented: {type(node)}")
