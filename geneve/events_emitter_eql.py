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

import math
from itertools import chain, product
from typing import Any, List, NoReturn, Tuple, Union

import eql

from .constraints import Branch, Document, Root
from .utils import TreeTraverser

__all__ = ()

traverser = TreeTraverser()


def collect_constraints(node: eql.ast.BaseNode, negate: bool = False, max_branches: int = None) -> Root:
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


def cc_or_terms(node: Union[eql.ast.Or, eql.ast.And], negate: bool, max_branches: int) -> Root:
    terms = tuple(collect_constraints(term, negate, max_branches) for term in node.terms)
    if max_branches:
        nr_branches = sum(len(branches) for branches in terms)
        if nr_branches > max_branches:
            raise ValueError(f"Root with too many branches (limit: {max_branches})")
    return Root.chain(terms)


def cc_and_terms(node: Union[eql.ast.Or, eql.ast.And], negate: bool, max_branches: int) -> Root:
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


def cc_subquery_by(node: eql.ast.SubqueryBy, negate: bool, max_branches: int) -> List[Tuple[Document, List[str]]]:
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


def cc_join_branch(seq: List[Tuple[Document, List[str]]]) -> Branch:
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
    if type(node.arguments[0]) is not eql.ast.Field:
        raise NotImplementedError(f"Unsupported argument type: {type(node.arguments[0])}")
    args_types = (eql.ast.String, eql.ast.Number)
    if any(type(arg) not in args_types for arg in node.arguments[1:]):
        wrong_types = sorted({str(type(arg)) for arg in node.arguments[1:] if type(arg) not in args_types})
        raise NotImplementedError(f"Unsupported argument type(s): {', '.join(wrong_types)}")
    fn_name = node.name.lower()
    if fn_name == "wildcard":
        return cc_wildcard(node, negate, max_branches)
    elif fn_name == "cidrmatch":
        return cc_function(node, negate, max_branches, "in")
    elif fn_name == "_cardinality":
        return cc_function(node, negate, max_branches, "cardinality")
    else:
        raise NotImplementedError(f"Unsupported function: {node.name}")


def cc_function(node: eql.ast.FunctionCall, negate: bool, max_branches: int, constraint_name: str) -> Root:
    field = node.arguments[0].render()
    constraint_name = constraint_name if not negate else f"not {constraint_name}"
    doc = Document(field, constraint_name, tuple(arg.value for arg in node.arguments[1:]))
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
