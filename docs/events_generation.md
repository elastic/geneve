## Events generation

The aim is to synthetize one or more documents that would make a given detection rule trigger a SIEM signal.


For instance, given the EQL query

```
network where destination.port == 22
```

the _minimal source event_ (with `@timestamp` omitted for readability) is

```
{"event": {"category": ["network"]}, "destination": {"port": 22}}
```

Independently from any other field being present, those in the minimal source event are needed for the detection engine to generate a signal.

Depending on the rule, multiple documents might be needed. Indeed

```
sequence by user.id
    [process where process.name : "cmd.exe"]
    [process where process.parent.name : "cmd.exe"]
```
requires two documents as below

```
{"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "xgG"}},
{"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"id": "xgG"}},
```
The fields content is generated pseudo-randomly according to each field type and the constraints specified in the query itself.

## Approach

The idea is to use the query itself to build the _minimal source event_.

These are the high level steps:

1. The query is parsed and translated into the corresponding abstract syntax tree (AST)
2. The AST is traversed and the fields constraints are collected
3. The constraints of each field are solved, if possible, and stored in a set of _field-value_ pairs
4. The set of _field-value_ pairs is translated to a document

Details about the single steps follow.

### Generating the AST

AST generation is currently based on the [EQL parser](https://eql.readthedocs.io/en/latest/api/parser.html), therefore only EQL, Kuery and ES|QL rules (which AST can be translated to EQL) are currently supported.

The relevant code (from [geneve/events\_emitter.py](../geneve/events_emitter.py)) is:

```python
def ast_from_rule(rule):
    if rule.type not in ("query", "eql", "esql"):
        raise NotImplementedError(f"Unsupported rule type: {rule.type}")
    elif (rule.type == "esql") != (rule.language == "esql"):
        raise NotImplementedError(f"Unsupported rule type and query language: {rule.type}, {rule.language}")
    elif rule.language == "eql":
        return ast_from_eql_query(rule.query)
    elif rule.language == "kuery":
        return ast_from_kql_query(rule.query)
    elif rule.language == "esql":
        return ast_from_esql_query(rule.query)
    else:
        raise NotImplementedError(f"Unsupported query language: {rule.language}")
```

#### ES|QL

ES|QL queries are parsed by [geneve/esql](../geneve/esql), a small [lark](https://lark-parser.readthedocs.io) grammar that covers the part of the language that selects documents. The query is translated to the same AST as EQL, so the following steps need no changes.

`esql.to_eql()` returns the AST to generate documents from: the translation is wrapped in a private `_esql` function, which the constraints collector uses to flag the constraints that come from ES|QL (and only them, even when the AST is mixed with EQL nodes). `esql.parse(query).where` is the plain translation, to inspect it.

Supported:

* `FROM` with any number of index patterns and an optional `METADATA` clause. The indices are returned by `esql.parse()` but do not drive the generation.
* `WHERE`, any number of times, with `AND`, `OR`, `NOT`, `==`, `!=`, `<`, `<=`, `>`, `>=`, `IN`, `IS [NOT] NULL`, `LIKE` (`*` and `?` only), `STARTS_WITH`, `ENDS_WITH`, `CIDR_MATCH`, `MV_CONTAINS(field, literal)` (treated as an equality: a single value is emitted, as an array of one on array fields) and `KQL("query")`. The string of `KQL()` is translated by the KQL front end and keeps the semantics of KQL, for instance it can ask for two values for an array field, which a comparison of ES|QL cannot, and a quoted value is a literal (`field:"*"` is an asterisk, not "any value", and `?` is never a wildcard) as Elasticsearch has it.
* `KEEP`, `DROP` and `SORT`, anywhere: they hide columns or sort the rows, the documents that match are the same, and they are ignored. `LIMIT` is ignored too, but only after the last `WHERE` and `STATS`.
* `STATS` once, with `COUNT(*)`, `COUNT(field)`, `COUNT_DISTINCT(field)` and `VALUES(field)`, named (`alias = ...`), and `BY` with plain fields. The `WHERE` that follows may compare the aliases of the counts with numbers (`>=`, `>`, `<=`, `<`, `==`, `!=`, `AND`, `OR`, `NOT`) and may ask what it likes for the `BY` fields. A group of documents is generated: as many as the conditions need (up to 1,000), all with the `BY` fields equal, with a different value of the field for each when `COUNT_DISTINCT` has to be more than one, and the same when it has to be one. An `OR` makes a branch for each side. `EVAL` after `STATS` is ignored as long as no `WHERE` asks for what it makes.

Everything else is rejected with an `Unsupported ...` error instead of generating documents that would not match the query. In particular:

* other commands (`EVAL` before `STATS`, `GROK`, `DISSECT`, `MV_EXPAND`, a second `STATS`, ...) and source commands (`ROW`, `SHOW`, ...), as well as `LIMIT` before a `WHERE` or `STATS`;
* aggregate functions other than the ones above (`MIN`, `MAX`, `SUM`, ...), arguments that are not a field (`COUNT_DISTINCT(TO_LOWER(f))`), `BY` with an expression or a name, and conditions after `STATS` on anything but the counts and the `BY` fields;
* functions other than the ones above, arithmetic and operands that are not a field on the left and a literal on the right of a comparison;
* `NULL` literals (use `IS NULL` and `IS NOT NULL`) and predicates on metadata fields such as `_id`;
* strings with `*` or `?` in `STARTS_WITH`/`ENDS_WITH`, `LIKE` patterns with backslash escapes or `[`, and `RLIKE`; in `==`, `!=`, `IN` and `MV_CONTAINS` instead they are what they are, not wildcards, and the documents have them as they are;
* more than one equality or pattern on the same field in a branch, for instance `tags == "a" AND tags == "b"`: on array fields each of them would become an independent value, but ES|QL returns null for multivalued fields in a comparison;
* what the solver of the field cannot do right: fractional numbers on `long` fields (they would be truncated) and network literals in `==`, `!=` and `IN` on `ip` fields (`CIDR_MATCH` is supported). These checks need the type of the field, therefore they are done when the query is added to `SourceEvents` and not when it is parsed.

Queries that expand to more than 10,000 branches, for instance by chaining many `IN` and `OR`, are rejected as well.

What the schema does not know of a field (the fields of the integrations) is what the literals of the query say, as ES|QL has typed literals: `flag != true` is a boolean, `n > 5` a long, `s == "a"` a keyword. It is the type of the solver and of the mapping that is generated. The other languages keep taking such a field for a keyword.

Fields of type `constant_keyword` (such as `data_stream.dataset`) are solved as plain keywords for ES|QL only, the other languages still reject them, and they are mapped as `keyword` so that the documents of different branches can share an index.

### Validating the documents against Elasticsearch

For ES|QL the query itself tells whether the documents are right. `tests/test_esql_validation.py` generates the documents of each branch of the supported queries and rules, indexes them in an Elasticsearch (Kibana is not needed) and runs the query, which must return each document once (for the queries that aggregate, a group of documents is a row, and the branches are checked one by one). It is opt-in:

```
TEST_ESQL_VALIDATION=1 TEST_ESQL_ES_URL=http://127.0.0.1:29650 TEST_STACK_VERSION=9.5.0 python -m pytest tests/test_esql_validation.py
```

`TEST_ESQL_ES_URL` defaults to the Elasticsearch of the docker compose file, put the credentials in the URL if it has any. The result for the rules is written to `tests/reports/esql_validation-<version>.md`.

Unlike the other languages, `LIKE` is case sensitive: it matches `FOO*` against `FOObar`, not against `foobar`.

### Collecting the constraints

Constraints collection is done in a recursive fashion, every [AST node](https://eql.readthedocs.io/en/latest/api/ast.html) is matched by an _emitter_ which purpose is to extract the constraints from the node.

For instance (from [geneve/events\_emitter\_eql.py](../geneve/events_emitter_eql.py))

```python
@traverser(eql.ast.Field)
def cc_field(node: eql.ast.Field, value: str, negate: bool) -> Root:
    doc = Document(node.render(), _nope("==", negate), value)
    return Root([Branch([doc])])
```

Constraints are essentially a list of tuples associated to each field. In the case of the sequence query above,

```
sequence by user.id
    [process where process.name : "cmd.exe"]
    [process where process.parent.name : "cmd.exe"]
```

a simplified representation of its constraints is

```json
[
    {
        "process.name": [
            ["wildcard", "cmd.exe"]
        ]
    },
    {
        "process.parent.name": [
            ["wildcard", "cmd.exe"]
        ]
    }
]
```

Note how it's a list of two dictionaries, one for each document to be generated, and how each can arbitrarily grow in the fields it can contain and the constraints each field can have.

Also, the `user.id` join value is omitted for readability. As a matter of fact, when the first document in the sequence is generated, all its join values are propagated (and named) as additional constraints of the subsequent documents of that sequence instance.

### Solving the constraints

Constraints are arbitrary, solution spaces are huge and space/time is a finite resource. [Constraint programming](https://en.wikipedia.org/wiki/Constraint_programming) is a branch on its own and comes with its Python [module](https://pypi.org/project/python-constraint/). Nevertheless we develop our solution in [geneve/constraints.py](../geneve/constraints.py).

Each document to be generated is represented by a `Constraints` object which collects all the fields that need to be present (or absent). Each field is associated with the list of constraints it needs to satisfy, if possible. The appropriate constraint solver is determined by the field type as identified by the ECS or some other schema.

The constraints solvers perform the following steps:

1. validate all the constraints and their arguments
2. check that constraints are not conflicting or resulting in the empty solution space
3. check that any specified value satisfies all the constraints
4. if no value was specified, generate one that meets all the constraints

As example, the most simple solver

```python
@solver("boolean", "==", "!=")
def solve_boolean_constraints(cls, field, value, constraints):
    for k,v in constraints:
        if k == "==":
            v = bool(v)
            if value is None or value == v:
                value = v
            else:
                raise ConflictError(f"is already {value}, cannot set to {v}", field, k)
        elif k == "!=":
            v = bool(v)
            if value is None or value != v:
                value = not v
            else:
                raise ConflictError(f"is already {value}, cannot set to {not v}", field, k)

    if value is None:
        value = random.choice((True, False))
    return {"value": value}
```

Solvers of keywords (with sets, wildcards and regex), longs and ip addresses (with ipv4, ipv6 and cidr blocks) are way more complex, necessarily incomplete but proven correct for some definitions of _tested_.

### Generating the documents

Once the constraints are solved and fields generated, assembling documents is the most mechanical step.

Each document receives all its fields and their content from the corresponding constraints solution, the proper structure is established in form of nested Python dictionaries and lists.

Here, slightly simplified (from [geneve/events\_emitter.py](../geneve/events_emitter.py))

```python
def events_from_branch(branch, schema, timestamp, meta):
    events = []
    for solution in branch.solve(schema):
        doc = {}
        for field, value in solution:
            if value is not None:
                deep_merge(doc, emit_field(field, value))
        events.append(Event(meta, doc))
    return events
```

Note how a field might have value `None`, meaning that somewhere in the query it was demanded to be absent (eg. `process.pid == null`) and nowhere else the opposite was requested (it would have risen a conflict error), and therefore it's duly excluded from the generated document.

### In action

Check the [Documents generation from test queries](../tests/reports/documents_from_queries.ipynb) report to see some more examples of documents generation.
