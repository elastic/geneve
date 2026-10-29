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

"""Check the documents generated for ES|QL queries against Elasticsearch itself.

The query is its own oracle: the documents generated for each branch of it are indexed and the very same query
is run, it must return them. Only Elasticsearch is needed, not Kibana.
"""

import re
from collections import namedtuple
from fnmatch import fnmatchcase

from geneve import esql
from geneve.events_emitter import SourceEvents, emit_mappings
from geneve.utils import deep_merge

TEMPLATE = "geneve-esql-validation"
UNKNOWN_COLUMN = re.compile(r"Unknown column \[([^\]]+)\]")
NO_MATCH = re.compile(r"No matches found for pattern \[([^\]]+)\]")
MAX_ATTEMPTS = 8
CHUNK = 500  # documents indexed and checked at once
MAX_GROUPS = 1000  # branches of a query that aggregates that are checked, one by one
MAX_ROWS = 10000  # ES|QL does not return more

# status is one of "validated", "failed" (the query did not return the documents), "error" (the query was
# refused), "skipped" (no documents can be generated, why is in `detail`)
# `groups` is how many groups of documents of the query (STATS) were run out of how many there are, `None` if the query has no groups
Result = namedtuple("Result", ["name", "status", "branches", "detail", "groups"], defaults=(None,))


def pick_index(sources):
    """Return an index name that the FROM of a query would read."""
    includes = [s for s in sources if not s.startswith("-")]
    excludes = [s[1:] for s in sources if s.startswith("-")]
    for pattern in includes:
        if ":" in pattern or "<" in pattern:
            continue  # remote clusters and date math
        name = pattern.replace("*", "geneve").lower()
        if not any(fnmatchcase(name, exclude) for exclude in excludes):
            return name
    raise NotImplementedError(f"No local index in FROM: {', '.join(sources)}")


def flatten(doc, path=()):
    for key, value in doc.items():
        if isinstance(value, dict):
            yield from flatten(value, path + (key,))
        else:
            yield ".".join(path + (key,)), value


def value_type(value):
    if isinstance(value, list):
        value = next((v for v in value if v is not None), None)
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "long"
    if isinstance(value, float):
        return "double"
    return "keyword"


def infer_mappings(mappings, docs, schema):
    """Type the fields that the schema does not know (those of the integrations) after their generated values."""
    inferred = {}
    for doc in docs:
        for path, value in flatten(doc):
            parts = path.split(".")
            # what hangs from a field that the schema knows is the field (a geo_point is an object with lat and lon)
            known = any(".".join(parts[:i]) in schema for i in range(1, len(parts) + 1))
            if not known and path != "@timestamp":
                inferred[path] = {"type": value_type(value)}
    deep_merge(mappings, {"properties": emit_mappings(list(inferred), inferred).get("properties", {})}, overwrite=True)
    return mappings


def index_documents(es, index, mappings, docs):
    es.options(ignore_status=404).indices.delete(index=index)
    es.indices.put_index_template(name=TEMPLATE, index_patterns=[index], priority=600, template={"mappings": mappings})
    es.indices.create(index=index)
    operations = []
    for doc in docs:
        operations.append({"index": {"_index": index}})
        operations.append(doc)
    response = es.bulk(operations=operations, refresh=True)
    if response["errors"]:
        errors = [item["index"]["error"] for item in response["items"] if "error" in item["index"]]
        raise RuntimeError(f"Indexing failed: {errors[0]}")


def run_documents(es, index, mappings, docs, query):
    """Index the documents and run the query. Return (rows, error)."""
    mappings.setdefault("properties", {})
    for _ in range(MAX_ATTEMPTS):
        index_documents(es, index, mappings, docs)
        try:
            response = es.esql.query(query=f"{query}\n| LIMIT {MAX_ROWS}")
        except Exception as e:  # noqa: BLE001
            body = getattr(e, "body", None)
            message = str(body if body else e)
            # the index only has the fields of the constraints, the query may name others in KEEP or so
            missing = UNKNOWN_COLUMN.findall(message) + [p.replace("*", "geneve_validation") for p in NO_MATCH.findall(message)]
            if not missing:
                return None, message
            deep_merge(mappings, {"properties": emit_mappings(missing, {}).get("properties", {})})
            continue
        return len(response["values"]), None
    return None, f"Unknown columns after {MAX_ATTEMPTS} attempts"


def validate_query(es, name, query, schema, stack_version=None, rule=None):
    """Generate documents for a query and check the query against them."""
    try:
        parsed = esql.parse(query)
        index = pick_index(parsed.sources)
        se = SourceEvents(schema)
        se.stack_version = stack_version
        root = se.add_rule(rule) if rule is not None else se.add_query(query)
        branches = [[event.doc for event in branch] for branch in se.emit(root, timestamp=True, complete=True, count=1)]
        mappings = infer_mappings(se.mappings(root), [doc for docs in branches for doc in docs], schema)
        for docs in branches:
            for doc in docs:
                # what an EVAL makes is for the query to make, not for the documents to have
                made = [path for path, _ in flatten(doc) if path in parsed.aliases]
                if made:
                    return Result(name, "failed", len(branches), f"the documents have {made[0]}, which an EVAL makes")
    except Exception as e:  # noqa: BLE001
        return Result(name, "skipped", 0, f"{type(e).__name__}: {e}".splitlines()[0][:160])

    try:
        if parsed.stats is not None:
            # a group of documents is one row of the result: the groups of a branch are checked by themselves,
            # the other branches could add to them (the BY of the query may be the same for all)
            step = max(1, -(-len(branches) // MAX_GROUPS))
            checked = range(0, len(branches), step)
            groups = (len(checked), len(branches))
            for i in checked:
                rows, error = run_documents(es, index, mappings, branches[i], query)
                if error:
                    return Result(name, "error", len(branches), f"branch {i}: {error[:300]}", groups)
                if not rows:
                    return Result(name, "failed", len(branches), f"branch {i}: no rows for {branches[i]}", groups)
            return Result(name, "validated", len(branches), "", groups)
        # each document is expected to be returned once: all together, only one by one to say which one is not
        documents = [(i, doc) for i, docs in enumerate(branches) for doc in docs]
        for start in range(0, len(documents), CHUNK):
            chunk = documents[start : start + CHUNK]
            rows, error = run_documents(es, index, mappings, [doc for _, doc in chunk], query)
            if error:
                return Result(name, "error", len(branches), error[:300])
            if rows == len(chunk):
                continue
            for i, doc in chunk:
                rows, error = run_documents(es, index, mappings, [doc], query)
                if error:
                    return Result(name, "error", len(branches), f"branch {i}: {error[:300]}")
                if not rows:
                    return Result(name, "failed", len(branches), f"branch {i}: no rows for {doc}")
            return Result(name, "failed", len(branches), f"{rows} rows were returned for {len(chunk)} documents")
    except Exception as e:  # noqa: BLE001
        # what Elasticsearch refuses of the index (the mappings) is a result too
        body = getattr(e, "body", None)
        return Result(name, "error", len(branches), f"{type(e).__name__}: {body if body else e}"[:300])
    finally:
        es.options(ignore_status=404).indices.delete(index=index)
        es.options(ignore_status=404).indices.delete_index_template(name=TEMPLATE)
    return Result(name, "validated", len(branches), "")


def groups_of(result):
    """Say how many groups of a query that aggregates were run, all of them or only some."""
    if result.groups is None:
        return ""
    checked, total = result.groups
    return f", all {total} group(s) run" if checked == total else f", {checked} of {total} groups run"


def render_report(title, version, results):
    counts = {status: sum(1 for r in results if r.status == status) for status in ("validated", "failed", "error", "skipped")}
    lines = [
        f"# {title}",
        "",
        "Documents generated for ES|QL are indexed and the query itself is run against Elasticsearch, it must return them.",
        "This is what is checked for each branch of the query. Only what Geneve generates documents for is listed",
        "as validated, failed or error; the rest is skipped and the reason is the one of the documents report.",
        "",
        "A query that aggregates (STATS) returns a row for each group of documents, which is a branch of the query.",
        f"Every group is run, unless the query has more than {MAX_GROUPS} of them: then evenly spaced ones are, and how many is said.",
        "",
        f"Elasticsearch version: {version}",
        "",
        "| validated | failed | error | skipped |",
        "|---|---|---|---|",
        "| {validated} | {failed} | {error} | {skipped} |".format(**counts),
        "",
    ]
    for status, heading in (("validated", "Validated"), ("failed", "Failed"), ("error", "Refused by Elasticsearch")):
        selected = sorted((r for r in results if r.status == status), key=lambda r: r.name)
        if not selected:
            continue
        lines += [f"## {heading} ({len(selected)})", ""]
        for r in selected:
            suffix = f", {r.branches} branch(es){groups_of(r)}" if status == "validated" else f": {r.detail}"
            lines.append(f"* {r.name}{suffix}")
        lines.append("")
    skipped = {}
    for r in results:
        if r.status == "skipped":
            skipped.setdefault(r.detail, []).append(r.name)
    if skipped:
        lines += [f"## Skipped ({counts['skipped']})", ""]
        for detail, names in sorted(skipped.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            lines.append(f"* {len(names)} x {detail}")
        lines.append("")
    return "\n".join(lines)
