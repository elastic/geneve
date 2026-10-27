#!/usr/bin/env python3
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

"""Generate the documents that an ES|QL query returns, and try it out.

Examples:

    python scripts/esql_demo.py 'FROM logs-* | WHERE process.name == "cmd.exe" AND user.id IN ("a", "b")'
    python scripts/esql_demo.py -f query.esql --count 2
    python scripts/esql_demo.py -i                      # type queries, one per line (end with an empty line)
    python scripts/esql_demo.py --es http://localhost:9200 'FROM logs-* | WHERE host.name LIKE "web-*"'

Without --es, only the documents are printed. With --es, they are indexed into a throwaway index of that
Elasticsearch (no Kibana needed) and the query itself is run against it: it must return the documents.
"""

import argparse
import json
import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from geneve import esql
from geneve.events_emitter import SourceEvents
from geneve.utils import load_schema

DEFAULT_SCHEMA = root_dir / "etc" / "ecs-v9.5.0.tar.gz"
SKIP = "(no documents could be generated)"


def generate(schema, query, count):
    """Return the branches of a query, each one is the list of the documents that make it match."""
    se = SourceEvents(schema)
    root = se.add_query(query)
    branches = [[event.doc for event in branch] for branch in se.emit(root, timestamp=True, complete=True, count=count)]
    return branches


def show(branches, limit):
    print(f"{len(branches)} branch(es), each one is a way to match the query\n")
    for i, docs in enumerate(branches[:limit]):
        print(f"--- branch {i}: {len(docs)} document(s)")
        for doc in docs:
            print(json.dumps(doc, indent=2, sort_keys=True))
    if len(branches) > limit:
        print(f"\n... {len(branches) - limit} more branch(es), use --branches to see them")


def check(es, schema, query):
    """Index the documents of each branch and run the query against them, as the validation tests do."""
    from tests import esql_validation as ev

    result = ev.validate_query(es, "demo", query, schema)
    print(f"\nElasticsearch {es.info()['version']['number']}: {result.status} ({result.branches} branch(es)) {result.detail}")
    return result.status == "validated"


def run(schema, query, args, es):
    query = query.strip()
    if not query:
        return True
    try:
        parsed = esql.parse(query)
        print(f"FROM {', '.join(parsed.sources)}")
        branches = generate(schema, query, args.count)
    except Exception as e:  # noqa: BLE001 - say why the query is not supported, whatever it is
        print(f"{type(e).__name__}: {e}")
        return False
    show(branches, args.branches)
    return check(es, schema, query) if es else True


def read_queries(args):
    if args.file:
        yield Path(args.file).read_text()
    elif args.query:
        yield args.query
    elif args.interactive:
        print("ES|QL query, end it with an empty line, ^D to quit")
        while True:
            lines = []
            try:
                while True:
                    line = input("esql> " if not lines else "  ... ")
                    if not line:
                        break
                    lines.append(line)
            except EOFError:
                if lines:
                    yield "\n".join(lines)
                return
            yield "\n".join(lines)
    else:
        yield sys.stdin.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("query", nargs="?", help="the ES|QL query, if neither this nor -f nor -i, it is read from stdin")
    parser.add_argument("-f", "--file", help="read the query from a file")
    parser.add_argument("-i", "--interactive", action="store_true", help="read queries until ^D")
    parser.add_argument("-c", "--count", type=int, default=1, help="documents per branch for queries that do not aggregate")
    parser.add_argument("-b", "--branches", type=int, default=5, help="how many branches to print")
    parser.add_argument("--schema", default=str(DEFAULT_SCHEMA), help="ECS archive, default: %(default)s")
    parser.add_argument("--es", help="Elasticsearch url to check the documents against, eg. http://localhost:9200")
    args = parser.parse_args()

    schema = load_schema(args.schema, "generated/ecs/ecs_flat.yml", root_dir)
    es = None
    if args.es:
        from elasticsearch import Elasticsearch

        es = Elasticsearch(args.es, request_timeout=60)
        if not es.ping():
            sys.exit(f"Could not reach Elasticsearch: {args.es}")

    results = [run(schema, query, args, es) for query in read_queries(args)]  # all of them, not until the first failure
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
