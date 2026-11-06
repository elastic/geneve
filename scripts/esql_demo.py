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
    python scripts/esql_demo.py --list                  # the built-in examples
    python scripts/esql_demo.py -e 6 -e 12              # run some of them (--example all runs every one)
    python scripts/esql_demo.py -e all --es http://localhost:9200 -b 1

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

# what is supported and what is not (the last ones), as the rules use it: (title, query)
EXAMPLES = (
    ("Equality and comparison", 'FROM logs-* | WHERE process.name == "regsvr32.exe" AND process.pid > 1024'),
    ("IN: a branch for each value", 'FROM logs-* | WHERE process.name IN ("cmd.exe", "powershell.exe", "bash")'),
    ("OR: a branch for each side", 'FROM logs-* | WHERE process.name == "a.exe" OR source.port < 1024'),
    ("LIKE: the wildcards are filled in", 'FROM logs-* | WHERE process.name LIKE "FOO*" AND file.path LIKE "/home/*/.ssh/?d_*"'),
    ("STARTS_WITH and ENDS_WITH", 'FROM logs-* | WHERE STARTS_WITH(process.command_line, "curl ") AND ENDS_WITH(file.name, ".sh")'),
    (
        "RLIKE: a string is made out of the regular expression",
        r'FROM logs-* | WHERE process.name RLIKE """(cmd|powershell)\.exe""" AND user.id RLIKE """[0-9]{3}-[a-z]+"""',
    ),
    ("NOT RLIKE: a string that does not match", r'FROM logs-* | WHERE process.name NOT RLIKE """(cmd|powershell)\.exe"""'),
    (
        "TO_LOWER: what the field is, whatever its case",
        'FROM logs-* | WHERE TO_LOWER(user_agent.original) LIKE "*curl*" AND TO_LOWER(process.name) IN ("cmd.exe", "bash")',
    ),
    ("TO_STRING of an ip", 'FROM logs-* | WHERE TO_STRING(source.ip) IN ("127.0.0.1", "::1")'),
    ("CIDR_MATCH", 'FROM logs-* | WHERE CIDR_MATCH(source.ip, "10.0.0.0/8", "192.168.0.0/16") AND user.name IS NOT NULL'),
    ("IS NULL and NOT", 'FROM logs-* | WHERE process.parent.name IS NULL AND NOT process.name == "a.exe"'),
    ("KQL() inside ES|QL", 'FROM logs-* | WHERE KQL("process.name: (cmd.exe or powershell.exe) and event.category: process")'),
    ("An EVAL alias that is a field", 'FROM logs-* | EVAL ua = TO_LOWER(user_agent.original) | WHERE ua LIKE "*fasthttp*"'),
    ("STATS: a group of documents", "FROM logs-* | STATS c = COUNT(*) BY host.id | WHERE c >= 5"),
    (
        "STATS: different values and a key",
        "FROM logs-* | WHERE event.action IS NOT NULL | STATS d = COUNT_DISTINCT(user.name), c = COUNT(*) BY host.id, source.ip | WHERE d >= 3 AND c >= 3",
    ),
    (
        "A rule-like query: METADATA, comments, KEEP, SORT",
        """FROM logs-endpoint.events.process-* METADATA _id
// programs started from a temporary folder
| WHERE host.os.type == "linux" AND event.type == "start"
    AND process.executable LIKE "/tmp/*" AND NOT process.parent.name IN ("cron", "systemd")
| KEEP @timestamp, host.name, process.executable
| SORT @timestamp DESC""",
    ),
    ("Not supported: the anchor of a regular expression", 'FROM logs-* | WHERE process.name RLIKE "^cmd"'),
    ("Not supported: it could never be true", 'FROM logs-* | WHERE TO_LOWER(process.name) == "CMD.EXE"'),
    ("Not supported: what CASE makes", 'FROM logs-* | EVAL k = CASE(process.pid > 10, "a", "b") | WHERE k == "a"'),
)
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
    if len(branches) > limit > 0:
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


def examples_to_run(selection):
    """Return the numbers (from 1) of the examples that were asked for, `all` is every one."""
    if "all" in selection:
        return range(1, len(EXAMPLES) + 1)
    numbers = []
    for item in selection:
        if not item.isdigit() or not 1 <= int(item) <= len(EXAMPLES):
            sys.exit(f"There is no example {item!r}, see --list")
        numbers.append(int(item))
    return numbers


def list_examples():
    for number, (title, query) in enumerate(EXAMPLES, 1):
        print(f"{number:2}. {title}")
        for line in query.splitlines():
            print(f"      {line}")


def read_queries(args):
    if args.example:
        for number in examples_to_run(args.example):
            title, query = EXAMPLES[number - 1]
            print(f"\n{'=' * 100}\n{number}. {title}\n\n{query}\n")
            yield query
    elif args.file:
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
    parser.add_argument("-l", "--list", action="store_true", help="list the examples")
    parser.add_argument(
        "-e", "--example", action="append", metavar="N", help="run an example (a number of --list, or all), can be repeated"
    )
    parser.add_argument("query", nargs="?", help="the ES|QL query, if neither this nor -f nor -i, it is read from stdin")
    parser.add_argument("-f", "--file", help="read the query from a file")
    parser.add_argument("-i", "--interactive", action="store_true", help="read queries until ^D")
    parser.add_argument("-c", "--count", type=int, default=1, help="documents per branch for queries that do not aggregate")
    parser.add_argument("-b", "--branches", type=int, default=5, help="how many branches to print")
    parser.add_argument("--schema", default=str(DEFAULT_SCHEMA), help="ECS archive, default: %(default)s")
    parser.add_argument("--es", help="Elasticsearch url to check the documents against, eg. http://localhost:9200")
    args = parser.parse_args()
    if args.list:
        list_examples()
        return

    schema = load_schema(args.schema, "generated/ecs/ecs_flat.yml", root_dir)
    es = None
    if args.es:
        from elasticsearch import Elasticsearch

        es = Elasticsearch(args.es, request_timeout=60)
        if not es.ping():
            sys.exit(f"Could not reach Elasticsearch: {args.es}")

    results = [run(schema, query, args, es) for query in read_queries(args)]  # all of them, not until the first failure
    if args.example:
        # the examples that say that they are not supported are expected to fail
        numbers = examples_to_run(args.example)
        sys.exit(0 if all(ok != EXAMPLES[number - 1][0].startswith("Not supported") for number, ok in zip(numbers, results)) else 1)
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
