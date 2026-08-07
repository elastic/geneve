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

"""
Verify that the GitHub ruleset 'Require CI to pass' contains exactly the set
of jobs that run unconditionally on pull_request in .github/workflows/main.yml.

Required environment variables:
  GITHUB_TOKEN       - token with repo read access
  GITHUB_REPOSITORY  - "owner/repo" (e.g. elastic/geneve)

Options:
  --fix   Update the ruleset to match the workflow instead of just reporting.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

from ruamel.yaml import YAML

WORKFLOW_PATH = Path(__file__).parent.parent / ".github" / "workflows" / "main.yml"
RULESET_NAME = "Require CI to pass"
MATRIX_VAR_RE = re.compile(r"\$\{\{\s*matrix\.(\S+?)\s*\}\}")


def load_workflow(path: Path) -> dict:
    yaml = YAML()
    with path.open() as fh:
        return yaml.load(fh)


def expand_matrix(name_template: str, matrix: dict) -> list[str]:
    """Return all job check-names produced by expanding *matrix* into *name_template*."""
    keys_in_name = set(MATRIX_VAR_RE.findall(name_template))

    # Pure include-style matrix (only key is 'include')
    if list(matrix.keys()) == ["include"]:
        combos = [
            {k: str(v) for k, v in entry.items() if k in keys_in_name}
            for entry in matrix["include"]
        ]
    else:
        # Dimension-style: cartesian product of the list-valued keys
        dim_keys = [k for k in matrix if k not in ("include", "exclude")]
        combos = [
            dict(zip(dim_keys, (str(v) for v in vals)))
            for vals in itertools.product(*[matrix[k] for k in dim_keys])
        ]
        # Additional 'include' entries may introduce extra combinations
        for entry in matrix.get("include", []):
            extra = {k: str(v) for k, v in entry.items()}
            if extra not in combos:
                combos.append(extra)

    names: list[str] = []
    seen: set[str] = set()
    for combo in combos:
        name = name_template
        for var, val in combo.items():
            name = re.sub(
                r"\$\{\{\s*matrix\." + re.escape(var) + r"\s*\}\}",
                val,
                name,
            )
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


def job_runs_on_prs(job: dict) -> bool:
    """Return True if the job runs unconditionally on pull_request events.

    Heuristic: if a job has an ``if:`` condition and that condition does not
    mention ``pull_request``, we assume the job is gated and will not run on
    ordinary PRs (e.g. the 'publish' job which is tag-only).
    """
    if_condition = job.get("if")
    if if_condition is None:
        return True
    return "pull_request" in str(if_condition)


def expected_checks(workflow: dict) -> set[str]:
    checks: set[str] = set()
    for job_id, job in workflow["jobs"].items():
        if not job_runs_on_prs(job):
            continue
        name_template = str(job.get("name", job_id))
        matrix = (job.get("strategy") or {}).get("matrix")
        if matrix:
            checks.update(expand_matrix(name_template, matrix))
        else:
            checks.add(name_template)
    return checks


def github_get(path: str, token: str) -> object:
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode(errors="replace")
        print(f"GitHub API error {exc.code} for GET {path}: {err_body}", file=sys.stderr)
        sys.exit(2)


def github_put(path: str, token: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        data=data,
        method="PUT",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode(errors="replace")
        print(f"GitHub API error {exc.code} for PUT {path}: {err_body}", file=sys.stderr)
        sys.exit(2)


def get_ruleset_detail(repo: str, token: str) -> dict:
    """Fetch the full detail of the named repository ruleset."""
    rulesets = github_get(f"/repos/{repo}/rulesets", token)
    match = next(
        (r for r in rulesets if r["name"] == RULESET_NAME and r.get("source_type") == "Repository"),
        None,
    )
    if match is None:
        print(f"ERROR: no repository ruleset named {RULESET_NAME!r} found in {repo}", file=sys.stderr)
        sys.exit(2)
    return github_get(f"/repos/{repo}/rulesets/{match['id']}", token)


def extract_checks(detail: dict) -> set[str]:
    """Extract the required status check context names from a ruleset detail."""
    for rule in detail.get("rules", []):
        if rule["type"] == "required_status_checks":
            return {c["context"] for c in rule["parameters"]["required_status_checks"]}
    print(f"ERROR: ruleset {RULESET_NAME!r} has no required_status_checks rule", file=sys.stderr)
    sys.exit(2)


def fix_ruleset(repo: str, token: str, detail: dict, expected: set[str]) -> None:
    """Update the ruleset so its required_status_checks exactly matches *expected*."""
    updated_rules = []
    for rule in detail.get("rules", []):
        if rule["type"] == "required_status_checks":
            updated_rules.append({
                "type": "required_status_checks",
                "parameters": {
                    **rule["parameters"],
                    "required_status_checks": [
                        {"context": name} for name in sorted(expected)
                    ],
                },
            })
        else:
            updated_rules.append(rule)

    payload = {
        "name": detail["name"],
        "target": detail.get("target", "branch"),
        "enforcement": detail["enforcement"],
        "conditions": detail["conditions"],
        "bypass_actors": detail.get("bypass_actors", []),
        "rules": updated_rules,
    }
    github_put(f"/repos/{repo}/rulesets/{detail['id']}", token, payload)
    print(f"Ruleset updated: {len(expected)} required checks now in sync with the workflow.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="update the ruleset to match the workflow instead of just reporting",
    )
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        print("ERROR: GITHUB_TOKEN and GITHUB_REPOSITORY must be set", file=sys.stderr)
        sys.exit(2)

    workflow = load_workflow(WORKFLOW_PATH)
    expected = expected_checks(workflow)
    detail = get_ruleset_detail(repo, token)
    actual = extract_checks(detail)

    missing_from_ruleset = expected - actual
    extra_in_ruleset = actual - expected

    if missing_from_ruleset:
        print("Jobs in workflow but MISSING from ruleset:")
        for name in sorted(missing_from_ruleset):
            print(f"  - {name!r}")

    if extra_in_ruleset:
        print("Contexts in ruleset but matching NO workflow job:")
        for name in sorted(extra_in_ruleset):
            print(f"  + {name!r}")

    if missing_from_ruleset or extra_in_ruleset:
        if args.fix:
            fix_ruleset(repo, token, detail, expected)
        else:
            print(
                f"\nFAIL: {len(missing_from_ruleset)} missing from ruleset, "
                f"{len(extra_in_ruleset)} extra in ruleset."
                "\nRun with --fix to update the ruleset automatically."
            )
            sys.exit(1)
    else:
        print(f"OK: {len(actual)} required checks are in sync with the workflow.")


if __name__ == "__main__":
    main()
