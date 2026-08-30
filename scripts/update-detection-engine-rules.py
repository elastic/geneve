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
Update the security_detection_engine package versions tracked in
tests/config.yaml by applying the pending Renovate PRs.

This script discovers open Renovate PRs for updates to the pre-built rules,
checks the relevant CI/build status, downloads the test report artifacts,
applies the report and signals updates, bumps the ruled versions, and
(optionally) commits and opens a PR.

By default the script runs in dry-run mode: it prints what it would do and
makes no changes. Pass --apply to perform the edits and git operations.
See the README in .github/agents/update-detection-engine-rules.agent.md for
the full workflow description.

Options:
  --apply         Perform the edits and git operations (default is dry-run).
  --yes           Auto-approve the judgment checkpoints (CI failures, new
                  untracked minor, and the final push/PR confirmation).
  --no-push       Commit locally but do not push or open a PR.
  --branch NAME   Branch to create and push (default: update-rules).

Required tooling (must be installed and authenticated):
  gh  - GitHub CLI, with access to elastic/geneve and app/elastic-renovate-prod.
  bk  - Buildkite CLI, with access to the serverless quality gate pipeline.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ruamel.yaml import YAML

ROOT = Path(__file__).parent.parent
CONFIG_PATH = ROOT / "tests" / "config.yaml"
REPORTS_DIR = ROOT / "tests" / "reports"

RENOVATE_AUTHOR = "app/elastic-renovate-prod"
SERVERLESS_PIPELINE = "elastic/geneve-serverless-security-quality-gate"

# Match the "to v<version>" suffix appearing in a Renovate PR title.
TITLE_VERSION_RE = re.compile(r"\bto v(?P<version>\d+\.\d+\.\d+(?:[-\w.]*))")

# Match the canonical report filename wherever it appears (Buildkite prefixes
# downloaded artifact files with 'artifact-<uuid>-'; the GitHub action does not).
REPORT_NAME_RE = re.compile(r"(?P<name>(?:documents|alerts)_from_rules-[^/]+\.new\.md)$")

# The alert report table-of-contents section headers that map to
# stack_signals keys, in the report's natural order.
STACK_SIGNAL_SECTIONS = [
    ("Failed rules", "ack_failed"),
    ("Unsuccessful rules with signals", "ack_unsuccessful_with_signals"),
    ("Rules with no signals", "ack_no_signals"),
    ("Rules with too few signals", "ack_too_few_signals"),
]

_cmd_cache: dict = {}


@dataclass
class RenovatePR:
    number: int
    title: str
    head_ref: str
    deployment: str  # "ech" or "serverless"
    minor: str | None  # MAJOR.MINOR for ECH, None for serverless
    new_version: str


@dataclass
class WorkItem:
    pr: RenovatePR
    old_version: str | None
    new_version: str
    ci_status: str = "unknown"
    report_new_files: list[Path] = field(default_factory=list)
    report_renames: list[tuple[Path, Path]] = field(default_factory=list)
    stack_signals: dict[str, int] = field(default_factory=dict)


def run_cmd(args, *, check: bool = True, text: bool = True) -> str:
    """Run an external command and return its stdout."""
    key = tuple(args)
    if key in _cmd_cache:
        return _cmd_cache[key]
    proc = subprocess.run(args, capture_output=True, text=text, check=False)
    if check and proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip() or "unknown error"
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(args)}\n{err}")
    out = proc.stdout
    _cmd_cache[key] = out
    return out


def run_cmd_json(args, *, check: bool = True):
    out = run_cmd(args, check=check)
    try:
        return json.loads(out) if out.strip() else None
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise RuntimeError(f"invalid JSON from {' '.join(args)}: {exc}\n{out}") from exc


def confirm(prompt: str, yes: bool) -> bool:
    """Prompt the user for a yes/no decision unless --yes was given."""
    if yes:
        return True
    while True:
        answer = input(f"{prompt} [y/N] ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("", "n", "no"):
            return False
        print("Please answer y or n.")


def load_config():
    yaml = YAML()
    yaml.preserve_quotes = True
    with CONFIG_PATH.open() as fh:
        return yaml.load(fh)


def save_config(data) -> None:
    yaml = YAML()
    yaml.preserve_quotes = True
    with CONFIG_PATH.open("w") as fh:
        yaml.dump(data, fh)


def read_rules_versions() -> dict:
    return load_config()["emitter_rules"]["rules_versions"]


def parse_renovate_prs() -> list[RenovatePR]:
    """Discover open Renovate PRs for security_detection_engine."""
    prs_json = run_cmd_json(
        [
            "gh",
            "pr",
            "list",
            "--author",
            RENOVATE_AUTHOR,
            "--state",
            "open",
            "--json",
            "number,title,headRefName",
        ]
    )
    prs: list[RenovatePR] = []
    for entry in prs_json or []:
        title = entry["title"]
        if "security_detection_engine" not in title:
            continue
        vm = TITLE_VERSION_RE.search(title)
        if not vm:
            continue
        new_version = vm.group("version")
        m = re.search(r"security_detection_engine-(\d+\.\d+)", title)
        if m:
            deployment, minor = "ech", m.group(1)
        elif re.search(r"security_detection_engine\b", title):
            deployment, minor = "serverless", None
        else:
            continue
        prs.append(
            RenovatePR(
                number=entry["number"],
                title=title,
                head_ref=entry["headRefName"],
                deployment=deployment,
                minor=minor,
                new_version=new_version,
            )
        )
    return prs


def highest_tracked_minor(rules_versions: dict) -> str | None:
    """Return the highest MAJOR.MINOR tracked in rules_versions (excluding serverless)."""
    minors = [m for m in rules_versions if m != "serverless"]
    if not minors:
        return None
    return max(minors, key=lambda m: tuple(int(p) for p in m.split(".")))


def ech_job_artifact(minor: str, highest_minor: str) -> tuple[str, str]:
    """Return (job_name, artifact_suffix) for an ECH PR's online-tests run.

    The highest tracked minor runs against a SNAPSHOT stack (e.g.
    'Online tests (9.6.0-SNAPSHOT)'); all others run against the released
    minor (e.g. 'Online tests (9.3.0)').
    """
    snapshot = "-SNAPSHOT" if minor == highest_minor else ""
    return f"Online tests ({minor}.0{snapshot})", f"test-reports-{minor}.0{snapshot}"


def check_github_status(pr: RenovatePR, highest_minor: str) -> str:
    """Return the status of the relevant GitHub Actions job for an ECH PR."""
    rollup = run_cmd_json(["gh", "pr", "view", str(pr.number), "--json", "statusCheckRollup"])
    job_name, _ = ech_job_artifact(pr.minor, highest_minor)
    for check in rollup.get("statusCheckRollup", []) or []:
        name = check.get("name") or check.get("context")
        if name == job_name:
            return check.get("conclusion") or check.get("status") or "unknown"
    return "unknown"


def check_buildkite_status(pr: RenovatePR) -> str:
    """Return the status of the serverless quality gate build for a PR branch."""
    builds = run_cmd_json(
        [
            "bk",
            "build",
            "list",
            "--pipeline",
            SERVERLESS_PIPELINE,
            "--branch",
            pr.head_ref,
            "--limit",
            "1",
            "--json",
        ]
    )
    if not builds:
        return "unknown"
    return builds[0].get("state") or builds[0].get("status") or "unknown"


def is_failed_status(status: str) -> bool:
    """Return whether a CI/build status is a definite failure.

    Statuses come from different sources with mixed casing: GitHub reports
    uppercase conclusions ('FAILURE'), Buildkite reports lowercase states
    ('failed'). Treat only explicit failure-like states as failed; anything
    unknown, in-progress, or skipped is not treated as a report-output change.
    """
    return status.lower() in {
        "failure",
        "failed",
        "canceled",
        "cancelled",
        "timed_out",
        "timeout",
        "error",
        "action_required",
        "startup_failure",
    }


def _canonical_report(path: Path) -> Path | None:
    """Return the canonical report filename for a downloaded artifact file."""
    m = REPORT_NAME_RE.search(path.name)
    return Path(m.group("name")) if m else None


def download_github_reports(pr: RenovatePR, highest_minor: str) -> list[tuple[Path, Path | None]]:
    """Download the ECH report artifacts for a PR into a temp dir.

    Downloads from the current workflow run for the relevant job. Ongoing runs
    have not published their artifact yet, so a 'no artifact' download failure
    is expected and returns an empty list (the caller reports the PR as not yet
    ready rather than as a real failure).
    """
    rollup = run_cmd_json(["gh", "pr", "view", str(pr.number), "--json", "statusCheckRollup"])
    job_name, artifact = ech_job_artifact(pr.minor, highest_minor)
    run_id = None
    for check in rollup.get("statusCheckRollup", []) or []:
        if check.get("name") == job_name:
            run_id = check.get("detailsUrl") or check.get("url")
            if run_id:
                m = re.search(r"actions/runs/(\d+)", run_id)
                run_id = m.group(1) if m else None
            break
    if not run_id:
        return []
    tmp = Path(tempfile.mkdtemp(prefix="geneve-reports-"))
    proc = subprocess.run(
        ["gh", "run", "download", run_id, "-n", artifact, "-D", str(tmp)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return []
    return [(p, _canonical_report(p)) for p in tmp.rglob("*.new.md")]


def _matching_build_number(head_ref: str, new_version: str) -> str | None:
    """Return the serverless QG build running the renovate bump to ``new_version``.

    ``bk build download --branch`` may resolve to an older build on the
    renovate branch, so select the build whose bump message matches the target
    version first and download that build's artifacts by number.
    """
    builds = run_cmd_json(
        [
            "bk",
            "build",
            "list",
            "--pipeline",
            SERVERLESS_PIPELINE,
            "--branch",
            head_ref,
            "--limit",
            "100",
            "--json",
        ]
    )
    pattern = re.compile(rf"to v{re.escape(new_version)}(?![\d.])")
    for build in builds or []:
        if pattern.search(build.get("message") or ""):
            return str(build.get("number"))
    return None


def download_buildkite_reports(pr: RenovatePR) -> list[tuple[Path, Path | None]]:
    """Download the serverless report artifacts for a PR into a temp dir."""
    build_number = _matching_build_number(pr.head_ref, pr.new_version)
    if not build_number:
        return []
    tmp = Path(tempfile.mkdtemp(prefix="geneve-reports-"))
    subprocess.run(
        ["bk", "build", "download", build_number, "--pipeline", SERVERLESS_PIPELINE],
        cwd=tmp,
        capture_output=True,
        text=True,
        check=False,
    )
    return [(p, _canonical_report(p)) for p in tmp.rglob("*.new.md")]


def parse_stack_signals(new_report: Path) -> dict[str, int]:
    """Extract the stack_signals counts from an alert report's table of contents."""
    text = new_report.read_text()
    counts: dict[str, int] = {}
    for header, key in STACK_SIGNAL_SECTIONS:
        m = re.search(rf"\[{re.escape(header)}\s*\((\d+)\)\]", text)
        if m:
            counts[key] = int(m.group(1))
    return counts


def _display_sort_key(item: WorkItem):
    """Sort Serverless first, then ECH minors by decreasing semver."""
    if item.pr.deployment == "serverless":
        return (0, ())
    return (1, tuple(-int(p) for p in item.pr.minor.split(".")))


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--apply", action="store_true", help="perform edits and git operations")
    parser.add_argument("--yes", action="store_true", help="auto-approve judgment checkpoints")
    parser.add_argument("--no-push", action="store_true", help="commit locally, do not push or open a PR")
    parser.add_argument("--branch", default="update-rules", help="branch name to create/push")
    args = parser.parse_args()

    prs = parse_renovate_prs()
    if not prs:
        print("Everything is up to date: no open security_detection_engine Renovate PRs.")
        return

    rulers = read_rules_versions()
    highest_minor = highest_tracked_minor(rulers)

    items: list[WorkItem] = []
    skipped: list[str] = []

    for pr in prs:
        key = pr.minor if pr.deployment == "ech" else "serverless"
        old_version = rulers.get(key)
        new_version = pr.new_version
        if (
            old_version is None
            and key != "serverless"
            and not confirm(
                f"PR #{pr.number} tracks new Kibana minor '{key}' not in tests/config.yaml. Add it?",
                args.yes,
            )
        ):
            # Newly tracked minor declined: needs a new entry + stack_signals section.
            skipped.append(f"{key} ({pr.title})")
            continue
        if old_version == new_version:
            print(f"PR #{pr.number}: {key} already at {new_version}; skipping.")
            continue
        items.append(WorkItem(pr=pr, old_version=old_version, new_version=new_version))

    if not items:
        print("No version updates to apply.")
        return

    # Check the relevant CI/build status and download reports.
    for item in items:
        if item.pr.deployment == "ech":
            item.ci_status = check_github_status(item.pr, highest_minor)
            files = download_github_reports(item.pr, highest_minor)
        else:
            item.ci_status = check_buildkite_status(item.pr)
            files = download_buildkite_reports(item.pr)
        for src, canonical in files:
            if canonical is None:
                continue
            if canonical.name.startswith("alerts_from_rules"):
                item.stack_signals = parse_stack_signals(src)
            if args.apply:
                staged = REPORTS_DIR / canonical.name
                shutil.copyfile(src, staged)
                item.report_new_files.append(staged)
            else:
                item.report_new_files.append(canonical)

    # Build the report rename mapping (the staged .new.md files), per item.
    for item in items:
        for new in item.report_new_files:
            if new.name.endswith(".new.md"):
                dst = REPORTS_DIR / (new.name[: -len(".new.md")] + ".md")
                item.report_renames.append((new, dst))

    # ---- Print the plan ----
    for item in sorted(items, key=_display_sort_key):
        depl = "ECH" if item.pr.deployment == "ech" else "Serverless"
        old = item.old_version or "(new)"
        print(f"[{depl}] {item.pr.minor or 'serverless'}: {old} -> {item.new_version} " f"(PR #{item.pr.number}, ci={item.ci_status})")
        if item.stack_signals:
            print(f"    stack_signals: {item.stack_signals}")
        if is_failed_status(item.ci_status):
            if item.report_renames:
                print("    (expected: report output changed, artifacts produced)")
            else:
                print("    WARNING: CI failed but produced no report artifacts - possible genuine failure")
        elif not item.report_renames:
            print("    (report not available yet)")

    if skipped:
        print("\nSkipped (not yet tracked / declined):")
        for s in skipped:
            print(f"  - {s}")

    # A job failing with no report artifacts is a genuine failure; the user
    # must confirm before proceeding. Failing jobs that DID produce report
    # artifacts are the expected signal for a rules update (the failure is how
    # the .new.md report is generated) and need no confirmation.
    failed = [item for item in items if is_failed_status(item.ci_status) and not item.report_renames]
    if failed and not args.apply:
        for item in failed:
            print(f"\nWARNING: PR #{item.pr.number} ({item.ci_status}) CI failed with no report artifacts.")

    if not args.apply:
        print("\nDry-run: no changes made. Re-run with --apply to apply.")
        return

    if failed and not confirm(
        "One or more relevant CI checks failed without producing report artifacts. Proceed anyway?",
        args.yes,
    ):
        return

    if not confirm("Apply the changes above (edit tests/config.yaml and tests/reports/)?", args.yes):
        return

    data = load_config()
    rules = data["emitter_rules"]["rules_versions"]
    signals = data["emitter_rules"]["stack_signals"]

    for item in items:
        key = item.pr.minor if item.pr.deployment == "ech" else "serverless"
        rules[key] = item.new_version
        if item.stack_signals:
            existing = signals.get(key)
            if existing is None:
                signals[key] = {}
                existing = signals[key]
            for k, v in item.stack_signals.items():
                existing[k] = v
            # Remove keys whose section is absent (count 0), preserving order.
            present = set(item.stack_signals)
            for k in list(existing):
                if k.startswith("ack_") and k not in present:
                    del existing[k]

    for item in items:
        for new, dst in item.report_renames:
            new.replace(dst)

    save_config(data)

    print("Applied config and report updates.")

    # ---- Commit and push ----
    ordered = sorted(items, key=_display_sort_key)
    new_versions = [i.new_version for i in ordered]
    subject = human_list("Update rules to ", new_versions)
    run_cmd(["git", "checkout", "-b", args.branch])
    run_cmd(["git", "add", "tests/config.yaml", "tests/reports/"])
    run_cmd(["git", "commit", "-m", subject])
    if not args.no_push:
        if not confirm(f"Push branch '{args.branch}' and open a PR against main?", args.yes):
            print("Committed locally; not pushing (push aborted).")
            return
        run_cmd(["git", "push", "origin", args.branch])
        pr_url = run_cmd(
            [
                "gh",
                "pr",
                "create",
                "--base",
                "main",
                "--title",
                subject,
                "--body",
                _pr_body(ordered),
            ]
        ).strip()
        print(f"PR created: {pr_url}")


def human_list(prefix, values):
    if len(values) == 1:
        return prefix + values[0]
    return prefix + ", ".join(values[:-1]) + ", and " + values[-1]


def _pr_body(items: list[WorkItem]) -> str:
    """Build the PR body grouped by deployment type with old -> new versions."""
    lines: list[str] = []
    sections: list[tuple[str, list[WorkItem]]] = [
        ("ECH", [i for i in items if i.pr.deployment == "ech"]),
        ("Serverless", [i for i in items if i.pr.deployment == "serverless"]),
    ]
    for heading, section in sections:
        if not section:
            continue
        if lines:
            lines.append("")
        lines.append(f"{heading}:")
        for item in section:
            label = item.pr.minor or "serverless"
            old = item.old_version or "new"
            lines.append(f"- {label}: {old} -> {item.new_version} (PR #{item.pr.number})")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
