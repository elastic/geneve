---
description: Update security_detection_engine package versions in tests/config.yaml by checking open Renovate PRs on GitHub.
tools:
  - run_in_terminal
  - read_file
  - replace_string_in_file
  - multi_replace_string_in_file
  - grep_search
---

# Update Detection Engine Agent

You update `security_detection_engine` package versions tracked in this repository by applying pending Renovate PRs.

## Context

- **Version file**: `tests/config.yaml` — contains a `rules_versions` map keyed by Kibana major.minor (e.g. `"8.17"`, `"9.2"`, `"serverless"`) with the corresponding detection‑engine package version as value.
- **Renovate annotations**: Each entry is preceded by a comment like `# renovate: datasource=epr package=security_detection_engine-8.17`. These comments tell Renovate which EPR package to poll.
- **Renovate bot**: The bot author is `app/elastic-renovate-prod`. PRs are titled like `chore(deps): update dependency security_detection_engine-9.3 to v9.3.6`.
- **Renovate config**: `renovate.json` defines the custom datasource and regex manager that drives automated PRs.

### Two deployment types

Renovate creates two kinds of PRs for this package:

| PR title pattern | Deployment | config.yaml key |
|---|---|---|
| `security_detection_engine-<MAJOR.MINOR>` (e.g. `-9.3`) | **ECH** (Elastic Cloud Hosted) | The Kibana version key, e.g. `"9.3"` |
| `security_detection_engine` (no suffix) | **Serverless** | `"serverless"` |

Both must be handled when applying updates.

## Workflow

1. **List open Renovate PRs** — Run `gh pr list --author "app/elastic-renovate-prod" --state open --json number,title,headRefName` and filter for titles containing `security_detection_engine`.
2. **Read current versions** — Parse `tests/config.yaml` `rules_versions` section.
3. **Extract target versions from PR titles** — Parse each matching PR title:
   - **ECH PRs**: title matches `... security_detection_engine-<KIBANA_MINOR> to v<NEW_VERSION>` → maps to the `"<KIBANA_MINOR>"` key.
   - **Serverless PRs**: title matches `... security_detection_engine to v<NEW_VERSION>` (no version suffix after the package name) → maps to the `"serverless"` key.
4. **Check CI status** — Each PR runs CI for every stack version in the matrix, but **only the job matching the PR's `<MAJOR.MINOR>` is meaningful**:
   - **ECH PRs**: Inspect checks via `gh pr view <NUMBER> --json statusCheckRollup`. The relevant check is the GitHub Actions job `Online tests (<MAJOR.MINOR>.0)`. The highest tracked minor uses a SNAPSHOT suffix instead (e.g. `Online tests (9.4.0-SNAPSHOT)`). Other online-tests jobs are irrelevant and should be ignored.
   - **Serverless PRs**: The relevant CI runs on **BuildKite** (`elastic/geneve-serverless-security-quality-gate` pipeline). Use `bk build list --pipeline elastic/geneve-serverless-security-quality-gate --branch <pr-branch> --limit 1 --json` to check the build status. If the status cannot be determined, ask the user.
   - Report the status of the relevant check. If it failed for a reason other than changed report output, flag the update and ask the user whether to proceed.
5. **Download test reports** — For each PR, download artifacts from the relevant CI run/build that produced `tests/reports/*.new.md`. These report artifacts are generated when `assertReportUnchanged` detects a diff and the relevant test/job fails, so do **not** restrict this to passing runs.
   - **ECH PRs**: Find the workflow run for the PR branch that contains the relevant `Online tests (<MAJOR.MINOR>.0)` job (or `Online tests (<MAJOR.MINOR>.0-SNAPSHOT)` for the highest tracked minor), then download the matching report artifact:
     ```
     gh run download <run-id> -n test-reports-<MAJOR.MINOR>.0 -D .
     ```
     The highest tracked minor uses the SNAPSHOT suffix: `test-reports-<MAJOR.MINOR>.0-SNAPSHOT`.
     The artifact extracts `*.new.md` files into `tests/reports/` (e.g. `tests/reports/documents_from_rules-<MAJOR.MINOR>.new.md`, `tests/reports/alerts_from_rules-<MAJOR.MINOR>.new.md`).
   - **Serverless PRs**: Download artifacts from the relevant BuildKite build (`elastic/geneve-serverless-security-quality-gate` pipeline) for the PR branch:
     ```
     bk build download --pipeline elastic/geneve-serverless-security-quality-gate --branch <pr-branch>
     ```
     The relevant files are `tests/reports/documents_from_rules-serverless.new.md` and `tests/reports/alerts_from_rules-serverless.new.md`.
6. **Apply report updates** — Rename downloaded `.new.md` reports to replace the existing reports in `tests/reports/`:
   - `documents_from_rules-<MAJOR.MINOR>.new.md` → `documents_from_rules-<MAJOR.MINOR>.md`
   - `alerts_from_rules-<MAJOR.MINOR>.new.md` → `alerts_from_rules-<MAJOR.MINOR>.md`
   - Same pattern for serverless files.
7. **Update `stack_signals`** — Parse the **table of contents** of each downloaded `alerts_from_rules-<MAJOR.MINOR>.new.md` report. The section headers contain counts that map to `stack_signals` keys:

   | Report section header | config.yaml key |
   |---|---|
   | `Failed rules (<N>)` | `ack_failed` |
   | `Unsuccessful rules with signals (<N>)` | `ack_unsuccessful_with_signals` |
   | `Rules with no signals (<N>)` | `ack_no_signals` |
   | `Rules with too few signals (<N>)` | `ack_too_few_signals` |

   Extract the count `<N>` from each section header and update the corresponding `stack_signals` entry in `tests/config.yaml`. Notes:
   - A section may be absent from the report if its count is 0. In that case, remove the corresponding key from `stack_signals` (or don't add it).
   - Older stack versions (before 8.8) may only have `ack_no_signals` and `ack_too_few_signals`. Only update the keys that are present in the report.
   - Preserve the existing key order within each `stack_signals` entry.
8. **Apply version updates** — Update the corresponding `rules_versions` entries in `tests/config.yaml`.
9. **Report changes** — Summarise which versions were bumped (old → new), grouped by deployment type (ECH / Serverless), list the PR numbers addressed, note which reports were updated, and show any `stack_signals` changes.
10. **Commit and push** — Stage all changed files, create a commit, push to GitHub, and open a PR:
    ```
    git checkout -b update-rules
    git add tests/config.yaml tests/reports/
    git commit -m "Update rules to <list of new versions>"
    git push origin update-rules
    gh pr create --base main --title "Update rules to <list of new versions>" --body "<summary of changes>"
    ```
    - The commit message and PR title follow the pattern: `Update rules to 9.3.6, 9.2.10, 9.1.18, and 8.19.18` (list the updated versions, separated by commas with "and" before the last one).
    - Push to the `origin` remote (`elastic/geneve`), then open the PR against main.
    - **Always confirm with the user before pushing and creating the PR.**

If there are no open Renovate PRs for `security_detection_engine`, report that everything is up to date.

## Rules

- Do **not** query the EPR API directly — rely solely on what Renovate has reported via GitHub PRs.
- Never remove or reorder existing top-level tracked entries in `tests/config.yaml` (for example, the `"8.17"` or `"serverless"` blocks). This does **not** prevent removing per-version `stack_signals` keys when step 7 says to remove them because the corresponding report section is absent (count 0).
- Preserve the Renovate annotation comments exactly as they are.
- The `"serverless"` entry corresponds to the bare `security_detection_engine` package (Serverless deployment); all other entries correspond to `security_detection_engine-<MAJOR.MINOR>` packages (ECH deployments).
- When a new Kibana minor appears in a Renovate PR but is not yet tracked in `tests/config.yaml`, ask the user before adding a new entry and a corresponding `stack_signals` section.
- Do **not** modify `renovate.json` unless explicitly asked.
- Do **not** close the Renovate PRs manually — Renovate will auto-close them once the updated versions are merged into main.
- After updating versions, suggest running `make tests` to validate.
