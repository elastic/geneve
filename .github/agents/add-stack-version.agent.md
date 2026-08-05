---
description: Add a new Elastic stack version to the test drill — promote the current CI SNAPSHOT to GA, introduce the next SNAPSHOT, update all config and infra files, seed initial reports, and open a draft PR.
tools:
  - run_in_terminal
  - read_file
  - replace_string_in_file
  - multi_replace_string_in_file
  - grep_search
---

# Add Stack Version Agent

You add a new Elastic stack version to the geneve test drill.

## Context

- **CI matrix**: `.github/workflows/main.yml` — the `online-tests` job contains a `matrix.include` list of `{stack-version, schema-uri}` pairs. Exactly one entry is a SNAPSHOT (e.g. `9.5.0-SNAPSHOT`); all others are GA releases. The `schema-uri` for each entry is `./etc/ecs-v{TAG}.tar.gz` where `{TAG}` is the highest ECS release tag present in `etc/` whose version is ≤ the stack version.
- **Version config**: `tests/config.yaml` — two relevant sections under `emitter_rules`:
  - `rules_versions`: maps Kibana major.minor (e.g. `"9.5"`) → detection engine package version, each preceded by a `# renovate:` annotation.
  - `stack_signals`: maps Kibana major.minor → expected signal counts used by online CI. Values for new versions are placeholders copied from the previous version; the `update-detection-engine-rules` agent corrects them once online CI has run.
- **ECS tarballs**: `etc/ecs-v{TAG}.tar.gz` — GitHub source archives of the `elastic/ecs` repository, saved from `https://github.com/elastic/ecs/archive/refs/tags/{TAG}.tar.gz`. Only GA releases are downloaded; never attempt to download a tarball for an unreleased (SNAPSHOT) version.
- **Reports**: `tests/reports/alerts_from_rules-{X.Y}.md` and `documents_from_rules-{X.Y}.md` — static report files keyed by major.minor only (no SNAPSHOT notation). Missing reports are always seeded by copying from the greatest version that already has them.
- **Infra files**: `docker-compose.yml` (all `TEST_STACK_VERSION:-{X.Y}.Z` default image references — ES nodes and Kibana) and `scripts/test-stacks.sh` (`DEFAULT_STACK_VERSIONS` space-separated list for local testing).

## Workflow

### 1. Read current state

- Read `.github/workflows/main.yml`: note the current SNAPSHOT entry (e.g. `9.5.0-SNAPSHOT`) and the full list of GA versions already in the `online-tests` matrix.
- Read `tests/config.yaml` `rules_versions`: note which major.minor keys are already tracked.
- Read `scripts/test-stacks.sh` `DEFAULT_STACK_VERSIONS`: note which versions are already listed.

### 2. Discover new GA version(s)

For the SNAPSHOT version (e.g. `9.5`) and any intermediate minor versions between it and the highest matrix GA, check whether detection engine packages exist on EPR:

```bash
curl -s "https://epr.elastic.co/search?package=security_detection_engine&kibana.version={X.Y}.0"
```

A non-empty JSON array response means that version is GA. Collect all confirmed new GAs in ascending order (e.g. `[9.4, 9.5]`). Report findings to the user and **ask for confirmation before proceeding**.

### 3. Determine the full version set

- `ga_versions`: confirmed new GA versions, ascending (e.g. `[9.4, 9.5]`)
- `new_snapshot`: `max(ga_versions)` minor+1 (e.g. `9.6`)
- For each GA version: get the latest detection engine package version from EPR:
  ```bash
  curl -s "https://epr.elastic.co/search?package=security_detection_engine-{X.Y}&kibana.version={X.Y}.0" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['version'])"
  ```
- For the SNAPSHOT: use the same package version as `max(ga_versions)` (no dedicated package for unreleased versions).

### 4. Download missing ECS tarballs

For each GA version in `ga_versions` where no `etc/ecs-v{X}.{Y}.*.tar.gz` file exists:

```bash
TAG=$(gh api 'repos/elastic/ecs/releases?per_page=50' \
  --jq '[.[] | select(.tag_name | test("^v{X}\\.{Y}\\.")) | select(.prerelease==false)] | first | .tag_name')
curl -L "https://github.com/elastic/ecs/archive/refs/tags/${TAG}.tar.gz" \
  -o "etc/ecs-${TAG}.tar.gz"
```

For the SNAPSHOT version: do not download — it will reuse the highest `etc/ecs-v*.tar.gz` already present whose version is ≤ the SNAPSHOT.

### 5. Update `tests/config.yaml`

For each version (GA versions not already tracked + `new_snapshot`) add entries using `replace_string_in_file`.

**`rules_versions`** — insert before the serverless renovate comment:

```yaml
    # renovate: datasource=epr package=security_detection_engine-{X.Y}
    "{X.Y}": "{LATEST_PKG_VERSION}"
    # renovate: datasource=epr package=security_detection_engine
    "serverless": ...
```

The annotation always uses `security_detection_engine-{X.Y}` — including for SNAPSHOT versions. For a SNAPSHOT (e.g. `"9.6"`), this primes Renovate to automatically bump the entry to the correct package version once the corresponding release is published on EPR.

**`stack_signals`** — insert before `"serverless":`, copying the four values from the highest currently-tracked version:

```yaml
    "{X.Y}":
      ack_failed: {N}
      ack_unsuccessful_with_signals: {N}
      ack_no_signals: {N}
      ack_too_few_signals: {N}
    "serverless":
```

### 6. Update `.github/workflows/main.yml`

Replace the old SNAPSHOT entry with the full new block — new SNAPSHOT first, then all new GA entries in descending order — in a single `replace_string_in_file` call. Example — old entry:

```yaml
          - stack-version: 9.5.0-SNAPSHOT
            schema-uri: "./etc/ecs-v9.4.0.tar.gz"
```

Replaced by:

```yaml
          - stack-version: 9.6.0-SNAPSHOT
            schema-uri: "./etc/ecs-v9.5.0.tar.gz"
          - stack-version: 9.5.0
            schema-uri: "./etc/ecs-v9.5.0.tar.gz"
```

The `schema-uri` for each entry is the highest `etc/ecs-v*.tar.gz` present after step 4 whose version is ≤ the stack version. This goes in commit 1.

### 7. Update `docker-compose.yml`

Replace all three `TEST_STACK_VERSION:-{OLD}.0` default image references with `max(ga_versions).0` using `multi_replace_string_in_file`.

### 8. Update `scripts/test-stacks.sh`

**GA commit**: prepend all new versions (GA + SNAPSHOT) that are not already in `DEFAULT_STACK_VERSIONS`, in descending order, to the existing list.

Example: before `"9.4 9.3 9.2 ..."`, after `"9.5 9.4 9.3 9.2 ..."`.

### 9. Copy reports for new versions

Process versions in ascending order: all GA versions not already tracked, then `new_snapshot`. For each `{X.Y}` missing either `tests/reports/alerts_from_rules-{X.Y}.md` or `tests/reports/documents_from_rules-{X.Y}.md`:

- Find the greatest `{A.B}` (across all existing files, including ones just copied in this step) for which both report files exist.
- Copy:
  ```bash
  cp tests/reports/alerts_from_rules-{A.B}.md    tests/reports/alerts_from_rules-{X.Y}.md
  cp tests/reports/documents_from_rules-{A.B}.md tests/reports/documents_from_rules-{X.Y}.md
  ```

No test runner is ever invoked. Reports are seeds only; accurate versions come from CI artifacts applied by `update-detection-engine-rules`.

### 10. Confirm and open draft PR

Show the user a full summary of all staged changes. **Always ask for confirmation before pushing.**

Then create exactly two commits in a new branch:

**Commit 1 — `"Add {max_ga} to the drill"`**

Stages (only what actually changed):
- `tests/config.yaml` (new GA entries)
- `tests/reports/alerts_from_rules-{X.Y}.md` and `documents_from_rules-{X.Y}.md` for each new GA
- `etc/ecs-v*.tar.gz` (newly downloaded tarballs)
- `.github/workflows/main.yml` (old SNAPSHOT replaced by full new block: new SNAPSHOT + all new GA entries)
- `docker-compose.yml`
- `scripts/test-stacks.sh` (all new versions prepended)

**Commit 2 — `"Add {new_snapshot} to the drill"`**

Stages:
- `tests/config.yaml` (new SNAPSHOT entry)
- `tests/reports/alerts_from_rules-{new_snapshot}.md` and `documents_from_rules-{new_snapshot}.md`

Then push and open the draft PR:

```bash
git checkout -b add-{versions}-to-the-drill
git add <commit-1 files> && git commit -m "Add {max_ga} to the drill"
git add <commit-2 files> && git commit -m "Add {new_snapshot} to the drill"
git push origin add-{versions}-to-the-drill
gh pr create --draft \
  --title "Add {versions} to the drill" \
  --body "Adds {max_ga} as GA and {new_snapshot} as SNAPSHOT.

stack_signals values for new versions are placeholders copied from the previous version and will be corrected by the update-detection-engine-rules agent once online CI has run."
```

The branch name and PR title use the SNAPSHOT versions. Example: branch `add-9.6-to-the-drill`, title `"Add 9.6 to the drill"`.

## Rules

- Never modify existing `rules_versions` or `stack_signals` entries — only add new ones.
- Preserve Renovate annotation comments exactly as written.
- The `schema-uri` for a matrix entry is always the highest `etc/ecs-v*.tar.gz` present with version ≤ the stack version. Never reference a tarball that does not exist in `etc/`.
- Never download an ECS tarball for an unreleased (SNAPSHOT) version.
- Report files are seeds only. They are keyed by major.minor with no SNAPSHOT notion.
- Always confirm with the user before pushing and creating the PR.
- Do not modify `renovate.json`.
- Do not close or modify any existing PRs.
