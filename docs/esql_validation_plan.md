# ES|QL validation parity plan

## Purpose

Bring ES|QL support under Geneve's existing correctness contract.

For a fixed rule set, schema, target-version configuration, corpus, and seed,
Geneve must generate the same branches and documents in the same order. For
each supported prebuilt rule branch, those documents must produce the expected
number of alerts in the target Security Solution.

The checked-in reports are the reproducible evidence of that contract.

## Current state

ES|QL has substantial offline coverage:

- `tests/test_esql.py` tests parsing, translation, branch construction,
  constraints, document emission, and supported aggregate semantics.
- `tests/test_esql_validation.py` can index generated documents into
  Elasticsearch and run the original ES|QL query against them.
- `tests/reports/esql_validation-9.5.md` records a manual validation run.

That validation is necessary but does not yet provide the established
Kuery/EQL guarantee:

- `TestSignalsRules` explicitly skips rules whose type is `esql`.
- `TestSignalsQueries` explicitly excludes ES|QL fixture queries.
- Therefore ES|QL rules do not appear in `alerts_from_*` reports.
- The direct Elasticsearch validation is opt-in through
  `TEST_ESQL_VALIDATION=1`; neither GitHub Actions nor Buildkite enables it.
- The validator checks query matching, not rule import, detection-rule
  execution, alert creation, or alert cardinality.
- Aggregate validation samples at most 40 branch-groups and checks that each
  sampled group returns a row. It is not a full alert-count assertion.
- Generated timestamped documents use the wall clock, so a seed alone does not
  presently make the full ES|QL corpus byte-for-byte reproducible.

Unsupported ES|QL constructs must remain explicit in the deterministic
documents and alerts reports. They must never disappear merely because the
signal harness does not admit ES|QL rules.

## Target contract

For every supported ES|QL rule branch:

1. Geneve generates a deterministic document group.
2. The original ES|QL query returns the generated documents, or its expected
   aggregate row.
3. Kibana imports and executes the corresponding detection rule successfully.
4. The rule creates exactly the expected number of alerts.
5. The result appears in the target-specific `alerts_from_*` report.

Known target-specific discrepancies are allowed only through explicit,
versioned acknowledgements, as with the existing EQL and Kuery rule tests.

The direct Elasticsearch validation remains complementary: it checks the
query semantics. The alert reports check the Security Solution behavior.

## Reproducibility requirements

The following inputs define one generated corpus:

- rule package and version;
- ECS/schema input;
- target Stack or Serverless version;
- optional source corpus;
- generation seed;
- deterministic clock value when timestamps are requested.

With identical inputs, ES|QL generation must reproduce:

- supported/unsupported rule classification;
- branch count and branch order;
- documents in every branch, including field ordering where report rendering
  depends on it;
- group composition for `STATS`;
- generated timestamps;
- expected alert counts;
- report ordering and contents.

No ES|QL code path may introduce hidden nondeterminism through wall-clock
time, an unseeded random source, unordered iteration, or externally varying
rule selection.

Add a focused seeded-corpus test that generates representative ES|QL rules
twice and compares their complete branch/document output. Include:

- simple predicates and disjunctions;
- `LIKE`, `RLIKE`, and KQL-in-ES|QL predicates;
- `STATS` with `COUNT` and `COUNT_DISTINCT`;
- `BY` keys, time buckets, and the supported “recent documents” form;
- aliases and source fields from integrations.

Inject or otherwise control the clock used for emitted timestamps. A test must
not need to relax equality because it happened at a different wall-clock time.

## Reports

### Documents reports

`documents_from_rules-<target>.md` must continue to list every prebuilt ES|QL
rule as either generated or skipped, with a specific error for unsupported or
unsatisfiable rules.

### Direct ES|QL validation reports

`esql_validation-<target>.md` must report, separately:

- validated;
- failed because generated documents did not match;
- refused by Elasticsearch;
- skipped because Geneve does not support the rule.

Make this report a reproducible baseline rather than a manually refreshed
artifact. A reduction in supported coverage or a changed validation result
must be visible in review.

For aggregate queries, either validate every branch-group or report and
enforce the deliberate sampling policy. Do not describe sampled validation as
validation of every branch.

### Alert reports

`alerts_from_rules-<target>.md` must include ES|QL prebuilt rules in the same
explicit outcome categories as EQL and Kuery rules:

- failed rule execution;
- unsuccessful rule execution with signals;
- no signals;
- too few signals;
- too many signals;
- correct signals.

`alerts_from_queries*.md` must also include ES|QL fixture queries, including
aggregate cases. These fixture tests provide a small, comprehensible
end-to-end guard before the larger prebuilt-rule drill.

No ES|QL rule or query may be silently omitted from an alert report. A rule
that cannot yet be placed into the alert harness must be listed explicitly
with its reason.

## Implementation sequence

### 1. Establish deterministic ES|QL generation

Add seeded corpus-equivalence tests and a controllable timestamp source. Audit
ES|QL parsing, branch expansion, aggregate group construction, and report
rendering for nondeterministic iteration and non-Geneve random sources.

Keep this change independent of Elasticsearch or Kibana so that it is fast
and reliable in the ordinary unit-test job.

### 2. Make direct Elasticsearch validation a CI check

Run `tests/test_esql_validation.py` for ES versions where ES|QL is available.
Commit target-version reports and compare regenerated output against them.

Start with the newest maintained Stack target. Add older targets only while
their prebuilt-rule package remains actively refreshed and the target remains
part of the useful compatibility contract.

### 3. Solve ES|QL source routing for the alert harness

The current blocker is that ES|QL rules search the indices named by `FROM`,
while the generic signal harness writes documents to isolated `geneve-ut-*`
indices.

Design and test a deterministic test-only routing strategy that:

- isolates each rule's generated documents from every other rule;
- makes the ES|QL rule read those documents;
- preserves the rule predicate and aggregate semantics being tested;
- handles supported `FROM` forms, or explicitly reports unsupported source
  forms;
- works for both Docker Stack and Serverless targets.

Do not remove the existing ES|QL skip until this behavior has direct tests.

### 4. Add ES|QL to the alert harness

Once routing exists, include supported ES|QL rules and query fixtures in:

- document and mapping generation;
- rule creation;
- rule-execution waiting;
- signal collection;
- expected-count calculation;
- the standard too-few and too-many assertions.

Decide and document the expected cardinality of an aggregate rule explicitly.
The harness must not assume that a document count, branch count, result-row
count, and alert count are interchangeable without a test proving the
relationship.

### 5. Seed target reports from local Docker runs

Use `scripts/test-stacks.sh` to establish and inspect reports locally, with
explicit current targets rather than its default historical sweep:

```bash
./scripts/test-stacks.sh --online --rules 9.5
```

Run targets in descending maintenance priority. Do not spend compatibility
effort on frozen rule packages solely to fill old report slots.

The script promotes a generated `*.new.md` report to `*.md` after a failing
comparison. Treat this as a deliberate baseline-update workflow:

1. run one explicit target in a clean worktree;
2. inspect the changed report and generated data;
3. explain every new status or cardinality difference;
4. commit the reviewed report with the code that caused it.

Serverless is a separate target and must be exercised through its dedicated
quality-gate environment.

## Acceptance criteria

The work is complete only when all of the following hold:

- ES|QL document generation is reproducible from a seed and controlled clock.
- Direct ES|QL validation runs in CI and has checked-in, reproducible reports.
- ES|QL is no longer unconditionally excluded from signal-rule or
  signal-query tests.
- Every supported ES|QL prebuilt rule has a visible status in the relevant
  `alerts_from_rules-<target>.md` report.
- ES|QL fixture queries have visible status in `alerts_from_queries*.md`.
- Alert counts are asserted, not inferred from a nonzero ES|QL result.
- Stack and Serverless discrepancies are versioned and explicitly
  acknowledged.
- Unsupported rules remain visible with actionable reasons.
