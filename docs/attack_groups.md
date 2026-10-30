# Attack groups

Big-picture design for generating **related** detection traffic from
pre-built rules, with countable ground truth. This document is for human
review and later architecture, design, planning, and implementation. It is
intentionally open-ended about *who* drives generation and *where*
documents land; Geneve remains the generation core.

## Motivation

Geneve turns logical expressions (today: Kuery and EQL, with further
languages evolving) into JSON source documents that can trigger Elastic
detection rules. Preparation is one-shot: queries or rules are parsed into
an AST, constraints are collected into Geneve’s intermediate
representation (IR), and emission repeatedly solves those constraints.

That pipeline already supports **local correlation inside one rule**. An
EQL sequence (and similar constructs) compiles to IR with join bindings so
several documents share keys and fire as one related story.

Across separate rules, documents are mostly independent draws. Shared
environment state today is thin (for example field history under
cardinality), not a durable entity store. You can trigger many pre-built
rules, but the resulting alerts rarely form a coherent attack narrative.

**Attack groups** scale the sequence idea from “related events for one
rule” to “related events for a *set* of rules”, expressed and solved at
the IR layer so language and rule-type differences do not matter once
front-ends have produced constraints.

## Goals

1. **Related multi-rule stories** — documents for several pre-built rules
   share entities (hosts, users, process lineage, network endpoints, …)
   so alerts read as one attack, not a bag of unrelated hits.
2. **Versioned rule inputs** — each Elastic stack / rules package version
   has its own pre-built set; attack-group artifacts are defined relative
   to such a set.
3. **Taxonomy-guided coverage** — avoid combinatorial explosion. Organize
   and select attack groups using **existing industry classifications**
   (notably MITRE ATT&CK tactics/techniques, and other mappings already
   carried by pre-built rules — e.g. domains, platforms, rule tags), not
   a bespoke “pair every rule with every other rule” scheme. The goal is
   a useful distribution of stories along those axes, reusing work the
   detection community has already done.
4. **Realistic mix** — interleave story documents with unrelated documents
   (other rules or noise) under controllable rates (signal/noise and
   related knobs).
5. **Countable ground truth** — know ahead of time how many attacks are
   being perpetrated (and which pre-built rules each story intends to
   exercise), so detections can be evaluated against an almost rigorous
   ledger.
6. **Deterministic generation** — authoring and maintenance of attack-group
   artifacts may use **AI / LLM help** (drafting membership, glue,
   bindings, narrative notes); **emission must not**. Generation stays
   Geneve IR → solvers → documents (seedable, reportable), with no model
   calls on the hot path.
7. **Reusable artifacts** — an attack-group file describes the *story*
   (rules, glue, entity joins), not *how* documents are produced or
   shipped. The same file should work for a one-shot Geneve run, a paced
   continuous stream, or a multi-host run where different stages use
   different host identities. Pacing, destinations, and host identity
   belong to the caller; they do not belong in the group format.

## Non-goals (for this picture)

- Exhaustive pairing of every pre-built rule with every other rule.
- Replacing Geneve’s per-rule quality reports; attack groups *add* a
  story-level contract on top.
- Specifying concrete wire formats, APIs, or integrations in this
  document (those belong to later design).
- Calling AI / LLM (or any generative model) during document emission.

## Core concepts

### Pre-built rules (versioned)

Inputs are the detection rules that ship with (or are loaded for) a given
stack / rules version. Only a subset is Geneve-capable today (language
and rule-type coverage is incomplete). Attack groups are defined over
rules that *can* be prepared into IR; unsupported rules are out of band
until front-ends catch up.

Those rules are assembled and maintained in Elastic’s public
[detection-rules](https://github.com/elastic/detection-rules) repository
(TOML sources, packaging, tests). That repo already carries much of the
classification attack groups should reuse rather than reinvent:

- **MITRE ATT&CK** (and versioned / multi-framework mappings such as
  ATT&CK + ATLAS) on each rule’s `threat` / `threat_mappings`;
- a governed **tag taxonomy** (`Domain:`, `Platform:`, `OS:`, `Tactic:`,
  `Data Source:`, `Threat:`, …);
- **ATT&CK Navigator** coverage layers produced at package build;
- **RTAs** (Red Team Automations) that emulate techniques to verify rules
  fire — a sibling “does this behavior actually trigger?” practice, not
  the same as Geneve document generation, but useful context for story
  design.

Attack-group authoring should treat detection-rules metadata as the
primary index for “which rules belong near each other,” and Geneve as the
engine that turns a chosen membership into related source documents.

### Attack group (artifact)

An **attack group** is a versioned file (or small file set) that names:

- membership: which pre-built rules participate in the story;
- how their IRs are joined (shared entity / field bindings — the scaled-up
  analogue of sequence `by` / `join_value`);
- optional **glue** queries (see below);
- optional metadata for humans and selectors — prefer **industry
  taxonomy references** (MITRE ATT&CK technique/tactic ids, platforms,
  …) and fields already present on pre-built rules, plus short notes on
  why these rules belong together.

Groups are **created and maintained** offline. Humans may draft them by
hand or with **AI / LLM assistance** (for example proposing rule
combinations, glue queries, join fields, or story metadata); the checked-in
artifacts remain the source of truth after review. They are **selected and
executed** by whatever drives Geneve for a given exercise. No AI / LLM is
involved in emission.

### Glue queries

Optional queries or local “rules” that are **not** part of the pre-built
detection pack. They participate in the same IR join graph so they bridge
entities between pre-built members (shared host, user, parent process,
…). Because the detection engine does not know them, their documents do
not (by design) create matching pre-built alerts. They are connective
tissue — and intentional unknown signal — inside the story.

### Intermediate representation as the join surface

All supported query languages must compile into Geneve’s constraints IR
before join and emit. Attack grouping therefore happens **after**
translation:

```text
rule / query  →  AST  →  constraints IR  →  join / group composition  →  solve / emit
```

That keeps multi-language membership (Kuery, EQL, future languages) a
front-end problem, not a grouping problem.

### Selection and rates

A caller is given (or discovers) configured rules and parameters such as:

- which attack-group artifacts are eligible (intersection with configured
  rules, rules-package version, **taxonomy filters** — ATT&CK tactic /
  technique, platform, …);
- how many stories to run, concurrency, pacing;
- signal/noise (or equivalent) so story docs are interleaved with
  unrelated generation.

Selection is policy; emission remains Geneve.

### Ground truth ledger

Because groups are fixed artifacts and emission is deterministic given
seed and policy, an execution can publish **a priori** expectations:

- number of attack stories started;
- for each story: which pre-built rules were intended to fire (and any
  cardinality / multiplicity);
- what was glue vs noise (should not count as “known” detections).

You can then ask, per story: did Security catch it, miss it, or only catch
part of it — complementary to today’s per-rule expected-signal checks.

“Almost” rigorous: real stacks have alert limits, timing quirks, and
extra hits from interleaved noise; the ledger still states what was
*intended*.

## Multi-host and multi-emitter angles (open-ended)

Stories need not assume a single host or a single process that writes
documents.

Useful shapes include:

- **Single-host narrative** — one identity threaded through several rules.
- **Coordinated multi-host** — distinct host (and related) identities
  bound inside one group so stages of the story land on different
  simulated machines but remain one attack.
- **Repeated / widespread pattern** — the same or similar group instantiated
  across many hosts in a close time window (campaign-like breach).

Geneve already reasons about field constraints and joins; host-scoped
identity (OS, architecture, host name, agent id, …) is another dimension
of the same entity-binding problem. Callers that have such identities
pass them into generation; the attack-group file only says which story
fields must stay consistent across documents and hosts.

Keep the group definition about **rules, glue, and bindings**. Keep
pacing, indexing/shipping, and “how many hosts” outside the file.

## Horizontal scale without synchronized generators (sketch)

Geneve is a Python generator, so the throughput of one process is limited.
The practical scale-out path is many Geneve emitters (processes, or
free-threaded replicas) each with their own memory and IR — not one shared
runtime.

The design fork that matters:

- **Synchronized coordination** — emitters share mutable state or talk at
  emit time (locks, queues, “ask peer for `user.id`”). Correctness is
  possible; scalability collapses into the synchronizer.
- **Unsynchronized coordination** — emitters never contact each other.
  Related documents still align because shared entity values are a pure
  function of inputs every emitter already has, for example:

  `(attack-group artifact, shared coordination seed, story_id, entity_id [, host_id]) → field values`

  Same inputs ⇒ same join keys. No runtime handshake.

Two shapes to keep in mind:

1. **Partitioned ownership** — shard `story_id` / `host_id` across
   emitters; each emitter emits whole stories (or whole hosts). Easy;
   scales as “N independent Geneve processes.”
2. **Cross-emitter story stages** — different emitters emit different
   rules/stages of the *same* story and must still share entities.
   Requires **content-addressable / seeded entity binding** in (or beside)
   the artifact — not today’s in-process `__environment` or
   emission-order `join_value` history alone.

Today’s sequence joins solve keys inside one `Branch.solve(environment)`
call. That model is right for a single process. Multi-emitter relatedness
has to lift identity into **derivable** values (artifact + seed + logical
entity ids), with each emitter assigned a disjoint slice of the id space
so they neither collide nor wait.

Getting this right is the difference between **embarrassingly parallel
scale-out** and **total synchronization**. The artifact + shared seeding
layer is where that choice is made; treat it as a first-class design
constraint, not an afterthought of “run Geneve under a process pool.”

## What already exists in Geneve (anchors)

| Piece | Role today | Relation to attack groups |
| --- | --- | --- |
| `SourceEvents` | Add many queries/rules; keep roots; emit repeatedly | Natural place to attach group composition |
| Constraints IR (`Root` / `Branch` / `Document`) | Generation IR | Join surface across rules |
| Sequence → `join_value` | Intra-rule related documents | Pattern to scale across rules |
| `__environment` | Thin shared state (e.g. cardinality history) | Insufficient as entity store; groups need richer bindings |
| Versioned `documents_from_rules-*` / `alerts_from_rules-*` | Per-rule prepare and signal quality | Story-level ledger is additive |
| Optional corpus merge on emit | Overlay / enrichment | Possible noise or realism aid; not the join mechanism |

## Hard problems (honest)

1. **Meaningfulness** — combining IRs is comparatively mechanical; deciding
   which rules form a *credible* story is not. Lean on **MITRE ATT&CK and
   similar industry maps** (and the threat mappings already on pre-built
   rules) as the primary structure; use curated packs, **AI / LLM–assisted
   drafting**, and human review to fill stories *within* that structure —
   not a fully automatic oracle, and not model calls at emit time.
2. **Distribution design** — cover enough stories along taxonomy axes
   (techniques, tactics, platforms, …) without exploding the artifact set
   or inventing a parallel classification system.
3. **Entity model** — what must be shared (and stable) across rules and
   hosts for alerts and UI drill-down to look right.
4. **How to grade a story** — what counts as detected when only some of
   the intended rules fire, alerts arrive late or out of order, or noise
   trips extra rules.
5. **Geneve coverage limits** — an attack group can only include pre-built
   rules that Geneve can already turn into IR (today: incomplete Kuery /
   EQL; other rule types and languages still skipped).
6. **Cross-emitter identity** — seeded, derivable entity binding vs
   in-process join history; wrong choice forces sync between generators.

## Principles

1. Checked-in artifacts over live AI / LLM prompts on the generation path.
2. IR is the lingua franca; languages meet there.
3. Glue is first-class for bridging, invisible to pre-built detection.
4. Prefer taxonomy-guided, curated coverage (MITRE et al.) over exhaustive
   rule combinations or a homemade classification.
5. Ground truth is a product of the plan, not an after-the-fact guess.
6. Group files stay about stories; callers own pacing, shipping, and hosts.
7. Prefer unsynchronized emitters bound by artifact + seed over emit-time
   coordination between generators.

## Suggested follow-on work (not a plan yet)

Order of depth, not a commitment:

1. Artifact sketch (fields, versioning, membership, bindings, glue).
2. Inventory of detection-rules metadata useful for grouping (ATT&CK,
   tags, navigator layers, RTA links).
3. IR composition API (join several prepared roots with shared entities).
4. Emission policy (interleave, rates, seeds) and story-level ledger
   format.
5. Authoring / maintenance workflow (human and/or AI / LLM), still offline.
6. Multi-host identity bindings as an extension of the same join model.
7. Seeded / content-addressable entity binding so multiple Geneve emitters
   can emit related docs without runtime sync.
8. Evaluation harness that compares ledger to observed alerts.

## Open questions

- How is “meaningful” judged and reviewed when groups were drafted with
  AI / LLM help — and how strictly must membership align with ATT&CK
  (or other) technique chains vs looser “same host / same campaign” joins?
- Which detection-rules fields/tags are enough to select membership
  (ATT&CK technique chains, `Tactic:` / `Platform:` / `OS:`, …), and when
  is human or AI / LLM judgment still required?
- How do RTAs and attack groups relate — complementary verification vs
  overlapping goals?
- Minimum viable join set (which entity fields must always align)?
- How do groups version when pre-built rules churn between releases?
- How much noise is allowed to trip extra rules before the ledger’s
  “almost” becomes “weak”?
- Should glue ever be optional exports for labs that *do* want custom
  rules installed, or always stay generator-local?
- What is the minimal entity-id / seed schema so cross-emitter joins stay
  stable without reintroducing shared mutable environment?
