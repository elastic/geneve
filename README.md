# Geneve

Geneve is a data generation tool, its name stands for GENerate EVEnts.

To better understand its basics, consider the Elastic Security's
[detection engine](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html).
It regularly searches one or more indices for suspicious events, when a
match is found it creates an alert. To do so it needs detection rules
which define what a _suspicious event_ looks like.

The original goal of Geneve is then summarized by:

> Given a detection rule, generate source events that would trigger an alert creation.

It does so by analyzing the rule, building an abstract syntax tree of the
enclosed query and translating it to an intermediate language that is used
for generating documents (= events) over and over.

What became obvious over time is that the query at the heart of each rule
is actually a powerful way to drive the documents generation that goes
well beyond the alerts triggering.

Additionally, one thing is generating garbage data that satisfies a rule
and another is generating realistic data that can be analyzed with Kibana,
which is an implicit goal of the tool.

This last is a quite harder nut to crack than the original goal and is
currently under development.

If you want to try it, read [Getting started](docs/getting_started.md).

# Status

## Data modeling

The rules/queries parsing, AST creation and IR generation are quite
developed and rigorously tested by the CI/CD pipelines. The generated
events are good enough to trigger many of the expected alerts on various
versions of the stack, from 8.2.0 to 8.6.0, but the work is necessarily
incomplete albeit as correct as possible.

The detection rules set used for the tests is separately loaded into
Geneve and is currently locked to version 8.2.0 (718 rules in total). Next
step is to use the rules preloaded in the Kibana under test
(https://github.com/elastic/geneve/issues/125).

Kind of issues observed in this area:

1. skipped rules due to unimplemented rule type (ie. threshold) or query
   language (ie. lucene).
	 <ins>73 rules</ins>.
2. generation errors due to unimplemented query language features or
   improvements needed in what is already implemented.
	 <ins>80 rules</ins>.
3. incorrect generation, the expected alerts are actually not created.
   <ins>5 rules</ins>.

The first two points are detailed in the
[Documents generation from detection rules](/tests/reports/documents_from_rules.md)
test report, the last is in the
[Alerts generation from detection rules](tests/reports/alerts_from_rules.md) one.

Number of rules for which correct data is generated and alerts are created: <ins>560</ins>.

## Data realism

Allowing the user to "click through" requires that generated data exploits
the relations that Kibana is made to observe. Having relations implies
having also the entities that such relations connect together, entities
that need to be consistent in the whole generation batch.

The problem is being understood more and more, parts of its solution are
already implemented others are still sketched.

## User interface

Geneve is composed of a Python module and a REST API server that exposes
it. The Python API is quite simple and stable, the REST API instead has
raw edges and needs proper simplification.
