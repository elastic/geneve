## v0.4.0 - Jan 28, 2025

#### Core

* Add fields superimposition.
* Drop the Geneve API server and proxy.
* Generate docs incrementally.

#### Testing

* Add Stack 8.16 and 8.17 to the test drill.
* Split out the tests configuration.
* Use rules versions specified in the test config file.
* Stop observing the stack version in Serverless.
* Disable the EPR condition on Serverless Kibana when searching for packages.
* Add an ESS Buildkite pipeline.
* Default to download rules from EPR if not configured locally.
* Various improvements to scripts/test-stacks.sh.
* Don't fail the Buildkite pipeline if the list fails.
* Drop deprecated `/api/detection_engine/rules/_bulk_delete`.
* Drop testing support for 7.x.
* Make `find_detection_engine_rules` more strict.
* Migrate to `_import` to bulk create rules.
* Add `filter` when extracting a tarball (fix Python warning).
* Test also bztar and xztar resources.
* Update to Python 3.13.
* Update to ECS 8.16.0.

## v0.3.0 - Aug 28, 2024

#### Core

* Split constraints analysis from document generation.
* Instantiate field solvers only once.
* Refactor keyword solver, add the oncept of strings solution space.
* Add Event constraints solver.
* Early detection of the wrong number of branches.
* Early detection of empty combined fields solution space.
* Fix field path splitting.
* Fix keyword list lookup.
* Fix location of the Geneve download cache on mscOS.
* Make constraints cloning more efficient.
* Do not optimize ASTs when converting from KQL.
* Fix invocations of `super`.
* Migrate to `pathlib`.
* Use `isinstance()` instead of comparing types.
* Add azure group solver.
* Add support for dynamic templates.
* Expand wildcards in the field name.
* Fix sequence rules with `runs=` on the first subquery.
* Improve errors reported by `guess_from_query`.
* Fix EQL sequence subqueries wrt to `fork` and `is_negated`.
* Avoid superfluous recreation of ip_address values.
* Use dicts to store history of values.
* Avoid calling fnmatchcase for solution points with no wildcards.
* Speed up util.has_wildcards by regex.
* Add `wildcard` field type.
* Adopt Renovate for automating the dependencies maintenance.
* Update all the dependencies.

#### Testing
* Add support for Serverless to the CI pipeline.
* Add Security serverless quality gate pipeline.
* Add Stack 8.8, 8.9, 8.10, 8.11, 8.12, 8.13, 8.14, and 8.15 to the test drill.
* Use only primary shards, no replicas, during the CI tests.
* Let failed rules to retry the execution and forget the failures if they eventually
  succeed or list all the failures if they eventually fail.
* Compare reports on success or in assertion errors but not on other errors.
* Drop generated documents from test reports.
  Makes report much more maintainable.
* Use a separate test report for each stack version.
* Use separate schema and rules for each stack version.
* Add rules version to the tests reports.
* Save container logs as artifacts.
* Make `load_schema` cache downloads.
* Improve diagnostics during the CI tests.
* Move code linting to its own job.
* Adopt Ruff for linting Python code.
* Adopt Staticcheck for linting Go code.
* Increase ES heap to 2GB in CI.
* Tag Geneve rules.
* Improve test progress on verbose execution.
* Add Python 3.12 to the test drill.
* Test only oldest and newest Python versions.
* Add Go 1.21 to the test drill.
* Test only oldest and newest Go versions.
* Allow disabling certs verification.
* Drop duplicated matrix entries.
* Add a weekly test run to detect detection rules updates.
* Pin eql package to 0.9.19.
* Add progress for rules parsing and documents creation.
* Allow user to specify `test-stacks.sh` params.
* Keep a copy of the test report for each iteration.
* Allow keeping the stack after testing.
* Use the latest available ECS when the calculated version is not avaialble.

#### API server

* Unified requests body decoding.
* Adopt Pygolo for interaction with the core.

#### API client

* Make actually `geneve --log` effective.

#### Documentation

* Refresh notebook output.
* Refresh events generation walk-through.

## v0.2.0 - Apr 12, 2023

#### Documentation

* Added the [Getting started](docs/getting_started.md) guide.
* Added the [Data model](docs/data_model.md) guide.
* Updated and improved the [events generation walk-through guide](docs/events_generation_walk-through.ipynb).

#### User interface

* Added [scripts/generate-alerts.sh](scripts/generate-alerts.sh).  
  Generate events that will trigger the rules you want. Use it as template.
* Added [scripts/generate-network-events.sh](scripts/generate-network-events.sh).  
  Forget rules and alers, let there be data! Use it as template.
* Improved robustness of `.ipynb` files.  
  You can play with the Jupiter notebooks with more freedom.

#### API server

* Configure rules execution schedule.  
  You'll get alerts in response to generated events sooner (~ 30 secs) than the
  average rule's interval (~ 2.5 mins, at best).
* Unified requests body decoding.  
  Less code to maintain.
* Allow fetching rules from Kibana.  
  You can use rules directly from your Kibana.

#### Core

* Prevent double solver registration.  
  In future, when you'll be able to create your solvers, this will prevent
  annoying and non-trivial to parse errors.
* Fix use of variable without associated value (IP generator).
* User prioritized document generation.  
  The order of generated fields is dictated by their order in the query.
* Incremental document generation.  
  Generated fields are progressively added to the document, content of
  later fields may depend on content of earlier ones.
* Add Autonomous System group solver.  
  The AS organizations are total fake though.
* Use [Faker](https://github.com/joke2k/faker) for geo info generation.
* Switch to per-group data generation.  
  Fields in the same group are generated together, this will help later
  with the development of entities generation.
* Make `*.bytes` fields are non-negative 32 bits numbers.
* Make `utils.resource()` able to cache downloaded files.
* Improved the [PyPi index entry](https://pypi.org/project/geneve/) of Geneve.

#### Testing

* Added stacks 8.6 and 8.7 to the test drill.
* Harmonize Geneve and Faker randomness.  
  One source of randomness to rule them all, a must for reproducible tests.
* Added helper `ExpectJson` for Geneve server testing.  
  It's easier to maintain test cases.
* Improved response body output when tests fail.  
  It's easier to understand what's wrong in the received output when it
  differs from the expected one.

## v0.1.1 - Nov 16, 2022

Service release to improve the CI/CD pipeline.

* Upload the Python source distribution (sdist) to PyPI, needed by the Homebrew formula.

## v0.1.0 - Nov 15, 2022

First documented release. What you can do with it:

* generate a lot of data, either in form of plain json content or documens already ingested in our favourite stack, Elasticsearch
* define a data model which describes the documents, the relations among them and their fields
* define a schema which specifies the type of each field (you cannot generate content without describing the meaning of it)

Of the above, the most definitve is the schema. Geneve uses [ECS](https://www.elastic.co/guide/en/ecs/current/index.html) as reference, you can use any alternative but it shall be defined in the same format as ECS.

About data models, they are a vast topic and any implementation is necessarily open and incomplete. Just to give a feeling of what you can already generate, think at the Elastic Security Solution [detection rules](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html). There are about 650 of them and you can generate documents to reliably trigger ~550 security alerts.

Is all this enough for filling up your stack with useful data? Not even close. Sure you can exhaust the storage but that alone is not very useful.

Indeed it's all interesting only if you can use Kibana to analyze it, exercise all the features and goodies it ships on every release, feel how it would be once you get in production.

At the moment there is enough only to visualize some data, a map, click through for a bit and get engaged. A scratch on the surface, a honest v0.1.0! 🎉
