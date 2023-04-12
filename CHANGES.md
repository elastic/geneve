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
