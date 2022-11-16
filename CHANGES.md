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
