# Geneve Obvious tool POC

This level-set tool cycles through enabled Detection Engine rules and generates
one rule-trigger group per second by default. A sequence rule can produce
multiple source documents for one trigger group.

`rule_ids` is an optional JSON array of stable Detection Engine rule IDs. When
provided, it narrows discovery to enabled rules in that exact set. When omitted,
`elastic.pipes.kbn.rules.get` discovers every enabled rule from Kibana and
places the raw rule records in Pipes state `rules`; the Geneve generator consumes
that state rather than querying Kibana itself. The previous revalidated
400-rule selection contains 389 EQL rules and 11 Kuery rules, with sorted
rule-ID digest
`sha256:db9614aa17fea66d29e5099723b57aacad2407dcad4ea1586b325eb4791131d1`.

The tool writes source documents only to configured canonical Endpoint data
streams. Elasticsearch creates those data streams from installed integration
templates on the first successful `create` write; the tool creates no custom
index or template. A retrieved rule whose generated event category has no
configured destination is counted as a generation failure.

## Target-stack connection inputs

Target-stack access is supplied by three required inputs:

- `target_es_url`: the Elasticsearch URL as a regular string input.
- `target_kibana_url`: the Kibana URL as a regular string input.
- `target_api_key`: a Google Secret Manager (GSM) `secret_ref` input.

The authenticated OIDC actor must have `roles/secretmanager.secretAccessor` on
the API-key secret. The controller uses that actor's identity to have External
Secrets Operator materialize a per-execution local Secret, waits for it before
installing the chart, and removes it with the execution namespace during
cleanup.

For example, a continuous execution supplies regular URLs and an API-key GSM
reference:

```sh
obc -r <remote> execute <pinned-chart> --action run \
  --input 'rule_ids=["<stable-rule-id>","<stable-rule-id>"]' \
  --input target_es_url=https://<deployment>.es.<region>.gcp.elastic-cloud.com:443 \
  --input target_kibana_url=https://<deployment>.kb.<region>.gcp.elastic-cloud.com:443 \
  --input target_api_key=projects/<project>/secrets/<api-key-secret> \
  --condition '{"term":{"status":{"value":"complete"}}}' \
  --finish-within never
```

The controller-derived local Secret name is the only secret value in the chart
values. The Deployment injects its `value` key as `GENEVE_TARGET_API_KEY`; it
injects the regular URL inputs as `GENEVE_TARGET_ES_URL` and
`GENEVE_TARGET_KIBANA_URL`. API-key references and payloads are never rendered into ConfigMaps, arguments,
or logs.

## Lifecycle

The deployment becomes ready only after it has retrieved and prepared at least
one enabled rule. The Kibana rules pipe records the selected raw rules in state
before the generator starts; readiness remains pending if selection or
preparation cannot produce a usable rule. The manifest declares a reserved
`status` output only because the controller requires every execution to name an
output condition. Geneve never emits it and does not receive an output Secret.
Because this tool is intended to run continuously, use the never-met
`status=complete` condition with `--finish-within never` and stop it with
`obc cancel`.

## Logs

The Pipes runtime emits ECS JSON to the container's stdout and stderr. The
Obvious cluster log collector routes each execution to
`kubernetes.container_logs.obvious_tool_geneve`; it promotes standard ECS
logging fields such as `message` and `log.level`. In Kibana, filter that dataset
and `kubernetes.labels.obvious_io_execution_id` for the execution ID. The log
stream contains operational diagnostics only: neither the target API-key
reference nor its payload is logged.

Build the image from the Geneve checkout. The image installs the temporary
`pipes-py` PR branch directly from Git:

```sh
docker build -f pipes/Dockerfile -t <image> .
```

The checked-in POC image reference is published to the Project Obvious Artifact
Registry. Future image versions must likewise be reachable by the Obvious
cluster before publishing the chart.
