# Geneve Obvious tool POC

This level-set tool cycles through the explicit `rule_ids` input for an
execution. It generates one rule-trigger group per second by default. A sequence
rule can produce multiple source documents for one trigger group.

`rule_ids` is a required JSON array string, not a chart default. This keeps the
selection in the execution request rather than generating data for every rule
enabled on a target stack. The revalidated 400-rule selection contains the
original 50 EQL rules, 339 additional EQL rules, and 11 Kuery rules. Its sorted
rule-ID digest is
`sha256:db9614aa17fea66d29e5099723b57aacad2407dcad4ea1586b325eb4791131d1`.

The tool writes source documents only to the canonical Endpoint data streams
that the selected rule searches. Elasticsearch creates those data streams from
the installed integration templates on the first successful `create` write; the
tool creates no custom target index or template.

## Target-stack connection inputs

The Obvious controller supplies `obvious-output`, which only grants writes to
the tool's output data stream. Target-stack access is supplied separately by
three required inputs:

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
  --input 'rule_ids=["<rule-id>","<rule-id>"]' \
  --input target_es_url=https://<deployment>.es.<region>.gcp.elastic-cloud.com:443 \
  --input target_kibana_url=https://<deployment>.kb.<region>.gcp.elastic-cloud.com:443 \
  --input target_api_key=projects/<project>/secrets/<api-key-secret> \
  --condition '{"term":{"status":{"value":"complete"}}}' \
  --finish-within never
```

The controller-derived local Secret name is the only secret value in the chart
values. The Deployment injects its `value` key as `GENEVE_TARGET_API_KEY`; it
injects the regular URL inputs as `GENEVE_TARGET_ES_URL` and
`GENEVE_TARGET_KIBANA_URL`. API-key references and payloads are never rendered
into ConfigMaps, arguments, logs, or output documents.

## Controller execution context

The controller supplies the execution ID and selected action through the reserved
`obvious.execution.id` and `obvious.execution.action` chart values. They are not
caller inputs. The Deployment exposes them to the tool as `OBVIOUS_EXECUTION_ID`
and `OBVIOUS_EXECUTION_ACTION`.

## Lifecycle

The deployment becomes ready only after it has fetched and prepared at least
one enabled allowlisted rule. If Kibana rate-limits a rule lookup, the generator
logs the delay and retries until the lookup succeeds; readiness remains pending
instead of the container restarting. It writes periodic output documents
containing rule-generation and bulk-ingestion counters. Because this tool is
intended to run continuously, execute it with `--finish-within never` and a
condition that will not ordinarily match, then stop it with `obc cancel`.

Build the image from the Geneve checkout. The image installs the temporary
`pipes-py` PR branch directly from Git:

```sh
docker build -f pipes/Dockerfile -t <image> .
```

The checked-in POC image reference is published to the Project Obvious Artifact
Registry. Future image versions must likewise be reachable by the Obvious
cluster before publishing the chart.
