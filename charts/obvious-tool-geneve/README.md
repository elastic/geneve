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

## Run Geneve

[Set up the `obc` CLI and remote first.](https://github.com/elastic/obvious-controller/blob/main/docs/cli.md)
This guide covers the Geneve-specific target preparation and execution steps.

### Prepare target-stack access

Target-stack access is supplied by three required inputs:

- `target_es_url`: the Elasticsearch URL as a regular string input.
- `target_kibana_url`: the Kibana URL as a regular string input.
- `target_api_key`: a Google Secret Manager (GSM) `secret_ref` input.

Create a target-stack API key with permission to read Kibana Detection Engine
rules and create documents in the configured Endpoint data streams. Store only
the encoded API-key value in GSM; keep URLs and YAML outside GSM.

```sh
export GSM_PROJECT_NUMBER=<gcp-project-number>
export GENEVE_TARGET_API_KEY_SECRET=<secret-name>
gcloud secrets create "$GENEVE_TARGET_API_KEY_SECRET" \
  --project="$GSM_PROJECT_NUMBER" \
  --replication-policy=automatic
read -r -s -p 'Encoded target-stack API key: ' GENEVE_TARGET_API_KEY
printf '\n'
printf %s "$GENEVE_TARGET_API_KEY" \
  | gcloud secrets versions add "$GENEVE_TARGET_API_KEY_SECRET" \
      --project="$GSM_PROJECT_NUMBER" --data-file=-
unset GENEVE_TARGET_API_KEY
```

Grant the identity used by the selected `obc` remote access to that one secret.
Obtaining the principal from `obc` avoids copying or wrapping it incorrectly:

```sh
export OBC_REMOTE=<remote>
ACTOR_PRINCIPAL=$(obc -r "$OBC_REMOTE" auth status -o json \
  | jq -r '.actor_gcp_identity.principal')
test -n "$ACTOR_PRINCIPAL" && test "$ACTOR_PRINCIPAL" != null
gcloud secrets add-iam-policy-binding \
  "projects/$GSM_PROJECT_NUMBER/secrets/$GENEVE_TARGET_API_KEY_SECRET" \
  --member="$ACTOR_PRINCIPAL" \
  --role=roles/secretmanager.secretAccessor
```

The controller uses that actor identity to have External Secrets Operator
materialize a per-execution local Secret, waits for it before installing the
chart, and removes it with the execution namespace during cleanup. The
Deployment receives its `value` key as `GENEVE_TARGET_API_KEY`; the API-key
payload is never rendered into chart values, ConfigMaps, arguments, or logs.

### Prepare the rule catalog

Use an authorized LLM or operator to manage rules only on a dedicated
Geneve/test target. Ask it to select an approximately 400-rule cohort of
Detection Engine `query` rules using EQL or Kuery, enable that cohort, and
disable rules outside it.

Do not put that cohort's IDs in the execution request. With no `rule_ids`
input, the published tool retrieves every currently enabled rule from Kibana
and passes all of them to Geneve. This is why the enabled catalog must remain
bounded.

### Start, inspect, and stop

Use the published `obvious-tool-geneve:0.6.0-alpha` chart and its `alerts`
action. For a continuous execution, create a request such as:

```yaml
chart: oci://us-central1-docker.pkg.dev/sec-eng-prod/geneve/obvious-tool-geneve:0.6.0-alpha
action: alerts
inputs:
  triggers_per_second: 5
  target_es_url: https://<deployment>.es.<region>.gcp.elastic-cloud.com:443
  target_kibana_url: https://<deployment>.kb.<region>.gcp.elastic-cloud.com
  target_api_key: projects/<gcp-project-number>/secrets/<secret-name>
finish_within: never
```

Start it and retain the reported execution ID:

```sh
obc -r "$OBC_REMOTE" execute --file geneve.yaml
obc -r "$OBC_REMOTE" status <execution-id>
obc -r "$OBC_REMOTE" cancel --yes <execution-id>
```

## Lifecycle

The deployment becomes ready only after it has retrieved and prepared at least
one enabled rule. The Kibana rules pipe records the selected raw rules in state
before the generator starts; readiness remains pending if selection or
preparation cannot produce a usable rule. The continuous workload requests
1 GiB and is limited to 4 GiB of memory. Per-rule preparation or generation
errors are logged and skipped; an OOM kill, readiness timeout, or
ExternalSecret synchronization failure requires investigation before retrying.

## Logs

The Pipes runtime emits ECS JSON to the container's stdout and stderr. The
Obvious cluster log collector routes each execution to
`kubernetes.container_logs.obvious_tool_geneve`; it promotes standard ECS
logging fields such as `message` and `log.level`. In Kibana, filter that dataset
and `kubernetes.labels.obvious_io_execution_id` for the execution ID. The log
stream contains operational diagnostics only: neither the target API-key
reference nor its payload is logged.
