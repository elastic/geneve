# Geneve Obvious tool POC

This level-set tool cycles through the 50 rule IDs in
`../../geneve_pipes/geneve-obvious-tool.yaml`. It generates one rule-trigger group per
second by default. A sequence rule can produce multiple source documents for
one trigger group.

The tool writes source documents only to the canonical Endpoint data streams
that the selected rule searches. Elasticsearch creates those data streams from
the installed integration templates on the first successful `create` write; the
tool creates no custom target index or template.

## Target-stack credential handoff

The Obvious controller supplies `obvious-output`, which only grants writes to
the tool's output data stream. It deliberately does not grant access to the
target stack. For this POC, after `obc execute` returns an execution ID, an
operator who has the local target credential file creates a namespaced Secret:

```sh
python geneve_pipes/create_target_stack_secret.py <execution-id> \
  --credentials ../creds.json
```

The helper creates `geneve-target-stack` in `obvious-exec-<execution-id>` from
standard input to `kubectl`; it does not expose secret values as chart inputs,
image content, command-line arguments, or logs. The controller deletes the
execution namespace, including this Secret, when the execution ends.

This is POC-only. A production tool needs controller-integrated, short-lived
credential delivery, such as a credential broker or External Secrets setup that
works for dynamic execution namespaces.

## Lifecycle

The deployment becomes ready only after it has fetched and prepared at least
one enabled allowlisted rule. It writes periodic output documents containing
rule-generation and bulk-ingestion counters. Because this tool is intended to
run continuously, execute it with `--finish-within never` and a condition that
will not ordinarily match, then stop it with `obc cancel`.

Build the image from the project directory so the unreleased `pipes-py` worktree
is included:

```sh
docker build -f geneve.git/geneve_pipes/Dockerfile -t <image> .
```

The checked-in POC image reference is published to the Project Obvious Artifact
Registry. Future image versions must likewise be reachable by the Obvious
cluster before publishing the chart.
