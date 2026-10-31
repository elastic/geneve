# Response

Backend: file. Model: Claude, Cursor agent session of 2026-10-31. The draft
committed in `stories/office-macro-to-ransomware.yaml` is this response with
no edits.

## Reasoning

Windows initial-access rules that Geneve emits are dominated by product
specific child-process rules (SolarWinds, Exchange, PaperCut). The classic
phishing entry, "Suspicious MS Office Child Process", fails in Geneve with an
unsolvable `process.name` constraint, so it is kept as the optional member
and "Execution of File Written or Modified by Microsoft Office" (emits,
carries `host.id`) is the working entry.

The chain follows a common ransomware playbook: download via script
interpreter (sequence by `process.entity_id`, carries `destination.ip` for the
C2 role), LSASS dump, lateral movement to a second host via the Task Scheduler
RPC interface (sequence by `host.id, process.entity_id`, carries `source.ip`
which is the workstation's address: a cross-field binding), then shadow copy
deletion on the file server.

`user.id` is bound to the clerk on every member even though no member
constrains it; whether the alerts will carry it is for the assessment to say.

## Story

See `stories/office-macro-to-ransomware.yaml`.
