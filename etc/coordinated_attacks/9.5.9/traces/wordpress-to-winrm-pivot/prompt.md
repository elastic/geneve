# Prompt (reconstructed)

This is the brief the story was authored from. It was not rendered by the
`propose` runner, which does not exist yet: the author (an AI session) worked
from the inventory and the request below. Future traces are rendered from
prompt templates and this file is replaced by the rendered prompt.

## Request

Design one attack story for Elastic Security pre-built rules, version 9.5.9,
mixed Linux and Windows endpoints, medium size (4–6 alerts, 2 hosts),
realistic and plausible: the story starts on a Linux host and moves to a
Windows host, with members on both platforms (each constraining its own
`host.os.type`) and the Linux host bound as `source.ip` of the Windows
member it reaches. Use only rules that Geneve can emit (status `ok` in
`inventory.json`). For each member give the kill-chain stage, the host role
and which entity each of `host.id`, `user.id`, `source.ip`, `destination.ip`
binds to. Give relative timing between members. State the expected alert
count.

## Inputs

- `etc/coordinated_attacks/9.5.9/inventory.json` (rules, tags, tactics, Geneve status, solved fields)
- Story draft format as in `stories/*.yaml`
