# Prompt (reconstructed)

This is the brief the story was authored from. It was not rendered by the
`propose` runner, which does not exist yet: the author (an AI session) worked
from the inventory and the request below. Future traces are rendered from
prompt templates and this file is replaced by the rendered prompt.

## Request

Design one attack story for Elastic Security pre-built rules, version 9.5.9,
Windows endpoint, small size (exactly 2 alerts, 1 host), realistic and
plausible: the shortest story that still has a timeline and an external
entity. Use only rules that Geneve can emit (status `ok` in
`inventory.json`). For each member give the kill-chain stage, the host role
and which entity each of `host.id`, `user.id`, `source.ip`, `destination.ip`
binds to. Give relative timing between members. State the expected alert
count.

## Inputs

- `etc/coordinated_attacks/9.5.9/inventory.json` (rules, tags, tactics, Geneve status, solved fields)
- Story draft format as in `stories/*.yaml`
