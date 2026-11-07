# Response

Backend: file. Model: Claude, Cursor agent session of 2026-11-01. The draft
committed in `stories/exposed-server-brute-force.yaml` is this response with
no edits.

## Reasoning

The Windows rules that constrain `source.ip` are the incoming lateral
movement sequences (RPC, WinRM, DCOM, SMB) and the Security log
authentication sequences. The latter fit an external attacker: "Multiple
Logon Failure Followed by Logon Success" is a sequence by
`winlog.computer_name, source.ip` of five network logon failures and one
success, with `user.name` constrained (not anonymous, not a machine account)
so the brute-forced account binds by name, and `source.ip` constrained
(non-loopback) so the attacker's public address binds there. The same
address appears again in "Remote Windows Service Installed", whose first
event is the network logon that precedes the service installation.

The last two members are what a ransomware affiliate does once the service
runs the payload: "Windows Defender Disabled via Registry Modification"
(where `user.id` is constrained inside a negated conjunction, which the
numeric role id satisfies) and "Volume Shadow Copy Deletion via PowerShell",
the only shadow copy rule not yet used by another story.

The SMB brute force rules themselves (threshold, ES|QL) cannot be emitted and
would be T3 in the ladder, so no optional member is kept. Windows user ids
are SIDs in real logs and the role gives a numeric id; the existing stories
make the same compromise.

## Story

See `stories/exposed-server-brute-force.yaml`.
