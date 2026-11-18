# Response

Backend: file. Model: Claude, Cursor agent session of 2026-11-01. The draft
committed in `stories/workstation-to-domain-controller.yaml` is this
response with no edits.

## Reasoning

The two hops need two incoming lateral movement rules that constrain
`source.ip` and emit. "Incoming Execution via PowerShell Remoting" (sequence
by `host.id`: WinRM connection then a child of wsmprovhost.exe) is how an
administrator reaches a jump host, so it carries the workstation's address.
"Remotely Started Services via RPC" (services.exe accepting an RPC
connection then starting a child) is the PsExec-like move onto the domain
controller, so it carries the jump host's address. Both join on `host.id`,
which the backpack pins.

On the workstation the entry is "Suspicious PDF Reader Child Process" and the
callback "Network Connection via Signed Binary" (a sequence whose network
event constrains `destination.ip` to a public address, binding the `c2`
role); "Enumeration of Administrator Accounts" explains how the operator
learns about the jump host and the domain admins. "Credential Acquisition
via Registry Hive Dumping" on the jump host yields the domain admin's cached
credentials; "NTDS or SAM Database File Copied" is the goal on the domain
controller. "Potential Lateral Tool Transfer via SMB Share" was considered
for the second hop and rejected: it constrains `user.id` to a SID pattern
that the numeric role id would contradict.

Two user roles: the IT administrator plays the workstation and the jump
host, the domain admin plays the domain controller. `host.name` is glued on
the first member of every host so the alerts name the machines. The optional
member, "LSASS Memory Dump Handle Access", is the other credential theft an
operator would try on the jump host; it is a `new_terms` rule, which Geneve
does not emit. The windows grow along the chain: seconds for the callback,
tens of minutes for the operator's manual steps, an hour before the last
hop.

## Story

See `stories/workstation-to-domain-controller.yaml`.
