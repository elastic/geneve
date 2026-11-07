# Response

Backend: file. Model: Claude, Cursor agent session of 2026-11-01. The draft
committed in `stories/wordpress-to-winrm-pivot.yaml` is this response with
no edits.

## Reasoning

A Linux web server is the usual way into a mixed estate, and WinRM is the
usual way out of it: evil-winrm runs from Linux and lands on Windows as
"Incoming Execution via WinRM Remote Shell" (sequence by `host.id`: a
connection to 5985/5986 with a non-loopback `source.ip`, then a child of
winrshost.exe). That member binds the web server's address as `source.ip`
and the file server as `host.id`.

On the Linux side, "PHP File Creation in WordPress Plugin Directory" is the
web shell drop (a file event by the web server process), "Potential Reverse
Shell via Child" the shell it spawns (its network event constrains
`destination.ip` to a public address, binding the `c2` role) and "Potential
Linux Credential Dumping via Proc Filesystem" (ps then strings on /tmp)
is how the operations account's password is found. On the Windows side,
"Symbolic Link to Shadow Copy Created" is the classic way to lift the SAM
from a shadow copy and "Clearing Windows Event Logs" the exit.

Two user roles: the web server's service account on the Linux members, the
operations account on the Windows ones. The reverse shell follows the web
shell within a minute; the credential hunt and the pivot are manual and get
twenty minutes and an hour.

## Story

See `stories/wordpress-to-winrm-pivot.yaml`.
