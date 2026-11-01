# Response

Backend: file. Model: Claude, Cursor agent session of 2026-11-01. The draft
committed in `stories/outlook-phish-to-ransomware.yaml` is this response
with no edits.

## Reasoning

The chain follows the affiliate playbook stage by stage, picking for each
tactic an emitting rule that is not already used by another story: initial
access "Suspicious MS Outlook Child Process", execution "Suspicious
Execution from INET Cache" (the attachment opened from the browser cache),
command and control "Network Connection via Registration Utility" (regsvr32
reaching a public `destination.ip`, binding the `c2` role), defense evasion
"Windows Defender Exclusions Added via PowerShell", persistence "Startup or
Run Key Registry Modification" (its `user.id` constraint only excludes the
system accounts), discovery "AdFind Command Activity", credential access
"Searching for Saved Credentials via VaultCmd", lateral movement "Service
Command Lateral Movement" (sc.exe against a remote host, whose network event
constrains `destination.ip` only to non-loopback, so the file server's
private address binds there), collection "Encrypting Files with WinRar or
7z", exfiltration "Potential Data Exfiltration via Rclone" and impact
"Volume Shadow Copy Deleted or Resized via VssAdmin".

Eleven required members over two hosts and one user: the accountant's
credentials carry the whole story, as is common when the account has local
admin on the file server. The optional member, "Potential Ransomware Note
File Dropped via SMB", is the encryptor's notes landing on the shares; it
exceeds Geneve's branch limit and is placed last so no required member
follows it. The timeline is the one of a hands-on intrusion: a minute
between dropper, callback and Defender tampering, half an hour of
discovery, an hour before the hop and before the exfiltration, three hours
of upload before the shadow copies go.

## Story

See `stories/outlook-phish-to-ransomware.yaml`.
