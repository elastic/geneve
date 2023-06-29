# Documents generation from detection rules

This report captures the error reported while generating documents from detection rules. Here you
can learn what rules are still problematic and for which no documents can be generated at the moment.

Curious about the inner workings? Read [here](signals_generation.md).

## Table of contents
   1. [Skipped rules](#skipped-rules)
      1. [Unsupported rule type: machine_learning (50)](#unsupported-rule-type-machine_learning-50)
      1. [Unsupported rule type: threshold (14)](#unsupported-rule-type-threshold-14)
      1. [Unsupported query language: lucene (6)](#unsupported-query-language-lucene-6)
      1. [Unsupported rule type: threat_match (3)](#unsupported-rule-type-threat_match-3)
   1. [Generation errors](#generation-errors)
      1. [Constraints solver not implemented: wildcard (44)](#constraints-solver-not-implemented-wildcard-44)
      1. [Root without branches (9)](#root-without-branches-9)
      1. [Unsupported function: match (5)](#unsupported-function-match-5)
      1. [Unsupported LHS type: <class 'eql.ast.FunctionCall'> (4)](#unsupported-lhs-type-class-eqlastfunctioncall-4)
      1. [Constraints solver not implemented: match_only_text (3)](#constraints-solver-not-implemented-match_only_text-3)
      1. [Unsupported &keyword 'file.Ext.windows.zone_identifier' constraint: > (2)](#unsupported-keyword-fileextwindowszone_identifier-constraint--2)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscopyfromscreen-systemdrawingbitmap-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'SetWindowsHookA'}): ('GetForegroundWindow')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssetwindowshooka-getforegroundwindow-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'System.IO.Compression.DeflateStream'}): ('FromBase64String')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssystemiocompressiondeflatestream-frombase64string-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsvirtualalloc-writeprocessmemory-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'waveInGetNumDevs'}): ('mciSendStringA')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringswaveingetnumdevs-mcisendstringa-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsrundll32exe-rundll32exe-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*42B5FAAE-6536-11D2-AE5A-0000F87571E3*'}): ('*40B66650-4972-11D1-A7CA-0000F87571E3*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings42b5faae-6536-11d2-ae5a-0000f87571e3-40b66650-4972-11d1-a7ca-0000f87571e3-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings827d319e-6eac-11d2-a4ea-00c04f79f83a-803e14a0-b4fb-11d0-a0d0-00a0c90f574b-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*CAB54552-DEEA-4691-817E-ED4A4D1AFC72*'}): ('*AADCED64-746C-4633-A97C-D61349046527*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-stringscab54552-deea-4691-817e-ed4a4d1afc72-aadced64-746c-4633-a97c-d61349046527-1)
      1. [Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (1)](#unsupported-keyword-processparentextrealpid-constraint--1)

## Skipped rules

### Unsupported rule type: machine_learning (50)

50 rules:

* Anomalous Kernel Module Activity
* Anomalous Linux Compiler Activity
* Anomalous Process For a Linux Population
* Anomalous Process For a Windows Population
* Anomalous Windows Process Creation
* DNS Tunneling
* Network Traffic to Rare Destination Country
* Rare AWS Error Code
* Rare User Logon
* Spike in AWS Error Messages
* Spike in Failed Logon Events
* Spike in Firewall Denies
* Spike in Logon Events
* Spike in Logon Events from a Source IP
* Spike in Network Traffic
* Spike in Network Traffic To a Country
* Suspicious Powershell Script
* Unusual AWS Command for a User
* Unusual City For an AWS Command
* Unusual Country For an AWS Command
* Unusual DNS Activity
* Unusual Hour for a User to Logon
* Unusual Linux Network Activity
* Unusual Linux Network Connection Discovery
* Unusual Linux Network Port Activity
* Unusual Linux Network Service
* Unusual Linux Process Calling the Metadata Service
* Unusual Linux Process Discovery Activity
* Unusual Linux System Information Discovery Activity
* Unusual Linux System Network Configuration Discovery
* Unusual Linux System Owner or User Discovery Activity
* Unusual Linux User Calling the Metadata Service
* Unusual Linux Username
* Unusual Linux Web Activity
* Unusual Login Activity
* Unusual Network Destination Domain Name
* Unusual Process For a Linux Host
* Unusual Process For a Windows Host
* Unusual Source IP for a User to Logon from
* Unusual Sudo Activity
* Unusual Web Request
* Unusual Web User Agent
* Unusual Windows Network Activity
* Unusual Windows Path Activity
* Unusual Windows Process Calling the Metadata Service
* Unusual Windows Remote User
* Unusual Windows Service
* Unusual Windows User Calling the Metadata Service
* Unusual Windows User Privilege Elevation Activity
* Unusual Windows Username

### Unsupported rule type: threshold (14)

14 rules:

* AWS IAM Brute Force of Assume Role Policy
* AWS Management Console Brute Force of Root User Identity
* Agent Spoofing - Multiple Hosts Using Same Agent
* Attempts to Brute Force a Microsoft 365 User Account
* Attempts to Brute Force an Okta User Account
* High Number of Okta User Password Reset or Unlock Attempts
* High Number of Process and/or Service Terminations
* O365 Excessive Single Sign-On Logon Errors
* Okta Brute Force or Password Spraying Attack
* Potential DNS Tunneling via NsLookup
* Potential LSASS Memory Dump via PssCaptureSnapShot
* Potential Password Spraying of Microsoft 365 User Accounts
* Potential SSH Brute Force Detected
* Sudo Heap-Based Buffer Overflow Attempt

### Unsupported query language: lucene (6)

6 rules:

* Cobalt Strike Command and Control Beacon
* Halfbaked Command and Control Beacon
* Inbound Connection to an Unsecure Elasticsearch Node
* Possible FIN7 DGA Command and Control Behavior
* Setgid Bit Set via chmod
* Setuid / Setgid Bit Set via chmod

### Unsupported rule type: threat_match (3)

3 rules:

* Threat Intel Filebeat Module (v7.x) Indicator Match
* Threat Intel Filebeat Module (v8.x) Indicator Match
* Threat Intel Indicator Match

## Generation errors

### Constraints solver not implemented: wildcard (44)

44 rules:
* Apple Scripting Execution with Administrator Privileges
* Attempt to Mount SMB Share via Command Line
* Attempt to Remove File Quarantine Attribute
* Command Shell Activity Started via RunDLL32
* Component Object Model Hijacking
* Control Panel Process with Unusual Arguments
* Creation of Hidden Login Item via Apple Script
* DNS-over-HTTPS Enabled via Registry
* Disabling User Account Control via Registry Modification
* Encoded Executable Stored in the Registry
* MS Office Macro Security Registry Modifications
* Microsoft Windows Defender Tampering
* Modification of AmsiEnable Registry Key
* Modification of WDigest Security Provider
* Network Logon Provider Registry Modification
* NullSessionPipe Registry Modification
* Persistence via WMI Standard Registry Provider
* Potential Persistence via Time Provider Modification
* Potential Port Monitor or Print Processor Registration Abuse
* Potential PrintNightmare Exploit Registry Modification
* Potential Privacy Control Bypass via Localhost Secure Copy
* Potential SharpRDP Behavior
* PowerShell Script Block Logging Disabled
* Privilege Escalation via Windir Environment Variable
* Prompt for Credentials with OSASCRIPT
* RDP Enabled via Registry
* Roshal Archive (RAR) or PowerShell File Downloaded from the Internet
* SIP Provider Modification
* SUNBURST Command and Control Activity
* Scheduled Tasks AT Command Enabled
* SolarWinds Process Disabling Services via Registry
* Startup or Run Key Registry Modification
* Suspicious Browser Child Process
* Suspicious ImagePath Service Creation
* Suspicious Print Spooler Point and Print DLL
* Suspicious Startup Shell Folder Modification
* Suspicious WMIC XSL Script Execution
* Symbolic Link to Shadow Copy Created
* Uncommon Registry Persistence Change
* Unusual Persistence via Services Registry
* Unusual Print Spooler Child Process
* Virtual Private Network Connection Attempt
* Web Application Suspicious Activity: No User Agent
* Windows Defender Disabled via Registry Modification

### Root without branches (9)

9 rules:
* Linux Restricted Shell Breakout via c89/c99 Shell evasion
* Linux Restricted Shell Breakout via cpulimit Shell Evasion
* Linux Restricted Shell Breakout via flock Shell evasion
* Linux Restricted Shell Breakout via the expect command
* Linux Restricted Shell Breakout via the find command
* Linux Restricted Shell Breakout via the gcc command
* Linux Restricted Shell Breakout via the ssh command
* Linux Restricted Shell Breakout via the vi command
* Persistence via Login or Logout Hook

### Unsupported function: match (5)

5 rules:
* Creation of Hidden Files and Directories
* Executable File Creation with Multiple Extensions
* Potential Credential Access via Windows Utilities
* Suspicious PowerShell Engine ImageLoad
* Whitespace Padding in Process Command Line

### Unsupported LHS type: <class 'eql.ast.FunctionCall'> (4)

4 rules:
* AdminSDHolder SDProp Exclusion Added
* Image File Execution Options Injection
* Suspicious Execution - Short Program Name
* Suspicious Process Access via Direct System Call

### Constraints solver not implemented: match_only_text (3)

3 rules:
* Account configured with never Expiring Password
* Kerberos Pre-authentication Disabled for User
* Windows CryptoAPI Spoofing Vulnerability (CVE-2020-0601 - CurveBall)

### Unsupported &keyword 'file.Ext.windows.zone_identifier' constraint: > (2)

2 rules:
* Downloaded Shortcut Files
* Downloaded URL Files

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)

1 rules:
* PowerShell Suspicious Script with Screenshot Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'SetWindowsHookA'}): ('GetForegroundWindow')) (1)

1 rules:
* PowerShell Keylogging Script

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'System.IO.Compression.DeflateStream'}): ('FromBase64String')) (1)

1 rules:
* PowerShell Suspicious Payload Encoded and Compressed

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)

1 rules:
* Potential Process Injection via PowerShell

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'waveInGetNumDevs'}): ('mciSendStringA')) (1)

1 rules:
* PowerShell Suspicious Script with Audio Capture Capabilities

### Unsolvable constraints: process.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)

1 rules:
* Execution from Unusual Directory - Command Line

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*42B5FAAE-6536-11D2-AE5A-0000F87571E3*'}): ('*40B66650-4972-11D1-A7CA-0000F87571E3*')) (1)

1 rules:
* Startup/Logon Script added to Group Policy Object

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)

1 rules:
* Group Policy Abuse for Privilege Addition

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*CAB54552-DEEA-4691-817E-ED4A4D1AFC72*'}): ('*AADCED64-746C-4633-A97C-D61349046527*')) (1)

1 rules:
* Scheduled Task Execution at Scale via GPO

### Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (1)

1 rules:
* Parent Process PID Spoofing
