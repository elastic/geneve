# Documents generation from detection rules

This report captures the error reported while generating documents from detection rules. Here you
can learn what rules are still problematic and for which no documents can be generated at the moment.

Curious about the inner workings? Read [here](signals_generation.md).

Rules version: 8.2.1

## Table of contents
   1. [Skipped rules](#skipped-rules)
      1. [Unsupported rule type: machine_learning (47)](#unsupported-rule-type-machine_learning-47)
      1. [Unsupported rule type: threshold (15)](#unsupported-rule-type-threshold-15)
      1. [Unsupported query language: lucene (5)](#unsupported-query-language-lucene-5)
      1. [Unsupported rule type: threat_match (2)](#unsupported-rule-type-threat_match-2)
   1. [Generation errors](#generation-errors)
      1. [Unsupported function: match (6)](#unsupported-function-match-6)
      1. [Field type solver: match_only_text (5)](#field-type-solver-match_only_text-5)
      1. [Unsupported LHS type: <class 'eql.ast.FunctionCall'> (4)](#unsupported-lhs-type-class-eqlastfunctioncall-4)
      1. [Root with too many branches (limit: 10000) (1)](#root-with-too-many-branches-limit-10000-1)
      1. [Root without branches (1)](#root-without-branches-1)
      1. [Unsolvable constraints: http.request.body.content (not in Strings({'*/swip/Upload.ashx*'}): ('POST*')) (1)](#unsolvable-constraints-httprequestbodycontent-not-in-stringsswipuploadashx-post-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscopyfromscreen-systemdrawingbitmap-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'System.IO.Compression.DeflateStream'}): ('FromBase64String')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssystemiocompressiondeflatestream-frombase64string-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsvirtualalloc-writeprocessmemory-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings827d319e-6eac-11d2-a4ea-00c04f79f83a-803e14a0-b4fb-11d0-a0d0-00a0c90f574b-1)
      1. [Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)](#unsupported-keyword-fileextentropy-constraint--1)
      1. [Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (1)](#unsupported-keyword-processparentextrealpid-constraint--1)

## Skipped rules

### Unsupported rule type: machine_learning (47)

47 rules:

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
* Unusual Linux Process Calling the Metadata Service
* Unusual Linux Process Discovery Activity
* Unusual Linux System Information Discovery Activity
* Unusual Linux System Network Configuration Discovery
* Unusual Linux System Owner or User Discovery Activity
* Unusual Linux User Calling the Metadata Service
* Unusual Linux Username
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

### Unsupported rule type: threshold (15)

15 rules:

* AWS IAM Brute Force of Assume Role Policy
* AWS Management Console Brute Force of Root User Identity
* Agent Spoofing - Multiple Hosts Using Same Agent
* Attempts to Brute Force a Microsoft 365 User Account
* Attempts to Brute Force an Okta User Account
* High Number of Okta User Password Reset or Unlock Attempts
* High Number of Process Terminations
* High Number of Process and/or Service Terminations
* O365 Excessive Single Sign-On Logon Errors
* Okta Brute Force or Password Spraying Attack
* Potential DNS Tunneling via NsLookup
* Potential LSASS Memory Dump via PssCaptureSnapShot
* Potential Password Spraying of Microsoft 365 User Accounts
* Potential SSH Brute Force Detected
* Sudo Heap-Based Buffer Overflow Attempt

### Unsupported query language: lucene (5)

5 rules:

* Cobalt Strike Command and Control Beacon
* Halfbaked Command and Control Beacon
* Inbound Connection to an Unsecure Elasticsearch Node
* Possible FIN7 DGA Command and Control Behavior
* Setuid / Setgid Bit Set via chmod

### Unsupported rule type: threat_match (2)

2 rules:

* Threat Intel Filebeat Module (v8.x) Indicator Match
* Threat Intel Indicator Match

## Generation errors

### Unsupported function: match (6)

6 rules:
* Abnormal Process ID or Lock File Created
* Creation of Hidden Files and Directories via CommandLine
* Executable File Creation with Multiple Extensions
* Potential Credential Access via Windows Utilities
* Process Started from Process ID (PID) File
* Suspicious PowerShell Engine ImageLoad

### Field type solver: match_only_text (5)

5 rules:
* Account Configured with Never-Expiring Password
* Kerberos Pre-authentication Disabled for User
* Scheduled Task Execution at Scale via GPO
* Startup/Logon Script added to Group Policy Object
* Windows CryptoAPI Spoofing Vulnerability (CVE-2020-0601 - CurveBall)

### Unsupported LHS type: <class 'eql.ast.FunctionCall'> (4)

4 rules:
* AdminSDHolder SDProp Exclusion Added
* Image File Execution Options Injection
* Suspicious Execution - Short Program Name
* Suspicious Process Access via Direct System Call

### Root with too many branches (limit: 10000) (1)

1 rules:
* Execution from Unusual Directory - Command Line

### Root without branches (1)

1 rules:
* Persistence via Login or Logout Hook

### Unsolvable constraints: http.request.body.content (not in Strings({'*/swip/Upload.ashx*'}): ('POST*')) (1)

1 rules:
* SUNBURST Command and Control Activity

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)

1 rules:
* PowerShell Suspicious Script with Screenshot Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'System.IO.Compression.DeflateStream'}): ('FromBase64String')) (1)

1 rules:
* PowerShell Suspicious Payload Encoded and Compressed

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)

1 rules:
* Potential Process Injection via PowerShell

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)

1 rules:
* Group Policy Abuse for Privilege Addition

### Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)

1 rules:
* Suspicious HTML File Creation

### Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (1)

1 rules:
* Parent Process PID Spoofing
