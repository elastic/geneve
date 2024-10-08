# Documents generation from detection rules

This report captures the error reported while generating documents from detection rules. Here you
can learn what rules are still problematic and for which no documents can be generated at the moment.

Curious about the inner workings? Read [here](signals_generation.md).

Rules version: 8.3.4

## Table of contents
   1. [Skipped rules](#skipped-rules)
      1. [Unsupported rule type: machine_learning (47)](#unsupported-rule-type-machine_learning-47)
      1. [Unsupported rule type: threshold (17)](#unsupported-rule-type-threshold-17)
      1. [Unsupported query language: lucene (5)](#unsupported-query-language-lucene-5)
      1. [Unsupported rule type: threat_match (2)](#unsupported-rule-type-threat_match-2)
   1. [Generation errors](#generation-errors)
      1. [Unsupported function: match (8)](#unsupported-function-match-8)
      1. [Unsupported LHS type: <class 'eql.ast.FunctionCall'> (5)](#unsupported-lhs-type-class-eqlastfunctioncall-5)
      1. [Field type solver: match_only_text (3)](#field-type-solver-match_only_text-3)
      1. [Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)](#unsupported-keyword-processparentextrealpid-constraint--2)
      1. [Root with too many branches (limit: 10000) (1)](#root-with-too-many-branches-limit-10000-1)
      1. [Root without branches (1)](#root-without-branches-1)
      1. [Unsolvable constraints: event.category & event.type (empty intersection) (1)](#unsolvable-constraints-eventcategory--eventtype-empty-intersection-1)
      1. [Unsolvable constraints: http.request.body.content (not in Strings({'*/swip/Upload.ashx*'}): ('POST*')) (1)](#unsolvable-constraints-httprequestbodycontent-not-in-stringsswipuploadashx-post-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscopyfromscreen-systemdrawingbitmap-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'DumpCreds'}): ('DumpCerts')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsdumpcreds-dumpcerts-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'STARTUPINFOEX'}): ('UpdateProcThreadAttribute')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsstartupinfoex-updateprocthreadattribute-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'SetWindowsHookA'}): ('GetForegroundWindow')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssetwindowshooka-getforegroundwindow-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'System.IO.Compression.DeflateStream'}): ('FromBase64String')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssystemiocompressiondeflatestream-frombase64string-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsvirtualalloc-writeprocessmemory-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'shi1_netname'}): ('shi1_remark')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsshi1_netname-shi1_remark-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'waveInGetNumDevs'}): ('mciSendStringA')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringswaveingetnumdevs-mcisendstringa-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'msdt.exe'}): ('msdt.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsmsdtexe-msdtexe-1)
      1. [Unsolvable constraints: process.parent.args (excluded by Strings({'WdiSystemHost'}): ('WdiSystemHost')) (1)](#unsolvable-constraints-processparentargs-excluded-by-stringswdisystemhost-wdisystemhost-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringsrundll32exe-rundll32exe-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'winword.exe'}): ('winword.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringswinwordexe-winwordexe-1)
      1. [Unsolvable constraints: registry.path (excluded by Strings({'HKLM\SOFTWARE\Microsoft\Internet Explorer\Extensions\*\Script'}): ('*\Software\Microsoft\Internet Explorer\Extensions\*\Script')) (1)](#unsolvable-constraints-registrypath-excluded-by-stringshklmsoftwaremicrosoftinternet-explorerextensionsscript-softwaremicrosoftinternet-explorerextensionsscript-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*42B5FAAE-6536-11D2-AE5A-0000F87571E3*'}): ('*40B66650-4972-11D1-A7CA-0000F87571E3*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings42b5faae-6536-11d2-ae5a-0000f87571e3-40b66650-4972-11d1-a7ca-0000f87571e3-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings827d319e-6eac-11d2-a4ea-00c04f79f83a-803e14a0-b4fb-11d0-a0d0-00a0c90f574b-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*CAB54552-DEEA-4691-817E-ED4A4D1AFC72*'}): ('*AADCED64-746C-4633-A97C-D61349046527*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-stringscab54552-deea-4691-817e-ed4a4d1afc72-aadced64-746c-4633-a97c-d61349046527-1)
      1. [Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)](#unsupported-keyword-fileextentropy-constraint--1)
      1. [Unsupported argument type(s): <class 'eql.ast.FunctionCall'> (1)](#unsupported-argument-types-class-eqlastfunctioncall-1)

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

### Unsupported rule type: threshold (17)

17 rules:

* AWS IAM Brute Force of Assume Role Policy
* AWS Management Console Brute Force of Root User Identity
* Agent Spoofing - Multiple Hosts Using Same Agent
* Attempts to Brute Force a Microsoft 365 User Account
* Attempts to Brute Force an Okta User Account
* High Number of Okta User Password Reset or Unlock Attempts
* High Number of Process Terminations
* High Number of Process and/or Service Terminations
* Multiple Alerts Involving a User
* Multiple Alerts in Different ATT&CK Tactics on a Single Host
* O365 Excessive Single Sign-On Logon Errors
* Okta Brute Force or Password Spraying Attack
* Potential DNS Tunneling via NsLookup
* Potential LSASS Memory Dump via PssCaptureSnapShot
* Potential Password Spraying of Microsoft 365 User Accounts
* Potential macOS SSH Brute Force Detected
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

### Unsupported function: match (8)

8 rules:
* Abnormal Process ID or Lock File Created
* Creation of Hidden Files and Directories via CommandLine
* Executable File Creation with Multiple Extensions
* Masquerading Space After Filename
* Potential Credential Access via Windows Utilities
* Process Started from Process ID (PID) File
* Suspicious PowerShell Engine ImageLoad
* Suspicious service was installed in the system

### Unsupported LHS type: <class 'eql.ast.FunctionCall'> (5)

5 rules:
* AdminSDHolder SDProp Exclusion Added
* Image File Execution Options Injection
* NullSessionPipe Registry Modification
* Suspicious Execution - Short Program Name
* Suspicious Process Access via Direct System Call

### Field type solver: match_only_text (3)

3 rules:
* Account Configured with Never-Expiring Password
* Kerberos Pre-authentication Disabled for User
* Windows CryptoAPI Spoofing Vulnerability (CVE-2020-0601 - CurveBall)

### Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)

2 rules:
* Parent Process PID Spoofing
* Privileges Elevation via Parent Process PID Spoofing

### Root with too many branches (limit: 10000) (1)

1 rules:
* Execution from Unusual Directory - Command Line

### Root without branches (1)

1 rules:
* Persistence via Login or Logout Hook

### Unsolvable constraints: event.category & event.type (empty intersection) (1)

1 rules:
* Symbolic Link to Shadow Copy Created

### Unsolvable constraints: http.request.body.content (not in Strings({'*/swip/Upload.ashx*'}): ('POST*')) (1)

1 rules:
* SUNBURST Command and Control Activity

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)

1 rules:
* PowerShell Suspicious Script with Screenshot Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'DumpCreds'}): ('DumpCerts')) (1)

1 rules:
* Potential Invoke-Mimikatz PowerShell Script

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'STARTUPINFOEX'}): ('UpdateProcThreadAttribute')) (1)

1 rules:
* PowerShell Script with Token Impersonation Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'SetWindowsHookA'}): ('GetForegroundWindow')) (1)

1 rules:
* PowerShell Keylogging Script

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'System.IO.Compression.DeflateStream'}): ('FromBase64String')) (1)

1 rules:
* PowerShell Suspicious Payload Encoded and Compressed

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)

1 rules:
* Potential Process Injection via PowerShell

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'shi1_netname'}): ('shi1_remark')) (1)

1 rules:
* PowerShell Share Enumeration Script

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'waveInGetNumDevs'}): ('mciSendStringA')) (1)

1 rules:
* PowerShell Suspicious Script with Audio Capture Capabilities

### Unsolvable constraints: process.name (excluded by Strings({'msdt.exe'}): ('msdt.exe')) (1)

1 rules:
* Suspicious Microsoft Diagnostics Wizard Execution

### Unsolvable constraints: process.parent.args (excluded by Strings({'WdiSystemHost'}): ('WdiSystemHost')) (1)

1 rules:
* Unusual Service Host Child Process - Childless Service

### Unsolvable constraints: process.parent.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)

1 rules:
* Conhost Spawned By Suspicious Parent Process

### Unsolvable constraints: process.parent.name (excluded by Strings({'winword.exe'}): ('winword.exe')) (1)

1 rules:
* Suspicious Process Creation CallTrace

### Unsolvable constraints: registry.path (excluded by Strings({'HKLM\SOFTWARE\Microsoft\Internet Explorer\Extensions\*\Script'}): ('*\Software\Microsoft\Internet Explorer\Extensions\*\Script')) (1)

1 rules:
* Uncommon Registry Persistence Change

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*42B5FAAE-6536-11D2-AE5A-0000F87571E3*'}): ('*40B66650-4972-11D1-A7CA-0000F87571E3*')) (1)

1 rules:
* Startup/Logon Script added to Group Policy Object

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)

1 rules:
* Group Policy Abuse for Privilege Addition

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*CAB54552-DEEA-4691-817E-ED4A4D1AFC72*'}): ('*AADCED64-746C-4633-A97C-D61349046527*')) (1)

1 rules:
* Scheduled Task Execution at Scale via GPO

### Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)

1 rules:
* Suspicious HTML File Creation

### Unsupported argument type(s): <class 'eql.ast.FunctionCall'> (1)

1 rules:
* Remote Computer Account DnsHostName Update
