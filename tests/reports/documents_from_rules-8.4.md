# Documents generation from detection rules

This report captures the error reported while generating documents from detection rules. Here you
can learn what rules are still problematic and for which no documents can be generated at the moment.

Curious about the inner workings? Read [here](signals_generation.md).

Rules version: 8.4.5

## Table of contents
   1. [Skipped rules](#skipped-rules)
      1. [Unsupported rule type: machine_learning (47)](#unsupported-rule-type-machine_learning-47)
      1. [Unsupported rule type: threshold (17)](#unsupported-rule-type-threshold-17)
      1. [Unsupported query language: lucene (5)](#unsupported-query-language-lucene-5)
      1. [Unsupported rule type: new_terms (3)](#unsupported-rule-type-new_terms-3)
      1. [Unsupported rule type: threat_match (2)](#unsupported-rule-type-threat_match-2)
   1. [Generation errors](#generation-errors)
      1. [Unsupported function: match (9)](#unsupported-function-match-9)
      1. [Unsupported LHS type: <class 'eql.ast.FunctionCall'> (6)](#unsupported-lhs-type-class-eqlastfunctioncall-6)
      1. [Field type solver: match_only_text (5)](#field-type-solver-match_only_text-5)
      1. [Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)](#unsupported-keyword-processparentextrealpid-constraint--2)
      1. [Root with too many branches (limit: 10000) (1)](#root-with-too-many-branches-limit-10000-1)
      1. [Unsolvable constraints: http.request.body.content (not in Strings({'*/swip/Upload.ashx*'}): ('POST*')) (1)](#unsolvable-constraints-httprequestbodycontent-not-in-stringsswipuploadashx-post-1)
      1. [Unsolvable constraints: kubernetes.audit.requestObject.spec.containers.image (cannot be null) (1)](#unsolvable-constraints-kubernetesauditrequestobjectspeccontainersimage-cannot-be-null-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscopyfromscreen-systemdrawingbitmap-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Cryptography.AESManaged'}): ('CipherMode')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscryptographyaesmanaged-ciphermode-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'System.IO.Compression.DeflateStream'}): ('FromBase64String')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssystemiocompressiondeflatestream-frombase64string-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsvirtualalloc-writeprocessmemory-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings827d319e-6eac-11d2-a4ea-00c04f79f83a-803e14a0-b4fb-11d0-a0d0-00a0c90f574b-1)
      1. [Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: <= (1)](#unsupported-keyword-dllextrelative_file_creation_time-constraint--1)
      1. [Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)](#unsupported-keyword-fileextentropy-constraint--1)
      1. [Unsupported argument type(s): <class 'eql.ast.Field'> (1)](#unsupported-argument-types-class-eqlastfield-1)
      1. [Unsupported argument type(s): <class 'eql.ast.FunctionCall'> (1)](#unsupported-argument-types-class-eqlastfunctioncall-1)
      1. [Unsupported argument type: <class 'eql.ast.FunctionCall'> (1)](#unsupported-argument-type-class-eqlastfunctioncall-1)

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
* Spike in Network Traffic
* Spike in Network Traffic To a Country
* Spike in Successful Logon Events from a Source IP
* Suspicious Powershell Script
* Unusual AWS Command for a User
* Unusual City For an AWS Command
* Unusual Country For an AWS Command
* Unusual DNS Activity
* Unusual Hour for a User to Logon
* Unusual Linux Network Activity
* Unusual Linux Network Configuration Discovery
* Unusual Linux Network Connection Discovery
* Unusual Linux Network Port Activity
* Unusual Linux Process Calling the Metadata Service
* Unusual Linux Process Discovery Activity
* Unusual Linux System Information Discovery Activity
* Unusual Linux User Calling the Metadata Service
* Unusual Linux User Discovery Activity
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

### Unsupported rule type: new_terms (3)

3 rules:

* First Time Seen Google Workspace OAuth Login from Third-Party Application
* FirstTime Seen Account Performing DCSync
* Potential Pass-the-Hash (PtH) Attempt

### Unsupported rule type: threat_match (2)

2 rules:

* Threat Intel Filebeat Module (v8.x) Indicator Match
* Threat Intel Indicator Match

## Generation errors

### Unsupported function: match (9)

9 rules:
* Abnormal Process ID or Lock File Created
* Creation of Hidden Files and Directories via CommandLine
* Executable File Creation with Multiple Extensions
* Masquerading Space After Filename
* Potential Credential Access via Windows Utilities
* Process Started from Process ID (PID) File
* Suspicious Execution via Microsoft Office Add-Ins
* Suspicious PowerShell Engine ImageLoad
* Suspicious service was installed in the system

### Unsupported LHS type: <class 'eql.ast.FunctionCall'> (6)

6 rules:
* AdminSDHolder SDProp Exclusion Added
* Image File Execution Options Injection
* Ingress Transfer via Windows BITS
* NullSessionPipe Registry Modification
* Suspicious Execution - Short Program Name
* Suspicious Process Access via Direct System Call

### Field type solver: match_only_text (5)

5 rules:
* Account Configured with Never-Expiring Password
* Kerberos Pre-authentication Disabled for User
* Scheduled Task Execution at Scale via GPO
* Startup/Logon Script added to Group Policy Object
* Windows CryptoAPI Spoofing Vulnerability (CVE-2020-0601 - CurveBall)

### Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)

2 rules:
* Parent Process PID Spoofing
* Privileges Elevation via Parent Process PID Spoofing

### Root with too many branches (limit: 10000) (1)

1 rules:
* Execution from Unusual Directory - Command Line

### Unsolvable constraints: http.request.body.content (not in Strings({'*/swip/Upload.ashx*'}): ('POST*')) (1)

1 rules:
* SUNBURST Command and Control Activity

### Unsolvable constraints: kubernetes.audit.requestObject.spec.containers.image (cannot be null) (1)

1 rules:
* Kubernetes Container Created with Excessive Linux Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)

1 rules:
* PowerShell Suspicious Script with Screenshot Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Cryptography.AESManaged'}): ('CipherMode')) (1)

1 rules:
* PowerShell Script with Encryption/Decryption Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'System.IO.Compression.DeflateStream'}): ('FromBase64String')) (1)

1 rules:
* PowerShell Suspicious Payload Encoded and Compressed

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)

1 rules:
* Potential Process Injection via PowerShell

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)

1 rules:
* Group Policy Abuse for Privilege Addition

### Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: <= (1)

1 rules:
* Unsigned DLL Loaded by Svchost

### Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)

1 rules:
* Suspicious HTML File Creation

### Unsupported argument type(s): <class 'eql.ast.Field'> (1)

1 rules:
* External User Added to Google Workspace Group

### Unsupported argument type(s): <class 'eql.ast.FunctionCall'> (1)

1 rules:
* Remote Computer Account DnsHostName Update

### Unsupported argument type: <class 'eql.ast.FunctionCall'> (1)

1 rules:
* Unsigned DLL Side-Loading from a Suspicious Folder
