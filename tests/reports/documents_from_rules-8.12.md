# Documents generation from detection rules

This report captures the error reported while generating documents from detection rules. Here you
can learn what rules are still problematic and for which no documents can be generated at the moment.

Curious about the inner workings? Read [here](signals_generation.md).

Rules version: 8.12.26

## Table of contents
   1. [Skipped rules](#skipped-rules)
      1. [Unsupported rule type: machine_learning (72)](#unsupported-rule-type-machine_learning-72)
      1. [Unsupported rule type: new_terms (72)](#unsupported-rule-type-new_terms-72)
      1. [Unsupported rule type: threshold (30)](#unsupported-rule-type-threshold-30)
      1. [Unsupported rule type: threat_match (5)](#unsupported-rule-type-threat_match-5)
      1. [Unsupported query language: lucene (4)](#unsupported-query-language-lucene-4)
      1. [Unsupported rule type: esql (3)](#unsupported-rule-type-esql-3)
   1. [Generation errors](#generation-errors)
      1. [Root with too many branches (limit: 10000) (15)](#root-with-too-many-branches-limit-10000-15)
      1. [Unsupported LHS type: <class 'eql.ast.FunctionCall'> (12)](#unsupported-lhs-type-class-eqlastfunctioncall-12)
      1. [Unsupported function: stringContains (12)](#unsupported-function-stringcontains-12)
      1. [Unsupported function: match (11)](#unsupported-function-match-11)
      1. [Unsupported argument type(s): <class 'eql.ast.Field'> (6)](#unsupported-argument-types-class-eqlastfield-6)
      1. [Root without branches (4)](#root-without-branches-4)
      1. [<class 'eql.ast.Sample'> (3)](#class-eqlastsample-3)
      1. [Unsupported &keyword 'file.Ext.windows.zone_identifier' constraint: > (3)](#unsupported-keyword-fileextwindowszone_identifier-constraint--3)
      1. [Unsupported argument type: <class 'eql.ast.FunctionCall'> (3)](#unsupported-argument-type-class-eqlastfunctioncall-3)
      1. [Unsupported function: startsWith (3)](#unsupported-function-startswith-3)
      1. [Pipes are unsupported (2)](#pipes-are-unsupported-2)
      1. [Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)](#unsupported-keyword-processparentextrealpid-constraint--2)
      1. [Unsupported function: endswith (2)](#unsupported-function-endswith-2)
      1. [<class 'eql.ast.SubqueryBy'> (1)](#class-eqlastsubqueryby-1)
      1. [Cannot choose from an empty set (1)](#cannot-choose-from-an-empty-set-1)
      1. [Unsolvable constraints: aws.cloudtrail.request_parameters (not in Strings({'*LifecycleConfiguration*'}): ('*Expiration=*')) (1)](#unsolvable-constraints-awscloudtrailrequest_parameters-not-in-stringslifecycleconfiguration-expiration-1)
      1. [Unsolvable constraints: aws.cloudtrail.request_parameters (not in Strings({'*attribute=userData*'}): ('*instanceId*')) (1)](#unsolvable-constraints-awscloudtrailrequest_parameters-not-in-stringsattributeuserdata-instanceid-1)
      1. [Unsolvable constraints: aws.cloudtrail.request_parameters (not in Strings({'*imageId*'}): ('*add*')) (1)](#unsolvable-constraints-awscloudtrailrequest_parameters-not-in-stringsimageid-add-1)
      1. [Unsolvable constraints: aws.cloudtrail.request_parameters (not in Strings({'*lambda:InvokeFunction*'}): ('*principal=**')) (1)](#unsolvable-constraints-awscloudtrailrequest_parameters-not-in-stringslambdainvokefunction-principal-1)
      1. [Unsolvable constraints: file.extension (cannot be non-null) (1)](#unsolvable-constraints-fileextension-cannot-be-non-null-1)
      1. [Unsolvable constraints: http.request.body.content (not in Strings({'*/swip/Upload.ashx*'}): ('POST*')) (1)](#unsolvable-constraints-httprequestbodycontent-not-in-stringsswipuploadashx-post-1)
      1. [Unsolvable constraints: kubernetes.audit.requestObject.spec.containers.image (cannot be null) (1)](#unsolvable-constraints-kubernetesauditrequestobjectspeccontainersimage-cannot-be-null-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscopyfromscreen-systemdrawingbitmap-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Cryptography.AESManaged'}): ('CipherMode')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscryptographyaesmanaged-ciphermode-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Invoke-WmiMethod'}): ('ComputerName')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsinvoke-wmimethod-computername-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'LsaCallAuthenticationPackage'}): ('KerbRetrieveEncodedTicketMessage')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringslsacallauthenticationpackage-kerbretrieveencodedticketmessage-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Set-MpPreference'}): ('DisableArchiveScanning')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsset-mppreference-disablearchivescanning-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'System.IO.Compression.DeflateStream'}): ('FromBase64String')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssystemiocompressiondeflatestream-frombase64string-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsvirtualalloc-writeprocessmemory-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[string]::join'}): ('$pSHoMe[')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsstringjoin-pshome-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*drive.google.com*'}): ('*export=download*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsdrivegooglecom-exportdownload-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*'}): ('*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings1131f6ad-9c07-11d1-f79f-00c04fc2dcd2s-1-5-21--1131f6aa-9c07-11d1-f79f-00c04fc2dcd2s-1-5-21--1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings827d319e-6eac-11d2-a4ea-00c04f79f83a-803e14a0-b4fb-11d0-a0d0-00a0c90f574b-1)
      1. [Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: < (1)](#unsupported-keyword-dllextrelative_file_creation_time-constraint--1)
      1. [Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: <= (1)](#unsupported-keyword-dllextrelative_file_creation_time-constraint--1)
      1. [Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)](#unsupported-keyword-fileextentropy-constraint--1)
      1. [Unsupported &keyword 'ml_is_dga.malicious_probability' constraint: > (1)](#unsupported-keyword-ml_is_dgamalicious_probability-constraint--1)
      1. [Unsupported &keyword 'problemchild.prediction_probability' constraint: <= (1)](#unsupported-keyword-problemchildprediction_probability-constraint--1)
      1. [Unsupported &keyword 'problemchild.prediction_probability' constraint: > (1)](#unsupported-keyword-problemchildprediction_probability-constraint--1)
      1. [Unsupported &keyword 'process.Ext.relative_file_creation_time' constraint: <= (1)](#unsupported-keyword-processextrelative_file_creation_time-constraint--1)
      1. [Unsupported &keyword 'user.id' constraint: >= (1)](#unsupported-keyword-userid-constraint--1)
      1. [Unsupported argument type(s): <class 'eql.ast.FunctionCall'> (1)](#unsupported-argument-types-class-eqlastfunctioncall-1)
      1. [Unsupported is_negated: {'is_negated': True} (1)](#unsupported-is_negated-is_negated-true-1)

## Skipped rules

### Unsupported rule type: machine_learning (72)

72 rules:

* Anomalous Linux Compiler Activity
* Anomalous Process For a Linux Population
* Anomalous Process For a Windows Population
* Anomalous Windows Process Creation
* DNS Tunneling
* High Mean of Process Arguments in an RDP Session
* High Mean of RDP Session Duration
* High Variance in RDP Session Duration
* Network Traffic to Rare Destination Country
* Potential DGA Activity
* Potential Data Exfiltration Activity to an Unusual Destination Port
* Potential Data Exfiltration Activity to an Unusual IP Address
* Potential Data Exfiltration Activity to an Unusual ISO Code
* Potential Data Exfiltration Activity to an Unusual Region
* Rare AWS Error Code
* Rare User Logon
* Spike in AWS Error Messages
* Spike in Bytes Sent to an External Device
* Spike in Bytes Sent to an External Device via Airdrop
* Spike in Failed Logon Events
* Spike in Firewall Denies
* Spike in Logon Events
* Spike in Network Traffic
* Spike in Network Traffic To a Country
* Spike in Number of Connections Made from a Source IP
* Spike in Number of Connections Made to a Destination IP
* Spike in Number of Processes in an RDP Session
* Spike in Remote File Transfers
* Spike in Successful Logon Events from a Source IP
* Suspicious Powershell Script
* Suspicious Windows Process Cluster Spawned by a Host
* Suspicious Windows Process Cluster Spawned by a Parent Process
* Suspicious Windows Process Cluster Spawned by a User
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
* Unusual Process Spawned by a Host
* Unusual Process Spawned by a Parent Process
* Unusual Process Spawned by a User
* Unusual Process Writing Data to an External Device
* Unusual Remote File Directory
* Unusual Remote File Extension
* Unusual Remote File Size
* Unusual Source IP for a User to Logon from
* Unusual Sudo Activity
* Unusual Time or Day for an RDP Session
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

### Unsupported rule type: new_terms (72)

72 rules:

* AWS CLI Command with Custom Endpoint URL
* AWS EC2 Admin Credential Fetch via Assumed Role
* AWS SSM `SendCommand` with Run Shell Command Parameters
* AWS STS GetCallerIdentity API Called for the First Time
* AWS STS Temporary Credentials via AssumeRole
* AWS Systems Manager SecureString Parameter Request with Decryption Flag
* Abnormal Process ID or Lock File Created
* Authentication via Unusual PAM Grantor
* CAP_SYS_ADMIN Assigned to Binary
* DPKG Package Installed by Unusual Parent Process
* Deprecated - Suspicious JAVA Child Process
* Discovery of Internet Capabilities via Built-in Tools
* Enumeration of Kernel Modules
* Enumeration of Kernel Modules via Proc
* Enumeration of Privileged Local Groups Membership
* Execution of an Unsigned Service
* File Permission Modification in Writable Directory
* First Occurrence GitHub Event for a Personal Access Token (PAT)
* First Occurrence of GitHub Repo Interaction From a New IP
* First Occurrence of GitHub User Interaction with Private Repo
* First Occurrence of IP Address For GitHub Personal Access Token (PAT)
* First Occurrence of IP Address For GitHub User
* First Occurrence of Okta User Session Started via Proxy
* First Occurrence of Personal Access Token (PAT) Use For a GitHub User
* First Occurrence of Private Repo Event from Specific GitHub Personal Access Token (PAT)
* First Occurrence of STS GetFederationToken Request by User
* First Occurrence of User Agent For a GitHub Personal Access Token (PAT)
* First Occurrence of User-Agent For a GitHub User
* First Time AWS Cloudformation Stack Creation by User
* First Time Seen AWS Secret Value Accessed in Secrets Manager
* First Time Seen Commonly Abused Remote Access Tool Execution
* First Time Seen Driver Loaded
* First Time Seen Google Workspace OAuth Login from Third-Party Application
* First Time Seen NewCredentials Logon Process
* First Time Seen Removable Device
* FirstTime Seen Account Performing DCSync
* Linux Clipboard Activity Detected
* Microsoft 365 Portal Login from Rare Location
* Microsoft Build Engine Started an Unusual Process
* Microsoft Build Engine Started by a Script Process
* Modification of Dynamic Linker Preload Shared Object
* Modification of Standard Authentication Module or Configuration
* Network Activity Detected via Kworker
* Network Traffic Capture via CAP_NET_RAW
* Potential Pass-the-Hash (PtH) Attempt
* Potential Privilege Escalation via Linux DAC permissions
* Potential Shadow File Read via Command Line Utilities
* Privileged Docker Container Creation
* Query Registry using Built-in Tools
* RPM Package Installed by Unusual Parent Process
* Rare SMB Connection to the Internet
* SSH Authorized Keys File Modification
* SSM Session Started to EC2 Instance
* Sensitive Files Compression
* Shared Object Created or Changed by Previously Unknown Process
* Successful Application SSO from Rare Unknown Client Device
* Sudoers File Modification
* Suspicious Microsoft 365 Mail Access by ClientAppId
* Suspicious Modprobe File Event
* Suspicious Network Activity to the Internet by Previously Unknown Executable
* Suspicious PowerShell Engine ImageLoad
* Suspicious PrintSpooler Service Executable File Creation
* Suspicious Sysctl File Event
* Suspicious System Commands Executed by Previously Unknown Executable
* Svchost spawning Cmd
* Systemd Service Started by Unusual Parent Process
* UID Elevation from Previously Unknown Executable
* Unauthorized Scope for Public App OAuth2 Token Grant with Client Credentials
* Unknown Execution of Binary with RWX Memory Region
* Unusual Discovery Activity by User
* Unusual Discovery Signal Alert with Unusual Process Command Line
* Unusual Discovery Signal Alert with Unusual Process Executable

### Unsupported rule type: threshold (30)

30 rules:

* AWS IAM Brute Force of Assume Role Policy
* AWS Management Console Brute Force of Root User Identity
* Agent Spoofing - Multiple Hosts Using Same Agent
* Attempts to Brute Force an Okta User Account
* Deprecated - Potential Password Spraying of Microsoft 365 User Accounts
* GitHub UEBA - Multiple Alerts from a GitHub Account
* High Number of Cloned GitHub Repos From PAT
* High Number of Okta User Password Reset or Unlock Attempts
* High Number of Process Terminations
* High Number of Process and/or Service Terminations
* Microsoft 365 Portal Logins from Impossible Travel Locations
* Multiple Alerts Involving a User
* Multiple Alerts in Different ATT&CK Tactics on a Single Host
* Multiple Okta Sessions Detected for a Single User
* Multiple Okta User Auth Events with Same Device Token Hash Behind a Proxy
* My First Rule
* O365 Excessive Single Sign-On Logon Errors
* Okta Brute Force or Password Spraying Attack
* Okta User Sessions Started from Different Geolocations
* Potential Buffer Overflow Attack Detected
* Potential LSASS Memory Dump via PssCaptureSnapShot
* Potential Network Scan Detected
* Potential Network Scan Executed From Host
* Potential Network Sweep Detected
* Potential Ransomware Behavior - High count of Readme files by System
* Potential SYN-Based Network Scan Detected
* Potential macOS SSH Brute Force Detected
* Rapid Secret Retrieval Attempts from AWS SecretsManager
* Sudo Heap-Based Buffer Overflow Attempt
* Suspicious Proc Pseudo File System Enumeration

### Unsupported rule type: threat_match (5)

5 rules:

* Rapid7 Threat Command CVEs Correlation
* Threat Intel Hash Indicator Match
* Threat Intel IP Address Indicator Match
* Threat Intel URL Indicator Match
* Threat Intel Windows Registry Indicator Match

### Unsupported query language: lucene (4)

4 rules:

* Cobalt Strike Command and Control Beacon
* Halfbaked Command and Control Beacon
* Inbound Connection to an Unsecure Elasticsearch Node
* Possible FIN7 DGA Command and Control Behavior

### Unsupported rule type: esql (3)

3 rules:

* AWS EC2 Multi-Region DescribeInstances API Calls
* AWS Service Quotas Multi-Region `GetServiceQuota` Requests
* Attempts to Brute Force a Microsoft 365 User Account

## Generation errors

### Root with too many branches (limit: 10000) (15)

15 rules:
* Connection to Commonly Abused Web Services
* Execution from Unusual Directory - Command Line
* External IP Lookup from Non-Browser Process
* File Compressed or Archived into Common Format
* Potential DNS Tunneling via NsLookup
* Potential Evasion via Windows Filtering Platform
* Potential Linux Ransomware Note Creation Detected
* Potential Masquerading as System32 DLL
* Potential Masquerading as System32 Executable
* Potential Pspy Process Monitoring Detected
* Potential Remote Code Execution via Web Server
* Potential Reverse Shell via Suspicious Binary
* Potential Reverse Shell via Suspicious Child Process
* Startup or Run Key Registry Modification
* Suspicious PowerShell Execution via Windows Scripts

### Unsupported LHS type: <class 'eql.ast.FunctionCall'> (12)

12 rules:
* AdminSDHolder SDProp Exclusion Added
* Image File Execution Options Injection
* Ingress Transfer via Windows BITS
* Memory Dump File with Unusual Extension
* NullSessionPipe Registry Modification
* Persistence via Hidden Run Key Detected
* Potential curl CVE-2023-38545 Exploitation
* Renamed Utility Executed with Short Program Name
* Suspicious Access to LDAP Attributes
* Suspicious Execution via MSIEXEC
* Suspicious Process Access via Direct System Call
* Uncommon Registry Persistence Change

### Unsupported function: stringContains (12)

12 rules:
* AWS EC2 Instance Console Login via Assumed Role
* AWS EC2 Instance Interaction with IAM Service
* AWS IAM CompromisedKeyQuarantine Policy Attached to User
* AWS RDS DB Instance Made Public
* AWS RDS DB Instance or Cluster Deletion Protection Disabled
* AWS RDS DB Instance or Cluster Password Modified
* AWS RDS DB Snapshot Shared with Another Account
* AWS RDS Snapshot Deleted
* AWS S3 Bucket Policy Added to Share with External Account
* AWS S3 Bucket Replicated to Another Account
* AWS S3 Bucket Server Access Logging Disabled
* AWS S3 Object Versioning Suspended

### Unsupported function: match (11)

11 rules:
* Alternate Data Stream Creation/Execution at Volume Root Directory
* Creation of Hidden Files and Directories via CommandLine
* Executable File Creation with Multiple Extensions
* Masquerading Space After Filename
* Potential Credential Access via Windows Utilities
* Potential Exploitation of an Unquoted Service Path Vulnerability
* Process Created with a Duplicated Token
* Process Started from Process ID (PID) File
* SUID/SGID Bit Set
* Suspicious Execution via Microsoft Office Add-Ins
* Suspicious Service was Installed in the System

### Unsupported argument type(s): <class 'eql.ast.Field'> (6)

6 rules:
* External User Added to Google Workspace Group
* Image Loaded with Invalid Signature
* Interactive Logon by an Unusual Process
* Potential Ransomware Note File Dropped via SMB
* Suspicious File Renamed via SMB
* Unusual Network Activity from a Windows System Binary

### Root without branches (4)

4 rules:
* Docker Escape via Nsenter
* Linux init (PID 1) Secret Dump via GDB
* Potential Protocol Tunneling via Chisel Server
* Suspicious Data Encryption via OpenSSL Utility

### <class 'eql.ast.Sample'> (3)

3 rules:
* Network Connection from Binary with RWX Memory Region
* Potential Meterpreter Reverse Shell
* Potential Reverse Shell via UDP

### Unsupported &keyword 'file.Ext.windows.zone_identifier' constraint: > (3)

3 rules:
* Downloaded Shortcut Files
* Downloaded URL Files
* File with Suspicious Extension Downloaded

### Unsupported argument type: <class 'eql.ast.FunctionCall'> (3)

3 rules:
* Active Directory Forced Authentication from Linux Host - SMB Named Pipes
* Unsigned DLL Loaded by a Trusted Process
* Unsigned DLL Side-Loading from a Suspicious Folder

### Unsupported function: startsWith (3)

3 rules:
* Persistent Scripts in the Startup Directory
* Potential ADIDNS Poisoning via Wildcard Record Creation
* SMB Connections via LOLBin or Untrusted Process

### Pipes are unsupported (2)

2 rules:
* Potential Successful Linux FTP Brute Force Attack Detected
* Potential Successful Linux RDP Brute Force Attack Detected

### Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)

2 rules:
* Parent Process PID Spoofing
* Privileges Elevation via Parent Process PID Spoofing

### Unsupported function: endswith (2)

2 rules:
* Potential Relay Attack against a Domain Controller
* Unusual Execution via Microsoft Common Console File

### <class 'eql.ast.SubqueryBy'> (1)

1 rules:
* Potential Okta MFA Bombing via Push Notifications

### Cannot choose from an empty set (1)

1 rules:
* MsiExec Service Child Process With Network Connection

### Unsolvable constraints: aws.cloudtrail.request_parameters (not in Strings({'*LifecycleConfiguration*'}): ('*Expiration=*')) (1)

1 rules:
* AWS S3 Bucket Expiration Lifecycle Configuration Added

### Unsolvable constraints: aws.cloudtrail.request_parameters (not in Strings({'*attribute=userData*'}): ('*instanceId*')) (1)

1 rules:
* Attempt to Retrieve User Data from AWS EC2 Instance

### Unsolvable constraints: aws.cloudtrail.request_parameters (not in Strings({'*imageId*'}): ('*add*')) (1)

1 rules:
* EC2 AMI Shared with Another Account

### Unsolvable constraints: aws.cloudtrail.request_parameters (not in Strings({'*lambda:InvokeFunction*'}): ('*principal=**')) (1)

1 rules:
* AWS Lambda Function Policy Updated to Allow Public Invocation

### Unsolvable constraints: file.extension (cannot be non-null) (1)

1 rules:
* Creation or Modification of Pluggable Authentication Module or Configuration

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

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Invoke-WmiMethod'}): ('ComputerName')) (1)

1 rules:
* PowerShell Script with Remote Execution Capabilities via WinRM

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'LsaCallAuthenticationPackage'}): ('KerbRetrieveEncodedTicketMessage')) (1)

1 rules:
* PowerShell Kerberos Ticket Dump

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Set-MpPreference'}): ('DisableArchiveScanning')) (1)

1 rules:
* PowerShell Script with Windows Defender Tampering Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'System.IO.Compression.DeflateStream'}): ('FromBase64String')) (1)

1 rules:
* PowerShell Suspicious Payload Encoded and Compressed

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)

1 rules:
* Potential Process Injection via PowerShell

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[string]::join'}): ('$pSHoMe[')) (1)

1 rules:
* Potential PowerShell Obfuscated Script

### Unsolvable constraints: process.command_line (not in Strings({'*drive.google.com*'}): ('*export=download*')) (1)

1 rules:
* Suspicious File Downloaded from Google Drive

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*'}): ('*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*')) (1)

1 rules:
* Potential Active Directory Replication Account Backdoor

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)

1 rules:
* Group Policy Abuse for Privilege Addition

### Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: < (1)

1 rules:
* Potential Windows Session Hijacking via CcmExec

### Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: <= (1)

1 rules:
* Unsigned DLL Loaded by Svchost

### Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)

1 rules:
* Suspicious HTML File Creation

### Unsupported &keyword 'ml_is_dga.malicious_probability' constraint: > (1)

1 rules:
* Machine Learning Detected a DNS Request With a High DGA Probability Score

### Unsupported &keyword 'problemchild.prediction_probability' constraint: <= (1)

1 rules:
* Machine Learning Detected a Suspicious Windows Event with a Low Malicious Probability Score

### Unsupported &keyword 'problemchild.prediction_probability' constraint: > (1)

1 rules:
* Machine Learning Detected a Suspicious Windows Event with a High Malicious Probability Score

### Unsupported &keyword 'process.Ext.relative_file_creation_time' constraint: <= (1)

1 rules:
* Suspicious Inter-Process Communication via Outlook

### Unsupported &keyword 'user.id' constraint: >= (1)

1 rules:
* Potential Privilege Escalation via UID INT_MAX Bug Detected

### Unsupported argument type(s): <class 'eql.ast.FunctionCall'> (1)

1 rules:
* Remote Computer Account DnsHostName Update

### Unsupported is_negated: {'is_negated': True} (1)

1 rules:
* MFA Deactivation with no Re-Activation for Okta User Account
