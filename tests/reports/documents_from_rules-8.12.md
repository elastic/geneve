# Documents generation from detection rules

This report captures the error reported while generating documents from detection rules. Here you
can learn what rules are still problematic and for which no documents can be generated at the moment.

Curious about the inner workings? Read [here](signals_generation.md).

Rules version: 8.12.6

## Table of contents
   1. [Skipped rules](#skipped-rules)
      1. [Unsupported rule type: machine_learning (72)](#unsupported-rule-type-machine_learning-72)
      1. [Unsupported rule type: new_terms (60)](#unsupported-rule-type-new_terms-60)
      1. [Unsupported rule type: threshold (29)](#unsupported-rule-type-threshold-29)
      1. [Unsupported query language: lucene (5)](#unsupported-query-language-lucene-5)
      1. [Unsupported rule type: threat_match (4)](#unsupported-rule-type-threat_match-4)
   1. [Generation errors](#generation-errors)
      1. [Field type solver: wildcard (62)](#field-type-solver-wildcard-62)
      1. [Root with too many branches (limit: 10000) (14)](#root-with-too-many-branches-limit-10000-14)
      1. [Unsupported LHS type: <class 'eql.ast.FunctionCall'> (9)](#unsupported-lhs-type-class-eqlastfunctioncall-9)
      1. [Unsupported function: match (9)](#unsupported-function-match-9)
      1. [Field type solver: match_only_text (6)](#field-type-solver-match_only_text-6)
      1. [Root without branches (3)](#root-without-branches-3)
      1. [Unsupported &keyword 'file.Ext.windows.zone_identifier' constraint: > (3)](#unsupported-keyword-fileextwindowszone_identifier-constraint--3)
      1. [Unsupported argument type(s): <class 'eql.ast.Field'> (3)](#unsupported-argument-types-class-eqlastfield-3)
      1. [<class 'eql.ast.Sample'> (2)](#class-eqlastsample-2)
      1. [<class 'eql.ast.SubqueryBy'> (2)](#class-eqlastsubqueryby-2)
      1. [Pipes are unsupported (2)](#pipes-are-unsupported-2)
      1. [Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.dce_rpc')) (2)](#unsolvable-constraints-eventdataset-not-in-stringsnetwork_trafficflow-zeekdce_rpc-2)
      1. [Unsolvable constraints: process.name (excluded by Strings({'cmd.exe'}): ('cmd.exe')) (2)](#unsolvable-constraints-processname-excluded-by-stringscmdexe-cmdexe-2)
      1. [Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)](#unsupported-keyword-processparentextrealpid-constraint--2)
      1. [Unsupported argument type: <class 'eql.ast.FunctionCall'> (2)](#unsupported-argument-type-class-eqlastfunctioncall-2)
      1. [Unsolvable constraints: event.action (excluded by Strings({'exec'}): ('exec')) (1)](#unsolvable-constraints-eventaction-excluded-by-stringsexec-exec-1)
      1. [Unsolvable constraints: event.category & event.type (empty intersection) (1)](#unsolvable-constraints-eventcategory--eventtype-empty-intersection-1)
      1. [Unsolvable constraints: event.dataset (not in Strings({'network_traffic.dns'}): ('zeek.dns')) (1)](#unsolvable-constraints-eventdataset-not-in-stringsnetwork_trafficdns-zeekdns-1)
      1. [Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.rdp')) (1)](#unsolvable-constraints-eventdataset-not-in-stringsnetwork_trafficflow-zeekrdp-1)
      1. [Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.smb')) (1)](#unsolvable-constraints-eventdataset-not-in-stringsnetwork_trafficflow-zeeksmb-1)
      1. [Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.smtp')) (1)](#unsolvable-constraints-eventdataset-not-in-stringsnetwork_trafficflow-zeeksmtp-1)
      1. [Unsolvable constraints: file.Ext.header_bytes (excluded by Strings({'504B0304*'}): ('504B0304*')) (1)](#unsolvable-constraints-fileextheader_bytes-excluded-by-strings504b0304-504b0304-1)
      1. [Unsolvable constraints: kubernetes.audit.requestObject.spec.containers.image (cannot be null) (1)](#unsolvable-constraints-kubernetesauditrequestobjectspeccontainersimage-cannot-be-null-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscopyfromscreen-systemdrawingbitmap-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Cryptography.AESManaged'}): ('CipherMode')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscryptographyaesmanaged-ciphermode-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'DumpCreds'}): ('DumpCerts')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsdumpcreds-dumpcerts-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Eventing.Reader.EventLogSession'}): ('.ClearLog')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringseventingreadereventlogsession-clearlog-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Get-WmiObject'}): ('AntiVirusProduct')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsget-wmiobject-antivirusproduct-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'IO.Compression.ZipFile'}): ('CompressionLevel')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsiocompressionzipfile-compressionlevel-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Invoke-WmiMethod'}): ('ComputerName')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsinvoke-wmimethod-computername-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'LsaCallAuthenticationPackage'}): ('KerbRetrieveEncodedTicketMessage')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringslsacallauthenticationpackage-kerbretrieveencodedticketmessage-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'STARTUPINFOEX'}): ('UpdateProcThreadAttribute')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsstartupinfoex-updateprocthreadattribute-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'SetWindowsHookA'}): ('GetForegroundWindow')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssetwindowshooka-getforegroundwindow-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'System.IO.Compression.DeflateStream'}): ('FromBase64String')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssystemiocompressiondeflatestream-frombase64string-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsvirtualalloc-writeprocessmemory-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Windows.Clipboard'}): (']::GetText')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringswindowsclipboard-gettext-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[System.Runtime.InteropServices.Marshal]::Copy'}): ('VirtualProtect')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssystemruntimeinteropservicesmarshalcopy-virtualprotect-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'capCreateCaptureWindowA'}): ('avicap32.dll')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscapcreatecapturewindowa-avicap32dll-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'defaultNamingContext'}): ('.MinLengthPassword')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsdefaultnamingcontext-minlengthpassword-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'shi1_netname'}): ('shi1_remark')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsshi1_netname-shi1_remark-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'waveInGetNumDevs'}): ('mciSendStringA')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringswaveingetnumdevs-mcisendstringa-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'elevation_service.exe'}): ('elevation_service.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringselevation_serviceexe-elevation_serviceexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'msdt.exe'}): ('msdt.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsmsdtexe-msdtexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'msedgewebview2.exe'}): ('msedgewebview2.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsmsedgewebview2exe-msedgewebview2exe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsrundll32exe-rundll32exe-1)
      1. [Unsolvable constraints: process.parent.args (excluded by Strings({'WdiSystemHost'}): ('WdiSystemHost')) (1)](#unsolvable-constraints-processparentargs-excluded-by-stringswdisystemhost-wdisystemhost-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'dllhost.exe'}): ('dllhost.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringsdllhostexe-dllhostexe-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringsrundll32exe-rundll32exe-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'winword.exe'}): ('winword.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringswinwordexe-winwordexe-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'wscript.exe'}): ('wscript.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringswscriptexe-wscriptexe-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*42B5FAAE-6536-11D2-AE5A-0000F87571E3*'}): ('*40B66650-4972-11D1-A7CA-0000F87571E3*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings42b5faae-6536-11d2-ae5a-0000f87571e3-40b66650-4972-11d1-a7ca-0000f87571e3-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings827d319e-6eac-11d2-a4ea-00c04f79f83a-803e14a0-b4fb-11d0-a0d0-00a0c90f574b-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*CAB54552-DEEA-4691-817E-ED4A4D1AFC72*'}): ('*AADCED64-746C-4633-A97C-D61349046527*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-stringscab54552-deea-4691-817e-ed4a4d1afc72-aadced64-746c-4633-a97c-d61349046527-1)
      1. [Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: <= (1)](#unsupported-keyword-dllextrelative_file_creation_time-constraint--1)
      1. [Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)](#unsupported-keyword-fileextentropy-constraint--1)
      1. [Unsupported &keyword 'ml_is_dga.malicious_probability' constraint: > (1)](#unsupported-keyword-ml_is_dgamalicious_probability-constraint--1)
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

### Unsupported rule type: new_terms (60)

60 rules:

* Abnormal Process ID or Lock File Created
* CAP_SYS_ADMIN Assigned to Binary
* Cron Job Created or Changed by Previously Unknown Process
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
* First Occurrence of User Agent For a GitHub Personal Access Token (PAT)
* First Occurrence of User-Agent For a GitHub User
* First Time Seen AWS Secret Value Accessed in Secrets Manager
* First Time Seen Commonly Abused Remote Access Tool Execution
* First Time Seen Driver Loaded
* First Time Seen Google Workspace OAuth Login from Third-Party Application
* First Time Seen NewCredentials Logon Process
* First Time Seen Removable Device
* FirstTime Seen Account Performing DCSync
* Microsoft Build Engine Started an Unusual Process
* Microsoft Build Engine Started by a Script Process
* Modification of Dynamic Linker Preload Shared Object
* Modification of Standard Authentication Module or Configuration
* Network Activity Detected via Kworker
* Network Traffic Capture via CAP_NET_RAW
* New Systemd Service Created by Previously Unknown Process
* New Systemd Timer Created
* Potential Pass-the-Hash (PtH) Attempt
* Potential Persistence Through MOTD File Creation Detected
* Potential Persistence Through Run Control Detected
* Potential Persistence Through Systemd-udevd
* Potential Persistence Through init.d Detected
* Potential Shadow File Read via Command Line Utilities
* Potential Sudo Hijacking Detected
* Potential Suspicious Clipboard Activity Detected
* Query Registry using Built-in Tools
* Rare SMB Connection to the Internet
* SSH Authorized Keys File Modification
* Sensitive Files Compression
* Shared Object Created or Changed by Previously Unknown Process
* Sudoers File Modification
* Suspicious JAVA Child Process
* Suspicious Microsoft 365 Mail Access by ClientAppId
* Suspicious Modprobe File Event
* Suspicious Network Activity to the Internet by Previously Unknown Executable
* Suspicious PowerShell Engine ImageLoad
* Suspicious Sysctl File Event
* Suspicious System Commands Executed by Previously Unknown Executable
* Svchost spawning Cmd
* UID Elevation from Previously Unknown Executable
* Unusual Discovery Activity by User
* Unusual Discovery Signal Alert with Unusual Process Command Line
* Unusual Discovery Signal Alert with Unusual Process Executable

### Unsupported rule type: threshold (29)

29 rules:

* AWS IAM Brute Force of Assume Role Policy
* AWS Management Console Brute Force of Root User Identity
* Agent Spoofing - Multiple Hosts Using Same Agent
* Attempts to Brute Force a Microsoft 365 User Account
* Attempts to Brute Force an Okta User Account
* GitHub UEBA - Multiple Alerts from a GitHub Account
* High Number of Cloned GitHub Repos From PAT
* High Number of Okta User Password Reset or Unlock Attempts
* High Number of Process Terminations
* High Number of Process and/or Service Terminations
* Multiple Alerts Involving a User
* Multiple Alerts in Different ATT&CK Tactics on a Single Host
* Multiple Okta Client Addresses for a Single User Session
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
* Potential Password Spraying of Microsoft 365 User Accounts
* Potential SYN-Based Network Scan Detected
* Potential macOS SSH Brute Force Detected
* Sudo Heap-Based Buffer Overflow Attempt
* Suspicious Proc Pseudo File System Enumeration

### Unsupported query language: lucene (5)

5 rules:

* Cobalt Strike Command and Control Beacon
* Halfbaked Command and Control Beacon
* Inbound Connection to an Unsecure Elasticsearch Node
* Possible FIN7 DGA Command and Control Behavior
* Setuid / Setgid Bit Set via chmod

### Unsupported rule type: threat_match (4)

4 rules:

* Threat Intel Hash Indicator Match
* Threat Intel IP Address Indicator Match
* Threat Intel URL Indicator Match
* Threat Intel Windows Registry Indicator Match

## Generation errors

### Field type solver: wildcard (62)

62 rules:
* Adding Hidden File Attribute via Attrib
* Apple Scripting Execution with Administrator Privileges
* Attempt to Mount SMB Share via Command Line
* Attempt to Remove File Quarantine Attribute
* Binary Executed from Shared Memory Directory
* Code Signing Policy Modification Through Registry
* Command Shell Activity Started via RunDLL32
* Control Panel Process with Unusual Arguments
* Creation of Hidden Login Item via Apple Script
* DNS-over-HTTPS Enabled via Registry
* Delayed Execution via Ping
* Disabling User Account Control via Registry Modification
* Encoded Executable Stored in the Registry
* Enumeration Command Spawned via WMIPrvSE
* Execution via Microsoft DotNet ClickOnce Host
* Exporting Exchange Mailbox via PowerShell
* Full User-Mode Dumps Enabled System-Wide
* Host Files System Changes via Windows Subsystem for Linux
* Local Account TokenFilter Policy Disabled
* MS Office Macro Security Registry Modifications
* Microsoft Windows Defender Tampering
* Modification of AmsiEnable Registry Key
* Modification of WDigest Security Provider
* NTDS or SAM Database File Copied
* Network Logon Provider Registry Modification
* Network-Level Authentication (NLA) Disabled
* Persistence via WMI Standard Registry Provider
* Potential Persistence via Time Provider Modification
* Potential Port Monitor or Print Processor Registration Abuse
* Potential Privacy Control Bypass via Localhost Secure Copy
* Potential Privilege Escalation via Linux DAC permissions
* Potential Reverse Shell Activity via Terminal
* Potential SharpRDP Behavior
* PowerShell Script Block Logging Disabled
* Privilege Escalation via CAP_CHOWN/CAP_FOWNER Capabilities
* Privilege Escalation via Windir Environment Variable
* Prompt for Credentials with OSASCRIPT
* RDP Enabled via Registry
* Roshal Archive (RAR) or PowerShell File Downloaded from the Internet
* SIP Provider Modification
* SUNBURST Command and Control Activity
* Scheduled Tasks AT Command Enabled
* Security Software Discovery via Grep
* Service Disabled via Registry Modification
* SolarWinds Process Disabling Services via Registry
* Suspicious Browser Child Process
* Suspicious Communication App Child Process
* Suspicious Content Extracted or Decompressed via Funzip
* Suspicious Execution via Windows Subsystem for Linux
* Suspicious File Downloaded from Google Drive
* Suspicious ImagePath Service Creation
* Suspicious Print Spooler Point and Print DLL
* Suspicious Startup Shell Folder Modification
* Suspicious WMIC XSL Script Execution
* Symbolic Link to Shadow Copy Created
* Uncommon Registry Persistence Change
* Unusual Persistence via Services Registry
* Unusual Print Spooler Child Process
* Virtual Private Network Connection Attempt
* Windows Defender Disabled via Registry Modification
* Windows Installer with Suspicious Properties
* Windows Subsystem for Linux Enabled via Dism Utility

### Root with too many branches (limit: 10000) (14)

14 rules:
* Component Object Model Hijacking
* Connection to Commonly Abused Web Services
* Execution from Unusual Directory - Command Line
* File Compressed or Archived into Common Format
* Potential DNS Tunneling via NsLookup
* Potential Evasion via Windows Filtering Platform
* Potential Linux Ransomware Note Creation Detected
* Potential Masquerading as System32 DLL
* Potential Masquerading as System32 Executable
* Potential Pspy Process Monitoring Detected
* Potential Reverse Shell via Suspicious Binary
* Potential Reverse Shell via Suspicious Child Process
* Startup or Run Key Registry Modification
* Suspicious File Changes Activity Detected

### Unsupported LHS type: <class 'eql.ast.FunctionCall'> (9)

9 rules:
* AdminSDHolder SDProp Exclusion Added
* Image File Execution Options Injection
* Ingress Transfer via Windows BITS
* Memory Dump File with Unusual Extension
* NullSessionPipe Registry Modification
* Potential curl CVE-2023-38545 Exploitation
* Renamed Utility Executed with Short Program Name
* Suspicious Execution via MSIEXEC
* Suspicious Process Access via Direct System Call

### Unsupported function: match (9)

9 rules:
* Creation of Hidden Files and Directories via CommandLine
* Executable File Creation with Multiple Extensions
* Masquerading Space After Filename
* Potential Credential Access via Windows Utilities
* Potential Exploitation of an Unquoted Service Path Vulnerability
* Process Created with a Duplicated Token
* Process Started from Process ID (PID) File
* Suspicious Execution via Microsoft Office Add-Ins
* Suspicious Service was Installed in the System

### Field type solver: match_only_text (6)

6 rules:
* Account Configured with Never-Expiring Password
* Kerberos Pre-authentication Disabled for User
* Segfault Detected
* Tainted Kernel Module Load
* Tainted Out-Of-Tree Kernel Module Load
* Windows CryptoAPI Spoofing Vulnerability (CVE-2020-0601 - CurveBall)

### Root without branches (3)

3 rules:
* Linux init (PID 1) Secret Dump via GDB
* Potential Protocol Tunneling via Chisel Server
* Suspicious Data Encryption via OpenSSL Utility

### Unsupported &keyword 'file.Ext.windows.zone_identifier' constraint: > (3)

3 rules:
* Downloaded Shortcut Files
* Downloaded URL Files
* File with Suspicious Extension Downloaded

### Unsupported argument type(s): <class 'eql.ast.Field'> (3)

3 rules:
* External User Added to Google Workspace Group
* Image Loaded with Invalid Signature
* Interactive Logon by an Unusual Process

### <class 'eql.ast.Sample'> (2)

2 rules:
* Potential Meterpreter Reverse Shell
* Potential Reverse Shell via UDP

### <class 'eql.ast.SubqueryBy'> (2)

2 rules:
* Direct Outbound SMB Connection
* Potential Okta MFA Bombing via Push Notifications

### Pipes are unsupported (2)

2 rules:
* Potential Successful Linux FTP Brute Force Attack Detected
* Potential Successful Linux RDP Brute Force Attack Detected

### Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.dce_rpc')) (2)

2 rules:
* RPC (Remote Procedure Call) from the Internet
* RPC (Remote Procedure Call) to the Internet

### Unsolvable constraints: process.name (excluded by Strings({'cmd.exe'}): ('cmd.exe')) (2)

2 rules:
* Execution via MS VisualStudio Pre/Post Build Events
* Web Shell Detection: Script Process Child of Common Web Processes

### Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)

2 rules:
* Parent Process PID Spoofing
* Privileges Elevation via Parent Process PID Spoofing

### Unsupported argument type: <class 'eql.ast.FunctionCall'> (2)

2 rules:
* Unsigned DLL Loaded by a Trusted Process
* Unsigned DLL Side-Loading from a Suspicious Folder

### Unsolvable constraints: event.action (excluded by Strings({'exec'}): ('exec')) (1)

1 rules:
* Process Discovery via Built-In Applications

### Unsolvable constraints: event.category & event.type (empty intersection) (1)

1 rules:
* Suspicious File Creation in /etc for Persistence

### Unsolvable constraints: event.dataset (not in Strings({'network_traffic.dns'}): ('zeek.dns')) (1)

1 rules:
* Abnormally Large DNS Response

### Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.rdp')) (1)

1 rules:
* RDP (Remote Desktop Protocol) from the Internet

### Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.smb')) (1)

1 rules:
* SMB (Windows File Sharing) Activity to the Internet

### Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.smtp')) (1)

1 rules:
* SMTP on Port 26/TCP

### Unsolvable constraints: file.Ext.header_bytes (excluded by Strings({'504B0304*'}): ('504B0304*')) (1)

1 rules:
* Archive File with Unusual Extension

### Unsolvable constraints: kubernetes.audit.requestObject.spec.containers.image (cannot be null) (1)

1 rules:
* Kubernetes Container Created with Excessive Linux Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)

1 rules:
* PowerShell Suspicious Script with Screenshot Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Cryptography.AESManaged'}): ('CipherMode')) (1)

1 rules:
* PowerShell Script with Encryption/Decryption Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'DumpCreds'}): ('DumpCerts')) (1)

1 rules:
* Potential Invoke-Mimikatz PowerShell Script

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Eventing.Reader.EventLogSession'}): ('.ClearLog')) (1)

1 rules:
* PowerShell Script with Log Clear Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Get-WmiObject'}): ('AntiVirusProduct')) (1)

1 rules:
* PowerShell Script with Discovery Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'IO.Compression.ZipFile'}): ('CompressionLevel')) (1)

1 rules:
* PowerShell Script with Archive Compression Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Invoke-WmiMethod'}): ('ComputerName')) (1)

1 rules:
* PowerShell Script with Remote Execution Capabilities via WinRM

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'LsaCallAuthenticationPackage'}): ('KerbRetrieveEncodedTicketMessage')) (1)

1 rules:
* PowerShell Kerberos Ticket Dump

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

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Windows.Clipboard'}): (']::GetText')) (1)

1 rules:
* PowerShell Suspicious Script with Clipboard Retrieval Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[System.Runtime.InteropServices.Marshal]::Copy'}): ('VirtualProtect')) (1)

1 rules:
* Potential Antimalware Scan Interface Bypass via PowerShell

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'capCreateCaptureWindowA'}): ('avicap32.dll')) (1)

1 rules:
* PowerShell Script with Webcam Video Capture Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'defaultNamingContext'}): ('.MinLengthPassword')) (1)

1 rules:
* PowerShell Script with Password Policy Discovery Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'shi1_netname'}): ('shi1_remark')) (1)

1 rules:
* PowerShell Share Enumeration Script

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'waveInGetNumDevs'}): ('mciSendStringA')) (1)

1 rules:
* PowerShell Suspicious Script with Audio Capture Capabilities

### Unsolvable constraints: process.name (excluded by Strings({'elevation_service.exe'}): ('elevation_service.exe')) (1)

1 rules:
* Potential Privilege Escalation via InstallerFileTakeOver

### Unsolvable constraints: process.name (excluded by Strings({'msdt.exe'}): ('msdt.exe')) (1)

1 rules:
* Suspicious Microsoft Diagnostics Wizard Execution

### Unsolvable constraints: process.name (excluded by Strings({'msedgewebview2.exe'}): ('msedgewebview2.exe')) (1)

1 rules:
* Potential Masquerading as Browser Process

### Unsolvable constraints: process.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)

1 rules:
* Suspicious MS Office Child Process

### Unsolvable constraints: process.parent.args (excluded by Strings({'WdiSystemHost'}): ('WdiSystemHost')) (1)

1 rules:
* Unusual Service Host Child Process - Childless Service

### Unsolvable constraints: process.parent.name (excluded by Strings({'dllhost.exe'}): ('dllhost.exe')) (1)

1 rules:
* Unusual Parent Process for cmd.exe

### Unsolvable constraints: process.parent.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)

1 rules:
* Conhost Spawned By Suspicious Parent Process

### Unsolvable constraints: process.parent.name (excluded by Strings({'winword.exe'}): ('winword.exe')) (1)

1 rules:
* Suspicious Process Creation CallTrace

### Unsolvable constraints: process.parent.name (excluded by Strings({'wscript.exe'}): ('wscript.exe')) (1)

1 rules:
* Windows Script Executing PowerShell

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*42B5FAAE-6536-11D2-AE5A-0000F87571E3*'}): ('*40B66650-4972-11D1-A7CA-0000F87571E3*')) (1)

1 rules:
* Startup/Logon Script added to Group Policy Object

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)

1 rules:
* Group Policy Abuse for Privilege Addition

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*CAB54552-DEEA-4691-817E-ED4A4D1AFC72*'}): ('*AADCED64-746C-4633-A97C-D61349046527*')) (1)

1 rules:
* Scheduled Task Execution at Scale via GPO

### Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: <= (1)

1 rules:
* Unsigned DLL Loaded by Svchost

### Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)

1 rules:
* Suspicious HTML File Creation

### Unsupported &keyword 'ml_is_dga.malicious_probability' constraint: > (1)

1 rules:
* Machine Learning Detected a DNS Request With a High DGA Probability Score

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
