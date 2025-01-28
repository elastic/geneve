# Documents generation from detection rules

This report captures the error reported while generating documents from detection rules. Here you
can learn what rules are still problematic and for which no documents can be generated at the moment.

Curious about the inner workings? Read [here](signals_generation.md).

Rules version: 8.13.23

## Table of contents
   1. [Skipped rules](#skipped-rules)
      1. [Unsupported rule type: new_terms (82)](#unsupported-rule-type-new_terms-82)
      1. [Unsupported rule type: machine_learning (72)](#unsupported-rule-type-machine_learning-72)
      1. [Unsupported rule type: threshold (29)](#unsupported-rule-type-threshold-29)
      1. [Unsupported rule type: esql (28)](#unsupported-rule-type-esql-28)
      1. [Unsupported rule type: threat_match (5)](#unsupported-rule-type-threat_match-5)
      1. [Unsupported query language: lucene (4)](#unsupported-query-language-lucene-4)
   1. [Generation errors](#generation-errors)
      1. [Root with too many branches (limit: 10000) (15)](#root-with-too-many-branches-limit-10000-15)
      1. [Unsupported LHS type: <class 'eql.ast.FunctionCall'> (12)](#unsupported-lhs-type-class-eqlastfunctioncall-12)
      1. [Unsupported function: stringContains (12)](#unsupported-function-stringcontains-12)
      1. [Unsupported function: match (11)](#unsupported-function-match-11)
      1. [Field type solver: match_only_text (7)](#field-type-solver-match_only_text-7)
      1. [Unsupported argument type(s): <class 'eql.ast.Field'> (6)](#unsupported-argument-types-class-eqlastfield-6)
      1. [Root without branches (4)](#root-without-branches-4)
      1. [Unsolvable constraints: process.name (excluded by Strings({'cmd.exe'}): ('cmd.exe')) (4)](#unsolvable-constraints-processname-excluded-by-stringscmdexe-cmdexe-4)
      1. [<class 'eql.ast.Sample'> (3)](#class-eqlastsample-3)
      1. [Unsupported &keyword 'file.Ext.windows.zone_identifier' constraint: > (3)](#unsupported-keyword-fileextwindowszone_identifier-constraint--3)
      1. [Unsupported argument type: <class 'eql.ast.FunctionCall'> (3)](#unsupported-argument-type-class-eqlastfunctioncall-3)
      1. [Unsupported function: startsWith (3)](#unsupported-function-startswith-3)
      1. [Pipes are unsupported (2)](#pipes-are-unsupported-2)
      1. [Unsolvable constraints: event.category & event.type (empty intersection) (2)](#unsolvable-constraints-eventcategory--eventtype-empty-intersection-2)
      1. [Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.dce_rpc')) (2)](#unsolvable-constraints-eventdataset-not-in-stringsnetwork_trafficflow-zeekdce_rpc-2)
      1. [Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)](#unsupported-keyword-processparentextrealpid-constraint--2)
      1. [Unsupported function: endswith (2)](#unsupported-function-endswith-2)
      1. [<class 'eql.ast.SubqueryBy'> (1)](#class-eqlastsubqueryby-1)
      1. [Cannot choose from an empty set (1)](#cannot-choose-from-an-empty-set-1)
      1. [Unsolvable constraints: aws.cloudtrail.request_parameters (not in Strings({'*LifecycleConfiguration*'}): ('*Expiration=*')) (1)](#unsolvable-constraints-awscloudtrailrequest_parameters-not-in-stringslifecycleconfiguration-expiration-1)
      1. [Unsolvable constraints: aws.cloudtrail.request_parameters (not in Strings({'*attribute=userData*'}): ('*instanceId*')) (1)](#unsolvable-constraints-awscloudtrailrequest_parameters-not-in-stringsattributeuserdata-instanceid-1)
      1. [Unsolvable constraints: aws.cloudtrail.request_parameters (not in Strings({'*imageId*'}): ('*add*')) (1)](#unsolvable-constraints-awscloudtrailrequest_parameters-not-in-stringsimageid-add-1)
      1. [Unsolvable constraints: aws.cloudtrail.request_parameters (not in Strings({'*lambda:InvokeFunction*'}): ('*principal=**')) (1)](#unsolvable-constraints-awscloudtrailrequest_parameters-not-in-stringslambdainvokefunction-principal-1)
      1. [Unsolvable constraints: event.dataset (not in Strings({'network_traffic.dns'}): ('zeek.dns')) (1)](#unsolvable-constraints-eventdataset-not-in-stringsnetwork_trafficdns-zeekdns-1)
      1. [Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.rdp')) (1)](#unsolvable-constraints-eventdataset-not-in-stringsnetwork_trafficflow-zeekrdp-1)
      1. [Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.smb')) (1)](#unsolvable-constraints-eventdataset-not-in-stringsnetwork_trafficflow-zeeksmb-1)
      1. [Unsolvable constraints: file.Ext.header_bytes (excluded by Strings({'504B0304*'}): ('504B0304*')) (1)](#unsolvable-constraints-fileextheader_bytes-excluded-by-strings504b0304-504b0304-1)
      1. [Unsolvable constraints: file.extension (cannot be non-null) (1)](#unsolvable-constraints-fileextension-cannot-be-non-null-1)
      1. [Unsolvable constraints: http.request.body.content (not in Strings({'*/swip/Upload.ashx*'}): ('POST*')) (1)](#unsolvable-constraints-httprequestbodycontent-not-in-stringsswipuploadashx-post-1)
      1. [Unsolvable constraints: kubernetes.audit.requestObject.spec.containers.image (cannot be null) (1)](#unsolvable-constraints-kubernetesauditrequestobjectspeccontainersimage-cannot-be-null-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (excluded by Strings({'DsGetSiteName'}): ('DsGetSiteName')) (1)](#unsolvable-constraints-powershellfilescript_block_text-excluded-by-stringsdsgetsitename-dsgetsitename-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscopyfromscreen-systemdrawingbitmap-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Cryptography.AESManaged'}): ('CipherMode')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscryptographyaesmanaged-ciphermode-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'DumpCreds'}): ('DumpCerts')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsdumpcreds-dumpcerts-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Eventing.Reader.EventLogSession'}): ('.ClearLog')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringseventingreadereventlogsession-clearlog-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Get-WmiObject'}): ('AntiVirusProduct')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsget-wmiobject-antivirusproduct-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'IO.Compression.ZipFile'}): ('CompressionLevel')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsiocompressionzipfile-compressionlevel-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Invoke-WmiMethod'}): ('ComputerName')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsinvoke-wmimethod-computername-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'LsaCallAuthenticationPackage'}): ('KerbRetrieveEncodedTicketMessage')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringslsacallauthenticationpackage-kerbretrieveencodedticketmessage-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'NTLMSSPNegotiate'}): ('NegotiateSMB')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsntlmsspnegotiate-negotiatesmb-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'STARTUPINFOEX'}): ('UpdateProcThreadAttribute')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsstartupinfoex-updateprocthreadattribute-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Set-MpPreference'}): ('DisableArchiveScanning')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsset-mppreference-disablearchivescanning-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'SetWindowsHookA'}): ('GetForegroundWindow')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssetwindowshooka-getforegroundwindow-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'System.IO.Compression.DeflateStream'}): ('FromBase64String')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssystemiocompressiondeflatestream-frombase64string-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsvirtualalloc-writeprocessmemory-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Windows.Clipboard'}): (']::GetText')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringswindowsclipboard-gettext-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[System.Runtime.InteropServices.Marshal]::Copy'}): ('VirtualProtect')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssystemruntimeinteropservicesmarshalcopy-virtualprotect-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[dbo].[Credentials]'}): ('Veeam')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsdbocredentials-veeam-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[string]::join'}): ('$pSHoMe[')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsstringjoin-pshome-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'capCreateCaptureWindowA'}): ('avicap32.dll')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscapcreatecapturewindowa-avicap32dll-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'defaultNamingContext'}): ('.MinLengthPassword')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsdefaultnamingcontext-minlengthpassword-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'shi1_netname'}): ('shi1_remark')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsshi1_netname-shi1_remark-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'waveInGetNumDevs'}): ('mciSendStringA')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringswaveingetnumdevs-mcisendstringa-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*drive.google.com*'}): ('*export=download*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsdrivegooglecom-exportdownload-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*fromhex*'}): ('*decode*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsfromhex-decode-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*id_dsa*'}): ('*/home/*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsid_dsa-home-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*net.ipv4.ip_forward*'}): ('*echo *')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsnetipv4ip_forward-echo--1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*vm.swappiness*'}): ('*echo *')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsvmswappiness-echo--1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'arp.exe'}): ('arp.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsarpexe-arpexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'elevation_service.exe'}): ('elevation_service.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringselevation_serviceexe-elevation_serviceexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'msdt.exe'}): ('msdt.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsmsdtexe-msdtexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'msedgewebview2.exe'}): ('msedgewebview2.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsmsedgewebview2exe-msedgewebview2exe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'powershell.exe'}): ('powershell.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringspowershellexe-powershellexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsrundll32exe-rundll32exe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'sc.exe'}): ('sc.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsscexe-scexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'sh'}): ('sh')) (1)](#unsolvable-constraints-processname-excluded-by-stringssh-sh-1)
      1. [Unsolvable constraints: process.name (not in Strings({'rundll32.exe'}): ('mshta.exe')) (1)](#unsolvable-constraints-processname-not-in-stringsrundll32exe-mshtaexe-1)
      1. [Unsolvable constraints: process.parent.args (excluded by Strings({'WdiSystemHost'}): ('WdiSystemHost')) (1)](#unsolvable-constraints-processparentargs-excluded-by-stringswdisystemhost-wdisystemhost-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'dllhost.exe'}): ('dllhost.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringsdllhostexe-dllhostexe-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringsrundll32exe-rundll32exe-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'winword.exe'}): ('winword.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringswinwordexe-winwordexe-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'wscript.exe'}): ('wscript.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringswscriptexe-wscriptexe-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*'}): ('*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings1131f6ad-9c07-11d1-f79f-00c04fc2dcd2s-1-5-21--1131f6aa-9c07-11d1-f79f-00c04fc2dcd2s-1-5-21--1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*42B5FAAE-6536-11D2-AE5A-0000F87571E3*'}): ('*40B66650-4972-11D1-A7CA-0000F87571E3*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings42b5faae-6536-11d2-ae5a-0000f87571e3-40b66650-4972-11d1-a7ca-0000f87571e3-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings827d319e-6eac-11d2-a4ea-00c04f79f83a-803e14a0-b4fb-11d0-a0d0-00a0c90f574b-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*CAB54552-DEEA-4691-817E-ED4A4D1AFC72*'}): ('*AADCED64-746C-4633-A97C-D61349046527*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-stringscab54552-deea-4691-817e-ed4a4d1afc72-aadced64-746c-4633-a97c-d61349046527-1)
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

### Unsupported rule type: new_terms (82)

82 rules:

* AWS CLI Command with Custom Endpoint URL
* AWS EC2 Admin Credential Fetch via Assumed Role
* AWS IAM Create User via Assumed Role on EC2 Instance
* AWS IAM Customer-Managed Policy Attached to Role by Rare User
* AWS SNS Email Subscription by Rare User
* AWS SSM Command Document Created by Rare User
* AWS SSM `SendCommand` Execution by Rare User
* AWS SSM `SendCommand` with Run Shell Command Parameters
* AWS STS AssumeRole with New MFA Device
* AWS STS AssumeRoot by Rare User and Member Account
* AWS STS GetCallerIdentity API Called for the First Time
* AWS STS Role Assumption by Service
* AWS STS Role Assumption by User
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
* First Occurrence of Entra ID Auth via DeviceCode Protocol
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
* Unusual Interactive Shell Launched from System User

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

### Unsupported rule type: threshold (29)

29 rules:

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

### Unsupported rule type: esql (28)

28 rules:

* AWS Bedrock Detected Multiple Attempts to use Denied Models by a Single User
* AWS Bedrock Detected Multiple Validation Exception Errors by a Single User
* AWS Bedrock Guardrails Detected Multiple Policy Violations Within a Single Blocked Request
* AWS Bedrock Guardrails Detected Multiple Violations by a Single User Over a Session
* AWS Discovery API Calls via CLI from a Single Resource
* AWS EC2 EBS Snapshot Shared with Another Account
* AWS EC2 Multi-Region DescribeInstances API Calls
* AWS IAM AdministratorAccess Policy Attached to Group
* AWS IAM AdministratorAccess Policy Attached to Role
* AWS IAM AdministratorAccess Policy Attached to User
* AWS IAM User Created Access Keys For Another User
* AWS S3 Bucket Enumeration or Brute Force
* AWS S3 Object Encryption Using External KMS Key
* AWS STS Role Chaining
* AWS Service Quotas Multi-Region `GetServiceQuota` Requests
* AWS Signin Single Factor Console Login with Federated User
* Attempts to Brute Force a Microsoft 365 User Account
* Azure Entra Sign-in Brute Force Microsoft 365 Accounts by Repeat Source
* Azure Entra Sign-in Brute Force against Microsoft 365 Accounts
* High Number of Okta Device Token Cookies Generated for Authentication
* Multiple Device Token Hashes for Single Okta Session
* Multiple Okta User Authentication Events with Client Address
* Multiple Okta User Authentication Events with Same Device Token Hash
* Okta User Sessions Started from Different Geolocations
* Potential AWS S3 Bucket Ransomware Note Uploaded
* Potential Abuse of Resources by High Token Count and Large Response Sizes
* Potential Widespread Malware Infection Across Multiple Hosts
* Unusual High Confidence Misconduct Blocks Detected

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

### Field type solver: match_only_text (7)

7 rules:
* Account Configured with Never-Expiring Password
* Kerberos Pre-authentication Disabled for User
* Segfault Detected
* Suspicious rc.local Error Message
* Tainted Kernel Module Load
* Tainted Out-Of-Tree Kernel Module Load
* Windows CryptoAPI Spoofing Vulnerability (CVE-2020-0601 - CurveBall)

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

### Unsolvable constraints: process.name (excluded by Strings({'cmd.exe'}): ('cmd.exe')) (4)

4 rules:
* Execution via MS VisualStudio Pre/Post Build Events
* Suspicious JetBrains TeamCity Child Process
* Suspicious Windows Command Shell Arguments
* Web Shell Detection: Script Process Child of Common Web Processes

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

### Unsolvable constraints: event.category & event.type (empty intersection) (2)

2 rules:
* Suspicious File Creation in /etc for Persistence
* Unsigned DLL loaded by DNS Service

### Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.dce_rpc')) (2)

2 rules:
* RPC (Remote Procedure Call) from the Internet
* RPC (Remote Procedure Call) to the Internet

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

### Unsolvable constraints: event.dataset (not in Strings({'network_traffic.dns'}): ('zeek.dns')) (1)

1 rules:
* Abnormally Large DNS Response

### Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.rdp')) (1)

1 rules:
* RDP (Remote Desktop Protocol) from the Internet

### Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.smb')) (1)

1 rules:
* SMB (Windows File Sharing) Activity to the Internet

### Unsolvable constraints: file.Ext.header_bytes (excluded by Strings({'504B0304*'}): ('504B0304*')) (1)

1 rules:
* Archive File with Unusual Extension

### Unsolvable constraints: file.extension (cannot be non-null) (1)

1 rules:
* Creation or Modification of Pluggable Authentication Module or Configuration

### Unsolvable constraints: http.request.body.content (not in Strings({'*/swip/Upload.ashx*'}): ('POST*')) (1)

1 rules:
* SUNBURST Command and Control Activity

### Unsolvable constraints: kubernetes.audit.requestObject.spec.containers.image (cannot be null) (1)

1 rules:
* Kubernetes Container Created with Excessive Linux Capabilities

### Unsolvable constraints: powershell.file.script_block_text (excluded by Strings({'DsGetSiteName'}): ('DsGetSiteName')) (1)

1 rules:
* PowerShell Suspicious Discovery Related Windows API Functions

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

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'NTLMSSPNegotiate'}): ('NegotiateSMB')) (1)

1 rules:
* Potential PowerShell Pass-the-Hash/Relay Script

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'STARTUPINFOEX'}): ('UpdateProcThreadAttribute')) (1)

1 rules:
* PowerShell Script with Token Impersonation Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Set-MpPreference'}): ('DisableArchiveScanning')) (1)

1 rules:
* PowerShell Script with Windows Defender Tampering Capabilities

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

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[dbo].[Credentials]'}): ('Veeam')) (1)

1 rules:
* PowerShell Script with Veeam Credential Access Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[string]::join'}): ('$pSHoMe[')) (1)

1 rules:
* Potential PowerShell Obfuscated Script

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

### Unsolvable constraints: process.command_line (not in Strings({'*drive.google.com*'}): ('*export=download*')) (1)

1 rules:
* Suspicious File Downloaded from Google Drive

### Unsolvable constraints: process.command_line (not in Strings({'*fromhex*'}): ('*decode*')) (1)

1 rules:
* Potential Hex Payload Execution

### Unsolvable constraints: process.command_line (not in Strings({'*id_dsa*'}): ('*/home/*')) (1)

1 rules:
* Private Key Searching Activity

### Unsolvable constraints: process.command_line (not in Strings({'*net.ipv4.ip_forward*'}): ('*echo *')) (1)

1 rules:
* IPv4/IPv6 Forwarding Activity

### Unsolvable constraints: process.command_line (not in Strings({'*vm.swappiness*'}): ('*echo *')) (1)

1 rules:
* Memory Swap Modification

### Unsolvable constraints: process.name (excluded by Strings({'arp.exe'}): ('arp.exe')) (1)

1 rules:
* Remote System Discovery Commands

### Unsolvable constraints: process.name (excluded by Strings({'elevation_service.exe'}): ('elevation_service.exe')) (1)

1 rules:
* Potential Privilege Escalation via InstallerFileTakeOver

### Unsolvable constraints: process.name (excluded by Strings({'msdt.exe'}): ('msdt.exe')) (1)

1 rules:
* Suspicious Microsoft Diagnostics Wizard Execution

### Unsolvable constraints: process.name (excluded by Strings({'msedgewebview2.exe'}): ('msedgewebview2.exe')) (1)

1 rules:
* Potential Masquerading as Browser Process

### Unsolvable constraints: process.name (excluded by Strings({'powershell.exe'}): ('powershell.exe')) (1)

1 rules:
* Delayed Execution via Ping

### Unsolvable constraints: process.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)

1 rules:
* Suspicious MS Office Child Process

### Unsolvable constraints: process.name (excluded by Strings({'sc.exe'}): ('sc.exe')) (1)

1 rules:
* Enumeration Command Spawned via WMIPrvSE

### Unsolvable constraints: process.name (excluded by Strings({'sh'}): ('sh')) (1)

1 rules:
* Suspicious macOS MS Office Child Process

### Unsolvable constraints: process.name (not in Strings({'rundll32.exe'}): ('mshta.exe')) (1)

1 rules:
* Script Execution via Microsoft HTML Application

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

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*'}): ('*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*')) (1)

1 rules:
* Potential Active Directory Replication Account Backdoor

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*42B5FAAE-6536-11D2-AE5A-0000F87571E3*'}): ('*40B66650-4972-11D1-A7CA-0000F87571E3*')) (1)

1 rules:
* Startup/Logon Script added to Group Policy Object

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)

1 rules:
* Group Policy Abuse for Privilege Addition

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*CAB54552-DEEA-4691-817E-ED4A4D1AFC72*'}): ('*AADCED64-746C-4633-A97C-D61349046527*')) (1)

1 rules:
* Scheduled Task Execution at Scale via GPO

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
