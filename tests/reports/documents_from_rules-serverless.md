# Documents generation from detection rules

This report captures the error reported while generating documents from detection rules. Here you
can learn what rules are still problematic and for which no documents can be generated at the moment.

Curious about the inner workings? Read [here](signals_generation.md).

Rules version: 9.2.2

## Table of contents
   1. [Skipped rules](#skipped-rules)
      1. [Unsupported rule type: new_terms (146)](#unsupported-rule-type-new_terms-146)
      1. [Unsupported rule type: machine_learning (95)](#unsupported-rule-type-machine_learning-95)
      1. [Unsupported rule type: esql (67)](#unsupported-rule-type-esql-67)
      1. [Unsupported rule type: threshold (31)](#unsupported-rule-type-threshold-31)
      1. [Unsupported rule type: threat_match (6)](#unsupported-rule-type-threat_match-6)
      1. [Unsupported query language: lucene (4)](#unsupported-query-language-lucene-4)
   1. [Generation errors](#generation-errors)
      1. [Unsupported function: match (22)](#unsupported-function-match-22)
      1. [Unsupported function: stringContains (20)](#unsupported-function-stringcontains-20)
      1. [Unsupported LHS type: <class 'eql.ast.FunctionCall'> (13)](#unsupported-lhs-type-class-eqlastfunctioncall-13)
      1. [Root with too many branches (limit: 10000) (12)](#root-with-too-many-branches-limit-10000-12)
      1. [Field type solver: constant_keyword (10)](#field-type-solver-constant_keyword-10)
      1. [Field type solver: match_only_text (7)](#field-type-solver-match_only_text-7)
      1. [Unsupported argument type(s): <class 'eql.ast.Field'> (7)](#unsupported-argument-types-class-eqlastfield-7)
      1. [Root without branches (6)](#root-without-branches-6)
      1. [Unsolvable constraints: process.name (excluded by Strings({'cmd.exe'}): ('cmd.exe')) (4)](#unsolvable-constraints-processname-excluded-by-stringscmdexe-cmdexe-4)
      1. [<class 'eql.ast.Sample'> (3)](#class-eqlastsample-3)
      1. [Unsolvable constraints: event.category & event.type (empty intersection) (3)](#unsolvable-constraints-eventcategory--eventtype-empty-intersection-3)
      1. [Unsupported argument type(s): <class 'eql.ast.FunctionCall'> (3)](#unsupported-argument-types-class-eqlastfunctioncall-3)
      1. [Unsupported argument type: <class 'eql.ast.FunctionCall'> (3)](#unsupported-argument-type-class-eqlastfunctioncall-3)
      1. [Unsupported function: endswith (3)](#unsupported-function-endswith-3)
      1. [Unsupported function: startsWith (3)](#unsupported-function-startswith-3)
      1. [Pipes are unsupported (2)](#pipes-are-unsupported-2)
      1. [Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.dce_rpc')) (2)](#unsolvable-constraints-eventdataset-not-in-stringsnetwork_trafficflow-zeekdce_rpc-2)
      1. [Unsolvable constraints: process.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (2)](#unsolvable-constraints-processname-excluded-by-stringsrundll32exe-rundll32exe-2)
      1. [Unsupported &keyword 'file.Ext.windows.zone_identifier' constraint: > (2)](#unsupported-keyword-fileextwindowszone_identifier-constraint--2)
      1. [Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)](#unsupported-keyword-processparentextrealpid-constraint--2)
      1. [<class 'eql.ast.SubqueryBy'> (1)](#class-eqlastsubqueryby-1)
      1. [Field type solver: flattened (1)](#field-type-solver-flattened-1)
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
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Microsoft.Office.Interop.Outlook'}): ('MAPI')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsmicrosoftofficeinteropoutlook-mapi-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'NTLMSSPNegotiate'}): ('NegotiateSMB')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsntlmsspnegotiate-negotiatesmb-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'STARTUPINFOEX'}): ('UpdateProcThreadAttribute')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsstartupinfoex-updateprocthreadattribute-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Set-MpPreference'}): ('DisableArchiveScanning')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsset-mppreference-disablearchivescanning-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'SetWindowsHookA'}): ('GetForegroundWindow')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssetwindowshooka-getforegroundwindow-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'System.IO.Compression.DeflateStream'}): ('FromBase64String')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssystemiocompressiondeflatestream-frombase64string-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsvirtualalloc-writeprocessmemory-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Windows.Clipboard'}): (']::GetText')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringswindowsclipboard-gettext-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[Ref].Assembly.GetType(('System.Management.Automation'}): ('.SetValue(')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsrefassemblygettypesystemmanagementautomation-setvalue-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[dbo].[Credentials]'}): ('Veeam')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsdbocredentials-veeam-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[string]::join'}): ('$pSHoMe[')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsstringjoin-pshome-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'capCreateCaptureWindowA'}): ('avicap32.dll')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscapcreatecapturewindowa-avicap32dll-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'defaultNamingContext'}): ('.MinLengthPassword')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsdefaultnamingcontext-minlengthpassword-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'shi1_netname'}): ('shi1_remark')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsshi1_netname-shi1_remark-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'waveInGetNumDevs'}): ('mciSendStringA')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringswaveingetnumdevs-mcisendstringa-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*@/*.zip*'}): ('*http*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringszip-http-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*\\*\*$*'}): ('*copy*')) (1)](#unsolvable-constraints-processcommand_line-not-in-strings-copy-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*drive.google.com*'}): ('*export=download*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsdrivegooglecom-exportdownload-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*fromhex*'}): ('*decode*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsfromhex-decode-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*id_dsa*'}): ('*/home/*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsid_dsa-home-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*net.ipv4.ip_forward*'}): ('*echo *')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsnetipv4ip_forward-echo--1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*vm.swappiness*'}): ('*echo *')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsvmswappiness-echo--1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'arp.exe'}): ('arp.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsarpexe-arpexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'dash'}): ('dash')) (1)](#unsolvable-constraints-processname-excluded-by-stringsdash-dash-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'elevation_service.exe'}): ('elevation_service.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringselevation_serviceexe-elevation_serviceexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'msdt.exe'}): ('msdt.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsmsdtexe-msdtexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'msedgewebview2.exe'}): ('msedgewebview2.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsmsedgewebview2exe-msedgewebview2exe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'net1.exe'}): ('net1.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsnet1exe-net1exe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'powershell.exe'}): ('powershell.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringspowershellexe-powershellexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'sc.exe'}): ('sc.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsscexe-scexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'sh'}): ('sh')) (1)](#unsolvable-constraints-processname-excluded-by-stringssh-sh-1)
      1. [Unsolvable constraints: process.name (not in Strings({'pluginkit'}): ('python*')) (1)](#unsolvable-constraints-processname-not-in-stringspluginkit-python-1)
      1. [Unsolvable constraints: process.name (not in Strings({'rundll32.exe'}): ('mshta.exe')) (1)](#unsolvable-constraints-processname-not-in-stringsrundll32exe-mshtaexe-1)
      1. [Unsolvable constraints: process.parent.args (excluded by Strings({'WdiSystemHost'}): ('WdiSystemHost')) (1)](#unsolvable-constraints-processparentargs-excluded-by-stringswdisystemhost-wdisystemhost-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'dllhost.exe'}): ('dllhost.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringsdllhostexe-dllhostexe-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringsrundll32exe-rundll32exe-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'winword.exe'}): ('winword.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringswinwordexe-winwordexe-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'wscript.exe'}): ('wscript.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringswscriptexe-wscriptexe-1)
      1. [Unsolvable constraints: process.pid (out of boundary, 1 <= 0 <= 4294967295) (1)](#unsolvable-constraints-processpid-out-of-boundary-1--0--4294967295-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*'}): ('*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings1131f6ad-9c07-11d1-f79f-00c04fc2dcd2s-1-5-21--1131f6aa-9c07-11d1-f79f-00c04fc2dcd2s-1-5-21--1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*42B5FAAE-6536-11D2-AE5A-0000F87571E3*'}): ('*40B66650-4972-11D1-A7CA-0000F87571E3*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings42b5faae-6536-11d2-ae5a-0000f87571e3-40b66650-4972-11d1-a7ca-0000f87571e3-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings827d319e-6eac-11d2-a4ea-00c04f79f83a-803e14a0-b4fb-11d0-a0d0-00a0c90f574b-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*CAB54552-DEEA-4691-817E-ED4A4D1AFC72*'}): ('*AADCED64-746C-4633-A97C-D61349046527*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-stringscab54552-deea-4691-817e-ed4a4d1afc72-aadced64-746c-4633-a97c-d61349046527-1)
      1. [Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: < (1)](#unsupported-keyword-dllextrelative_file_creation_time-constraint--1)
      1. [Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: <= (1)](#unsupported-keyword-dllextrelative_file_creation_time-constraint--1)
      1. [Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)](#unsupported-keyword-fileextentropy-constraint--1)
      1. [Unsupported &keyword 'ml_is_dga.malicious_probability' constraint: > (1)](#unsupported-keyword-ml_is_dgamalicious_probability-constraint--1)
      1. [Unsupported &keyword 'o365.audit.OperationCount' constraint: >= (1)](#unsupported-keyword-o365auditoperationcount-constraint--1)
      1. [Unsupported &keyword 'problemchild.prediction_probability' constraint: <= (1)](#unsupported-keyword-problemchildprediction_probability-constraint--1)
      1. [Unsupported &keyword 'problemchild.prediction_probability' constraint: > (1)](#unsupported-keyword-problemchildprediction_probability-constraint--1)
      1. [Unsupported &keyword 'process.Ext.relative_file_creation_time' constraint: <= (1)](#unsupported-keyword-processextrelative_file_creation_time-constraint--1)
      1. [Unsupported &keyword 'user.id' constraint: >= (1)](#unsupported-keyword-userid-constraint--1)
      1. [Unsupported is_negated: {'is_negated': True} (1)](#unsupported-is_negated-is_negated-true-1)

## Skipped rules

### Unsupported rule type: new_terms (146)

146 rules:

* AWS CLI Command with Custom Endpoint URL
* AWS DynamoDB Scan by Unusual User
* AWS DynamoDB Table Exported to S3
* AWS EC2 Route Table Created
* AWS EC2 Route Table Modified or Deleted
* AWS EC2 Unauthorized Admin Credential Fetch via Assumed Role
* AWS EC2 User Data Retrieval for EC2 Instance
* AWS First Occurrence of STS GetFederationToken Request by User
* AWS IAM API Calls via Temporary Session Tokens
* AWS IAM Assume Role Policy Update
* AWS IAM Create User via Assumed Role on EC2 Instance
* AWS IAM Customer-Managed Policy Attached to Role by Rare User
* AWS S3 Unauthenticated Bucket Access by Rare Source
* AWS SNS Rare Protocol Subscription by User
* AWS SNS Topic Created by Rare User
* AWS SNS Topic Message Publish by Rare User
* AWS SSM Command Document Created by Rare User
* AWS SSM Session Started to EC2 Instance
* AWS SSM `SendCommand` Execution by Rare User
* AWS SSM `SendCommand` with Run Shell Command Parameters
* AWS STS AssumeRole with New MFA Device
* AWS STS AssumeRoot by Rare User and Member Account
* AWS STS GetCallerIdentity API Called for the First Time
* AWS STS Role Assumption by Service
* AWS STS Role Assumption by User
* AWS STS Role Chaining
* AWS Systems Manager SecureString Parameter Request with Decryption Flag
* Abnormal Process ID or Lock File Created
* Authentication via Unusual PAM Grantor
* Azure Compute Restore Point Collection Deleted by Unusual User
* Azure Entra ID Rare App ID for Principal Authentication
* Azure Key Vault Modified
* Azure Key Vault Secret Key Usage by Unusual Identity
* Azure Storage Account Blob Public Access Enabled
* Azure Storage Account Deletion by Unusual User
* Azure Storage Account Keys Accessed by Privileged User
* Azure Storage Blob Retrieval via AzCopy
* CAP_SYS_ADMIN Assigned to Binary
* DPKG Package Installed by Unusual Parent Process
* Delegated Managed Service Account Modification by an Unusual User
* Discovery of Internet Capabilities via Built-in Tools
* Entra ID OAuth user_impersonation Scope for Unusual User and Client
* Entra ID User Signed In from Unusual Device
* Enumeration of Kernel Modules
* Enumeration of Kernel Modules via Proc
* Enumeration of Privileged Local Groups Membership
* Execution of an Unsigned Service
* Execution via MSSQL xp_cmdshell Stored Procedure
* External Authentication Method Addition or Modification in Entra ID
* File Creation in /var/log via Suspicious Process
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
* First Occurrence of User Agent For a GitHub Personal Access Token (PAT)
* First Occurrence of User-Agent For a GitHub User
* First Time AWS CloudFormation Stack Creation
* First Time Seen AWS Secret Value Accessed in Secrets Manager
* First Time Seen Commonly Abused Remote Access Tool Execution
* First Time Seen Driver Loaded
* First Time Seen Google Workspace OAuth Login from Third-Party Application
* First Time Seen NewCredentials Logon Process
* First Time Seen Removable Device
* FirstTime Seen Account Performing DCSync
* Kernel Object File Creation
* Kill Command Execution
* Kubernetes Unusual Decision by User Agent
* LSASS Memory Dump Handle Access
* Linux Clipboard Activity Detected
* M365 Identity Login from Atypical Travel Location
* Microsoft 365 Illicit Consent Grant via Registered Application
* Microsoft 365 Suspicious Inbox Rule to Delete or Move Emails
* Microsoft Build Engine Started an Unusual Process
* Microsoft Build Engine Started by a Script Process
* Microsoft Entra ID Conditional Access Policy (CAP) Modified
* Microsoft Entra ID Elevated Access to User Access Administrator
* Microsoft Entra ID Illicit Consent Grant via Registered Application
* Microsoft Entra ID Rare Authentication Requirement for Principal User
* Microsoft Entra ID Service Principal Credentials Added by Rare User
* Microsoft Entra ID SharePoint Access for User Principal via Auth Broker
* Microsoft Graph First Occurrence of Client Request
* Modification of Dynamic Linker Preload Shared Object
* Modification of Standard Authentication Module or Configuration
* Network Activity Detected via Kworker
* Network Traffic Capture via CAP_NET_RAW
* New USB Storage Device Mounted
* Potential Credential Access via DCSync
* Potential Pass-the-Hash (PtH) Attempt
* Potential Privilege Escalation via Linux DAC permissions
* Potential Shadow File Read via Command Line Utilities
* Privileged Docker Container Creation
* Process Backgrounded by Unusual Parent
* Query Registry using Built-in Tools
* RPM Package Installed by Unusual Parent Process
* Rare SMB Connection to the Internet
* SSH Authorized Keys File Modification
* Sensitive Files Compression
* Shared Object Created or Changed by Previously Unknown Process
* Successful Application SSO from Rare Unknown Client Device
* Successful SSH Authentication from Unusual IP Address
* Successful SSH Authentication from Unusual SSH Public Key
* Successful SSH Authentication from Unusual User
* Suspicious Email Access by First-Party Application via Microsoft Graph
* Suspicious Mailbox Permission Delegation in Exchange Online
* Suspicious Microsoft 365 Mail Access by Unusual ClientAppId
* Suspicious Modprobe File Event
* Suspicious Named Pipe Creation
* Suspicious Network Activity to the Internet by Previously Unknown Executable
* Suspicious Path Invocation from Command Line
* Suspicious PowerShell Engine ImageLoad
* Suspicious PrintSpooler Service Executable File Creation
* Suspicious Sysctl File Event
* Suspicious System Commands Executed by Previously Unknown Executable
* Svchost spawning Cmd
* System Binary Symlink to Suspicious Location
* Systemd Service Started by Unusual Parent Process
* UID Elevation from Previously Unknown Executable
* Unauthorized Scope for Public App OAuth2 Token Grant with Client Credentials
* Unknown Execution of Binary with RWX Memory Region
* Unusual AWS S3 Object Encryption with SSE-C
* Unusual Discovery Activity by User
* Unusual Discovery Signal Alert with Unusual Process Command Line
* Unusual Discovery Signal Alert with Unusual Process Executable
* Unusual Execution from Kernel Thread (kthreadd) Parent
* Unusual Exim4 Child Process
* Unusual File Operation by dns.exe
* Unusual Interactive Process Launched in a Container
* Unusual Interactive Shell Launched from System User
* Unusual LD_PRELOAD/LD_LIBRARY_PATH Command Line Arguments
* Unusual Network Connection to Suspicious Top Level Domain
* Unusual Network Connection to Suspicious Web Service
* Unusual Pkexec Execution
* Unusual Preload Environment Variable Process Execution
* Unusual ROPC Login Attempt by User Principal
* Unusual Remote File Creation
* Unusual SSHD Child Process
* Unusual Scheduled Task Update
* Unusual Web Config File Access
* Web Shell Detection: Script Process Child of Common Web Processes
* dMSA Account Creation by an Unusual User

### Unsupported rule type: machine_learning (95)

95 rules:

* Anomalous Linux Compiler Activity
* Anomalous Process For a Linux Population
* Anomalous Process For a Windows Population
* Anomalous Windows Process Creation
* DNS Tunneling
* Decline in host-based traffic
* High Command Line Entropy Detected for Privileged Commands
* High Mean of Process Arguments in an RDP Session
* High Mean of RDP Session Duration
* High Variance in RDP Session Duration
* Host Detected with Suspicious Windows Process(es)
* Network Traffic to Rare Destination Country
* Parent Process Detected with Suspicious Windows Process(es)
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
* Spike in Group Application Assignment Change Events
* Spike in Group Lifecycle Change Events
* Spike in Group Management Events
* Spike in Group Membership Events
* Spike in Group Privilege Change Events
* Spike in Logon Events
* Spike in Network Traffic
* Spike in Network Traffic To a Country
* Spike in Number of Connections Made from a Source IP
* Spike in Number of Connections Made to a Destination IP
* Spike in Number of Processes in an RDP Session
* Spike in Privileged Command Execution by a User
* Spike in Remote File Transfers
* Spike in Special Logon Events
* Spike in Special Privilege Use Events
* Spike in Successful Logon Events from a Source IP
* Spike in User Account Management Events
* Spike in User Lifecycle Management Change Events
* Spike in host-based traffic
* Suspicious Powershell Script
* Unusual AWS Command for a User
* Unusual City For an AWS Command
* Unusual Country For an AWS Command
* Unusual DNS Activity
* Unusual Group Name Accessed by a User
* Unusual Host Name for Okta Privileged Operations Detected
* Unusual Host Name for Windows Privileged Operations Detected
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
* Unusual Privilege Type assigned to a User
* Unusual Process Detected for Privileged Commands by a User
* Unusual Process For a Linux Host
* Unusual Process For a Windows Host
* Unusual Process Spawned by a Host
* Unusual Process Spawned by a Parent Process
* Unusual Process Spawned by a User
* Unusual Process Writing Data to an External Device
* Unusual Region Name for Okta Privileged Operations Detected
* Unusual Region Name for Windows Privileged Operations Detected
* Unusual Remote File Directory
* Unusual Remote File Extension
* Unusual Remote File Size
* Unusual Source IP for Okta Privileged Operations Detected
* Unusual Source IP for Windows Privileged Operations Detected
* Unusual Source IP for a User to Logon from
* Unusual Spike in Concurrent Active Sessions by a User
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
* User Detected with Suspicious Windows Process(es)

### Unsupported rule type: esql (67)

67 rules:

* AWS Access Token Used from Multiple Addresses
* AWS Bedrock Detected Multiple Attempts to use Denied Models by a Single User
* AWS Bedrock Detected Multiple Validation Exception Errors by a Single User
* AWS Bedrock Guardrails Detected Multiple Policy Violations Within a Single Blocked Request
* AWS Bedrock Guardrails Detected Multiple Violations by a Single User Over a Session
* AWS Bedrock Invocations without Guardrails Detected by a Single User Over a Session
* AWS Discovery API Calls via CLI from a Single Resource
* AWS EC2 Multi-Region DescribeInstances API Calls
* AWS IAM User Created Access Keys For Another User
* AWS S3 Object Encryption Using External KMS Key
* AWS S3 Static Site JavaScript File Uploaded
* AWS Service Quotas Multi-Region `GetServiceQuota` Requests
* Azure OpenAI Insecure Output Handling
* Command Line Obfuscation via Whitespace Padding
* Dynamic IEX Reconstruction via Method String Access
* Entra ID Actor Token User Impersonation Abuse
* Excessive Secret or Key Retrieval from Azure Key Vault
* High Number of Egress Network Connections from Unusual Executable
* High Number of Okta Device Token Cookies Generated for Authentication
* M365 OneDrive Excessive File Downloads with OAuth Token
* Microsoft 365 Brute Force via Entra ID Sign-Ins
* Microsoft 365 or Entra ID Sign-in from a Suspicious Source
* Microsoft Entra ID Concurrent Sign-Ins with Suspicious Properties
* Microsoft Entra ID Exccessive Account Lockouts Detected
* Microsoft Entra ID MFA TOTP Brute Force Attempts
* Microsoft Entra ID Sign-In Brute Force Activity
* Microsoft Entra ID Suspicious Session Reuse to Graph Access
* Multiple Device Token Hashes for Single Okta Session
* Multiple Microsoft 365 User Account Lockouts in Short Time Window
* Multiple Okta User Authentication Events with Client Address
* Multiple Okta User Authentication Events with Same Device Token Hash
* OIDC Discovery URL Changed in Entra ID
* Okta User Sessions Started from Different Geolocations
* Potential Abuse of Resources by High Token Count and Large Response Sizes
* Potential Azure OpenAI Model Theft
* Potential Denial of Azure OpenAI ML Service
* Potential Dynamic IEX Reconstruction via Environment Variables
* Potential Malicious PowerShell Based on Alert Correlation
* Potential Malware-Driven SSH Brute Force Attempt
* Potential Microsoft 365 User Account Brute Force
* Potential Port Scanning Activity from Compromised Host
* Potential PowerShell Obfuscation via Backtick-Escaped Variable Expansion
* Potential PowerShell Obfuscation via Character Array Reconstruction
* Potential PowerShell Obfuscation via Concatenated Dynamic Command Invocation
* Potential PowerShell Obfuscation via High Numeric Character Proportion
* Potential PowerShell Obfuscation via High Special Character Proportion
* Potential PowerShell Obfuscation via Invalid Escape Sequences
* Potential PowerShell Obfuscation via Reverse Keywords
* Potential PowerShell Obfuscation via Special Character Overuse
* Potential PowerShell Obfuscation via String Concatenation
* Potential PowerShell Obfuscation via String Reordering
* Potential Ransomware Behavior - Note Files by System
* Potential Subnet Scanning Activity from Compromised Host
* Potential Widespread Malware Infection Across Multiple Hosts
* PowerShell Obfuscation via Negative Index String Reversal
* Rare Connection to WebDAV Target
* Suspicious Microsoft 365 UserLoggedIn via OAuth Code
* Suspicious Microsoft OAuth Flow via Auth Broker to DRS
* Unusual Base64 Encoding/Decoding Activity
* Unusual Command Execution from Web Server Parent
* Unusual File Creation by Web Server
* Unusual File Transfer Utility Launched
* Unusual High Confidence Content Filter Blocks Detected
* Unusual High Denied Sensitive Information Policy Blocks Detected
* Unusual High Denied Topic Blocks Detected
* Unusual High Word Policy Blocks Detected
* Unusual Process Spawned from Web Server Parent

### Unsupported rule type: threshold (31)

31 rules:

* AWS IAM Brute Force of Assume Role Policy
* AWS Management Console Brute Force of Root User Identity
* AWS S3 Bucket Enumeration or Brute Force
* Agent Spoofing - Multiple Hosts Using Same Agent
* Attempts to Brute Force an Okta User Account
* Azure Compute Restore Point Collections Deleted
* Azure Storage Account Deletions by User
* Excessive AWS S3 Object Encryption with SSE-C
* GitHub UEBA - Multiple Alerts from a GitHub Account
* High Number of Cloned GitHub Repos From PAT
* High Number of Okta User Password Reset or Unlock Attempts
* High Number of Process Terminations
* High Number of Process and/or Service Terminations
* M365 Identity Login from Impossible Travel Location
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
* Potential SYN-Based Port Scan Detected
* Potential macOS SSH Brute Force Detected
* Rapid Secret Retrieval Attempts from AWS SecretsManager
* Sudo Heap-Based Buffer Overflow Attempt
* Suspicious Proc Pseudo File System Enumeration

### Unsupported rule type: threat_match (6)

6 rules:

* Rapid7 Threat Command CVEs Correlation
* Threat Intel Email Indicator Match
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

### Unsupported function: match (22)

22 rules:
* Alternate Data Stream Creation/Execution at Volume Root Directory
* BloodHound Suite User-Agents Detected
* Creation of Hidden Files and Directories via CommandLine
* Executable File Creation with Multiple Extensions
* Masquerading Space After Filename
* Network Activity to a Suspicious Top Level Domain
* Potential AWS S3 Bucket Ransomware Note Uploaded
* Potential Command Shell via NetCat
* Potential Credential Access via Windows Utilities
* Potential Exploitation of an Unquoted Service Path Vulnerability
* Potential Windows Error Manager Masquerading
* Process Created with a Duplicated Token
* Process Started from Process ID (PID) File
* Remote File Download via PowerShell
* SUID/SGID Bit Set
* Simple HTTP Web Server Connection
* Simple HTTP Web Server Creation
* Suspicious Execution via Microsoft Office Add-Ins
* Suspicious Service was Installed in the System
* Unusual Child Processes of RunDLL32
* Unusual Network Connection via RunDLL32
* Unusual Process Execution Path - Alternate Data Stream

### Unsupported function: stringContains (20)

20 rules:
* AWS EC2 EBS Snapshot Access Removed
* AWS EC2 EBS Snapshot Shared or Made Public
* AWS EC2 Instance Console Login via Assumed Role
* AWS EC2 Instance Interaction with IAM Service
* AWS IAM AdministratorAccess Policy Attached to Group
* AWS IAM AdministratorAccess Policy Attached to Role
* AWS IAM AdministratorAccess Policy Attached to User
* AWS IAM CompromisedKeyQuarantine Policy Attached to User
* AWS IAM Login Profile Added for Root
* AWS RDS DB Instance Made Public
* AWS RDS DB Instance or Cluster Deletion Protection Disabled
* AWS RDS DB Instance or Cluster Password Modified
* AWS RDS DB Snapshot Shared with Another Account
* AWS RDS Snapshot Deleted
* AWS S3 Bucket Expiration Lifecycle Configuration Added
* AWS S3 Bucket Policy Added to Allow Public Access
* AWS S3 Bucket Policy Added to Share with External Account
* AWS S3 Bucket Replicated to Another Account
* AWS S3 Bucket Server Access Logging Disabled
* AWS S3 Object Versioning Suspended

### Unsupported LHS type: <class 'eql.ast.FunctionCall'> (13)

13 rules:
* AdminSDHolder SDProp Exclusion Added
* Image File Execution Options Injection
* Ingress Transfer via Windows BITS
* Memory Dump File with Unusual Extension
* NullSessionPipe Registry Modification
* Persistence via Hidden Run Key Detected
* Potential Hex Payload Execution via Command-Line
* Potential curl CVE-2023-38545 Exploitation
* Renamed Utility Executed with Short Program Name
* Suspicious Access to LDAP Attributes
* Suspicious Execution via MSIEXEC
* Suspicious Process Access via Direct System Call
* Uncommon Registry Persistence Change

### Root with too many branches (limit: 10000) (12)

12 rules:
* Connection to Commonly Abused Web Services
* Execution from Unusual Directory - Command Line
* External IP Lookup from Non-Browser Process
* Potential DNS Tunneling via NsLookup
* Potential Evasion via Windows Filtering Platform
* Potential Linux Ransomware Note Creation Detected
* Potential Masquerading as System32 DLL
* Potential Masquerading as System32 Executable
* Potential Pspy Process Monitoring Detected
* Potential Remote Code Execution via Web Server
* Potential Reverse Shell via Suspicious Binary
* Potential Reverse Shell via Suspicious Child Process

### Field type solver: constant_keyword (10)

10 rules:
* CrowdStrike External Alerts
* Elastic Security External Alerts
* Google SecOps External Alerts
* Microsoft Sentinel External Alerts
* Potential DLL Side-Loading via Trusted Microsoft Programs
* Potential Toolshell Initial Exploit (CVE-2025-53770 & CVE-2025-53771)
* Potential VIEWSTATE RCE Attempt on SharePoint/IIS
* SentinelOne Alert External Alerts
* SentinelOne Threat External Alerts
* Splunk External Alerts

### Field type solver: match_only_text (7)

7 rules:
* Process Started with Executable Stack
* Segfault Detected
* Suspicious Usage of bpf_probe_write_user Helper
* Suspicious rc.local Error Message
* Tainted Kernel Module Load
* Tainted Out-Of-Tree Kernel Module Load
* Windows CryptoAPI Spoofing Vulnerability (CVE-2020-0601 - CurveBall)

### Unsupported argument type(s): <class 'eql.ast.Field'> (7)

7 rules:
* External User Added to Google Workspace Group
* Image Loaded with Invalid Signature
* Interactive Logon by an Unusual Process
* Potential Ransomware Note File Dropped via SMB
* Suspicious File Renamed via SMB
* Unusual Network Activity from a Windows System Binary
* Windows Service Installed via an Unusual Client

### Root without branches (6)

6 rules:
* Docker Escape via Nsenter
* Initramfs Extraction via CPIO
* Kubectl Configuration Discovery
* Linux init (PID 1) Secret Dump via GDB
* Potential Protocol Tunneling via Chisel Server
* Suspicious Data Encryption via OpenSSL Utility

### Unsolvable constraints: process.name (excluded by Strings({'cmd.exe'}): ('cmd.exe')) (4)

4 rules:
* Execution via MS VisualStudio Pre/Post Build Events
* Suspicious Execution from a WebDav Share
* Suspicious JetBrains TeamCity Child Process
* Suspicious Windows Command Shell Arguments

### <class 'eql.ast.Sample'> (3)

3 rules:
* Network Connection from Binary with RWX Memory Region
* Potential Meterpreter Reverse Shell
* Potential Reverse Shell via UDP

### Unsolvable constraints: event.category & event.type (empty intersection) (3)

3 rules:
* File with Right-to-Left Override Character (RTLO) Created/Executed
* Python Site or User Customize File Creation
* Unsigned DLL loaded by DNS Service

### Unsupported argument type(s): <class 'eql.ast.FunctionCall'> (3)

3 rules:
* Potential Kerberos Relay Attack against a Computer Account
* Potential NTLM Relay Attack against a Computer Account
* Remote Computer Account DnsHostName Update

### Unsupported argument type: <class 'eql.ast.FunctionCall'> (3)

3 rules:
* Active Directory Forced Authentication from Linux Host - SMB Named Pipes
* Unsigned DLL Loaded by a Trusted Process
* Unsigned DLL Side-Loading from a Suspicious Folder

### Unsupported function: endswith (3)

3 rules:
* Potential Computer Account Relay Activity
* Potential Machine Account Relay Attack via SMB
* Unusual Execution via Microsoft Common Console File

### Unsupported function: startsWith (3)

3 rules:
* Persistent Scripts in the Startup Directory
* Potential ADIDNS Poisoning via Wildcard Record Creation
* SMB Connections via LOLBin or Untrusted Process

### Pipes are unsupported (2)

2 rules:
* Potential Successful Linux FTP Brute Force Attack Detected
* Potential Successful Linux RDP Brute Force Attack Detected

### Unsolvable constraints: event.dataset (not in Strings({'network_traffic.flow'}): ('zeek.dce_rpc')) (2)

2 rules:
* RPC (Remote Procedure Call) from the Internet
* RPC (Remote Procedure Call) to the Internet

### Unsolvable constraints: process.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (2)

2 rules:
* Potential Execution via FileFix Phishing Attack
* Suspicious MS Office Child Process

### Unsupported &keyword 'file.Ext.windows.zone_identifier' constraint: > (2)

2 rules:
* Downloaded Shortcut Files
* File with Suspicious Extension Downloaded

### Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)

2 rules:
* Parent Process PID Spoofing
* Privileges Elevation via Parent Process PID Spoofing

### <class 'eql.ast.SubqueryBy'> (1)

1 rules:
* Potential Okta MFA Bombing via Push Notifications

### Field type solver: flattened (1)

1 rules:
* Suspicious ADRS Token Request by Microsoft Auth Broker

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

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Microsoft.Office.Interop.Outlook'}): ('MAPI')) (1)

1 rules:
* PowerShell Mailbox Collection Script

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

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[Ref].Assembly.GetType(('System.Management.Automation'}): ('.SetValue(')) (1)

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

### Unsolvable constraints: process.command_line (not in Strings({'*@/*.zip*'}): ('*http*')) (1)

1 rules:
* Potential Data Exfiltration Through Curl

### Unsolvable constraints: process.command_line (not in Strings({'*\\*\*$*'}): ('*copy*')) (1)

1 rules:
* Remote File Copy to a Hidden Share

### Unsolvable constraints: process.command_line (not in Strings({'*drive.google.com*'}): ('*export=download*')) (1)

1 rules:
* Suspicious File Downloaded from Google Drive

### Unsolvable constraints: process.command_line (not in Strings({'*fromhex*'}): ('*decode*')) (1)

1 rules:
* Potential Hex Payload Execution via Common Utility

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

### Unsolvable constraints: process.name (excluded by Strings({'dash'}): ('dash')) (1)

1 rules:
* Potential CVE-2025-32463 Nsswitch File Creation

### Unsolvable constraints: process.name (excluded by Strings({'elevation_service.exe'}): ('elevation_service.exe')) (1)

1 rules:
* Potential Privilege Escalation via InstallerFileTakeOver

### Unsolvable constraints: process.name (excluded by Strings({'msdt.exe'}): ('msdt.exe')) (1)

1 rules:
* Suspicious Microsoft Diagnostics Wizard Execution

### Unsolvable constraints: process.name (excluded by Strings({'msedgewebview2.exe'}): ('msedgewebview2.exe')) (1)

1 rules:
* Potential Masquerading as Browser Process

### Unsolvable constraints: process.name (excluded by Strings({'net1.exe'}): ('net1.exe')) (1)

1 rules:
* Account Discovery Command via SYSTEM Account

### Unsolvable constraints: process.name (excluded by Strings({'powershell.exe'}): ('powershell.exe')) (1)

1 rules:
* Delayed Execution via Ping

### Unsolvable constraints: process.name (excluded by Strings({'sc.exe'}): ('sc.exe')) (1)

1 rules:
* Enumeration Command Spawned via WMIPrvSE

### Unsolvable constraints: process.name (excluded by Strings({'sh'}): ('sh')) (1)

1 rules:
* Suspicious macOS MS Office Child Process

### Unsolvable constraints: process.name (not in Strings({'pluginkit'}): ('python*')) (1)

1 rules:
* Finder Sync Plugin Registered and Enabled

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

### Unsolvable constraints: process.pid (out of boundary, 1 <= 0 <= 4294967295) (1)

1 rules:
* Service Creation via Local Kerberos Authentication

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

### Unsupported &keyword 'o365.audit.OperationCount' constraint: >= (1)

1 rules:
* Excessive Microsoft 365 Mailbox Items Accessed

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

### Unsupported is_negated: {'is_negated': True} (1)

1 rules:
* MFA Deactivation with no Re-Activation for Okta User Account
