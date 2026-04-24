# Documents generation from detection rules

This report captures the error reported while generating documents from detection rules. Here you
can learn what rules are still problematic and for which no documents can be generated at the moment.

Curious about the inner workings? Read [here](signals_generation.md).

Rules version: 8.19.21

## Table of contents
   1. [Skipped rules](#skipped-rules)
      1. [Unsupported rule type: new_terms (184)](#unsupported-rule-type-new_terms-184)
      1. [Unsupported rule type: esql (138)](#unsupported-rule-type-esql-138)
      1. [Unsupported rule type: machine_learning (95)](#unsupported-rule-type-machine_learning-95)
      1. [Unsupported rule type: threshold (28)](#unsupported-rule-type-threshold-28)
      1. [Unsupported rule type: threat_match (6)](#unsupported-rule-type-threat_match-6)
      1. [Unsupported query language: lucene (4)](#unsupported-query-language-lucene-4)
   1. [Generation errors](#generation-errors)
      1. [Field type solver: constant_keyword (275)](#field-type-solver-constant_keyword-275)
      1. [Unsupported function: match (32)](#unsupported-function-match-32)
      1. [Unsupported function: stringContains (23)](#unsupported-function-stringcontains-23)
      1. [Root with too many branches (limit: 10000) (18)](#root-with-too-many-branches-limit-10000-18)
      1. [Unsupported LHS type: <class 'eql.ast.FunctionCall'> (11)](#unsupported-lhs-type-class-eqlastfunctioncall-11)
      1. [Root without branches (8)](#root-without-branches-8)
      1. [Unsupported argument type(s): <class 'eql.ast.Field'> (8)](#unsupported-argument-types-class-eqlastfield-8)
      1. [Unsolvable constraints: process.name (excluded by Strings({'cmd.exe'}): ('cmd.exe')) (6)](#unsolvable-constraints-processname-excluded-by-stringscmdexe-cmdexe-6)
      1. [Unsupported function: startsWith (4)](#unsupported-function-startswith-4)
      1. [<class 'eql.ast.Sample'> (3)](#class-eqlastsample-3)
      1. [Unsupported argument type(s): <class 'eql.ast.FunctionCall'> (3)](#unsupported-argument-types-class-eqlastfunctioncall-3)
      1. [Unsupported argument type: <class 'eql.ast.FunctionCall'> (3)](#unsupported-argument-type-class-eqlastfunctioncall-3)
      1. [Unsupported function: endswith (3)](#unsupported-function-endswith-3)
      1. [Field type solver: match_only_text (2)](#field-type-solver-match_only_text-2)
      1. [Unsolvable constraints: event.category & event.type (empty intersection) (2)](#unsolvable-constraints-eventcategory--eventtype-empty-intersection-2)
      1. [Unsolvable constraints: process.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (2)](#unsolvable-constraints-processname-excluded-by-stringsrundll32exe-rundll32exe-2)
      1. [Unsupported &keyword 'file.Ext.windows.zone_identifier' constraint: > (2)](#unsupported-keyword-fileextwindowszone_identifier-constraint--2)
      1. [Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)](#unsupported-keyword-processparentextrealpid-constraint--2)
      1. [Unsupported is_negated: {'is_negated': True} (2)](#unsupported-is_negated-is_negated-true-2)
      1. ['NoneType' object is not subscriptable (1)](#nonetype-object-is-not-subscriptable-1)
      1. [<class 'eql.ast.SubqueryBy'> (1)](#class-eqlastsubqueryby-1)
      1. [Cannot choose from an empty set (1)](#cannot-choose-from-an-empty-set-1)
      1. [Unsolvable constraints: file.Ext.header_bytes (excluded by Strings({'504B0304*'}): ('504B0304*')) (1)](#unsolvable-constraints-fileextheader_bytes-excluded-by-strings504b0304-504b0304-1)
      1. [Unsolvable constraints: file.extension (cannot be non-null) (1)](#unsolvable-constraints-fileextension-cannot-be-non-null-1)
      1. [Unsolvable constraints: file.name (not in Strings({'*.so.*'}): ('.*.so')) (1)](#unsolvable-constraints-filename-not-in-stringsso-so-1)
      1. [Unsolvable constraints: http.request.body.content (not in Strings({'*/swip/Upload.ashx*'}): ('POST*')) (1)](#unsolvable-constraints-httprequestbodycontent-not-in-stringsswipuploadashx-post-1)
      1. [Unsolvable constraints: http.request.body.content (not in Strings({'*child_process*'}): ('*.exec*')) (1)](#unsolvable-constraints-httprequestbodycontent-not-in-stringschild_process-exec-1)
      1. [Unsolvable constraints: kubernetes.audit.requestObject.spec.containers.image (cannot be null) (1)](#unsolvable-constraints-kubernetesauditrequestobjectspeccontainersimage-cannot-be-null-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (excluded by Strings({'DsGetSiteName'}): ('DsGetSiteName')) (1)](#unsolvable-constraints-powershellfilescript_block_text-excluded-by-stringsdsgetsitename-dsgetsitename-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscopyfromscreen-systemdrawingbitmap-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Cryptography.AESManaged'}): ('CipherMode')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscryptographyaesmanaged-ciphermode-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'DumpCreds'}): ('DumpCerts')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsdumpcreds-dumpcerts-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Eventing.Reader.EventLogSession'}): ('.ClearLog')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringseventingreadereventlogsession-clearlog-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Get-AudioDevice'}): ('Recording')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsget-audiodevice-recording-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Get-WmiObject'}): ('AntiVirusProduct')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsget-wmiobject-antivirusproduct-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'IO.Compression.ZipFile'}): ('CompressionLevel')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsiocompressionzipfile-compressionlevel-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Invoke-WmiMethod'}): ('ComputerName')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsinvoke-wmimethod-computername-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'LsaCallAuthenticationPackage'}): ('KerbRetrieveEncodedTicketMessage')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringslsacallauthenticationpackage-kerbretrieveencodedticketmessage-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Microsoft.Office.Interop.Outlook'}): ('MAPI')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsmicrosoftofficeinteropoutlook-mapi-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'NTLMSSPNegotiate'}): ('NegotiateSMB')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsntlmsspnegotiate-negotiatesmb-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'New-MailboxExportRequest'}): ('-FilePath')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsnew-mailboxexportrequest--filepath-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'STARTUPINFOEX'}): ('UpdateProcThreadAttribute')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsstartupinfoex-updateprocthreadattribute-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Set-MpPreference'}): ('DisableArchiveScanning')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsset-mppreference-disablearchivescanning-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'SetWindowsHookEx'}): ('GetForegroundWindow')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssetwindowshookex-getforegroundwindow-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsvirtualalloc-writeprocessmemory-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Windows.Clipboard'}): (']::GetText')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringswindowsclipboard-gettext-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[Ref].Assembly.GetType(('System.Management.Automation'}): ('.SetValue(')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsrefassemblygettypesystemmanagementautomation-setvalue-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[System.Reflection.Assembly]::Load'}): ('FromBase64String')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssystemreflectionassemblyload-frombase64string-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[dbo].[Credentials]'}): ('Veeam')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsdbocredentials-veeam-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[string]::join'}): ('$pSHoMe[')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsstringjoin-pshome-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'capCreateCaptureWindowA'}): ('avicap32.dll')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscapcreatecapturewindowa-avicap32dll-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'defaultNamingContext'}): ('.MinLengthPassword')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsdefaultnamingcontext-minlengthpassword-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'shi1_netname'}): ('shi1_remark')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsshi1_netname-shi1_remark-1)
      1. [Unsolvable constraints: process.command_line (excluded by Strings({'*/proc/sys/vm/drop_caches*'}): ('*drop_caches*')) (1)](#unsolvable-constraints-processcommand_line-excluded-by-stringsprocsysvmdrop_caches-drop_caches-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*-e *'}): ('*RABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgA*')) (1)](#unsolvable-constraints-processcommand_line-not-in-strings-e--rabpahmayqbiagwazqbsaguayqbsahqaaqbtaguatqbvag4aaqb0ag8acgbpag4azwaga-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*-o *'}): ('*.c *')) (1)](#unsolvable-constraints-processcommand_line-not-in-strings-o--c--1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*Remove-Item*'}): ('*ConsoleHost_history.txt*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsremove-item-consolehost_historytxt-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*\\*\*$*'}): ('* copy*')) (1)](#unsolvable-constraints-processcommand_line-not-in-strings--copy-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*com.apple.Safari*'}): ('*IncludeDevelopMenu*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringscomapplesafari-includedevelopmenu-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*connect=*'}): ('*restrict=off*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsconnect-restrictoff-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*csrutil*status*'}): ('*enabled*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringscsrutilstatus-enabled-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*drive.google.com*'}): ('*export=download*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsdrivegooglecom-exportdownload-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*fromhex*'}): ('*decode*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsfromhex-decode-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*id_dsa*'}): ('*/home/*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsid_dsa-home-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*net.ipv4.ip_forward*'}): ('*echo *')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsnetipv4ip_forward-echo--1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*vm.swappiness*'}): ('*echo *')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsvmswappiness-echo--1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'arp.exe'}): ('arp.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsarpexe-arpexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'cp'}): ('cp')) (1)](#unsolvable-constraints-processname-excluded-by-stringscp-cp-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'elevation_service.exe'}): ('elevation_service.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringselevation_serviceexe-elevation_serviceexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'kubectl'}): ('kubectl')) (1)](#unsolvable-constraints-processname-excluded-by-stringskubectl-kubectl-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'msdt.exe'}): ('msdt.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsmsdtexe-msdtexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'msedgewebview2.exe'}): ('msedgewebview2.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsmsedgewebview2exe-msedgewebview2exe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'nc.traditional'}): ('nc.traditional')) (1)](#unsolvable-constraints-processname-excluded-by-stringsnctraditional-nctraditional-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'net1.exe'}): ('net1.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsnet1exe-net1exe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'nohup'}): ('nohup')) (1)](#unsolvable-constraints-processname-excluded-by-stringsnohup-nohup-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'powershell.exe'}): ('powershell.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringspowershellexe-powershellexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'python*'}): ('python*')) (1)](#unsolvable-constraints-processname-excluded-by-stringspython-python-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'sc.exe'}): ('sc.exe')) (1)](#unsolvable-constraints-processname-excluded-by-stringsscexe-scexe-1)
      1. [Unsolvable constraints: process.name (excluded by Strings({'sh'}): ('sh')) (1)](#unsolvable-constraints-processname-excluded-by-stringssh-sh-1)
      1. [Unsolvable constraints: process.name (not in Strings({'java'}): ('.*')) (1)](#unsolvable-constraints-processname-not-in-stringsjava--1)
      1. [Unsolvable constraints: process.name (not in Strings({'pluginkit'}): ('python*')) (1)](#unsolvable-constraints-processname-not-in-stringspluginkit-python-1)
      1. [Unsolvable constraints: process.name (not in Strings({'rundll32.exe'}): ('mshta.exe')) (1)](#unsolvable-constraints-processname-not-in-stringsrundll32exe-mshtaexe-1)
      1. [Unsolvable constraints: process.parent.args (excluded by Strings({'WdiSystemHost'}): ('WdiSystemHost')) (1)](#unsolvable-constraints-processparentargs-excluded-by-stringswdisystemhost-wdisystemhost-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'dllhost.exe'}): ('dllhost.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringsdllhostexe-dllhostexe-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'fish'}): ('fish')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringsfish-fish-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringsrundll32exe-rundll32exe-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'winword.exe'}): ('winword.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringswinwordexe-winwordexe-1)
      1. [Unsolvable constraints: process.parent.name (excluded by Strings({'wscript.exe'}): ('wscript.exe')) (1)](#unsolvable-constraints-processparentname-excluded-by-stringswscriptexe-wscriptexe-1)
      1. [Unsolvable constraints: process.parent.name (not in Strings({'slack.exe'}): ('CiscoCollabHost.exe')) (1)](#unsolvable-constraints-processparentname-not-in-stringsslackexe-ciscocollabhostexe-1)
      1. [Unsolvable constraints: process.pid (out of boundary, 1 <= 0 <= 4294967295) (1)](#unsolvable-constraints-processpid-out-of-boundary-1--0--4294967295-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*'}): ('*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings1131f6ad-9c07-11d1-f79f-00c04fc2dcd2s-1-5-21--1131f6aa-9c07-11d1-f79f-00c04fc2dcd2s-1-5-21--1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*42B5FAAE-6536-11D2-AE5A-0000F87571E3*'}): ('*40B66650-4972-11D1-A7CA-0000F87571E3*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings42b5faae-6536-11d2-ae5a-0000f87571e3-40b66650-4972-11d1-a7ca-0000f87571e3-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings827d319e-6eac-11d2-a4ea-00c04f79f83a-803e14a0-b4fb-11d0-a0d0-00a0c90f574b-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*CAB54552-DEEA-4691-817E-ED4A4D1AFC72*'}): ('*AADCED64-746C-4633-A97C-D61349046527*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-stringscab54552-deea-4691-817e-ed4a4d1afc72-aadced64-746c-4633-a97c-d61349046527-1)
      1. [Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: < (1)](#unsupported-keyword-dllextrelative_file_creation_time-constraint--1)
      1. [Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: <= (1)](#unsupported-keyword-dllextrelative_file_creation_time-constraint--1)
      1. [Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)](#unsupported-keyword-fileextentropy-constraint--1)
      1. [Unsupported &keyword 'ml_is_dga.malicious_probability' constraint: > (1)](#unsupported-keyword-ml_is_dgamalicious_probability-constraint--1)
      1. [Unsupported &keyword 'powershell.file.script_block_entropy_bits' constraint: >= (1)](#unsupported-keyword-powershellfilescript_block_entropy_bits-constraint--1)
      1. [Unsupported &keyword 'powershell.file.script_block_length' constraint: > (1)](#unsupported-keyword-powershellfilescript_block_length-constraint--1)
      1. [Unsupported &keyword 'problemchild.prediction_probability' constraint: <= (1)](#unsupported-keyword-problemchildprediction_probability-constraint--1)
      1. [Unsupported &keyword 'problemchild.prediction_probability' constraint: > (1)](#unsupported-keyword-problemchildprediction_probability-constraint--1)
      1. [Unsupported &keyword 'process.Ext.relative_file_creation_time' constraint: <= (1)](#unsupported-keyword-processextrelative_file_creation_time-constraint--1)

## Skipped rules

### Unsupported rule type: new_terms (184)

184 rules:

* AWS API Activity from Uncommon S3 Client by Rare User
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
* AWS IAM Long-Term Access Key First Seen from Source IP
* AWS IAM OIDC Provider Created by Rare User
* AWS S3 Unauthenticated Bucket Access by Rare Source
* AWS SNS Rare Protocol Subscription by User
* AWS SNS Topic Created by Rare User
* AWS SNS Topic Message Publish by Rare User
* AWS SSM Command Document Created by Rare User
* AWS SSM Inventory Reconnaissance by Rare User
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
* Account or Group Discovery via Built-In Tools
* Authentication via Unusual PAM Grantor
* Azure Arc Cluster Credential Access by Identity from Unusual Source
* Azure Compute Restore Point Collection Deleted by Unusual User
* Azure Compute Snapshot Deletion by Unusual User and Resource Group
* Azure Diagnostic Settings Deleted
* Azure Key Vault Modified
* Azure Key Vault Unusual Secret Key Usage
* Azure Storage Account Blob Public Access Enabled
* Azure Storage Account Deletion by Unusual User
* Azure Storage Account Keys Accessed by Privileged User
* Azure Storage Blob Retrieval via AzCopy
* DPKG Package Installed by Unusual Parent Process
* Delegated Managed Service Account Modification by an Unusual User
* Deprecated - Suspicious PrintSpooler Service Executable File Creation
* Deprecated - Unusual Discovery Activity by User
* Discovery of Internet Capabilities via Built-in Tools
* Entra ID Conditional Access Policy (CAP) Modified
* Entra ID Elevated Access to User Access Administrator
* Entra ID External Authentication Methods (EAM) Modified
* Entra ID OAuth Authorization Code Grant for Unusual User, App, and Resource
* Entra ID OAuth Device Code Grant by Unusual User
* Entra ID OAuth ROPC Grant Login Detected
* Entra ID OAuth user_impersonation Scope for Unusual User and Client
* Entra ID Service Principal Credentials Created by Unusual User
* Entra ID Service Principal Federated Credential Authentication by Unusual Client
* Entra ID Service Principal with Unusual Source ASN
* Entra ID Sharepoint or OneDrive Accessed by Unusual Client
* Entra ID User Sign-in with Unusual Authentication Type
* Entra ID User Sign-in with Unusual Client
* Entra ID User Sign-in with Unusual Non-Managed Device
* Enumeration of Kernel Modules via Proc
* Enumeration of Privileged Local Groups Membership
* Execution of an Unsigned Service
* Execution via MSSQL xp_cmdshell Stored Procedure
* File Creation in /var/log via Suspicious Process
* File Creation in World-Writable Directory by Unusual Process
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
* First Time AWS CloudFormation Stack Creation
* First Time Python Accessed Sensitive Credential Files
* First Time Python Created a LaunchAgent or LaunchDaemon
* First Time Python Spawned a Shell on Host
* First Time Seen AWS Secret Value Accessed in Secrets Manager
* First Time Seen Driver Loaded
* First Time Seen Google Workspace OAuth Login from Third-Party Application
* First Time Seen NewCredentials Logon Process
* First Time Seen Remote Monitoring and Management Tool
* First Time Seen Removable Device
* FirstTime Seen Account Performing DCSync
* FortiGate Administrator Account Creation from Unusual Source
* GenAI Process Connection to Unusual Domain
* GitHub Actions Unusual Bot Push to Repository
* Github Activity on a Private Repository from an Unusual IP
* Interactive Shell Launched via Unusual Parent Process in a Container
* Kernel Object File Creation
* Kill Command Execution
* Kubernetes Anonymous Request Authorized by Unusual User Agent
* Kubernetes Denied Service Account Request via Unusual User Agent
* Kubernetes Forbidden Request from Unusual User Agent
* Kubernetes Secret Access via Unusual User Agent
* Kubernetes Suspicious Self-Subject Review via Unusual User Agent
* Kubernetes Unusual Decision by User Agent
* LSASS Memory Dump Handle Access
* Linux Audio Recording Activity Detected
* Linux Clipboard Activity Detected
* Linux System Information Discovery
* Linux System Information Discovery via Getconf
* Linux Video Recording or Screenshot Activity Detected
* M365 Exchange Inbox Phishing Evasion Rule Created
* M365 Exchange Mailbox Accessed by Unusual Client
* M365 Exchange Mailbox High-Risk Permission Delegated
* M365 Identity Login from Atypical Travel Location
* M365 Identity OAuth Illicit Consent Grant by Rare Client and User
* M365 Identity Unusual SSO Authentication Errors for User
* M365 SharePoint/OneDrive File Access via PowerShell
* Microsoft Build Engine Started an Unusual Process
* Microsoft Build Engine Started by a Script Process
* Microsoft Graph Request Email Access by Unusual User and Client
* Microsoft Graph Request User Impersonation by Unusual Client
* Modification of Dynamic Linker Preload Shared Object
* Network Activity Detected via Kworker
* Network Traffic Capture via CAP_NET_RAW
* New GitHub Self Hosted Action Runner
* Okta Sign-In Events via Third-Party IdP
* Potential Credential Access via DCSync
* Potential HTTP Downgrade Attack
* Potential Pass-the-Hash (PtH) Attempt
* Potential Privilege Escalation via Linux DAC permissions
* Potential Shadow File Read via Command Line Utilities
* Privileged Docker Container Creation
* Process Backgrounded by Unusual Parent
* Process Discovery via Built-In Applications
* Query Registry using Built-in Tools
* RPM Package Installed by Unusual Parent Process
* Rare SMB Connection to the Internet
* Remote File Creation in World Writeable Directory
* SMB (Windows File Sharing) Activity to the Internet
* SSH Authorized Keys File Activity
* Sensitive Files Compression
* Shared Object Created by Previously Unknown Process
* Successful Application SSO from Rare Unknown Client Device
* Successful SSH Authentication from Unusual IP Address
* Successful SSH Authentication from Unusual SSH Public Key
* Successful SSH Authentication from Unusual User
* Suspicious Modprobe File Event
* Suspicious Named Pipe Creation
* Suspicious Network Activity to the Internet by Previously Unknown Executable
* Suspicious Path Invocation from Command Line
* Suspicious PowerShell Engine ImageLoad
* Suspicious Sysctl File Event
* Suspicious System Commands Executed by Previously Unknown Executable
* Svchost spawning Cmd
* System Binary Symlink to Suspicious Location
* System Network Connections Discovery
* System Owner/User Discovery Linux
* Systemd Service Started by Unusual Parent Process
* UID Elevation from Previously Unknown Executable
* Unauthorized Scope for Public App OAuth2 Token Grant with Client Credentials
* Unknown Execution of Binary with RWX Memory Region
* Unusual AWS S3 Object Encryption with SSE-C
* Unusual Discovery Signal Alert with Unusual Process Command Line
* Unusual Discovery Signal Alert with Unusual Process Executable
* Unusual Execution from Kernel Thread (kthreadd) Parent
* Unusual Exim4 Child Process
* Unusual File Operation by dns.exe
* Unusual Interactive Shell Launched from System User
* Unusual Kernel Module Enumeration
* Unusual Kubernetes Sensitive Workload Modification
* Unusual LD_PRELOAD/LD_LIBRARY_PATH Command Line Arguments
* Unusual Login via System User
* Unusual Network Connection to Suspicious Top Level Domain
* Unusual Network Connection to Suspicious Web Service
* Unusual Pkexec Execution
* Unusual Preload Environment Variable Process Execution
* Unusual Process Modifying GenAI Configuration File
* Unusual Remote File Creation
* Unusual SSHD Child Process
* Unusual Scheduled Task Update
* Unusual Web Config File Access
* Unusual Web Server Command Execution
* Web Shell Detection: Script Process Child of Common Web Processes
* dMSA Account Creation by an Unusual User

### Unsupported rule type: esql (138)

138 rules:

* AWS Access Token Used from Multiple Addresses
* AWS Bedrock Detected Multiple Attempts to use Denied Models by a Single User
* AWS Bedrock Detected Multiple Validation Exception Errors by a Single User
* AWS Bedrock Guardrails Detected Multiple Policy Violations Within a Single Blocked Request
* AWS Bedrock Guardrails Detected Multiple Violations by a Single User Over a Session
* AWS Bedrock Invocations without Guardrails Detected by a Single User Over a Session
* AWS Credentials Used from GitHub Actions and Non-CI/CD Infrastructure
* AWS Discovery API Calls via CLI from a Single Resource
* AWS EC2 LOLBin Execution via SSM SendCommand
* AWS EC2 Multi-Region DescribeInstances API Calls
* AWS IAM User Created Access Keys For Another User
* AWS Rare Source AS Organization Activity
* AWS S3 Object Encryption Using External KMS Key
* AWS S3 Static Site JavaScript File Uploaded
* AWS Service Quotas Multi-Region GetServiceQuota Requests
* Agent Spoofing - Multiple Hosts Using Same Agent
* Alerts From Multiple Integrations by Destination Address
* Alerts From Multiple Integrations by Source Address
* Alerts From Multiple Integrations by User Name
* Alerts in Different ATT&CK Tactics by Host
* Azure Key Vault Excessive Secret or Key Retrieved
* Azure OpenAI Insecure Output Handling
* Command Line Obfuscation via Whitespace Padding
* Correlated Alerts on Similar User Identities
* Detection Alert on a Process Exhibiting CPU Spike
* Dynamic IEX Reconstruction via Method String Access
* Elastic Defend and Email Alerts Correlation
* Elastic Defend and Network Security Alerts Correlation
* Entra ID Actor Token User Impersonation Abuse
* Entra ID Concurrent Sign-in with Suspicious Properties
* Entra ID Federated Identity Credential Issuer Modified
* Entra ID Illicit Consent Grant via Registered Application
* Entra ID MFA TOTP Brute Force Attempted
* Entra ID OAuth Device Code Flow with Concurrent Sign-ins
* Entra ID OAuth Flow by Microsoft Authentication Broker to Device Registration Service (DRS)
* Entra ID OAuth User Impersonation to Microsoft Graph
* Entra ID Sign-in Brute Force Attempted (Microsoft 365)
* Entra ID User Sign-in Brute Force Attempted
* File Transfer Utility Launched from Unusual Parent
* First Time Seen DNS Query to RMM Domain
* First-Time FortiGate Administrator Login
* FortiGate Administrator Login from Multiple IP Addresses
* FortiGate FortiCloud SSO Login from Unusual Source
* GitHub Actions Workflow Modification Blocked
* GitHub Exfiltration via High Number of Repository Clones by User
* High Number of Closed Pull Requests by User
* High Number of Egress Network Connections from Unusual Executable
* High Number of Protected Branch Force Pushes by User
* Kubernetes Creation or Modification of Sensitive Role
* Kubernetes Potential Endpoint Permission Enumeration Attempt Detected
* Kubernetes Potential Endpoint Permission Enumeration Attempt by Anonymous User Detected
* Kubernetes Secret or ConfigMap Access via Azure Arc Proxy
* LSASS Process Access via Windows API
* Lateral Movement Alerts from a Newly Observed Source Address
* Lateral Movement Alerts from a Newly Observed User
* Long Base64 Encoded Command via Scripting Interpreter
* M365 Azure Monitor Alert Email with Financial or Billing Theme
* M365 Identity OAuth Flow by First-Party Microsoft App from Multiple IPs
* M365 Identity User Account Lockouts
* M365 Identity User Brute Force Attempted
* M365 OneDrive/SharePoint Excessive File Downloads
* M365 or Entra ID Identity Sign-in from a Suspicious Source
* Microsoft Entra ID Exccessive Account Lockouts Detected
* Multiple Alerts Involving a User
* Multiple Alerts in Same ATT&CK Tactic by Host
* Multiple Alerts on a Host Exhibiting CPU Spike
* Multiple Cloud Secrets Accessed by Source Address
* Multiple Device Token Hashes for Single Okta Session
* Multiple Elastic Defend Alerts by Agent
* Multiple Elastic Defend Alerts from a Single Process Tree
* Multiple External EDR Alerts by Host
* Multiple Logon Failure from the same Source Address
* Multiple Machine Learning Alerts by Influencer Field
* Multiple Okta User Authentication Events with Same Device Token Hash
* Multiple Remote Management Tool Vendors on Same Host
* Multiple Vulnerabilities by Asset via Wiz
* Newly Observed Elastic Defend Behavior Alert
* Newly Observed FortiGate Alert
* Newly Observed High Severity Detection Alert
* Newly Observed High Severity Suricata Alert
* Newly Observed Palo Alto Network Alert
* Newly Observed Process Exhibiting High CPU Usage
* Newly Observed ScreenConnect Host Server
* Okta AiTM Session Cookie Replay
* Okta Successful Login After Credential Attack
* Okta User Sessions Started from Different Geolocations
* Potential Abuse of Resources by High Token Count and Large Response Sizes
* Potential Account Takeover - Logon from New Source IP
* Potential Account Takeover - Mixed Logon Types
* Potential Azure OpenAI Model Theft
* Potential Credential Discovery via Recursive Grep
* Potential Denial of Azure OpenAI ML Service
* Potential Dynamic IEX Reconstruction via Environment Variables
* Potential Linux Local Account Brute Force Detected
* Potential Malicious PowerShell Based on Alert Correlation
* Potential Malware-Driven SSH Brute Force Attempt
* Potential Network Scan Detected
* Potential Okta Brute Force (Device Token Rotation)
* Potential Okta Brute Force (Multi-Source)
* Potential Okta Credential Stuffing (Single Source)
* Potential Okta Password Spray (Multi-Source)
* Potential Okta Password Spray (Single Source)
* Potential Password Spraying Attack via SSH
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
* Potential Spike in Web Server Error Logs
* Potential Subnet Scanning Activity from Compromised Host
* Potential Widespread Malware Infection Across Multiple Hosts
* PowerShell Obfuscation via Negative Index String Reversal
* Privileged Accounts Brute Force
* Rare Connection to WebDAV Target
* Several Failed Protected Branch Force Pushes by User
* Suspected Lateral Movement from Compromised Host
* Suspicious AWS S3 Connection via Script Interpreter
* Suspicious Python Shell Command Execution
* Suspicious TCC Access Granted for User Folders
* Unusual Base64 Encoding/Decoding Activity
* Unusual Command Execution from Web Server Parent
* Unusual File Creation by Web Server
* Unusual High Confidence Content Filter Blocks Detected
* Unusual High Denied Sensitive Information Policy Blocks Detected
* Unusual High Denied Topic Blocks Detected
* Unusual High Word Policy Blocks Detected
* Unusual Process Spawned from Web Server Parent
* Web Server Discovery or Fuzzing Activity
* Web Server Potential Command Injection Request
* Web Server Potential Spike in Error Response Codes
* Web Server Suspicious User Agent Requests

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

### Unsupported rule type: threshold (28)

28 rules:

* AWS IAM Principal Enumeration via UpdateAssumeRolePolicy
* AWS Management Console Brute Force of Root User Identity
* AWS S3 Bucket Enumeration or Brute Force
* AWS Secrets Manager Rapid Secrets Retrieval
* Attempts to Brute Force an Okta User Account
* Azure Compute Restore Point Collections Deleted
* Azure Compute Snapshot Deletions by User
* Azure Storage Account Deletions by User
* Deprecated - Sudo Heap-Based Buffer Overflow Attempt
* Excessive AWS S3 Object Encryption with SSE-C
* GitHub UEBA - Multiple Alerts from a GitHub Account
* High Number of Cloned GitHub Repos From PAT
* High Number of Okta User Password Reset or Unlock Attempts
* High Number of Process Terminations
* High Number of Process and/or Service Terminations
* M365 Identity Login from Impossible Travel Location
* Multiple Alerts in Different ATT&CK Tactics on a Single Host
* Multiple Okta Sessions Detected for a Single User
* Multiple Okta User Auth Events with Same Device Token Hash Behind a Proxy
* My First Rule
* Okta Multiple OS Names Detected for a Single DT Hash
* Potential Buffer Overflow Attack Detected
* Potential LSASS Memory Dump via PssCaptureSnapShot
* Potential Network Scan Executed From Host
* Potential Network Sweep Detected
* Potential SYN-Based Port Scan Detected
* Potential macOS SSH Brute Force Detected
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

### Field type solver: constant_keyword (275)

275 rules:
* AWS CloudShell Environment Created
* AWS CloudTrail Log Created
* AWS CloudTrail Log Deleted
* AWS CloudTrail Log Evasion
* AWS CloudTrail Log Suspended
* AWS CloudTrail Log Updated
* AWS CloudWatch Alarm Deletion
* AWS CloudWatch Log Group Deletion
* AWS CloudWatch Log Stream Deletion
* AWS Config Resource Deletion
* AWS Configuration Recorder Stopped
* AWS EC2 AMI Shared with Another Account
* AWS EC2 Deprecated AMI Discovery
* AWS EC2 Encryption Disabled
* AWS EC2 Export Task
* AWS EC2 Full Network Packet Capture Detected
* AWS EC2 Instance Connect SSH Public Key Uploaded
* AWS EC2 Network Access Control List Creation
* AWS EC2 Network Access Control List Deletion
* AWS EC2 Security Group Configuration Change
* AWS EC2 Serial Console Access Enabled
* AWS EFS File System Deleted
* AWS EventBridge Rule Disabled or Deleted
* AWS GuardDuty Detector Deletion
* AWS GuardDuty Member Account Manipulation
* AWS IAM Deactivation of MFA Device
* AWS IAM Group Creation
* AWS IAM Group Deletion
* AWS IAM Roles Anywhere Profile Creation
* AWS IAM SAML Provider Created
* AWS IAM SAML Provider Updated
* AWS IAM User Addition to Group
* AWS KMS Customer Managed Key Disabled or Scheduled for Deletion
* AWS Lambda Layer Added to Existing Function
* AWS Management Console Root Login
* AWS RDS DB Instance Restored
* AWS RDS DB Instance or Cluster Deleted
* AWS RDS Snapshot Export
* AWS Route 53 Domain Transfer Lock Disabled
* AWS Route 53 Domain Transferred to Another Account
* AWS Route 53 Private Hosted Zone Associated With a VPC
* AWS Route 53 Resolver Query Log Configuration Deleted
* AWS S3 Bucket Configuration Deletion
* AWS SQS Queue Purge
* AWS Sensitive IAM Operations Performed via CloudShell
* AWS Sign-In Console Login with Federated User
* AWS Sign-In Root Password Recovery Requested
* AWS VPC Flow Logs Deletion
* AWS WAF Access Control List Deletion
* AWS WAF Rule or Rule Group Deletion
* Abnormally Large DNS Response
* Accepted Default Telnet Port Connection
* Administrator Privileges Assigned to an Okta Group
* Application Added to Google Workspace Domain
* Application Removed from Blocklist in Google Workspace
* Attempt to Create Okta API Token
* Attempt to Deactivate an Okta Application
* Attempt to Deactivate an Okta Network Zone
* Attempt to Deactivate an Okta Policy
* Attempt to Deactivate an Okta Policy Rule
* Attempt to Delete an Okta Application
* Attempt to Delete an Okta Network Zone
* Attempt to Delete an Okta Policy
* Attempt to Delete an Okta Policy Rule
* Attempt to Modify an Okta Application
* Attempt to Modify an Okta Network Zone
* Attempt to Modify an Okta Policy
* Attempt to Modify an Okta Policy Rule
* Attempt to Reset MFA Factors for an Okta User Account
* Attempt to Revoke Okta API Token
* Attempted Bypass of Okta MFA
* Azure Automation Account Created
* Azure Automation Runbook Created or Modified
* Azure Automation Runbook Deleted
* Azure Automation Webhook Created
* Azure Blob Storage Container Access Level Modified
* Azure Blob Storage Permissions Modified
* Azure Compute VM Command Executed
* Azure Diagnostic Settings Alert Suppression Rule Created or Modified
* Azure Event Hub Authorization Rule Created or Updated
* Azure Event Hub Deleted
* Azure Kubernetes Services (AKS) Kubernetes Events Deleted
* Azure Kubernetes Services (AKS) Kubernetes Pods Deleted
* Azure Kubernetes Services (AKS) Kubernetes Rolebindings Created
* Azure RBAC Built-In Administrator Roles Assigned
* Azure Resource Group Deleted
* Azure Service Principal Sign-In Followed by Arc Cluster Credential Access
* Azure Storage Account Key Regenerated
* Azure VNet Firewall Front Door WAF Policy Deleted
* Azure VNet Firewall Policy Deleted
* Azure VNet Full Network Packet Capture Enabled
* Azure VNet Network Watcher Deleted
* Command and Scripting Interpreter via Windows Scripts
* CrowdStrike External Alerts
* CyberArk Privileged Access Security Error
* CyberArk Privileged Access Security Recommended Monitor
* Default Cobalt Strike Team Server Certificate
* Deprecated - M365 Exchange DLP Policy Deleted
* Deprecated - M365 Security Compliance Email Reported by User as Malware or Phish
* Deprecated - M365 Security Compliance Potential Ransomware Activity
* Deprecated - M365 Security Compliance Unusual Volume of File Deletion
* Deprecated - M365 Security Compliance User Restricted from Sending Email
* Deprecated - M365 Teams External Access Enabled
* Deprecated - M365 Teams Guest Access Enabled
* Domain Added to Google Workspace Trusted Domains
* Elastic Security External Alerts
* Entra ID ADRS Token Request by Microsoft Authentication Broker
* Entra ID Application Credential Modified
* Entra ID Custom Domain Added or Verified
* Entra ID Domain Federation Configuration Change
* Entra ID External Guest User Invited
* Entra ID Global Administrator Role Assigned
* Entra ID Global Administrator Role Assigned (PIM User)
* Entra ID High Risk Sign-in
* Entra ID High Risk User Sign-in Heuristic
* Entra ID MFA Disabled for User
* Entra ID OAuth Device Code Grant by Microsoft Authentication Broker
* Entra ID OAuth PRT Issuance to Non-Managed Device Detected
* Entra ID OAuth Phishing via First-Party Microsoft Application
* Entra ID PowerShell Sign-in
* Entra ID Privileged Identity Management (PIM) Role Modified
* Entra ID Protection - Risk Detection - Sign-in Risk
* Entra ID Protection - Risk Detection - User Risk
* Entra ID Protection Admin Confirmed Compromise
* Entra ID Protection Alerts for User Detected
* Entra ID Protection User Alert and Device Registration
* Entra ID Service Principal Created
* Entra ID Sign-in TeamFiltration User-Agent Detected
* Entra ID Unusual Cloud Device Registration
* Entra ID User Added as Registered Application Owner
* Entra ID User Added as Service Principal Owner
* Entra ID User Reported Suspicious Activity
* Enumerating Domain Trusts via NLTEST.EXE
* Execution via Windows Subsystem for Linux
* FortiGate Configuration File Downloaded
* FortiGate Overly Permissive Firewall Policy Created
* FortiGate SOCKS Traffic from an Unusual Process
* FortiGate SSL VPN Login Followed by SIEM Alert by User
* FortiGate SSO Login Followed by Administrator Account Creation
* FortiGate Super Admin Account Creation
* Forwarded Google Workspace Security Alert
* GCP Firewall Rule Creation
* GCP Firewall Rule Deletion
* GCP Firewall Rule Modification
* GCP IAM Custom Role Creation
* GCP IAM Role Deletion
* GCP IAM Service Account Key Deletion
* GCP Logging Bucket Deletion
* GCP Logging Sink Deletion
* GCP Logging Sink Modification
* GCP Pub/Sub Subscription Creation
* GCP Pub/Sub Subscription Deletion
* GCP Pub/Sub Topic Creation
* GCP Pub/Sub Topic Deletion
* GCP Service Account Creation
* GCP Service Account Deletion
* GCP Service Account Disabled
* GCP Service Account Key Creation
* GCP Storage Bucket Configuration Modification
* GCP Storage Bucket Deletion
* GCP Storage Bucket Permissions Modification
* GCP Virtual Private Cloud Network Deletion
* GCP Virtual Private Cloud Route Creation
* GCP Virtual Private Cloud Route Deletion
* GitHub App Deleted
* GitHub Owner Role Granted To User
* GitHub Private Repository Turned Public
* GitHub Protected Branch Settings Changed
* GitHub Repository Deleted
* GitHub Secret Scanning Disabled
* Google Drive Ownership Transferred via Google Workspace
* Google SecOps External Alerts
* Google Workspace 2SV Policy Disabled
* Google Workspace API Access Granted via Domain-Wide Delegation
* Google Workspace Admin Role Assigned to a User
* Google Workspace Admin Role Deletion
* Google Workspace Bitlocker Setting Disabled
* Google Workspace Custom Admin Role Created
* Google Workspace Custom Gmail Route Created or Modified
* Google Workspace Drive Encryption Key(s) Accessed from Anonymous User
* Google Workspace MFA Enforcement Disabled
* Google Workspace Object Copied to External Drive with App Consent
* Google Workspace Password Policy Modified
* Google Workspace Restrictions for Marketplace Modified to Allow Any App
* Google Workspace Role Modified
* Google Workspace Suspended User Account Renewed
* Google Workspace User Organizational Unit Changed
* IBM QRadar External Alerts
* IPSEC NAT Traversal Port Activity
* Initial Access via File Upload Followed by GET Request
* Insecure AWS EC2 VPC Security Group Ingress Rule Added
* Kubernetes Anonymous User Create/Update/Patch Pods Request
* Kubernetes Cluster-Admin Role Binding Created
* Kubernetes Creation of a RoleBinding Referencing a ServiceAccount
* Kubernetes Events Deleted
* Kubernetes Exposed Service Created With Type NodePort
* Kubernetes Forbidden Creation Request
* Kubernetes Pod Created With HostIPC
* Kubernetes Pod Created With HostNetwork
* Kubernetes Pod Created With HostPID
* Kubernetes Pod Created with a Sensitive hostPath Volume
* Kubernetes Privileged Pod Created
* Kubernetes Sensitive RBAC Change Followed by Workload Modification
* Kubernetes Service Account Modified RBAC Objects
* Kubernetes Suspicious Assignment of Controller Service Account
* Kubernetes User Exec into Pod
* M365 Exchange Anti-Phish Policy Deleted
* M365 Exchange Anti-Phish Rule Modification
* M365 Exchange DKIM Signing Configuration Disabled
* M365 Exchange Email Safe Attachment Rule Disabled
* M365 Exchange Email Safe Link Policy Disabled
* M365 Exchange Federated Domain Created or Modified
* M365 Exchange MFA Notification Email Deleted or Moved
* M365 Exchange Mail Flow Transport Rule Created
* M365 Exchange Mail Flow Transport Rule Modified
* M365 Exchange Mailbox Audit Logging Bypass Added
* M365 Exchange Mailbox Items Accessed Excessively
* M365 Exchange Malware Filter Policy Deleted
* M365 Exchange Malware Filter Rule Modified
* M365 Exchange Management Group Role Assigned
* M365 Identity Global Administrator Role Assigned
* M365 Identity OAuth Flow by User Sign-in to Device Registration
* M365 Identity OAuth Phishing via First-Party Microsoft Application
* M365 OneDrive Malware File Upload
* M365 SharePoint Malware File Detected
* M365 SharePoint Search for Sensitive Content
* M365 SharePoint Site Administrator Added
* M365 SharePoint Site Sharing Policy Weakened
* M365 Teams Custom Application Interaction Enabled
* MFA Disabled for Google Workspace Organization
* Microsoft Sentinel External Alerts
* Modification or Removal of an Okta Application Sign-On Policy
* New GitHub App Installed
* New GitHub Owner Added
* New GitHub Personal Access Token (PAT) Added
* New Okta Identity Provider (IdP) Added by Admin
* Okta Alerts Following Unusual Proxy Authentication
* Okta FastPass Phishing Detection
* Okta ThreatInsight Threat Suspected Promotion
* Okta User Assigned Administrator Role
* Okta User Session Impersonation
* Possible Okta DoS Attack
* Potential Credential Access via Renamed COM+ Services DLL
* Potential DLL Side-Loading via Trusted Microsoft Programs
* Potential File Transfer via Curl for Windows
* Potential Persistence via File Modification
* Potential Toolshell Initial Exploit (CVE-2025-53770 & CVE-2025-53771)
* Potential VIEWSTATE RCE Attempt on SharePoint/IIS
* Potential Webshell Deployed via Apache Struts CVE-2023-50164 Exploitation
* Potentially Successful Okta MFA Bombing via Push Notifications
* Process Started with Executable Stack
* RDP (Remote Desktop Protocol) from the Internet
* RPC (Remote Procedure Call) from the Internet
* RPC (Remote Procedure Call) to the Internet
* React2Shell Network Security Alert
* Roshal Archive (RAR) or PowerShell File Downloaded from the Internet
* SMTP on Port 26/TCP
* SentinelOne Alert External Alerts
* SentinelOne Threat External Alerts
* Splunk External Alerts
* Stolen Credentials Used to Login to Okta Account After MFA Reset
* Suricata and Elastic Defend Network Correlation
* Suspicious Activity Reported by Okta User
* Suspicious Usage of bpf_probe_write_user Helper
* Suspicious WMI Event Subscription Created
* Suspicious Windows Powershell Arguments
* Suspicious rc.local Error Message
* Tainted Kernel Module Load
* Tainted Out-Of-Tree Kernel Module Load
* Unauthorized Access to an Okta Application
* VNC (Virtual Network Computing) from the Internet
* VNC (Virtual Network Computing) to the Internet
* WMI Incoming Lateral Movement
* Whoami Process Activity
* Zoom Meeting with no Passcode

### Unsupported function: match (32)

32 rules:
* Alternate Data Stream Creation/Execution at Volume Root Directory
* Command Obfuscation via Unicode Modifier Letters
* Creation of Hidden Files and Directories via CommandLine
* Entra ID Sign-in BloodHound Suite User-Agent Detected
* Executable File Creation with Multiple Extensions
* File Deletion via Shred
* GenAI Process Connection to Suspicious Top Level Domain
* Masquerading Space After Filename
* Network Activity to a Suspicious Top Level Domain
* Potential AWS S3 Bucket Ransomware Note Uploaded
* Potential Command Shell via NetCat
* Potential Credential Access via Windows Utilities
* Potential Data Exfiltration Through Curl
* Potential Data Exfiltration Through Wget
* Potential Exploitation of an Unquoted Service Path Vulnerability
* Potential Linux Tunneling and/or Port Forwarding
* Potential Linux Tunneling and/or Port Forwarding via Command Line
* Potential Windows Error Manager Masquerading
* Process Created with a Duplicated Token
* Process Started from Process ID (PID) File
* React2Shell (CVE-2025-55182) Exploitation Attempt
* Remote File Download via PowerShell
* Renamed Utility Executed with Short Program Name
* SUID/SGID Bit Set
* Simple HTTP Web Server Connection
* Simple HTTP Web Server Creation
* Suspicious Curl from macOS Application
* Suspicious Execution via Microsoft Office Add-Ins
* Suspicious Service was Installed in the System
* Unusual Child Processes of RunDLL32
* Unusual Network Connection via RunDLL32
* Unusual Process Execution Path - Alternate Data Stream

### Unsupported function: stringContains (23)

23 rules:
* AWS EC2 EBS Snapshot Access Removed
* AWS EC2 EBS Snapshot Shared or Made Public
* AWS EC2 Instance Console Login via Assumed Role
* AWS EC2 Instance Interaction with IAM Service
* AWS IAM AdministratorAccess Policy Attached to Group
* AWS IAM AdministratorAccess Policy Attached to Role
* AWS IAM AdministratorAccess Policy Attached to User
* AWS IAM CompromisedKeyQuarantine Policy Attached to User
* AWS IAM Login Profile Added for Root
* AWS IAM Roles Anywhere Trust Anchor Created with External CA
* AWS Lambda Function Policy Updated to Allow Public Invocation
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
* AWS Suspicious User Agent Fingerprint

### Root with too many branches (limit: 10000) (18)

18 rules:
* Connection to Common Large Language Model Endpoints
* Connection to Commonly Abused Web Services
* Execution from Unusual Directory - Command Line
* External IP Lookup from Non-Browser Process
* GenAI Process Accessing Sensitive Files
* GenAI or MCP Server Child Process Execution
* Potential DNS Tunneling via NsLookup
* Potential Evasion via Windows Filtering Platform
* Potential External Linux SSH Brute Force Detected
* Potential Internal Linux SSH Brute Force Detected
* Potential Linux Ransomware Note Creation Detected
* Potential Masquerading as System32 DLL
* Potential Masquerading as System32 Executable
* Potential Reverse Shell via Suspicious Binary
* Potential Reverse Shell via Suspicious Child Process
* Potential Successful SSH Brute Force Attack
* Suspicious React Server Child Process
* Unusual User Privilege Enumeration via id

### Unsupported LHS type: <class 'eql.ast.FunctionCall'> (11)

11 rules:
* AdminSDHolder SDProp Exclusion Added
* Image File Execution Options Injection
* Ingress Transfer via Windows BITS
* Memory Dump File with Unusual Extension
* NullSessionPipe Registry Modification
* Persistence via Hidden Run Key Detected
* Potential Hex Payload Execution via Command-Line
* Suspicious Access to LDAP Attributes
* Suspicious Execution via MSIEXEC
* Suspicious Process Access via Direct System Call
* Uncommon Registry Persistence Change

### Root without branches (8)

8 rules:
* Initramfs Extraction via CPIO
* Interactive Terminal Spawned via Perl
* Kubectl Configuration Discovery
* Linux User or Group Deletion
* Linux init (PID 1) Secret Dump via GDB
* Potential Docker Escape via Nsenter
* Potential Linux Backdoor User Account Creation
* Suspicious Data Encryption via OpenSSL Utility

### Unsupported argument type(s): <class 'eql.ast.Field'> (8)

8 rules:
* External User Added to Google Workspace Group
* Image Loaded with Invalid Signature
* Interactive Logon by an Unusual Process
* M365 Exchange Inbox Forwarding Rule Created
* Potential Ransomware Note File Dropped via SMB
* Suspicious File Renamed via SMB
* Unusual Network Activity from a Windows System Binary
* Windows Service Installed via an Unusual Client

### Unsolvable constraints: process.name (excluded by Strings({'cmd.exe'}): ('cmd.exe')) (6)

6 rules:
* Execution via MS VisualStudio Pre/Post Build Events
* Suspicious Execution from VS Code Extension
* Suspicious Execution from a WebDav Share
* Suspicious JetBrains TeamCity Child Process
* Suspicious Shell Execution via Velociraptor
* Suspicious Windows Command Shell Arguments

### Unsupported function: startsWith (4)

4 rules:
* AWS IAM Virtual MFA Device Registration Attempt with Session Token
* Persistent Scripts in the Startup Directory
* Potential ADIDNS Poisoning via Wildcard Record Creation
* SMB Connections via LOLBin or Untrusted Process

### <class 'eql.ast.Sample'> (3)

3 rules:
* Network Connection from Binary with RWX Memory Region
* Potential Meterpreter Reverse Shell
* Potential Reverse Shell via UDP

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
* Potential Computer Account NTLM Relay Activity
* Potential Machine Account Relay Attack via SMB
* Unusual Execution via Microsoft Common Console File

### Field type solver: match_only_text (2)

2 rules:
* Segfault Detected
* Windows CryptoAPI Spoofing Vulnerability (CVE-2020-0601 - CurveBall)

### Unsolvable constraints: event.category & event.type (empty intersection) (2)

2 rules:
* File with Right-to-Left Override Character (RTLO) Created/Executed
* Unsigned DLL loaded by DNS Service

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

### Unsupported is_negated: {'is_negated': True} (2)

2 rules:
* Elastic Defend Alert Followed by Telemetry Loss
* MFA Deactivation with no Re-Activation for Okta User Account

### 'NoneType' object is not subscriptable (1)

1 rules:
* GenAI Process Performing Encoding/Chunking Prior to Network Activity

### <class 'eql.ast.SubqueryBy'> (1)

1 rules:
* Potential Okta MFA Bombing via Push Notifications

### Cannot choose from an empty set (1)

1 rules:
* DNS Request for IP Lookup Service via Unsigned Binary

### Unsolvable constraints: file.Ext.header_bytes (excluded by Strings({'504B0304*'}): ('504B0304*')) (1)

1 rules:
* Archive File with Unusual Extension

### Unsolvable constraints: file.extension (cannot be non-null) (1)

1 rules:
* Pluggable Authentication Module or Configuration Creation

### Unsolvable constraints: file.name (not in Strings({'*.so.*'}): ('.*.so')) (1)

1 rules:
* Creation of Hidden Shared Object File

### Unsolvable constraints: http.request.body.content (not in Strings({'*/swip/Upload.ashx*'}): ('POST*')) (1)

1 rules:
* Deprecated - SUNBURST Command and Control Activity

### Unsolvable constraints: http.request.body.content (not in Strings({'*child_process*'}): ('*.exec*')) (1)

1 rules:
* Anomalous React Server Components Flight Data Patterns

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

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Get-AudioDevice'}): ('Recording')) (1)

1 rules:
* PowerShell Suspicious Script with Audio Capture Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Get-WmiObject'}): ('AntiVirusProduct')) (1)

1 rules:
* Deprecated - PowerShell Script with Discovery Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'IO.Compression.ZipFile'}): ('CompressionLevel')) (1)

1 rules:
* PowerShell Script with Archive Compression Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Invoke-WmiMethod'}): ('ComputerName')) (1)

1 rules:
* Deprecated - PowerShell Script with Remote Execution Capabilities via WinRM

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'LsaCallAuthenticationPackage'}): ('KerbRetrieveEncodedTicketMessage')) (1)

1 rules:
* PowerShell Kerberos Ticket Dump

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Microsoft.Office.Interop.Outlook'}): ('MAPI')) (1)

1 rules:
* PowerShell Mailbox Collection Script

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'NTLMSSPNegotiate'}): ('NegotiateSMB')) (1)

1 rules:
* Potential PowerShell Pass-the-Hash/Relay Script

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'New-MailboxExportRequest'}): ('-FilePath')) (1)

1 rules:
* Exchange Mailbox Export via PowerShell

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'STARTUPINFOEX'}): ('UpdateProcThreadAttribute')) (1)

1 rules:
* PowerShell Script with Token Impersonation Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Set-MpPreference'}): ('DisableArchiveScanning')) (1)

1 rules:
* PowerShell Script with Windows Defender Tampering Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'SetWindowsHookEx'}): ('GetForegroundWindow')) (1)

1 rules:
* PowerShell Keylogging Script

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)

1 rules:
* Potential Process Injection via PowerShell

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Windows.Clipboard'}): (']::GetText')) (1)

1 rules:
* PowerShell Suspicious Script with Clipboard Retrieval Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[Ref].Assembly.GetType(('System.Management.Automation'}): ('.SetValue(')) (1)

1 rules:
* Potential Antimalware Scan Interface Bypass via PowerShell

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[System.Reflection.Assembly]::Load'}): ('FromBase64String')) (1)

1 rules:
* Suspicious .NET Reflection via PowerShell

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[dbo].[Credentials]'}): ('Veeam')) (1)

1 rules:
* PowerShell Script with Veeam Credential Access Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[string]::join'}): ('$pSHoMe[')) (1)

1 rules:
* Deprecated - Potential PowerShell Obfuscated Script

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'capCreateCaptureWindowA'}): ('avicap32.dll')) (1)

1 rules:
* PowerShell Script with Webcam Video Capture Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'defaultNamingContext'}): ('.MinLengthPassword')) (1)

1 rules:
* PowerShell Script with Password Policy Discovery Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'shi1_netname'}): ('shi1_remark')) (1)

1 rules:
* PowerShell Share Enumeration Script

### Unsolvable constraints: process.command_line (excluded by Strings({'*/proc/sys/vm/drop_caches*'}): ('*drop_caches*')) (1)

1 rules:
* Suspicious Kernel Feature Activity

### Unsolvable constraints: process.command_line (not in Strings({'*-e *'}): ('*RABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgA*')) (1)

1 rules:
* Disabling Windows Defender Security Settings via PowerShell

### Unsolvable constraints: process.command_line (not in Strings({'*-o *'}): ('*.c *')) (1)

1 rules:
* GenAI Process Compiling or Generating Executables

### Unsolvable constraints: process.command_line (not in Strings({'*Remove-Item*'}): ('*ConsoleHost_history.txt*')) (1)

1 rules:
* Clearing Windows Console History

### Unsolvable constraints: process.command_line (not in Strings({'*\\*\*$*'}): ('* copy*')) (1)

1 rules:
* Remote File Copy to a Hidden Share

### Unsolvable constraints: process.command_line (not in Strings({'*com.apple.Safari*'}): ('*IncludeDevelopMenu*')) (1)

1 rules:
* Modification of Safari Settings via Defaults Command

### Unsolvable constraints: process.command_line (not in Strings({'*connect=*'}): ('*restrict=off*')) (1)

1 rules:
* Potential Traffic Tunneling using QEMU

### Unsolvable constraints: process.command_line (not in Strings({'*csrutil*status*'}): ('*enabled*')) (1)

1 rules:
* Suspicious SIP Check by macOS Application

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

### Unsolvable constraints: process.name (excluded by Strings({'cp'}): ('cp')) (1)

1 rules:
* Boot File Copy

### Unsolvable constraints: process.name (excluded by Strings({'elevation_service.exe'}): ('elevation_service.exe')) (1)

1 rules:
* Potential Privilege Escalation via InstallerFileTakeOver

### Unsolvable constraints: process.name (excluded by Strings({'kubectl'}): ('kubectl')) (1)

1 rules:
* Container Management Utility Run Inside A Container

### Unsolvable constraints: process.name (excluded by Strings({'msdt.exe'}): ('msdt.exe')) (1)

1 rules:
* Suspicious Microsoft Diagnostics Wizard Execution

### Unsolvable constraints: process.name (excluded by Strings({'msedgewebview2.exe'}): ('msedgewebview2.exe')) (1)

1 rules:
* Potential Masquerading as Browser Process

### Unsolvable constraints: process.name (excluded by Strings({'nc.traditional'}): ('nc.traditional')) (1)

1 rules:
* Suspicious Network Tool Launched Inside A Container

### Unsolvable constraints: process.name (excluded by Strings({'net1.exe'}): ('net1.exe')) (1)

1 rules:
* Account Discovery Command via SYSTEM Account

### Unsolvable constraints: process.name (excluded by Strings({'nohup'}): ('nohup')) (1)

1 rules:
* Curl or Wget Egress Network Connection via LoLBin

### Unsolvable constraints: process.name (excluded by Strings({'powershell.exe'}): ('powershell.exe')) (1)

1 rules:
* Delayed Execution via Ping

### Unsolvable constraints: process.name (excluded by Strings({'python*'}): ('python*')) (1)

1 rules:
* Base64 Decoded Payload Piped to Interpreter

### Unsolvable constraints: process.name (excluded by Strings({'sc.exe'}): ('sc.exe')) (1)

1 rules:
* Enumeration Command Spawned via WMIPrvSE

### Unsolvable constraints: process.name (excluded by Strings({'sh'}): ('sh')) (1)

1 rules:
* Suspicious macOS MS Office Child Process

### Unsolvable constraints: process.name (not in Strings({'java'}): ('.*')) (1)

1 rules:
* Suspicious Child Execution via Web Server

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

### Unsolvable constraints: process.parent.name (excluded by Strings({'fish'}): ('fish')) (1)

1 rules:
* Kubeconfig File Discovery

### Unsolvable constraints: process.parent.name (excluded by Strings({'rundll32.exe'}): ('rundll32.exe')) (1)

1 rules:
* Conhost Spawned By Suspicious Parent Process

### Unsolvable constraints: process.parent.name (excluded by Strings({'winword.exe'}): ('winword.exe')) (1)

1 rules:
* Suspicious Process Creation CallTrace

### Unsolvable constraints: process.parent.name (excluded by Strings({'wscript.exe'}): ('wscript.exe')) (1)

1 rules:
* Windows Script Executing PowerShell

### Unsolvable constraints: process.parent.name (not in Strings({'slack.exe'}): ('CiscoCollabHost.exe')) (1)

1 rules:
* Suspicious Communication App Child Process

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

### Unsupported &keyword 'powershell.file.script_block_entropy_bits' constraint: >= (1)

1 rules:
* PowerShell Suspicious Payload Encoded and Compressed

### Unsupported &keyword 'powershell.file.script_block_length' constraint: > (1)

1 rules:
* Potential PowerShell Obfuscated Script via High Entropy

### Unsupported &keyword 'problemchild.prediction_probability' constraint: <= (1)

1 rules:
* Machine Learning Detected a Suspicious Windows Event with a Low Malicious Probability Score

### Unsupported &keyword 'problemchild.prediction_probability' constraint: > (1)

1 rules:
* Machine Learning Detected a Suspicious Windows Event with a High Malicious Probability Score

### Unsupported &keyword 'process.Ext.relative_file_creation_time' constraint: <= (1)

1 rules:
* Suspicious Inter-Process Communication via Outlook
