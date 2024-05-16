# Alerts generation from detection rules

This report captures the detection rules signals generation coverage. Here you can
learn what rules are supported and what not and why.

Curious about the inner workings? Read [here](signals_generation.md).

Rules version: 8.2.1

## Table of contents
   1. [Rules with no signals (3)](#rules-with-no-signals-3)
   1. [Rules with too few signals (1)](#rules-with-too-few-signals-1)
   1. [Rules with the correct signals (575)](#rules-with-the-correct-signals-575)

## Rules with no signals (3)

### Azure External Guest User Invitation

Branch count: 2  
Document count: 2  
Index: geneve-ut-122

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Invite external user" and azure.auditlogs.properties.target_resources.*.display_name:guest and event.outcome:(Success or success)
```



### Azure Full Network Packet Capture Detected

Branch count: 6  
Document count: 6  
Index: geneve-ut-125

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:
    (
        "MICROSOFT.NETWORK/*/STARTPACKETCAPTURE/ACTION" or
        "MICROSOFT.NETWORK/*/VPNCONNECTIONS/STARTPACKETCAPTURE/ACTION" or
        "MICROSOFT.NETWORK/*/PACKETCAPTURES/WRITE"
    ) and
event.outcome:(Success or success)
```



### Azure Global Administrator Role Addition to PIM User

Branch count: 4  
Document count: 4  
Index: geneve-ut-126

```python
event.dataset:azure.auditlogs and azure.auditlogs.properties.category:RoleManagement and
    azure.auditlogs.operation_name:("Add eligible member to role in PIM completed (permanent)" or
                                    "Add member to role in PIM completed (timebound)") and
    azure.auditlogs.properties.target_resources.*.display_name:"Global Administrator" and
    event.outcome:(Success or success)
```



## Rules with too few signals (1)

### Potential Shell via Web Server

Branch count: 84  
Document count: 84  
Index: geneve-ut-439  
Failure message(s):  
  got 48 signals, expected 84  

```python
event.category:process and event.type:(start or process_started) and
process.name:(bash or dash or ash or zsh or "python*" or "perl*" or "php*") and
process.parent.name:("apache" or "nginx" or "www" or "apache2" or "httpd" or "www-data")
```



## Rules with the correct signals (575)

### AWS Access Secret in Secrets Manager

Branch count: 1  
Document count: 1  
Index: geneve-ut-000

```python
event.dataset:aws.cloudtrail and event.provider:secretsmanager.amazonaws.com and event.action:GetSecretValue
```



### AWS CloudTrail Log Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-001

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:CreateTrail and event.outcome:success
```



### AWS CloudTrail Log Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-002

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:DeleteTrail and event.outcome:success
```



### AWS CloudTrail Log Suspended

Branch count: 1  
Document count: 1  
Index: geneve-ut-003

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:StopLogging and event.outcome:success
```



### AWS CloudTrail Log Updated

Branch count: 1  
Document count: 1  
Index: geneve-ut-004

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:UpdateTrail and event.outcome:success
```



### AWS CloudWatch Alarm Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-005

```python
event.dataset:aws.cloudtrail and event.provider:monitoring.amazonaws.com and event.action:DeleteAlarms and event.outcome:success
```



### AWS CloudWatch Log Group Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-006

```python
event.dataset:aws.cloudtrail and event.provider:logs.amazonaws.com and event.action:DeleteLogGroup and event.outcome:success
```



### AWS CloudWatch Log Stream Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-007

```python
event.dataset:aws.cloudtrail and event.provider:logs.amazonaws.com and event.action:DeleteLogStream and event.outcome:success
```



### AWS Config Resource Deletion

Branch count: 9  
Document count: 9  
Index: geneve-ut-008

```python
event.dataset:aws.cloudtrail and event.provider:config.amazonaws.com and
    event.action:(DeleteConfigRule or DeleteOrganizationConfigRule or DeleteConfigurationAggregator or
    DeleteConfigurationRecorder or DeleteConformancePack or DeleteOrganizationConformancePack or
    DeleteDeliveryChannel or DeleteRemediationConfiguration or DeleteRetentionConfiguration)
```



### AWS Configuration Recorder Stopped

Branch count: 1  
Document count: 1  
Index: geneve-ut-009

```python
event.dataset:aws.cloudtrail and event.provider:config.amazonaws.com and event.action:StopConfigurationRecorder and event.outcome:success
```



### AWS Deletion of RDS Instance or Cluster

Branch count: 3  
Document count: 3  
Index: geneve-ut-010

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(DeleteDBCluster or DeleteGlobalCluster or DeleteDBInstance)
and event.outcome:success
```



### AWS EC2 Encryption Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-011

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:DisableEbsEncryptionByDefault and event.outcome:success
```



### AWS EC2 Full Network Packet Capture Detected

Branch count: 4  
Document count: 4  
Index: geneve-ut-012

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and
event.action:(CreateTrafficMirrorFilter or CreateTrafficMirrorFilterRule or CreateTrafficMirrorSession or CreateTrafficMirrorTarget) and
event.outcome:success
```



### AWS EC2 Network Access Control List Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-013

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(CreateNetworkAcl or CreateNetworkAclEntry) and event.outcome:success
```



### AWS EC2 Network Access Control List Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-014

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(DeleteNetworkAcl or DeleteNetworkAclEntry) and event.outcome:success
```



### AWS EC2 Snapshot Activity

Branch count: 1  
Document count: 1  
Index: geneve-ut-015

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:ModifySnapshotAttribute
```



### AWS EC2 VM Export Failure

Branch count: 1  
Document count: 1  
Index: geneve-ut-016

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:CreateInstanceExportTask and event.outcome:failure
```



### AWS EFS File System or Mount Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-017

```python
event.dataset:aws.cloudtrail and event.provider:elasticfilesystem.amazonaws.com and
event.action:(DeleteMountTarget or DeleteFileSystem) and event.outcome:success
```



### AWS ElastiCache Security Group Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-018

```python
event.dataset:aws.cloudtrail and event.provider:elasticache.amazonaws.com and event.action:"Create Cache Security Group" and
event.outcome:success
```



### AWS ElastiCache Security Group Modified or Deleted

Branch count: 5  
Document count: 5  
Index: geneve-ut-019

```python
event.dataset:aws.cloudtrail and event.provider:elasticache.amazonaws.com and event.action:("Delete Cache Security Group" or
"Authorize Cache Security Group Ingress" or  "Revoke Cache Security Group Ingress" or "AuthorizeCacheSecurityGroupEgress" or
"RevokeCacheSecurityGroupEgress") and event.outcome:success
```



### AWS EventBridge Rule Disabled or Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-020

```python
event.dataset:aws.cloudtrail and event.provider:eventbridge.amazonaws.com and event.action:(DeleteRule or DisableRule) and
event.outcome:success
```



### AWS Execution via System Manager

Branch count: 1  
Document count: 1  
Index: geneve-ut-021

```python
event.dataset:aws.cloudtrail and event.provider:ssm.amazonaws.com and event.action:SendCommand and event.outcome:success
```



### AWS GuardDuty Detector Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-022

```python
event.dataset:aws.cloudtrail and event.provider:guardduty.amazonaws.com and event.action:DeleteDetector and event.outcome:success
```



### AWS IAM Assume Role Policy Update

Branch count: 1  
Document count: 1  
Index: geneve-ut-023

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:UpdateAssumeRolePolicy and event.outcome:success
```



### AWS IAM Deactivation of MFA Device

Branch count: 2  
Document count: 2  
Index: geneve-ut-025

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:(DeactivateMFADevice or DeleteVirtualMFADevice) and event.outcome:success
```



### AWS IAM Group Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-026

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:CreateGroup and event.outcome:success
```



### AWS IAM Group Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-027

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:DeleteGroup and event.outcome:success
```



### AWS IAM Password Recovery Requested

Branch count: 1  
Document count: 1  
Index: geneve-ut-028

```python
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:PasswordRecoveryRequested and event.outcome:success
```



### AWS IAM User Addition to Group

Branch count: 1  
Document count: 1  
Index: geneve-ut-029

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:AddUserToGroup and event.outcome:success
```



### AWS Management Console Root Login

Branch count: 1  
Document count: 1  
Index: geneve-ut-031

```python
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:ConsoleLogin and aws.cloudtrail.user_identity.type:Root and event.outcome:success
```



### AWS RDS Cluster Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-032

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(CreateDBCluster or CreateGlobalCluster) and event.outcome:success
```



### AWS RDS Instance Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-033

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:CreateDBInstance and event.outcome:success
```



### AWS RDS Instance/Cluster Stoppage

Branch count: 2  
Document count: 2  
Index: geneve-ut-034

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(StopDBCluster or StopDBInstance) and event.outcome:success
```



### AWS RDS Security Group Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-035

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:CreateDBSecurityGroup and event.outcome:success
```



### AWS RDS Security Group Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-036

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:DeleteDBSecurityGroup and event.outcome:success
```



### AWS RDS Snapshot Export

Branch count: 1  
Document count: 1  
Index: geneve-ut-037

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:StartExportTask and event.outcome:success
```



### AWS RDS Snapshot Restored

Branch count: 1  
Document count: 1  
Index: geneve-ut-038

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:RestoreDBInstanceFromDBSnapshot and
event.outcome:success
```



### AWS Redshift Cluster Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-039

```python
event.dataset:aws.cloudtrail and event.provider:redshift.amazonaws.com and event.action:CreateCluster and event.outcome:success
```



### AWS Root Login Without MFA

Branch count: 1  
Document count: 1  
Index: geneve-ut-040

```python
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:ConsoleLogin and
  aws.cloudtrail.user_identity.type:Root and
  aws.cloudtrail.console_login.additional_eventdata.mfa_used:false and
  event.outcome:success
```



### AWS Route 53 Domain Transfer Lock Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-041

```python
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:DisableDomainTransferLock and event.outcome:success
```



### AWS Route 53 Domain Transferred to Another Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-042

```python
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:TransferDomainToAnotherAwsAccount and event.outcome:success
```



### AWS Route Table Created

Branch count: 2  
Document count: 2  
Index: geneve-ut-043

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:(CreateRoute or CreateRouteTable) and
event.outcome:success
```



### AWS Route Table Modified or Deleted

Branch count: 5  
Document count: 5  
Index: geneve-ut-044

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:(ReplaceRoute or ReplaceRouteTableAssociation or
DeleteRouteTable or DeleteRoute or DisassociateRouteTable) and event.outcome:success
```



### AWS Route53 private hosted zone associated with a VPC

Branch count: 1  
Document count: 1  
Index: geneve-ut-045

```python
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:AssociateVPCWithHostedZone and
event.outcome:success
```



### AWS S3 Bucket Configuration Deletion

Branch count: 5  
Document count: 5  
Index: geneve-ut-046

```python
event.dataset:aws.cloudtrail and event.provider:s3.amazonaws.com and
  event.action:(DeleteBucketPolicy or DeleteBucketReplication or DeleteBucketCors or
                DeleteBucketEncryption or DeleteBucketLifecycle)
  and event.outcome:success
```



### AWS SAML Activity

Branch count: 4  
Document count: 4  
Index: geneve-ut-047

```python
event.dataset:aws.cloudtrail and event.provider:(iam.amazonaws.com or sts.amazonaws.com) and event.action:(Assumerolewithsaml or
UpdateSAMLProvider) and event.outcome:success
```



### AWS STS GetSessionToken Abuse

Branch count: 1  
Document count: 1  
Index: geneve-ut-048

```python
event.dataset:aws.cloudtrail and event.provider:sts.amazonaws.com and event.action:GetSessionToken and
aws.cloudtrail.user_identity.type:IAMUser and event.outcome:success
```



### AWS Security Group Configuration Change Detection

Branch count: 6  
Document count: 6  
Index: geneve-ut-049

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(AuthorizeSecurityGroupEgress or
CreateSecurityGroup or ModifyInstanceAttribute or ModifySecurityGroupRules or RevokeSecurityGroupEgress or
RevokeSecurityGroupIngress) and event.outcome:success
```



### AWS Security Token Service (STS) AssumeRole Usage

Branch count: 1  
Document count: 1  
Index: geneve-ut-050

```python
event.dataset:aws.cloudtrail and event.provider:sts.amazonaws.com and event.action:AssumedRole and
aws.cloudtrail.user_identity.session_context.session_issuer.type:Role and event.outcome:success
```



### AWS VPC Flow Logs Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-051

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:DeleteFlowLogs and event.outcome:success
```



### AWS WAF Access Control List Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-052

```python
event.dataset:aws.cloudtrail and event.action:DeleteWebACL and event.outcome:success
```



### AWS WAF Rule or Rule Group Deletion

Branch count: 6  
Document count: 6  
Index: geneve-ut-053

```python
event.dataset:aws.cloudtrail and event.provider:(waf.amazonaws.com or waf-regional.amazonaws.com or wafv2.amazonaws.com) and event.action:(DeleteRule or DeleteRuleGroup) and event.outcome:success
```



### Abnormally Large DNS Response

Branch count: 6  
Document count: 6  
Index: geneve-ut-055

```python
event.category:(network or network_traffic) and destination.port:53 and
  (event.dataset:zeek.dns or type:dns or event.type:connection) and network.bytes > 60000
```



### Access of Stored Browser Credentials

Branch count: 26  
Document count: 26  
Index: geneve-ut-056

```python
process where event.type in ("start", "process_started") and
  process.args :
    (
      "/Users/*/Library/Application Support/Google/Chrome/Default/Login Data",
      "/Users/*/Library/Application Support/Google/Chrome/Default/Cookies",
      "/Users/*/Library/Application Support/Google/Chrome/Profile*/Cookies",
      "/Users/*/Library/Cookies*",
      "/Users/*/Library/Application Support/Firefox/Profiles/*.default/cookies.sqlite",
      "/Users/*/Library/Application Support/Firefox/Profiles/*.default/key*.db",
      "/Users/*/Library/Application Support/Firefox/Profiles/*.default/logins.json",
      "Login Data",
      "Cookies.binarycookies",
      "key4.db",
      "key3.db",
      "logins.json",
      "cookies.sqlite"
    )
```



### Access to Keychain Credentials Directories

Branch count: 12  
Document count: 12  
Index: geneve-ut-057

```python
process where event.type in ("start", "process_started") and
  process.args :
    (
      "/Users/*/Library/Keychains/*",
      "/Library/Keychains/*",
      "/Network/Library/Keychains/*",
      "System.keychain",
      "login.keychain-db",
      "login.keychain"
    ) and
    not process.args : ("find-certificate",
                      "add-trusted-cert",
                      "set-keychain-settings",
                      "delete-certificate",
                      "/Users/*/Library/Keychains/openvpn.keychain-db",
                      "show-keychain-info",
                      "lock-keychain",
                      "set-key-partition-list",
                      "import",
                      "find-identity") and
    not process.parent.executable :
      (
        "/Applications/OpenVPN Connect/OpenVPN Connect.app/Contents/MacOS/OpenVPN Connect",
        "/Applications/Microsoft Defender.app/Contents/MacOS/wdavdaemon_enterprise.app/Contents/MacOS/wdavdaemon_enterprise",
        "/opt/jc/bin/jumpcloud-agent"
      ) and
    not process.executable : "/opt/jc/bin/jumpcloud-agent"
```



### Account Discovery Command via SYSTEM Account

Branch count: 8  
Document count: 8  
Index: geneve-ut-059

```python
process where event.type in ("start", "process_started") and
  (?process.Ext.token.integrity_level_name : "System" or
  ?winlog.event_data.IntegrityLevel : "System") and
  (process.name : "whoami.exe" or
  (process.name : "net1.exe" and not process.parent.name : "net.exe"))
```



### Account Password Reset Remotely

Branch count: 8  
Document count: 16  
Index: geneve-ut-060

```python
sequence by host.id with maxspan=5m
  [authentication where event.action == "logged-in" and
    /* event 4624 need to be logged */
    winlog.logon.type : "Network" and event.outcome == "success" and source.ip != null and
    source.ip != "127.0.0.1" and source.ip != "::1"] by winlog.event_data.TargetLogonId
   /* event 4724 need to be logged */
  [iam where event.action == "reset-password" and
   (
    /*
       This rule is very noisy if not scoped to privileged accounts, duplicate the
       rule and add your own naming convention and accounts of interest here.
     */
    winlog.event_data.TargetUserName: ("*Admin*", "*super*", "*SVC*", "*DC0*", "*service*", "*DMZ*", "*ADM*") or
    winlog.event_data.TargetSid : "S-1-5-21-*-500"
    )
  ] by winlog.event_data.SubjectLogonId
```



### AdFind Command Activity

Branch count: 72  
Document count: 72  
Index: geneve-ut-061

```python
process where event.type in ("start", "process_started") and
  (process.name : "AdFind.exe" or process.pe.original_file_name == "AdFind.exe") and
  process.args : ("objectcategory=computer", "(objectcategory=computer)",
                  "objectcategory=person", "(objectcategory=person)",
                  "objectcategory=subnet", "(objectcategory=subnet)",
                  "objectcategory=group", "(objectcategory=group)",
                  "objectcategory=organizationalunit", "(objectcategory=organizationalunit)",
                  "objectcategory=attributeschema", "(objectcategory=attributeschema)",
                  "domainlist", "dcmodes", "adinfo", "dclist", "computers_pwnotreqd", "trustdmp")
```



### Adding Hidden File Attribute via Attrib

Branch count: 2  
Document count: 2  
Index: geneve-ut-062

```python
process where event.type in ("start", "process_started") and
  process.name : "attrib.exe" and process.args : "+h"
```



### AdminSDHolder Backdoor

Branch count: 1  
Document count: 1  
Index: geneve-ut-063

```python
event.action:"Directory Service Changes" and event.code:5136 and winlog.event_data.ObjectDN:CN=AdminSDHolder,CN=System*
```



### Administrator Privileges Assigned to an Okta Group

Branch count: 1  
Document count: 1  
Index: geneve-ut-065

```python
event.dataset:okta.system and event.action:group.privilege.grant
```



### Administrator Role Assigned to an Okta User

Branch count: 1  
Document count: 1  
Index: geneve-ut-066

```python
event.dataset:okta.system and event.action:user.account.privilege.grant
```



### Adobe Hijack Persistence

Branch count: 2  
Document count: 2  
Index: geneve-ut-067

```python
file where event.type == "creation" and
  file.path : ("?:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe",
               "?:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe") and
  not process.name : "msiexec.exe"
```



### Adversary Behavior - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-068

```python
event.kind:alert and event.module:endgame and (event.action:rules_engine_event or endgame.event_subtype_full:rules_engine_event)
```



### Agent Spoofing - Mismatched Agent ID

Branch count: 1  
Document count: 1  
Index: geneve-ut-069

```python
event.agent_id_status:agent_id_mismatch
```



### Apple Script Execution followed by Network Connection

Branch count: 1  
Document count: 2  
Index: geneve-ut-075

```python
sequence by host.id, process.entity_id with maxspan=30s
 [process where event.type == "start" and process.name == "osascript"]
 [network where event.type != "end" and process.name == "osascript" and destination.ip != "::1" and
  not cidrmatch(destination.ip,
    "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32",
    "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24",
    "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10", "FF00::/8")]
```



### Apple Scripting Execution with Administrator Privileges

Branch count: 2  
Document count: 2  
Index: geneve-ut-076

```python
process where event.type in ("start", "process_started") and process.name : "osascript" and
  process.command_line : "osascript*with administrator privileges"
```



### Application Added to Google Workspace Domain

Branch count: 1  
Document count: 1  
Index: geneve-ut-077

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:ADD_APPLICATION
```



### Attempt to Create Okta API Token

Branch count: 1  
Document count: 1  
Index: geneve-ut-078

```python
event.dataset:okta.system and event.action:system.api_token.create
```



### Attempt to Deactivate MFA for an Okta User Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-079

```python
event.dataset:okta.system and event.action:user.mfa.factor.deactivate
```



### Attempt to Deactivate an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-080

```python
event.dataset:okta.system and event.action:application.lifecycle.deactivate
```



### Attempt to Deactivate an Okta Network Zone

Branch count: 1  
Document count: 1  
Index: geneve-ut-081

```python
event.dataset:okta.system and event.action:zone.deactivate
```



### Attempt to Deactivate an Okta Policy

Branch count: 1  
Document count: 1  
Index: geneve-ut-082

```python
event.dataset:okta.system and event.action:policy.lifecycle.deactivate
```



### Attempt to Deactivate an Okta Policy Rule

Branch count: 1  
Document count: 1  
Index: geneve-ut-083

```python
event.dataset:okta.system and event.action:policy.rule.deactivate
```



### Attempt to Delete an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-084

```python
event.dataset:okta.system and event.action:application.lifecycle.delete
```



### Attempt to Delete an Okta Network Zone

Branch count: 1  
Document count: 1  
Index: geneve-ut-085

```python
event.dataset:okta.system and event.action:zone.delete
```



### Attempt to Delete an Okta Policy

Branch count: 1  
Document count: 1  
Index: geneve-ut-086

```python
event.dataset:okta.system and event.action:policy.lifecycle.delete
```



### Attempt to Delete an Okta Policy Rule

Branch count: 1  
Document count: 1  
Index: geneve-ut-087

```python
event.dataset:okta.system and event.action:policy.rule.delete
```



### Attempt to Disable Gatekeeper

Branch count: 2  
Document count: 2  
Index: geneve-ut-088

```python
event.category:process and event.type:(start or process_started) and 
  process.args:(spctl and "--master-disable")
```



### Attempt to Disable Syslog Service

Branch count: 30  
Document count: 30  
Index: geneve-ut-089

```python
event.category:process and event.type:(start or process_started) and
  ((process.name:service and process.args:stop) or
     (process.name:chkconfig and process.args:off) or
     (process.name:systemctl and process.args:(disable or stop or kill)))
  and process.args:(syslog or rsyslog or "syslog-ng")
```



### Attempt to Enable the Root Account

Branch count: 2  
Document count: 2  
Index: geneve-ut-090

```python
event.category:process and event.type:(start or process_started) and
 process.name:dsenableroot and not process.args:"-d"
```



### Attempt to Install Root Certificate

Branch count: 2  
Document count: 2  
Index: geneve-ut-091

```python
event.category:process and event.type:(start or process_started) and
  process.name:security and process.args:"add-trusted-cert" and
  not process.parent.executable:("/Library/Bitdefender/AVP/product/bin/BDCoreIssues" or "/Applications/Bitdefender/SecurityNetworkInstallerApp.app/Contents/MacOS/SecurityNetworkInstallerApp"
)
```



### Attempt to Modify an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-092

```python
event.dataset:okta.system and event.action:application.lifecycle.update
```



### Attempt to Modify an Okta Network Zone

Branch count: 3  
Document count: 3  
Index: geneve-ut-093

```python
event.dataset:okta.system and event.action:(zone.update or network_zone.rule.disabled or zone.remove_blacklist)
```



### Attempt to Modify an Okta Policy

Branch count: 1  
Document count: 1  
Index: geneve-ut-094

```python
event.dataset:okta.system and event.action:policy.lifecycle.update
```



### Attempt to Modify an Okta Policy Rule

Branch count: 1  
Document count: 1  
Index: geneve-ut-095

```python
event.dataset:okta.system and event.action:policy.rule.update
```



### Attempt to Mount SMB Share via Command Line

Branch count: 8  
Document count: 8  
Index: geneve-ut-096

```python
process where event.type in ("start", "process_started") and
  (
    process.name : "mount_smbfs" or
    (process.name : "open" and process.args : "smb://*") or
    (process.name : "mount" and process.args : "smbfs") or
    (process.name : "osascript" and process.command_line : "osascript*mount volume*smb://*")
  ) and
  not process.parent.executable : "/Applications/Google Drive.app/Contents/MacOS/Google Drive"
```



### Attempt to Remove File Quarantine Attribute

Branch count: 12  
Document count: 12  
Index: geneve-ut-097

```python
process where event.type in ("start", "process_started") and
  process.name : "xattr" and
  (
    (process.args : "com.apple.quarantine" and process.args : ("-d", "-w")) or
    (process.args : "-c") or
    (process.command_line : ("/bin/bash -c xattr -c *", "/bin/zsh -c xattr -c *", "/bin/sh -c xattr -c *"))
  ) and not process.args_count > 12
```



### Attempt to Reset MFA Factors for an Okta User Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-098

```python
event.dataset:okta.system and event.action:user.mfa.factor.reset_all
```



### Attempt to Revoke Okta API Token

Branch count: 1  
Document count: 1  
Index: geneve-ut-099

```python
event.dataset:okta.system and event.action:system.api_token.revoke
```



### Attempt to Unload Elastic Endpoint Security Kernel Extension

Branch count: 4  
Document count: 4  
Index: geneve-ut-100

```python
event.category:process and event.type:(start or process_started) and
 process.name:kextunload and process.args:("/System/Library/Extensions/EndpointSecurity.kext" or "EndpointSecurity.kext")
```



### Attempted Bypass of Okta MFA

Branch count: 1  
Document count: 1  
Index: geneve-ut-101

```python
event.dataset:okta.system and event.action:user.mfa.attempt_bypass
```



### Authorization Plugin Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-104

```python
event.category:file and not event.type:deletion and
  file.path:(/Library/Security/SecurityAgentPlugins/* and
  not /Library/Security/SecurityAgentPlugins/TeamViewerAuthPlugin.bundle/*) and
  not process.name:shove and process.code_signature.trusted:true
```



### Azure AD Global Administrator Role Assigned

Branch count: 1  
Document count: 1  
Index: geneve-ut-105

```python
event.dataset:azure.auditlogs and azure.auditlogs.properties.category:RoleManagement and
azure.auditlogs.operation_name:"Add member to role" and
azure.auditlogs.properties.target_resources.0.modified_properties.1.new_value:"\"Global Administrator\""
```



### Azure Active Directory High Risk Sign-in

Branch count: 4  
Document count: 4  
Index: geneve-ut-106

```python
event.dataset:azure.signinlogs and
  (azure.signinlogs.properties.risk_level_during_signin:high or azure.signinlogs.properties.risk_level_aggregated:high) and
  event.outcome:(success or Success)
```



### Azure Active Directory High Risk User Sign-in Heuristic

Branch count: 4  
Document count: 4  
Index: geneve-ut-107

```python
event.dataset:azure.signinlogs and
  azure.signinlogs.properties.risk_state:("confirmedCompromised" or "atRisk") and event.outcome:(success or Success)
```



### Azure Active Directory PowerShell Sign-in

Branch count: 2  
Document count: 2  
Index: geneve-ut-108

```python
event.dataset:azure.signinlogs and
  azure.signinlogs.properties.app_display_name:"Azure Active Directory PowerShell" and
  azure.signinlogs.properties.token_issuer_type:AzureAD and event.outcome:(success or Success)
```



### Azure Alert Suppression Rule Created or Modified

Branch count: 1  
Document count: 1  
Index: geneve-ut-109

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.SECURITY/ALERTSSUPPRESSIONRULES/WRITE" and
event.outcome: "success"
```



### Azure Application Credential Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-110

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Update application - Certificates and secrets management" and event.outcome:(success or Success)
```



### Azure Automation Account Created

Branch count: 2  
Document count: 2  
Index: geneve-ut-111

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WRITE" and event.outcome:(Success or success)
```



### Azure Automation Runbook Created or Modified

Branch count: 6  
Document count: 6  
Index: geneve-ut-112

```python
event.dataset:azure.activitylogs and
  azure.activitylogs.operation_name:
  (
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DRAFT/WRITE" or
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE" or
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/PUBLISH/ACTION"
  ) and
  event.outcome:(Success or success)
```



### Azure Automation Runbook Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-113

```python
event.dataset:azure.activitylogs and
    azure.activitylogs.operation_name:"MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE" and 
    event.outcome:(Success or success)
```



### Azure Automation Webhook Created

Branch count: 4  
Document count: 4  
Index: geneve-ut-114

```python
event.dataset:azure.activitylogs and
  azure.activitylogs.operation_name:
    (
      "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/ACTION" or
      "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/WRITE"
    ) and
  event.outcome:(Success or success)
```



### Azure Blob Container Access Level Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-115

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE" and event.outcome:(Success or success)
```



### Azure Blob Permissions Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-116

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:(
     "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/BLOBS/MANAGEOWNERSHIP/ACTION" or
     "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/BLOBS/MODIFYPERMISSIONS/ACTION") and
  event.outcome:(Success or success)
```



### Azure Command Execution on Virtual Machine

Branch count: 2  
Document count: 2  
Index: geneve-ut-117

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION" and event.outcome:(Success or success)
```



### Azure Conditional Access Policy Modified

Branch count: 4  
Document count: 4  
Index: geneve-ut-118

```python
event.dataset:(azure.activitylogs or azure.auditlogs) and
event.action:"Update conditional access policy" and event.outcome:(Success or success)
```



### Azure Diagnostic Settings Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-119

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE" and event.outcome:(Success or success)
```



### Azure Event Hub Authorization Rule Created or Updated

Branch count: 2  
Document count: 2  
Index: geneve-ut-120

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.EVENTHUB/NAMESPACES/AUTHORIZATIONRULES/WRITE" and event.outcome:(Success or success)
```



### Azure Event Hub Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-121

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE" and event.outcome:(Success or success)
```



### Azure Firewall Policy Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-123

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE" and event.outcome:(Success or success)
```



### Azure Frontdoor Web Application Firewall (WAF) Policy Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-124

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/FRONTDOORWEBAPPLICATIONFIREWALLPOLICIES/DELETE" and event.outcome:(Success or success)
```



### Azure Key Vault Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-127

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KEYVAULT/VAULTS/WRITE" and event.outcome:(Success or success)
```



### Azure Kubernetes Events Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-128

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EVENTS.K8S.IO/EVENTS/DELETE" and
event.outcome:(Success or success)
```



### Azure Kubernetes Pods Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-129

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE" and
event.outcome:(Success or success)
```



### Azure Kubernetes Rolebindings Created

Branch count: 4  
Document count: 4  
Index: geneve-ut-130

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:
	("MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLEBINDINGS/WRITE" or
	 "MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLEBINDINGS/WRITE") and
event.outcome:(Success or success)
```



### Azure Network Watcher Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-131

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE" and event.outcome:(Success or success)
```



### Azure Privilege Identity Management Role Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-132

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Update role setting in PIM" and event.outcome:(Success or success)
```



### Azure Resource Group Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-133

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE" and event.outcome:(Success or success)
```



### Azure Service Principal Addition

Branch count: 2  
Document count: 2  
Index: geneve-ut-134

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add service principal" and event.outcome:(success or Success)
```



### Azure Service Principal Credentials Added

Branch count: 2  
Document count: 2  
Index: geneve-ut-135

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add service principal credentials" and event.outcome:(success or Success)
```



### Azure Storage Account Key Regenerated

Branch count: 2  
Document count: 2  
Index: geneve-ut-136

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION" and event.outcome:(Success or success)
```



### Azure Virtual Network Device Modified or Deleted

Branch count: 22  
Document count: 22  
Index: geneve-ut-137

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:("MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/WRITE" or
"MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/DELETE" or "MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE" or
"MICROSOFT.NETWORK/NETWORKINTERFACES/JOIN/ACTION" or "MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE" or
"MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/DELETE" or "MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/WRITE" or
"MICROSOFT.NETWORK/VIRTUALHUBS/DELETE" or "MICROSOFT.NETWORK/VIRTUALHUBS/WRITE" or
"MICROSOFT.NETWORK/VIRTUALROUTERS/WRITE" or "MICROSOFT.NETWORK/VIRTUALROUTERS/DELETE") and
event.outcome:(Success or success)
```



### BPF filter applied using TC

Branch count: 1  
Document count: 1  
Index: geneve-ut-138

```python
process where event.type != "end" and process.executable : "/usr/sbin/tc" and process.args : "filter" and process.args : "add" and process.args : "bpf" and not process.parent.executable: "/usr/sbin/libvirtd"
```



### Base16 or Base32 Encoding/Decoding Activity

Branch count: 8  
Document count: 8  
Index: geneve-ut-139

```python
event.category:process and event.type:(start or process_started) and
  process.name:(base16 or base32 or base32plain or base32hex)
```



### Bash Shell Profile Modification

Branch count: 9  
Document count: 9  
Index: geneve-ut-140

```python
event.category:file and event.type:change and
  process.name:(* and not (sudo or
                           vim or
                           zsh or
                           env or
                           nano or
                           bash or
                           Terminal or
                           xpcproxy or
                           login or
                           cat or
                           cp or
                           launchctl or
                           java)) and
  not process.executable:(/Applications/* or /private/var/folders/* or /usr/local/*) and
  file.path:(/private/etc/rc.local or
             /etc/rc.local or
             /home/*/.profile or
             /home/*/.profile1 or
             /home/*/.bash_profile or
             /home/*/.bash_profile1 or
             /home/*/.bashrc or
             /Users/*/.bash_profile or
             /Users/*/.zshenv)
```



### Binary Executed from Shared Memory Directory

Branch count: 4  
Document count: 4  
Index: geneve-ut-141

```python
process where event.type == "start" and 
    event.action == "exec" and user.name == "root" and 
    process.executable : (
        "/dev/shm/*",
        "/run/shm/*",
        "/var/run/*",
        "/var/lock/*"
    ) and
    not process.executable : ( "/var/run/docker/*")
```



### Bypass UAC via Event Viewer

Branch count: 2  
Document count: 2  
Index: geneve-ut-142

```python
process where event.type in ("start", "process_started") and
  process.parent.name : "eventvwr.exe" and
  not process.executable :
            ("?:\\Windows\\SysWOW64\\mmc.exe",
             "?:\\Windows\\System32\\mmc.exe",
             "?:\\Windows\\SysWOW64\\WerFault.exe",
             "?:\\Windows\\System32\\WerFault.exe")
```



### Chkconfig Service Add

Branch count: 2  
Document count: 2  
Index: geneve-ut-143

```python
process where event.type == "start" and 
   (process.executable : "/usr/sbin/chkconfig" and process.args : "--add") or 
   (process.args : "*chkconfig" and process.args : "--add")
```



### Clearing Windows Console History

Branch count: 24  
Document count: 24  
Index: geneve-ut-144

```python
process where event.action == "start" and
  (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or process.pe.original_file_name == "PowerShell.EXE") and
     (process.args : "*Clear-History*" or
     (process.args : ("*Remove-Item*", "rm") and process.args : ("*ConsoleHost_history.txt*", "*(Get-PSReadlineOption).HistorySavePath*")) or
     (process.args : "*Set-PSReadlineOption*" and process.args : "*SaveNothing*"))
```



### Clearing Windows Event Logs

Branch count: 15  
Document count: 15  
Index: geneve-ut-145

```python
process where event.type in ("process_started", "start") and
  (process.name : "wevtutil.exe" or process.pe.original_file_name == "wevtutil.exe") and
    process.args : ("/e:false", "cl", "clear-log") or
  process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and process.args : "Clear-EventLog"
```



### Command Execution via SolarWinds Process

Branch count: 24  
Document count: 24  
Index: geneve-ut-147

```python
process where event.type in ("start", "process_started") and process.name: ("cmd.exe", "powershell.exe") and
process.parent.name: (
     "ConfigurationWizard*.exe",
     "NetflowDatabaseMaintenance*.exe",
     "NetFlowService*.exe",
     "SolarWinds.Administration*.exe",
     "SolarWinds.Collector.Service*.exe",
     "SolarwindsDiagnostics*.exe"
     )
```



### Command Prompt Network Connection

Branch count: 1  
Document count: 2  
Index: geneve-ut-148

```python
sequence by process.entity_id
  [process where process.name : "cmd.exe" and event.type == "start"]
  [network where process.name : "cmd.exe" and
     not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
                                  "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32",
                                  "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
                                  "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
                                  "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
                                  "FE80::/10", "FF00::/8")]
```



### Command Shell Activity Started via RunDLL32

Branch count: 2  
Document count: 2  
Index: geneve-ut-149

```python
process where event.type == "start" and
 process.name : ("cmd.exe", "powershell.exe") and
  process.parent.name : "rundll32.exe" and process.parent.command_line != null and
  /* common FPs can be added here */
  not process.parent.args : ("C:\\Windows\\System32\\SHELL32.dll,RunAsNewUser_RunDLL",
                             "C:\\WINDOWS\\*.tmp,zzzzInvokeManagedCustomActionOutOfProc")
```



### Component Object Model Hijacking

Branch count: 22  
Document count: 22  
Index: geneve-ut-150

```python
registry where
 (registry.path : "HK*}\\InprocServer32\\" and registry.data.strings: ("scrobj.dll", "C:\\*\\scrobj.dll") and
 not registry.path : "*\\{06290BD*-48AA-11D2-8432-006008C3FBFC}\\*")
 or
 /* in general COM Registry changes on Users Hive is less noisy and worth alerting */
 (registry.path : ("HKEY_USERS\\*Classes\\*\\InprocServer32\\",
                   "HKEY_USERS\\*Classes\\*\\LocalServer32\\",
                   "HKEY_USERS\\*Classes\\*\\DelegateExecute\\",
                   "HKEY_USERS\\*Classes\\*\\TreatAs\\",
                   "HKEY_USERS\\*Classes\\CLSID\\*\\ScriptletURL\\") and
 not (process.executable : "?:\\Program Files*\\Veeam\\Backup and Replication\\Console\\veeam.backup.shell.exe" and
      registry.path : "HKEY_USERS\\S-1-5-21-*_Classes\\CLSID\\*\\LocalServer32\\") and
 /* not necessary but good for filtering privileged installations */
 user.domain != "NT AUTHORITY"
 ) and
 /* removes false-positives generated by OneDrive and Teams */
 not process.name : ("OneDrive.exe","OneDriveSetup.exe","FileSyncConfig.exe","Teams.exe") and
 /* Teams DLL loaded by regsvr */
 not (process.name: "regsvr32.exe" and
 registry.data.strings : "*Microsoft.Teams.*.dll")
```



### Conhost Spawned By Suspicious Parent Process

Branch count: 30  
Document count: 30  
Index: geneve-ut-151

```python
process where event.type in ("start", "process_started") and
  process.name : "conhost.exe" and
  process.parent.name : ("svchost.exe", "lsass.exe", "services.exe", "smss.exe", "winlogon.exe", "explorer.exe",
                         "dllhost.exe", "rundll32.exe", "regsvr32.exe", "userinit.exe", "wininit.exe", "spoolsv.exe",
                         "wermgr.exe", "csrss.exe", "ctfmon.exe")
```



### Connection to Commonly Abused Free SSL Certificate Providers

Branch count: 24  
Document count: 24  
Index: geneve-ut-152

```python
network where network.protocol == "dns" and
  /* Add new free SSL certificate provider domains here */
  dns.question.name : ("*letsencrypt.org", "*.sslforfree.com", "*.zerossl.com", "*.freessl.org") and

  /* Native Windows process paths that are unlikely to have network connections to domains secured using free SSL certificates */
  process.executable : ("C:\\Windows\\System32\\*.exe",
                        "C:\\Windows\\System\\*.exe",
	                  "C:\\Windows\\SysWOW64\\*.exe",
		          "C:\\Windows\\Microsoft.NET\\Framework*\\*.exe",
		          "C:\\Windows\\explorer.exe",
		          "C:\\Windows\\notepad.exe") and

  /* Insert noisy false positives here */
  not process.name : ("svchost.exe", "MicrosoftEdge*.exe", "msedge.exe")
```



### Connection to Commonly Abused Web Services

Branch count: 27  
Document count: 27  
Index: geneve-ut-153

```python
network where network.protocol == "dns" and
    process.name != null and user.id not in ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
    /* Add new WebSvc domains here */
    dns.question.name :
    (
        "raw.githubusercontent.*",
        "*.pastebin.*",
        "*drive.google.*",
        "*docs.live.*",
        "*api.dropboxapi.*",
        "*dropboxusercontent.*",
        "*onedrive.*",
        "*4shared.*",
        "*.file.io",
        "*filebin.net",
        "*slack-files.com",
        "*ghostbin.*",
        "*ngrok.*",
        "*portmap.*",
        "*serveo.net",
        "*localtunnel.me",
        "*pagekite.me",
        "*localxpose.io",
        "*notabug.org",
        "rawcdn.githack.*",
        "paste.nrecom.net",
        "zerobin.net",
        "controlc.com",
        "requestbin.net",
        "cdn.discordapp.com",
        "discordapp.com",
        "discord.com"
    ) and
    /* Insert noisy false positives here */
    not process.executable :
    (
      "?:\\Program Files\\*.exe",
      "?:\\Program Files (x86)\\*.exe",
      "?:\\Windows\\System32\\WWAHost.exe",
      "?:\\Windows\\System32\\smartscreen.exe",
      "?:\\Windows\\System32\\MicrosoftEdgeCP.exe",
      "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
      "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
      "?:\\Users\\*\\AppData\\Local\\Programs\\Fiddler\\Fiddler.exe",
      "?:\\Users\\*\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
      "?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
      "?:\\Windows\\system32\\mobsync.exe",
      "?:\\Windows\\SysWOW64\\mobsync.exe",
      "?:\\Users\\*\\AppData\\Local\\Discord\\app-*\\Discord.exe"
    )
```



### Connection to External Network via Telnet

Branch count: 1  
Document count: 2  
Index: geneve-ut-154

```python
sequence by process.entity_id
  [process where process.name == "telnet" and event.type == "start"]
  [network where process.name == "telnet" and
    not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
                                  "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32",
                                  "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
                                  "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
                                  "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
                                  "FE80::/10", "FF00::/8")]
```



### Connection to Internal Network via Telnet

Branch count: 1  
Document count: 2  
Index: geneve-ut-155

```python
sequence by process.entity_id
  [process where process.name == "telnet" and event.type == "start"]
  [network where process.name == "telnet" and
    cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
                              "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32",
                              "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
                              "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
                              "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
                              "FE80::/10", "FF00::/8")]
```



### Control Panel Process with Unusual Arguments

Branch count: 48  
Document count: 48  
Index: geneve-ut-156

```python
process where event.type in ("start", "process_started") and
 process.executable : ("?:\\Windows\\SysWOW64\\control.exe", "?:\\Windows\\System32\\control.exe") and
 process.command_line :
          ("*.jpg*",
           "*.png*",
           "*.gif*",
           "*.bmp*",
           "*.jpeg*",
           "*.TIFF*",
           "*.inf*",
           "*.cpl:*/*",
           "*../../..*",
           "*/AppData/Local/*",
           "*:\\Users\\Public\\*",
           "*\\AppData\\Local\\*")
```



### Creation of Hidden Launch Agent or Daemon

Branch count: 5  
Document count: 5  
Index: geneve-ut-158

```python
file where event.type != "deletion" and
  file.path :
  (
    "/System/Library/LaunchAgents/.*.plist",
    "/Library/LaunchAgents/.*.plist",
    "/Users/*/Library/LaunchAgents/.*.plist",
    "/System/Library/LaunchDaemons/.*.plist",
    "/Library/LaunchDaemons/.*.plist"
  )
```



### Creation of Hidden Login Item via Apple Script

Branch count: 2  
Document count: 2  
Index: geneve-ut-159

```python
process where event.type in ("start", "process_started") and process.name : "osascript" and
 process.command_line : "osascript*login item*hidden:true*"
```



### Creation of Hidden Shared Object File

Branch count: 1  
Document count: 1  
Index: geneve-ut-160

```python
file where event.action : "creation" and file.extension == "so" and file.name : ".*.so"
```



### Creation of a Hidden Local User Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-161

```python
registry where registry.path : "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\*$\\"
```



### Creation or Modification of Domain Backup DPAPI private key

Branch count: 2  
Document count: 2  
Index: geneve-ut-162

```python
file where event.type != "deletion" and file.name : ("ntds_capi_*.pfx", "ntds_capi_*.pvk")
```



### Creation or Modification of Root Certificate

Branch count: 8  
Document count: 8  
Index: geneve-ut-163

```python
registry where event.type in ("creation", "change") and
  registry.path :
    (
      "HKLM\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "HKLM\\Software\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "HKLM\\Software\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "HKLM\\Software\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob"
    )
```



### Creation or Modification of a new GPO Scheduled Task or Service

Branch count: 2  
Document count: 2  
Index: geneve-ut-164

```python
file where event.type != "deletion" and
  file.path : ("?:\\Windows\\SYSVOL\\domain\\Policies\\*\\MACHINE\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
               "?:\\Windows\\SYSVOL\\domain\\Policies\\*\\MACHINE\\Preferences\\Preferences\\Services\\Services.xml") and
  not process.name : "dfsrs.exe"
```



### Credential Acquisition via Registry Hive Dumping

Branch count: 8  
Document count: 8  
Index: geneve-ut-165

```python
process where event.type in ("start", "process_started") and
 process.pe.original_file_name == "reg.exe" and
 process.args : ("save", "export") and
 process.args : ("hklm\\sam", "hklm\\security")
```



### Credential Dumping - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-166

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:cred_theft_event or endgame.event_subtype_full:cred_theft_event)
```



### Credential Dumping - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-167

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:cred_theft_event or endgame.event_subtype_full:cred_theft_event)
```



### Credential Manipulation - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-168

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:token_manipulation_event or endgame.event_subtype_full:token_manipulation_event)
```



### Credential Manipulation - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-169

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:token_manipulation_event or endgame.event_subtype_full:token_manipulation_event)
```



### CyberArk Privileged Access Security Error

Branch count: 1  
Document count: 1  
Index: geneve-ut-170

```python
event.dataset:cyberarkpas.audit and event.type:error
```



### CyberArk Privileged Access Security Recommended Monitor

Branch count: 20  
Document count: 20  
Index: geneve-ut-171

```python
event.dataset:cyberarkpas.audit and
  event.code:(4 or 22 or 24 or 31 or 38 or 57 or 60 or 130 or 295 or 300 or 302 or
              308 or 319 or 344 or 346 or 359 or 361 or 378 or 380 or 411) and
  not event.type:error
```



### DNS-over-HTTPS Enabled via Registry

Branch count: 4  
Document count: 4  
Index: geneve-ut-173

```python
registry where event.type in ("creation", "change") and
  (registry.path : "*\\SOFTWARE\\Policies\\Microsoft\\Edge\\BuiltInDnsClientEnabled" and
  registry.data.strings : "1") or
  (registry.path : "*\\SOFTWARE\\Google\\Chrome\\DnsOverHttpsMode" and
  registry.data.strings : "secure") or
  (registry.path : "*\\SOFTWARE\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS" and
  registry.data.strings : "1")
```



### Default Cobalt Strike Team Server Certificate

Branch count: 6  
Document count: 6  
Index: geneve-ut-174

```python
event.category:(network or network_traffic) and (tls.server.hash.md5:950098276A495286EB2A2556FBAB6D83 or
  tls.server.hash.sha1:6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C or
  tls.server.hash.sha256:87F2085C32B6A2CC709B365F55873E207A9CAA10BFFECF2FD16D3CF9D94D390C)
```



### Delete Volume USN Journal with Fsutil

Branch count: 4  
Document count: 4  
Index: geneve-ut-175

```python
process where event.type in ("start", "process_started") and
  (process.name : "fsutil.exe" or process.pe.original_file_name == "fsutil.exe") and
  process.args : "deletejournal" and process.args : "usn"
```



### Deleting Backup Catalogs with Wbadmin

Branch count: 4  
Document count: 4  
Index: geneve-ut-176

```python
process where event.type in ("start", "process_started") and
  (process.name : "wbadmin.exe" or process.pe.original_file_name == "WBADMIN.EXE") and
  process.args : "catalog" and process.args : "delete"
```



### Direct Outbound SMB Connection

Branch count: 1  
Document count: 2  
Index: geneve-ut-177

```python
sequence by process.entity_id
  [process where event.type == "start" and process.pid != 4]
  [network where destination.port == 445 and process.pid != 4 and
     not cidrmatch(destination.ip, "127.0.0.1", "::1")]
```



### Disable Windows Event and Security Logs Using Built-in Tools

Branch count: 16  
Document count: 16  
Index: geneve-ut-178

```python
process where event.type in ("start", "process_started") and

  ((process.name:"logman.exe" or process.pe.original_file_name == "Logman.exe") and
      process.args : "EventLog-*" and process.args : ("stop", "delete")) or

  ((process.name : ("pwsh.exe", "powershell.exe", "powershell_ise.exe") or process.pe.original_file_name in
      ("pwsh.exe", "powershell.exe", "powershell_ise.exe")) and
	process.args : "Set-Service" and process.args: "EventLog" and process.args : "Disabled")  or

  ((process.name:"auditpol.exe" or process.pe.original_file_name == "AUDITPOL.EXE") and process.args : "/success:disable")
```



### Disable Windows Firewall Rules via Netsh

Branch count: 3  
Document count: 3  
Index: geneve-ut-179

```python
process where event.type in ("start", "process_started") and
  process.name : "netsh.exe" and
  (process.args : "disable" and process.args : "firewall" and process.args : "set") or
  (process.args : "advfirewall" and process.args : "off" and process.args : "state")
```



### Disabling User Account Control via Registry Modification

Branch count: 6  
Document count: 6  
Index: geneve-ut-180

```python
registry where event.type == "change" and
  registry.path :
    (
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop"
    ) and
  registry.data.strings : ("0", "0x00000000")
```



### Disabling Windows Defender Security Settings via PowerShell

Branch count: 24  
Document count: 24  
Index: geneve-ut-181

```python
process where event.type == "start" and
 (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or process.pe.original_file_name in ("powershell.exe", "pwsh.dll", "powershell_ise.exe")) and
 process.args : "Set-MpPreference" and process.args : ("-Disable*", "Disabled", "NeverSend", "-Exclusion*")
```



### Domain Added to Google Workspace Trusted Domains

Branch count: 1  
Document count: 1  
Index: geneve-ut-182

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:ADD_TRUSTED_DOMAINS
```



### Dumping Account Hashes via Built-In Commands

Branch count: 4  
Document count: 4  
Index: geneve-ut-183

```python
event.category:process and event.type:start and
 process.name:(defaults or mkpassdb) and process.args:(ShadowHashData or "-dump")
```



### Dumping of Keychain Content via Security Command

Branch count: 2  
Document count: 2  
Index: geneve-ut-184

```python
process where event.type in ("start", "process_started") and process.args : "dump-keychain" and process.args : "-d"
```



### Dynamic Linker Copy

Branch count: 4  
Document count: 8  
Index: geneve-ut-185

```python
sequence by process.entity_id with maxspan=1m
[process where event.type == "start" and process.name : ("cp", "rsync") and process.args : ("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/etc/ld.so.preload")]
[file where event.action == "creation" and file.extension == "so"]
```



### EggShell Backdoor Execution

Branch count: 2  
Document count: 2  
Index: geneve-ut-186

```python
event.category:process and event.type:(start or process_started) and process.name:espl and process.args:eyJkZWJ1ZyI6*
```



### Elastic Agent Service Terminated

Branch count: 199  
Document count: 199  
Index: geneve-ut-187

```python
process where
/* net, sc or wmic stopping or deleting Elastic Agent on Windows */
(event.type == "start" and
  process.name : ("net.exe", "sc.exe", "wmic.exe","powershell.exe","taskkill.exe","PsKill.exe","ProcessHacker.exe") and
  process.args : ("stopservice","uninstall", "stop", "disabled","Stop-Process","terminate","suspend") and
  process.args : ("elasticendpoint", "Elastic Agent","elastic-agent","elastic-endpoint"))
or
/* service or systemctl used to stop Elastic Agent on Linux */
(event.type == "end" and
  (process.name : ("systemctl", "service") and 
    process.args : "elastic-agent" and
    process.args : "stop") 
  or 
  /* Unload Elastic Agent extension on MacOS */
  (process.name : "kextunload" and
    process.args : "com.apple.iokit.EndpointSecurity" and
    event.action : "end"))
```



### Emond Rules Creation or Modification

Branch count: 3  
Document count: 3  
Index: geneve-ut-188

```python
file where event.type != "deletion" and
 file.path : ("/private/etc/emond.d/rules/*.plist", "/etc/emon.d/rules/*.plist", "/private/var/db/emondClients/*")
```



### Enable Host Network Discovery via Netsh

Branch count: 2  
Document count: 2  
Index: geneve-ut-189

```python
process where event.type == "start" and
process.name : "netsh.exe" and
process.args : ("firewall", "advfirewall") and process.args : "group=Network Discovery" and process.args : "enable=Yes"
```



### Encoded Executable Stored in the Registry

Branch count: 1  
Document count: 1  
Index: geneve-ut-190

```python
registry where
/* update here with encoding combinations */
 registry.data.strings : "TVqQAAMAAAAEAAAA*"
```



### Encrypting Files with WinRar or 7z

Branch count: 64  
Document count: 64  
Index: geneve-ut-191

```python
process where event.type in ("start", "process_started") and
  ((process.name:"rar.exe" or process.code_signature.subject_name == "win.rar GmbH" or
      process.pe.original_file_name == "Command line RAR") and
    process.args == "a" and process.args : ("-hp*", "-p*", "-dw", "-tb", "-ta", "/hp*", "/p*", "/dw", "/tb", "/ta"))

  or
  (process.pe.original_file_name in ("7z.exe", "7za.exe") and
     process.args == "a" and process.args : ("-p*", "-sdel"))

  /* uncomment if noisy for backup software related FPs */
  /* not process.parent.executable : ("C:\\Program Files\\*.exe", "C:\\Program Files (x86)\\*.exe") */
```



### Endpoint Security

Branch count: 1  
Document count: 1  
Index: geneve-ut-192

```python
event.kind:alert and event.module:(endpoint and not endgame)
```



### Enumerating Domain Trusts via NLTEST.EXE

Branch count: 14  
Document count: 14  
Index: geneve-ut-193

```python
process where event.type in ("start", "process_started") and
    process.name : "nltest.exe" and process.args : (
        "/DCLIST:*", "/DCNAME:*", "/DSGET*",
        "/LSAQUERYFTI:*", "/PARENTDOMAIN",
        "/DOMAIN_TRUSTS", "/BDC_QUERY:*")
```



### Enumeration Command Spawned via WMIPrvSE

Branch count: 44  
Document count: 44  
Index: geneve-ut-194

```python
process where event.type in ("start", "process_started") and
  process.name:
  (
    "arp.exe",
    "dsquery.exe",
    "dsget.exe",
    "gpresult.exe",
    "hostname.exe",
    "ipconfig.exe",
    "nbtstat.exe",
    "net.exe",
    "net1.exe",
    "netsh.exe",
    "netstat.exe",
    "nltest.exe",
    "ping.exe",
    "qprocess.exe",
    "quser.exe",
    "qwinsta.exe",
    "reg.exe",
    "sc.exe",
    "systeminfo.exe",
    "tasklist.exe",
    "tracert.exe",
    "whoami.exe"
  ) and
  process.parent.name:"wmiprvse.exe"
```



### Enumeration of Administrator Accounts

Branch count: 124  
Document count: 124  
Index: geneve-ut-195

```python
process where event.type in ("start", "process_started") and
  (((process.name : "net.exe" or process.pe.original_file_name == "net.exe") or
    ((process.name : "net1.exe" or process.pe.original_file_name == "net1.exe") and
        not process.parent.name : "net.exe")) and
   process.args : ("group", "user", "localgroup") and
   process.args : ("admin", "Domain Admins", "Remote Desktop Users", "Enterprise Admins", "Organization Management") and
   not process.args : "/add")

   or

  ((process.name : "wmic.exe" or process.pe.original_file_name == "wmic.exe") and
     process.args : ("group", "useraccount"))
```



### Enumeration of Kernel Modules

Branch count: 8  
Document count: 8  
Index: geneve-ut-196

```python
event.category:process and event.type:(start or process_started) and
  process.args:(kmod and list and sudo or sudo and (depmod or lsmod or modinfo))
```



### Enumeration of Privileged Local Groups Membership

Branch count: 4  
Document count: 4  
Index: geneve-ut-197

```python
iam where event.action == "user-member-enumerated" and

  /* excluding machine account */
  not winlog.event_data.SubjectUserName: ("*$", "LOCAL SERVICE", "NETWORK SERVICE") and

  /* noisy and usual legit processes excluded */
  not winlog.event_data.CallerProcessName:
               ("-",
                "?:\\Windows\\System32\\VSSVC.exe",
                "?:\\Windows\\System32\\SearchIndexer.exe",
                "?:\\Windows\\System32\\CompatTelRunner.exe",
                "?:\\Windows\\System32\\oobe\\msoobe.exe",
                "?:\\Windows\\System32\\net1.exe",
                "?:\\Windows\\System32\\svchost.exe",
                "?:\\Windows\\System32\\Netplwiz.exe",
                "?:\\Windows\\System32\\msiexec.exe",
                "?:\\Windows\\SysWOW64\\msiexec.exe",
                "?:\\Windows\\System32\\CloudExperienceHostBroker.exe",
                "?:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                "?:\\Windows\\System32\\SrTasks.exe",
                "?:\\Windows\\System32\\lsass.exe",
                "?:\\Windows\\System32\\diskshadow.exe",
                "?:\\Windows\\System32\\dfsrs.exe",
                "?:\\Program Files\\*.exe",
                "?:\\Program Files (x86)\\*.exe",
                "?:\\WindowsAzure\\*\\WaAppAgent.exe",
                "?:\\Windows\\System32\\vssadmin.exe",
                "?:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe",
                "?:\\Windows\\System32\\dllhost.exe",
                "?:\\Windows\\System32\\mmc.exe",
                "?:\\Windows\\System32\\SettingSyncHost.exe",
                "?:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe",
                "?:\\Windows\\System32\\SystemSettingsAdminFlows.exe",
                "?:\\Windows\\Temp\\rubrik_vmware???\\snaptool.exe",
                "?:\\Windows\\System32\\inetsrv\\w3wp.exe",
                "?:\\$WINDOWS.~BT\\Sources\\*.exe",
                "?:\\Windows\\System32\\wsmprovhost.exe",
                "?:\\Windows\\System32\\spool\\drivers\\x64\\3\\x3jobt3?.exe",
                "?:\\Windows\\System32\\mstsc.exe",
                "?:\\Windows\\System32\\esentutl.exe",
                "?:\\Windows\\System32\\RecoveryDrive.exe",
                "?:\\Windows\\System32\\SystemPropertiesComputerName.exe") and

  /* privileged local groups */
  (group.name:("admin*","RemoteDesktopUsers") or
   winlog.event_data.TargetSid:("S-1-5-32-544","S-1-5-32-555"))
```



### Enumeration of Users or Groups via Built-in Commands

Branch count: 46  
Document count: 46  
Index: geneve-ut-198

```python
process where event.type in ("start", "process_started") and
  (
    process.name : ("ldapsearch", "dsmemberutil") or
    (process.name : "dscl" and
      process.args : ("read", "-read", "list", "-list", "ls", "search", "-search") and
      process.args : ("/Active Directory/*", "/Users*", "/Groups*"))
	) and
  not process.parent.executable : ("/Applications/NoMAD.app/Contents/MacOS/NoMAD",
     "/Applications/ZoomPresence.app/Contents/MacOS/ZoomPresence",
     "/Applications/Sourcetree.app/Contents/MacOS/Sourcetree",
     "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon",
     "/Applications/Jamf Connect.app/Contents/MacOS/Jamf Connect",
     "/usr/local/jamf/bin/jamf",
     "/Library/Application Support/AirWatch/hubd",
     "/opt/jc/bin/jumpcloud-agent",
     "/Applications/ESET Endpoint Antivirus.app/Contents/MacOS/esets_daemon",
     "/Applications/ESET Endpoint Security.app/Contents/MacOS/esets_daemon",
     "/Library/PrivilegedHelperTools/com.fortinet.forticlient.uninstall_helper"
    )
```



### Execution of COM object via Xwizard

Branch count: 4  
Document count: 4  
Index: geneve-ut-201

```python
process where event.type in ("start", "process_started") and
 process.pe.original_file_name : "xwizard.exe" and
 (
   (process.args : "RunWizard" and process.args : "{*}") or
   (process.executable != null and
     not process.executable : ("C:\\Windows\\SysWOW64\\xwizard.exe", "C:\\Windows\\System32\\xwizard.exe")
   )
 )
```



### Execution of File Written or Modified by Microsoft Office

Branch count: 16  
Document count: 32  
Index: geneve-ut-202

```python
sequence with maxspan=2h
  [file where event.type != "deletion" and file.extension : "exe" and
     (process.name : "WINWORD.EXE" or
      process.name : "EXCEL.EXE" or
      process.name : "OUTLOOK.EXE" or
      process.name : "POWERPNT.EXE" or
      process.name : "eqnedt32.exe" or
      process.name : "fltldr.exe" or
      process.name : "MSPUB.EXE" or
      process.name : "MSACCESS.EXE")
  ] by host.id, file.path
  [process where event.type in ("start", "process_started")] by host.id, process.executable
```



### Execution of File Written or Modified by PDF Reader

Branch count: 8  
Document count: 16  
Index: geneve-ut-203

```python
sequence with maxspan=2h
  [file where event.type != "deletion" and file.extension : "exe" and
     (process.name : "AcroRd32.exe" or
      process.name : "rdrcef.exe" or
      process.name : "FoxitPhantomPDF.exe" or
      process.name : "FoxitReader.exe") and
     not (file.name : "FoxitPhantomPDF.exe" or
          file.name : "FoxitPhantomPDFUpdater.exe" or
          file.name : "FoxitReader.exe" or
          file.name : "FoxitReaderUpdater.exe" or
          file.name : "AcroRd32.exe" or
          file.name : "rdrcef.exe")
  ] by host.id, file.path
  [process where event.type in ("start", "process_started")] by host.id, process.executable
```



### Execution of Persistent Suspicious Program

Branch count: 432  
Document count: 1296  
Index: geneve-ut-204

```python
/* userinit followed by explorer followed by early child process of explorer (unlikely to be launched interactively) within 1m */
sequence by host.id, user.name with maxspan=1m
  [process where event.type in ("start", "process_started") and process.name : "userinit.exe" and process.parent.name : "winlogon.exe"]
  [process where event.type in ("start", "process_started") and process.name : "explorer.exe"]
  [process where event.type in ("start", "process_started") and process.parent.name : "explorer.exe" and
   /* add suspicious programs here */
   process.pe.original_file_name in ("cscript.exe",
                                     "wscript.exe",
                                     "PowerShell.EXE",
                                     "MSHTA.EXE",
                                     "RUNDLL32.EXE",
                                     "REGSVR32.EXE",
                                     "RegAsm.exe",
                                     "MSBuild.exe",
                                     "InstallUtil.exe") and
    /* add potential suspicious paths here */
    process.args : ("C:\\Users\\*", "C:\\ProgramData\\*", "C:\\Windows\\Temp\\*", "C:\\Windows\\Tasks\\*", "C:\\PerfLogs\\*", "C:\\Intel\\*")
   ]
```



### Execution via Electron Child Process Node.js Module

Branch count: 2  
Document count: 2  
Index: geneve-ut-205

```python
event.category:process and event.type:(start or process_started) and process.args:("-e" and const*require*child_process*)
```



### Execution via MSSQL xp_cmdshell Stored Procedure

Branch count: 2  
Document count: 2  
Index: geneve-ut-206

```python
process where event.type in ("start", "process_started") and
  process.name : "cmd.exe" and process.parent.name : "sqlservr.exe"
```



### Execution via TSClient Mountpoint

Branch count: 2  
Document count: 2  
Index: geneve-ut-207

```python
process where event.type in ("start", "process_started") and process.executable : "\\Device\\Mup\\tsclient\\*.exe"
```



### Execution via local SxS Shared Module

Branch count: 1  
Document count: 1  
Index: geneve-ut-208

```python
file where file.extension : "dll" and file.path : "C:\\*\\*.exe.local\\*.dll"
```



### Execution with Explicit Credentials via Scripting

Branch count: 24  
Document count: 24  
Index: geneve-ut-209

```python
event.category:process and event.type:(start or process_started) and
 process.name:"security_authtrampoline" and
 process.parent.name:(osascript or com.apple.automator.runner or sh or bash or dash or zsh or python* or Python or perl* or php* or ruby or pwsh)
```



### Exploit - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-210

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:exploit_event or endgame.event_subtype_full:exploit_event)
```



### Exploit - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-211

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:exploit_event or endgame.event_subtype_full:exploit_event)
```



### Exporting Exchange Mailbox via PowerShell

Branch count: 6  
Document count: 6  
Index: geneve-ut-212

```python
process where event.type in ("start", "process_started") and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and process.args : "New-MailboxExportRequest*"
```



### External Alerts

Branch count: 1  
Document count: 1  
Index: geneve-ut-213

```python
event.kind:alert and not event.module:(endgame or endpoint)
```



### External IP Lookup from Non-Browser Process

Branch count: 19  
Document count: 19  
Index: geneve-ut-214

```python
network where network.protocol == "dns" and
    process.name != null and user.id not in ("S-1-5-19", "S-1-5-20") and
    event.action == "lookup_requested" and
    /* Add new external IP lookup services here */
    dns.question.name :
    (
        "*api.ipify.org",
        "*freegeoip.app",
        "*checkip.amazonaws.com",
        "*checkip.dyndns.org",
        "*freegeoip.app",
        "*icanhazip.com",
        "*ifconfig.*",
        "*ipecho.net",
        "*ipgeoapi.com",
        "*ipinfo.io",
        "*ip.anysrc.net",
        "*myexternalip.com",
        "*myipaddress.com",
        "*showipaddress.com",
        "*whatismyipaddress.com",
        "*wtfismyip.com",
        "*ipapi.co",
        "*ip-lookup.net",
        "*ipstack.com"
    ) and
    /* Insert noisy false positives here */
    not process.executable :
    (
      "?:\\Program Files\\*.exe",
      "?:\\Program Files (x86)\\*.exe",
      "?:\\Windows\\System32\\WWAHost.exe",
      "?:\\Windows\\System32\\smartscreen.exe",
      "?:\\Windows\\System32\\MicrosoftEdgeCP.exe",
      "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
      "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
      "?:\\Users\\*\\AppData\\Local\\Programs\\Fiddler\\Fiddler.exe",
      "?:\\Users\\*\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
      "?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"
    )
```



### File Deletion via Shred

Branch count: 8  
Document count: 8  
Index: geneve-ut-215

```python
event.category:process and event.type:(start or process_started) and process.name:shred and
  process.args:("-u" or "--remove" or "-z" or "--zero")
```



### File Permission Modification in Writable Directory

Branch count: 24  
Document count: 24  
Index: geneve-ut-216

```python
event.category:process and event.type:(start or process_started) and
  process.name:(chmod or chown or chattr or chgrp) and
  process.working_directory:(/tmp or /var/tmp or /dev/shm) and
  not user.name:root
```



### File made Immutable by Chattr

Branch count: 2  
Document count: 2  
Index: geneve-ut-217

```python
process where event.type == "start" and user.name == "root" and process.executable : "/usr/bin/chattr" and process.args : ("-*i*", "+*i*") and not process.parent.executable: "/lib/systemd/systemd"
```



### Finder Sync Plugin Registered and Enabled

Branch count: 4  
Document count: 8  
Index: geneve-ut-218

```python
sequence by host.id, user.id with maxspan = 5s
  [process where event.type in ("start", "process_started") and process.name : "pluginkit" and process.args : "-a"]
  [process where event.type in ("start", "process_started") and process.name : "pluginkit" and
    process.args : "-e" and process.args : "use" and process.args : "-i" and
    not process.args :
    (
      "com.google.GoogleDrive.FinderSyncAPIExtension",
      "com.google.drivefs.findersync",
      "com.boxcryptor.osx.Rednif",
      "com.adobe.accmac.ACCFinderSync",
      "com.microsoft.OneDrive.FinderSync",
      "com.insynchq.Insync.Insync-Finder-Integration",
      "com.box.desktop.findersyncext"
    )
  ]
```



### GCP Firewall Rule Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-219

```python
event.dataset:gcp.audit and event.action:(*.compute.firewalls.insert or google.appengine.*.Firewall.Create*Rule)
```



### GCP Firewall Rule Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-220

```python
event.dataset:gcp.audit and event.action:(*.compute.firewalls.delete or google.appengine.*.Firewall.Delete*Rule)
```



### GCP Firewall Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-221

```python
event.dataset:gcp.audit and event.action:(*.compute.firewalls.patch or google.appengine.*.Firewall.Update*Rule)
```



### GCP IAM Custom Role Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-222

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.CreateRole and event.outcome:success
```



### GCP IAM Role Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-223

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DeleteRole and event.outcome:success
```



### GCP IAM Service Account Key Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-224

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DeleteServiceAccountKey and event.outcome:success
```



### GCP Kubernetes Rolebindings Created or Patched

Branch count: 8  
Document count: 8  
Index: geneve-ut-225

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:(io.k8s.authorization.rbac.v*.clusterrolebindings.create or
io.k8s.authorization.rbac.v*.rolebindings.create or io.k8s.authorization.rbac.v*.clusterrolebindings.patch or
io.k8s.authorization.rbac.v*.rolebindings.patch) and event.outcome:success and
not gcp.audit.authentication_info.principal_email:"system:addon-manager"
```



### GCP Logging Bucket Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-226

```python
event.dataset:gcp.audit and event.action:google.logging.v*.ConfigServiceV*.DeleteBucket and event.outcome:success
```



### GCP Logging Sink Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-227

```python
event.dataset:gcp.audit and event.action:google.logging.v*.ConfigServiceV*.DeleteSink and event.outcome:success
```



### GCP Logging Sink Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-228

```python
event.dataset:gcp.audit and event.action:google.logging.v*.ConfigServiceV*.UpdateSink and event.outcome:success
```



### GCP Pub/Sub Subscription Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-229

```python
event.dataset:gcp.audit and event.action:google.pubsub.v*.Subscriber.CreateSubscription and event.outcome:success
```



### GCP Pub/Sub Subscription Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-230

```python
event.dataset:gcp.audit and event.action:google.pubsub.v*.Subscriber.DeleteSubscription and event.outcome:success
```



### GCP Pub/Sub Topic Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-231

```python
event.dataset:gcp.audit and event.action:google.pubsub.v*.Publisher.CreateTopic and event.outcome:success
```



### GCP Pub/Sub Topic Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-232

```python
event.dataset:gcp.audit and event.action:google.pubsub.v*.Publisher.DeleteTopic and event.outcome:success
```



### GCP Service Account Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-233

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.CreateServiceAccount and event.outcome:success
```



### GCP Service Account Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-234

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DeleteServiceAccount and event.outcome:success
```



### GCP Service Account Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-235

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DisableServiceAccount and event.outcome:success
```



### GCP Service Account Key Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-236

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.CreateServiceAccountKey and event.outcome:success
```



### GCP Storage Bucket Configuration Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-237

```python
event.dataset:gcp.audit and event.action:"storage.buckets.update" and event.outcome:success
```



### GCP Storage Bucket Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-238

```python
event.dataset:gcp.audit and event.action:"storage.buckets.delete"
```



### GCP Storage Bucket Permissions Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-239

```python
event.dataset:gcp.audit and event.action:"storage.setIamPermissions" and event.outcome:success
```



### GCP Virtual Private Cloud Network Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-240

```python
event.dataset:gcp.audit and event.action:v*.compute.networks.delete and event.outcome:success
```



### GCP Virtual Private Cloud Route Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-241

```python
event.dataset:gcp.audit and event.action:(v*.compute.routes.insert or "beta.compute.routes.insert")
```



### GCP Virtual Private Cloud Route Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-242

```python
event.dataset:gcp.audit and event.action:v*.compute.routes.delete and event.outcome:success
```



### Google Workspace API Access Granted via Domain-Wide Delegation of Authority

Branch count: 1  
Document count: 1  
Index: geneve-ut-243

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:AUTHORIZE_API_CLIENT_ACCESS
```



### Google Workspace Admin Role Assigned to a User

Branch count: 1  
Document count: 1  
Index: geneve-ut-244

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:ASSIGN_ROLE
```



### Google Workspace Admin Role Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-245

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:DELETE_ROLE
```



### Google Workspace Custom Admin Role Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-246

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:CREATE_ROLE
```



### Google Workspace MFA Enforcement Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-247

```python
event.dataset:google_workspace.admin and event.provider:admin
  and event.category:iam and event.action:ENFORCE_STRONG_AUTHENTICATION
  and google_workspace.admin.new_value:false
```



### Google Workspace Password Policy Modified

Branch count: 12  
Document count: 12  
Index: geneve-ut-248

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and
  event.action:(CHANGE_APPLICATION_SETTING or CREATE_APPLICATION_SETTING) and
  google_workspace.admin.setting.name:(
    "Password Management - Enforce strong password" or
    "Password Management - Password reset frequency" or
    "Password Management - Enable password reuse" or
    "Password Management - Enforce password policy at next login" or
    "Password Management - Minimum password length" or
    "Password Management - Maximum password length"
  )
```



### Google Workspace Role Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-249

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:(ADD_PRIVILEGE or UPDATE_ROLE)
```



### Hosts File Modified

Branch count: 12  
Document count: 12  
Index: geneve-ut-255

```python
any where

  /* file events for creation; file change events are not captured by some of the included sources for linux and so may
     miss this, which is the purpose of the process + command line args logic below */
  (
   event.category == "file" and event.type in ("change", "creation") and
     file.path : ("/private/etc/hosts", "/etc/hosts", "?:\\Windows\\System32\\drivers\\etc\\hosts")
  )
  or

  /* process events for change targeting linux only */
  (
   event.category == "process" and event.type in ("start") and
     process.name in ("nano", "vim", "vi", "emacs", "echo", "sed") and
     process.args : ("/etc/hosts")
  )
```



### Hping Process Activity

Branch count: 6  
Document count: 6  
Index: geneve-ut-256

```python
event.category:process and event.type:(start or process_started) and process.name:(hping or hping2 or hping3)
```



### IIS HTTP Logging Disabled

Branch count: 4  
Document count: 4  
Index: geneve-ut-257

```python
process where event.type in ("start", "process_started") and
  (process.name : "appcmd.exe" or process.pe.original_file_name == "appcmd.exe") and
  process.args : "/dontLog*:*True" and
  not process.parent.name : "iissetup.exe"
```



### IPSEC NAT Traversal Port Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-258

```python
event.category:(network or network_traffic) and network.transport:udp and destination.port:4500
```



### ImageLoad via Windows Update Auto Update Client

Branch count: 16  
Document count: 16  
Index: geneve-ut-260

```python
process where event.type in ("start", "process_started") and
  (process.pe.original_file_name == "wuauclt.exe" or process.name : "wuauclt.exe") and
   /* necessary windows update client args to load a dll */
   process.args : "/RunHandlerComServer" and process.args : "/UpdateDeploymentProvider" and
   /* common paths writeable by a standard user where the target DLL can be placed */
   process.args : ("C:\\Users\\*.dll", "C:\\ProgramData\\*.dll", "C:\\Windows\\Temp\\*.dll", "C:\\Windows\\Tasks\\*.dll")
```



### Incoming DCOM Lateral Movement via MSHTA

Branch count: 4  
Document count: 8  
Index: geneve-ut-262

```python
sequence with maxspan=1m
  [process where event.type in ("start", "process_started") and
     process.name : "mshta.exe" and process.args : "-Embedding"
  ] by host.id, process.entity_id
  [network where event.type == "start" and process.name : "mshta.exe" and
     network.direction : ("incoming", "ingress") and network.transport == "tcp" and
     source.port > 49151 and destination.port > 49151 and source.ip != "127.0.0.1" and source.ip != "::1"
  ] by host.id, process.entity_id
```



### Incoming DCOM Lateral Movement with MMC

Branch count: 4  
Document count: 8  
Index: geneve-ut-263

```python
sequence by host.id with maxspan=1m
 [network where event.type == "start" and process.name : "mmc.exe" and source.port >= 49152 and
 destination.port >= 49152 and source.ip != "127.0.0.1" and source.ip != "::1" and
  network.direction : ("incoming", "ingress") and network.transport == "tcp"
 ] by process.entity_id
 [process where event.type in ("start", "process_started") and process.parent.name : "mmc.exe"
 ] by process.parent.entity_id
```



### Incoming DCOM Lateral Movement with ShellBrowserWindow or ShellWindows

Branch count: 4  
Document count: 8  
Index: geneve-ut-264

```python
sequence by host.id with maxspan=5s
 [network where event.type == "start" and process.name : "explorer.exe" and
  network.direction : ("incoming", "ingress") and network.transport == "tcp" and
  source.port > 49151 and destination.port > 49151 and source.ip != "127.0.0.1" and source.ip != "::1"
 ] by process.entity_id
 [process where event.type in ("start", "process_started") and
  process.parent.name : "explorer.exe"
 ] by process.parent.entity_id
```



### Incoming Execution via PowerShell Remoting

Branch count: 4  
Document count: 8  
Index: geneve-ut-265

```python
sequence by host.id with maxspan = 30s
   [network where network.direction : ("incoming", "ingress") and destination.port in (5985, 5986) and
    network.protocol == "http" and source.ip != "127.0.0.1" and source.ip != "::1"
   ]
   [process where event.type == "start" and process.parent.name : "wsmprovhost.exe" and not process.name : "conhost.exe"]
```



### Incoming Execution via WinRM Remote Shell

Branch count: 4  
Document count: 8  
Index: geneve-ut-266

```python
sequence by host.id with maxspan=30s
   [network where process.pid == 4 and network.direction : ("incoming", "ingress") and
    destination.port in (5985, 5986) and network.protocol == "http" and source.ip != "127.0.0.1" and source.ip != "::1"
   ]
   [process where event.type == "start" and process.parent.name : "winrshost.exe" and not process.name : "conhost.exe"]
```



### InstallUtil Process Making Network Connections

Branch count: 4  
Document count: 8  
Index: geneve-ut-267

```python
/* the benefit of doing this as an eql sequence vs kql is this will limit to alerting only on the first network connection */

sequence by process.entity_id
  [process where event.type in ("start", "process_started") and process.name : "installutil.exe"]
  [network where process.name : "installutil.exe" and network.direction : ("outgoing", "egress")]
```



### Installation of Custom Shim Databases

Branch count: 8  
Document count: 16  
Index: geneve-ut-268

```python
sequence by process.entity_id with maxspan = 5m
  [process where event.type in ("start", "process_started") and
    not (process.name : "sdbinst.exe" and process.parent.name : "msiexec.exe")]
  [registry where event.type in ("creation", "change") and
    registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\*.sdb"]
```



### Installation of Security Support Provider

Branch count: 2  
Document count: 2  
Index: geneve-ut-269

```python
registry where
   registry.path : ("HKLM\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Security Packages*",
                    "HKLM\\SYSTEM\\*ControlSet*\\Control\\Lsa\\OSConfig\\Security Packages*") and
   not process.executable : ("C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\SysWOW64\\msiexec.exe")
```



### Interactive Terminal Spawned via Perl

Branch count: 6  
Document count: 6  
Index: geneve-ut-270

```python
event.category:process and event.type:(start or process_started) and process.name:perl and
  process.args:("exec \"/bin/sh\";" or "exec \"/bin/dash\";" or "exec \"/bin/bash\";")
```



### Interactive Terminal Spawned via Python

Branch count: 6  
Document count: 6  
Index: geneve-ut-271

```python
event.category:process and event.type:(start or process_started) and 
  process.name:python* and
  process.args:("import pty; pty.spawn(\"/bin/sh\")" or
                "import pty; pty.spawn(\"/bin/dash\")" or
                "import pty; pty.spawn(\"/bin/bash\")")
```



### KRBTGT Delegation Backdoor

Branch count: 1  
Document count: 1  
Index: geneve-ut-272

```python
event.action:modified-user-account and event.code:4738 and winlog.event_data.AllowedToDelegateTo:*krbtgt*
```



### Kerberos Cached Credentials Dumping

Branch count: 2  
Document count: 2  
Index: geneve-ut-273

```python
event.category:process and event.type:(start or process_started) and
  process.name:kcc and
  process.args:copy_cred_cache
```



### Kerberos Traffic from Unusual Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-275

```python
network where event.type == "start" and network.direction : ("outgoing", "egress") and
 destination.port == 88 and source.port >= 49152 and
 not process.executable :
            ("?:\\Windows\\System32\\lsass.exe",
             "System",
             "\\device\\harddiskvolume?\\windows\\system32\\lsass.exe",
             "?:\\Program Files\\rapid7\\nexpose\\nse\\.DLLCACHE\\nseserv.exe",
             "?:\\Program Files (x86)\\GFI\\LanGuard 12 Agent\\lnsscomm.exe",
             "?:\\Program Files (x86)\\SuperScan\\scanner.exe",
             "?:\\Program Files (x86)\\Nmap\\nmap.exe",
             "\\device\\harddiskvolume?\\program files (x86)\\nmap\\nmap.exe") and
 destination.address !="127.0.0.1" and destination.address !="::1" and
 /* insert false positives here */
 not process.name in ("swi_fc.exe", "fsIPcam.exe", "IPCamera.exe", "MicrosoftEdgeCP.exe", "MicrosoftEdge.exe", "iexplore.exe", "chrome.exe", "msedge.exe", "opera.exe", "firefox.exe")
```



### Kernel Module Removal

Branch count: 6  
Document count: 6  
Index: geneve-ut-276

```python
event.category:process and event.type:(start or process_started) and
  process.args:((rmmod and sudo) or (modprobe and sudo and ("--remove" or "-r")))
```



### Kernel module load via insmod

Branch count: 1  
Document count: 1  
Index: geneve-ut-277

```python
process where event.type == "start" and process.executable : "/usr/sbin/insmod" and process.args : "*.ko"
```



### Keychain Password Retrieval via Command Line

Branch count: 16  
Document count: 16  
Index: geneve-ut-278

```python
process where event.type == "start" and
 process.name : "security" and process.args : "-wa" and process.args : ("find-generic-password", "find-internet-password") and
 process.args : ("Chrome*", "Chromium", "Opera", "Safari*", "Brave", "Microsoft Edge", "Edge", "Firefox*") and
 not process.parent.executable : "/Applications/Keeper Password Manager.app/Contents/Frameworks/Keeper Password Manager Helper*/Contents/MacOS/Keeper Password Manager Helper*"
```



### Kubernetes Exposed Service Created With Type NodePort

Branch count: 3  
Document count: 3  
Index: geneve-ut-279

```python
kubernetes.audit.objectRef.resource:"services" and kubernetes.audit.verb:("create" or "update" or "patch") and kubernetes.audit.requestObject.spec.type:"NodePort"
```



### Kubernetes Pod Created With HostIPC

Branch count: 3  
Document count: 3  
Index: geneve-ut-280

```python
kubernetes.audit.objectRef.resource:"pods" and kubernetes.audit.verb:("create" or "update" or "patch") and kubernetes.audit.requestObject.spec.hostIPC:true
```



### Kubernetes Pod Created With HostNetwork

Branch count: 3  
Document count: 3  
Index: geneve-ut-281

```python
kubernetes.audit.objectRef.resource:"pods" and kubernetes.audit.verb:("create" or "update" or "patch") and kubernetes.audit.requestObject.spec.hostNetwork:true
```



### Kubernetes Pod Created With HostPID

Branch count: 3  
Document count: 3  
Index: geneve-ut-282

```python
kubernetes.audit.objectRef.resource:"pods" and kubernetes.audit.verb:("create" or "update" or "patch") and kubernetes.audit.requestObject.spec.hostPID:true
```



### Kubernetes Pod created with a Sensitive hostPath Volume

Branch count: 42  
Document count: 42  
Index: geneve-ut-283

```python
kubernetes.audit.objectRef.resource:"pods" 
  and kubernetes.audit.verb:("create" or "update" or "patch") 
  and kubernetes.audit.requestObject.spec.volumes.hostPath.path:("/" or "/proc" or "/root" or "/var" or "/var/run/docker.sock" or "/var/run/crio/crio.sock" or "/var/run/cri-dockerd.sock" or "/var/lib/kubelet" or "/var/lib/kubelet/pki" or "/var/lib/docker/overlay2" or "/etc" or "/etc/kubernetes" or "/etc/kubernetes/manifests" or "/home/admin")
```



### Kubernetes Privileged Pod Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-284

```python
kubernetes.audit.objectRef.resource:pods and kubernetes.audit.verb:create and
  kubernetes.audit.requestObject.spec.containers.securityContext.privileged:true
```



### Kubernetes Suspicious Self-Subject Review

Branch count: 6  
Document count: 6  
Index: geneve-ut-285

```python
kubernetes.audit.verb:"create" 
and kubernetes.audit.objectRef.resource:("selfsubjectaccessreviews" or "selfsubjectrulesreviews") 
and kubernetes.audit.user.username:(system\:serviceaccount\:* or system\:node\:*) or kubernetes.audit.impersonatedUser.username:(system\:serviceaccount\:* or system\:node\:*)
```



### Kubernetes User Exec into Pod

Branch count: 1  
Document count: 1  
Index: geneve-ut-286

```python
kubernetes.audit.objectRef.resource:"pods" 
  and kubernetes.audit.objectRef.subresource:"exec"
```



### LSASS Memory Dump Creation

Branch count: 20  
Document count: 20  
Index: geneve-ut-287

```python
file where file.name : ("lsass*.dmp", "dumpert.dmp", "Andrew.dmp", "SQLDmpr*.mdmp", "Coredump.dmp") and

 not (process.executable : ("?:\\Program Files\\Microsoft SQL Server\\*\\Shared\\SqlDumper.exe", "?:\\Windows\\System32\\dllhost.exe") and
      file.path : ("?:\\Program Files\\Microsoft SQL Server\\*\\Shared\\ErrorDumps\\SQLDmpr*.mdmp",
                   "?:\\*\\Reporting Services\\Logfiles\\SQLDmpr*.mdmp")) and

 not (process.executable : "?:\\WINDOWS\\system32\\WerFault.exe" and
      file.path : "?:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\CrashDumps\\lsass.exe.*.dmp")
```



### LSASS Memory Dump Handle Access

Branch count: 18  
Document count: 18  
Index: geneve-ut-288

```python
any where event.action == "File System" and event.code == "4656" and

    winlog.event_data.ObjectName : (
        "?:\\Windows\\System32\\lsass.exe",
        "\\Device\\HarddiskVolume?\\Windows\\System32\\lsass.exe",
        "\\Device\\HarddiskVolume??\\Windows\\System32\\lsass.exe") and

    /* The right to perform an operation controlled by an extended access right. */

    (winlog.event_data.AccessMask : ("0x1fffff" , "0x1010", "0x120089", "0x1F3FFF") or
     winlog.event_data.AccessMaskDescription : ("READ_CONTROL", "Read from process memory"))

     /* Common Noisy False Positives */

    and not winlog.event_data.ProcessName : (
        "?:\\Program Files\\*.exe",
        "?:\\Program Files (x86)\\*.exe",
        "?:\\Windows\\system32\\wbem\\WmiPrvSE.exe",
        "?:\\Windows\\System32\\dllhost.exe",
        "?:\\Windows\\System32\\svchost.exe",
        "?:\\Windows\\System32\\msiexec.exe",
        "?:\\ProgramData\\Microsoft\\Windows Defender\\*.exe",
        "?:\\Windows\\explorer.exe")
```



### Lateral Movement via Startup Folder

Branch count: 8  
Document count: 8  
Index: geneve-ut-289

```python
file where event.type in ("creation", "change") and

 /* via RDP TSClient mounted share or SMB */
  (process.name : "mstsc.exe" or process.pid == 4) and

   file.path : ("?:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
                "?:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")
```



### Launch Agent Creation or Modification and Immediate Loading

Branch count: 6  
Document count: 12  
Index: geneve-ut-290

```python
sequence by host.id with maxspan=1m
 [file where event.type != "deletion" and 
  file.path : ("/System/Library/LaunchAgents/*", "/Library/LaunchAgents/*", "/Users/*/Library/LaunchAgents/*")
 ]
 [process where event.type in ("start", "process_started") and process.name == "launchctl" and process.args == "load"]
```



### LaunchDaemon Creation or Modification and Immediate Loading

Branch count: 4  
Document count: 8  
Index: geneve-ut-291

```python
sequence by host.id with maxspan=1m
 [file where event.type != "deletion" and file.path : ("/System/Library/LaunchDaemons/*", "/Library/LaunchDaemons/*")]
 [process where event.type in ("start", "process_started") and process.name == "launchctl" and process.args == "load"]
```



### Linux Restricted Shell Breakout via  Linux Binary(s)

Branch count: 79  
Document count: 79  
Index: geneve-ut-292

```python
process where event.type == "start" and

    /* launch shells from unusual process */
    (process.name == "capsh" and process.args == "--") or

    /* launching shells from unusual parents or parent+arg combos */
    (process.name in ("bash", "sh", "dash","ash") and
        (process.parent.name in ("byebug","git","ftp","strace")) or

        /* shells specified in parent args */
        /* nice rule is broken in 8.2 */
        (process.parent.args in ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash", "sh", "bash", "dash", "ash") and
            (
             (process.parent.name == "nice") or
             (process.parent.name == "cpulimit" and process.parent.args == "-f") or
             (process.parent.name == "find" and process.parent.args == "-exec" and process.parent.args == ";") or
             (process.parent.name == "flock" and process.parent.args == "-u" and process.parent.args == "/")
            )
        ) or

         /* shells specified in args */
         (process.args in ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash", "sh", "bash", "dash", "ash") and
            (process.parent.name == "crash" and process.parent.args == "-h") or
            (process.name == "sensible-pager" and process.parent.name in ("apt", "apt-get") and process.parent.args == "changelog")
            /* scope to include more sensible-pager invoked shells with different parent process to reduce noise and remove false positives */
          )
    ) or
    (process.name == "busybox" and process.args_count == 2 and process.args in ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash", "sh", "bash", "dash", "ash") )or
    (process.name == "env" and process.args_count == 2 and process.args in ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/ash", "sh", "bash", "dash", "ash")) or
    (process.parent.name in ("vi", "vim") and process.parent.args == "-c" and process.parent.args in (":!/bin/bash", ":!/bin/sh", ":!bash", ":!sh")) or
    (process.parent.name in ("c89","c99", "gcc") and process.parent.args in ("sh,-s", "bash,-s", "dash,-s", "ash,-s", "/bin/sh,-s", "/bin/bash,-s", "/bin/dash,-s", "/bin/ash,-s") and process.parent.args == "-wrapper") or
    (process.parent.name == "expect" and process.parent.args == "-c" and process.parent.args in ("spawn /bin/sh;interact", "spawn /bin/bash;interact", "spawn /bin/dash;interact", "spawn sh;interact", "spawn bash;interact", "spawn dash;interact")) or
    (process.parent.name == "mysql" and process.parent.args == "-e" and process.parent.args in ("\\!*sh", "\\!*bash", "\\!*dash", "\\!*/bin/sh", "\\!*/bin/bash", "\\!*/bin/dash")) or
    (process.parent.name == "ssh" and process.parent.args == "-o" and process.parent.args in ("ProxyCommand=;sh 0<&2 1>&2", "ProxyCommand=;bash 0<&2 1>&2", "ProxyCommand=;dash 0<&2 1>&2", "ProxyCommand=;/bin/sh 0<&2 1>&2", "ProxyCommand=;/bin/bash 0<&2 1>&2", "ProxyCommand=;/bin/dash 0<&2 1>&2")) or
    (process.parent.name in ("nawk", "mawk", "awk", "gawk") and process.parent.args : "BEGIN {system(*)}")
```



### Local Scheduled Task Creation

Branch count: 600  
Document count: 1200  
Index: geneve-ut-293

```python
sequence with maxspan=1m
  [process where event.type != "end" and
    ((process.name : ("cmd.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "mshta.exe",
                      "powershell.exe", "pwsh.exe", "powershell_ise.exe", "WmiPrvSe.exe", "wsmprovhost.exe", "winrshost.exe") or
    process.pe.original_file_name : ("cmd.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "mshta.exe",
                                     "powershell.exe", "pwsh.dll", "powershell_ise.exe", "WmiPrvSe.exe", "wsmprovhost.exe",
                                     "winrshost.exe")) or
    process.code_signature.trusted == false)] by process.entity_id
  [process where event.type == "start" and
    (process.name : "schtasks.exe" or process.pe.original_file_name == "schtasks.exe") and
    process.args : ("/create", "-create") and process.args : ("/RU", "/SC", "/TN", "/TR", "/F", "/XML") and
    /* exclude SYSTEM Integrity Level - look for task creations by non-SYSTEM user */
    not (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System")
  ] by process.parent.entity_id
```



### MFA Disabled for Google Workspace Organization

Branch count: 2  
Document count: 2  
Index: geneve-ut-294

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:(ENFORCE_STRONG_AUTHENTICATION or ALLOW_STRONG_AUTHENTICATION) and google_workspace.admin.new_value:false
```



### MS Office Macro Security Registry Modifications

Branch count: 12  
Document count: 12  
Index: geneve-ut-295

```python
registry where event.type == "change" and
    registry.path : (
        "HKU\\S-1-5-21-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\AccessVBOM",
        "HKU\\S-1-5-21-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\VbaWarnings"
        ) and
    registry.data.strings == "0x00000001" and
    process.name : ("cscript.exe", "wscript.exe", "mshta.exe", "mshta.exe", "winword.exe", "excel.exe")
```



### MacOS Installer Package Spawns Network Event

Branch count: 48  
Document count: 96  
Index: geneve-ut-296

```python
sequence by host.id, user.id with maxspan=30s
[process where event.type == "start" and event.action == "exec" and process.parent.name : ("installer", "package_script_service") and process.name : ("bash", "sh", "zsh", "python", "osascript", "tclsh*")] 
[network where event.type == "start" and process.name : ("curl", "osascript", "wget", "python")]
```



### Malware - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-297

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:file_classification_event or endgame.event_subtype_full:file_classification_event)
```



### Malware - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-298

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:file_classification_event or endgame.event_subtype_full:file_classification_event)
```



### Microsoft 365 Exchange Anti-Phish Policy Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-299

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-AntiPhishPolicy" and event.outcome:success
```



### Microsoft 365 Exchange Anti-Phish Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-300

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-AntiPhishRule" or "Disable-AntiPhishRule") and event.outcome:success
```



### Microsoft 365 Exchange DKIM Signing Configuration Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-301

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Set-DkimSigningConfig" and o365.audit.Parameters.Enabled:False and event.outcome:success
```



### Microsoft 365 Exchange DLP Policy Removed

Branch count: 1  
Document count: 1  
Index: geneve-ut-302

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-DlpPolicy" and event.outcome:success
```



### Microsoft 365 Exchange Malware Filter Policy Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-303

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-MalwareFilterPolicy" and event.outcome:success
```



### Microsoft 365 Exchange Malware Filter Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-304

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-MalwareFilterRule" or "Disable-MalwareFilterRule") and event.outcome:success
```



### Microsoft 365 Exchange Management Group Role Assignment

Branch count: 1  
Document count: 1  
Index: geneve-ut-305

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"New-ManagementRoleAssignment" and event.outcome:success
```



### Microsoft 365 Exchange Safe Attachment Rule Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-306

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Disable-SafeAttachmentRule" and event.outcome:success
```



### Microsoft 365 Exchange Safe Link Policy Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-307

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Disable-SafeLinksRule" and event.outcome:success
```



### Microsoft 365 Exchange Transport Rule Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-308

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"New-TransportRule" and event.outcome:success
```



### Microsoft 365 Exchange Transport Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-309

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-TransportRule" or "Disable-TransportRule") and event.outcome:success
```



### Microsoft 365 Global Administrator Role Assigned

Branch count: 1  
Document count: 1  
Index: geneve-ut-310

```python
event.dataset:o365.audit and event.code:"AzureActiveDirectory" and event.action:"Add member to role." and
o365.audit.ModifiedProperties.Role_DisplayName.NewValue:"Global Administrator"
```



### Microsoft 365 Inbox Forwarding Rule Created

Branch count: 3  
Document count: 3  
Index: geneve-ut-311

```python
event.dataset:o365.audit and event.provider:Exchange and
event.category:web and event.action:"New-InboxRule" and
    (
        o365.audit.Parameters.ForwardTo:* or
        o365.audit.Parameters.ForwardAsAttachmentTo:* or
        o365.audit.Parameters.RedirectTo:*
    )
    and event.outcome:success
```



### Microsoft 365 Potential ransomware activity

Branch count: 1  
Document count: 1  
Index: geneve-ut-312

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"Potential ransomware activity" and event.outcome:success
```



### Microsoft 365 Teams Custom Application Interaction Allowed

Branch count: 1  
Document count: 1  
Index: geneve-ut-313

```python
event.dataset:o365.audit and event.provider:MicrosoftTeams and
event.category:web and event.action:TeamsTenantSettingChanged and
o365.audit.Name:"Allow sideloading and interaction of custom apps" and
o365.audit.NewValue:True and event.outcome:success
```



### Microsoft 365 Teams External Access Enabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-314

```python
event.dataset:o365.audit and event.provider:(SkypeForBusiness or MicrosoftTeams) and
event.category:web and event.action:"Set-CsTenantFederationConfiguration" and
o365.audit.Parameters.AllowFederatedUsers:True and event.outcome:success
```



### Microsoft 365 Teams Guest Access Enabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-315

```python
event.dataset:o365.audit and event.provider:(SkypeForBusiness or MicrosoftTeams) and
event.category:web and event.action:"Set-CsTeamsClientConfiguration" and
o365.audit.Parameters.AllowGuestUser:True and event.outcome:success
```



### Microsoft 365 Unusual Volume of File Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-316

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"Unusual volume of file deletion" and event.outcome:success
```



### Microsoft 365 User Restricted from Sending Email

Branch count: 1  
Document count: 1  
Index: geneve-ut-317

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"User restricted from sending email" and event.outcome:success
```



### Microsoft Build Engine Started an Unusual Process

Branch count: 6  
Document count: 6  
Index: geneve-ut-318

```python
process where event.type in ("start", "process_started") and
  process.parent.name : "MSBuild.exe" and
  process.name : ("csc.exe", "iexplore.exe", "powershell.exe")
```



### Microsoft Build Engine Started by a Script Process

Branch count: 14  
Document count: 14  
Index: geneve-ut-319

```python
process where event.type == "start" and
  (process.name : "MSBuild.exe" or process.pe.original_file_name == "MSBuild.exe") and
  process.parent.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cscript.exe", "wscript.exe", "mshta.exe")
```



### Microsoft Build Engine Started by a System Process

Branch count: 4  
Document count: 4  
Index: geneve-ut-320

```python
process where event.type in ("start", "process_started") and
  process.name : "MSBuild.exe" and
  process.parent.name : ("explorer.exe", "wmiprvse.exe")
```



### Microsoft Build Engine Started by an Office Application

Branch count: 16  
Document count: 16  
Index: geneve-ut-321

```python
process where event.type in ("start", "process_started") and
  process.name : "MSBuild.exe" and
  process.parent.name : ("eqnedt32.exe",
                         "excel.exe",
                         "fltldr.exe",
                         "msaccess.exe",
                         "mspub.exe",
                         "outlook.exe",
                         "powerpnt.exe",
                         "winword.exe" )
```



### Microsoft Build Engine Using an Alternate Name

Branch count: 2  
Document count: 2  
Index: geneve-ut-322

```python
process where event.type in ("start", "process_started") and
  process.pe.original_file_name == "MSBuild.exe" and
  not process.name : "MSBuild.exe"
```



### Microsoft Exchange Server UM Spawning Suspicious Processes

Branch count: 2  
Document count: 2  
Index: geneve-ut-323

```python
process where event.type == "start" and
  process.parent.name : ("UMService.exe", "UMWorkerProcess.exe") and
    not process.executable :
              ("?:\\Windows\\System32\\werfault.exe",
               "?:\\Windows\\System32\\wermgr.exe",
               "?:\\Program Files\\Microsoft\\Exchange Server\\V??\\Bin\\UMWorkerProcess.exe",
               "D:\\Exchange 2016\\Bin\\UMWorkerProcess.exe",
               "E:\\ExchangeServer\\Bin\\UMWorkerProcess.exe")
```



### Microsoft Exchange Server UM Writing Suspicious Files

Branch count: 48  
Document count: 48  
Index: geneve-ut-324

```python
file where event.type == "creation" and
  process.name : ("UMWorkerProcess.exe", "umservice.exe") and
  file.extension : ("php", "jsp", "js", "aspx", "asmx", "asax", "cfm", "shtml") and
  (
    file.path : "?:\\inetpub\\wwwroot\\aspnet_client\\*" or

    (file.path : "?:\\*\\Microsoft\\Exchange Server*\\FrontEnd\\HttpProxy\\owa\\auth\\*" and
       not (file.path : "?:\\*\\Microsoft\\Exchange Server*\\FrontEnd\\HttpProxy\\owa\\auth\\version\\*" or
            file.name : ("errorFE.aspx", "expiredpassword.aspx", "frowny.aspx", "GetIdToken.htm", "logoff.aspx",
                        "logon.aspx", "OutlookCN.aspx", "RedirSuiteServiceProxy.aspx", "signout.aspx"))) or

    (file.path : "?:\\*\\Microsoft\\Exchange Server*\\FrontEnd\\HttpProxy\\ecp\\auth\\*" and
       not file.name : "TimeoutLogoff.aspx")
  )
```



### Microsoft Exchange Worker Spawning Suspicious Processes

Branch count: 8  
Document count: 8  
Index: geneve-ut-325

```python
process where event.type == "start" and
  process.parent.name : "w3wp.exe" and process.parent.args : "MSExchange*AppPool" and
  (process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe") or
  process.pe.original_file_name in ("cmd.exe", "powershell.exe", "pwsh.dll", "powershell_ise.exe"))
```



### Microsoft IIS Connection Strings Decryption

Branch count: 4  
Document count: 4  
Index: geneve-ut-326

```python
process where event.type in ("start", "process_started") and
  (process.name : "aspnet_regiis.exe" or process.pe.original_file_name == "aspnet_regiis.exe") and
  process.args : "connectionStrings" and process.args : "-pdf"
```



### Microsoft IIS Service Account Password Dumped

Branch count: 4  
Document count: 4  
Index: geneve-ut-327

```python
process where event.type in ("start", "process_started") and
   (process.name : "appcmd.exe" or process.pe.original_file_name == "appcmd.exe") and
   process.args : "/list" and process.args : "/text*password"
```



### Microsoft Windows Defender Tampering

Branch count: 30  
Document count: 30  
Index: geneve-ut-328

```python
registry where event.type in ("creation", "change") and
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\PUAProtection" and
  registry.data.strings : ("0", "0x00000000")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection\\DisallowExploitProtectionOverride" and
  registry.data.strings : ("0", "0x00000000")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Features\\TamperProtection" and
  registry.data.strings : ("0", "0x00000000")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableIntrusionPreventionSystem" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableScriptScanning" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access\\EnableControlledFolderAccess" and
  registry.data.strings : ("0", "0x00000000")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableIOAVProtection" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting\\DisableEnhancedNotifications" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet\\DisableBlockAtFirstSeen" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet\\SpynetReporting" and
  registry.data.strings : ("0", "0x00000000")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet\\SubmitSamplesConsent" and
  registry.data.strings : ("0", "0x00000000")) or
  (registry.path : "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableBehaviorMonitoring" and
  registry.data.strings : ("1", "0x00000001"))
```



### Mimikatz Memssp Log File Detected

Branch count: 1  
Document count: 1  
Index: geneve-ut-329

```python
file where file.name : "mimilsa.log" and process.name : "lsass.exe"
```



### Modification of AmsiEnable Registry Key

Branch count: 8  
Document count: 8  
Index: geneve-ut-330

```python
registry where event.type in ("creation", "change") and
  registry.path : (
    "HKEY_USERS\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable",
    "HKU\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable"
  ) and
  registry.data.strings: ("0", "0x00000000")
```



### Modification of Boot Configuration

Branch count: 8  
Document count: 8  
Index: geneve-ut-331

```python
process where event.type in ("start", "process_started") and
  (process.name : "bcdedit.exe" or process.pe.original_file_name == "bcdedit.exe") and
    (
      (process.args : "/set" and process.args : "bootstatuspolicy" and process.args : "ignoreallfailures") or
      (process.args : "no" and process.args : "recoveryenabled")
    )
```



### Modification of Dynamic Linker Preload Shared Object

Branch count: 1  
Document count: 1  
Index: geneve-ut-332

```python
event.category:file and not event.type:deletion and file.path:/etc/ld.so.preload
```



### Modification of Environment Variable via Launchctl

Branch count: 1  
Document count: 1  
Index: geneve-ut-333

```python
event.category:process and event.type:start and
  process.name:launchctl and
  process.args:(setenv and not (JAVA*_HOME or
                                RUNTIME_JAVA_HOME or
                                DBUS_LAUNCHD_SESSION_BUS_SOCKET or
                                ANT_HOME or
                                LG_WEBOS_TV_SDK_HOME or
                                WEBOS_CLI_TV or
                                EDEN_ENV)
                ) and
  not process.parent.executable:("/Applications/NoMachine.app/Contents/Frameworks/bin/nxserver.bin" or
                                 "/usr/local/bin/kr" or
                                 "/Applications/NoMachine.app/Contents/Frameworks/bin/nxserver.bin" or
                                 "/Applications/IntelliJ IDEA CE.app/Contents/jbr/Contents/Home/lib/jspawnhelper") and
  not process.args : "*.vmoptions"
```



### Modification of OpenSSH Binaries

Branch count: 5  
Document count: 5  
Index: geneve-ut-334

```python
event.category:file and event.type:change and
 process.name:* and
 (file.path:(/usr/sbin/sshd or /usr/bin/ssh or /usr/bin/sftp or /usr/bin/scp) or file.name:libkeyutils.so) and
 not process.name:("dpkg" or "yum" or "dnf" or "dnf-automatic")
```



### Modification of Safari Settings via Defaults Command

Branch count: 1  
Document count: 1  
Index: geneve-ut-335

```python
event.category:process and event.type:start and
  process.name:defaults and process.args:
    (com.apple.Safari and write and not
      (
      UniversalSearchEnabled or
      SuppressSearchSuggestions or
      WebKitTabToLinksPreferenceKey or
      ShowFullURLInSmartSearchField or
      com.apple.Safari.ContentPageGroupIdentifier.WebKit2TabsToLinks
      )
    )
```



### Modification of Standard Authentication Module or Configuration

Branch count: 3  
Document count: 3  
Index: geneve-ut-336

```python
event.category:file and event.type:change and 
  (file.name:pam_*.so or file.path:(/etc/pam.d/* or /private/etc/pam.d/*)) and 
  process.executable:
    (* and 
      not 
      (
        /bin/yum or 
        "/usr/sbin/pam-auth-update" or 
        /usr/libexec/packagekitd or 
        /usr/bin/dpkg or 
        /usr/bin/vim or 
        /usr/libexec/xpcproxy or 
        /usr/bin/bsdtar or 
        /usr/local/bin/brew or
        /usr/bin/rsync or
        /usr/bin/yum or
        /var/lib/docker/*/bin/yum or
        /var/lib/docker/*/bin/dpkg or
        ./merged/var/lib/docker/*/bin/dpkg or
        "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/package_script_service.xpc/Contents/MacOS/package_script_service"
      )
    ) and
  not file.path:
         (
           /tmp/snap.rootfs_*/pam_*.so or
           /tmp/newroot/lib/*/pam_*.so or
           /private/var/folders/*/T/com.apple.fileprovider.ArchiveService/TemporaryItems/*/lib/security/pam_*.so or
           /tmp/newroot/usr/lib64/security/pam_*.so
         )
```



### Modification of WDigest Security Provider

Branch count: 8  
Document count: 8  
Index: geneve-ut-337

```python
registry where event.type : ("creation", "change") and
    registry.path :
        "HKLM\\SYSTEM\\*ControlSet*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential"
    and registry.data.strings : ("1", "0x00000001") and
    not (process.executable : "?:\\Windows\\System32\\svchost.exe" and user.id : "S-1-5-18")
```



### Modification or Removal of an Okta Application Sign-On Policy

Branch count: 2  
Document count: 2  
Index: geneve-ut-338

```python
event.dataset:okta.system and event.action:(application.policy.sign_on.update or application.policy.sign_on.rule.delete)
```



### Mounting Hidden or WebDav Remote Shares

Branch count: 24  
Document count: 24  
Index: geneve-ut-339

```python
process where event.type in ("start", "process_started") and
 ((process.name : "net.exe" or process.pe.original_file_name == "net.exe") or ((process.name : "net1.exe" or process.pe.original_file_name == "net1.exe") and
 not process.parent.name : "net.exe")) and
 process.args : "use" and
 /* including hidden and webdav based online shares such as onedrive  */
 process.args : ("\\\\*\\*$*", "\\\\*@SSL\\*", "http*") and
 /* excluding shares deletion operation */
 not process.args : "/d*"
```



### MsBuild Making Network Connections

Branch count: 1  
Document count: 2  
Index: geneve-ut-340

```python
sequence by process.entity_id
  [process where process.name : "MSBuild.exe" and event.type == "start"]
  [network where process.name : "MSBuild.exe" and
     not cidrmatch(destination.ip, "127.0.0.1", "::1")]
```



### Mshta Making Network Connections

Branch count: 2  
Document count: 4  
Index: geneve-ut-341

```python
sequence by process.entity_id with maxspan=10m
  [process where event.type in ("start", "process_started") and process.name : "mshta.exe" and
     not process.parent.name : "Microsoft.ConfigurationManagement.exe" and
     not (process.parent.executable : "C:\\Amazon\\Amazon Assistant\\amazonAssistantService.exe" or
          process.parent.executable : "C:\\TeamViewer\\TeamViewer.exe") and
     not process.args : "ADSelfService_Enroll.hta"]
  [network where process.name : "mshta.exe"]
```



### Multi-Factor Authentication Disabled for an Azure User

Branch count: 2  
Document count: 2  
Index: geneve-ut-342

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Disable Strong Authentication" and event.outcome:(Success or success)
```



### NTDS or SAM Database File Copied

Branch count: 168  
Document count: 168  
Index: geneve-ut-343

```python
process where event.type in ("start", "process_started") and
  (
    (process.pe.original_file_name in ("Cmd.Exe", "PowerShell.EXE", "XCOPY.EXE") and
       process.args : ("copy", "xcopy", "Copy-Item", "move", "cp", "mv")
    ) or
    (process.pe.original_file_name : "esentutl.exe" and process.args : ("*/y*", "*/vss*", "*/d*"))
  ) and
  process.args : ("*\\ntds.dit", "*\\config\\SAM", "\\*\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\*", "*/system32/config/SAM*")
```



### Netcat Network Activity

Branch count: 25  
Document count: 50  
Index: geneve-ut-344

```python
sequence by process.entity_id
  [process where (process.name == "nc" or process.name == "ncat" or process.name == "netcat" or
                  process.name == "netcat.openbsd" or process.name == "netcat.traditional") and
     event.type == "start"]
  [network where (process.name == "nc" or process.name == "ncat" or process.name == "netcat" or
                  process.name == "netcat.openbsd" or process.name == "netcat.traditional")]
```



### Network Connection via Certutil

Branch count: 1  
Document count: 2  
Index: geneve-ut-345

```python
sequence by process.entity_id
  [process where process.name : "certutil.exe" and event.type == "start"]
  [network where process.name : "certutil.exe" and
    not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
                                  "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32",
                                  "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
                                  "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
                                  "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
                                  "FE80::/10", "FF00::/8")]
```



### Network Connection via Compiled HTML File

Branch count: 1  
Document count: 2  
Index: geneve-ut-346

```python
sequence by process.entity_id
  [process where process.name : "hh.exe" and event.type == "start"]
  [network where process.name : "hh.exe" and
     not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
       "FE80::/10", "FF00::/8")]
```



### Network Connection via MsXsl

Branch count: 1  
Document count: 2  
Index: geneve-ut-347

```python
sequence by process.entity_id
  [process where process.name : "msxsl.exe" and event.type == "start"]
  [network where process.name : "msxsl.exe" and
     not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
       "FE80::/10", "FF00::/8")]
```



### Network Connection via Registration Utility

Branch count: 18  
Document count: 36  
Index: geneve-ut-348

```python
sequence by process.entity_id
  [process where event.type == "start" and
   process.name : ("regsvr32.exe", "RegAsm.exe", "RegSvcs.exe") and
   not (
         (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System") and
         (process.parent.name : "msiexec.exe" or process.parent.executable : ("C:\\Program Files (x86)\\*.exe", "C:\\Program Files\\*.exe"))
       )
   ]
  [network where process.name : ("regsvr32.exe", "RegAsm.exe", "RegSvcs.exe")  and
   not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
       "FE80::/10", "FF00::/8") and network.protocol != "dns"]
```



### Network Connection via Signed Binary

Branch count: 16  
Document count: 32  
Index: geneve-ut-349

```python
sequence by process.entity_id
  [process where (process.name : "expand.exe" or process.name : "extrac32.exe" or
                 process.name : "ieexec.exe" or process.name : "makecab.exe") and
                 event.type == "start"]
  [network where (process.name : "expand.exe" or process.name : "extrac32.exe" or
                 process.name : "ieexec.exe" or process.name : "makecab.exe") and
    not cidrmatch(destination.ip,
      "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32",
      "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24",
      "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
      "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10", "FF00::/8")]
```



### Network Logon Provider Registry Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-350

```python
registry where registry.data.strings != null and
 registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\NetworkProvider\\ProviderPath" and
 /* Excluding default NetworkProviders RDPNP, LanmanWorkstation and webclient. */
 not ( user.id : "S-1-5-18" and
       registry.data.strings in
                ("%SystemRoot%\\System32\\ntlanman.dll",
                 "%SystemRoot%\\System32\\drprov.dll",
                 "%SystemRoot%\\System32\\davclnt.dll")
      )
```



### New ActiveSyncAllowedDeviceID Added via PowerShell

Branch count: 6  
Document count: 6  
Index: geneve-ut-352

```python
process where event.type in ("start", "process_started") and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and process.args : "Set-CASMailbox*ActiveSyncAllowedDeviceIDs*"
```



### New or Modified Federation Domain

Branch count: 6  
Document count: 6  
Index: geneve-ut-353

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Set-AcceptedDomain" or
"Set-MsolDomainFederationSettings" or "Add-FederatedDomain" or "New-AcceptedDomain" or "Remove-AcceptedDomain" or "Remove-FederatedDomain") and
event.outcome:success
```



### Nping Process Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-354

```python
event.category:process and event.type:(start or process_started) and process.name:nping
```



### NullSessionPipe Registry Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-355

```python
registry where
registry.path : "HKLM\\SYSTEM\\*ControlSet*\\services\\LanmanServer\\Parameters\\NullSessionPipes" and
registry.data.strings != null
```



### O365 Email Reported by User as Malware or Phish

Branch count: 1  
Document count: 1  
Index: geneve-ut-356

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.action:AlertTriggered and rule.name:"Email reported by user as malware or phish"
```



### O365 Exchange Suspicious Mailbox Right Delegation

Branch count: 3  
Document count: 3  
Index: geneve-ut-358

```python
event.dataset:o365.audit and event.provider:Exchange and event.action:Add-MailboxPermission and
o365.audit.Parameters.AccessRights:(FullAccess or SendAs or SendOnBehalf) and event.outcome:success and
not user.id : "NT AUTHORITY\SYSTEM (Microsoft.Exchange.Servicehost)"
```



### O365 Mailbox Audit Logging Bypass

Branch count: 1  
Document count: 1  
Index: geneve-ut-359

```python
event.dataset:o365.audit and event.provider:Exchange and event.action:Set-MailboxAuditBypassAssociation and event.outcome:success
```



### Okta User Session Impersonation

Branch count: 1  
Document count: 1  
Index: geneve-ut-361

```python
event.dataset:okta.system and event.action:user.session.impersonation.initiate
```



### OneDrive Malware File Upload

Branch count: 1  
Document count: 1  
Index: geneve-ut-362

```python
event.dataset:o365.audit and event.provider:OneDrive and event.code:SharePointFileOperation and event.action:FileMalwareDetected
```



### Outbound Scheduled Task Activity via PowerShell

Branch count: 36  
Document count: 72  
Index: geneve-ut-363

```python
sequence by host.id, process.entity_id with maxspan = 5s
 [any where (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
  (dll.name : "taskschd.dll" or file.name : "taskschd.dll") and process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe")]
 [network where process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and destination.port == 135 and not destination.address in ("127.0.0.1", "::1")]
```



### Peripheral Device Discovery

Branch count: 4  
Document count: 4  
Index: geneve-ut-365

```python
process where event.type in ("start", "process_started") and
  (process.name : "fsutil.exe" or process.pe.original_file_name == "fsutil.exe") and
  process.args : "fsinfo" and process.args : "drives"
```



### Permission Theft - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-366

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:token_protection_event or endgame.event_subtype_full:token_protection_event)
```



### Permission Theft - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-367

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:token_protection_event or endgame.event_subtype_full:token_protection_event)
```



### Persistence via BITS Job Notify Cmdline

Branch count: 1  
Document count: 1  
Index: geneve-ut-368

```python
process where event.type == "start" and
  process.parent.name : "svchost.exe" and process.parent.args : "BITS" and
  not process.executable :
              ("?:\\Windows\\System32\\WerFaultSecure.exe",
               "?:\\Windows\\System32\\WerFault.exe",
               "?:\\Windows\\System32\\wermgr.exe",
               "?:\\WINDOWS\\system32\\directxdatabaseupdater.exe")
```



### Persistence via DirectoryService Plugin Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-369

```python
event.category:file and not event.type:deletion and
  file.path:/Library/DirectoryServices/PlugIns/*.dsplug
```



### Persistence via Docker Shortcut Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-370

```python
event.category : file and event.action : modification and 
 file.path : /Users/*/Library/Preferences/com.apple.dock.plist and 
 not process.name : (xpcproxy or cfprefsd or plutil or jamf or PlistBuddy or InstallerRemotePluginService)
```



### Persistence via Folder Action Script

Branch count: 66  
Document count: 132  
Index: geneve-ut-371

```python
sequence by host.id with maxspan=5s
 [process where event.type in ("start", "process_started", "info") and process.name == "com.apple.foundation.UserScriptService"] by process.pid
 [process where event.type in ("start", "process_started") and process.name in ("osascript", "python", "tcl", "node", "perl", "ruby", "php", "bash", "csh", "zsh", "sh") and
  not process.args : "/Users/*/Library/Application Support/iTerm2/Scripts/AutoLaunch/*.scpt"
 ] by process.parent.pid
```



### Persistence via Hidden Run Key Detected

Branch count: 7  
Document count: 7  
Index: geneve-ut-372

```python
/* Registry Path ends with backslash */
registry where /* length(registry.data.strings) > 0 and */
 registry.path : ("HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\",
                  "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\",
                  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\")
```



### Persistence via KDE AutoStart Script or Desktop File Modification

Branch count: 32  
Document count: 32  
Index: geneve-ut-373

```python
file where event.type != "deletion" and
  file.extension in ("sh", "desktop") and
  file.path :
    (
      "/home/*/.config/autostart/*", "/root/.config/autostart/*",
      "/home/*/.kde/Autostart/*", "/root/.kde/Autostart/*",
      "/home/*/.kde4/Autostart/*", "/root/.kde4/Autostart/*",
      "/home/*/.kde/share/autostart/*", "/root/.kde/share/autostart/*",
      "/home/*/.kde4/share/autostart/*", "/root/.kde4/share/autostart/*",
      "/home/*/.local/share/autostart/*", "/root/.local/share/autostart/*",
      "/home/*/.config/autostart-scripts/*", "/root/.config/autostart-scripts/*",
      "/etc/xdg/autostart/*", "/usr/share/autostart/*"
    ) and
    not process.name in ("yum", "dpkg", "install", "dnf", "teams", "yum-cron", "dnf-automatic")
```



### Persistence via Microsoft Office AddIns

Branch count: 18  
Document count: 18  
Index: geneve-ut-375

```python
file where event.type != "deletion" and
 file.extension : ("wll","xll","ppa","ppam","xla","xlam") and
 file.path :
    (
    "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Word\\Startup\\*",
    "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\AddIns\\*",
    "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\*"
    )
```



### Persistence via Microsoft Outlook VBA

Branch count: 1  
Document count: 1  
Index: geneve-ut-376

```python
file where event.type != "deletion" and
 file.path : "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Outlook\\VbaProject.OTM"
```



### Persistence via Scheduled Job Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-377

```python
file where event.type != "deletion" and
 file.path : "?:\\Windows\\Tasks\\*" and file.extension : "job"
```



### Persistence via TelemetryController Scheduled Task Hijack

Branch count: 2  
Document count: 2  
Index: geneve-ut-378

```python
process where event.type in ("start", "process_started") and
  process.parent.name : "CompatTelRunner.exe" and process.args : "-cv*" and
  not process.name : ("conhost.exe",
                      "DeviceCensus.exe",
                      "CompatTelRunner.exe",
                      "DismHost.exe",
                      "rundll32.exe",
                      "powershell.exe")
```



### Persistence via Update Orchestrator Service Hijack

Branch count: 1  
Document count: 1  
Index: geneve-ut-379

```python
process where event.type == "start" and
  process.parent.executable : "C:\\Windows\\System32\\svchost.exe" and
  process.parent.args : "UsoSvc" and
  not process.executable :
          ("?:\\ProgramData\\Microsoft\\Windows\\UUS\\Packages\\*\\amd64\\MoUsoCoreWorker.exe",
          "?:\\Windows\\System32\\UsoClient.exe",
          "?:\\Windows\\System32\\MusNotification.exe",
          "?:\\Windows\\System32\\MusNotificationUx.exe",
          "?:\\Windows\\System32\\MusNotifyIcon.exe",
          "?:\\Windows\\System32\\WerFault.exe",
          "?:\\Windows\\System32\\WerMgr.exe",
          "?:\\Windows\\UUS\\amd64\\MoUsoCoreWorker.exe",
          "?:\\Windows\\System32\\MoUsoCoreWorker.exe",
          "?:\\Windows\\UUS\\amd64\\UsoCoreWorker.exe",
          "?:\\Windows\\System32\\UsoCoreWorker.exe",
          "?:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\OfficeC2RClient.exe")
```



### Persistence via WMI Event Subscription

Branch count: 8  
Document count: 8  
Index: geneve-ut-380

```python
process where event.type in ("start", "process_started") and
  (process.name : "wmic.exe" or process.pe.original_file_name == "wmic.exe") and
  process.args : "create" and
  process.args : ("ActiveScriptEventConsumer", "CommandLineEventConsumer")
```



### Persistence via WMI Standard Registry Provider

Branch count: 24  
Document count: 24  
Index: geneve-ut-381

```python
registry where 
 registry.data.strings != null and process.name : "WmiPrvSe.exe" and
 registry.path : (
                  "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                  "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                  "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
                  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
                  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
                  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
                  "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
                  "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
                  "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\ServiceDLL",
                  "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\ImagePath",
                  "HKEY_USERS\\*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*", 
                  "HKEY_USERS\\*\\Environment\\UserInitMprLogonScript", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Shell", 
                  "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff\\Script", 
                  "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon\\Script", 
                  "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown\\Script", 
                  "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Startup\\Script", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Ctf\\LangBarAddin\\*\\FilePath", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Exec", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Script", 
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Command Processor\\Autorun"
                  )
```



### Persistent Scripts in the Startup Directory

Branch count: 7  
Document count: 7  
Index: geneve-ut-382

```python
file where event.type != "deletion" and user.domain != "NT AUTHORITY" and

  /* detect shortcuts created by wscript.exe or cscript.exe */
  (file.path : "C:\\*\\Programs\\Startup\\*.lnk" and
     process.name : ("wscript.exe", "cscript.exe")) or

  /* detect vbs or js files created by any process */
  file.path : ("C:\\*\\Programs\\Startup\\*.vbs",
               "C:\\*\\Programs\\Startup\\*.vbe",
               "C:\\*\\Programs\\Startup\\*.wsh",
               "C:\\*\\Programs\\Startup\\*.wsf",
               "C:\\*\\Programs\\Startup\\*.js")
```



### Port Forwarding Rule Addition

Branch count: 1  
Document count: 1  
Index: geneve-ut-383

```python
registry where registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Services\\PortProxy\\v4tov4\\*"
```



### Possible Consent Grant Attack via Azure-Registered Application

Branch count: 18  
Document count: 18  
Index: geneve-ut-384

```python
event.dataset:(azure.activitylogs or azure.auditlogs or o365.audit) and
  (
    azure.activitylogs.operation_name:"Consent to application" or
    azure.auditlogs.operation_name:"Consent to application" or
    o365.audit.Operation:"Consent to application."
  ) and
  event.outcome:(Success or success)
```



### Possible Okta DoS Attack

Branch count: 4  
Document count: 4  
Index: geneve-ut-386

```python
event.dataset:okta.system and event.action:(application.integration.rate_limit_exceeded or system.org.rate_limit.warning or system.org.rate_limit.violation or core.concurrency.org.limit.violation)
```



### Potential Abuse of Repeated MFA Push Notifications

Branch count: 1  
Document count: 3  
Index: geneve-ut-387

```python
sequence by user.email with maxspan=10m
  [any where event.module == "okta" and event.action == "user.mfa.okta_verify.deny_push"]
  [any where event.module == "okta" and event.action == "user.mfa.okta_verify.deny_push"]
  [any where event.module == "okta" and event.action == "user.authentication.sso"]
```



### Potential Admin Group Account Addition

Branch count: 16  
Document count: 16  
Index: geneve-ut-388

```python
event.category:process and event.type:(start or process_started) and
 process.name:(dscl or dseditgroup) and process.args:(("/Groups/admin" or admin) and ("-a" or "-append"))
```



### Potential Application Shimming via Sdbinst

Branch count: 2  
Document count: 2  
Index: geneve-ut-389

```python
process where event.type in ("start", "process_started") and process.name : "sdbinst.exe"
```



### Potential Command and Control via Internet Explorer

Branch count: 2  
Document count: 6  
Index: geneve-ut-390

```python
sequence by host.id, user.name with maxspan = 5s
  [library where dll.name : "IEProxy.dll" and process.name : ("rundll32.exe", "regsvr32.exe")]
  [process where event.type == "start" and process.parent.name : "iexplore.exe" and process.parent.args : "-Embedding"]
  /* IE started via COM in normal conditions makes few connections, mainly to Microsoft and OCSP related domains, add FPs here */
  [network where network.protocol == "dns" and process.name : "iexplore.exe" and
   not dns.question.name :
   (
    "*.microsoft.com",
    "*.digicert.com",
    "*.msocsp.com",
    "*.windowsupdate.com",
    "*.bing.com",
    "*.identrust.com",
    "*.sharepoint.com",
    "*.office365.com",
    "*.office.com"
    )
  ] /* with runs=5 */
```



### Potential Cookies Theft via Browser Debugging

Branch count: 63  
Document count: 63  
Index: geneve-ut-391

```python
process where event.type in ("start", "process_started", "info") and
  process.name in (
             "Microsoft Edge",
             "chrome.exe",
             "Google Chrome",
             "google-chrome-stable",
             "google-chrome-beta",
             "google-chrome",
             "msedge.exe") and
   process.args : ("--remote-debugging-port=*",
                   "--remote-debugging-targets=*",
                   "--remote-debugging-pipe=*") and
   process.args : "--user-data-dir=*" and not process.args:"--remote-debugging-port=0"
```



### Potential Credential Access via DCSync

Branch count: 6  
Document count: 6  
Index: geneve-ut-392

```python
any where event.action == "Directory Service Access" and
  event.code == "4662" and winlog.event_data.Properties : (

    /* Control Access Rights/Permissions Symbol */

    "*DS-Replication-Get-Changes*",
    "*DS-Replication-Get-Changes-All*",
    "*DS-Replication-Get-Changes-In-Filtered-Set*",

    /* Identifying GUID used in ACE */

    "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*",
    "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*",
    "*89e95b76-444d-4c62-991a-0facbeda640c*")

    /* The right to perform an operation controlled by an extended access right. */

    and winlog.event_data.AccessMask : "0x100" and
    not winlog.event_data.SubjectUserName : ("*$", "MSOL_*")
```



### Potential Credential Access via DuplicateHandle in LSASS

Branch count: 1  
Document count: 1  
Index: geneve-ut-393

```python
process where event.code == "10" and

 /* LSASS requesting DuplicateHandle access right to another process */
 process.name : "lsass.exe" and winlog.event_data.GrantedAccess == "0x40" and

 /* call is coming from an unknown executable region */
 winlog.event_data.CallTrace : "*UNKNOWN*"
```



### Potential Credential Access via LSASS Memory Dump

Branch count: 2  
Document count: 2  
Index: geneve-ut-394

```python
process where event.code == "10" and
  winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe" and

   /* DLLs exporting MiniDumpWriteDump API to create an lsass mdmp*/
  winlog.event_data.CallTrace : ("*dbghelp*", "*dbgcore*") and

   /* case of lsass crashing */
  not process.executable : ("?:\\Windows\\System32\\WerFault.exe", "?:\\Windows\\System32\\WerFaultSecure.exe")
```



### Potential Credential Access via Renamed COM+ Services DLL

Branch count: 2  
Document count: 4  
Index: geneve-ut-395

```python
sequence by process.entity_id with maxspan=1m
 [process where event.category == "process" and
    process.name : "rundll32.exe"]
 [process where event.category == "process" and event.dataset : "windows.sysmon_operational" and event.code == "7" and
   (file.pe.original_file_name : "COMSVCS.DLL" or file.pe.imphash : "EADBCCBB324829ACB5F2BBE87E5549A8") and
    /* renamed COMSVCS */
    not file.name : "COMSVCS.DLL"]
```



### Potential Credential Access via Trusted Developer Utility

Branch count: 16  
Document count: 32  
Index: geneve-ut-396

```python
sequence by process.entity_id
 [process where event.type == "start" and (process.name : "MSBuild.exe" or process.pe.original_file_name == "MSBuild.exe")]
 [any where (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
  (dll.name : ("vaultcli.dll", "SAMLib.DLL") or file.name : ("vaultcli.dll", "SAMLib.DLL"))]
```



### Potential DLL Side-Loading via Microsoft Antimalware Service Executable

Branch count: 2  
Document count: 2  
Index: geneve-ut-398

```python
process where event.type == "start" and
  (process.pe.original_file_name == "MsMpEng.exe" and not process.name : "MsMpEng.exe") or
  (process.name : "MsMpEng.exe" and not
        process.executable : ("?:\\ProgramData\\Microsoft\\Windows Defender\\*.exe",
                              "?:\\Program Files\\Windows Defender\\*.exe",
                              "?:\\Program Files (x86)\\Windows Defender\\*.exe",
                              "?:\\Program Files\\Microsoft Security Client\\*.exe",
                              "?:\\Program Files (x86)\\Microsoft Security Client\\*.exe"))
```



### Potential DLL SideLoading via Trusted Microsoft Programs

Branch count: 4  
Document count: 4  
Index: geneve-ut-399

```python
process where event.type == "start" and
  process.pe.original_file_name in ("WinWord.exe", "EXPLORER.EXE", "w3wp.exe", "DISM.EXE") and
  not (process.name : ("winword.exe", "explorer.exe", "w3wp.exe", "Dism.exe") or
         process.executable : ("?:\\Windows\\explorer.exe",
                               "?:\\Program Files\\Microsoft Office\\root\\Office*\\WINWORD.EXE",
                               "?:\\Program Files?(x86)\\Microsoft Office\\root\\Office*\\WINWORD.EXE",
                               "?:\\Windows\\System32\\Dism.exe",
                               "?:\\Windows\\SysWOW64\\Dism.exe",
                               "?:\\Windows\\System32\\inetsrv\\w3wp.exe")
         )
```



### Potential DNS Tunneling via Iodine

Branch count: 4  
Document count: 4  
Index: geneve-ut-400

```python
event.category:process and event.type:(start or process_started) and process.name:(iodine or iodined)
```



### Potential Disabling of SELinux

Branch count: 2  
Document count: 2  
Index: geneve-ut-402

```python
event.category:process and event.type:(start or process_started) and process.name:setenforce and process.args:0
```



### Potential Evasion via Filter Manager

Branch count: 2  
Document count: 2  
Index: geneve-ut-403

```python
process where event.type in ("start", "process_started") and
 process.name : "fltMC.exe" and process.args : "unload"
```



### Potential Hidden Local User Account Creation

Branch count: 6  
Document count: 6  
Index: geneve-ut-404

```python
event.category:process and event.type:(start or process_started) and
 process.name:dscl and process.args:(IsHidden and create and (true or 1 or yes))
```



### Potential JAVA/JNDI Exploitation Attempt

Branch count: 60  
Document count: 120  
Index: geneve-ut-406

```python
sequence by host.id with maxspan=1m
 [network where event.action == "connection_attempted" and
  process.name : "java" and
  /*
     outbound connection attempt to
     LDAP, RMI or DNS standard ports
     by JAVA process
   */
  destination.port in (1389, 389, 1099, 53, 5353)] by process.pid
 [process where event.type == "start" and

  /* Suspicious JAVA child process */
  process.parent.name : "java" and
   process.name : ("sh",
                   "bash",
                   "dash",
                   "ksh",
                   "tcsh",
                   "zsh",
                   "curl",
                   "perl*",
                   "python*",
                   "ruby*",
                   "php*",
                   "wget")] by process.parent.pid
```



### Potential Kerberos Attack via Bifrost

Branch count: 8  
Document count: 8  
Index: geneve-ut-407

```python
event.category:process and event.type:start and 
 process.args:("-action" and ("-kerberoast" or askhash or asktgs or asktgt or s4u or ("-ticket" and ptt) or (dump and (tickets or keytab))))
```



### Potential LSA Authentication Package Abuse

Branch count: 1  
Document count: 1  
Index: geneve-ut-408

```python
registry where event.type == "change" and
  registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Authentication Packages" and
  /* exclude SYSTEM SID - look for changes by non-SYSTEM user */
  not user.id : "S-1-5-18"
```



### Potential LSASS Clone Creation via PssCaptureSnapShot

Branch count: 1  
Document count: 1  
Index: geneve-ut-409

```python
process where event.code:"4688" and
  process.executable : "?:\\Windows\\System32\\lsass.exe" and
  process.parent.executable : "?:\\Windows\\System32\\lsass.exe"
```



### Potential Lateral Tool Transfer via SMB Share

Branch count: 16  
Document count: 32  
Index: geneve-ut-411

```python
sequence by host.id with maxspan=30s
  [network where event.type == "start" and process.pid == 4 and destination.port == 445 and
   network.direction : ("incoming", "ingress") and
   network.transport == "tcp" and source.ip != "127.0.0.1" and source.ip != "::1"
  ] by process.entity_id
  /* add more executable extensions here if they are not noisy in your environment */
  [file where event.type in ("creation", "change") and process.pid == 4 and file.extension : ("exe", "dll", "bat", "cmd")] by process.entity_id
```



### Potential Local NTLM Relay via HTTP

Branch count: 12  
Document count: 12  
Index: geneve-ut-412

```python
process where event.type in ("start", "process_started") and
  process.name : "rundll32.exe" and

  /* Rundll32 WbeDav Client  */
  process.args : ("?:\\Windows\\System32\\davclnt.dll,DavSetCookie", "?:\\Windows\\SysWOW64\\davclnt.dll,DavSetCookie") and 

  /* Access to named pipe via http */
  process.args : ("http*/print/pipe/*", "http*/pipe/spoolss", "http*/pipe/srvsvc")
```



### Potential Microsoft Office Sandbox Evasion

Branch count: 1  
Document count: 1  
Index: geneve-ut-413

```python
event.category:file and not event.type:deletion and file.name:~$*.zip and host.os.type:macos
```



### Potential Modification of Accessibility Binaries

Branch count: 48  
Document count: 48  
Index: geneve-ut-414

```python
process where event.type in ("start", "process_started", "info") and
 process.parent.name : ("Utilman.exe", "winlogon.exe") and user.name == "SYSTEM" and
 process.args :
    (
    "C:\\Windows\\System32\\osk.exe",
    "C:\\Windows\\System32\\Magnify.exe",
    "C:\\Windows\\System32\\Narrator.exe",
    "C:\\Windows\\System32\\Sethc.exe",
    "utilman.exe",
    "ATBroker.exe",
    "DisplaySwitch.exe",
    "sethc.exe"
    )
 and not process.pe.original_file_name in
    (
    "osk.exe",
    "sethc.exe",
    "utilman2.exe",
    "DisplaySwitch.exe",
    "ATBroker.exe",
    "ScreenMagnifier.exe",
    "SR.exe",
    "Narrator.exe",
    "magnify.exe",
    "MAGNIFY.EXE"
    )

/* uncomment once in winlogbeat to avoid bypass with rogue process with matching pe original file name */
/* and process.code_signature.subject_name == "Microsoft Windows" and process.code_signature.status == "trusted" */
```



### Potential OpenSSH Backdoor Logging Activity

Branch count: 84  
Document count: 84  
Index: geneve-ut-415

```python
file where event.type == "change" and process.executable : ("/usr/sbin/sshd", "/usr/bin/ssh") and
  (
    (file.name : (".*", "~*", "*~") and not file.name : (".cache", ".viminfo", ".bash_history")) or
    file.extension : ("in", "out", "ini", "h", "gz", "so", "sock", "sync", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9") or
    file.path :
    (
      "/private/etc/*--",
      "/usr/share/*",
      "/usr/include/*",
      "/usr/local/include/*",
      "/private/tmp/*",
      "/private/var/tmp/*",
      "/usr/tmp/*",
      "/usr/share/man/*",
      "/usr/local/share/*",
      "/usr/lib/*.so.*",
      "/private/etc/ssh/.sshd_auth",
      "/usr/bin/ssd",
      "/private/var/opt/power",
      "/private/etc/ssh/ssh_known_hosts",
      "/private/var/html/lol",
      "/private/var/log/utmp",
      "/private/var/lib",
      "/var/run/sshd/sshd.pid",
      "/var/run/nscd/ns.pid",
      "/var/run/udev/ud.pid",
      "/var/run/udevd.pid"
    )
  )
```



### Potential Persistence via Atom Init Script Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-417

```python
event.category:"file" and not event.type:"deletion" and
 file.path:/Users/*/.atom/init.coffee and not process.name:(Atom or xpcproxy) and not user.name:root
```



### Potential Persistence via Login Hook

Branch count: 1  
Document count: 1  
Index: geneve-ut-418

```python
event.category:"file" and not event.type:"deletion" and
 file.name:"com.apple.loginwindow.plist" and
 process.name:(* and not (systemmigrationd or DesktopServicesHelper or diskmanagementd or rsync or launchd or cfprefsd or xpcproxy or ManagedClient or MCXCompositor or backupd or "iMazing Profile Editor"
))
```



### Potential Persistence via Periodic Tasks

Branch count: 3  
Document count: 3  
Index: geneve-ut-419

```python
event.category:"file" and not event.type:"deletion" and
 file.path:(/private/etc/periodic/* or /private/etc/defaults/periodic.conf or /private/etc/periodic.conf)
```



### Potential Persistence via Time Provider Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-420

```python
registry where event.type:"change" and
  registry.path:"HKLM\\SYSTEM\\*ControlSet*\\Services\\W32Time\\TimeProviders\\*" and
  registry.data.strings:"*.dll"
```



### Potential Port Monitor or Print Processor Registration Abuse

Branch count: 4  
Document count: 4  
Index: geneve-ut-421

```python
registry where event.type in ("creation", "change") and
  registry.path : ("HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Monitors\\*",
    "HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Environments\\Windows*\\Print Processors\\*") and
  registry.data.strings : "*.dll" and
  /* exclude SYSTEM SID - look for changes by non-SYSTEM user */
  not user.id : "S-1-5-18"
```



### Potential Privacy Control Bypass via Localhost Secure Copy

Branch count: 4  
Document count: 4  
Index: geneve-ut-422

```python
process where event.type in ("start", "process_started") and
 process.name:"scp" and
 process.args:"StrictHostKeyChecking=no" and
 process.command_line:("scp *localhost:/*", "scp *127.0.0.1:/*") and
 not process.args:"vagrant@*127.0.0.1*"
```



### Potential Privacy Control Bypass via TCCDB Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-423

```python
process where event.type in ("start", "process_started") and process.name : "sqlite*" and
 process.args : "/*/Application Support/com.apple.TCC/TCC.db" and
 not process.parent.executable : "/Library/Bitdefender/AVP/product/bin/*"
```



### Potential Privilege Escalation via InstallerFileTakeOver

Branch count: 8  
Document count: 8  
Index: geneve-ut-424

```python
/* This rule is compatible with both Sysmon and Elastic Endpoint */

process where event.type == "start" and
    (?process.Ext.token.integrity_level_name : "System" or
    ?winlog.event_data.IntegrityLevel : "System") and
    (
      (process.name : "elevation_service.exe" and
       not process.pe.original_file_name == "elevation_service.exe") or

      (process.parent.name : "elevation_service.exe" and
       process.name : ("rundll32.exe", "cmd.exe", "powershell.exe"))
    )
```



### Potential Privilege Escalation via PKEXEC

Branch count: 1  
Document count: 1  
Index: geneve-ut-425

```python
file where file.path : "/*GCONV_PATH*"
```



### Potential Privilege Escalation via Sudoers File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-426

```python
event.category:process and event.type:start and process.args:(echo and *NOPASSWD*ALL*)
```



### Potential Privileged Escalation via SamAccountName Spoofing

Branch count: 1  
Document count: 1  
Index: geneve-ut-427

```python
iam where event.action == "renamed-user-account" and
  /* machine account name renamed to user like account name */
  winlog.event_data.OldTargetUserName : "*$" and not winlog.event_data.NewTargetUserName : "*$"
```



### Potential Process Herpaderping Attempt

Branch count: 1  
Document count: 2  
Index: geneve-ut-428

```python
sequence with maxspan=5s
   [process where event.type == "start" and not process.parent.executable : "C:\\Windows\\SoftwareDistribution\\*.exe"] by host.id, process.executable, process.parent.entity_id
   [file where event.type == "change" and event.action == "overwrite" and file.extension == "exe"] by host.id, file.path, process.entity_id
```



### Potential Protocol Tunneling via EarthWorm

Branch count: 1  
Document count: 1  
Index: geneve-ut-430

```python
process where event.type == "start" and
 process.args : "-s" and process.args : "-d" and process.args : "rssocks"
```



### Potential Remote Credential Access via Registry

Branch count: 1  
Document count: 2  
Index: geneve-ut-431

```python
sequence by host.id, user.id with maxspan=1m
 [authentication where
   event.outcome == "success" and event.action == "logged-in" and
   winlog.logon.type == "Network" and not user.name == "ANONYMOUS LOGON" and
   not user.domain == "NT AUTHORITY" and source.ip != "127.0.0.1" and source.ip !="::1"]
 [file where event.action == "creation" and process.name : "svchost.exe" and
  file.Ext.header_bytes : "72656766*" and user.id : "S-1-5-21-*" and file.size >= 30000 and
  not file.path :
           ("?:\\Windows\\system32\\HKEY_LOCAL_MACHINE_SOFTWARE_Microsoft_*.registry",
            "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG?",
            "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat",
            "?:\\Users\\*\\ntuser.dat.LOG?",
            "?:\\Users\\*\\NTUSER.DAT")]
```



### Potential Remote Desktop Shadowing Activity

Branch count: 4  
Document count: 4  
Index: geneve-ut-432

```python
/* Identifies the modification of RDP Shadow registry or
  the execution of processes indicative of active shadow RDP session */

any where
  (event.category == "registry" and
     registry.path : "HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\Shadow"
  ) or
  (event.category == "process" and
     (process.name : ("RdpSaUacHelper.exe", "RdpSaProxy.exe") and process.parent.name : "svchost.exe") or
     (process.pe.original_file_name : "mstsc.exe" and process.args : "/shadow:*")
  )
```



### Potential Remote Desktop Tunneling Detected

Branch count: 10  
Document count: 10  
Index: geneve-ut-433

```python
process where event.type in ("start", "process_started") and
  /* RDP port and usual SSH tunneling related switches in command line */
  process.args : "*:3389" and
  process.args : ("-L", "-P", "-R", "-pw", "-ssh")
```



### Potential Reverse Shell Activity via Terminal

Branch count: 80  
Document count: 80  
Index: geneve-ut-434

```python
process where event.type in ("start", "process_started") and
  process.name in ("sh", "bash", "zsh", "dash", "zmodload") and
  process.args : ("*/dev/tcp/*", "*/dev/udp/*", "*zsh/net/tcp*", "*zsh/net/udp*") and

  /* noisy FPs */
  not (process.parent.name : "timeout" and process.executable : "/var/lib/docker/overlay*") and
  not process.command_line : ("*/dev/tcp/sirh_db/*", "*/dev/tcp/remoteiot.com/*", "*dev/tcp/elk.stag.one/*", "*dev/tcp/kafka/*", "*/dev/tcp/$0/$1*", "*/dev/tcp/127.*", "*/dev/udp/127.*", "*/dev/tcp/localhost/*") and
  not process.parent.command_line : "runc init"
```



### Potential Secure File Deletion via SDelete Utility

Branch count: 1  
Document count: 1  
Index: geneve-ut-436

```python
file where event.type == "change" and file.name : "*AAA.AAA"
```



### Potential Shadow Credentials added to AD Object

Branch count: 1  
Document count: 1  
Index: geneve-ut-437

```python
event.action:"Directory Service Changes" and event.code:"5136" and winlog.event_data.AttributeLDAPDisplayName:"msDS-KeyCredentialLink"
```



### Potential SharpRDP Behavior

Branch count: 64  
Document count: 192  
Index: geneve-ut-438

```python
/* Incoming RDP followed by a new RunMRU string value set to cmd, powershell, taskmgr or tsclient, followed by process execution within 1m */

sequence by host.id with maxspan=1m
  [network where event.type == "start" and process.name : "svchost.exe" and destination.port == 3389 and 
   network.direction : ("incoming", "ingress") and network.transport == "tcp" and
   source.ip != "127.0.0.1" and source.ip != "::1"
  ]

  [registry where process.name : "explorer.exe" and 
   registry.path : ("HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\*") and
   registry.data.strings : ("cmd.exe*", "powershell.exe*", "taskmgr*", "\\\\tsclient\\*.exe\\*")
  ]

  [process where event.type in ("start", "process_started") and
   (process.parent.name : ("cmd.exe", "powershell.exe", "taskmgr.exe") or process.args : ("\\\\tsclient\\*.exe")) and 
   not process.name : "conhost.exe"
   ]
```



### Potential Windows Error Manager Masquerading

Branch count: 8  
Document count: 16  
Index: geneve-ut-440

```python
sequence by host.id, process.entity_id with maxspan = 5s
  [process where event.type:"start" and process.name : ("wermgr.exe", "WerFault.exe") and process.args_count == 1]
  [network where process.name : ("wermgr.exe", "WerFault.exe") and network.protocol != "dns" and
    network.direction : ("outgoing", "egress") and destination.ip !="::1" and destination.ip !="127.0.0.1"
  ]
```



### PowerShell Kerberos Ticket Request

Branch count: 1  
Document count: 1  
Index: geneve-ut-441

```python
event.category:process and
  powershell.file.script_block_text : (
    KerberosRequestorSecurityToken
  )
```



### PowerShell MiniDump Script

Branch count: 3  
Document count: 3  
Index: geneve-ut-443

```python
event.category:process and powershell.file.script_block_text:(MiniDumpWriteDump or MiniDumpWithFullMemory or pmuDetirWpmuDiniM)
```



### PowerShell PSReflect Script

Branch count: 9  
Document count: 9  
Index: geneve-ut-444

```python
event.category:process and
  powershell.file.script_block_text:(
    "New-InMemoryModule" or
    "Add-Win32Type" or
    psenum or
    DefineDynamicAssembly or
    DefineDynamicModule or
    "Reflection.TypeAttributes" or
    "Reflection.Emit.OpCodes" or
    "Reflection.Emit.CustomAttributeBuilder" or
    "Runtime.InteropServices.DllImportAttribute"
  )
```



### PowerShell Script Block Logging Disabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-445

```python
registry where event.type == "change" and
    registry.path :
        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging"
    and registry.data.strings : ("0", "0x00000000")
```



### PowerShell Suspicious Discovery Related Windows API Functions

Branch count: 11  
Document count: 11  
Index: geneve-ut-446

```python
event.category:process and
  powershell.file.script_block_text : (
    NetShareEnum or
    NetWkstaUserEnum or
    NetSessionEnum or
    NetLocalGroupEnum or
    NetLocalGroupGetMembers or
    DsGetSiteName or
    DsEnumerateDomainTrusts or
    WTSEnumerateSessionsEx or
    WTSQuerySessionInformation or
    LsaGetLogonSessionData or
    QueryServiceObjectSecurity
  )
```



### Privilege Escalation via Named Pipe Impersonation

Branch count: 4  
Document count: 4  
Index: geneve-ut-450

```python
process where event.type in ("start", "process_started") and
 process.pe.original_file_name in ("Cmd.Exe", "PowerShell.EXE") and
 process.args : "echo" and process.args : ">" and process.args : "\\\\.\\pipe\\*"
```



### Privilege Escalation via Rogue Named Pipe Impersonation

Branch count: 1  
Document count: 1  
Index: geneve-ut-451

```python
file where event.action : "Pipe Created*" and
 /* normal sysmon named pipe creation events truncate the pipe keyword */
  file.name : "\\*\\Pipe\\*"
```



### Privilege Escalation via Root Crontab File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-452

```python
event.category:file and not event.type:deletion and
 file.path:/private/var/at/tabs/root and not process.executable:/usr/bin/crontab
```



### Privilege Escalation via Windir Environment Variable

Branch count: 2  
Document count: 2  
Index: geneve-ut-453

```python
registry where registry.path : ("HKEY_USERS\\*\\Environment\\windir", "HKEY_USERS\\*\\Environment\\systemroot") and 
 not registry.data.strings : ("C:\\windows", "%SystemRoot%")
```



### Process Activity via Compiled HTML File

Branch count: 14  
Document count: 14  
Index: geneve-ut-454

```python
process where event.type in ("start", "process_started") and
 process.parent.name : "hh.exe" and
 process.name : ("mshta.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cscript.exe", "wscript.exe")
```



### Process Execution from an Unusual Directory

Branch count: 198  
Document count: 198  
Index: geneve-ut-455

```python
process where event.type in ("start", "process_started", "info") and
 /* add suspicious execution paths here */
process.executable : ("C:\\PerfLogs\\*.exe","C:\\Users\\Public\\*.exe","C:\\Windows\\Tasks\\*.exe","C:\\Intel\\*.exe","C:\\AMD\\Temp\\*.exe","C:\\Windows\\AppReadiness\\*.exe",
"C:\\Windows\\ServiceState\\*.exe","C:\\Windows\\security\\*.exe","C:\\Windows\\IdentityCRL\\*.exe","C:\\Windows\\Branding\\*.exe","C:\\Windows\\csc\\*.exe",
 "C:\\Windows\\DigitalLocker\\*.exe","C:\\Windows\\en-US\\*.exe","C:\\Windows\\wlansvc\\*.exe","C:\\Windows\\Prefetch\\*.exe","C:\\Windows\\Fonts\\*.exe",
 "C:\\Windows\\diagnostics\\*.exe","C:\\Windows\\TAPI\\*.exe","C:\\Windows\\INF\\*.exe","C:\\Windows\\System32\\Speech\\*.exe","C:\\windows\\tracing\\*.exe",
 "c:\\windows\\IME\\*.exe","c:\\Windows\\Performance\\*.exe","c:\\windows\\intel\\*.exe","c:\\windows\\ms\\*.exe","C:\\Windows\\dot3svc\\*.exe",
 "C:\\Windows\\panther\\*.exe","C:\\Windows\\RemotePackages\\*.exe","C:\\Windows\\OCR\\*.exe","C:\\Windows\\appcompat\\*.exe","C:\\Windows\\apppatch\\*.exe","C:\\Windows\\addins\\*.exe",
 "C:\\Windows\\Setup\\*.exe","C:\\Windows\\Help\\*.exe","C:\\Windows\\SKB\\*.exe","C:\\Windows\\Vss\\*.exe","C:\\Windows\\Web\\*.exe","C:\\Windows\\servicing\\*.exe","C:\\Windows\\CbsTemp\\*.exe",
 "C:\\Windows\\Logs\\*.exe","C:\\Windows\\WaaS\\*.exe","C:\\Windows\\ShellExperiences\\*.exe","C:\\Windows\\ShellComponents\\*.exe","C:\\Windows\\PLA\\*.exe",
 "C:\\Windows\\Migration\\*.exe","C:\\Windows\\debug\\*.exe","C:\\Windows\\Cursors\\*.exe","C:\\Windows\\Containers\\*.exe","C:\\Windows\\Boot\\*.exe","C:\\Windows\\bcastdvr\\*.exe",
 "C:\\Windows\\assembly\\*.exe","C:\\Windows\\TextInput\\*.exe","C:\\Windows\\security\\*.exe","C:\\Windows\\schemas\\*.exe","C:\\Windows\\SchCache\\*.exe","C:\\Windows\\Resources\\*.exe",
 "C:\\Windows\\rescache\\*.exe","C:\\Windows\\Provisioning\\*.exe","C:\\Windows\\PrintDialog\\*.exe","C:\\Windows\\PolicyDefinitions\\*.exe","C:\\Windows\\media\\*.exe",
 "C:\\Windows\\Globalization\\*.exe","C:\\Windows\\L2Schemas\\*.exe","C:\\Windows\\LiveKernelReports\\*.exe","C:\\Windows\\ModemLogs\\*.exe","C:\\Windows\\ImmersiveControlPanel\\*.exe") and
 not process.name : ("SpeechUXWiz.exe","SystemSettings.exe","TrustedInstaller.exe","PrintDialog.exe","MpSigStub.exe","LMS.exe","mpam-*.exe") and
 not process.executable :
           ("?:\\Intel\\Wireless\\WUSetupLauncher.exe",
            "?:\\Intel\\Wireless\\Setup.exe",
            "?:\\Intel\\Move Mouse.exe",
            "?:\\windows\\Panther\\DiagTrackRunner.exe",
            "?:\\Windows\\servicing\\GC64\\tzupd.exe",
            "?:\\Users\\Public\\res\\RemoteLite.exe",
            "?:\\Users\\Public\\IBM\\ClientSolutions\\*.exe",
            "?:\\Users\\Public\\Documents\\syspin.exe",
            "?:\\Users\\Public\\res\\FileWatcher.exe")
 /* uncomment once in winlogbeat */
 /* and not (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true) */
```



### Process Injection - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-456

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:kernel_shellcode_event or endgame.event_subtype_full:kernel_shellcode_event)
```



### Process Injection - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-457

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:kernel_shellcode_event or endgame.event_subtype_full:kernel_shellcode_event)
```



### Process Injection by the Microsoft Build Engine

Branch count: 1  
Document count: 1  
Index: geneve-ut-458

```python
process.name:MSBuild.exe and event.action:"CreateRemoteThread detected (rule: CreateRemoteThread)"
```



### Process Termination followed by Deletion

Branch count: 3  
Document count: 6  
Index: geneve-ut-460

```python
sequence by host.id with maxspan=5s
   [process where event.type == "end" and 
    process.code_signature.trusted == false and
    not process.executable : ("C:\\Windows\\SoftwareDistribution\\*.exe", "C:\\Windows\\WinSxS\\*.exe")
   ] by process.executable
   [file where event.type == "deletion" and file.extension : ("exe", "scr", "com") and
    not process.executable :
             ("?:\\Program Files\\*.exe",
              "?:\\Program Files (x86)\\*.exe",
              "?:\\Windows\\System32\\svchost.exe",
              "?:\\Windows\\System32\\drvinst.exe") and
    not file.path : ("?:\\Program Files\\*.exe", "?:\\Program Files (x86)\\*.exe")
   ] by file.path
```



### Program Files Directory Masquerading

Branch count: 1  
Document count: 1  
Index: geneve-ut-461

```python
process where event.type == "start" and
 process.executable : "C:\\*Program*Files*\\*.exe" and
 not process.executable : ("C:\\Program Files\\*.exe", "C:\\Program Files (x86)\\*.exe", "C:\\Users\\*.exe", "C:\\ProgramData\\*.exe")
```



### Prompt for Credentials with OSASCRIPT

Branch count: 2  
Document count: 2  
Index: geneve-ut-462

```python
process where event.type in ("start", "process_started") and process.name : "osascript" and
 process.command_line : "osascript*display dialog*password*"
```



### PsExec Network Connection

Branch count: 1  
Document count: 2  
Index: geneve-ut-463

```python
sequence by process.entity_id
  [process where process.name : "PsExec.exe" and event.type == "start" and

   /* This flag suppresses the display of the license dialog and may
      indicate that psexec executed for the first time in the machine */
   process.args : "-accepteula" and

   not process.executable : ("?:\\ProgramData\\Docusnap\\Discovery\\discovery\\plugins\\17\\Bin\\psexec.exe",
                             "?:\\Docusnap 11\\Bin\\psexec.exe",
                             "?:\\Program Files\\Docusnap X\\Bin\\psexec.exe",
                             "?:\\Program Files\\Docusnap X\\Tools\\dsDNS.exe") and
   not process.parent.executable : "?:\\Program Files (x86)\\Cynet\\Cynet Scanner\\CynetScanner.exe"]
  [network where process.name : "PsExec.exe"]
```



### RDP (Remote Desktop Protocol) from the Internet

Branch count: 12  
Document count: 12  
Index: geneve-ut-464

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:3389 or event.dataset:zeek.rdp) and
  not source.ip:(
    10.0.0.0/8 or
    127.0.0.0/8 or
    169.254.0.0/16 or
    172.16.0.0/12 or
    192.0.0.0/24 or
    192.0.0.0/29 or
    192.0.0.8/32 or
    192.0.0.9/32 or
    192.0.0.10/32 or
    192.0.0.170/32 or
    192.0.0.171/32 or
    192.0.2.0/24 or
    192.31.196.0/24 or
    192.52.193.0/24 or
    192.168.0.0/16 or
    192.88.99.0/24 or
    224.0.0.0/4 or
    100.64.0.0/10 or
    192.175.48.0/24 or
    198.18.0.0/15 or
    198.51.100.0/24 or
    203.0.113.0/24 or
    240.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  ) and
  destination.ip:(
    10.0.0.0/8 or
    172.16.0.0/12 or
    192.168.0.0/16
  )
```



### RDP Enabled via Registry

Branch count: 8  
Document count: 8  
Index: geneve-ut-465

```python
registry where event.type in ("creation", "change") and
  registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Control\\Terminal Server\\fDenyTSConnections" and
  registry.data.strings : ("0", "0x00000000") and not (process.name : "svchost.exe" and user.domain == "NT AUTHORITY") and
  not process.executable : "C:\\Windows\\System32\\SystemPropertiesRemote.exe"
```



### RPC (Remote Procedure Call) from the Internet

Branch count: 12  
Document count: 12  
Index: geneve-ut-466

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:135 or event.dataset:zeek.dce_rpc) and
  not source.ip:(
    10.0.0.0/8 or
    127.0.0.0/8 or
    169.254.0.0/16 or
    172.16.0.0/12 or
    192.0.0.0/24 or
    192.0.0.0/29 or
    192.0.0.8/32 or
    192.0.0.9/32 or
    192.0.0.10/32 or
    192.0.0.170/32 or
    192.0.0.171/32 or
    192.0.2.0/24 or
    192.31.196.0/24 or
    192.52.193.0/24 or
    192.168.0.0/16 or
    192.88.99.0/24 or
    224.0.0.0/4 or
    100.64.0.0/10 or
    192.175.48.0/24 or
    198.18.0.0/15 or
    198.51.100.0/24 or
    203.0.113.0/24 or
    240.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  ) and
  destination.ip:(
    10.0.0.0/8 or
    172.16.0.0/12 or
    192.168.0.0/16
  )
```



### RPC (Remote Procedure Call) to the Internet

Branch count: 12  
Document count: 12  
Index: geneve-ut-467

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:135 or event.dataset:zeek.dce_rpc) and
  source.ip:(
    10.0.0.0/8 or
    172.16.0.0/12 or
    192.168.0.0/16
  ) and
  not destination.ip:(
    10.0.0.0/8 or
    127.0.0.0/8 or
    169.254.0.0/16 or
    172.16.0.0/12 or
    192.0.0.0/24 or
    192.0.0.0/29 or
    192.0.0.8/32 or
    192.0.0.9/32 or
    192.0.0.10/32 or
    192.0.0.170/32 or
    192.0.0.171/32 or
    192.0.2.0/24 or
    192.31.196.0/24 or
    192.52.193.0/24 or
    192.168.0.0/16 or
    192.88.99.0/24 or
    224.0.0.0/4 or
    100.64.0.0/10 or
    192.175.48.0/24 or
    198.18.0.0/15 or
    198.51.100.0/24 or
    203.0.113.0/24 or
    240.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  )
```



### Ransomware - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-468

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:ransomware_event or endgame.event_subtype_full:ransomware_event)
```



### Ransomware - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-469

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:ransomware_event or endgame.event_subtype_full:ransomware_event)
```



### Registry Persistence via AppCert DLL

Branch count: 1  
Document count: 1  
Index: geneve-ut-472

```python
registry where
/* uncomment once stable length(bytes_written_string) > 0 and */
  registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Control\\Session Manager\\AppCertDLLs\\*"
```



### Registry Persistence via AppInit DLL

Branch count: 2  
Document count: 2  
Index: geneve-ut-473

```python
registry where
   registry.path : ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls",
                    "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls") and
   not process.executable : ("C:\\Windows\\System32\\msiexec.exe",
                             "C:\\Windows\\SysWOW64\\msiexec.exe",
                             "C:\\Program Files\\Commvault\\ContentStore*\\Base\\cvd.exe",
                             "C:\\Program Files (x86)\\Commvault\\ContentStore*\\Base\\cvd.exe")
```



### Remote Computer Account DnsHostName Update

Branch count: 1  
Document count: 2  
Index: geneve-ut-474

```python
sequence by host.id with maxspan=5m

  [authentication where event.action == "logged-in" and
   winlog.logon.type == "Network" and event.outcome == "success" and
   not user.name == "ANONYMOUS LOGON" and not winlog.event_data.SubjectUserName : "*$" and
   not user.domain == "NT AUTHORITY" and source.ip != "127.0.0.1" and source.ip !="::1"] by winlog.event_data.TargetLogonId

  [iam where event.action == "changed-computer-account" and

   /* if DnsHostName value equal a DC DNS hostname then it's highly suspicious */
    winlog.event_data.DnsHostName : "??*"] by winlog.event_data.SubjectLogonId
```



### Remote Desktop Enabled in Windows Firewall by Netsh

Branch count: 36  
Document count: 36  
Index: geneve-ut-475

```python
process where event.type in ("start", "process_started") and
 (process.name : "netsh.exe" or process.pe.original_file_name == "netsh.exe") and
 process.args : ("localport=3389", "RemoteDesktop", "group=\"remote desktop\"") and
 process.args : ("action=allow", "enable=Yes", "enable")
```



### Remote Execution via File Shares

Branch count: 4  
Document count: 8  
Index: geneve-ut-476

```python
sequence with maxspan=1m
  [file where event.type in ("creation", "change") and process.pid == 4 and file.extension : "exe"] by host.id, file.path
  [process where event.type in ("start", "process_started")] by host.id, process.executable
```



### Remote File Copy to a Hidden Share

Branch count: 32  
Document count: 32  
Index: geneve-ut-477

```python
process where event.type in ("start", "process_started") and
  process.name : ("cmd.exe", "powershell.exe", "robocopy.exe", "xcopy.exe") and
  process.args : ("copy*", "move*", "cp", "mv") and process.args : "*$*"
```



### Remote File Copy via TeamViewer

Branch count: 11  
Document count: 11  
Index: geneve-ut-478

```python
file where event.type == "creation" and process.name : "TeamViewer.exe" and
  file.extension : ("exe", "dll", "scr", "com", "bat", "ps1", "vbs", "vbe", "js", "wsh", "hta")
```



### Remote File Download via Desktopimgdownldr Utility

Branch count: 4  
Document count: 4  
Index: geneve-ut-479

```python
process where event.type in ("start", "process_started") and
  (process.name : "desktopimgdownldr.exe" or process.pe.original_file_name == "desktopimgdownldr.exe") and
  process.args : "/lockscreenurl:http*"
```



### Remote File Download via MpCmdRun

Branch count: 2  
Document count: 2  
Index: geneve-ut-480

```python
process where event.type == "start" and
  (process.name : "MpCmdRun.exe" or process.pe.original_file_name == "MpCmdRun.exe") and
   process.args : "-DownloadFile" and process.args : "-url" and process.args : "-path"
```



### Remote File Download via PowerShell

Branch count: 12  
Document count: 24  
Index: geneve-ut-481

```python
sequence by host.id, process.entity_id with maxspan=30s
  [network where process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and network.protocol == "dns" and
   not dns.question.name : ("localhost", "*.microsoft.com", "*.azureedge.net", "*.powershellgallery.com", "*.windowsupdate.com", "metadata.google.internal") and 
   not user.domain : "NT AUTHORITY"]
    [file where process.name : "powershell.exe" and event.type == "creation" and file.extension : ("exe", "dll", "ps1", "bat") and 
   not file.name : "__PSScriptPolicy*.ps1"]
```



### Remote File Download via Script Interpreter

Branch count: 8  
Document count: 16  
Index: geneve-ut-482

```python
sequence by host.id, process.entity_id
  [network where process.name : ("wscript.exe", "cscript.exe") and network.protocol != "dns" and
   network.direction : ("outgoing", "egress") and network.type == "ipv4" and destination.ip != "127.0.0.1"
  ]
  [file where event.type == "creation" and file.extension : ("exe", "dll")]
```



### Remote SSH Login Enabled via systemsetup Command

Branch count: 2  
Document count: 2  
Index: geneve-ut-483

```python
event.category:process and event.type:(start or process_started) and
 process.name:systemsetup and
 process.args:("-setremotelogin" and on) and
 not process.parent.executable : /usr/local/jamf/bin/jamf
```



### Remote Scheduled Task Creation

Branch count: 2  
Document count: 4  
Index: geneve-ut-484

```python
/* Task Scheduler service incoming connection followed by TaskCache registry modification  */

sequence by host.id, process.entity_id with maxspan = 1m
   [network where process.name : "svchost.exe" and
   network.direction : ("incoming", "ingress") and source.port >= 49152 and destination.port >= 49152 and
   source.ip != "127.0.0.1" and source.ip != "::1"
   ]
   [registry where registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions"]
```



### Remote System Discovery Commands

Branch count: 6  
Document count: 6  
Index: geneve-ut-485

```python
process where event.type in ("start", "process_started") and
  ((process.name : "nbtstat.exe" and process.args : ("-n", "-s")) or
  (process.name : "arp.exe" and process.args : "-a"))
```



### Remotely Started Services via RPC

Branch count: 16  
Document count: 32  
Index: geneve-ut-486

```python
sequence with maxspan=1s
   [network where process.name : "services.exe" and
      network.direction : ("incoming", "ingress") and network.transport == "tcp" and 
      source.port >= 49152 and destination.port >= 49152 and source.ip != "127.0.0.1" and source.ip != "::1"
   ] by host.id, process.entity_id

   [process where event.type in ("start", "process_started") and process.parent.name : "services.exe" and 
       not (process.name : "svchost.exe" and process.args : "tiledatamodelsvc") and 
       not (process.name : "msiexec.exe" and process.args : "/V") and
       not process.executable :
               ("?:\\Windows\\ADCR_Agent\\adcrsvc.exe",
                "?:\\Windows\\System32\\VSSVC.exe",
                "?:\\Windows\\servicing\\TrustedInstaller.exe",
                "?:\\Windows\\System32\\svchost.exe",
                "?:\\Program Files (x86)\\*.exe",
                "?:\\Program Files\\*.exe",
                "?:\\Windows\\PSEXESVC.EXE",
                "?:\\Windows\\System32\\sppsvc.exe",
                "?:\\Windows\\System32\\wbem\\WmiApSrv.exe",
                "?:\\WINDOWS\\RemoteAuditService.exe",
                "?:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe",
                "?:\\Windows\\VeeamLogShipper\\VeeamLogShipper.exe",
                "?:\\Windows\\CAInvokerService.exe",
                "?:\\Windows\\System32\\upfc.exe",
                "?:\\Windows\\AdminArsenal\\PDQ*.exe",
                "?:\\Windows\\System32\\vds.exe",
                "?:\\Windows\\Veeam\\Backup\\VeeamDeploymentSvc.exe",
                "?:\\Windows\\ProPatches\\Scheduler\\STSchedEx.exe",
                "?:\\Windows\\System32\\certsrv.exe",
                "?:\\Windows\\eset-remote-install-service.exe",
                "?:\\Pella Corporation\\Pella Order Management\\GPAutoSvc.exe",
                "?:\\Pella Corporation\\OSCToGPAutoService\\OSCToGPAutoSvc.exe",
                "?:\\Pella Corporation\\Pella Order Management\\GPAutoSvc.exe",
                "?:\\Windows\\SysWOW64\\NwxExeSvc\\NwxExeSvc.exe",
                "?:\\Windows\\System32\\taskhostex.exe")
   ] by host.id, process.parent.entity_id
```



### Renamed AutoIt Scripts Interpreter

Branch count: 3  
Document count: 3  
Index: geneve-ut-487

```python
process where event.type in ("start", "process_started", "info") and
  process.pe.original_file_name : "AutoIt*.exe" and not process.name : "AutoIt*.exe"
```



### Roshal Archive (RAR) or PowerShell File Downloaded from the Internet

Branch count: 24  
Document count: 24  
Index: geneve-ut-488

```python
event.category:(network or network_traffic) and network.protocol:http and
  (url.extension:(ps1 or rar) or url.path:(*.ps1 or *.rar)) and
    not destination.ip:(
      10.0.0.0/8 or
      127.0.0.0/8 or
      169.254.0.0/16 or
      172.16.0.0/12 or
      192.0.0.0/24 or
      192.0.0.0/29 or
      192.0.0.8/32 or
      192.0.0.9/32 or
      192.0.0.10/32 or
      192.0.0.170/32 or
      192.0.0.171/32 or
      192.0.2.0/24 or
      192.31.196.0/24 or
      192.52.193.0/24 or
      192.168.0.0/16 or
      192.88.99.0/24 or
      224.0.0.0/4 or
      100.64.0.0/10 or
      192.175.48.0/24 or
      198.18.0.0/15 or
      198.51.100.0/24 or
      203.0.113.0/24 or
      240.0.0.0/4 or
      "::1" or
      "FE80::/10" or
      "FF00::/8"
    ) and
    source.ip:(
      10.0.0.0/8 or
      172.16.0.0/12 or
      192.168.0.0/16
    )
```



### SIP Provider Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-489

```python
registry where event.type:"change" and
  registry.path: (
    "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllPutSignedDataMsg\\{*}\\Dll",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllPutSignedDataMsg\\{*}\\Dll",
    "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{*}\\$Dll",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{*}\\$Dll"
    ) and
  registry.data.strings:"*.dll"
```



### SMB (Windows File Sharing) Activity to the Internet

Branch count: 18  
Document count: 18  
Index: geneve-ut-490

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:(139 or 445) or event.dataset:zeek.smb) and
  source.ip:(
    10.0.0.0/8 or
    172.16.0.0/12 or
    192.168.0.0/16
  ) and
  not destination.ip:(
    10.0.0.0/8 or
    127.0.0.0/8 or
    169.254.0.0/16 or
    172.16.0.0/12 or
    192.0.0.0/24 or
    192.0.0.0/29 or
    192.0.0.8/32 or
    192.0.0.9/32 or
    192.0.0.10/32 or
    192.0.0.170/32 or
    192.0.0.171/32 or
    192.0.2.0/24 or
    192.31.196.0/24 or
    192.52.193.0/24 or
    192.168.0.0/16 or
    192.88.99.0/24 or
    224.0.0.0/4 or
    100.64.0.0/10 or
    192.175.48.0/24 or
    198.18.0.0/15 or
    198.51.100.0/24 or
    203.0.113.0/24 or
    240.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  )
```



### SMTP on Port 26/TCP

Branch count: 4  
Document count: 4  
Index: geneve-ut-491

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:26 or (event.dataset:zeek.smtp and destination.port:26))
```



### SSH Authorized Keys File Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-492

```python
event.category:file and event.type:(change or creation) and 
 file.name:("authorized_keys" or "authorized_keys2") and 
 not process.executable:
             (/Library/Developer/CommandLineTools/usr/bin/git or 
              /usr/local/Cellar/maven/*/libexec/bin/mvn or 
              /Library/Java/JavaVirtualMachines/jdk*.jdk/Contents/Home/bin/java or 
              /usr/bin/vim or 
              /usr/local/Cellar/coreutils/*/bin/gcat or 
              /usr/bin/bsdtar or
              /usr/bin/nautilus or 
              /usr/bin/scp or
              /usr/bin/touch or 
              /var/lib/docker/* or
              /usr/bin/google_guest_agent)
```



### Scheduled Task Created by a Windows Script

Branch count: 20  
Document count: 40  
Index: geneve-ut-494

```python
sequence by host.id with maxspan = 30s
  [any where (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
   (dll.name : "taskschd.dll" or file.name : "taskschd.dll") and
   process.name : ("cscript.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe")]
  [registry where registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions"]
```



### Scheduled Tasks AT Command Enabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-496

```python
registry where
 registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Configuration\\EnableAt" and
 registry.data.strings : ("1", "0x00000001")
```



### Screensaver Plist File Modified by Unexpected Process

Branch count: 3  
Document count: 3  
Index: geneve-ut-497

```python
file where event.type != "deletion" and
  file.name: "com.apple.screensaver.*.plist" and
  file.path : (
    "/Users/*/Library/Preferences/ByHost/*",
    "/Library/Managed Preferences/*",
    "/System/Library/Preferences/*"
    ) and
  /* Filter OS processes modifying screensaver plist files */
  not process.executable : (
    "/usr/sbin/cfprefsd",
    "/usr/libexec/xpcproxy",
    "/System/Library/CoreServices/ManagedClient.app/Contents/Resources/MCXCompositor",
    "/System/Library/CoreServices/ManagedClient.app/Contents/MacOS/ManagedClient"
    )
```



### Searching for Saved Credentials via VaultCmd

Branch count: 4  
Document count: 4  
Index: geneve-ut-498

```python
process where event.type in ("start", "process_started") and
  (process.pe.original_file_name:"vaultcmd.exe" or process.name:"vaultcmd.exe") and
  process.args:"/list*"
```



### Security Software Discovery using WMIC

Branch count: 4  
Document count: 4  
Index: geneve-ut-499

```python
process where event.type in ("start", "process_started") and
   (process.name:"wmic.exe" or process.pe.original_file_name:"wmic.exe") and
    process.args:"/namespace:\\\\root\\SecurityCenter2" and process.args:"Get"
```



### Security Software Discovery via Grep

Branch count: 58  
Document count: 58  
Index: geneve-ut-500

```python
process where event.type == "start" and
process.name : "grep" and user.id != "0" and
 not process.parent.executable : "/Library/Application Support/*" and
   process.args :
         ("Little Snitch*",
          "Avast*",
          "Avira*",
          "ESET*",
          "BlockBlock*",
          "360Sec*",
          "LuLu*",
          "KnockKnock*",
          "kav",
          "KIS",
          "RTProtectionDaemon*",
          "Malware*",
          "VShieldScanner*",
          "WebProtection*",
          "webinspectord*",
          "McAfee*",
          "isecespd*",
          "macmnsvc*",
          "masvc*",
          "kesl*",
          "avscan*",
          "guard*",
          "rtvscand*",
          "symcfgd*",
          "scmdaemon*",
          "symantec*",
          "sophos*",
          "osquery*",
          "elastic-endpoint*"
          ) and
   not (process.args : "Avast" and process.args : "Passwords")
```



### Sensitive Files Compression

Branch count: 135  
Document count: 135  
Index: geneve-ut-501

```python
event.category:process and event.type:start and
  process.name:(zip or tar or gzip or hdiutil or 7z) and
  process.args:
    (
      /root/.ssh/id_rsa or
      /root/.ssh/id_rsa.pub or
      /root/.ssh/id_ed25519 or
      /root/.ssh/id_ed25519.pub or
      /root/.ssh/authorized_keys or
      /root/.ssh/authorized_keys2 or
      /root/.ssh/known_hosts or
      /root/.bash_history or
      /etc/hosts or
      /home/*/.ssh/id_rsa or
      /home/*/.ssh/id_rsa.pub or
      /home/*/.ssh/id_ed25519 or
      /home/*/.ssh/id_ed25519.pub or
      /home/*/.ssh/authorized_keys or
      /home/*/.ssh/authorized_keys2 or
      /home/*/.ssh/known_hosts or
      /home/*/.bash_history or
      /root/.aws/credentials or
      /root/.aws/config or
      /home/*/.aws/credentials or
      /home/*/.aws/config or
      /root/.docker/config.json or
      /home/*/.docker/config.json or
      /etc/group or
      /etc/passwd or
      /etc/shadow or
      /etc/gshadow
    )
```



### Sensitive Privilege SeEnableDelegationPrivilege assigned to a User

Branch count: 1  
Document count: 1  
Index: geneve-ut-502

```python
event.action: "Authorization Policy Change" and event.code:4704 and winlog.event_data.PrivilegeList:"SeEnableDelegationPrivilege"
```



### Service Command Lateral Movement

Branch count: 32  
Document count: 64  
Index: geneve-ut-503

```python
sequence by process.entity_id with maxspan = 1m
  [process where event.type in ("start", "process_started") and
     (process.name : "sc.exe" or process.pe.original_file_name : "sc.exe") and
      process.args : "\\\\*" and process.args : ("binPath=*", "binpath=*") and
      process.args : ("create", "config", "failure", "start")]
  [network where process.name : "sc.exe" and destination.ip != "127.0.0.1"]
```



### Service Control Spawned via Script Interpreter

Branch count: 96  
Document count: 96  
Index: geneve-ut-504

```python
/* This rule is not compatible with Sysmon due to user.id issues */

process where event.type == "start" and
  (process.name : "sc.exe" or process.pe.original_file_name == "sc.exe") and
  process.parent.name : ("cmd.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe",
                         "wmic.exe", "mshta.exe","powershell.exe", "pwsh.exe") and
  process.args:("config", "create", "start", "delete", "stop", "pause") and
  /* exclude SYSTEM SID - look for service creations by non-SYSTEM user */
  not user.id : "S-1-5-18"
```



### Service Creation via Local Kerberos Authentication

Branch count: 1  
Document count: 2  
Index: geneve-ut-505

```python
sequence by host.id with maxspan=5m
 [authentication where

  /* event 4624 need to be logged */
  event.action == "logged-in" and event.outcome == "success" and

  /* authenticate locally using relayed kerberos Ticket */
  winlog.event_data.AuthenticationPackageName :"Kerberos" and winlog.logon.type == "Network" and
  cidrmatch(source.ip, "127.0.0.0/8", "::1") and source.port > 0] by winlog.event_data.TargetLogonId

  [any where
   /* event 4697 need to be logged */
   event.action : "service-installed"] by winlog.event_data.SubjectLogonId
```



### SharePoint Malware File Upload

Branch count: 1  
Document count: 1  
Index: geneve-ut-507

```python
event.dataset:o365.audit and event.provider:SharePoint and event.code:SharePointFileOperation and event.action:FileMalwareDetected
```



### Shell Execution via Apple Scripting

Branch count: 6  
Document count: 12  
Index: geneve-ut-508

```python
sequence by host.id with maxspan=5s
 [process where event.type in ("start", "process_started", "info") and process.name == "osascript"] by process.pid
 [process where event.type in ("start", "process_started") and process.name == "sh" and process.args == "-c"] by process.parent.pid
```



### Signed Proxy Execution via MS Work Folders

Branch count: 2  
Document count: 2  
Index: geneve-ut-509

```python
process where event.type in ("start","process_started")
    and process.name : "control.exe" and process.parent.name : "WorkFolders.exe"
    and not process.executable : ("?:\\Windows\\System32\\control.exe", "?:\\Windows\\SysWOW64\\control.exe")
```



### SoftwareUpdate Preferences Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-510

```python
event.category:process and event.type:(start or process_started) and
 process.name:defaults and 
 process.args:(write and "-bool" and (com.apple.SoftwareUpdate or /Library/Preferences/com.apple.SoftwareUpdate.plist) and not (TRUE or true))
```



### SolarWinds Process Disabling Services via Registry

Branch count: 14  
Document count: 14  
Index: geneve-ut-511

```python
registry where registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\Start" and
  registry.data.strings : ("4", "0x00000004") and
  process.name : (
      "SolarWinds.BusinessLayerHost*.exe",
      "ConfigurationWizard*.exe",
      "NetflowDatabaseMaintenance*.exe",
      "NetFlowService*.exe",
      "SolarWinds.Administration*.exe",
      "SolarWinds.Collector.Service*.exe" ,
      "SolarwindsDiagnostics*.exe")
```



### Startup Folder Persistence via Unsigned Process

Branch count: 24  
Document count: 48  
Index: geneve-ut-519

```python
sequence by host.id, process.entity_id with maxspan=5s
  [process where event.type in ("start", "process_started") and process.code_signature.trusted == false and
  /* suspicious paths can be added here  */
   process.executable : ("C:\\Users\\*.exe", 
                         "C:\\ProgramData\\*.exe", 
                         "C:\\Windows\\Temp\\*.exe", 
                         "C:\\Windows\\Tasks\\*.exe", 
                         "C:\\Intel\\*.exe", 
                         "C:\\PerfLogs\\*.exe")
   ]
   [file where event.type != "deletion" and user.domain != "NT AUTHORITY" and
    file.path : ("C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*", 
                 "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*")
   ]
```



### Startup Persistence by a Suspicious Process

Branch count: 36  
Document count: 36  
Index: geneve-ut-520

```python
file where event.type != "deletion" and
  user.domain != "NT AUTHORITY" and
  file.path : ("C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
               "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*") and
  process.name : ("cmd.exe",
                  "powershell.exe",
                  "wmic.exe",
                  "mshta.exe",
                  "pwsh.exe",
                  "cscript.exe",
                  "wscript.exe",
                  "regsvr32.exe",
                  "RegAsm.exe",
                  "rundll32.exe",
                  "EQNEDT32.EXE",
                  "WINWORD.EXE",
                  "EXCEL.EXE",
                  "POWERPNT.EXE",
                  "MSPUB.EXE",
                  "MSACCESS.EXE",
                  "iexplore.exe",
                  "InstallUtil.exe")
```



### Startup or Run Key Registry Modification

Branch count: 60  
Document count: 60  
Index: geneve-ut-521

```python
registry where registry.data.strings != null and
 registry.path : (
     /* Machine Hive */
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*", 
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*", 
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*", 
     "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*",   
     /* Users Hive */
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*", 
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*", 
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*", 
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*"
     ) and
  /* add common legitimate changes without being too restrictive as this is one of the most abused AESPs */
  not registry.data.strings : "ctfmon.exe /n" and
  not (registry.value : "Application Restart #*" and process.name : "csrss.exe") and
  user.id not in ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
  not registry.data.strings : ("?:\\Program Files\\*.exe", "?:\\Program Files (x86)\\*.exe") and
  not process.executable : ("?:\\Windows\\System32\\msiexec.exe", "?:\\Windows\\SysWOW64\\msiexec.exe") and
  not (process.name : "OneDriveSetup.exe" and
       registry.value : ("Delete Cached Standalone Update Binary", "Delete Cached Update Binary", "amd64", "Uninstall *") and
       registry.data.strings : "?:\\Windows\\system32\\cmd.exe /q /c * \"?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\*\"")
```



### Sublime Plugin or Application Script Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-523

```python
file where event.type in ("change", "creation") and file.extension : "py" and
  file.path :
    (
      "/Users/*/Library/Application Support/Sublime Text*/Packages/*.py",
      "/Applications/Sublime Text.app/Contents/MacOS/sublime.py"
    ) and
  not process.executable :
    (
      "/Applications/Sublime Text*.app/Contents/*",
      "/usr/local/Cellar/git/*/bin/git",
      "/Library/Developer/CommandLineTools/usr/bin/git",
      "/usr/libexec/xpcproxy",
      "/System/Library/PrivateFrameworks/DesktopServicesPriv.framework/Versions/A/Resources/DesktopServicesHelper"
    )
```



### Sudoers File Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-525

```python
event.category:file and event.type:change and file.path:(/etc/sudoers* or /private/etc/sudoers*)
```



### Suspicious .NET Code Compilation

Branch count: 32  
Document count: 32  
Index: geneve-ut-526

```python
process where event.type in ("start", "process_started") and
  process.name : ("csc.exe", "vbc.exe") and
  process.parent.name : ("wscript.exe", "mshta.exe", "cscript.exe", "wmic.exe", "svchost.exe", "rundll32.exe", "cmstp.exe", "regsvr32.exe")
```



### Suspicious .NET Reflection via PowerShell

Branch count: 2  
Document count: 2  
Index: geneve-ut-527

```python
event.category:process and
  powershell.file.script_block_text : (
    "[System.Reflection.Assembly]::Load" or
    "[Reflection.Assembly]::Load"
  )
```



### Suspicious Activity Reported by Okta User

Branch count: 1  
Document count: 1  
Index: geneve-ut-528

```python
event.dataset:okta.system and event.action:user.account.report_suspicious_activity_by_enduser
```



### Suspicious Automator Workflows Execution

Branch count: 2  
Document count: 4  
Index: geneve-ut-529

```python
sequence by host.id with maxspan=30s
 [process where event.type in ("start", "process_started") and process.name == "automator"]
 [network where process.name:"com.apple.automator.runner"]
```



### Suspicious Browser Child Process

Branch count: 182  
Document count: 182  
Index: geneve-ut-530

```python
process where event.type in ("start", "process_started") and
  process.parent.name : ("Google Chrome", "Google Chrome Helper*", "firefox", "Opera", "Safari", "com.apple.WebKit.WebContent", "Microsoft Edge") and
  process.name : ("sh", "bash", "dash", "ksh", "tcsh", "zsh", "curl", "wget", "python*", "perl*", "php*", "osascript", "pwsh") and 
  process.command_line != null and 
  not process.args : 
    ( 
      "/Library/Application Support/Microsoft/MAU*/Microsoft AutoUpdate.app/Contents/MacOS/msupdate", 
      "hw.model", 
      "IOPlatformExpertDevice", 
      "/Volumes/Google Chrome/Google Chrome.app/Contents/Frameworks/*/Resources/install.sh",
      "--defaults-torrc", 
      "Chrome.app", 
      "Framework.framework/Versions/*/Resources/keystone_promote_preflight.sh", 
      "/Users/*/Library/Application Support/Google/Chrome/recovery/*/ChromeRecovery", 
      "$DISPLAY", 
      "GIO_LAUNCHED_DESKTOP_FILE_PID=$$"
    )
```



### Suspicious Calendar File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-531

```python
event.category:file and event.action:modification and
  file.path:/Users/*/Library/Calendars/*.calendar/Events/*.ics and
  process.executable:
  (* and not
    (
      /System/Library/* or
      /System/Applications/Calendar.app/Contents/MacOS/* or
      /System/Applications/Mail.app/Contents/MacOS/Mail or
      /usr/libexec/xpcproxy or
      /sbin/launchd or
      /Applications/*
    )
  )
```



### Suspicious CertUtil Commands

Branch count: 14  
Document count: 14  
Index: geneve-ut-532

```python
process where event.type == "start" and
  (process.name : "certutil.exe" or process.pe.original_file_name == "CertUtil.exe") and
  process.args : ("?decode", "?encode", "?urlcache", "?verifyctl", "?encodehex", "?decodehex", "?exportPFX")
```



### Suspicious Child Process of Adobe Acrobat Reader Update Service

Branch count: 2  
Document count: 2  
Index: geneve-ut-533

```python
event.category:process and event.type:(start or process_started) and
  process.parent.name:com.adobe.ARMDC.SMJobBlessHelper and
  user.name:root and
  not process.executable: (/Library/PrivilegedHelperTools/com.adobe.ARMDC.SMJobBlessHelper or
                           /usr/bin/codesign or
                           /private/var/folders/zz/*/T/download/ARMDCHammer or
                           /usr/sbin/pkgutil or
                           /usr/bin/shasum or
                           /usr/bin/perl* or
                           /usr/sbin/spctl or
                           /usr/sbin/installer)
```



### Suspicious Cmd Execution via WMI

Branch count: 4  
Document count: 4  
Index: geneve-ut-534

```python
process where event.type in ("start", "process_started") and
 process.parent.name : "WmiPrvSE.exe" and process.name : "cmd.exe" and
 process.args : "\\\\127.0.0.1\\*" and process.args : ("2>&1", "1>")
```



### Suspicious CronTab Creation or Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-535

```python
file where event.type != "deletion" and process.name != null and 
  file.path : "/private/var/at/tabs/*" and not process.executable == "/usr/bin/crontab"
```



### Suspicious DLL Loaded for Persistence or Privilege Escalation

Branch count: 90  
Document count: 90  
Index: geneve-ut-536

```python
any where
 (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
 (
  /* compatible with Elastic Endpoint Library Events */
  (dll.name : ("wlbsctrl.dll", "wbemcomn.dll", "WptsExtensions.dll", "Tsmsisrv.dll", "TSVIPSrv.dll", "Msfte.dll",
               "wow64log.dll", "WindowsCoreDeviceInfo.dll", "Ualapi.dll", "wlanhlp.dll", "phoneinfo.dll", "EdgeGdi.dll",
               "cdpsgshims.dll", "windowsperformancerecordercontrol.dll", "diagtrack_win.dll")
   and (dll.code_signature.trusted == false or dll.code_signature.exists == false)) or

  /* compatible with Sysmon EventID 7 - Image Load */
  (file.name : ("wlbsctrl.dll", "wbemcomn.dll", "WptsExtensions.dll", "Tsmsisrv.dll", "TSVIPSrv.dll", "Msfte.dll",
               "wow64log.dll", "WindowsCoreDeviceInfo.dll", "Ualapi.dll", "wlanhlp.dll", "phoneinfo.dll", "EdgeGdi.dll",
               "cdpsgshims.dll", "windowsperformancerecordercontrol.dll", "diagtrack_win.dll")
   and not file.code_signature.status == "Valid")
  )
```



### Suspicious Emond Child Process

Branch count: 44  
Document count: 44  
Index: geneve-ut-537

```python
process where event.type in ("start", "process_started") and
 process.parent.name : "emond" and
 process.name : (
   "bash",
   "dash",
   "sh",
   "tcsh",
   "csh",
   "zsh",
   "ksh",
   "fish",
   "Python",
   "python*",
   "perl*",
   "php*",
   "osascript",
   "pwsh",
   "curl",
   "wget",
   "cp",
   "mv",
   "touch",
   "echo",
   "base64",
   "launchctl")
```



### Suspicious Endpoint Security Parent Process

Branch count: 6  
Document count: 6  
Index: geneve-ut-538

```python
process where event.type in ("start", "process_started", "info") and
 process.name : ("esensor.exe", "elastic-endpoint.exe") and
 process.parent.executable != null and
  /* add FPs here */
 not process.parent.executable : ("C:\\Program Files\\Elastic\\*",
                                  "C:\\Windows\\System32\\services.exe",
                                  "C:\\Windows\\System32\\WerFault*.exe",
                                  "C:\\Windows\\System32\\wermgr.exe")
```



### Suspicious Execution from a Mounted Device

Branch count: 8  
Document count: 8  
Index: geneve-ut-540

```python
process where event.type == "start" and process.executable : "C:\\*" and
  (process.working_directory : "?:\\" and not process.working_directory: "C:\\") and
  process.parent.name : "explorer.exe" and
  process.name : ("rundll32.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "regsvr32.exe",
                  "cscript.exe", "wscript.exe")
```



### Suspicious Execution via Scheduled Task

Branch count: 128  
Document count: 128  
Index: geneve-ut-541

```python
process where event.type == "start" and
    /* Schedule service cmdline on Win10+ */
    process.parent.name : "svchost.exe" and process.parent.args : "Schedule" and
    /* add suspicious programs here */
    process.pe.original_file_name in
                                (
                                  "cscript.exe",
                                  "wscript.exe",
                                  "PowerShell.EXE",
                                  "Cmd.Exe",
                                  "MSHTA.EXE",
                                  "RUNDLL32.EXE",
                                  "REGSVR32.EXE",
                                  "MSBuild.exe",
                                  "InstallUtil.exe",
                                  "RegAsm.exe",
                                  "RegSvcs.exe",
                                  "msxsl.exe",
                                  "CONTROL.EXE",
                                  "EXPLORER.EXE",
                                  "Microsoft.Workflow.Compiler.exe",
                                  "msiexec.exe"
                                  ) and
    /* add suspicious paths here */
    process.args : (
       "C:\\Users\\*",
       "C:\\ProgramData\\*",
       "C:\\Windows\\Temp\\*",
       "C:\\Windows\\Tasks\\*",
       "C:\\PerfLogs\\*",
       "C:\\Intel\\*",
       "C:\\Windows\\Debug\\*",
       "C:\\HP\\*")
```



### Suspicious Explorer Child Process

Branch count: 28  
Document count: 28  
Index: geneve-ut-542

```python
process where event.type in ("start", "process_started") and
  (
   process.name : ("cscript.exe", "wscript.exe", "powershell.exe", "rundll32.exe", "cmd.exe", "mshta.exe", "regsvr32.exe") or
   process.pe.original_file_name in ("cscript.exe", "wscript.exe", "PowerShell.EXE", "RUNDLL32.EXE", "Cmd.Exe", "MSHTA.EXE", "REGSVR32.EXE")
  ) and
  /* Explorer started via DCOM */
  process.parent.name : "explorer.exe" and process.parent.args : "-Embedding" and
  not process.parent.args:
          (
            /* Noisy CLSID_SeparateSingleProcessExplorerHost Explorer COM Class IDs   */
            "/factory,{5BD95610-9434-43C2-886C-57852CC8A120}",
            "/factory,{ceff45ee-c862-41de-aee2-a022c81eda92}"
          )
```



### Suspicious File Creation in /etc for Persistence

Branch count: 5  
Document count: 5  
Index: geneve-ut-543

```python
file where event.action == "creation" and user.name == "root" and file.path : ("/etc/ld.so.conf.d/*", "/etc/cron.d/*", "/etc/sudoers.d/*", "/etc/rc.d/init.d/*", "/etc/systemd/system/*") and not process.executable : ("*/dpkg", "*/yum", "*/apt", "*/dnf", "*/systemd")
```



### Suspicious Hidden Child Process of Launchd

Branch count: 2  
Document count: 2  
Index: geneve-ut-545

```python
event.category:process and event.type:(start or process_started) and
 process.name:.* and process.parent.executable:/sbin/launchd
```



### Suspicious Image Load (taskschd.dll) from MS Office

Branch count: 20  
Document count: 20  
Index: geneve-ut-546

```python
any where
 (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
  process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE", "MSACCESS.EXE") and
  (dll.name : "taskschd.dll" or file.name : "taskschd.dll")
```



### Suspicious ImagePath Service Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-547

```python
registry where registry.path : "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath" and
 /* add suspicious registry ImagePath values here */
 registry.data.strings : ("%COMSPEC%*", "*\\.\\pipe\\*")
```



### Suspicious JAVA Child Process

Branch count: 16  
Document count: 16  
Index: geneve-ut-548

```python
process where event.type in ("start", "process_started") and
  process.parent.name : "java" and
  process.name : ("sh", "bash", "dash", "ksh", "tcsh", "zsh", "curl", "wget")
```



### Suspicious LSASS Access via MalSecLogon

Branch count: 1  
Document count: 1  
Index: geneve-ut-549

```python
process where event.code == "10" and
  winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe" and

   /* seclogon service accessing lsass */
  winlog.event_data.CallTrace : "*seclogon.dll*" and process.name : "svchost.exe" and

   /* PROCESS_CREATE_PROCESS & PROCESS_DUP_HANDLE & PROCESS_QUERY_INFORMATION */
  winlog.event_data.GrantedAccess == "0x14c0"
```



### Suspicious MS Office Child Process

Branch count: 912  
Document count: 912  
Index: geneve-ut-550

```python
process where event.type in ("start", "process_started") and
  process.parent.name : ("eqnedt32.exe", "excel.exe", "fltldr.exe", "msaccess.exe", "mspub.exe", "powerpnt.exe", "winword.exe", "outlook.exe") and
  process.name : ("Microsoft.Workflow.Compiler.exe", "arp.exe", "atbroker.exe", "bginfo.exe", "bitsadmin.exe", "cdb.exe", "certutil.exe",
                "cmd.exe", "cmstp.exe", "control.exe", "cscript.exe", "csi.exe", "dnx.exe", "dsget.exe", "dsquery.exe", "forfiles.exe",
                "fsi.exe", "ftp.exe", "gpresult.exe", "hostname.exe", "ieexec.exe", "iexpress.exe", "installutil.exe", "ipconfig.exe",
                "mshta.exe", "msxsl.exe", "nbtstat.exe", "net.exe", "net1.exe", "netsh.exe", "netstat.exe", "nltest.exe", "odbcconf.exe",
                "ping.exe", "powershell.exe", "pwsh.exe", "qprocess.exe", "quser.exe", "qwinsta.exe", "rcsi.exe", "reg.exe", "regasm.exe",
                "regsvcs.exe", "regsvr32.exe", "sc.exe", "schtasks.exe", "systeminfo.exe", "tasklist.exe", "tracert.exe", "whoami.exe",
                "wmic.exe", "wscript.exe", "xwizard.exe", "explorer.exe", "rundll32.exe", "hh.exe", "msdt.exe")
```



### Suspicious MS Outlook Child Process

Branch count: 104  
Document count: 104  
Index: geneve-ut-551

```python
process where event.type in ("start", "process_started") and
  process.parent.name : "outlook.exe" and
  process.name : ("Microsoft.Workflow.Compiler.exe", "arp.exe", "atbroker.exe", "bginfo.exe", "bitsadmin.exe",
                  "cdb.exe", "certutil.exe", "cmd.exe", "cmstp.exe", "cscript.exe", "csi.exe", "dnx.exe", "dsget.exe",
                  "dsquery.exe", "forfiles.exe", "fsi.exe", "ftp.exe", "gpresult.exe", "hostname.exe", "ieexec.exe",
                  "iexpress.exe", "installutil.exe", "ipconfig.exe", "mshta.exe", "msxsl.exe", "nbtstat.exe", "net.exe",
                  "net1.exe", "netsh.exe", "netstat.exe", "nltest.exe", "odbcconf.exe", "ping.exe", "powershell.exe",
                  "pwsh.exe", "qprocess.exe", "quser.exe", "qwinsta.exe", "rcsi.exe", "reg.exe", "regasm.exe",
                  "regsvcs.exe", "regsvr32.exe", "sc.exe", "schtasks.exe", "systeminfo.exe", "tasklist.exe",
                  "tracert.exe", "whoami.exe", "wmic.exe", "wscript.exe", "xwizard.exe")
```



### Suspicious Managed Code Hosting Process

Branch count: 64  
Document count: 128  
Index: geneve-ut-552

```python
sequence by process.entity_id with maxspan=5m
 [process where event.type == "start" and 
  process.name : ("wscript.exe", "cscript.exe", "mshta.exe", "wmic.exe", "regsvr32.exe", "svchost.exe", "dllhost.exe", "cmstp.exe")]
 [file where event.type != "deletion" and
  file.name : ("wscript.exe.log",
               "cscript.exe",
               "mshta.exe.log",
               "wmic.exe.log",
               "svchost.exe.log",
               "dllhost.exe.log",
               "cmstp.exe.log",
               "regsvr32.exe.log")]
```



### Suspicious Network Connection Attempt by Root

Branch count: 1  
Document count: 2  
Index: geneve-ut-554

```python
sequence by process.entity_id with maxspan=1m
[network where event.type == "start" and event.action == "connection_attempted" and user.id == "0" and 
    not process.executable : ("/bin/ssh", "/sbin/ssh", "/usr/lib/systemd/systemd", "/usr/sbin/sshd")]
[process where event.action == "session_id_change" and user.id == "0" and
    not process.executable : ("/bin/ssh", "/sbin/ssh", "/usr/lib/systemd/systemd", "/usr/sbin/sshd")]
```



### Suspicious PDF Reader Child Process

Branch count: 424  
Document count: 424  
Index: geneve-ut-555

```python
process where event.type in ("start", "process_started") and
  process.parent.name : ("AcroRd32.exe",
                         "Acrobat.exe",
                         "FoxitPhantomPDF.exe",
                         "FoxitReader.exe") and
  process.name : ("arp.exe", "dsquery.exe", "dsget.exe", "gpresult.exe", "hostname.exe", "ipconfig.exe", "nbtstat.exe",
                  "net.exe", "net1.exe", "netsh.exe", "netstat.exe", "nltest.exe", "ping.exe", "qprocess.exe",
                  "quser.exe", "qwinsta.exe", "reg.exe", "sc.exe", "systeminfo.exe", "tasklist.exe", "tracert.exe",
                  "whoami.exe", "bginfo.exe", "cdb.exe", "cmstp.exe", "csi.exe", "dnx.exe", "fsi.exe", "ieexec.exe",
                  "iexpress.exe", "installutil.exe", "Microsoft.Workflow.Compiler.exe", "msbuild.exe", "mshta.exe",
                  "msxsl.exe", "odbcconf.exe", "rcsi.exe", "regsvr32.exe", "xwizard.exe", "atbroker.exe",
                  "forfiles.exe", "schtasks.exe", "regasm.exe", "regsvcs.exe", "cmd.exe", "cscript.exe",
                  "powershell.exe", "pwsh.exe", "wmic.exe", "wscript.exe", "bitsadmin.exe", "certutil.exe", "ftp.exe")
```



### Suspicious Portable Executable Encoded in Powershell Script

Branch count: 1  
Document count: 1  
Index: geneve-ut-556

```python
event.category:process and
  powershell.file.script_block_text : (
    TVqQAAMAAAAEAAAA
  )
```



### Suspicious Print Spooler File Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-559

```python
file where event.type : "deletion" and
 not process.name : ("spoolsv.exe", "dllhost.exe", "explorer.exe") and
 file.path : "?:\\Windows\\System32\\spool\\drivers\\x64\\3\\*.dll"
```



### Suspicious Print Spooler Point and Print DLL

Branch count: 1  
Document count: 2  
Index: geneve-ut-560

```python
sequence by host.id with maxspan=30s
[registry where
 registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\SpoolDirectory" and
 registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4"]
[registry where
 registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\CopyFiles\\Payload\\Module" and
 registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4\\*"]
```



### Suspicious PrintSpooler SPL File Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-561

```python
file where event.type != "deletion" and
  file.extension : "spl" and
  file.path : "?:\\Windows\\System32\\spool\\PRINTERS\\*" and
  not process.name : ("spoolsv.exe",
                      "printfilterpipelinesvc.exe",
                      "PrintIsolationHost.exe",
                      "splwow64.exe",
                      "msiexec.exe",
                      "poqexec.exe")
```



### Suspicious PrintSpooler Service Executable File Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-562

```python
file where event.type != "deletion" and process.name : "spoolsv.exe" and
  file.extension : ("exe", "dll") and
  not file.path : ("?:\\Windows\\System32\\spool\\*", "?:\\Windows\\Temp\\*", "?:\\Users\\*")
```



### Suspicious Process Execution via Renamed PsExec Executable

Branch count: 3  
Document count: 3  
Index: geneve-ut-565

```python
process where event.type in ("start", "process_started", "info") and
  process.pe.original_file_name : "psexesvc.exe" and not process.name : "PSEXESVC.exe"
```



### Suspicious Process from Conhost

Branch count: 2  
Document count: 2  
Index: geneve-ut-566

```python
process where event.type in ("start", "process_started") and
  process.parent.name : "conhost.exe" and
  not process.executable : ("?:\\Windows\\splwow64.exe", "?:\\Windows\\System32\\WerFault.exe", "?:\\Windows\\System32\\conhost.exe")
```



### Suspicious RDP ActiveX Client Loaded

Branch count: 32  
Document count: 32  
Index: geneve-ut-567

```python
any where (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
 (dll.name : "mstscax.dll" or file.name : "mstscax.dll") and
   /* depending on noise in your env add here extra paths  */
  process.executable :
    (
    "C:\\Windows\\*",
    "C:\\Users\\Public\\*",
    "C:\\Users\\Default\\*",
    "C:\\Intel\\*",
    "C:\\PerfLogs\\*",
    "C:\\ProgramData\\*",
    "\\Device\\Mup\\*",
    "\\\\*"
    ) and
    /* add here FPs */
  not process.executable : ("C:\\Windows\\System32\\mstsc.exe", "C:\\Windows\\SysWOW64\\mstsc.exe")
```



### Suspicious Remote Registry Access via SeBackupPrivilege

Branch count: 1  
Document count: 2  
Index: geneve-ut-568

```python
sequence by host.id, winlog.event_data.SubjectLogonId with maxspan=1m
 [iam where event.action == "logged-in-special"  and
  winlog.event_data.PrivilegeList : "SeBackupPrivilege" and

  /* excluding accounts with existing privileged access */
  not winlog.event_data.PrivilegeList : "SeDebugPrivilege"]
 [any where event.action == "Detailed File Share" and winlog.event_data.RelativeTargetName : "winreg"]
```



### Suspicious Script Object Execution

Branch count: 2  
Document count: 4  
Index: geneve-ut-569

```python
sequence by process.entity_id with maxspan=2m
  [process where event.type == "start"
   and (process.code_signature.subject_name in ("Microsoft Corporation", "Microsoft Windows") and
   process.code_signature.trusted == true) and
     not process.executable : (
       "?:\\Windows\\System32\\cscript.exe",
       "?:\\Windows\\SysWOW64\\cscript.exe",
       "?:\\Program Files (x86)\\Internet Explorer\\iexplore.exe",
       "?:\\Program Files\\Internet Explorer\\iexplore.exe",
       "?:\\Windows\\SystemApps\\Microsoft.MicrosoftEdge_*\\MicrosoftEdge.exe",
       "?:\\Windows\\system32\\msiexec.exe",
       "?:\\Windows\\SysWOW64\\msiexec.exe",
       "?:\\Windows\\System32\\smartscreen.exe",
       "?:\\Windows\\system32\\taskhostw.exe",
       "?:\\windows\\system32\\inetsrv\\w3wp.exe",
       "?:\\windows\\SysWOW64\\inetsrv\\w3wp.exe",
       "?:\\Windows\\system32\\wscript.exe",
       "?:\\Windows\\SysWOW64\\wscript.exe",
       "?:\\Windows\\system32\\mobsync.exe",
       "?:\\Windows\\SysWOW64\\mobsync.exe",
       "?:\\Windows\\System32\\cmd.exe",
       "?:\\Windows\\SysWOW64\\cmd.exe")]
  [library where event.type == "start" and dll.name : "scrobj.dll"]
```



### Suspicious SolarWinds Child Process

Branch count: 4  
Document count: 4  
Index: geneve-ut-570

```python
process where event.type in ("start", "process_started") and
 process.parent.name: ("SolarWinds.BusinessLayerHost.exe", "SolarWinds.BusinessLayerHostx64.exe") and
 not process.name : (
        "APMServiceControl*.exe",
        "ExportToPDFCmd*.Exe",
        "SolarWinds.Credentials.Orion.WebApi*.exe",
        "SolarWinds.Orion.Topology.Calculator*.exe",
        "Database-Maint.exe",
        "SolarWinds.Orion.ApiPoller.Service.exe",
        "WerFault.exe",
        "WerMgr.exe")
```



### Suspicious Startup Shell Folder Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-571

```python
registry where
 registry.path : (
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup"
     ) and
  registry.data.strings != null and
  /* Normal Startup Folder Paths */
  not registry.data.strings : (
           "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
           )
```



### Suspicious WMI Image Load from MS Office

Branch count: 20  
Document count: 20  
Index: geneve-ut-572

```python
any where
 (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
  process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE", "MSACCESS.EXE") and
  (dll.name : "wmiutils.dll" or file.name : "wmiutils.dll")
```



### Suspicious WMIC XSL Script Execution

Branch count: 96  
Document count: 192  
Index: geneve-ut-573

```python
sequence by process.entity_id with maxspan = 2m
[process where event.type in ("start", "process_started") and
   (process.name : "WMIC.exe" or process.pe.original_file_name : "wmic.exe") and
   process.args : ("format*:*", "/format*:*", "*-format*:*") and
   not process.command_line : "* /format:table *"]
[any where (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
 (dll.name : ("jscript.dll", "vbscript.dll") or file.name : ("jscript.dll", "vbscript.dll"))]
```



### Suspicious WerFault Child Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-574

```python
process where event.type in ("start", "process_started") and
  process.parent.name : "WerFault.exe" and
  not process.name : ("cofire.exe",
                      "psr.exe",
                      "VsJITDebugger.exe",
                      "TTTracer.exe",
                      "rundll32.exe",
                      "LogiOptionsMgr.exe") and
  not process.args : ("/LOADSAVEDWINDOWS",
                      "/restore",
                      "RestartByRestartManager*",
                      "--restarted",
                      "createdump",
                      "dontsend",
                      "/watson")
```



### Suspicious Zoom Child Process

Branch count: 12  
Document count: 12  
Index: geneve-ut-575

```python
process where event.type in ("start", "process_started", "info") and
 process.parent.name : "Zoom.exe" and process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe")
```



### Suspicious macOS MS Office Child Process

Branch count: 114  
Document count: 114  
Index: geneve-ut-576

```python
process where event.type in ("start", "process_started") and
 process.parent.name:("Microsoft Word", "Microsoft PowerPoint", "Microsoft Excel") and
 process.name:
 (
   "bash", 
   "dash", 
   "sh", 
   "tcsh", 
   "csh", 
   "zsh", 
   "ksh", 
   "fish", 
   "python*", 
   "perl*", 
   "php*", 
   "osascript",
   "pwsh", 
   "curl", 
   "wget", 
   "cp", 
   "mv", 
   "base64", 
   "launchctl"
  ) and
  /* noisy false positives related to product version discovery and office errors reporting */
  not process.args:
    (
      "ProductVersion",
      "hw.model",
      "ioreg",
      "ProductName",
      "ProductUserVisibleVersion",
      "ProductBuildVersion",
      "/Library/Application Support/Microsoft/MERP*/Microsoft Error Reporting.app/Contents/MacOS/Microsoft Error Reporting"
    )
```



### Svchost spawning Cmd

Branch count: 2  
Document count: 2  
Index: geneve-ut-577

```python
process where event.type == "start" and
  process.parent.name : "svchost.exe" and process.name : "cmd.exe" and
  not (process.pe.original_file_name : "cmd.exe" and process.args : (
    "??:\\Program Files\\Npcap\\CheckStatus.bat?",
    "?:\\Program Files\\Npcap\\CheckStatus.bat",
    "\\system32\\cleanmgr.exe",
    "?:\\Windows\\system32\\silcollector.cmd",
    "\\system32\\AppHostRegistrationVerifier.exe",
    "\\system32\\ServerManagerLauncher.exe"))
```



### System Log File Deletion

Branch count: 9  
Document count: 9  
Index: geneve-ut-579

```python
file where event.type == "deletion" and
  file.path :
    (
    "/var/run/utmp",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/var/log/faillog",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/secure",
    "/var/log/auth.log"
    ) and
    not process.name : ("gzip")
```



### System Shells via Services

Branch count: 8  
Document count: 8  
Index: geneve-ut-580

```python
process where event.type in ("start", "process_started") and
  process.parent.name : "services.exe" and
  process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe") and

  /* Third party FP's */
  not process.args : "NVDisplay.ContainerLocalSystem"
```



### SystemKey Access via Command Line

Branch count: 4  
Document count: 4  
Index: geneve-ut-581

```python
event.category:process and event.type:(start or process_started) and
  process.args:("/private/var/db/SystemKey" or "/var/db/SystemKey")
```



### TCC Bypass via Mounted APFS Snapshot Access

Branch count: 2  
Document count: 2  
Index: geneve-ut-582

```python
event.category : process and event.type : (start or process_started) and process.name : mount_apfs and
  process.args : (/System/Volumes/Data and noowners)
```



### Tampering of Bash Command-Line History

Branch count: 90  
Document count: 90  
Index: geneve-ut-583

```python
process where event.type in ("start", "process_started") and
 (
  ((process.args : ("rm", "echo") or
    (process.args : "ln" and process.args : "-sf" and process.args : "/dev/null") or
    (process.args : "truncate" and process.args : "-s0"))
    and process.args : (".bash_history", "/root/.bash_history", "/home/*/.bash_history","/Users/.bash_history", "/Users/*/.bash_history",
                        ".zsh_history", "/root/.zsh_history", "/home/*/.zsh_history", "/Users/.zsh_history", "/Users/*/.zsh_history")) or
  (process.name : "history" and process.args : "-c") or
  (process.args : "export" and process.args : ("HISTFILE=/dev/null", "HISTFILESIZE=0")) or
  (process.args : "unset" and process.args : "HISTFILE") or
  (process.args : "set" and process.args : "history" and process.args : "+o")
 )
```



### Telnet Port Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-584

```python
event.category:(network or network_traffic) and network.transport:tcp and destination.port:23
```



### Third-party Backup Files Deleted via Unexpected Process

Branch count: 4  
Document count: 4  
Index: geneve-ut-585

```python
file where event.type == "deletion" and
  (
  /* Veeam Related Backup Files */
  (file.extension : ("VBK", "VIB", "VBM") and
  not process.executable : ("?:\\Windows\\Veeam\\Backup\\*",
                            "?:\\Program Files\\Veeam\\Backup and Replication\\*",
                            "?:\\Program Files (x86)\\Veeam\\Backup and Replication\\*")) or

  /* Veritas Backup Exec Related Backup File */
  (file.extension : "BKF" and
  not process.executable : ("?:\\Program Files\\Veritas\\Backup Exec\\*",
                            "?:\\Program Files (x86)\\Veritas\\Backup Exec\\*"))
  )
```



### Threat Detected by Okta ThreatInsight

Branch count: 1  
Document count: 1  
Index: geneve-ut-586

```python
event.dataset:okta.system and event.action:security.threat.detected
```



### Timestomping using Touch Command

Branch count: 4  
Document count: 4  
Index: geneve-ut-589

```python
process where event.type == "start" and
 process.name : "touch" and user.id != "0" and
 process.args : ("-r", "-t", "-a*","-m*") and
 not process.args : ("/usr/lib/go-*/bin/go", "/usr/lib/dracut/dracut-functions.sh", "/tmp/KSInstallAction.*/m/.patch/*")
```



### UAC Bypass Attempt via Elevated COM Internet Explorer Add-On Installer

Branch count: 2  
Document count: 2  
Index: geneve-ut-590

```python
process where event.type in ("start", "process_started") and
 process.executable : "C:\\*\\AppData\\*\\Temp\\IDC*.tmp\\*.exe" and
 process.parent.name : "ieinstal.exe" and process.parent.args : "-Embedding"

 /* uncomment once in winlogbeat */
 /* and not (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true) */
```



### UAC Bypass Attempt via Privileged IFileOperation COM Interface

Branch count: 6  
Document count: 6  
Index: geneve-ut-591

```python
file where event.type : "change" and process.name : "dllhost.exe" and
  /* Known modules names side loaded into process running with high or system integrity level for UAC Bypass, update here for new modules */
  file.name : ("wow64log.dll", "comctl32.dll", "DismCore.dll", "OskSupport.dll", "duser.dll", "Accessibility.ni.dll") and
  /* has no impact on rule logic just to avoid OS install related FPs */
  not file.path : ("C:\\Windows\\SoftwareDistribution\\*", "C:\\Windows\\WinSxS\\*")
```



### UAC Bypass Attempt via Windows Directory Masquerading

Branch count: 4  
Document count: 4  
Index: geneve-ut-592

```python
process where event.type in ("start", "process_started") and
  process.args : ("C:\\Windows \\system32\\*.exe", "C:\\Windows \\SysWOW64\\*.exe")
```



### UAC Bypass Attempt with IEditionUpgradeManager Elevated COM Interface

Branch count: 2  
Document count: 2  
Index: geneve-ut-593

```python
process where event.type in ("start", "process_started") and process.name : "Clipup.exe" and
  not process.executable : "C:\\Windows\\System32\\ClipUp.exe" and process.parent.name : "dllhost.exe" and
  /* CLSID of the Elevated COM Interface IEditionUpgradeManager */
  process.parent.args : "/Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}"
```



### UAC Bypass via DiskCleanup Scheduled Task Hijack

Branch count: 1  
Document count: 1  
Index: geneve-ut-594

```python
process where event.type == "start" and
 process.args : "/autoclean" and process.args : "/d" and
 not process.executable : ("C:\\Windows\\System32\\cleanmgr.exe",
                           "C:\\Windows\\SysWOW64\\cleanmgr.exe",
                           "C:\\Windows\\System32\\taskhostw.exe")
```



### UAC Bypass via ICMLuaUtil Elevated COM Interface

Branch count: 4  
Document count: 4  
Index: geneve-ut-595

```python
process where event.type in ("start", "process_started") and
 process.parent.name == "dllhost.exe" and
 process.parent.args in ("/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}", "/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}") and
 process.pe.original_file_name != "WerFault.exe"
```



### UAC Bypass via Windows Firewall Snap-In Hijack

Branch count: 2  
Document count: 2  
Index: geneve-ut-596

```python
process where event.type in ("start", "process_started") and
 process.parent.name == "mmc.exe" and
 /* process.Ext.token.integrity_level_name == "high" can be added in future for tuning */
 /* args of the Windows Firewall SnapIn */
  process.parent.args == "WF.msc" and process.name != "WerFault.exe"
```



### Unauthorized Access to an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-597

```python
event.dataset:okta.system and event.action:app.generic.unauth_app_access_attempt
```



### Unexpected Child Process of macOS Screensaver Engine

Branch count: 1  
Document count: 1  
Index: geneve-ut-599

```python
process where event.type == "start" and process.parent.name == "ScreenSaverEngine"
```



### Unusual Child Process from a System Virtual Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-601

```python
process where event.type in ("start", "process_started") and
  process.parent.pid == 4 and
  not process.executable : ("Registry", "MemCompression", "?:\\Windows\\System32\\smss.exe")
```



### Unusual Child Process of dns.exe

Branch count: 1  
Document count: 1  
Index: geneve-ut-602

```python
process where event.type == "start" and process.parent.name : "dns.exe" and
  not process.name : "conhost.exe"
```



### Unusual Child Processes of RunDLL32

Branch count: 8  
Document count: 16  
Index: geneve-ut-603

```python
sequence with maxspan=1h
  [process where event.type in ("start", "process_started") and
     (process.name : "rundll32.exe" or process.pe.original_file_name == "RUNDLL32.EXE") and
      process.args_count == 1
  ] by process.entity_id
  [process where event.type in ("start", "process_started") and process.parent.name : "rundll32.exe"
  ] by process.parent.entity_id
```



### Unusual Executable File Creation by a System Critical Process

Branch count: 18  
Document count: 18  
Index: geneve-ut-607

```python
file where event.type != "deletion" and
  file.extension : ("exe", "dll") and
  process.name : ("smss.exe",
                  "autochk.exe",
                  "csrss.exe",
                  "wininit.exe",
                  "services.exe",
                  "lsass.exe",
                  "winlogon.exe",
                  "userinit.exe",
                  "LogonUI.exe")
```



### Unusual File Creation - Alternate Data Stream

Branch count: 29  
Document count: 29  
Index: geneve-ut-608

```python
file where event.type == "creation" and
  file.path : "C:\\*:*" and
  not file.path : "C:\\*:zone.identifier*" and
  file.extension :
    (
      "pdf",
      "dll",
      "png",
      "exe",
      "dat",
      "com",
      "bat",
      "cmd",
      "sys",
      "vbs",
      "ps1",
      "hta",
      "txt",
      "vbe",
      "js",
      "wsh",
      "docx",
      "doc",
      "xlsx",
      "xls",
      "pptx",
      "ppt",
      "rtf",
      "gif",
      "jpg",
      "png",
      "bmp",
      "img",
      "iso"
    )
```



### Unusual File Modification by dns.exe

Branch count: 3  
Document count: 3  
Index: geneve-ut-609

```python
file where process.name : "dns.exe" and event.type in ("creation", "deletion", "change") and
  not file.name : "dns.log"
```



### Unusual Network Activity from a Windows System Binary

Branch count: 800  
Document count: 1600  
Index: geneve-ut-622

```python
sequence by process.entity_id with maxspan=5m
  [process where event.type in ("start", "process_started") and

     /* known applocker bypasses */
     (process.name : "bginfo.exe" or
      process.name : "cdb.exe" or
      process.name : "control.exe" or
      process.name : "cmstp.exe" or
      process.name : "csi.exe" or
      process.name : "dnx.exe" or
      process.name : "fsi.exe" or
      process.name : "ieexec.exe" or
      process.name : "iexpress.exe" or
      process.name : "installutil.exe" or
      process.name : "Microsoft.Workflow.Compiler.exe" or
      process.name : "MSBuild.exe" or
      process.name : "msdt.exe" or
      process.name : "mshta.exe" or
      process.name : "msiexec.exe" or
      process.name : "msxsl.exe" or
      process.name : "odbcconf.exe" or
      process.name : "rcsi.exe" or
      process.name : "regsvr32.exe" or
      process.name : "xwizard.exe")]
  [network where
     (process.name : "bginfo.exe" or
      process.name : "cdb.exe" or
      process.name : "control.exe" or
      process.name : "cmstp.exe" or
      process.name : "csi.exe" or
      process.name : "dnx.exe" or
      process.name : "fsi.exe" or
      process.name : "ieexec.exe" or
      process.name : "iexpress.exe" or
      process.name : "installutil.exe" or
      process.name : "Microsoft.Workflow.Compiler.exe" or
      process.name : "MSBuild.exe" or
      process.name : "msdt.exe" or
      process.name : "mshta.exe" or
      process.name : "msiexec.exe" or
      process.name : "msxsl.exe" or
      process.name : "odbcconf.exe" or
      process.name : "rcsi.exe" or
      process.name : "regsvr32.exe" or
      process.name : "xwizard.exe")]
```



### Unusual Network Connection via DllHost

Branch count: 2  
Document count: 4  
Index: geneve-ut-623

```python
sequence by host.id, process.entity_id with maxspan=1m
  [process where event.type in ("start", "process_started") and process.name : "dllhost.exe" and process.args_count == 1]
  [network where process.name : "dllhost.exe" and
   not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
    "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
    "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
    "FF00::/8")]
```



### Unusual Network Connection via RunDLL32

Branch count: 2  
Document count: 4  
Index: geneve-ut-624

```python
sequence by host.id, process.entity_id with maxspan=1m
  [process where event.type in ("start", "process_started") and process.name : "rundll32.exe" and process.args_count == 1]
  [network where process.name : "rundll32.exe" and
   not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
       "FE80::/10", "FF00::/8")]
```



### Unusual Parent Process for cmd.exe

Branch count: 48  
Document count: 48  
Index: geneve-ut-626

```python
process where event.type in ("start", "process_started") and
  process.name : "cmd.exe" and
  process.parent.name : ("lsass.exe",
                         "csrss.exe",
                         "epad.exe",
                         "regsvr32.exe",
                         "dllhost.exe",
                         "LogonUI.exe",
                         "wermgr.exe",
                         "spoolsv.exe",
                         "jucheck.exe",
                         "jusched.exe",
                         "ctfmon.exe",
                         "taskhostw.exe",
                         "GoogleUpdate.exe",
                         "sppsvc.exe",
                         "sihost.exe",
                         "slui.exe",
                         "SIHClient.exe",
                         "SearchIndexer.exe",
                         "SearchProtocolHost.exe",
                         "FlashPlayerUpdateService.exe",
                         "WerFault.exe",
                         "WUDFHost.exe",
                         "unsecapp.exe",
                         "wlanext.exe" )
```



### Unusual Parent-Child Relationship

Branch count: 64  
Document count: 64  
Index: geneve-ut-627

```python
process where event.type in ("start", "process_started") and
process.parent.name != null and
 (
   /* suspicious parent processes */
   (process.name:"autochk.exe" and not process.parent.name:"smss.exe") or
   (process.name:("fontdrvhost.exe", "dwm.exe") and not process.parent.name:("wininit.exe", "winlogon.exe")) or
   (process.name:("consent.exe", "RuntimeBroker.exe", "TiWorker.exe") and not process.parent.name:"svchost.exe") or
   (process.name:"SearchIndexer.exe" and not process.parent.name:"services.exe") or
   (process.name:"SearchProtocolHost.exe" and not process.parent.name:("SearchIndexer.exe", "dllhost.exe")) or
   (process.name:"dllhost.exe" and not process.parent.name:("services.exe", "svchost.exe")) or
   (process.name:"smss.exe" and not process.parent.name:("System", "smss.exe")) or
   (process.name:"csrss.exe" and not process.parent.name:("smss.exe", "svchost.exe")) or
   (process.name:"wininit.exe" and not process.parent.name:"smss.exe") or
   (process.name:"winlogon.exe" and not process.parent.name:"smss.exe") or
   (process.name:("lsass.exe", "LsaIso.exe") and not process.parent.name:"wininit.exe") or
   (process.name:"LogonUI.exe" and not process.parent.name:("wininit.exe", "winlogon.exe")) or
   (process.name:"services.exe" and not process.parent.name:"wininit.exe") or
   (process.name:"svchost.exe" and not process.parent.name:("MsMpEng.exe", "services.exe")) or
   (process.name:"spoolsv.exe" and not process.parent.name:"services.exe") or
   (process.name:"taskhost.exe" and not process.parent.name:("services.exe", "svchost.exe")) or
   (process.name:"taskhostw.exe" and not process.parent.name:("services.exe", "svchost.exe")) or
   (process.name:"userinit.exe" and not process.parent.name:("dwm.exe", "winlogon.exe")) or
   (process.name:("wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe") and not process.parent.name:"svchost.exe") or
   /* suspicious child processes */
   (process.parent.name:("SearchProtocolHost.exe", "taskhost.exe", "csrss.exe") and not process.name:("werfault.exe", "wermgr.exe", "WerFaultSecure.exe")) or
   (process.parent.name:"autochk.exe" and not process.name:("chkdsk.exe", "doskey.exe", "WerFault.exe")) or
   (process.parent.name:"smss.exe" and not process.name:("autochk.exe", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "setupcl.exe", "WerFault.exe")) or
   (process.parent.name:"wermgr.exe" and not process.name:("WerFaultSecure.exe", "wermgr.exe", "WerFault.exe")) or
   (process.parent.name:"conhost.exe" and not process.name:("mscorsvw.exe", "wermgr.exe", "WerFault.exe", "WerFaultSecure.exe"))
  )
```



### Unusual Persistence via Services Registry

Branch count: 4  
Document count: 4  
Index: geneve-ut-628

```python
registry where registry.path : ("HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ServiceDLL", "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath") and
  not registry.data.strings : ("?:\\windows\\system32\\Drivers\\*.sys",
                               "\\SystemRoot\\System32\\drivers\\*.sys",
                               "\\??\\?:\\Windows\\system32\\Drivers\\*.SYS",
                               "system32\\DRIVERS\\USBSTOR") and
  not (process.name : "procexp??.exe" and registry.data.strings : "?:\\*\\procexp*.sys") and
  not process.executable : ("?:\\Program Files\\*.exe",
                            "?:\\Program Files (x86)\\*.exe",
                            "?:\\Windows\\System32\\svchost.exe",
                            "?:\\Windows\\winsxs\\*\\TiWorker.exe",
                            "?:\\Windows\\System32\\drvinst.exe",
                            "?:\\Windows\\System32\\services.exe",
                            "?:\\Windows\\System32\\msiexec.exe",
                            "?:\\Windows\\System32\\regsvr32.exe")
```



### Unusual Print Spooler Child Process

Branch count: 32  
Document count: 32  
Index: geneve-ut-629

```python
process where event.type == "start" and
 process.parent.name : "spoolsv.exe" and
 (?process.Ext.token.integrity_level_name : "System" or
 ?winlog.event_data.IntegrityLevel : "System") and

 /* exclusions for FP control below */
 not process.name : ("splwow64.exe", "PDFCreator.exe", "acrodist.exe", "spoolsv.exe", "msiexec.exe", "route.exe", "WerFault.exe") and
 not process.command_line : "*\\WINDOWS\\system32\\spool\\DRIVERS*" and
 not (process.name : "net.exe" and process.command_line : ("*stop*", "*start*")) and
 not (process.name : ("cmd.exe", "powershell.exe") and process.command_line : ("*.spl*", "*\\program files*", "*route add*")) and
 not (process.name : "netsh.exe" and process.command_line : ("*add portopening*", "*rule name*")) and
 not (process.name : "regsvr32.exe" and process.command_line : "*PrintConfig.dll*")
```



### Unusual Process Execution Path - Alternate Data Stream

Branch count: 1  
Document count: 1  
Index: geneve-ut-630

```python
process where event.type == "start" and
  process.args : "?:\\*:*" and process.args_count == 1
```



### Unusual Process Network Connection

Branch count: 144  
Document count: 288  
Index: geneve-ut-633

```python
sequence by process.entity_id
  [process where (process.name : "Microsoft.Workflow.Compiler.exe" or
                  process.name : "bginfo.exe" or
                  process.name : "cdb.exe" or
                  process.name : "cmstp.exe" or
                  process.name : "csi.exe" or
                  process.name : "dnx.exe" or
                  process.name : "fsi.exe" or
                  process.name : "ieexec.exe" or
                  process.name : "iexpress.exe" or
                  process.name : "odbcconf.exe" or
                  process.name : "rcsi.exe" or
                  process.name : "xwizard.exe") and
     event.type == "start"]
  [network where (process.name : "Microsoft.Workflow.Compiler.exe" or
                  process.name : "bginfo.exe" or
                  process.name : "cdb.exe" or
                  process.name : "cmstp.exe" or
                  process.name : "csi.exe" or
                  process.name : "dnx.exe" or
                  process.name : "fsi.exe" or
                  process.name : "ieexec.exe" or
                  process.name : "iexpress.exe" or
                  process.name : "odbcconf.exe" or
                  process.name : "rcsi.exe" or
                  process.name : "xwizard.exe")]
```



### User Account Creation

Branch count: 8  
Document count: 8  
Index: geneve-ut-647

```python
process where event.type in ("start", "process_started") and
  process.name : ("net.exe", "net1.exe") and
  not process.parent.name : "net.exe" and
  (process.args : "user" and process.args : ("/ad", "/add"))
```



### User Added as Owner for Azure Application

Branch count: 2  
Document count: 2  
Index: geneve-ut-648

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add owner to application" and event.outcome:(Success or success)
```



### User Added as Owner for Azure Service Principal

Branch count: 2  
Document count: 2  
Index: geneve-ut-649

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add owner to service principal" and event.outcome:(Success or success)
```



### User Added to Privileged Group in Active Directory

Branch count: 8  
Document count: 8  
Index: geneve-ut-650

```python
iam where event.action == "added-member-to-group" and
  group.name : ("Admin*",
                "Local Administrators",
                "Domain Admins",
                "Enterprise Admins",
                "Backup Admins",
                "Schema Admins",
                "DnsAdmins",
                "Exchange Organization Administrators")
```



### User account exposed to Kerberoasting

Branch count: 1  
Document count: 1  
Index: geneve-ut-651

```python
event.action:"Directory Service Changes" and event.code:5136 and winlog.event_data.ObjectClass:"user"
and winlog.event_data.AttributeLDAPDisplayName:"servicePrincipalName"
```



### VNC (Virtual Network Computing) from the Internet

Branch count: 6  
Document count: 6  
Index: geneve-ut-652

```python
event.category:(network or network_traffic) and network.transport:tcp and destination.port >= 5800 and destination.port <= 5810 and
  not source.ip:(
    10.0.0.0/8 or
    127.0.0.0/8 or
    169.254.0.0/16 or
    172.16.0.0/12 or
    192.0.0.0/24 or
    192.0.0.0/29 or
    192.0.0.8/32 or
    192.0.0.9/32 or
    192.0.0.10/32 or
    192.0.0.170/32 or
    192.0.0.171/32 or
    192.0.2.0/24 or
    192.31.196.0/24 or
    192.52.193.0/24 or
    192.168.0.0/16 or
    192.88.99.0/24 or
    224.0.0.0/4 or
    100.64.0.0/10 or
    192.175.48.0/24 or
    198.18.0.0/15 or
    198.51.100.0/24 or
    203.0.113.0/24 or
    240.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  ) and
  destination.ip:(
    10.0.0.0/8 or
    172.16.0.0/12 or
    192.168.0.0/16
  )
```



### VNC (Virtual Network Computing) to the Internet

Branch count: 6  
Document count: 6  
Index: geneve-ut-653

```python
event.category:(network or network_traffic) and network.transport:tcp and destination.port >= 5800 and destination.port <= 5810 and
  source.ip:(
    10.0.0.0/8 or
    172.16.0.0/12 or
    192.168.0.0/16
  ) and
  not destination.ip:(
    10.0.0.0/8 or
    127.0.0.0/8 or
    169.254.0.0/16 or
    172.16.0.0/12 or
    192.0.0.0/24 or
    192.0.0.0/29 or
    192.0.0.8/32 or
    192.0.0.9/32 or
    192.0.0.10/32 or
    192.0.0.170/32 or
    192.0.0.171/32 or
    192.0.2.0/24 or
    192.31.196.0/24 or
    192.52.193.0/24 or
    192.168.0.0/16 or
    192.88.99.0/24 or
    224.0.0.0/4 or
    100.64.0.0/10 or
    192.175.48.0/24 or
    198.18.0.0/15 or
    198.51.100.0/24 or
    203.0.113.0/24 or
    240.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  )
```



### Virtual Machine Fingerprinting

Branch count: 10  
Document count: 10  
Index: geneve-ut-654

```python
event.category:process and event.type:(start or process_started) and
  process.args:("/sys/class/dmi/id/bios_version" or
                "/sys/class/dmi/id/product_name" or
                "/sys/class/dmi/id/chassis_vendor" or
                "/proc/scsi/scsi" or
                "/proc/ide/hd0/model") and
  not user.name:root
```



### Virtual Machine Fingerprinting via Grep

Branch count: 6  
Document count: 6  
Index: geneve-ut-655

```python
process where event.type == "start" and
 process.name in ("grep", "egrep") and user.id != "0" and
 process.args : ("parallels*", "vmware*", "virtualbox*") and process.args : "Manufacturer*" and
 not process.parent.executable in ("/Applications/Docker.app/Contents/MacOS/Docker", "/usr/libexec/kcare/virt-what")
```



### Virtual Private Network Connection Attempt

Branch count: 6  
Document count: 6  
Index: geneve-ut-656

```python
process where event.type in ("start", "process_started") and
  (
    (process.name : "networksetup" and process.args : "-connectpppoeservice") or
    (process.name : "scutil" and process.args : "--nc" and process.args : "start") or
    (process.name : "osascript" and process.command_line : "osascript*set VPN to service*")
  )
```



### Volume Shadow Copy Deleted or Resized via VssAdmin

Branch count: 8  
Document count: 8  
Index: geneve-ut-657

```python
process where event.type in ("start", "process_started")
  and (process.name : "vssadmin.exe" or process.pe.original_file_name == "VSSADMIN.EXE") and
  process.args in ("delete", "resize") and process.args : "shadows*"
```



### Volume Shadow Copy Deletion via PowerShell

Branch count: 120  
Document count: 120  
Index: geneve-ut-658

```python
process where event.type in ("start", "process_started") and
  process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and
  process.args : ("*Get-WmiObject*", "*gwmi*", "*Get-CimInstance*", "*gcim*") and
  process.args : ("*Win32_ShadowCopy*") and
  process.args : ("*.Delete()*", "*Remove-WmiObject*", "*rwmi*", "*Remove-CimInstance*", "*rcim*")
```



### Volume Shadow Copy Deletion via WMIC

Branch count: 4  
Document count: 4  
Index: geneve-ut-659

```python
process where event.type in ("start", "process_started") and
  (process.name : "WMIC.exe" or process.pe.original_file_name == "wmic.exe") and
  process.args : "delete" and process.args : "shadowcopy"
```



### WMI Incoming Lateral Movement

Branch count: 4  
Document count: 8  
Index: geneve-ut-660

```python
sequence by host.id with maxspan = 2s

 /* Accepted Incoming RPC connection by Winmgmt service */

  [network where process.name : "svchost.exe" and network.direction : ("incoming", "ingress") and
   source.ip != "127.0.0.1" and source.ip != "::1" and source.port >= 49152 and destination.port >= 49152
  ]

  /* Excluding Common FPs Nessus and SCCM */

  [process where event.type in ("start", "process_started") and process.parent.name : "WmiPrvSE.exe" and
   not process.args : ("C:\\windows\\temp\\nessus_*.txt", 
                       "C:\\windows\\TEMP\\nessus_*.TMP", 
                       "C:\\Windows\\CCM\\SystemTemp\\*", 
                       "C:\\Windows\\CCMCache\\*", 
                       "C:\\CCM\\Cache\\*")
   ]
```



### Web Application Suspicious Activity: No User Agent

Branch count: 1  
Document count: 1  
Index: geneve-ut-661

```python
url.path:*
```



### Web Application Suspicious Activity: POST Request Declined

Branch count: 1  
Document count: 1  
Index: geneve-ut-662

```python
http.response.status_code:403 and http.request.method:post
```



### Web Application Suspicious Activity: Unauthorized Method

Branch count: 1  
Document count: 1  
Index: geneve-ut-663

```python
http.response.status_code:405
```



### Web Application Suspicious Activity: sqlmap User Agent

Branch count: 1  
Document count: 1  
Index: geneve-ut-664

```python
user_agent.original:"sqlmap/1.3.11#stable (http://sqlmap.org)"
```



### WebProxy Settings Modification

Branch count: 3  
Document count: 3  
Index: geneve-ut-665

```python
event.category : process and event.type : start and
 process.name : networksetup and process.args : (("-setwebproxy" or "-setsecurewebproxy" or "-setautoproxyurl") and not (Bluetooth or off)) and
 not process.parent.executable : ("/Library/PrivilegedHelperTools/com.80pct.FreedomHelper" or
                                  "/Applications/Fiddler Everywhere.app/Contents/Resources/app/out/WebServer/Fiddler.WebUi" or
                                  "/usr/libexec/xpcproxy")
```



### WebServer Access Logs Deleted

Branch count: 5  
Document count: 5  
Index: geneve-ut-666

```python
file where event.type == "deletion" and
  file.path : ("C:\\inetpub\\logs\\LogFiles\\*.log",
               "/var/log/apache*/access.log",
               "/etc/httpd/logs/access_log",
               "/var/log/httpd/access_log",
               "/var/www/*/logs/access.log")
```



### Webshell Detection: Script Process Child of Common Web Processes

Branch count: 42  
Document count: 42  
Index: geneve-ut-667

```python
process where event.type == "start" and
  process.parent.name : ("w3wp.exe", "httpd.exe", "nginx.exe", "php.exe", "php-cgi.exe", "tomcat.exe") and
  process.name : ("cmd.exe", "cscript.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "wmic.exe", "wscript.exe")
```



### Whoami Process Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-668

```python
process where event.type in ("start", "process_started") and process.name : "whoami.exe"
```



### Windows Defender Disabled via Registry Modification

Branch count: 12  
Document count: 12  
Index: geneve-ut-670

```python
registry where event.type in ("creation", "change") and
  (
    (
      registry.path:"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware" and
      registry.data.strings: ("1", "0x00000001")
   ) or
   (
      registry.path:"HKLM\\System\\*ControlSet*\\Services\\WinDefend\\Start" and
      registry.data.strings in ("3", "4", "0x00000003", "0x00000004")
   )
  )
```



### Windows Defender Exclusions Added via PowerShell

Branch count: 12  
Document count: 12  
Index: geneve-ut-671

```python
process where event.type == "start" and
 (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or process.pe.original_file_name in ("powershell.exe", "pwsh.dll", "powershell_ise.exe")) and
  process.args : ("*Add-MpPreference*", "*Set-MpPreference*") and
  process.args : ("*-Exclusion*")
```



### Windows Event Logs Cleared

Branch count: 2  
Document count: 2  
Index: geneve-ut-672

```python
event.action:("audit-log-cleared" or "Log clear")
```



### Windows Firewall Disabled via PowerShell

Branch count: 16  
Document count: 16  
Index: geneve-ut-673

```python
process where event.action == "start" and
  (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or process.pe.original_file_name == "PowerShell.EXE") and
   process.args : "*Set-NetFirewallProfile*" and
  (process.args : "*-Enabled*" and process.args : "*False*") and
  (process.args : "*-All*" or process.args : ("*Public*", "*Domain*", "*Private*"))
```



### Windows Network Enumeration

Branch count: 16  
Document count: 16  
Index: geneve-ut-674

```python
process where event.type in ("start", "process_started") and
  ((process.name : "net.exe" or process.pe.original_file_name == "net.exe") or
   ((process.name : "net1.exe" or process.pe.original_file_name == "net1.exe") and
       not process.parent.name : "net.exe")) and
  (process.args : "view" or (process.args : "time" and process.args : "\\\\*"))


  /* expand when ancestry is available
  and not descendant of [process where event.type == ("start", "process_started") and process.name : "cmd.exe" and
                           ((process.parent.name : "userinit.exe") or
                            (process.parent.name : "gpscript.exe") or
                            (process.parent.name : "explorer.exe" and
                               process.args : "C:\\*\\Start Menu\\Programs\\Startup\\*.bat*"))]
  */
```



### Windows Registry File Creation in SMB Share

Branch count: 1  
Document count: 1  
Index: geneve-ut-675

```python
file where event.type == "creation" and
 /* regf file header */
 file.Ext.header_bytes : "72656766*" and file.size >= 30000 and
 process.pid == 4 and user.id : "s-1-5-21*"
```



### Windows Script Executing PowerShell

Branch count: 4  
Document count: 4  
Index: geneve-ut-676

```python
process where event.type in ("start", "process_started") and
  process.parent.name : ("cscript.exe", "wscript.exe") and process.name : "powershell.exe"
```



### Windows Script Interpreter Executing Process via WMI

Branch count: 288  
Document count: 576  
Index: geneve-ut-677

```python
sequence by host.id with maxspan = 5s
    [any where (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
     (dll.name : "wmiutils.dll" or file.name : "wmiutils.dll") and process.name : ("wscript.exe", "cscript.exe")]
    [process where event.type in ("start", "process_started") and
     process.parent.name : "wmiprvse.exe" and
     user.domain != "NT AUTHORITY" and
     (process.pe.original_file_name :
        (
          "cscript.exe",
          "wscript.exe",
          "PowerShell.EXE",
          "Cmd.Exe",
          "MSHTA.EXE",
          "RUNDLL32.EXE",
          "REGSVR32.EXE",
          "MSBuild.exe",
          "InstallUtil.exe",
          "RegAsm.exe",
          "RegSvcs.exe",
          "msxsl.exe",
          "CONTROL.EXE",
          "EXPLORER.EXE",
          "Microsoft.Workflow.Compiler.exe",
          "msiexec.exe"
        ) or
      process.executable : ("C:\\Users\\*.exe", "C:\\ProgramData\\*.exe")
     )
    ]
```



### Windows Service Installed via an Unusual Client

Branch count: 2  
Document count: 2  
Index: geneve-ut-678

```python
event.action:"service-installed"  and (winlog.event_data.ClientProcessId:"0" or winlog.event_data.ParentProcessId:"0")
```



### Zoom Meeting with no Passcode

Branch count: 1  
Document count: 1  
Index: geneve-ut-679

```python
event.type:creation and event.module:zoom and event.dataset:zoom.webhook and
  event.action:meeting.created and not zoom.meeting.password:*
```
