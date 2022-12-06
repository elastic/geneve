# Alerts generation from detection rules

This report captures the detection rules signals generation coverage. Here you can
learn what rules are supported and what not and why.

Curious about the inner workings? Read [here](signals_generation.md).

## Table of contents
   1. [Rules with no signals (5)](#rules-with-no-signals-5)
   1. [Rules with the correct signals (560)](#rules-with-the-correct-signals-560)

## Rules with no signals (5)

### Azure AD Global Administrator Role Assigned

Branch count: 1  
Document count: 1  
Index: geneve-ut-110

```python
event.dataset:azure.auditlogs and azure.auditlogs.properties.category:RoleManagement and
azure.auditlogs.operation_name:"Add member to role" and
azure.auditlogs.properties.target_resources.0.modified_properties.1.new_value:"\"Global Administrator\""
```

```python
[{'event': {'dataset': 'azure.auditlogs'}, 'azure': {'auditlogs': {'properties': {'category': 'RoleManagement', 'target_resources': {'`0`': {'modified_properties': {'`1`': {'new_value': '"Global Administrator"'}}}}}, 'operation_name': 'Add member to role'}}, '@timestamp': 0}]
```



### Azure External Guest User Invitation

Branch count: 2  
Document count: 2  
Index: geneve-ut-127

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Invite external user" and azure.auditlogs.properties.target_resources.*.display_name:guest and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'operation_name': 'Invite external user', 'properties': {'target_resources': {'`*`': {'display_name': 'guest'}}}}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'operation_name': 'Invite external user', 'properties': {'target_resources': {'`*`': {'display_name': 'guest'}}}}}, '@timestamp': 1}]
```



### Azure Full Network Packet Capture Detected

Branch count: 2  
Document count: 2  
Index: geneve-ut-130

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:
    (
        "MICROSOFT.NETWORK/*/STARTPACKETCAPTURE/ACTION" or
        "MICROSOFT.NETWORK/*/VPNCONNECTIONS/STARTPACKETCAPTURE/ACTION" or
        "MICROSOFT.NETWORK/*/PACKETCAPTURES/WRITE"
    ) and 
event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/yXIUtkNIoixTFl/VPNCONNECTIONS/STARTPACKETCAPTURE/ACTION'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/zswuEEXpWqNVR/VPNCONNECTIONS/STARTPACKETCAPTURE/ACTION'}}, '@timestamp': 1}]
```



### Azure Global Administrator Role Addition to PIM User

Branch count: 4  
Document count: 4  
Index: geneve-ut-131

```python
event.dataset:azure.auditlogs and azure.auditlogs.properties.category:RoleManagement and
    azure.auditlogs.operation_name:("Add eligible member to role in PIM completed (permanent)" or
                                    "Add member to role in PIM completed (timebound)") and
    azure.auditlogs.properties.target_resources.*.display_name:"Global Administrator" and
    event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'properties': {'category': 'RoleManagement', 'target_resources': {'`*`': {'display_name': 'Global Administrator'}}}, 'operation_name': 'Add eligible member to role in PIM completed (permanent)'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'properties': {'category': 'RoleManagement', 'target_resources': {'`*`': {'display_name': 'Global Administrator'}}}, 'operation_name': 'Add eligible member to role in PIM completed (permanent)'}}, '@timestamp': 1},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'properties': {'category': 'RoleManagement', 'target_resources': {'`*`': {'display_name': 'Global Administrator'}}}, 'operation_name': 'Add member to role in PIM completed (timebound)'}}, '@timestamp': 2},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'properties': {'category': 'RoleManagement', 'target_resources': {'`*`': {'display_name': 'Global Administrator'}}}, 'operation_name': 'Add member to role in PIM completed (timebound)'}}, '@timestamp': 3}]
```



### LaunchDaemon Creation or Modification and Immediate Loading

Branch count: 4  
Document count: 8  
Index: geneve-ut-290

```python
sequence by host.id with maxspan=1m
 [file where event.type != "deletion" and file.path in ("/System/Library/LaunchDaemons/*", "/Library/LaunchDaemons/*")]
 [process where event.type in ("start", "process_started") and process.name == "launchctl" and process.args == "load"]
```

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'path': '/System/Library/LaunchDaemons/UyyFjSvILOoOHmx'}, 'host': {'id': 'BnL'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'launchctl', 'args': ['load']}, 'host': {'id': 'BnL'}, '@timestamp': 1},
 {'event': {'type': ['eOA'], 'category': ['file']}, 'file': {'path': '/System/Library/LaunchDaemons/gaiFqsyzKNyyQ'}, 'host': {'id': 'DpU'}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'launchctl', 'args': ['load']}, 'host': {'id': 'DpU'}, '@timestamp': 3},
 {'event': {'type': ['EUD'], 'category': ['file']}, 'file': {'path': '/Library/LaunchDaemons/xVTOLWtimrFgT'}, 'host': {'id': 'msh'}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'launchctl', 'args': ['load']}, 'host': {'id': 'msh'}, '@timestamp': 5},
 {'event': {'type': ['CeL'], 'category': ['file']}, 'file': {'path': '/Library/LaunchDaemons/L'}, 'host': {'id': 'Sjo'}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'launchctl', 'args': ['load']}, 'host': {'id': 'Sjo'}, '@timestamp': 7}]
```



## Rules with the correct signals (560)

### AWS Access Secret in Secrets Manager

Branch count: 1  
Document count: 1  
Index: geneve-ut-000

```python
event.dataset:aws.cloudtrail and event.provider:secretsmanager.amazonaws.com and event.action:GetSecretValue
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'secretsmanager.amazonaws.com', 'action': 'GetSecretValue'}, '@timestamp': 0}]
```



### AWS CloudTrail Log Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-001

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:CreateTrail and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'cloudtrail.amazonaws.com', 'action': 'CreateTrail', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS CloudTrail Log Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-002

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:DeleteTrail and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'cloudtrail.amazonaws.com', 'action': 'DeleteTrail', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS CloudTrail Log Suspended

Branch count: 1  
Document count: 1  
Index: geneve-ut-003

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:StopLogging and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'cloudtrail.amazonaws.com', 'action': 'StopLogging', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS CloudTrail Log Updated

Branch count: 1  
Document count: 1  
Index: geneve-ut-004

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:UpdateTrail and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'cloudtrail.amazonaws.com', 'action': 'UpdateTrail', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS CloudWatch Alarm Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-005

```python
event.dataset:aws.cloudtrail and event.provider:monitoring.amazonaws.com and event.action:DeleteAlarms and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'monitoring.amazonaws.com', 'action': 'DeleteAlarms', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS CloudWatch Log Group Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-006

```python
event.dataset:aws.cloudtrail and event.provider:logs.amazonaws.com and event.action:DeleteLogGroup and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'logs.amazonaws.com', 'action': 'DeleteLogGroup', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS CloudWatch Log Stream Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-007

```python
event.dataset:aws.cloudtrail and event.provider:logs.amazonaws.com and event.action:DeleteLogStream and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'logs.amazonaws.com', 'action': 'DeleteLogStream', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS Config Service Tampering

Branch count: 9  
Document count: 9  
Index: geneve-ut-008

```python
event.dataset:aws.cloudtrail and event.provider:config.amazonaws.com and
    event.action:(DeleteConfigRule or DeleteOrganizationConfigRule or DeleteConfigurationAggregator or
    DeleteConfigurationRecorder or DeleteConformancePack or DeleteOrganizationConformancePack or
    DeleteDeliveryChannel or DeleteRemediationConfiguration or DeleteRetentionConfiguration)
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'config.amazonaws.com', 'action': 'DeleteConfigRule'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'config.amazonaws.com', 'action': 'DeleteOrganizationConfigRule'}, '@timestamp': 1},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'config.amazonaws.com', 'action': 'DeleteConfigurationAggregator'}, '@timestamp': 2},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'config.amazonaws.com', 'action': 'DeleteConfigurationRecorder'}, '@timestamp': 3},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'config.amazonaws.com', 'action': 'DeleteConformancePack'}, '@timestamp': 4},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'config.amazonaws.com', 'action': 'DeleteOrganizationConformancePack'}, '@timestamp': 5},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'config.amazonaws.com', 'action': 'DeleteDeliveryChannel'}, '@timestamp': 6},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'config.amazonaws.com', 'action': 'DeleteRemediationConfiguration'}, '@timestamp': 7},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'config.amazonaws.com', 'action': 'DeleteRetentionConfiguration'}, '@timestamp': 8}]
```



### AWS Configuration Recorder Stopped

Branch count: 1  
Document count: 1  
Index: geneve-ut-009

```python
event.dataset:aws.cloudtrail and event.provider:config.amazonaws.com and event.action:StopConfigurationRecorder and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'config.amazonaws.com', 'action': 'StopConfigurationRecorder', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS Deletion of RDS Instance or Cluster

Branch count: 3  
Document count: 3  
Index: geneve-ut-010

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(DeleteDBCluster or DeleteGlobalCluster or DeleteDBInstance) 
and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'rds.amazonaws.com', 'action': 'DeleteDBCluster', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'rds.amazonaws.com', 'action': 'DeleteGlobalCluster', 'outcome': 'success'}, '@timestamp': 1},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'rds.amazonaws.com', 'action': 'DeleteDBInstance', 'outcome': 'success'}, '@timestamp': 2}]
```



### AWS EC2 Encryption Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-011

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:DisableEbsEncryptionByDefault and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'DisableEbsEncryptionByDefault', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS EC2 Flow Log Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-012

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:DeleteFlowLogs and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'DeleteFlowLogs', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS EC2 Full Network Packet Capture Detected

Branch count: 4  
Document count: 4  
Index: geneve-ut-013

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and 
event.action:(CreateTrafficMirrorFilter or CreateTrafficMirrorFilterRule or CreateTrafficMirrorSession or CreateTrafficMirrorTarget) and 
event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'CreateTrafficMirrorFilter', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'CreateTrafficMirrorFilterRule', 'outcome': 'success'}, '@timestamp': 1},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'CreateTrafficMirrorSession', 'outcome': 'success'}, '@timestamp': 2},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'CreateTrafficMirrorTarget', 'outcome': 'success'}, '@timestamp': 3}]
```



### AWS EC2 Network Access Control List Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-014

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(CreateNetworkAcl or CreateNetworkAclEntry) and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'CreateNetworkAcl', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'CreateNetworkAclEntry', 'outcome': 'success'}, '@timestamp': 1}]
```



### AWS EC2 Network Access Control List Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-015

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(DeleteNetworkAcl or DeleteNetworkAclEntry) and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'DeleteNetworkAcl', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'DeleteNetworkAclEntry', 'outcome': 'success'}, '@timestamp': 1}]
```



### AWS EC2 Snapshot Activity

Branch count: 1  
Document count: 1  
Index: geneve-ut-016

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:ModifySnapshotAttribute
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'ModifySnapshotAttribute'}, '@timestamp': 0}]
```



### AWS EC2 VM Export Failure

Branch count: 1  
Document count: 1  
Index: geneve-ut-017

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:CreateInstanceExportTask and event.outcome:failure
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'CreateInstanceExportTask', 'outcome': 'failure'}, '@timestamp': 0}]
```



### AWS EFS File System or Mount Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-018

```python
event.dataset:aws.cloudtrail and event.provider:elasticfilesystem.amazonaws.com and 
event.action:(DeleteMountTarget or DeleteFileSystem) and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'elasticfilesystem.amazonaws.com', 'action': 'DeleteMountTarget', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'elasticfilesystem.amazonaws.com', 'action': 'DeleteFileSystem', 'outcome': 'success'}, '@timestamp': 1}]
```



### AWS ElastiCache Security Group Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-019

```python
event.dataset:aws.cloudtrail and event.provider:elasticache.amazonaws.com and event.action:"Create Cache Security Group" and 
event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'elasticache.amazonaws.com', 'action': 'Create Cache Security Group', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS ElastiCache Security Group Modified or Deleted

Branch count: 5  
Document count: 5  
Index: geneve-ut-020

```python
event.dataset:aws.cloudtrail and event.provider:elasticache.amazonaws.com and event.action:("Delete Cache Security Group" or 
"Authorize Cache Security Group Ingress" or  "Revoke Cache Security Group Ingress" or "AuthorizeCacheSecurityGroupEgress" or 
"RevokeCacheSecurityGroupEgress") and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'elasticache.amazonaws.com', 'action': 'Delete Cache Security Group', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'elasticache.amazonaws.com', 'action': 'Authorize Cache Security Group Ingress', 'outcome': 'success'}, '@timestamp': 1},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'elasticache.amazonaws.com', 'action': 'Revoke Cache Security Group Ingress', 'outcome': 'success'}, '@timestamp': 2},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'elasticache.amazonaws.com', 'action': 'AuthorizeCacheSecurityGroupEgress', 'outcome': 'success'}, '@timestamp': 3},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'elasticache.amazonaws.com', 'action': 'RevokeCacheSecurityGroupEgress', 'outcome': 'success'}, '@timestamp': 4}]
```



### AWS EventBridge Rule Disabled or Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-021

```python
event.dataset:aws.cloudtrail and event.provider:eventbridge.amazonaws.com and event.action:(DeleteRule or DisableRule) and 
event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'eventbridge.amazonaws.com', 'action': 'DeleteRule', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'eventbridge.amazonaws.com', 'action': 'DisableRule', 'outcome': 'success'}, '@timestamp': 1}]
```



### AWS Execution via System Manager

Branch count: 1  
Document count: 1  
Index: geneve-ut-022

```python
event.dataset:aws.cloudtrail and event.provider:ssm.amazonaws.com and event.action:SendCommand and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'ssm.amazonaws.com', 'action': 'SendCommand', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS GuardDuty Detector Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-023

```python
event.dataset:aws.cloudtrail and event.provider:guardduty.amazonaws.com and event.action:DeleteDetector and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'guardduty.amazonaws.com', 'action': 'DeleteDetector', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS IAM Assume Role Policy Update

Branch count: 1  
Document count: 1  
Index: geneve-ut-024

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:UpdateAssumeRolePolicy and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'iam.amazonaws.com', 'action': 'UpdateAssumeRolePolicy', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS IAM Deactivation of MFA Device

Branch count: 2  
Document count: 2  
Index: geneve-ut-026

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:(DeactivateMFADevice or DeleteVirtualMFADevice) and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'iam.amazonaws.com', 'action': 'DeactivateMFADevice', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'iam.amazonaws.com', 'action': 'DeleteVirtualMFADevice', 'outcome': 'success'}, '@timestamp': 1}]
```



### AWS IAM Group Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-027

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:CreateGroup and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'iam.amazonaws.com', 'action': 'CreateGroup', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS IAM Group Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-028

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:DeleteGroup and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'iam.amazonaws.com', 'action': 'DeleteGroup', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS IAM Password Recovery Requested

Branch count: 1  
Document count: 1  
Index: geneve-ut-029

```python
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:PasswordRecoveryRequested and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'signin.amazonaws.com', 'action': 'PasswordRecoveryRequested', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS IAM User Addition to Group

Branch count: 1  
Document count: 1  
Index: geneve-ut-030

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:AddUserToGroup and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'iam.amazonaws.com', 'action': 'AddUserToGroup', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS Management Console Root Login

Branch count: 1  
Document count: 1  
Index: geneve-ut-032

```python
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:ConsoleLogin and aws.cloudtrail.user_identity.type:Root and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'signin.amazonaws.com', 'action': 'ConsoleLogin', 'outcome': 'success'}, 'aws': {'cloudtrail': {'user_identity': {'type': 'Root'}}}, '@timestamp': 0}]
```



### AWS RDS Cluster Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-033

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(CreateDBCluster or CreateGlobalCluster) and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'rds.amazonaws.com', 'action': 'CreateDBCluster', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'rds.amazonaws.com', 'action': 'CreateGlobalCluster', 'outcome': 'success'}, '@timestamp': 1}]
```



### AWS RDS Instance Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-034

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:CreateDBInstance and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'rds.amazonaws.com', 'action': 'CreateDBInstance', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS RDS Instance/Cluster Stoppage

Branch count: 2  
Document count: 2  
Index: geneve-ut-035

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(StopDBCluster or StopDBInstance) and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'rds.amazonaws.com', 'action': 'StopDBCluster', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'rds.amazonaws.com', 'action': 'StopDBInstance', 'outcome': 'success'}, '@timestamp': 1}]
```



### AWS RDS Security Group Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-036

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:CreateDBSecurityGroup and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'rds.amazonaws.com', 'action': 'CreateDBSecurityGroup', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS RDS Security Group Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-037

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:DeleteDBSecurityGroup and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'rds.amazonaws.com', 'action': 'DeleteDBSecurityGroup', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS RDS Snapshot Export

Branch count: 1  
Document count: 1  
Index: geneve-ut-038

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:StartExportTask and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'rds.amazonaws.com', 'action': 'StartExportTask', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS RDS Snapshot Export

Branch count: 1  
Document count: 1  
Index: geneve-ut-039

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:StartExportTask and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'rds.amazonaws.com', 'action': 'StartExportTask', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS RDS Snapshot Restored

Branch count: 1  
Document count: 1  
Index: geneve-ut-040

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:RestoreDBInstanceFromDBSnapshot and
event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'rds.amazonaws.com', 'action': 'RestoreDBInstanceFromDBSnapshot', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS Root Login Without MFA

Branch count: 1  
Document count: 1  
Index: geneve-ut-041

```python
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:ConsoleLogin and
  aws.cloudtrail.user_identity.type:Root and
  aws.cloudtrail.console_login.additional_eventdata.mfa_used:false and
  event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'signin.amazonaws.com', 'action': 'ConsoleLogin', 'outcome': 'success'}, 'aws': {'cloudtrail': {'user_identity': {'type': 'Root'}, 'console_login': {'additional_eventdata': {'mfa_used': False}}}}, '@timestamp': 0}]
```



### AWS Route 53 Domain Transfer Lock Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-042

```python
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:DisableDomainTransferLock and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'route53.amazonaws.com', 'action': 'DisableDomainTransferLock', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS Route 53 Domain Transferred to Another Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-043

```python
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:TransferDomainToAnotherAwsAccount and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'route53.amazonaws.com', 'action': 'TransferDomainToAnotherAwsAccount', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS Route Table Created

Branch count: 2  
Document count: 2  
Index: geneve-ut-044

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:(CreateRoute or CreateRouteTable) and 
event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'cloudtrail.amazonaws.com', 'action': 'CreateRoute', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'cloudtrail.amazonaws.com', 'action': 'CreateRouteTable', 'outcome': 'success'}, '@timestamp': 1}]
```



### AWS Route Table Modified or Deleted

Branch count: 5  
Document count: 5  
Index: geneve-ut-045

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:(ReplaceRoute or ReplaceRouteTableAssociation or
DeleteRouteTable or DeleteRoute or DisassociateRouteTable) and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'cloudtrail.amazonaws.com', 'action': 'ReplaceRoute', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'cloudtrail.amazonaws.com', 'action': 'ReplaceRouteTableAssociation', 'outcome': 'success'}, '@timestamp': 1},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'cloudtrail.amazonaws.com', 'action': 'DeleteRouteTable', 'outcome': 'success'}, '@timestamp': 2},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'cloudtrail.amazonaws.com', 'action': 'DeleteRoute', 'outcome': 'success'}, '@timestamp': 3},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'cloudtrail.amazonaws.com', 'action': 'DisassociateRouteTable', 'outcome': 'success'}, '@timestamp': 4}]
```



### AWS Route53 private hosted zone associated with a VPC

Branch count: 1  
Document count: 1  
Index: geneve-ut-046

```python
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:AssociateVPCWithHostedZone and 
event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'route53.amazonaws.com', 'action': 'AssociateVPCWithHostedZone', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS S3 Bucket Configuration Deletion

Branch count: 5  
Document count: 5  
Index: geneve-ut-047

```python
event.dataset:aws.cloudtrail and event.provider:s3.amazonaws.com and
  event.action:(DeleteBucketPolicy or DeleteBucketReplication or DeleteBucketCors or
                DeleteBucketEncryption or DeleteBucketLifecycle)
  and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 's3.amazonaws.com', 'action': 'DeleteBucketPolicy', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 's3.amazonaws.com', 'action': 'DeleteBucketReplication', 'outcome': 'success'}, '@timestamp': 1},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 's3.amazonaws.com', 'action': 'DeleteBucketCors', 'outcome': 'success'}, '@timestamp': 2},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 's3.amazonaws.com', 'action': 'DeleteBucketEncryption', 'outcome': 'success'}, '@timestamp': 3},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 's3.amazonaws.com', 'action': 'DeleteBucketLifecycle', 'outcome': 'success'}, '@timestamp': 4}]
```



### AWS SAML Activity

Branch count: 4  
Document count: 4  
Index: geneve-ut-048

```python
event.dataset:aws.cloudtrail and event.provider:(iam.amazonaws.com or sts.amazonaws.com) and event.action:(Assumerolewithsaml or 
UpdateSAMLProvider) and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'iam.amazonaws.com', 'action': 'Assumerolewithsaml', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'iam.amazonaws.com', 'action': 'UpdateSAMLProvider', 'outcome': 'success'}, '@timestamp': 1},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'sts.amazonaws.com', 'action': 'Assumerolewithsaml', 'outcome': 'success'}, '@timestamp': 2},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'sts.amazonaws.com', 'action': 'UpdateSAMLProvider', 'outcome': 'success'}, '@timestamp': 3}]
```



### AWS STS GetSessionToken Abuse

Branch count: 1  
Document count: 1  
Index: geneve-ut-049

```python
event.dataset:aws.cloudtrail and event.provider:sts.amazonaws.com and event.action:GetSessionToken and 
aws.cloudtrail.user_identity.type:IAMUser and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'sts.amazonaws.com', 'action': 'GetSessionToken', 'outcome': 'success'}, 'aws': {'cloudtrail': {'user_identity': {'type': 'IAMUser'}}}, '@timestamp': 0}]
```



### AWS Security Group Configuration Change Detection

Branch count: 6  
Document count: 6  
Index: geneve-ut-050

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(AuthorizeSecurityGroupEgress or 
CreateSecurityGroup or ModifyInstanceAttribute or ModifySecurityGroupRules or RevokeSecurityGroupEgress or 
RevokeSecurityGroupIngress) and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'AuthorizeSecurityGroupEgress', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'CreateSecurityGroup', 'outcome': 'success'}, '@timestamp': 1},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'ModifyInstanceAttribute', 'outcome': 'success'}, '@timestamp': 2},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'ModifySecurityGroupRules', 'outcome': 'success'}, '@timestamp': 3},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'RevokeSecurityGroupEgress', 'outcome': 'success'}, '@timestamp': 4},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'ec2.amazonaws.com', 'action': 'RevokeSecurityGroupIngress', 'outcome': 'success'}, '@timestamp': 5}]
```



### AWS Security Token Service (STS) AssumeRole Usage

Branch count: 1  
Document count: 1  
Index: geneve-ut-051

```python
event.dataset:aws.cloudtrail and event.provider:sts.amazonaws.com and event.action:AssumedRole and 
aws.cloudtrail.user_identity.session_context.session_issuer.type:Role and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'sts.amazonaws.com', 'action': 'AssumedRole', 'outcome': 'success'}, 'aws': {'cloudtrail': {'user_identity': {'session_context': {'session_issuer': {'type': 'Role'}}}}}, '@timestamp': 0}]
```



### AWS WAF Access Control List Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-052

```python
event.dataset:aws.cloudtrail and event.action:DeleteWebACL and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'action': 'DeleteWebACL', 'outcome': 'success'}, '@timestamp': 0}]
```



### AWS WAF Rule or Rule Group Deletion

Branch count: 6  
Document count: 6  
Index: geneve-ut-053

```python
event.dataset:aws.cloudtrail and event.provider:(waf.amazonaws.com or waf-regional.amazonaws.com or wafv2.amazonaws.com) and event.action:(DeleteRule or DeleteRuleGroup) and event.outcome:success
```

```python
[{'event': {'dataset': 'aws.cloudtrail', 'provider': 'waf.amazonaws.com', 'action': 'DeleteRule', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'waf.amazonaws.com', 'action': 'DeleteRuleGroup', 'outcome': 'success'}, '@timestamp': 1},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'waf-regional.amazonaws.com', 'action': 'DeleteRule', 'outcome': 'success'}, '@timestamp': 2},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'waf-regional.amazonaws.com', 'action': 'DeleteRuleGroup', 'outcome': 'success'}, '@timestamp': 3},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'wafv2.amazonaws.com', 'action': 'DeleteRule', 'outcome': 'success'}, '@timestamp': 4},
 {'event': {'dataset': 'aws.cloudtrail', 'provider': 'wafv2.amazonaws.com', 'action': 'DeleteRuleGroup', 'outcome': 'success'}, '@timestamp': 5}]
```



### Abnormally Large DNS Response

Branch count: 6  
Document count: 6  
Index: geneve-ut-054

```python
event.category:(network or network_traffic) and destination.port:53 and
  (event.dataset:zeek.dns or type:dns or event.type:connection) and network.bytes > 60000
```

```python
[{'event': {'category': ['network'], 'dataset': 'zeek.dns'}, 'destination': {'port': 53}, 'network': {'bytes': 4289315490}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'destination': {'port': 53}, 'type': 'dns', 'network': {'bytes': 3844421733}, '@timestamp': 1},
 {'event': {'category': ['network'], 'type': ['connection']}, 'destination': {'port': 53}, 'network': {'bytes': 2633854608}, '@timestamp': 2},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.dns'}, 'destination': {'port': 53}, 'network': {'bytes': 3734515522}, '@timestamp': 3},
 {'event': {'category': ['network_traffic']}, 'destination': {'port': 53}, 'type': 'dns', 'network': {'bytes': 2043283025}, '@timestamp': 4},
 {'event': {'category': ['network_traffic'], 'type': ['connection']}, 'destination': {'port': 53}, 'network': {'bytes': 1797270498}, '@timestamp': 5}]
```



### Access of Stored Browser Credentials

Branch count: 2  
Document count: 2  
Index: geneve-ut-055

```python
process where event.type in ("start", "process_started") and
  process.args :
    (
      "/Users/*/Library/Application Support/Google/Chrome/Default/Login Data", 
      "/Users/*/Library/Application Support/Google/Chrome/Default/Cookies", 
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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['/Users/*/Library/Application Support/Google/Chrome/Default/Login Data', '/Users/*/Library/Application Support/Google/Chrome/Default/Cookies', '/Users/*/Library/Cookies*', '/Users/*/Library/Application Support/Firefox/Profiles/*.default/cookies.sqlite', '/Users/*/Library/Application Support/Firefox/Profiles/*.default/key*.db', '/Users/*/Library/Application Support/Firefox/Profiles/*.default/logins.json', 'Login Data', 'Cookies.binarycookies', 'key4.db', 'key3.db', 'logins.json', 'cookies.sqlite']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'args': ['/Users/*/Library/Application Support/Google/Chrome/Default/Login Data', '/Users/*/Library/Application Support/Google/Chrome/Default/Cookies', '/Users/*/Library/Cookies*', '/Users/*/Library/Application Support/Firefox/Profiles/*.default/cookies.sqlite', '/Users/*/Library/Application Support/Firefox/Profiles/*.default/key*.db', '/Users/*/Library/Application Support/Firefox/Profiles/*.default/logins.json', 'Login Data', 'Cookies.binarycookies', 'key4.db', 'key3.db', 'logins.json', 'cookies.sqlite']}, '@timestamp': 1}]
```



### Access to Keychain Credentials Directories

Branch count: 2  
Document count: 2  
Index: geneve-ut-056

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
    not process.parent.executable : "/Applications/OpenVPN Connect/OpenVPN Connect.app/Contents/MacOS/OpenVPN Connect"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['/Users/*/Library/Keychains/*', '/Library/Keychains/*', '/Network/Library/Keychains/*', 'System.keychain', 'login.keychain-db', 'login.keychain'], 'parent': {'executable': 'ZFy'}}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'args': ['/Users/*/Library/Keychains/*', '/Library/Keychains/*', '/Network/Library/Keychains/*', 'System.keychain', 'login.keychain-db', 'login.keychain'], 'parent': {'executable': 'XIU'}}, '@timestamp': 1}]
```



### Account Discovery Command via SYSTEM Account

Branch count: 8  
Document count: 8  
Index: geneve-ut-057

```python
process where event.type in ("start", "process_started") and 
  (?process.Ext.token.integrity_level_name : "System" or
  ?winlog.event_data.IntegrityLevel : "System") and
  (process.name : "whoami.exe" or
  (process.name : "net1.exe" and not process.parent.name : "net.exe"))
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'Ext': {'token': {'integrity_level_name': 'System'}}, 'name': 'whoami.exe'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'Ext': {'token': {'integrity_level_name': 'System'}}, 'name': 'net1.exe', 'parent': {'name': 'ZFy'}}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'winlog': {'event_data': {'IntegrityLevel': 'System'}}, 'process': {'name': 'whoami.exe'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'winlog': {'event_data': {'IntegrityLevel': 'System'}}, 'process': {'name': 'net1.exe', 'parent': {'name': 'XIU'}}, '@timestamp': 3},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'Ext': {'token': {'integrity_level_name': 'System'}}, 'name': 'whoami.exe'}, '@timestamp': 4},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'Ext': {'token': {'integrity_level_name': 'System'}}, 'name': 'net1.exe', 'parent': {'name': 'tkN'}}, '@timestamp': 5},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'winlog': {'event_data': {'IntegrityLevel': 'System'}}, 'process': {'name': 'whoami.exe'}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'winlog': {'event_data': {'IntegrityLevel': 'System'}}, 'process': {'name': 'net1.exe', 'parent': {'name': 'Ioi'}}, '@timestamp': 7}]
```



### Account Password Reset Remotely

Branch count: 1  
Document count: 2  
Index: geneve-ut-058

```python
sequence by host.id with maxspan=5m
  [authentication where event.action == "logged-in" and
    /* event 4624 need to be logged */
    winlog.logon.type : "Network" and event.outcome == "success" and source.ip != null and
    source.ip != "127.0.0.1" and source.ip != "::1"] by winlog.event_data.TargetLogonId
   /* event 4724 need to be logged */
  [iam where event.action == "reset-password"] by winlog.event_data.SubjectLogonId
```

```python
[{'event': {'action': 'logged-in', 'outcome': 'success', 'category': ['authentication']}, 'winlog': {'logon': {'type': 'Network'}, 'event_data': {'TargetLogonId': 'yFj'}}, 'source': {'ip': 'aa79:ec58:8d14:2981:f18d:f2a6:6b1f:4182'}, 'host': {'id': 'fUy'}, '@timestamp': 0},
 {'event': {'action': 'reset-password', 'category': ['iam']}, 'host': {'id': 'fUy'}, 'winlog': {'event_data': {'SubjectLogonId': 'yFj'}}, '@timestamp': 1}]
```



### AdFind Command Activity

Branch count: 4  
Document count: 4  
Index: geneve-ut-060

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'AdFind.exe', 'args': ['objectcategory=computer', '(objectcategory=computer)', 'objectcategory=person', '(objectcategory=person)', 'objectcategory=subnet', '(objectcategory=subnet)', 'objectcategory=group', '(objectcategory=group)', 'objectcategory=organizationalunit', '(objectcategory=organizationalunit)', 'objectcategory=attributeschema', '(objectcategory=attributeschema)', 'domainlist', 'dcmodes', 'adinfo', 'dclist', 'computers_pwnotreqd', 'trustdmp']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'AdFind.exe'}, 'args': ['objectcategory=computer', '(objectcategory=computer)', 'objectcategory=person', '(objectcategory=person)', 'objectcategory=subnet', '(objectcategory=subnet)', 'objectcategory=group', '(objectcategory=group)', 'objectcategory=organizationalunit', '(objectcategory=organizationalunit)', 'objectcategory=attributeschema', '(objectcategory=attributeschema)', 'domainlist', 'dcmodes', 'adinfo', 'dclist', 'computers_pwnotreqd', 'trustdmp']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'AdFind.exe', 'args': ['objectcategory=computer', '(objectcategory=computer)', 'objectcategory=person', '(objectcategory=person)', 'objectcategory=subnet', '(objectcategory=subnet)', 'objectcategory=group', '(objectcategory=group)', 'objectcategory=organizationalunit', '(objectcategory=organizationalunit)', 'objectcategory=attributeschema', '(objectcategory=attributeschema)', 'domainlist', 'dcmodes', 'adinfo', 'dclist', 'computers_pwnotreqd', 'trustdmp']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'AdFind.exe'}, 'args': ['objectcategory=computer', '(objectcategory=computer)', 'objectcategory=person', '(objectcategory=person)', 'objectcategory=subnet', '(objectcategory=subnet)', 'objectcategory=group', '(objectcategory=group)', 'objectcategory=organizationalunit', '(objectcategory=organizationalunit)', 'objectcategory=attributeschema', '(objectcategory=attributeschema)', 'domainlist', 'dcmodes', 'adinfo', 'dclist', 'computers_pwnotreqd', 'trustdmp']}, '@timestamp': 3}]
```



### Adding Hidden File Attribute via Attrib

Branch count: 2  
Document count: 2  
Index: geneve-ut-061

```python
process where event.type in ("start", "process_started") and
  process.name : "attrib.exe" and process.args : "+h"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'attrib.exe', 'args': ['+h']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'attrib.exe', 'args': ['+h']}, '@timestamp': 1}]
```



### AdminSDHolder Backdoor

Branch count: 1  
Document count: 1  
Index: geneve-ut-062

```python
event.action:"Directory Service Changes" and event.code:5136 and winlog.event_data.ObjectDN:CN=AdminSDHolder,CN=System*
```

```python
[{'event': {'action': 'Directory Service Changes', 'code': 5136}, 'winlog': {'event_data': {'ObjectDN': 'CN=AdminSDHolder,CN=SystemXIUtkNI'}}, '@timestamp': 0}]
```



### Administrator Privileges Assigned to an Okta Group

Branch count: 1  
Document count: 1  
Index: geneve-ut-064

```python
event.dataset:okta.system and event.action:group.privilege.grant
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'group.privilege.grant'}, '@timestamp': 0}]
```



### Administrator Role Assigned to an Okta User

Branch count: 1  
Document count: 1  
Index: geneve-ut-065

```python
event.dataset:okta.system and event.action:user.account.privilege.grant
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'user.account.privilege.grant'}, '@timestamp': 0}]
```



### Adobe Hijack Persistence

Branch count: 1  
Document count: 1  
Index: geneve-ut-066

```python
file where event.type == "creation" and
  file.path : ("?:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe",
               "?:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe") and
  not process.name : "msiexec.exe"
```

```python
[{'event': {'type': ['creation'], 'category': ['file']}, 'file': {'path': 'A:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe'}, 'process': {'name': 'XIU'}, '@timestamp': 0}]
```



### Adversary Behavior - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-067

```python
event.kind:alert and event.module:endgame and (event.action:rules_engine_event or endgame.event_subtype_full:rules_engine_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'rules_engine_event'}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'event_subtype_full': 'rules_engine_event'}, '@timestamp': 1}]
```



### Agent Spoofing - Mismatched Agent ID

Branch count: 1  
Document count: 1  
Index: geneve-ut-068

```python
event.agent_id_status:agent_id_mismatch
```

```python
[{'event': {'agent_id_status': 'agent_id_mismatch'}, '@timestamp': 0}]
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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'osascript', 'entity_id': 'XIU'}, 'host': {'id': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['tkN'], 'category': ['network']}, 'process': {'name': 'osascript', 'entity_id': 'XIU'}, 'destination': {'ip': '48.35.95.170'}, 'host': {'id': 'ZFy'}, '@timestamp': 1}]
```



### Application Added to Google Workspace Domain

Branch count: 1  
Document count: 1  
Index: geneve-ut-077

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:ADD_APPLICATION
```

```python
[{'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'ADD_APPLICATION'}, '@timestamp': 0}]
```



### Attempt to Create Okta API Token

Branch count: 1  
Document count: 1  
Index: geneve-ut-078

```python
event.dataset:okta.system and event.action:system.api_token.create
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'system.api_token.create'}, '@timestamp': 0}]
```



### Attempt to Deactivate MFA for an Okta User Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-079

```python
event.dataset:okta.system and event.action:user.mfa.factor.deactivate
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'user.mfa.factor.deactivate'}, '@timestamp': 0}]
```



### Attempt to Deactivate an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-080

```python
event.dataset:okta.system and event.action:application.lifecycle.deactivate
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'application.lifecycle.deactivate'}, '@timestamp': 0}]
```



### Attempt to Deactivate an Okta Network Zone

Branch count: 1  
Document count: 1  
Index: geneve-ut-081

```python
event.dataset:okta.system and event.action:zone.deactivate
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'zone.deactivate'}, '@timestamp': 0}]
```



### Attempt to Deactivate an Okta Policy

Branch count: 1  
Document count: 1  
Index: geneve-ut-082

```python
event.dataset:okta.system and event.action:policy.lifecycle.deactivate
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'policy.lifecycle.deactivate'}, '@timestamp': 0}]
```



### Attempt to Deactivate an Okta Policy Rule

Branch count: 1  
Document count: 1  
Index: geneve-ut-083

```python
event.dataset:okta.system and event.action:policy.rule.deactivate
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'policy.rule.deactivate'}, '@timestamp': 0}]
```



### Attempt to Delete an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-084

```python
event.dataset:okta.system and event.action:application.lifecycle.delete
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'application.lifecycle.delete'}, '@timestamp': 0}]
```



### Attempt to Delete an Okta Network Zone

Branch count: 1  
Document count: 1  
Index: geneve-ut-085

```python
event.dataset:okta.system and event.action:zone.delete
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'zone.delete'}, '@timestamp': 0}]
```



### Attempt to Delete an Okta Policy

Branch count: 1  
Document count: 1  
Index: geneve-ut-086

```python
event.dataset:okta.system and event.action:policy.lifecycle.delete
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'policy.lifecycle.delete'}, '@timestamp': 0}]
```



### Attempt to Delete an Okta Policy Rule

Branch count: 1  
Document count: 1  
Index: geneve-ut-087

```python
event.dataset:okta.system and event.action:policy.rule.delete
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'policy.rule.delete'}, '@timestamp': 0}]
```



### Attempt to Disable Gatekeeper

Branch count: 2  
Document count: 2  
Index: geneve-ut-088

```python
event.category:process and event.type:(start or process_started) and 
  process.args:(spctl and "--master-disable")
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['spctl', '--master-disable']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'args': ['spctl', '--master-disable']}, '@timestamp': 1}]
```



### Attempt to Disable IPTables or Firewall

Branch count: 21  
Document count: 21  
Index: geneve-ut-089

```python
event.category:process and event.type:(start or process_started) and
  process.name:ufw and process.args:(allow or disable or reset) or

  (((process.name:service and process.args:stop) or
     (process.name:chkconfig and process.args:off) or
     (process.name:systemctl and process.args:(disable or stop or kill))) and
   process.args:(firewalld or ip6tables or iptables))
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'ufw', 'args': ['allow']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'ufw', 'args': ['disable']}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'ufw', 'args': ['reset']}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'ufw', 'args': ['allow']}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'ufw', 'args': ['disable']}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'ufw', 'args': ['reset']}, '@timestamp': 5},
 {'process': {'name': 'service', 'args': ['stop', 'firewalld']}, '@timestamp': 6},
 {'process': {'name': 'service', 'args': ['stop', 'ip6tables']}, '@timestamp': 7},
 {'process': {'name': 'service', 'args': ['stop', 'iptables']}, '@timestamp': 8},
 {'process': {'name': 'chkconfig', 'args': ['off', 'firewalld']}, '@timestamp': 9},
 {'process': {'name': 'chkconfig', 'args': ['off', 'ip6tables']}, '@timestamp': 10},
 {'process': {'name': 'chkconfig', 'args': ['off', 'iptables']}, '@timestamp': 11},
 {'process': {'name': 'systemctl', 'args': ['disable', 'firewalld']}, '@timestamp': 12},
 {'process': {'name': 'systemctl', 'args': ['disable', 'ip6tables']}, '@timestamp': 13},
 {'process': {'name': 'systemctl', 'args': ['disable', 'iptables']}, '@timestamp': 14},
 {'process': {'name': 'systemctl', 'args': ['stop', 'firewalld']}, '@timestamp': 15},
 {'process': {'name': 'systemctl', 'args': ['stop', 'ip6tables']}, '@timestamp': 16},
 {'process': {'name': 'systemctl', 'args': ['stop', 'iptables']}, '@timestamp': 17},
 {'process': {'name': 'systemctl', 'args': ['kill', 'firewalld']}, '@timestamp': 18},
 {'process': {'name': 'systemctl', 'args': ['kill', 'ip6tables']}, '@timestamp': 19},
 {'process': {'name': 'systemctl', 'args': ['kill', 'iptables']}, '@timestamp': 20}]
```



### Attempt to Disable Syslog Service

Branch count: 30  
Document count: 30  
Index: geneve-ut-090

```python
event.category:process and event.type:(start or process_started) and
  ((process.name:service and process.args:stop) or
     (process.name:chkconfig and process.args:off) or
     (process.name:systemctl and process.args:(disable or stop or kill)))
  and process.args:(syslog or rsyslog or "syslog-ng")
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'service', 'args': ['stop', 'syslog']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'service', 'args': ['stop', 'rsyslog']}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'service', 'args': ['stop', 'syslog-ng']}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chkconfig', 'args': ['off', 'syslog']}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chkconfig', 'args': ['off', 'rsyslog']}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chkconfig', 'args': ['off', 'syslog-ng']}, '@timestamp': 5},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'systemctl', 'args': ['disable', 'syslog']}, '@timestamp': 6},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'systemctl', 'args': ['disable', 'rsyslog']}, '@timestamp': 7},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'systemctl', 'args': ['disable', 'syslog-ng']}, '@timestamp': 8},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'systemctl', 'args': ['stop', 'syslog']}, '@timestamp': 9},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'systemctl', 'args': ['stop', 'rsyslog']}, '@timestamp': 10},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'systemctl', 'args': ['stop', 'syslog-ng']}, '@timestamp': 11},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'systemctl', 'args': ['kill', 'syslog']}, '@timestamp': 12},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'systemctl', 'args': ['kill', 'rsyslog']}, '@timestamp': 13},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'systemctl', 'args': ['kill', 'syslog-ng']}, '@timestamp': 14},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'service', 'args': ['stop', 'syslog']}, '@timestamp': 15},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'service', 'args': ['stop', 'rsyslog']}, '@timestamp': 16},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'service', 'args': ['stop', 'syslog-ng']}, '@timestamp': 17},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chkconfig', 'args': ['off', 'syslog']}, '@timestamp': 18},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chkconfig', 'args': ['off', 'rsyslog']}, '@timestamp': 19},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chkconfig', 'args': ['off', 'syslog-ng']}, '@timestamp': 20},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'systemctl', 'args': ['disable', 'syslog']}, '@timestamp': 21},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'systemctl', 'args': ['disable', 'rsyslog']}, '@timestamp': 22},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'systemctl', 'args': ['disable', 'syslog-ng']}, '@timestamp': 23},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'systemctl', 'args': ['stop', 'syslog']}, '@timestamp': 24},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'systemctl', 'args': ['stop', 'rsyslog']}, '@timestamp': 25},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'systemctl', 'args': ['stop', 'syslog-ng']}, '@timestamp': 26},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'systemctl', 'args': ['kill', 'syslog']}, '@timestamp': 27},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'systemctl', 'args': ['kill', 'rsyslog']}, '@timestamp': 28},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'systemctl', 'args': ['kill', 'syslog-ng']}, '@timestamp': 29}]
```



### Attempt to Enable the Root Account

Branch count: 2  
Document count: 2  
Index: geneve-ut-091

```python
event.category:process and event.type:(start or process_started) and
 process.name:dsenableroot and not process.args:"-d"
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'dsenableroot', 'args': ['ZFy']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'dsenableroot', 'args': ['XIU']}, '@timestamp': 1}]
```



### Attempt to Install Root Certificate

Branch count: 2  
Document count: 2  
Index: geneve-ut-092

```python
event.category:process and event.type:(start or process_started) and
  process.name:security and process.args:"add-trusted-cert"
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'security', 'args': ['add-trusted-cert']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'security', 'args': ['add-trusted-cert']}, '@timestamp': 1}]
```



### Attempt to Modify an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-093

```python
event.dataset:okta.system and event.action:application.lifecycle.update
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'application.lifecycle.update'}, '@timestamp': 0}]
```



### Attempt to Modify an Okta Network Zone

Branch count: 3  
Document count: 3  
Index: geneve-ut-094

```python
event.dataset:okta.system and event.action:(zone.update or network_zone.rule.disabled or zone.remove_blacklist)
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'zone.update'}, '@timestamp': 0},
 {'event': {'dataset': 'okta.system', 'action': 'network_zone.rule.disabled'}, '@timestamp': 1},
 {'event': {'dataset': 'okta.system', 'action': 'zone.remove_blacklist'}, '@timestamp': 2}]
```



### Attempt to Modify an Okta Policy

Branch count: 1  
Document count: 1  
Index: geneve-ut-095

```python
event.dataset:okta.system and event.action:policy.lifecycle.update
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'policy.lifecycle.update'}, '@timestamp': 0}]
```



### Attempt to Modify an Okta Policy Rule

Branch count: 1  
Document count: 1  
Index: geneve-ut-096

```python
event.dataset:okta.system and event.action:policy.rule.update
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'policy.rule.update'}, '@timestamp': 0}]
```



### Attempt to Reset MFA Factors for an Okta User Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-099

```python
event.dataset:okta.system and event.action:user.mfa.factor.reset_all
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'user.mfa.factor.reset_all'}, '@timestamp': 0}]
```



### Attempt to Revoke Okta API Token

Branch count: 1  
Document count: 1  
Index: geneve-ut-100

```python
event.dataset:okta.system and event.action:system.api_token.revoke
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'system.api_token.revoke'}, '@timestamp': 0}]
```



### Attempt to Unload Elastic Endpoint Security Kernel Extension

Branch count: 4  
Document count: 4  
Index: geneve-ut-101

```python
event.category:process and event.type:(start or process_started) and
 process.name:kextunload and process.args:("/System/Library/Extensions/EndpointSecurity.kext" or "EndpointSecurity.kext")
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'kextunload', 'args': ['/System/Library/Extensions/EndpointSecurity.kext']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'kextunload', 'args': ['EndpointSecurity.kext']}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'kextunload', 'args': ['/System/Library/Extensions/EndpointSecurity.kext']}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'kextunload', 'args': ['EndpointSecurity.kext']}, '@timestamp': 3}]
```



### Attempted Bypass of Okta MFA

Branch count: 1  
Document count: 1  
Index: geneve-ut-102

```python
event.dataset:okta.system and event.action:user.mfa.attempt_bypass
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'user.mfa.attempt_bypass'}, '@timestamp': 0}]
```



### Auditd Login Attempt at Forbidden Time

Branch count: 1  
Document count: 1  
Index: geneve-ut-105

```python
event.module:auditd and event.action:"attempted-log-in-during-unusual-hour-to"
```

```python
[{'event': {'module': 'auditd', 'action': 'attempted-log-in-during-unusual-hour-to'}, '@timestamp': 0}]
```



### Auditd Login from Forbidden Location

Branch count: 1  
Document count: 1  
Index: geneve-ut-106

```python
event.module:auditd and event.action:"attempted-log-in-from-unusual-place-to"
```

```python
[{'event': {'module': 'auditd', 'action': 'attempted-log-in-from-unusual-place-to'}, '@timestamp': 0}]
```



### Auditd Max Failed Login Attempts

Branch count: 1  
Document count: 1  
Index: geneve-ut-107

```python
event.module:auditd and event.action:"failed-log-in-too-many-times-to"
```

```python
[{'event': {'module': 'auditd', 'action': 'failed-log-in-too-many-times-to'}, '@timestamp': 0}]
```



### Auditd Max Login Sessions

Branch count: 1  
Document count: 1  
Index: geneve-ut-108

```python
event.module:auditd and event.action:"opened-too-many-sessions-to"
```

```python
[{'event': {'module': 'auditd', 'action': 'opened-too-many-sessions-to'}, '@timestamp': 0}]
```



### Authorization Plugin Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-109

```python
event.category:file and not event.type:deletion and
  file.path:(/Library/Security/SecurityAgentPlugins/* and
  not /Library/Security/SecurityAgentPlugins/TeamViewerAuthPlugin.bundle/Contents/*)
```

```python
[{'event': {'category': ['file'], 'type': ['ZFy']}, 'file': {'path': '/Library/Security/SecurityAgentPlugins/UyyFjSvILOoOHmx'}, '@timestamp': 0}]
```



### Azure Active Directory High Risk Sign-in

Branch count: 4  
Document count: 4  
Index: geneve-ut-111

```python
event.dataset:azure.signinlogs and
  (azure.signinlogs.properties.risk_level_during_signin:high or azure.signinlogs.properties.risk_level_aggregated:high) and
  event.outcome:(success or Success)
```

```python
[{'event': {'dataset': 'azure.signinlogs', 'outcome': 'success'}, 'azure': {'signinlogs': {'properties': {'risk_level_during_signin': 'high'}}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.signinlogs', 'outcome': 'Success'}, 'azure': {'signinlogs': {'properties': {'risk_level_during_signin': 'high'}}}, '@timestamp': 1},
 {'event': {'dataset': 'azure.signinlogs', 'outcome': 'success'}, 'azure': {'signinlogs': {'properties': {'risk_level_aggregated': 'high'}}}, '@timestamp': 2},
 {'event': {'dataset': 'azure.signinlogs', 'outcome': 'Success'}, 'azure': {'signinlogs': {'properties': {'risk_level_aggregated': 'high'}}}, '@timestamp': 3}]
```



### Azure Active Directory High Risk User Sign-in Heuristic

Branch count: 4  
Document count: 4  
Index: geneve-ut-112

```python
event.dataset:azure.signinlogs and
  azure.signinlogs.properties.risk_state:("confirmedCompromised" or "atRisk") and event.outcome:(success or Success)
```

```python
[{'event': {'dataset': 'azure.signinlogs', 'outcome': 'success'}, 'azure': {'signinlogs': {'properties': {'risk_state': 'confirmedCompromised'}}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.signinlogs', 'outcome': 'Success'}, 'azure': {'signinlogs': {'properties': {'risk_state': 'confirmedCompromised'}}}, '@timestamp': 1},
 {'event': {'dataset': 'azure.signinlogs', 'outcome': 'success'}, 'azure': {'signinlogs': {'properties': {'risk_state': 'atRisk'}}}, '@timestamp': 2},
 {'event': {'dataset': 'azure.signinlogs', 'outcome': 'Success'}, 'azure': {'signinlogs': {'properties': {'risk_state': 'atRisk'}}}, '@timestamp': 3}]
```



### Azure Active Directory PowerShell Sign-in

Branch count: 2  
Document count: 2  
Index: geneve-ut-113

```python
event.dataset:azure.signinlogs and
  azure.signinlogs.properties.app_display_name:"Azure Active Directory PowerShell" and
  azure.signinlogs.properties.token_issuer_type:AzureAD and event.outcome:(success or Success)
```

```python
[{'event': {'dataset': 'azure.signinlogs', 'outcome': 'success'}, 'azure': {'signinlogs': {'properties': {'app_display_name': 'Azure Active Directory PowerShell', 'token_issuer_type': 'AzureAD'}}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.signinlogs', 'outcome': 'Success'}, 'azure': {'signinlogs': {'properties': {'app_display_name': 'Azure Active Directory PowerShell', 'token_issuer_type': 'AzureAD'}}}, '@timestamp': 1}]
```



### Azure Alert Suppression Rule Created or Modified

Branch count: 1  
Document count: 1  
Index: geneve-ut-114

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.SECURITY/ALERTSSUPPRESSIONRULES/WRITE" and 
event.outcome: "success"
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.SECURITY/ALERTSSUPPRESSIONRULES/WRITE'}}, '@timestamp': 0}]
```



### Azure Application Credential Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-115

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Update application - Certificates and secrets management" and event.outcome:(success or Success)
```

```python
[{'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'operation_name': 'Update application - Certificates and secrets management'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'operation_name': 'Update application - Certificates and secrets management'}}, '@timestamp': 1}]
```



### Azure Automation Account Created

Branch count: 2  
Document count: 2  
Index: geneve-ut-116

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WRITE" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WRITE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WRITE'}}, '@timestamp': 1}]
```



### Azure Automation Runbook Created or Modified

Branch count: 6  
Document count: 6  
Index: geneve-ut-117

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

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DRAFT/WRITE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DRAFT/WRITE'}}, '@timestamp': 1},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE'}}, '@timestamp': 2},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE'}}, '@timestamp': 3},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/PUBLISH/ACTION'}}, '@timestamp': 4},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/PUBLISH/ACTION'}}, '@timestamp': 5}]
```



### Azure Automation Runbook Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-118

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE'}}, '@timestamp': 1}]
```



### Azure Automation Webhook Created

Branch count: 4  
Document count: 4  
Index: geneve-ut-119

```python
event.dataset:azure.activitylogs and
  azure.activitylogs.operation_name:
    (
      "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/ACTION" or
      "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/WRITE"
    ) and
  event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/ACTION'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/ACTION'}}, '@timestamp': 1},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/WRITE'}}, '@timestamp': 2},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/WRITE'}}, '@timestamp': 3}]
```



### Azure Blob Container Access Level Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-120

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE'}}, '@timestamp': 1}]
```



### Azure Blob Permissions Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-121

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:(
     "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/BLOBS/MANAGEOWNERSHIP/ACTION" or
     "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/BLOBS/MODIFYPERMISSIONS/ACTION") and 
  event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/BLOBS/MANAGEOWNERSHIP/ACTION'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/BLOBS/MANAGEOWNERSHIP/ACTION'}}, '@timestamp': 1},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/BLOBS/MODIFYPERMISSIONS/ACTION'}}, '@timestamp': 2},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/BLOBS/MODIFYPERMISSIONS/ACTION'}}, '@timestamp': 3}]
```



### Azure Command Execution on Virtual Machine

Branch count: 2  
Document count: 2  
Index: geneve-ut-122

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION'}}, '@timestamp': 1}]
```



### Azure Conditional Access Policy Modified

Branch count: 4  
Document count: 4  
Index: geneve-ut-123

```python
event.dataset:(azure.activitylogs or azure.auditlogs) and
event.action:"Update conditional access policy" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'action': 'Update conditional access policy', 'outcome': 'Success'}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'action': 'Update conditional access policy', 'outcome': 'success'}, '@timestamp': 1},
 {'event': {'dataset': 'azure.auditlogs', 'action': 'Update conditional access policy', 'outcome': 'Success'}, '@timestamp': 2},
 {'event': {'dataset': 'azure.auditlogs', 'action': 'Update conditional access policy', 'outcome': 'success'}, '@timestamp': 3}]
```



### Azure Diagnostic Settings Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-124

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE'}}, '@timestamp': 1}]
```



### Azure Event Hub Authorization Rule Created or Updated

Branch count: 2  
Document count: 2  
Index: geneve-ut-125

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.EVENTHUB/NAMESPACES/AUTHORIZATIONRULES/WRITE" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.EVENTHUB/NAMESPACES/AUTHORIZATIONRULES/WRITE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.EVENTHUB/NAMESPACES/AUTHORIZATIONRULES/WRITE'}}, '@timestamp': 1}]
```



### Azure Event Hub Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-126

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE'}}, '@timestamp': 1}]
```



### Azure Firewall Policy Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-128

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE'}}, '@timestamp': 1}]
```



### Azure Frontdoor Web Application Firewall (WAF) Policy Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-129

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/FRONTDOORWEBAPPLICATIONFIREWALLPOLICIES/DELETE" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/FRONTDOORWEBAPPLICATIONFIREWALLPOLICIES/DELETE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/FRONTDOORWEBAPPLICATIONFIREWALLPOLICIES/DELETE'}}, '@timestamp': 1}]
```



### Azure Key Vault Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-132

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KEYVAULT/VAULTS/WRITE" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.KEYVAULT/VAULTS/WRITE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.KEYVAULT/VAULTS/WRITE'}}, '@timestamp': 1}]
```



### Azure Kubernetes Events Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-133

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EVENTS.K8S.IO/EVENTS/DELETE" and 
event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EVENTS.K8S.IO/EVENTS/DELETE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EVENTS.K8S.IO/EVENTS/DELETE'}}, '@timestamp': 1}]
```



### Azure Kubernetes Pods Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-134

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE" and 
event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE'}}, '@timestamp': 1}]
```



### Azure Kubernetes Rolebindings Created

Branch count: 4  
Document count: 4  
Index: geneve-ut-135

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:
	("MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLEBINDINGS/WRITE" or
	 "MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLEBINDINGS/WRITE") and 
event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLEBINDINGS/WRITE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLEBINDINGS/WRITE'}}, '@timestamp': 1},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLEBINDINGS/WRITE'}}, '@timestamp': 2},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLEBINDINGS/WRITE'}}, '@timestamp': 3}]
```



### Azure Network Watcher Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-136

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE'}}, '@timestamp': 1}]
```



### Azure Privilege Identity Management Role Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-137

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Update role setting in PIM" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'operation_name': 'Update role setting in PIM'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'operation_name': 'Update role setting in PIM'}}, '@timestamp': 1}]
```



### Azure Resource Group Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-138

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE'}}, '@timestamp': 1}]
```



### Azure Service Principal Addition

Branch count: 2  
Document count: 2  
Index: geneve-ut-139

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add service principal" and event.outcome:(success or Success)
```

```python
[{'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'operation_name': 'Add service principal'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'operation_name': 'Add service principal'}}, '@timestamp': 1}]
```



### Azure Service Principal Credentials Added

Branch count: 2  
Document count: 2  
Index: geneve-ut-140

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add service principal credentials" and event.outcome:(success or Success)
```

```python
[{'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'operation_name': 'Add service principal credentials'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'operation_name': 'Add service principal credentials'}}, '@timestamp': 1}]
```



### Azure Storage Account Key Regenerated

Branch count: 2  
Document count: 2  
Index: geneve-ut-141

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION'}}, '@timestamp': 1}]
```



### Azure Virtual Network Device Modified or Deleted

Branch count: 22  
Document count: 22  
Index: geneve-ut-142

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:("MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/WRITE" or
"MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/DELETE" or "MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE" or
"MICROSOFT.NETWORK/NETWORKINTERFACES/JOIN/ACTION" or "MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE" or
"MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/DELETE" or "MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/WRITE" or
"MICROSOFT.NETWORK/VIRTUALHUBS/DELETE" or "MICROSOFT.NETWORK/VIRTUALHUBS/WRITE" or
"MICROSOFT.NETWORK/VIRTUALROUTERS/WRITE" or "MICROSOFT.NETWORK/VIRTUALROUTERS/DELETE") and 
event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/WRITE'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/WRITE'}}, '@timestamp': 1},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/DELETE'}}, '@timestamp': 2},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/DELETE'}}, '@timestamp': 3},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE'}}, '@timestamp': 4},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE'}}, '@timestamp': 5},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/JOIN/ACTION'}}, '@timestamp': 6},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/JOIN/ACTION'}}, '@timestamp': 7},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE'}}, '@timestamp': 8},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE'}}, '@timestamp': 9},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/DELETE'}}, '@timestamp': 10},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/DELETE'}}, '@timestamp': 11},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/WRITE'}}, '@timestamp': 12},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/NETWORKVIRTUALAPPLIANCES/WRITE'}}, '@timestamp': 13},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/VIRTUALHUBS/DELETE'}}, '@timestamp': 14},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/VIRTUALHUBS/DELETE'}}, '@timestamp': 15},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/VIRTUALHUBS/WRITE'}}, '@timestamp': 16},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/VIRTUALHUBS/WRITE'}}, '@timestamp': 17},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/VIRTUALROUTERS/WRITE'}}, '@timestamp': 18},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/VIRTUALROUTERS/WRITE'}}, '@timestamp': 19},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/VIRTUALROUTERS/DELETE'}}, '@timestamp': 20},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'MICROSOFT.NETWORK/VIRTUALROUTERS/DELETE'}}, '@timestamp': 21}]
```



### Base16 or Base32 Encoding/Decoding Activity

Branch count: 8  
Document count: 8  
Index: geneve-ut-143

```python
event.category:process and event.type:(start or process_started) and
  process.name:(base16 or base32 or base32plain or base32hex)
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'base16'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'base32'}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'base32plain'}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'base32hex'}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'base16'}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'base32'}, '@timestamp': 5},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'base32plain'}, '@timestamp': 6},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'base32hex'}, '@timestamp': 7}]
```



### Base64 Encoding/Decoding Activity

Branch count: 10  
Document count: 10  
Index: geneve-ut-144

```python
event.category:process and event.type:(start or process_started) and
  process.name:(base64 or base64plain or base64url or base64mime or base64pem)
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'base64'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'base64plain'}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'base64url'}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'base64mime'}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'base64pem'}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'base64'}, '@timestamp': 5},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'base64plain'}, '@timestamp': 6},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'base64url'}, '@timestamp': 7},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'base64mime'}, '@timestamp': 8},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'base64pem'}, '@timestamp': 9}]
```



### Bash Shell Profile Modification

Branch count: 3  
Document count: 3  
Index: geneve-ut-145

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

```python
[{'event': {'category': ['file'], 'type': ['change']}, 'process': {'name': 'ZFy', 'executable': 'XIU'}, 'file': {'path': '/private/etc/rc.local'}, '@timestamp': 0},
 {'event': {'category': ['file'], 'type': ['change']}, 'process': {'name': 'tkN', 'executable': 'Ioi'}, 'file': {'path': '/etc/rc.local'}, '@timestamp': 1},
 {'event': {'category': ['file'], 'type': ['change']}, 'process': {'name': 'xTF', 'executable': 'lEz'}, 'file': {'path': '/home/wuEE/.bash_profile'}, '@timestamp': 2}]
```



### Bypass UAC via Event Viewer

Branch count: 2  
Document count: 2  
Index: geneve-ut-146

```python
process where event.type in ("start", "process_started") and
  process.parent.name : "eventvwr.exe" and
  not process.executable : 
            ("?:\\Windows\\SysWOW64\\mmc.exe", 
             "?:\\Windows\\System32\\mmc.exe",
             "?:\\Windows\\SysWOW64\\WerFault.exe",
             "?:\\Windows\\System32\\WerFault.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'eventvwr.exe'}, 'executable': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'eventvwr.exe'}, 'executable': 'XIU'}, '@timestamp': 1}]
```



### Bypass UAC via Sdclt

Branch count: 4  
Document count: 8  
Index: geneve-ut-147

```python
/* add winlogbeat-* when process.code_signature.* fields are populated */
/* still needs testing, applicable binary was not available on test machine */

sequence with maxspan=1m
  [process where event.type in ("start", "process_started") and process.name : "sdclt.exe" and
     /* uncomment once in winlogbeat */
     /* process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true and */
     process.args : "/kickoffelev"
  ] by process.entity_id
  [process where event.type in ("start", "process_started") and process.parent.name : "sdclt.exe" and
     not (process.executable : "C:\\Windows\\System32\\sdclt.exe" or
          process.executable : "C:\\Windows\\System32\\control.exe" or
          process.executable : "C:\\Windows\\SysWOW64\\sdclt.exe" or
          process.executable : "C:\\Windows\\SysWOW64\\control.exe")
  ] by process.parent.entity_id
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sdclt.exe', 'args': ['/kickoffelev'], 'entity_id': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'sdclt.exe', 'entity_id': 'ZFy'}, 'executable': 'XIU'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sdclt.exe', 'args': ['/kickoffelev'], 'entity_id': 'tkN'}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'sdclt.exe', 'entity_id': 'tkN'}, 'executable': 'Ioi'}, '@timestamp': 3},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'sdclt.exe', 'args': ['/kickoffelev'], 'entity_id': 'xTF'}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'sdclt.exe', 'entity_id': 'xTF'}, 'executable': 'lEz'}, '@timestamp': 5},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'sdclt.exe', 'args': ['/kickoffelev'], 'entity_id': 'swu'}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'sdclt.exe', 'entity_id': 'swu'}, 'executable': 'EEX'}, '@timestamp': 7}]
```



### Clearing Windows Console History

Branch count: 6  
Document count: 6  
Index: geneve-ut-148

```python
process where event.action == "start" and
  (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or process.pe.original_file_name == "PowerShell.EXE") and
     (process.args : "*Clear-History*" or
     (process.args : ("*Remove-Item*", "rm") and process.args : ("*ConsoleHost_history.txt*", "*(Get-PSReadlineOption).HistorySavePath*")) or
     (process.args : "*Set-PSReadlineOption*" and process.args : "*SaveNothing*"))
```

```python
[{'event': {'action': 'start', 'category': ['process']}, 'process': {'name': 'pwsh.exe', 'args': ['*Clear-History*']}, '@timestamp': 0},
 {'event': {'action': 'start', 'category': ['process']}, 'process': {'name': 'powershell_ise.exe', 'args': ['*Remove-Item*', 'rm', '*ConsoleHost_history.txt*', '*(Get-PSReadlineOption).HistorySavePath*']}, '@timestamp': 1},
 {'event': {'action': 'start', 'category': ['process']}, 'process': {'name': 'powershell_ise.exe', 'args': ['*Set-PSReadlineOption*', '*SaveNothing*']}, '@timestamp': 2},
 {'event': {'action': 'start', 'category': ['process']}, 'process': {'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['*Clear-History*']}, '@timestamp': 3},
 {'event': {'action': 'start', 'category': ['process']}, 'process': {'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['*Remove-Item*', 'rm', '*ConsoleHost_history.txt*', '*(Get-PSReadlineOption).HistorySavePath*']}, '@timestamp': 4},
 {'event': {'action': 'start', 'category': ['process']}, 'process': {'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['*Set-PSReadlineOption*', '*SaveNothing*']}, '@timestamp': 5}]
```



### Clearing Windows Event Logs

Branch count: 5  
Document count: 5  
Index: geneve-ut-149

```python
process where event.type in ("process_started", "start") and
  (process.name : "wevtutil.exe" or process.pe.original_file_name == "wevtutil.exe") and
    process.args : ("/e:false", "cl", "clear-log") or
  process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and process.args : "Clear-EventLog"
```

```python
[{'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'wevtutil.exe', 'args': ['/e:false', 'cl', 'clear-log']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'wevtutil.exe'}, 'args': ['/e:false', 'cl', 'clear-log']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'wevtutil.exe', 'args': ['/e:false', 'cl', 'clear-log']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'wevtutil.exe'}, 'args': ['/e:false', 'cl', 'clear-log']}, '@timestamp': 3},
 {'process': {'name': 'pwsh.exe', 'args': ['Clear-EventLog']}, 'event': {'category': ['process']}, '@timestamp': 4}]
```



### Command Execution via SolarWinds Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-151

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'powershell.exe', 'parent': {'name': 'SolarWinds.AdministrationIUtkNIoix.exe'}}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'parent': {'name': 'NetflowDatabaseMaintenanceOHmxBnLeOA.exe'}}, '@timestamp': 1}]
```



### Command Prompt Network Connection

Branch count: 1  
Document count: 2  
Index: geneve-ut-152

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

```python
[{'process': {'name': 'cmd.exe', 'entity_id': 'ZFy'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'cmd.exe', 'entity_id': 'ZFy'}, 'destination': {'ip': '170.121.236.89'}, 'event': {'category': ['network']}, '@timestamp': 1}]
```



### Conhost Spawned By Suspicious Parent Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-155

```python
process where event.type in ("start", "process_started") and
  process.name : "conhost.exe" and
  process.parent.name : ("svchost.exe", "lsass.exe", "services.exe", "smss.exe", "winlogon.exe", "explorer.exe",
                         "dllhost.exe", "rundll32.exe", "regsvr32.exe", "userinit.exe", "wininit.exe", "spoolsv.exe",
                         "wermgr.exe", "csrss.exe", "ctfmon.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'conhost.exe', 'parent': {'name': 'winlogon.exe'}}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'conhost.exe', 'parent': {'name': 'spoolsv.exe'}}, '@timestamp': 1}]
```



### Connection to Commonly Abused Free SSL Certificate Providers

Branch count: 1  
Document count: 1  
Index: geneve-ut-156

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

```python
[{'network': {'protocol': 'dns'}, 'dns': {'question': {'name': 'XIUtkNIletsencrypt.org'}}, 'process': {'executable': 'C:\\Windows\\System32\\ixTFlEzswuEEXp.exe', 'name': 'WqN'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Connection to Commonly Abused Web Services

Branch count: 1  
Document count: 1  
Index: geneve-ut-157

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
      "?:\\Users\\*\\AppData\\Local\\Discord\\-*\\Discord.exe"
    )
```

```python
[{'network': {'protocol': 'dns'}, 'process': {'name': 'ZFy', 'executable': 'lEz'}, 'user': {'id': 'XIU'}, 'dns': {'question': {'name': 'kNIoixTFnotabug.org'}}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Connection to External Network via Telnet

Branch count: 1  
Document count: 2  
Index: geneve-ut-158

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

```python
[{'process': {'name': 'telnet', 'entity_id': 'ZFy'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'telnet', 'entity_id': 'ZFy'}, 'destination': {'ip': '170.121.236.89'}, 'event': {'category': ['network']}, '@timestamp': 1}]
```



### Connection to Internal Network via Telnet

Branch count: 1  
Document count: 2  
Index: geneve-ut-159

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

```python
[{'process': {'name': 'telnet', 'entity_id': 'ZFy'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'telnet', 'entity_id': 'ZFy'}, 'destination': {'ip': '192.175.48.54'}, 'event': {'category': ['network']}, '@timestamp': 1}]
```



### Creation of Hidden Launch Agent or Daemon

Branch count: 1  
Document count: 1  
Index: geneve-ut-162

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

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'path': '/Users/fUyyFjSvILO/Library/LaunchAgents/.Ezswu.plist'}, '@timestamp': 0}]
```



### Creation of a Hidden Local User Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-164

```python
registry where registry.path : "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\*$\\"
```

```python
[{'registry': {'path': 'HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\XIUtkNI$\\'}, 'event': {'category': ['registry']}, '@timestamp': 0}]
```



### Creation of a local user account

Branch count: 1  
Document count: 1  
Index: geneve-ut-165

```python
event.module:security and event.code:4720
```

```python
[{'event': {'module': 'security', 'code': 4720}, '@timestamp': 0}]
```



### Creation or Modification of Domain Backup DPAPI private key

Branch count: 1  
Document count: 1  
Index: geneve-ut-166

```python
file where event.type != "deletion" and file.name : ("ntds_capi_*.pfx", "ntds_capi_*.pvk")
```

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'name': 'ntds_capi_UyyFjSvILOoOHmx.pfx'}, '@timestamp': 0}]
```



### Creation or Modification of Root Certificate

Branch count: 2  
Document count: 2  
Index: geneve-ut-167

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

```python
[{'event': {'type': ['creation'], 'category': ['registry']}, 'registry': {'path': 'HKLM\\Software\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\XIUtkNI\\Blob'}, '@timestamp': 0},
 {'event': {'type': ['change'], 'category': ['registry']}, 'registry': {'path': 'HKLM\\Software\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\ixTFlEzswuEEXp\\Blob'}, '@timestamp': 1}]
```



### Creation or Modification of a new GPO Scheduled Task or Service

Branch count: 1  
Document count: 1  
Index: geneve-ut-168

```python
file where event.type != "deletion" and
  file.path : ("?:\\Windows\\SYSVOL\\domain\\Policies\\*\\MACHINE\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
               "?:\\Windows\\SYSVOL\\domain\\Policies\\*\\MACHINE\\Preferences\\Preferences\\Services\\Services.xml") and
  not process.name : "dfsrs.exe"
```

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'path': 'y:\\Windows\\SYSVOL\\domain\\Policies\\kNIoixTF\\MACHINE\\Preferences\\Preferences\\Services\\Services.xml'}, 'process': {'name': 'lEz'}, '@timestamp': 0}]
```



### Credential Acquisition via Registry Hive Dumping

Branch count: 2  
Document count: 2  
Index: geneve-ut-169

```python
process where event.type in ("start", "process_started") and
 process.pe.original_file_name == "reg.exe" and
 process.args : ("save", "export") and
 process.args : ("hklm\\sam", "hklm\\security")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'reg.exe'}, 'args': ['save', 'export', 'hklm\\sam', 'hklm\\security']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'reg.exe'}, 'args': ['save', 'export', 'hklm\\sam', 'hklm\\security']}, '@timestamp': 1}]
```



### Credential Dumping - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-170

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:cred_theft_event or endgame.event_subtype_full:cred_theft_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'cred_theft_event'}, 'endgame': {'metadata': {'type': 'detection'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'detection'}, 'event_subtype_full': 'cred_theft_event'}, '@timestamp': 1}]
```



### Credential Dumping - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-171

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:cred_theft_event or endgame.event_subtype_full:cred_theft_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'cred_theft_event'}, 'endgame': {'metadata': {'type': 'prevention'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'prevention'}, 'event_subtype_full': 'cred_theft_event'}, '@timestamp': 1}]
```



### Credential Manipulation - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-172

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:token_manipulation_event or endgame.event_subtype_full:token_manipulation_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'token_manipulation_event'}, 'endgame': {'metadata': {'type': 'detection'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'detection'}, 'event_subtype_full': 'token_manipulation_event'}, '@timestamp': 1}]
```



### Credential Manipulation - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-173

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:token_manipulation_event or endgame.event_subtype_full:token_manipulation_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'token_manipulation_event'}, 'endgame': {'metadata': {'type': 'prevention'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'prevention'}, 'event_subtype_full': 'token_manipulation_event'}, '@timestamp': 1}]
```



### CyberArk Privileged Access Security Error

Branch count: 1  
Document count: 1  
Index: geneve-ut-174

```python
event.dataset:cyberarkpas.audit and event.type:error
```

```python
[{'event': {'dataset': 'cyberarkpas.audit', 'type': ['error']}, '@timestamp': 0}]
```



### CyberArk Privileged Access Security Recommended Monitor

Branch count: 20  
Document count: 20  
Index: geneve-ut-175

```python
event.dataset:cyberarkpas.audit and
  event.code:(4 or 22 or 24 or 31 or 38 or 57 or 60 or 130 or 295 or 300 or 302 or
              308 or 319 or 344 or 346 or 359 or 361 or 378 or 380 or 411) and
  not event.type:error
```

```python
[{'event': {'dataset': 'cyberarkpas.audit', 'code': 4, 'type': ['ZFy']}, '@timestamp': 0},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 22, 'type': ['XIU']}, '@timestamp': 1},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 24, 'type': ['tkN']}, '@timestamp': 2},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 31, 'type': ['Ioi']}, '@timestamp': 3},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 38, 'type': ['xTF']}, '@timestamp': 4},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 57, 'type': ['lEz']}, '@timestamp': 5},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 60, 'type': ['swu']}, '@timestamp': 6},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 130, 'type': ['EEX']}, '@timestamp': 7},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 295, 'type': ['pWq']}, '@timestamp': 8},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 300, 'type': ['NVR']}, '@timestamp': 9},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 302, 'type': ['cym']}, '@timestamp': 10},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 308, 'type': ['EEw']}, '@timestamp': 11},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 319, 'type': ['VPY']}, '@timestamp': 12},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 344, 'type': ['MGz']}, '@timestamp': 13},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 346, 'type': ['Nfm']}, '@timestamp': 14},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 359, 'type': ['lOP']}, '@timestamp': 15},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 361, 'type': ['ZRg']}, '@timestamp': 16},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 378, 'type': ['UvW']}, '@timestamp': 17},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 380, 'type': ['CiM']}, '@timestamp': 18},
 {'event': {'dataset': 'cyberarkpas.audit', 'code': 411, 'type': ['ZOf']}, '@timestamp': 19}]
```



### DNS Activity to the Internet

Branch count: 24  
Document count: 24  
Index: geneve-ut-176

```python
event.category:(network or network_traffic) and (event.type:connection or type:dns) and (destination.port:53 or event.dataset:zeek.dns)
  and source.ip:(
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

```python
[{'event': {'category': ['network'], 'type': ['connection']}, 'destination': {'port': 53, 'ip': '170.121.236.89'}, 'source': {'ip': '10.214.62.131'}, '@timestamp': 0},
 {'event': {'category': ['network'], 'type': ['connection']}, 'destination': {'port': 53, 'ip': '54.2.158.30'}, 'source': {'ip': '172.28.20.160'}, '@timestamp': 1},
 {'event': {'category': ['network'], 'type': ['connection']}, 'destination': {'port': 53, 'ip': '219.54.168.90'}, 'source': {'ip': '192.168.96.70'}, '@timestamp': 2},
 {'event': {'category': ['network'], 'type': ['connection'], 'dataset': 'zeek.dns'}, 'source': {'ip': '10.209.3.152'}, 'destination': {'ip': '169.225.121.243'}, '@timestamp': 3},
 {'event': {'category': ['network'], 'type': ['connection'], 'dataset': 'zeek.dns'}, 'source': {'ip': '172.24.207.103'}, 'destination': {'ip': '199.127.185.194'}, '@timestamp': 4},
 {'event': {'category': ['network'], 'type': ['connection'], 'dataset': 'zeek.dns'}, 'source': {'ip': '192.168.186.159'}, 'destination': {'ip': '112.141.185.70'}, '@timestamp': 5},
 {'event': {'category': ['network']}, 'type': 'dns', 'destination': {'port': 53, 'ip': '149.102.124.168'}, 'source': {'ip': '10.197.122.33'}, '@timestamp': 6},
 {'event': {'category': ['network']}, 'type': 'dns', 'destination': {'port': 53, 'ip': '197.7.114.246'}, 'source': {'ip': '172.18.192.161'}, '@timestamp': 7},
 {'event': {'category': ['network']}, 'type': 'dns', 'destination': {'port': 53, 'ip': 'd5e4:e45:48d:758d:eac9:ff60:21ff:ce20'}, 'source': {'ip': '192.168.1.78'}, '@timestamp': 8},
 {'event': {'category': ['network'], 'dataset': 'zeek.dns'}, 'type': 'dns', 'source': {'ip': '10.29.111.63'}, 'destination': {'ip': '121.161.84.247'}, '@timestamp': 9},
 {'event': {'category': ['network'], 'dataset': 'zeek.dns'}, 'type': 'dns', 'source': {'ip': '172.23.250.187'}, 'destination': {'ip': '151.149.0.92'}, '@timestamp': 10},
 {'event': {'category': ['network'], 'dataset': 'zeek.dns'}, 'type': 'dns', 'source': {'ip': '192.168.247.115'}, 'destination': {'ip': '178.204.52.89'}, '@timestamp': 11},
 {'event': {'category': ['network_traffic'], 'type': ['connection']}, 'destination': {'port': 53, 'ip': '7ee8:2ac7:8fd8:c24b:a168:4644:d2ea:bc0f'}, 'source': {'ip': '10.239.247.149'}, '@timestamp': 12},
 {'event': {'category': ['network_traffic'], 'type': ['connection']}, 'destination': {'port': 53, 'ip': '60.47.190.229'}, 'source': {'ip': '172.19.127.35'}, '@timestamp': 13},
 {'event': {'category': ['network_traffic'], 'type': ['connection']}, 'destination': {'port': 53, 'ip': 'd693:36a4:eaa1:660b:fe6b:8957:739e:8b1b'}, 'source': {'ip': '192.168.165.29'}, '@timestamp': 14},
 {'event': {'category': ['network_traffic'], 'type': ['connection'], 'dataset': 'zeek.dns'}, 'source': {'ip': '10.209.145.8'}, 'destination': {'ip': '139.59.60.34'}, '@timestamp': 15},
 {'event': {'category': ['network_traffic'], 'type': ['connection'], 'dataset': 'zeek.dns'}, 'source': {'ip': '172.21.68.62'}, 'destination': {'ip': '189.141.142.160'}, '@timestamp': 16},
 {'event': {'category': ['network_traffic'], 'type': ['connection'], 'dataset': 'zeek.dns'}, 'source': {'ip': '192.168.64.185'}, 'destination': {'ip': '60.8.116.38'}, '@timestamp': 17},
 {'event': {'category': ['network_traffic']}, 'type': 'dns', 'destination': {'port': 53, 'ip': '147.73.59.170'}, 'source': {'ip': '10.178.22.53'}, '@timestamp': 18},
 {'event': {'category': ['network_traffic']}, 'type': 'dns', 'destination': {'port': 53, 'ip': '184.97.58.102'}, 'source': {'ip': '172.18.235.169'}, '@timestamp': 19},
 {'event': {'category': ['network_traffic']}, 'type': 'dns', 'destination': {'port': 53, 'ip': '46.77.189.36'}, 'source': {'ip': '192.168.22.13'}, '@timestamp': 20},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.dns'}, 'type': 'dns', 'source': {'ip': '10.139.227.125'}, 'destination': {'ip': '159.213.231.147'}, '@timestamp': 21},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.dns'}, 'type': 'dns', 'source': {'ip': '172.23.111.141'}, 'destination': {'ip': '547b:40e6:6d4a:85e0:ec27:61ef:77cd:b63c'}, '@timestamp': 22},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.dns'}, 'type': 'dns', 'source': {'ip': '192.168.253.192'}, 'destination': {'ip': '169.49.132.205'}, '@timestamp': 23}]
```



### Default Cobalt Strike Team Server Certificate

Branch count: 6  
Document count: 6  
Index: geneve-ut-179

```python
event.category:(network or network_traffic) and (tls.server.hash.md5:950098276A495286EB2A2556FBAB6D83 or
  tls.server.hash.sha1:6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C or
  tls.server.hash.sha256:87F2085C32B6A2CC709B365F55873E207A9CAA10BFFECF2FD16D3CF9D94D390C)
```

```python
[{'event': {'category': ['network']}, 'tls': {'server': {'hash': {'md5': '950098276A495286EB2A2556FBAB6D83'}}}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'tls': {'server': {'hash': {'sha1': '6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C'}}}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'tls': {'server': {'hash': {'sha256': '87F2085C32B6A2CC709B365F55873E207A9CAA10BFFECF2FD16D3CF9D94D390C'}}}, '@timestamp': 2},
 {'event': {'category': ['network_traffic']}, 'tls': {'server': {'hash': {'md5': '950098276A495286EB2A2556FBAB6D83'}}}, '@timestamp': 3},
 {'event': {'category': ['network_traffic']}, 'tls': {'server': {'hash': {'sha1': '6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C'}}}, '@timestamp': 4},
 {'event': {'category': ['network_traffic']}, 'tls': {'server': {'hash': {'sha256': '87F2085C32B6A2CC709B365F55873E207A9CAA10BFFECF2FD16D3CF9D94D390C'}}}, '@timestamp': 5}]
```



### Delete Volume USN Journal with Fsutil

Branch count: 4  
Document count: 4  
Index: geneve-ut-180

```python
process where event.type in ("start", "process_started") and
  (process.name : "fsutil.exe" or process.pe.original_file_name == "fsutil.exe") and 
  process.args : "deletejournal" and process.args : "usn"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'fsutil.exe', 'args': ['deletejournal', 'usn']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'fsutil.exe'}, 'args': ['deletejournal', 'usn']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'fsutil.exe', 'args': ['deletejournal', 'usn']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'fsutil.exe'}, 'args': ['deletejournal', 'usn']}, '@timestamp': 3}]
```



### Deleting Backup Catalogs with Wbadmin

Branch count: 4  
Document count: 4  
Index: geneve-ut-181

```python
process where event.type in ("start", "process_started") and
  (process.name : "wbadmin.exe" or process.pe.original_file_name == "WBADMIN.EXE") and
  process.args : "catalog" and process.args : "delete"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'wbadmin.exe', 'args': ['catalog', 'delete']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'WBADMIN.EXE'}, 'args': ['catalog', 'delete']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'wbadmin.exe', 'args': ['catalog', 'delete']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'WBADMIN.EXE'}, 'args': ['catalog', 'delete']}, '@timestamp': 3}]
```



### Direct Outbound SMB Connection

Branch count: 1  
Document count: 2  
Index: geneve-ut-182

```python
sequence by process.entity_id
  [process where event.type == "start" and process.pid != 4]
  [network where destination.port == 445 and process.pid != 4 and
     not cidrmatch(destination.ip, "127.0.0.1", "::1")]
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'pid': 4289255490, 'entity_id': 'UTv'}, '@timestamp': 0},
 {'destination': {'port': 445, 'ip': '229.172.181.141'}, 'process': {'pid': 2366908802, 'entity_id': 'UTv'}, 'event': {'category': ['network']}, '@timestamp': 1}]
```



### Disable Windows Event and Security Logs Using Built-in Tools

Branch count: 10  
Document count: 10  
Index: geneve-ut-183

```python
process where event.type in ("start", "process_started") and

  ((process.name:"logman.exe" or process.pe.original_file_name == "Logman.exe") and
      process.args : "EventLog-*" and process.args : ("stop", "delete")) or

  ((process.name : ("pwsh.exe", "powershell.exe", "powershell_ise.exe") or process.pe.original_file_name in
      ("pwsh.exe", "powershell.exe", "powershell_ise.exe")) and
	process.args : "Set-Service" and process.args: "EventLog" and process.args : "Disabled")  or

  ((process.name:"auditpol.exe" or process.pe.original_file_name == "AUDITPOL.EXE") and process.args : "/success:disable")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'logman.exe', 'args': ['EventLog-*', 'stop', 'delete']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Logman.exe'}, 'args': ['EventLog-*', 'stop', 'delete']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'logman.exe', 'args': ['EventLog-*', 'stop', 'delete']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Logman.exe'}, 'args': ['EventLog-*', 'stop', 'delete']}, '@timestamp': 3},
 {'process': {'name': 'pwsh.exe', 'args': ['Set-Service', 'EventLog', 'Disabled']}, 'event': {'category': ['process']}, '@timestamp': 4},
 {'process': {'pe': {'original_file_name': 'pwsh.exe'}, 'args': ['Set-Service', 'EventLog', 'Disabled']}, 'event': {'category': ['process']}, '@timestamp': 5},
 {'process': {'pe': {'original_file_name': 'powershell.exe'}, 'args': ['Set-Service', 'EventLog', 'Disabled']}, 'event': {'category': ['process']}, '@timestamp': 6},
 {'process': {'pe': {'original_file_name': 'powershell_ise.exe'}, 'args': ['Set-Service', 'EventLog', 'Disabled']}, 'event': {'category': ['process']}, '@timestamp': 7},
 {'process': {'name': 'auditpol.exe', 'args': ['/success:disable']}, 'event': {'category': ['process']}, '@timestamp': 8},
 {'process': {'pe': {'original_file_name': 'AUDITPOL.EXE'}, 'args': ['/success:disable']}, 'event': {'category': ['process']}, '@timestamp': 9}]
```



### Disable Windows Firewall Rules via Netsh

Branch count: 3  
Document count: 3  
Index: geneve-ut-184

```python
process where event.type in ("start", "process_started") and
  process.name : "netsh.exe" and
  (process.args : "disable" and process.args : "firewall" and process.args : "set") or
  (process.args : "advfirewall" and process.args : "off" and process.args : "state")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'netsh.exe', 'args': ['disable', 'firewall', 'set']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'netsh.exe', 'args': ['disable', 'firewall', 'set']}, '@timestamp': 1},
 {'process': {'args': ['advfirewall', 'off', 'state']}, 'event': {'category': ['process']}, '@timestamp': 2}]
```



### Disabling Windows Defender Security Settings via PowerShell

Branch count: 4  
Document count: 4  
Index: geneve-ut-186

```python
process where event.type == "start" and
 (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or process.pe.original_file_name in ("powershell.exe", "pwsh.dll", "powershell_ise.exe")) and
 process.args : "Set-MpPreference" and process.args : ("-Disable*", "Disabled", "NeverSend", "-Exclusion*")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'pwsh.exe', 'args': ['Set-MpPreference', '-Disable*', 'Disabled', 'NeverSend', '-Exclusion*']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'powershell.exe'}, 'args': ['Set-MpPreference', '-Disable*', 'Disabled', 'NeverSend', '-Exclusion*']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'pwsh.dll'}, 'args': ['Set-MpPreference', '-Disable*', 'Disabled', 'NeverSend', '-Exclusion*']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'powershell_ise.exe'}, 'args': ['Set-MpPreference', '-Disable*', 'Disabled', 'NeverSend', '-Exclusion*']}, '@timestamp': 3}]
```



### Domain Added to Google Workspace Trusted Domains

Branch count: 1  
Document count: 1  
Index: geneve-ut-187

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:ADD_TRUSTED_DOMAINS
```

```python
[{'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'ADD_TRUSTED_DOMAINS'}, '@timestamp': 0}]
```



### Dumping Account Hashes via Built-In Commands

Branch count: 4  
Document count: 4  
Index: geneve-ut-190

```python
event.category:process and event.type:start and
 process.name:(defaults or mkpassdb) and process.args:(ShadowHashData or "-dump")
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'defaults', 'args': ['ShadowHashData']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'defaults', 'args': ['-dump']}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'mkpassdb', 'args': ['ShadowHashData']}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'mkpassdb', 'args': ['-dump']}, '@timestamp': 3}]
```



### Dumping of Keychain Content via Security Command

Branch count: 2  
Document count: 2  
Index: geneve-ut-191

```python
process where event.type in ("start", "process_started") and process.args : "dump-keychain" and process.args : "-d"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['dump-keychain', '-d']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'args': ['dump-keychain', '-d']}, '@timestamp': 1}]
```



### EggShell Backdoor Execution

Branch count: 2  
Document count: 2  
Index: geneve-ut-192

```python
event.category:process and event.type:(start or process_started) and process.name:espl and process.args:eyJkZWJ1ZyI6*
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'espl', 'args': ['eyJkZWJ1ZyI6*']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'espl', 'args': ['eyJkZWJ1ZyI6*']}, '@timestamp': 1}]
```



### Emond Rules Creation or Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-193

```python
file where event.type != "deletion" and
 file.path : ("/private/etc/emond.d/rules/*.plist", "/etc/emon.d/rules/*.plist")
```

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'path': '/etc/emon.d/rules/UyyFjSvILOoOHmx.plist'}, '@timestamp': 0}]
```



### Enable Host Network Discovery via Netsh

Branch count: 1  
Document count: 1  
Index: geneve-ut-194

```python
process where event.type == "start" and
process.name : "netsh.exe" and
process.args : ("firewall", "advfirewall") and process.args : "group=Network Discovery" and process.args : "enable=Yes"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'netsh.exe', 'args': ['firewall', 'advfirewall', 'group=Network Discovery', 'enable=Yes']}, '@timestamp': 0}]
```



### Encrypting Files with WinRar or 7z

Branch count: 8  
Document count: 8  
Index: geneve-ut-196

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'rar.exe', 'args': ['-hp*', '-p*', '-dw', '-tb', '-ta', '/hp*', '/p*', '/dw', '/tb', '/ta', 'a']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'code_signature': {'subject_name': 'win.rar GmbH'}, 'args': ['-hp*', '-p*', '-dw', '-tb', '-ta', '/hp*', '/p*', '/dw', '/tb', '/ta', 'a']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Command line RAR'}, 'args': ['-hp*', '-p*', '-dw', '-tb', '-ta', '/hp*', '/p*', '/dw', '/tb', '/ta', 'a']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'rar.exe', 'args': ['-hp*', '-p*', '-dw', '-tb', '-ta', '/hp*', '/p*', '/dw', '/tb', '/ta', 'a']}, '@timestamp': 3},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'code_signature': {'subject_name': 'win.rar GmbH'}, 'args': ['-hp*', '-p*', '-dw', '-tb', '-ta', '/hp*', '/p*', '/dw', '/tb', '/ta', 'a']}, '@timestamp': 4},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Command line RAR'}, 'args': ['-hp*', '-p*', '-dw', '-tb', '-ta', '/hp*', '/p*', '/dw', '/tb', '/ta', 'a']}, '@timestamp': 5},
 {'process': {'pe': {'original_file_name': '7z.exe'}, 'args': ['-p*', '-sdel', 'a']}, 'event': {'category': ['process']}, '@timestamp': 6},
 {'process': {'pe': {'original_file_name': '7za.exe'}, 'args': ['-p*', '-sdel', 'a']}, 'event': {'category': ['process']}, '@timestamp': 7}]
```



### Endpoint Security

Branch count: 1  
Document count: 1  
Index: geneve-ut-197

```python
event.kind:alert and event.module:(endpoint and not endgame)
```

```python
[{'event': {'kind': 'alert', 'module': 'endpoint'}, '@timestamp': 0}]
```



### Enumeration Command Spawned via WMIPrvSE

Branch count: 2  
Document count: 2  
Index: geneve-ut-198

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'tasklist.exe', 'parent': {'name': 'wmiprvse.exe'}}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'qwinsta.exe', 'parent': {'name': 'wmiprvse.exe'}}, '@timestamp': 1}]
```



### Enumeration of Administrator Accounts

Branch count: 10  
Document count: 10  
Index: geneve-ut-199

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'net.exe', 'args': ['group', 'user', 'localgroup', 'admin', 'Domain Admins', 'Remote Desktop Users', 'Enterprise Admins', 'Organization Management']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net.exe'}, 'args': ['group', 'user', 'localgroup', 'admin', 'Domain Admins', 'Remote Desktop Users', 'Enterprise Admins', 'Organization Management']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'net1.exe', 'parent': {'name': 'ZFy'}, 'args': ['group', 'user', 'localgroup', 'admin', 'Domain Admins', 'Remote Desktop Users', 'Enterprise Admins', 'Organization Management']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net1.exe'}, 'parent': {'name': 'XIU'}, 'args': ['group', 'user', 'localgroup', 'admin', 'Domain Admins', 'Remote Desktop Users', 'Enterprise Admins', 'Organization Management']}, '@timestamp': 3},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'net.exe', 'args': ['group', 'user', 'localgroup', 'admin', 'Domain Admins', 'Remote Desktop Users', 'Enterprise Admins', 'Organization Management']}, '@timestamp': 4},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net.exe'}, 'args': ['group', 'user', 'localgroup', 'admin', 'Domain Admins', 'Remote Desktop Users', 'Enterprise Admins', 'Organization Management']}, '@timestamp': 5},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'net1.exe', 'parent': {'name': 'tkN'}, 'args': ['group', 'user', 'localgroup', 'admin', 'Domain Admins', 'Remote Desktop Users', 'Enterprise Admins', 'Organization Management']}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net1.exe'}, 'parent': {'name': 'Ioi'}, 'args': ['group', 'user', 'localgroup', 'admin', 'Domain Admins', 'Remote Desktop Users', 'Enterprise Admins', 'Organization Management']}, '@timestamp': 7},
 {'process': {'name': 'wmic.exe', 'args': ['group', 'useraccount']}, 'event': {'category': ['process']}, '@timestamp': 8},
 {'process': {'pe': {'original_file_name': 'wmic.exe'}, 'args': ['group', 'useraccount']}, 'event': {'category': ['process']}, '@timestamp': 9}]
```



### Enumeration of Kernel Modules

Branch count: 2  
Document count: 2  
Index: geneve-ut-200

```python
event.category:process and event.type:(start or process_started) and
  process.args:(kmod and list and sudo or sudo and (depmod or lsmod or modinfo))
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['kmod', 'list', 'sudo']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'args': ['kmod', 'list', 'sudo']}, '@timestamp': 1}]
```



### Enumeration of Privileged Local Groups Membership

Branch count: 2  
Document count: 2  
Index: geneve-ut-201

```python
iam where event.action == "user-member-enumerated" and

 /* noisy and usual legit processes excluded */
 not winlog.event_data.CallerProcessName:
              ("?:\\Windows\\System32\\VSSVC.exe",
               "?:\\Windows\\System32\\SearchIndexer.exe",
               "?:\\Windows\\System32\\CompatTelRunner.exe",
               "?:\\Windows\\System32\\oobe\\msoobe.exe",
               "?:\\Windows\\System32\\net1.exe",
               "?:\\Windows\\System32\\svchost.exe",
               "?:\\Windows\\System32\\Netplwiz.exe",
               "?:\\Windows\\System32\\msiexec.exe",
               "?:\\Windows\\System32\\CloudExperienceHostBroker.exe",
               "?:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
               "?:\\Windows\\System32\\SrTasks.exe",
               "?:\\Windows\\System32\\lsass.exe",
               "?:\\Windows\\System32\\diskshadow.exe",
               "?:\\Windows\\System32\\dfsrs.exe",
               "?:\\Program Files\\*.exe",
               "?:\\Program Files (x86)\\*.exe") and
  /* privileged local groups */
 (group.name:("admin*","RemoteDesktopUsers") or
  winlog.event_data.TargetSid:("S-1-5-32-544","S-1-5-32-555"))
```

```python
[{'event': {'action': 'user-member-enumerated', 'category': ['iam']}, 'winlog': {'event_data': {'CallerProcessName': 'ZFy'}}, 'group': {'name': 'RemoteDesktopUsers'}, '@timestamp': 0},
 {'event': {'action': 'user-member-enumerated', 'category': ['iam']}, 'winlog': {'event_data': {'CallerProcessName': 'Utk', 'TargetSid': 'S-1-5-32-544'}}, '@timestamp': 1}]
```



### Enumeration of Users or Groups via Built-in Commands

Branch count: 3  
Document count: 3  
Index: geneve-ut-202

```python
process where event.type in ("start", "process_started") and
  not process.parent.executable : ("/Applications/NoMAD.app/Contents/MacOS/NoMAD", 
    "/Applications/ZoomPresence.app/Contents/MacOS/ZoomPresence",
     "/Applications/Sourcetree.app/Contents/MacOS/Sourcetree",
     "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon",
     "/Applications/Jamf Connect.app/Contents/MacOS/Jamf Connect",
     "/usr/local/jamf/bin/jamf"
    ) and 
  process.name : ("ldapsearch", "dsmemberutil") or
  (process.name : "dscl" and 
     process.args : ("read", "-read", "list", "-list", "ls", "search", "-search") and 
     process.args : ("/Active Directory/*", "/Users*", "/Groups*"))
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'executable': 'ZFy'}, 'name': 'dsmemberutil'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'executable': 'Utk'}, 'name': 'dsmemberutil'}, '@timestamp': 1},
 {'process': {'name': 'dscl', 'args': ['read', '-read', 'list', '-list', 'ls', 'search', '-search', '/Active Directory/*', '/Users*', '/Groups*']}, 'event': {'category': ['process']}, '@timestamp': 2}]
```



### Execution of COM object via Xwizard

Branch count: 4  
Document count: 4  
Index: geneve-ut-205

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'xwizard.exe'}, 'args': ['RunWizard', '{*}']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'xwizard.exe'}, 'executable': 'ZFy'}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'xwizard.exe'}, 'args': ['RunWizard', '{*}']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'xwizard.exe'}, 'executable': 'XIU'}, '@timestamp': 3}]
```



### Execution of File Written or Modified by Microsoft Office

Branch count: 2  
Document count: 4  
Index: geneve-ut-206

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

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'extension': 'exe', 'path': 'NIo'}, 'process': {'name': 'MSACCESS.EXE'}, 'host': {'id': 'Utk'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'host': {'id': 'Utk'}, 'process': {'executable': 'NIo'}, '@timestamp': 1},
 {'event': {'type': ['ixT'], 'category': ['file']}, 'file': {'extension': 'exe', 'path': 'mxB'}, 'process': {'name': 'OUTLOOK.EXE'}, 'host': {'id': 'oOH'}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'host': {'id': 'oOH'}, 'process': {'executable': 'mxB'}, '@timestamp': 3}]
```



### Execution of File Written or Modified by PDF Reader

Branch count: 2  
Document count: 4  
Index: geneve-ut-207

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

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'extension': 'exe', 'name': 'Utk', 'path': 'ixT'}, 'process': {'name': 'AcroRd32.exe'}, 'host': {'id': 'NIo'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'host': {'id': 'NIo'}, 'process': {'executable': 'ixT'}, '@timestamp': 1},
 {'event': {'type': ['FlE'], 'category': ['file']}, 'file': {'extension': 'exe', 'name': 'Hmx', 'path': 'eOA'}, 'process': {'name': 'rdrcef.exe'}, 'host': {'id': 'BnL'}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'host': {'id': 'BnL'}, 'process': {'executable': 'eOA'}, '@timestamp': 3}]
```



### Execution of Persistent Suspicious Program

Branch count: 72  
Document count: 216  
Index: geneve-ut-208

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'ZFy'}, 'user': {'name': 'XIU'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'ZFy'}, 'user': {'name': 'XIU'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'cscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'ZFy'}, 'user': {'name': 'XIU'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'tkN'}, 'user': {'name': 'Ioi'}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'tkN'}, 'user': {'name': 'Ioi'}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'wscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'tkN'}, 'user': {'name': 'Ioi'}, '@timestamp': 5},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'xTF'}, 'user': {'name': 'lEz'}, '@timestamp': 6},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'xTF'}, 'user': {'name': 'lEz'}, '@timestamp': 7},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'xTF'}, 'user': {'name': 'lEz'}, '@timestamp': 8},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'swu'}, 'user': {'name': 'EEX'}, '@timestamp': 9},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'swu'}, 'user': {'name': 'EEX'}, '@timestamp': 10},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSHTA.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'swu'}, 'user': {'name': 'EEX'}, '@timestamp': 11},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'pWq'}, 'user': {'name': 'NVR'}, '@timestamp': 12},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'pWq'}, 'user': {'name': 'NVR'}, '@timestamp': 13},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'pWq'}, 'user': {'name': 'NVR'}, '@timestamp': 14},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'cym'}, 'user': {'name': 'EEw'}, '@timestamp': 15},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'cym'}, 'user': {'name': 'EEw'}, '@timestamp': 16},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'REGSVR32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'cym'}, 'user': {'name': 'EEw'}, '@timestamp': 17},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'VPY'}, 'user': {'name': 'MGz'}, '@timestamp': 18},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'VPY'}, 'user': {'name': 'MGz'}, '@timestamp': 19},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RegAsm.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'VPY'}, 'user': {'name': 'MGz'}, '@timestamp': 20},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'Nfm'}, 'user': {'name': 'lOP'}, '@timestamp': 21},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'Nfm'}, 'user': {'name': 'lOP'}, '@timestamp': 22},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSBuild.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'Nfm'}, 'user': {'name': 'lOP'}, '@timestamp': 23},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'ZRg'}, 'user': {'name': 'UvW'}, '@timestamp': 24},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'ZRg'}, 'user': {'name': 'UvW'}, '@timestamp': 25},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'InstallUtil.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'ZRg'}, 'user': {'name': 'UvW'}, '@timestamp': 26},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'CiM'}, 'user': {'name': 'ZOf'}, '@timestamp': 27},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'CiM'}, 'user': {'name': 'ZOf'}, '@timestamp': 28},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'cscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'CiM'}, 'user': {'name': 'ZOf'}, '@timestamp': 29},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'HaT'}, 'user': {'name': 'Dgz'}, '@timestamp': 30},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'HaT'}, 'user': {'name': 'Dgz'}, '@timestamp': 31},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'wscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'HaT'}, 'user': {'name': 'Dgz'}, '@timestamp': 32},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'RJi'}, 'user': {'name': 'LSj'}, '@timestamp': 33},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'RJi'}, 'user': {'name': 'LSj'}, '@timestamp': 34},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'RJi'}, 'user': {'name': 'LSj'}, '@timestamp': 35},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'oGr'}, 'user': {'name': 'myw'}, '@timestamp': 36},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'oGr'}, 'user': {'name': 'myw'}, '@timestamp': 37},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSHTA.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'oGr'}, 'user': {'name': 'myw'}, '@timestamp': 38},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'DUN'}, 'user': {'name': 'rZj'}, '@timestamp': 39},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'DUN'}, 'user': {'name': 'rZj'}, '@timestamp': 40},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'DUN'}, 'user': {'name': 'rZj'}, '@timestamp': 41},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'eyL'}, 'user': {'name': 'uZf'}, '@timestamp': 42},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'eyL'}, 'user': {'name': 'uZf'}, '@timestamp': 43},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'REGSVR32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'eyL'}, 'user': {'name': 'uZf'}, '@timestamp': 44},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'Izm'}, 'user': {'name': 'iEG'}, '@timestamp': 45},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'Izm'}, 'user': {'name': 'iEG'}, '@timestamp': 46},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RegAsm.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'Izm'}, 'user': {'name': 'iEG'}, '@timestamp': 47},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'gav'}, 'user': {'name': 'KEI'}, '@timestamp': 48},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'gav'}, 'user': {'name': 'KEI'}, '@timestamp': 49},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSBuild.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'gav'}, 'user': {'name': 'KEI'}, '@timestamp': 50},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'pdu'}, 'user': {'name': 'DJL'}, '@timestamp': 51},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'pdu'}, 'user': {'name': 'DJL'}, '@timestamp': 52},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'InstallUtil.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'pdu'}, 'user': {'name': 'DJL'}, '@timestamp': 53},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'Mru'}, 'user': {'name': 'Toc'}, '@timestamp': 54},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'Mru'}, 'user': {'name': 'Toc'}, '@timestamp': 55},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'cscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'Mru'}, 'user': {'name': 'Toc'}, '@timestamp': 56},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'svB'}, 'user': {'name': 'ayA'}, '@timestamp': 57},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'svB'}, 'user': {'name': 'ayA'}, '@timestamp': 58},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'wscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'svB'}, 'user': {'name': 'ayA'}, '@timestamp': 59},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'olI'}, 'user': {'name': 'YAR'}, '@timestamp': 60},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'olI'}, 'user': {'name': 'YAR'}, '@timestamp': 61},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'olI'}, 'user': {'name': 'YAR'}, '@timestamp': 62},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'LbR'}, 'user': {'name': 'zWY'}, '@timestamp': 63},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'LbR'}, 'user': {'name': 'zWY'}, '@timestamp': 64},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSHTA.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'LbR'}, 'user': {'name': 'zWY'}, '@timestamp': 65},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'srf'}, 'user': {'name': 'ybO'}, '@timestamp': 66},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'srf'}, 'user': {'name': 'ybO'}, '@timestamp': 67},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'srf'}, 'user': {'name': 'ybO'}, '@timestamp': 68},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'YUa'}, 'user': {'name': 'gTr'}, '@timestamp': 69},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'YUa'}, 'user': {'name': 'gTr'}, '@timestamp': 70},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'REGSVR32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'YUa'}, 'user': {'name': 'gTr'}, '@timestamp': 71},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'NYj'}, 'user': {'name': 'LwO'}, '@timestamp': 72},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'NYj'}, 'user': {'name': 'LwO'}, '@timestamp': 73},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RegAsm.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'NYj'}, 'user': {'name': 'LwO'}, '@timestamp': 74},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'Tvb'}, 'user': {'name': 'zIv'}, '@timestamp': 75},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'Tvb'}, 'user': {'name': 'zIv'}, '@timestamp': 76},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSBuild.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'Tvb'}, 'user': {'name': 'zIv'}, '@timestamp': 77},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'lLx'}, 'user': {'name': 'tPu'}, '@timestamp': 78},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'lLx'}, 'user': {'name': 'tPu'}, '@timestamp': 79},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'InstallUtil.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'lLx'}, 'user': {'name': 'tPu'}, '@timestamp': 80},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'AMM'}, 'user': {'name': 'Fqp'}, '@timestamp': 81},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'AMM'}, 'user': {'name': 'Fqp'}, '@timestamp': 82},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'cscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'AMM'}, 'user': {'name': 'Fqp'}, '@timestamp': 83},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'kOO'}, 'user': {'name': 'kis'}, '@timestamp': 84},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'kOO'}, 'user': {'name': 'kis'}, '@timestamp': 85},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'wscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'kOO'}, 'user': {'name': 'kis'}, '@timestamp': 86},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'thB'}, 'user': {'name': 'Czn'}, '@timestamp': 87},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'thB'}, 'user': {'name': 'Czn'}, '@timestamp': 88},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'thB'}, 'user': {'name': 'Czn'}, '@timestamp': 89},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'Njd'}, 'user': {'name': 'yQm'}, '@timestamp': 90},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'Njd'}, 'user': {'name': 'yQm'}, '@timestamp': 91},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSHTA.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'Njd'}, 'user': {'name': 'yQm'}, '@timestamp': 92},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'SbA'}, 'user': {'name': 'gZp'}, '@timestamp': 93},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'SbA'}, 'user': {'name': 'gZp'}, '@timestamp': 94},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'SbA'}, 'user': {'name': 'gZp'}, '@timestamp': 95},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'GZa'}, 'user': {'name': 'Tdb'}, '@timestamp': 96},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'GZa'}, 'user': {'name': 'Tdb'}, '@timestamp': 97},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'REGSVR32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'GZa'}, 'user': {'name': 'Tdb'}, '@timestamp': 98},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'FRI'}, 'user': {'name': 'sji'}, '@timestamp': 99},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'FRI'}, 'user': {'name': 'sji'}, '@timestamp': 100},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RegAsm.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'FRI'}, 'user': {'name': 'sji'}, '@timestamp': 101},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'LnP'}, 'user': {'name': 'tYo'}, '@timestamp': 102},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'LnP'}, 'user': {'name': 'tYo'}, '@timestamp': 103},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSBuild.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'LnP'}, 'user': {'name': 'tYo'}, '@timestamp': 104},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'Ufu'}, 'user': {'name': 'FWk'}, '@timestamp': 105},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'Ufu'}, 'user': {'name': 'FWk'}, '@timestamp': 106},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'InstallUtil.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'Ufu'}, 'user': {'name': 'FWk'}, '@timestamp': 107},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'PRa'}, 'user': {'name': 'QXr'}, '@timestamp': 108},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'PRa'}, 'user': {'name': 'QXr'}, '@timestamp': 109},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'cscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'PRa'}, 'user': {'name': 'QXr'}, '@timestamp': 110},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'kNg'}, 'user': {'name': 'yXL'}, '@timestamp': 111},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'kNg'}, 'user': {'name': 'yXL'}, '@timestamp': 112},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'wscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'kNg'}, 'user': {'name': 'yXL'}, '@timestamp': 113},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'ZiZ'}, 'user': {'name': 'pAg'}, '@timestamp': 114},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'ZiZ'}, 'user': {'name': 'pAg'}, '@timestamp': 115},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'ZiZ'}, 'user': {'name': 'pAg'}, '@timestamp': 116},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'pPT'}, 'user': {'name': 'PzX'}, '@timestamp': 117},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'pPT'}, 'user': {'name': 'PzX'}, '@timestamp': 118},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSHTA.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'pPT'}, 'user': {'name': 'PzX'}, '@timestamp': 119},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'Lhv'}, 'user': {'name': 'NEh'}, '@timestamp': 120},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'Lhv'}, 'user': {'name': 'NEh'}, '@timestamp': 121},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'Lhv'}, 'user': {'name': 'NEh'}, '@timestamp': 122},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'Rrd'}, 'user': {'name': 'FNh'}, '@timestamp': 123},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'Rrd'}, 'user': {'name': 'FNh'}, '@timestamp': 124},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'REGSVR32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'Rrd'}, 'user': {'name': 'FNh'}, '@timestamp': 125},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'oQP'}, 'user': {'name': 'sNG'}, '@timestamp': 126},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'oQP'}, 'user': {'name': 'sNG'}, '@timestamp': 127},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RegAsm.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'oQP'}, 'user': {'name': 'sNG'}, '@timestamp': 128},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'ATJ'}, 'user': {'name': 'mwZ'}, '@timestamp': 129},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'ATJ'}, 'user': {'name': 'mwZ'}, '@timestamp': 130},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSBuild.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'ATJ'}, 'user': {'name': 'mwZ'}, '@timestamp': 131},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'HQy'}, 'user': {'name': 'Bcb'}, '@timestamp': 132},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'HQy'}, 'user': {'name': 'Bcb'}, '@timestamp': 133},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'InstallUtil.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'HQy'}, 'user': {'name': 'Bcb'}, '@timestamp': 134},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'qJj'}, 'user': {'name': 'vmQ'}, '@timestamp': 135},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'qJj'}, 'user': {'name': 'vmQ'}, '@timestamp': 136},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'cscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'qJj'}, 'user': {'name': 'vmQ'}, '@timestamp': 137},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'EYJ'}, 'user': {'name': 'XuO'}, '@timestamp': 138},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'EYJ'}, 'user': {'name': 'XuO'}, '@timestamp': 139},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'wscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'EYJ'}, 'user': {'name': 'XuO'}, '@timestamp': 140},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'LNy'}, 'user': {'name': 'JDj'}, '@timestamp': 141},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'LNy'}, 'user': {'name': 'JDj'}, '@timestamp': 142},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'LNy'}, 'user': {'name': 'JDj'}, '@timestamp': 143},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'LAG'}, 'user': {'name': 'yXj'}, '@timestamp': 144},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'LAG'}, 'user': {'name': 'yXj'}, '@timestamp': 145},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSHTA.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'LAG'}, 'user': {'name': 'yXj'}, '@timestamp': 146},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'TFO'}, 'user': {'name': 'gMM'}, '@timestamp': 147},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'TFO'}, 'user': {'name': 'gMM'}, '@timestamp': 148},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'TFO'}, 'user': {'name': 'gMM'}, '@timestamp': 149},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'Pkz'}, 'user': {'name': 'BsU'}, '@timestamp': 150},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'Pkz'}, 'user': {'name': 'BsU'}, '@timestamp': 151},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'REGSVR32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'Pkz'}, 'user': {'name': 'BsU'}, '@timestamp': 152},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'TCj'}, 'user': {'name': 'fwZ'}, '@timestamp': 153},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'TCj'}, 'user': {'name': 'fwZ'}, '@timestamp': 154},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RegAsm.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'TCj'}, 'user': {'name': 'fwZ'}, '@timestamp': 155},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'iGt'}, 'user': {'name': 'xuX'}, '@timestamp': 156},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'iGt'}, 'user': {'name': 'xuX'}, '@timestamp': 157},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSBuild.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'iGt'}, 'user': {'name': 'xuX'}, '@timestamp': 158},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'xWg'}, 'user': {'name': 'uzn'}, '@timestamp': 159},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'xWg'}, 'user': {'name': 'uzn'}, '@timestamp': 160},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'InstallUtil.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'xWg'}, 'user': {'name': 'uzn'}, '@timestamp': 161},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'kkC'}, 'user': {'name': 'GpD'}, '@timestamp': 162},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'kkC'}, 'user': {'name': 'GpD'}, '@timestamp': 163},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'cscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'kkC'}, 'user': {'name': 'GpD'}, '@timestamp': 164},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'BGQ'}, 'user': {'name': 'zgU'}, '@timestamp': 165},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'BGQ'}, 'user': {'name': 'zgU'}, '@timestamp': 166},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'wscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'BGQ'}, 'user': {'name': 'zgU'}, '@timestamp': 167},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'Nph'}, 'user': {'name': 'HcY'}, '@timestamp': 168},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'Nph'}, 'user': {'name': 'HcY'}, '@timestamp': 169},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'Nph'}, 'user': {'name': 'HcY'}, '@timestamp': 170},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'efW'}, 'user': {'name': 'ryE'}, '@timestamp': 171},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'efW'}, 'user': {'name': 'ryE'}, '@timestamp': 172},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSHTA.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'efW'}, 'user': {'name': 'ryE'}, '@timestamp': 173},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'YNp'}, 'user': {'name': 'ksi'}, '@timestamp': 174},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'YNp'}, 'user': {'name': 'ksi'}, '@timestamp': 175},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'YNp'}, 'user': {'name': 'ksi'}, '@timestamp': 176},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'hfo'}, 'user': {'name': 'HNU'}, '@timestamp': 177},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'hfo'}, 'user': {'name': 'HNU'}, '@timestamp': 178},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'REGSVR32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'hfo'}, 'user': {'name': 'HNU'}, '@timestamp': 179},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'tWb'}, 'user': {'name': 'yTv'}, '@timestamp': 180},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'tWb'}, 'user': {'name': 'yTv'}, '@timestamp': 181},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RegAsm.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'tWb'}, 'user': {'name': 'yTv'}, '@timestamp': 182},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'xUm'}, 'user': {'name': 'tVt'}, '@timestamp': 183},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'xUm'}, 'user': {'name': 'tVt'}, '@timestamp': 184},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSBuild.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'xUm'}, 'user': {'name': 'tVt'}, '@timestamp': 185},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'nYh'}, 'user': {'name': 'bqj'}, '@timestamp': 186},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'nYh'}, 'user': {'name': 'bqj'}, '@timestamp': 187},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'InstallUtil.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'nYh'}, 'user': {'name': 'bqj'}, '@timestamp': 188},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'oFZ'}, 'user': {'name': 'iFm'}, '@timestamp': 189},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'oFZ'}, 'user': {'name': 'iFm'}, '@timestamp': 190},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'cscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'oFZ'}, 'user': {'name': 'iFm'}, '@timestamp': 191},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'hdx'}, 'user': {'name': 'tgm'}, '@timestamp': 192},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'hdx'}, 'user': {'name': 'tgm'}, '@timestamp': 193},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'wscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'hdx'}, 'user': {'name': 'tgm'}, '@timestamp': 194},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'FTY'}, 'user': {'name': 'eaU'}, '@timestamp': 195},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'FTY'}, 'user': {'name': 'eaU'}, '@timestamp': 196},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'FTY'}, 'user': {'name': 'eaU'}, '@timestamp': 197},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'qVU'}, 'user': {'name': 'CGs'}, '@timestamp': 198},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'qVU'}, 'user': {'name': 'CGs'}, '@timestamp': 199},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSHTA.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'qVU'}, 'user': {'name': 'CGs'}, '@timestamp': 200},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'tMP'}, 'user': {'name': 'VTT'}, '@timestamp': 201},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'tMP'}, 'user': {'name': 'VTT'}, '@timestamp': 202},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'tMP'}, 'user': {'name': 'VTT'}, '@timestamp': 203},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'USR'}, 'user': {'name': 'JtZ'}, '@timestamp': 204},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'USR'}, 'user': {'name': 'JtZ'}, '@timestamp': 205},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'REGSVR32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'USR'}, 'user': {'name': 'JtZ'}, '@timestamp': 206},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'gOH'}, 'user': {'name': 'Zpa'}, '@timestamp': 207},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'gOH'}, 'user': {'name': 'Zpa'}, '@timestamp': 208},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'RegAsm.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'gOH'}, 'user': {'name': 'Zpa'}, '@timestamp': 209},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'waE'}, 'user': {'name': 'Mwa'}, '@timestamp': 210},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'waE'}, 'user': {'name': 'Mwa'}, '@timestamp': 211},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'MSBuild.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'waE'}, 'user': {'name': 'Mwa'}, '@timestamp': 212},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'userinit.exe', 'parent': {'name': 'winlogon.exe'}}, 'host': {'id': 'NUW'}, 'user': {'name': 'Bkk'}, '@timestamp': 213},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'explorer.exe'}, 'host': {'id': 'NUW'}, 'user': {'name': 'Bkk'}, '@timestamp': 214},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe'}, 'pe': {'original_file_name': 'InstallUtil.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*']}, 'host': {'id': 'NUW'}, 'user': {'name': 'Bkk'}, '@timestamp': 215}]
```



### Execution via Electron Child Process Node.js Module

Branch count: 2  
Document count: 2  
Index: geneve-ut-209

```python
event.category:process and event.type:(start or process_started) and process.args:("-e" and const*require*child_process*)
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['const*require*child_process*', '-e']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'args': ['const*require*child_process*', '-e']}, '@timestamp': 1}]
```



### Execution via MSSQL xp_cmdshell Stored Procedure

Branch count: 2  
Document count: 2  
Index: geneve-ut-210

```python
process where event.type in ("start", "process_started") and
  process.name : "cmd.exe" and process.parent.name : "sqlservr.exe"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'parent': {'name': 'sqlservr.exe'}}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'parent': {'name': 'sqlservr.exe'}}, '@timestamp': 1}]
```



### Execution via Regsvcs/Regasm

Branch count: 4  
Document count: 4  
Index: geneve-ut-211

```python
event.category:process and event.type:(start or process_started) and process.name:(RegAsm.exe or RegSvcs.exe)
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'RegAsm.exe'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'RegSvcs.exe'}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'RegAsm.exe'}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'RegSvcs.exe'}, '@timestamp': 3}]
```



### Execution via TSClient Mountpoint

Branch count: 2  
Document count: 2  
Index: geneve-ut-212

```python
process where event.type in ("start", "process_started") and process.executable : "\\Device\\Mup\\tsclient\\*.exe"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'executable': '\\Device\\Mup\\tsclient\\XIUtkNI.exe'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'executable': '\\Device\\Mup\\tsclient\\ixTFlEzswuEEXp.exe'}, '@timestamp': 1}]
```



### Execution via local SxS Shared Module

Branch count: 1  
Document count: 1  
Index: geneve-ut-213

```python
file where file.extension : "dll" and file.path : "C:\\*\\*.exe.local\\*.dll"
```

```python
[{'file': {'extension': 'dll', 'path': 'C:\\XIUtkNI\\SvILO.exe.local\\Ezswu.dll'}, 'event': {'category': ['file']}, '@timestamp': 0}]
```



### Execution with Explicit Credentials via Scripting

Branch count: 18  
Document count: 18  
Index: geneve-ut-214

```python
event.category:process and event.type:(start or process_started) and
 process.name:"security_authtrampoline" and
 process.parent.name:(osascript or com.apple.automator.runner or sh or bash or dash or zsh or python* or perl* or php* or ruby or pwsh)
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'osascript'}}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'com.apple.automator.runner'}}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'sh'}}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'bash'}}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'dash'}}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'zsh'}}, '@timestamp': 5},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'pythonyXIUtkNIoixTFl'}}, '@timestamp': 6},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'ruby'}}, '@timestamp': 7},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'pwsh'}}, '@timestamp': 8},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'osascript'}}, '@timestamp': 9},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'com.apple.automator.runner'}}, '@timestamp': 10},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'sh'}}, '@timestamp': 11},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'bash'}}, '@timestamp': 12},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'dash'}}, '@timestamp': 13},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'zsh'}}, '@timestamp': 14},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'pythonzswuEEXpWqNVR'}}, '@timestamp': 15},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'ruby'}}, '@timestamp': 16},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'security_authtrampoline', 'parent': {'name': 'pwsh'}}, '@timestamp': 17}]
```



### Exploit - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-215

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:exploit_event or endgame.event_subtype_full:exploit_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'exploit_event'}, 'endgame': {'metadata': {'type': 'detection'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'detection'}, 'event_subtype_full': 'exploit_event'}, '@timestamp': 1}]
```



### Exploit - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-216

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:exploit_event or endgame.event_subtype_full:exploit_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'exploit_event'}, 'endgame': {'metadata': {'type': 'prevention'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'prevention'}, 'event_subtype_full': 'exploit_event'}, '@timestamp': 1}]
```



### Exporting Exchange Mailbox via PowerShell

Branch count: 2  
Document count: 2  
Index: geneve-ut-217

```python
process where event.type in ("start", "process_started") and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and process.args : "New-MailboxExportRequest*"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'pwsh.exe', 'args': ['New-MailboxExportRequest*']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'powershell_ise.exe', 'args': ['New-MailboxExportRequest*']}, '@timestamp': 1}]
```



### External Alerts

Branch count: 1  
Document count: 1  
Index: geneve-ut-218

```python
event.kind:alert and not event.module:(endgame or endpoint)
```

```python
[{'event': {'kind': 'alert', 'module': 'ZFy'}, '@timestamp': 0}]
```



### External IP Lookup from Non-Browser Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-219

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

```python
[{'network': {'protocol': 'dns'}, 'process': {'name': 'ZFy', 'executable': 'lEz'}, 'user': {'id': 'XIU'}, 'event': {'action': 'lookup_requested', 'category': ['network']}, 'dns': {'question': {'name': 'kNIoixTFipstack.com'}}, '@timestamp': 0}]
```



### FTP (File Transfer Protocol) Activity to the Internet

Branch count: 18  
Document count: 18  
Index: geneve-ut-220

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:(20 or 21) or event.dataset:zeek.ftp) and
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
    192.168.0.0/16 or
    224.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  )
```

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 20, 'ip': 'e6ea:94e4:e5ac:b58c:1b43:3a53:aa79:ec59'}, 'source': {'ip': '10.214.62.131'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 20, 'ip': '119.10.44.216'}, 'source': {'ip': '172.31.81.251'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 20, 'ip': '104.129.204.102'}, 'source': {'ip': '192.168.147.58'}, '@timestamp': 2},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 21, 'ip': '149.239.86.175'}, 'source': {'ip': '10.111.13.86'}, '@timestamp': 3},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 21, 'ip': '112.141.185.70'}, 'source': {'ip': '172.27.169.243'}, '@timestamp': 4},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 21, 'ip': 'b781:36ad:968a:1fd9:42e0:603d:9566:7ca8'}, 'source': {'ip': '192.168.197.122'}, '@timestamp': 5},
 {'event': {'category': ['network'], 'dataset': 'zeek.ftp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.155.175.169'}, 'destination': {'ip': '21ff:ce1f:c206:4389:a7:5646:506a:fac3'}, '@timestamp': 6},
 {'event': {'category': ['network'], 'dataset': 'zeek.ftp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.21.27.73'}, 'destination': {'ip': '156.105.128.203'}, '@timestamp': 7},
 {'event': {'category': ['network'], 'dataset': 'zeek.ftp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.162.120'}, 'destination': {'ip': '93.16.168.118'}, '@timestamp': 8},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 20, 'ip': 'cde8:687a:c169:7ee6:e8d4:8f4f:b2cc:3459'}, 'source': {'ip': '10.247.115.164'}, '@timestamp': 9},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 20, 'ip': 'e2fc:2265:c4e2:24bd:4b82:92c6:7ee8:2ac8'}, 'source': {'ip': '172.30.255.121'}, '@timestamp': 10},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 20, 'ip': '147.172.30.18'}, 'source': {'ip': '192.168.120.95'}, '@timestamp': 11},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 21, 'ip': '200.44.53.86'}, 'source': {'ip': '10.231.61.22'}, '@timestamp': 12},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 21, 'ip': 'bd8d:8e9f:3c38:5e93:2a21:f2e3:2a70:2899'}, 'source': {'ip': '172.27.220.217'}, '@timestamp': 13},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 21, 'ip': '3.79.219.137'}, 'source': {'ip': '192.168.64.185'}, '@timestamp': 14},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.ftp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.77.111.86'}, 'destination': {'ip': 'b861:3a65:7d92:a4ae:175d:4ee4:1dd9:801e'}, '@timestamp': 15},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.ftp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.17.96.216'}, 'destination': {'ip': '46.77.189.36'}, '@timestamp': 16},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.ftp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.139.227'}, 'destination': {'ip': '159.213.231.147'}, '@timestamp': 17}]
```



### File Deletion via Shred

Branch count: 8  
Document count: 8  
Index: geneve-ut-221

```python
event.category:process and event.type:(start or process_started) and process.name:shred and
  process.args:("-u" or "--remove" or "-z" or "--zero")
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'shred', 'args': ['-u']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'shred', 'args': ['--remove']}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'shred', 'args': ['-z']}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'shred', 'args': ['--zero']}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'shred', 'args': ['-u']}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'shred', 'args': ['--remove']}, '@timestamp': 5},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'shred', 'args': ['-z']}, '@timestamp': 6},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'shred', 'args': ['--zero']}, '@timestamp': 7}]
```



### File Permission Modification in Writable Directory

Branch count: 24  
Document count: 24  
Index: geneve-ut-222

```python
event.category:process and event.type:(start or process_started) and
  process.name:(chmod or chown or chattr or chgrp) and
  process.working_directory:(/tmp or /var/tmp or /dev/shm) and
  not user.name:root
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chmod', 'working_directory': '/tmp'}, 'user': {'name': 'ZFy'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chmod', 'working_directory': '/var/tmp'}, 'user': {'name': 'XIU'}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chmod', 'working_directory': '/dev/shm'}, 'user': {'name': 'tkN'}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chown', 'working_directory': '/tmp'}, 'user': {'name': 'Ioi'}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chown', 'working_directory': '/var/tmp'}, 'user': {'name': 'xTF'}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chown', 'working_directory': '/dev/shm'}, 'user': {'name': 'lEz'}, '@timestamp': 5},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chattr', 'working_directory': '/tmp'}, 'user': {'name': 'swu'}, '@timestamp': 6},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chattr', 'working_directory': '/var/tmp'}, 'user': {'name': 'EEX'}, '@timestamp': 7},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chattr', 'working_directory': '/dev/shm'}, 'user': {'name': 'pWq'}, '@timestamp': 8},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chgrp', 'working_directory': '/tmp'}, 'user': {'name': 'NVR'}, '@timestamp': 9},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chgrp', 'working_directory': '/var/tmp'}, 'user': {'name': 'cym'}, '@timestamp': 10},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'chgrp', 'working_directory': '/dev/shm'}, 'user': {'name': 'EEw'}, '@timestamp': 11},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chmod', 'working_directory': '/tmp'}, 'user': {'name': 'VPY'}, '@timestamp': 12},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chmod', 'working_directory': '/var/tmp'}, 'user': {'name': 'MGz'}, '@timestamp': 13},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chmod', 'working_directory': '/dev/shm'}, 'user': {'name': 'Nfm'}, '@timestamp': 14},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chown', 'working_directory': '/tmp'}, 'user': {'name': 'lOP'}, '@timestamp': 15},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chown', 'working_directory': '/var/tmp'}, 'user': {'name': 'ZRg'}, '@timestamp': 16},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chown', 'working_directory': '/dev/shm'}, 'user': {'name': 'UvW'}, '@timestamp': 17},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chattr', 'working_directory': '/tmp'}, 'user': {'name': 'CiM'}, '@timestamp': 18},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chattr', 'working_directory': '/var/tmp'}, 'user': {'name': 'ZOf'}, '@timestamp': 19},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chattr', 'working_directory': '/dev/shm'}, 'user': {'name': 'HaT'}, '@timestamp': 20},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chgrp', 'working_directory': '/tmp'}, 'user': {'name': 'Dgz'}, '@timestamp': 21},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chgrp', 'working_directory': '/var/tmp'}, 'user': {'name': 'RJi'}, '@timestamp': 22},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'chgrp', 'working_directory': '/dev/shm'}, 'user': {'name': 'LSj'}, '@timestamp': 23}]
```



### File and Directory Discovery

Branch count: 125  
Document count: 375  
Index: geneve-ut-223

```python
sequence by agent.id, user.name with maxspan=1m
[process where event.type in ("start", "process_started") and
  ((process.name : "cmd.exe" or process.pe.original_file_name == "Cmd.Exe") and process.args : "dir") or
    process.name : "tree.com"]
[process where event.type in ("start", "process_started") and
  ((process.name : "cmd.exe" or process.pe.original_file_name == "Cmd.Exe") and process.args : "dir") or
    process.name : "tree.com"]
[process where event.type in ("start", "process_started") and
  ((process.name : "cmd.exe" or process.pe.original_file_name == "Cmd.Exe") and process.args : "dir") or
    process.name : "tree.com"]
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'ZFy'}, 'user': {'name': 'XIU'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'ZFy'}, 'user': {'name': 'XIU'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'ZFy'}, 'user': {'name': 'XIU'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'tkN'}, 'user': {'name': 'Ioi'}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'tkN'}, 'user': {'name': 'Ioi'}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'tkN'}, 'user': {'name': 'Ioi'}, '@timestamp': 5},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'xTF'}, 'user': {'name': 'lEz'}, '@timestamp': 6},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'xTF'}, 'user': {'name': 'lEz'}, '@timestamp': 7},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'xTF'}, 'user': {'name': 'lEz'}, '@timestamp': 8},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'swu'}, 'user': {'name': 'EEX'}, '@timestamp': 9},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'swu'}, 'user': {'name': 'EEX'}, '@timestamp': 10},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'swu'}, 'user': {'name': 'EEX'}, '@timestamp': 11},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'pWq'}, 'user': {'name': 'NVR'}, '@timestamp': 12},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'pWq'}, 'user': {'name': 'NVR'}, '@timestamp': 13},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'pWq'}, 'user': {'name': 'NVR'}, '@timestamp': 14},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'cym'}, 'user': {'name': 'EEw'}, '@timestamp': 15},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'cym'}, 'user': {'name': 'EEw'}, '@timestamp': 16},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'cym'}, 'user': {'name': 'EEw'}, '@timestamp': 17},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'VPY'}, 'user': {'name': 'MGz'}, '@timestamp': 18},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'VPY'}, 'user': {'name': 'MGz'}, '@timestamp': 19},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'VPY'}, 'user': {'name': 'MGz'}, '@timestamp': 20},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Nfm'}, 'user': {'name': 'lOP'}, '@timestamp': 21},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Nfm'}, 'user': {'name': 'lOP'}, '@timestamp': 22},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Nfm'}, 'user': {'name': 'lOP'}, '@timestamp': 23},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'ZRg'}, 'user': {'name': 'UvW'}, '@timestamp': 24},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'ZRg'}, 'user': {'name': 'UvW'}, '@timestamp': 25},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'ZRg'}, 'user': {'name': 'UvW'}, '@timestamp': 26},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'CiM'}, 'user': {'name': 'ZOf'}, '@timestamp': 27},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'CiM'}, 'user': {'name': 'ZOf'}, '@timestamp': 28},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'CiM'}, 'user': {'name': 'ZOf'}, '@timestamp': 29},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'HaT'}, 'user': {'name': 'Dgz'}, '@timestamp': 30},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'HaT'}, 'user': {'name': 'Dgz'}, '@timestamp': 31},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'HaT'}, 'user': {'name': 'Dgz'}, '@timestamp': 32},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'RJi'}, 'user': {'name': 'LSj'}, '@timestamp': 33},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'RJi'}, 'user': {'name': 'LSj'}, '@timestamp': 34},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'RJi'}, 'user': {'name': 'LSj'}, '@timestamp': 35},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'oGr'}, 'user': {'name': 'myw'}, '@timestamp': 36},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'oGr'}, 'user': {'name': 'myw'}, '@timestamp': 37},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'oGr'}, 'user': {'name': 'myw'}, '@timestamp': 38},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'DUN'}, 'user': {'name': 'rZj'}, '@timestamp': 39},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'DUN'}, 'user': {'name': 'rZj'}, '@timestamp': 40},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'DUN'}, 'user': {'name': 'rZj'}, '@timestamp': 41},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'eyL'}, 'user': {'name': 'uZf'}, '@timestamp': 42},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'eyL'}, 'user': {'name': 'uZf'}, '@timestamp': 43},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'eyL'}, 'user': {'name': 'uZf'}, '@timestamp': 44},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Izm'}, 'user': {'name': 'iEG'}, '@timestamp': 45},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Izm'}, 'user': {'name': 'iEG'}, '@timestamp': 46},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Izm'}, 'user': {'name': 'iEG'}, '@timestamp': 47},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'gav'}, 'user': {'name': 'KEI'}, '@timestamp': 48},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'gav'}, 'user': {'name': 'KEI'}, '@timestamp': 49},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'gav'}, 'user': {'name': 'KEI'}, '@timestamp': 50},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'pdu'}, 'user': {'name': 'DJL'}, '@timestamp': 51},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'pdu'}, 'user': {'name': 'DJL'}, '@timestamp': 52},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'pdu'}, 'user': {'name': 'DJL'}, '@timestamp': 53},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Mru'}, 'user': {'name': 'Toc'}, '@timestamp': 54},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Mru'}, 'user': {'name': 'Toc'}, '@timestamp': 55},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Mru'}, 'user': {'name': 'Toc'}, '@timestamp': 56},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'svB'}, 'user': {'name': 'ayA'}, '@timestamp': 57},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'svB'}, 'user': {'name': 'ayA'}, '@timestamp': 58},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'svB'}, 'user': {'name': 'ayA'}, '@timestamp': 59},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'olI'}, 'user': {'name': 'YAR'}, '@timestamp': 60},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'olI'}, 'user': {'name': 'YAR'}, '@timestamp': 61},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'olI'}, 'user': {'name': 'YAR'}, '@timestamp': 62},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'LbR'}, 'user': {'name': 'zWY'}, '@timestamp': 63},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'LbR'}, 'user': {'name': 'zWY'}, '@timestamp': 64},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'LbR'}, 'user': {'name': 'zWY'}, '@timestamp': 65},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'srf'}, 'user': {'name': 'ybO'}, '@timestamp': 66},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'srf'}, 'user': {'name': 'ybO'}, '@timestamp': 67},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'srf'}, 'user': {'name': 'ybO'}, '@timestamp': 68},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'YUa'}, 'user': {'name': 'gTr'}, '@timestamp': 69},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'YUa'}, 'user': {'name': 'gTr'}, '@timestamp': 70},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'YUa'}, 'user': {'name': 'gTr'}, '@timestamp': 71},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'NYj'}, 'user': {'name': 'LwO'}, '@timestamp': 72},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'NYj'}, 'user': {'name': 'LwO'}, '@timestamp': 73},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'NYj'}, 'user': {'name': 'LwO'}, '@timestamp': 74},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Tvb'}, 'user': {'name': 'zIv'}, '@timestamp': 75},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Tvb'}, 'user': {'name': 'zIv'}, '@timestamp': 76},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Tvb'}, 'user': {'name': 'zIv'}, '@timestamp': 77},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'lLx'}, 'user': {'name': 'tPu'}, '@timestamp': 78},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'lLx'}, 'user': {'name': 'tPu'}, '@timestamp': 79},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'lLx'}, 'user': {'name': 'tPu'}, '@timestamp': 80},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'AMM'}, 'user': {'name': 'Fqp'}, '@timestamp': 81},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'AMM'}, 'user': {'name': 'Fqp'}, '@timestamp': 82},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'AMM'}, 'user': {'name': 'Fqp'}, '@timestamp': 83},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'kOO'}, 'user': {'name': 'kis'}, '@timestamp': 84},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'kOO'}, 'user': {'name': 'kis'}, '@timestamp': 85},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'kOO'}, 'user': {'name': 'kis'}, '@timestamp': 86},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'thB'}, 'user': {'name': 'Czn'}, '@timestamp': 87},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'thB'}, 'user': {'name': 'Czn'}, '@timestamp': 88},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'thB'}, 'user': {'name': 'Czn'}, '@timestamp': 89},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Njd'}, 'user': {'name': 'yQm'}, '@timestamp': 90},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Njd'}, 'user': {'name': 'yQm'}, '@timestamp': 91},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Njd'}, 'user': {'name': 'yQm'}, '@timestamp': 92},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'SbA'}, 'user': {'name': 'gZp'}, '@timestamp': 93},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'SbA'}, 'user': {'name': 'gZp'}, '@timestamp': 94},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'SbA'}, 'user': {'name': 'gZp'}, '@timestamp': 95},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'GZa'}, 'user': {'name': 'Tdb'}, '@timestamp': 96},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'GZa'}, 'user': {'name': 'Tdb'}, '@timestamp': 97},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'GZa'}, 'user': {'name': 'Tdb'}, '@timestamp': 98},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'FRI'}, 'user': {'name': 'sji'}, '@timestamp': 99},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'FRI'}, 'user': {'name': 'sji'}, '@timestamp': 100},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'FRI'}, 'user': {'name': 'sji'}, '@timestamp': 101},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'LnP'}, 'user': {'name': 'tYo'}, '@timestamp': 102},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'LnP'}, 'user': {'name': 'tYo'}, '@timestamp': 103},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'LnP'}, 'user': {'name': 'tYo'}, '@timestamp': 104},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Ufu'}, 'user': {'name': 'FWk'}, '@timestamp': 105},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Ufu'}, 'user': {'name': 'FWk'}, '@timestamp': 106},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Ufu'}, 'user': {'name': 'FWk'}, '@timestamp': 107},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'PRa'}, 'user': {'name': 'QXr'}, '@timestamp': 108},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'PRa'}, 'user': {'name': 'QXr'}, '@timestamp': 109},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'PRa'}, 'user': {'name': 'QXr'}, '@timestamp': 110},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'kNg'}, 'user': {'name': 'yXL'}, '@timestamp': 111},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'kNg'}, 'user': {'name': 'yXL'}, '@timestamp': 112},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'kNg'}, 'user': {'name': 'yXL'}, '@timestamp': 113},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'ZiZ'}, 'user': {'name': 'pAg'}, '@timestamp': 114},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'ZiZ'}, 'user': {'name': 'pAg'}, '@timestamp': 115},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'ZiZ'}, 'user': {'name': 'pAg'}, '@timestamp': 116},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'pPT'}, 'user': {'name': 'PzX'}, '@timestamp': 117},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'pPT'}, 'user': {'name': 'PzX'}, '@timestamp': 118},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'pPT'}, 'user': {'name': 'PzX'}, '@timestamp': 119},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Lhv'}, 'user': {'name': 'NEh'}, '@timestamp': 120},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Lhv'}, 'user': {'name': 'NEh'}, '@timestamp': 121},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Lhv'}, 'user': {'name': 'NEh'}, '@timestamp': 122},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Rrd'}, 'user': {'name': 'FNh'}, '@timestamp': 123},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Rrd'}, 'user': {'name': 'FNh'}, '@timestamp': 124},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Rrd'}, 'user': {'name': 'FNh'}, '@timestamp': 125},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'oQP'}, 'user': {'name': 'sNG'}, '@timestamp': 126},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'oQP'}, 'user': {'name': 'sNG'}, '@timestamp': 127},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'oQP'}, 'user': {'name': 'sNG'}, '@timestamp': 128},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'ATJ'}, 'user': {'name': 'mwZ'}, '@timestamp': 129},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'ATJ'}, 'user': {'name': 'mwZ'}, '@timestamp': 130},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'ATJ'}, 'user': {'name': 'mwZ'}, '@timestamp': 131},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'HQy'}, 'user': {'name': 'Bcb'}, '@timestamp': 132},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'HQy'}, 'user': {'name': 'Bcb'}, '@timestamp': 133},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'HQy'}, 'user': {'name': 'Bcb'}, '@timestamp': 134},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'qJj'}, 'user': {'name': 'vmQ'}, '@timestamp': 135},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'qJj'}, 'user': {'name': 'vmQ'}, '@timestamp': 136},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'qJj'}, 'user': {'name': 'vmQ'}, '@timestamp': 137},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'EYJ'}, 'user': {'name': 'XuO'}, '@timestamp': 138},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'EYJ'}, 'user': {'name': 'XuO'}, '@timestamp': 139},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'EYJ'}, 'user': {'name': 'XuO'}, '@timestamp': 140},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'LNy'}, 'user': {'name': 'JDj'}, '@timestamp': 141},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'LNy'}, 'user': {'name': 'JDj'}, '@timestamp': 142},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'LNy'}, 'user': {'name': 'JDj'}, '@timestamp': 143},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'LAG'}, 'user': {'name': 'yXj'}, '@timestamp': 144},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'LAG'}, 'user': {'name': 'yXj'}, '@timestamp': 145},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'LAG'}, 'user': {'name': 'yXj'}, '@timestamp': 146},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'TFO'}, 'user': {'name': 'gMM'}, '@timestamp': 147},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'TFO'}, 'user': {'name': 'gMM'}, '@timestamp': 148},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'TFO'}, 'user': {'name': 'gMM'}, '@timestamp': 149},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Pkz'}, 'user': {'name': 'BsU'}, '@timestamp': 150},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Pkz'}, 'user': {'name': 'BsU'}, '@timestamp': 151},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Pkz'}, 'user': {'name': 'BsU'}, '@timestamp': 152},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'TCj'}, 'user': {'name': 'fwZ'}, '@timestamp': 153},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'TCj'}, 'user': {'name': 'fwZ'}, '@timestamp': 154},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'TCj'}, 'user': {'name': 'fwZ'}, '@timestamp': 155},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'iGt'}, 'user': {'name': 'xuX'}, '@timestamp': 156},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'iGt'}, 'user': {'name': 'xuX'}, '@timestamp': 157},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'iGt'}, 'user': {'name': 'xuX'}, '@timestamp': 158},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'xWg'}, 'user': {'name': 'uzn'}, '@timestamp': 159},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'xWg'}, 'user': {'name': 'uzn'}, '@timestamp': 160},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'xWg'}, 'user': {'name': 'uzn'}, '@timestamp': 161},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'kkC'}, 'user': {'name': 'GpD'}, '@timestamp': 162},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'kkC'}, 'user': {'name': 'GpD'}, '@timestamp': 163},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'kkC'}, 'user': {'name': 'GpD'}, '@timestamp': 164},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'BGQ'}, 'user': {'name': 'zgU'}, '@timestamp': 165},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'BGQ'}, 'user': {'name': 'zgU'}, '@timestamp': 166},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'BGQ'}, 'user': {'name': 'zgU'}, '@timestamp': 167},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Nph'}, 'user': {'name': 'HcY'}, '@timestamp': 168},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Nph'}, 'user': {'name': 'HcY'}, '@timestamp': 169},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Nph'}, 'user': {'name': 'HcY'}, '@timestamp': 170},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'efW'}, 'user': {'name': 'ryE'}, '@timestamp': 171},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'efW'}, 'user': {'name': 'ryE'}, '@timestamp': 172},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'efW'}, 'user': {'name': 'ryE'}, '@timestamp': 173},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'YNp'}, 'user': {'name': 'ksi'}, '@timestamp': 174},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'YNp'}, 'user': {'name': 'ksi'}, '@timestamp': 175},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'YNp'}, 'user': {'name': 'ksi'}, '@timestamp': 176},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'hfo'}, 'user': {'name': 'HNU'}, '@timestamp': 177},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'hfo'}, 'user': {'name': 'HNU'}, '@timestamp': 178},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'hfo'}, 'user': {'name': 'HNU'}, '@timestamp': 179},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'tWb'}, 'user': {'name': 'yTv'}, '@timestamp': 180},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'tWb'}, 'user': {'name': 'yTv'}, '@timestamp': 181},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'tWb'}, 'user': {'name': 'yTv'}, '@timestamp': 182},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'xUm'}, 'user': {'name': 'tVt'}, '@timestamp': 183},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'xUm'}, 'user': {'name': 'tVt'}, '@timestamp': 184},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'xUm'}, 'user': {'name': 'tVt'}, '@timestamp': 185},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'nYh'}, 'user': {'name': 'bqj'}, '@timestamp': 186},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'nYh'}, 'user': {'name': 'bqj'}, '@timestamp': 187},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'nYh'}, 'user': {'name': 'bqj'}, '@timestamp': 188},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'oFZ'}, 'user': {'name': 'iFm'}, '@timestamp': 189},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'oFZ'}, 'user': {'name': 'iFm'}, '@timestamp': 190},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'oFZ'}, 'user': {'name': 'iFm'}, '@timestamp': 191},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'hdx'}, 'user': {'name': 'tgm'}, '@timestamp': 192},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'hdx'}, 'user': {'name': 'tgm'}, '@timestamp': 193},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'hdx'}, 'user': {'name': 'tgm'}, '@timestamp': 194},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'FTY'}, 'user': {'name': 'eaU'}, '@timestamp': 195},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'FTY'}, 'user': {'name': 'eaU'}, '@timestamp': 196},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'FTY'}, 'user': {'name': 'eaU'}, '@timestamp': 197},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'qVU'}, 'user': {'name': 'CGs'}, '@timestamp': 198},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'qVU'}, 'user': {'name': 'CGs'}, '@timestamp': 199},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'qVU'}, 'user': {'name': 'CGs'}, '@timestamp': 200},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'tMP'}, 'user': {'name': 'VTT'}, '@timestamp': 201},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'tMP'}, 'user': {'name': 'VTT'}, '@timestamp': 202},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'tMP'}, 'user': {'name': 'VTT'}, '@timestamp': 203},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'USR'}, 'user': {'name': 'JtZ'}, '@timestamp': 204},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'USR'}, 'user': {'name': 'JtZ'}, '@timestamp': 205},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'USR'}, 'user': {'name': 'JtZ'}, '@timestamp': 206},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'gOH'}, 'user': {'name': 'Zpa'}, '@timestamp': 207},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'gOH'}, 'user': {'name': 'Zpa'}, '@timestamp': 208},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'gOH'}, 'user': {'name': 'Zpa'}, '@timestamp': 209},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'waE'}, 'user': {'name': 'Mwa'}, '@timestamp': 210},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'waE'}, 'user': {'name': 'Mwa'}, '@timestamp': 211},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'waE'}, 'user': {'name': 'Mwa'}, '@timestamp': 212},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'NUW'}, 'user': {'name': 'Bkk'}, '@timestamp': 213},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'NUW'}, 'user': {'name': 'Bkk'}, '@timestamp': 214},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'NUW'}, 'user': {'name': 'Bkk'}, '@timestamp': 215},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'EvW'}, 'user': {'name': 'pDa'}, '@timestamp': 216},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'EvW'}, 'user': {'name': 'pDa'}, '@timestamp': 217},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'EvW'}, 'user': {'name': 'pDa'}, '@timestamp': 218},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'EHo'}, 'user': {'name': 'LUQ'}, '@timestamp': 219},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'EHo'}, 'user': {'name': 'LUQ'}, '@timestamp': 220},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'EHo'}, 'user': {'name': 'LUQ'}, '@timestamp': 221},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'rOp'}, 'user': {'name': 'AoP'}, '@timestamp': 222},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'rOp'}, 'user': {'name': 'AoP'}, '@timestamp': 223},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'rOp'}, 'user': {'name': 'AoP'}, '@timestamp': 224},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'snA'}, 'user': {'name': 'zfT'}, '@timestamp': 225},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'snA'}, 'user': {'name': 'zfT'}, '@timestamp': 226},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'snA'}, 'user': {'name': 'zfT'}, '@timestamp': 227},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'GhC'}, 'user': {'name': 'SBI'}, '@timestamp': 228},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'GhC'}, 'user': {'name': 'SBI'}, '@timestamp': 229},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'GhC'}, 'user': {'name': 'SBI'}, '@timestamp': 230},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'evW'}, 'user': {'name': 'DFj'}, '@timestamp': 231},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'evW'}, 'user': {'name': 'DFj'}, '@timestamp': 232},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'evW'}, 'user': {'name': 'DFj'}, '@timestamp': 233},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'vNw'}, 'user': {'name': 'Zvp'}, '@timestamp': 234},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'vNw'}, 'user': {'name': 'Zvp'}, '@timestamp': 235},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'vNw'}, 'user': {'name': 'Zvp'}, '@timestamp': 236},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'lGK'}, 'user': {'name': 'nmJ'}, '@timestamp': 237},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'lGK'}, 'user': {'name': 'nmJ'}, '@timestamp': 238},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'lGK'}, 'user': {'name': 'nmJ'}, '@timestamp': 239},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'xAR'}, 'user': {'name': 'fvC'}, '@timestamp': 240},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'xAR'}, 'user': {'name': 'fvC'}, '@timestamp': 241},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'xAR'}, 'user': {'name': 'fvC'}, '@timestamp': 242},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'JYG'}, 'user': {'name': 'JPo'}, '@timestamp': 243},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'JYG'}, 'user': {'name': 'JPo'}, '@timestamp': 244},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'JYG'}, 'user': {'name': 'JPo'}, '@timestamp': 245},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'rCs'}, 'user': {'name': 'mbe'}, '@timestamp': 246},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'rCs'}, 'user': {'name': 'mbe'}, '@timestamp': 247},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'rCs'}, 'user': {'name': 'mbe'}, '@timestamp': 248},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'csu'}, 'user': {'name': 'jVM'}, '@timestamp': 249},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'csu'}, 'user': {'name': 'jVM'}, '@timestamp': 250},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'csu'}, 'user': {'name': 'jVM'}, '@timestamp': 251},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'LxI'}, 'user': {'name': 'epS'}, '@timestamp': 252},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'LxI'}, 'user': {'name': 'epS'}, '@timestamp': 253},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'LxI'}, 'user': {'name': 'epS'}, '@timestamp': 254},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Bva'}, 'user': {'name': 'ffs'}, '@timestamp': 255},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Bva'}, 'user': {'name': 'ffs'}, '@timestamp': 256},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Bva'}, 'user': {'name': 'ffs'}, '@timestamp': 257},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'DZs'}, 'user': {'name': 'QGm'}, '@timestamp': 258},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'DZs'}, 'user': {'name': 'QGm'}, '@timestamp': 259},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'DZs'}, 'user': {'name': 'QGm'}, '@timestamp': 260},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'WCV'}, 'user': {'name': 'gEm'}, '@timestamp': 261},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'WCV'}, 'user': {'name': 'gEm'}, '@timestamp': 262},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'WCV'}, 'user': {'name': 'gEm'}, '@timestamp': 263},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Wbt'}, 'user': {'name': 'HvQ'}, '@timestamp': 264},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Wbt'}, 'user': {'name': 'HvQ'}, '@timestamp': 265},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Wbt'}, 'user': {'name': 'HvQ'}, '@timestamp': 266},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'dZp'}, 'user': {'name': 'gGg'}, '@timestamp': 267},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'dZp'}, 'user': {'name': 'gGg'}, '@timestamp': 268},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'dZp'}, 'user': {'name': 'gGg'}, '@timestamp': 269},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'ClA'}, 'user': {'name': 'IUu'}, '@timestamp': 270},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'ClA'}, 'user': {'name': 'IUu'}, '@timestamp': 271},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'ClA'}, 'user': {'name': 'IUu'}, '@timestamp': 272},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Idq'}, 'user': {'name': 'CpZ'}, '@timestamp': 273},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Idq'}, 'user': {'name': 'CpZ'}, '@timestamp': 274},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Idq'}, 'user': {'name': 'CpZ'}, '@timestamp': 275},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'mvu'}, 'user': {'name': 'YwG'}, '@timestamp': 276},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'mvu'}, 'user': {'name': 'YwG'}, '@timestamp': 277},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'mvu'}, 'user': {'name': 'YwG'}, '@timestamp': 278},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'WGR'}, 'user': {'name': 'LbR'}, '@timestamp': 279},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'WGR'}, 'user': {'name': 'LbR'}, '@timestamp': 280},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'WGR'}, 'user': {'name': 'LbR'}, '@timestamp': 281},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'iPS'}, 'user': {'name': 'zSY'}, '@timestamp': 282},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'iPS'}, 'user': {'name': 'zSY'}, '@timestamp': 283},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'iPS'}, 'user': {'name': 'zSY'}, '@timestamp': 284},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'xes'}, 'user': {'name': 'FNF'}, '@timestamp': 285},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'xes'}, 'user': {'name': 'FNF'}, '@timestamp': 286},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'xes'}, 'user': {'name': 'FNF'}, '@timestamp': 287},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'hyW'}, 'user': {'name': 'KCK'}, '@timestamp': 288},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'hyW'}, 'user': {'name': 'KCK'}, '@timestamp': 289},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'hyW'}, 'user': {'name': 'KCK'}, '@timestamp': 290},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'CsB'}, 'user': {'name': 'cMQ'}, '@timestamp': 291},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'CsB'}, 'user': {'name': 'cMQ'}, '@timestamp': 292},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'CsB'}, 'user': {'name': 'cMQ'}, '@timestamp': 293},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'xXQ'}, 'user': {'name': 'rxL'}, '@timestamp': 294},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'xXQ'}, 'user': {'name': 'rxL'}, '@timestamp': 295},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'xXQ'}, 'user': {'name': 'rxL'}, '@timestamp': 296},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'lBR'}, 'user': {'name': 'KKv'}, '@timestamp': 297},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'lBR'}, 'user': {'name': 'KKv'}, '@timestamp': 298},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'lBR'}, 'user': {'name': 'KKv'}, '@timestamp': 299},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'zkE'}, 'user': {'name': 'AQn'}, '@timestamp': 300},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'zkE'}, 'user': {'name': 'AQn'}, '@timestamp': 301},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'zkE'}, 'user': {'name': 'AQn'}, '@timestamp': 302},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'wFZ'}, 'user': {'name': 'hyq'}, '@timestamp': 303},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'wFZ'}, 'user': {'name': 'hyq'}, '@timestamp': 304},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'wFZ'}, 'user': {'name': 'hyq'}, '@timestamp': 305},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'LZO'}, 'user': {'name': 'TxJ'}, '@timestamp': 306},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'LZO'}, 'user': {'name': 'TxJ'}, '@timestamp': 307},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'LZO'}, 'user': {'name': 'TxJ'}, '@timestamp': 308},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'HdA'}, 'user': {'name': 'yIe'}, '@timestamp': 309},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'HdA'}, 'user': {'name': 'yIe'}, '@timestamp': 310},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'HdA'}, 'user': {'name': 'yIe'}, '@timestamp': 311},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'iAt'}, 'user': {'name': 'EOw'}, '@timestamp': 312},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'iAt'}, 'user': {'name': 'EOw'}, '@timestamp': 313},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'iAt'}, 'user': {'name': 'EOw'}, '@timestamp': 314},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'lKr'}, 'user': {'name': 'QNG'}, '@timestamp': 315},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'lKr'}, 'user': {'name': 'QNG'}, '@timestamp': 316},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'lKr'}, 'user': {'name': 'QNG'}, '@timestamp': 317},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'CxX'}, 'user': {'name': 'SbS'}, '@timestamp': 318},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'CxX'}, 'user': {'name': 'SbS'}, '@timestamp': 319},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'CxX'}, 'user': {'name': 'SbS'}, '@timestamp': 320},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'aex'}, 'user': {'name': 'ShP'}, '@timestamp': 321},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'aex'}, 'user': {'name': 'ShP'}, '@timestamp': 322},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'aex'}, 'user': {'name': 'ShP'}, '@timestamp': 323},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'TDf'}, 'user': {'name': 'tFl'}, '@timestamp': 324},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'TDf'}, 'user': {'name': 'tFl'}, '@timestamp': 325},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'TDf'}, 'user': {'name': 'tFl'}, '@timestamp': 326},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'gOZ'}, 'user': {'name': 'DDw'}, '@timestamp': 327},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'gOZ'}, 'user': {'name': 'DDw'}, '@timestamp': 328},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'gOZ'}, 'user': {'name': 'DDw'}, '@timestamp': 329},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'pUd'}, 'user': {'name': 'qEn'}, '@timestamp': 330},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'pUd'}, 'user': {'name': 'qEn'}, '@timestamp': 331},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'pUd'}, 'user': {'name': 'qEn'}, '@timestamp': 332},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'Gnj'}, 'user': {'name': 'KWM'}, '@timestamp': 333},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Gnj'}, 'user': {'name': 'KWM'}, '@timestamp': 334},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Gnj'}, 'user': {'name': 'KWM'}, '@timestamp': 335},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'sHa'}, 'user': {'name': 'DyX'}, '@timestamp': 336},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'sHa'}, 'user': {'name': 'DyX'}, '@timestamp': 337},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'sHa'}, 'user': {'name': 'DyX'}, '@timestamp': 338},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'oKb'}, 'user': {'name': 'Yqz'}, '@timestamp': 339},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'oKb'}, 'user': {'name': 'Yqz'}, '@timestamp': 340},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'oKb'}, 'user': {'name': 'Yqz'}, '@timestamp': 341},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'JzZ'}, 'user': {'name': 'Wjx'}, '@timestamp': 342},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'JzZ'}, 'user': {'name': 'Wjx'}, '@timestamp': 343},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'JzZ'}, 'user': {'name': 'Wjx'}, '@timestamp': 344},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'sdq'}, 'user': {'name': 'IVV'}, '@timestamp': 345},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'sdq'}, 'user': {'name': 'IVV'}, '@timestamp': 346},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'sdq'}, 'user': {'name': 'IVV'}, '@timestamp': 347},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'Wkj'}, 'user': {'name': 'tNG'}, '@timestamp': 348},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Wkj'}, 'user': {'name': 'tNG'}, '@timestamp': 349},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Wkj'}, 'user': {'name': 'tNG'}, '@timestamp': 350},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'amc'}, 'user': {'name': 'tZp'}, '@timestamp': 351},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'amc'}, 'user': {'name': 'tZp'}, '@timestamp': 352},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'amc'}, 'user': {'name': 'tZp'}, '@timestamp': 353},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'kSK'}, 'user': {'name': 'EYk'}, '@timestamp': 354},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'kSK'}, 'user': {'name': 'EYk'}, '@timestamp': 355},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'kSK'}, 'user': {'name': 'EYk'}, '@timestamp': 356},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'LGV'}, 'user': {'name': 'aoY'}, '@timestamp': 357},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'LGV'}, 'user': {'name': 'aoY'}, '@timestamp': 358},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'LGV'}, 'user': {'name': 'aoY'}, '@timestamp': 359},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'hvW'}, 'user': {'name': 'cyi'}, '@timestamp': 360},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'hvW'}, 'user': {'name': 'cyi'}, '@timestamp': 361},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'hvW'}, 'user': {'name': 'cyi'}, '@timestamp': 362},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'aVE'}, 'user': {'name': 'DpR'}, '@timestamp': 363},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'aVE'}, 'user': {'name': 'DpR'}, '@timestamp': 364},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'aVE'}, 'user': {'name': 'DpR'}, '@timestamp': 365},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'Jks'}, 'user': {'name': 'rhV'}, '@timestamp': 366},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'Jks'}, 'user': {'name': 'rhV'}, '@timestamp': 367},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'args': ['dir']}, 'agent': {'id': 'Jks'}, 'user': {'name': 'rhV'}, '@timestamp': 368},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'Csw'}, 'user': {'name': 'Muj'}, '@timestamp': 369},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'Csw'}, 'user': {'name': 'Muj'}, '@timestamp': 370},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['dir']}, 'agent': {'id': 'Csw'}, 'user': {'name': 'Muj'}, '@timestamp': 371},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'epT'}, 'user': {'name': 'rxP'}, '@timestamp': 372},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'epT'}, 'user': {'name': 'rxP'}, '@timestamp': 373},
 {'process': {'name': 'tree.com'}, 'event': {'category': ['process']}, 'agent': {'id': 'epT'}, 'user': {'name': 'rxP'}, '@timestamp': 374}]
```



### Finder Sync Plugin Registered and Enabled

Branch count: 4  
Document count: 8  
Index: geneve-ut-224

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'pluginkit', 'args': ['-a']}, 'host': {'id': 'ZFy'}, 'user': {'id': 'XIU'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'pluginkit', 'args': ['-e', 'use', '-i']}, 'host': {'id': 'ZFy'}, 'user': {'id': 'XIU'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'pluginkit', 'args': ['-a']}, 'host': {'id': 'tkN'}, 'user': {'id': 'Ioi'}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'pluginkit', 'args': ['-e', 'use', '-i']}, 'host': {'id': 'tkN'}, 'user': {'id': 'Ioi'}, '@timestamp': 3},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'pluginkit', 'args': ['-a']}, 'host': {'id': 'xTF'}, 'user': {'id': 'lEz'}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'pluginkit', 'args': ['-e', 'use', '-i']}, 'host': {'id': 'xTF'}, 'user': {'id': 'lEz'}, '@timestamp': 5},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'pluginkit', 'args': ['-a']}, 'host': {'id': 'swu'}, 'user': {'id': 'EEX'}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'pluginkit', 'args': ['-e', 'use', '-i']}, 'host': {'id': 'swu'}, 'user': {'id': 'EEX'}, '@timestamp': 7}]
```



### GCP Firewall Rule Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-225

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:v*.compute.firewalls.insert
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'vXIUtkNI.compute.firewalls.insert'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'vixTFlEzswuEEXp.compute.firewalls.insert'}, '@timestamp': 1}]
```



### GCP Firewall Rule Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-226

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:v*.compute.firewalls.delete
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'vXIUtkNI.compute.firewalls.delete'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'vixTFlEzswuEEXp.compute.firewalls.delete'}, '@timestamp': 1}]
```



### GCP Firewall Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-227

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:v*.compute.firewalls.patch
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'vXIUtkNI.compute.firewalls.patch'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'vixTFlEzswuEEXp.compute.firewalls.patch'}, '@timestamp': 1}]
```



### GCP IAM Custom Role Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-228

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.CreateRole and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vXIUtkNI.CreateRole', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vixTFlEzswuEEXp.CreateRole', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP IAM Role Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-229

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.DeleteRole and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vXIUtkNI.DeleteRole', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vixTFlEzswuEEXp.DeleteRole', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP IAM Service Account Key Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-230

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.DeleteServiceAccountKey and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vXIUtkNI.DeleteServiceAccountKey', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vixTFlEzswuEEXp.DeleteServiceAccountKey', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Kubernetes Rolebindings Created or Patched

Branch count: 2  
Document count: 2  
Index: geneve-ut-231

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:(io.k8s.authorization.rbac.v*.clusterrolebindings.create or 
io.k8s.authorization.rbac.v*.rolebindings.create or io.k8s.authorization.rbac.v*.clusterrolebindings.patch or 
io.k8s.authorization.rbac.v*.rolebindings.patch) and event.outcome:success and
not gcp.audit.authentication_info.principal_email:"system:addon-manager"
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'io.k8s.authorization.rbac.vXIUtkNI.rolebindings.patch', 'outcome': 'success'}, 'gcp': {'audit': {'authentication_info': {'principal_email': 'oix'}}}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'io.k8s.authorization.rbac.vEzswu.clusterrolebindings.patch', 'outcome': 'success'}, 'gcp': {'audit': {'authentication_info': {'principal_email': 'EEX'}}}, '@timestamp': 1}]
```



### GCP Logging Bucket Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-232

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.logging.v*.ConfigServiceV*.DeleteBucket and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.logging.vXIUtkNI.ConfigServiceVSvILO.DeleteBucket', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.logging.vOHmxBnLeOA.ConfigServiceVN.DeleteBucket', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Logging Sink Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-233

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.logging.v*.ConfigServiceV*.DeleteSink and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.logging.vXIUtkNI.ConfigServiceVSvILO.DeleteSink', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.logging.vOHmxBnLeOA.ConfigServiceVN.DeleteSink', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Logging Sink Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-234

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.logging.v*.ConfigServiceV*.UpdateSink and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.logging.vXIUtkNI.ConfigServiceVSvILO.UpdateSink', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.logging.vOHmxBnLeOA.ConfigServiceVN.UpdateSink', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Pub/Sub Subscription Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-235

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Subscriber.CreateSubscription and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.pubsub.vXIUtkNI.Subscriber.CreateSubscription', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.pubsub.vixTFlEzswuEEXp.Subscriber.CreateSubscription', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Pub/Sub Subscription Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-236

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Subscriber.DeleteSubscription and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.pubsub.vXIUtkNI.Subscriber.DeleteSubscription', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.pubsub.vixTFlEzswuEEXp.Subscriber.DeleteSubscription', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Pub/Sub Topic Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-237

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Publisher.CreateTopic and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.pubsub.vXIUtkNI.Publisher.CreateTopic', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.pubsub.vixTFlEzswuEEXp.Publisher.CreateTopic', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Pub/Sub Topic Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-238

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Publisher.DeleteTopic and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.pubsub.vXIUtkNI.Publisher.DeleteTopic', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.pubsub.vixTFlEzswuEEXp.Publisher.DeleteTopic', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Service Account Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-239

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.CreateServiceAccount and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vXIUtkNI.CreateServiceAccount', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vixTFlEzswuEEXp.CreateServiceAccount', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Service Account Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-240

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.DeleteServiceAccount and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vXIUtkNI.DeleteServiceAccount', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vixTFlEzswuEEXp.DeleteServiceAccount', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Service Account Disabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-241

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.DisableServiceAccount and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vXIUtkNI.DisableServiceAccount', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vixTFlEzswuEEXp.DisableServiceAccount', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Service Account Key Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-242

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.iam.admin.v*.CreateServiceAccountKey and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'google.iam.admin.vXIUtkNI.CreateServiceAccountKey', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'google.iam.admin.vixTFlEzswuEEXp.CreateServiceAccountKey', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Storage Bucket Configuration Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-243

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:"storage.buckets.update" and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'storage.buckets.update', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'storage.buckets.update', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Storage Bucket Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-244

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:"storage.buckets.delete"
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'storage.buckets.delete'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'storage.buckets.delete'}, '@timestamp': 1}]
```



### GCP Storage Bucket Permissions Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-245

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:"storage.setIamPermissions" and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'storage.setIamPermissions', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'storage.setIamPermissions', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Virtual Private Cloud Network Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-246

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:v*.compute.networks.delete and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'vXIUtkNI.compute.networks.delete', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'vixTFlEzswuEEXp.compute.networks.delete', 'outcome': 'success'}, '@timestamp': 1}]
```



### GCP Virtual Private Cloud Route Creation

Branch count: 4  
Document count: 4  
Index: geneve-ut-247

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:(v*.compute.routes.insert or "beta.compute.routes.insert")
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'vXIUtkNI.compute.routes.insert'}, '@timestamp': 0},
 {'event': {'dataset': 'googlecloud.audit', 'action': 'beta.compute.routes.insert'}, '@timestamp': 1},
 {'event': {'dataset': 'gcp.audit', 'action': 'vixTFlEzswuEEXp.compute.routes.insert'}, '@timestamp': 2},
 {'event': {'dataset': 'gcp.audit', 'action': 'beta.compute.routes.insert'}, '@timestamp': 3}]
```



### GCP Virtual Private Cloud Route Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-248

```python
event.dataset:(googlecloud.audit or gcp.audit) and event.action:v*.compute.routes.delete and event.outcome:success
```

```python
[{'event': {'dataset': 'googlecloud.audit', 'action': 'vXIUtkNI.compute.routes.delete', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'gcp.audit', 'action': 'vixTFlEzswuEEXp.compute.routes.delete', 'outcome': 'success'}, '@timestamp': 1}]
```



### Google Workspace API Access Granted via Domain-Wide Delegation of Authority

Branch count: 1  
Document count: 1  
Index: geneve-ut-249

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:AUTHORIZE_API_CLIENT_ACCESS
```

```python
[{'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'AUTHORIZE_API_CLIENT_ACCESS'}, '@timestamp': 0}]
```



### Google Workspace Admin Role Assigned to a User

Branch count: 1  
Document count: 1  
Index: geneve-ut-250

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:ASSIGN_ROLE
```

```python
[{'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'ASSIGN_ROLE'}, '@timestamp': 0}]
```



### Google Workspace Admin Role Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-251

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:DELETE_ROLE
```

```python
[{'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'DELETE_ROLE'}, '@timestamp': 0}]
```



### Google Workspace Custom Admin Role Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-252

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:CREATE_ROLE
```

```python
[{'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'CREATE_ROLE'}, '@timestamp': 0}]
```



### Google Workspace MFA Enforcement Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-253

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:ENFORCE_STRONG_AUTHENTICATION and google_workspace.admin.new_value:false
```

```python
[{'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'ENFORCE_STRONG_AUTHENTICATION'}, 'google_workspace': {'admin': {'new_value': False}}, '@timestamp': 0}]
```



### Google Workspace Password Policy Modified

Branch count: 12  
Document count: 12  
Index: geneve-ut-254

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

```python
[{'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'CHANGE_APPLICATION_SETTING'}, 'google_workspace': {'admin': {'setting': {'name': 'Password Management - Enforce strong password'}}}, '@timestamp': 0},
 {'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'CHANGE_APPLICATION_SETTING'}, 'google_workspace': {'admin': {'setting': {'name': 'Password Management - Password reset frequency'}}}, '@timestamp': 1},
 {'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'CHANGE_APPLICATION_SETTING'}, 'google_workspace': {'admin': {'setting': {'name': 'Password Management - Enable password reuse'}}}, '@timestamp': 2},
 {'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'CHANGE_APPLICATION_SETTING'}, 'google_workspace': {'admin': {'setting': {'name': 'Password Management - Enforce password policy at next login'}}}, '@timestamp': 3},
 {'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'CHANGE_APPLICATION_SETTING'}, 'google_workspace': {'admin': {'setting': {'name': 'Password Management - Minimum password length'}}}, '@timestamp': 4},
 {'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'CHANGE_APPLICATION_SETTING'}, 'google_workspace': {'admin': {'setting': {'name': 'Password Management - Maximum password length'}}}, '@timestamp': 5},
 {'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'CREATE_APPLICATION_SETTING'}, 'google_workspace': {'admin': {'setting': {'name': 'Password Management - Enforce strong password'}}}, '@timestamp': 6},
 {'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'CREATE_APPLICATION_SETTING'}, 'google_workspace': {'admin': {'setting': {'name': 'Password Management - Password reset frequency'}}}, '@timestamp': 7},
 {'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'CREATE_APPLICATION_SETTING'}, 'google_workspace': {'admin': {'setting': {'name': 'Password Management - Enable password reuse'}}}, '@timestamp': 8},
 {'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'CREATE_APPLICATION_SETTING'}, 'google_workspace': {'admin': {'setting': {'name': 'Password Management - Enforce password policy at next login'}}}, '@timestamp': 9},
 {'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'CREATE_APPLICATION_SETTING'}, 'google_workspace': {'admin': {'setting': {'name': 'Password Management - Minimum password length'}}}, '@timestamp': 10},
 {'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'CREATE_APPLICATION_SETTING'}, 'google_workspace': {'admin': {'setting': {'name': 'Password Management - Maximum password length'}}}, '@timestamp': 11}]
```



### Google Workspace Role Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-255

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:(ADD_PRIVILEGE or UPDATE_ROLE)
```

```python
[{'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'ADD_PRIVILEGE'}, '@timestamp': 0},
 {'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'UPDATE_ROLE'}, '@timestamp': 1}]
```



### Hex Encoding/Decoding Activity

Branch count: 6  
Document count: 6  
Index: geneve-ut-258

```python
event.category:process and event.type:(start or process_started) and process.name:(hexdump or od or xxd)
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hexdump'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'od'}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'xxd'}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'hexdump'}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'od'}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'xxd'}, '@timestamp': 5}]
```



### Hosts File Modified

Branch count: 8  
Document count: 8  
Index: geneve-ut-261

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

```python
[{'event': {'category': ['file'], 'type': ['change']}, 'file': {'path': 'E:\\Windows\\System32\\drivers\\etc\\hosts'}, '@timestamp': 0},
 {'event': {'category': ['file'], 'type': ['creation']}, 'file': {'path': '/private/etc/hosts'}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'nano', 'args': ['/etc/hosts']}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'vim', 'args': ['/etc/hosts']}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'vi', 'args': ['/etc/hosts']}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'emacs', 'args': ['/etc/hosts']}, '@timestamp': 5},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'echo', 'args': ['/etc/hosts']}, '@timestamp': 6},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'sed', 'args': ['/etc/hosts']}, '@timestamp': 7}]
```



### Hping Process Activity

Branch count: 6  
Document count: 6  
Index: geneve-ut-262

```python
event.category:process and event.type:(start or process_started) and process.name:(hping or hping2 or hping3)
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hping'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hping2'}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hping3'}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'hping'}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'hping2'}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'hping3'}, '@timestamp': 5}]
```



### IIS HTTP Logging Disabled

Branch count: 4  
Document count: 4  
Index: geneve-ut-263

```python
process where event.type in ("start", "process_started") and
  (process.name : "appcmd.exe" or process.pe.original_file_name == "appcmd.exe") and
  process.args : "/dontLog*:*True" and
  not process.parent.name : "iissetup.exe"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'appcmd.exe', 'args': ['/dontLog*:*True'], 'parent': {'name': 'ZFy'}}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'appcmd.exe'}, 'args': ['/dontLog*:*True'], 'parent': {'name': 'XIU'}}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'appcmd.exe', 'args': ['/dontLog*:*True'], 'parent': {'name': 'tkN'}}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'appcmd.exe'}, 'args': ['/dontLog*:*True'], 'parent': {'name': 'Ioi'}}, '@timestamp': 3}]
```



### IPSEC NAT Traversal Port Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-264

```python
event.category:(network or network_traffic) and network.transport:udp and destination.port:4500
```

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'udp'}, 'destination': {'port': 4500}, '@timestamp': 0},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'udp'}, 'destination': {'port': 4500}, '@timestamp': 1}]
```



### IRC (Internet Relay Chat) Protocol Activity to the Internet

Branch count: 18  
Document count: 18  
Index: geneve-ut-265

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:(6667 or 6697) or event.dataset:zeek.irc) and
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
    192.168.0.0/16 or
    224.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  )
```

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 6667, 'ip': 'e6ea:94e4:e5ac:b58c:1b43:3a53:aa79:ec59'}, 'source': {'ip': '10.214.62.131'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 6667, 'ip': '119.10.44.216'}, 'source': {'ip': '172.31.81.251'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 6667, 'ip': '104.129.204.102'}, 'source': {'ip': '192.168.147.58'}, '@timestamp': 2},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 6697, 'ip': '149.239.86.175'}, 'source': {'ip': '10.111.13.86'}, '@timestamp': 3},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 6697, 'ip': '112.141.185.70'}, 'source': {'ip': '172.27.169.243'}, '@timestamp': 4},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 6697, 'ip': 'b781:36ad:968a:1fd9:42e0:603d:9566:7ca8'}, 'source': {'ip': '192.168.197.122'}, '@timestamp': 5},
 {'event': {'category': ['network'], 'dataset': 'zeek.irc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.155.175.169'}, 'destination': {'ip': '21ff:ce1f:c206:4389:a7:5646:506a:fac3'}, '@timestamp': 6},
 {'event': {'category': ['network'], 'dataset': 'zeek.irc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.21.27.73'}, 'destination': {'ip': '156.105.128.203'}, '@timestamp': 7},
 {'event': {'category': ['network'], 'dataset': 'zeek.irc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.162.120'}, 'destination': {'ip': '93.16.168.118'}, '@timestamp': 8},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 6667, 'ip': 'cde8:687a:c169:7ee6:e8d4:8f4f:b2cc:3459'}, 'source': {'ip': '10.247.115.164'}, '@timestamp': 9},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 6667, 'ip': 'e2fc:2265:c4e2:24bd:4b82:92c6:7ee8:2ac8'}, 'source': {'ip': '172.30.255.121'}, '@timestamp': 10},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 6667, 'ip': '147.172.30.18'}, 'source': {'ip': '192.168.120.95'}, '@timestamp': 11},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 6697, 'ip': '200.44.53.86'}, 'source': {'ip': '10.231.61.22'}, '@timestamp': 12},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 6697, 'ip': 'bd8d:8e9f:3c38:5e93:2a21:f2e3:2a70:2899'}, 'source': {'ip': '172.27.220.217'}, '@timestamp': 13},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 6697, 'ip': '3.79.219.137'}, 'source': {'ip': '192.168.64.185'}, '@timestamp': 14},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.irc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.77.111.86'}, 'destination': {'ip': 'b861:3a65:7d92:a4ae:175d:4ee4:1dd9:801e'}, '@timestamp': 15},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.irc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.17.96.216'}, 'destination': {'ip': '46.77.189.36'}, '@timestamp': 16},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.irc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.139.227'}, 'destination': {'ip': '159.213.231.147'}, '@timestamp': 17}]
```



### ImageLoad via Windows Update Auto Update Client

Branch count: 4  
Document count: 4  
Index: geneve-ut-267

```python
process where event.type in ("start", "process_started") and
  (process.pe.original_file_name == "wuauclt.exe" or process.name : "wuauclt.exe") and
   /* necessary windows update client args to load a dll */
   process.args : "/RunHandlerComServer" and process.args : "/UpdateDeploymentProvider" and
   /* common paths writeable by a standard user where the target DLL can be placed */
   process.args : ("C:\\Users\\*.dll", "C:\\ProgramData\\*.dll", "C:\\Windows\\Temp\\*.dll", "C:\\Windows\\Tasks\\*.dll")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'wuauclt.exe'}, 'args': ['/RunHandlerComServer', '/UpdateDeploymentProvider', 'C:\\Users\\*.dll', 'C:\\ProgramData\\*.dll', 'C:\\Windows\\Temp\\*.dll', 'C:\\Windows\\Tasks\\*.dll']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'wuauclt.exe', 'args': ['/RunHandlerComServer', '/UpdateDeploymentProvider', 'C:\\Users\\*.dll', 'C:\\ProgramData\\*.dll', 'C:\\Windows\\Temp\\*.dll', 'C:\\Windows\\Tasks\\*.dll']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'wuauclt.exe'}, 'args': ['/RunHandlerComServer', '/UpdateDeploymentProvider', 'C:\\Users\\*.dll', 'C:\\ProgramData\\*.dll', 'C:\\Windows\\Temp\\*.dll', 'C:\\Windows\\Tasks\\*.dll']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'wuauclt.exe', 'args': ['/RunHandlerComServer', '/UpdateDeploymentProvider', 'C:\\Users\\*.dll', 'C:\\ProgramData\\*.dll', 'C:\\Windows\\Temp\\*.dll', 'C:\\Windows\\Tasks\\*.dll']}, '@timestamp': 3}]
```



### Incoming DCOM Lateral Movement via MSHTA

Branch count: 2  
Document count: 4  
Index: geneve-ut-269

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'mshta.exe', 'args': ['-Embedding'], 'entity_id': 'XIU'}, 'host': {'id': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['network']}, 'process': {'name': 'mshta.exe', 'entity_id': 'XIU'}, 'network': {'direction': 'ingress', 'transport': 'tcp'}, 'source': {'port': 64839, 'ip': '3023:5fa9:a92d:c839:9a9f:e89a:c443:b67b'}, 'destination': {'port': 56065}, 'host': {'id': 'ZFy'}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'mshta.exe', 'args': ['-Embedding'], 'entity_id': 'TFl'}, 'host': {'id': 'oix'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['network']}, 'process': {'name': 'mshta.exe', 'entity_id': 'TFl'}, 'network': {'direction': 'ingress', 'transport': 'tcp'}, 'source': {'port': 61095, 'ip': '9566:7ca7:8676:5e58:62bd:10db:7472:f04c'}, 'destination': {'port': 57092}, 'host': {'id': 'oix'}, '@timestamp': 3}]
```



### Incoming DCOM Lateral Movement with MMC

Branch count: 2  
Document count: 4  
Index: geneve-ut-270

```python
sequence by host.id with maxspan=1m
 [network where event.type == "start" and process.name : "mmc.exe" and source.port >= 49152 and
 destination.port >= 49152 and source.ip != "127.0.0.1" and source.ip != "::1" and
  network.direction : ("incoming", "ingress") and network.transport == "tcp"
 ] by process.entity_id
 [process where event.type in ("start", "process_started") and process.parent.name : "mmc.exe"
 ] by process.parent.entity_id
```

```python
[{'event': {'type': ['start'], 'category': ['network']}, 'process': {'name': 'mmc.exe', 'entity_id': 'jSv'}, 'source': {'port': 64740, 'ip': '229.172.181.141'}, 'destination': {'port': 62863}, 'network': {'direction': 'ingress', 'transport': 'tcp'}, 'host': {'id': 'yyF'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'mmc.exe', 'entity_id': 'jSv'}}, 'host': {'id': 'yyF'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['network']}, 'process': {'name': 'mmc.exe', 'entity_id': 'XpW'}, 'source': {'port': 56259, 'ip': '708d:b945:3e09:df7f:5d4f:9e31:a728:d9ac'}, 'destination': {'port': 58173}, 'network': {'direction': 'ingress', 'transport': 'tcp'}, 'host': {'id': 'uEE'}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'mmc.exe', 'entity_id': 'XpW'}}, 'host': {'id': 'uEE'}, '@timestamp': 3}]
```



### Incoming DCOM Lateral Movement with ShellBrowserWindow or ShellWindows

Branch count: 2  
Document count: 4  
Index: geneve-ut-271

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

```python
[{'event': {'type': ['start'], 'category': ['network']}, 'process': {'name': 'explorer.exe', 'entity_id': 'vIL'}, 'network': {'direction': 'ingress', 'transport': 'tcp'}, 'source': {'port': 62863, 'ip': 'c443:b67a:770a:2cd7:3602:9e1d:7a8f:dfec'}, 'destination': {'port': 52641}, 'host': {'id': 'FjS'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe', 'entity_id': 'vIL'}}, 'host': {'id': 'FjS'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['network']}, 'process': {'name': 'explorer.exe', 'entity_id': 'eOA'}, 'network': {'direction': 'incoming', 'transport': 'tcp'}, 'source': {'port': 58173, 'ip': '62bd:10db:7472:f04b:708d:b945:3e09:df80'}, 'destination': {'port': 65131}, 'host': {'id': 'BnL'}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'explorer.exe', 'entity_id': 'eOA'}}, 'host': {'id': 'BnL'}, '@timestamp': 3}]
```



### Incoming Execution via PowerShell Remoting

Branch count: 2  
Document count: 4  
Index: geneve-ut-272

```python
sequence by host.id with maxspan = 30s
   [network where network.direction : ("incoming", "ingress") and destination.port in (5985, 5986) and
    network.protocol == "http" and source.ip != "127.0.0.1" and source.ip != "::1"
   ]
   [process where event.type == "start" and process.parent.name : "wsmprovhost.exe" and not process.name : "conhost.exe"]
```

```python
[{'network': {'direction': 'ingress', 'protocol': 'http'}, 'destination': {'port': 5985}, 'source': {'ip': '1b43:3a53:aa79:ec58:8d14:2981:f18d:f2a7'}, 'event': {'category': ['network']}, 'host': {'id': 'Utk'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'wsmprovhost.exe'}, 'name': 'NIo'}, 'host': {'id': 'Utk'}, '@timestamp': 1},
 {'network': {'direction': 'incoming', 'protocol': 'http'}, 'destination': {'port': 5986}, 'source': {'ip': 'baf5:6682:de3c:cb58:a9e1:79f2:73bd:f2be'}, 'event': {'category': ['network']}, 'host': {'id': 'FlE'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'wsmprovhost.exe'}, 'name': 'zsw'}, 'host': {'id': 'FlE'}, '@timestamp': 3}]
```



### Incoming Execution via WinRM Remote Shell

Branch count: 2  
Document count: 4  
Index: geneve-ut-273

```python
sequence by host.id with maxspan=30s
   [network where process.pid == 4 and network.direction : ("incoming", "ingress") and
    destination.port in (5985, 5986) and network.protocol == "http" and source.ip != "127.0.0.1" and source.ip != "::1"
   ]
   [process where event.type == "start" and process.parent.name : "winrshost.exe" and not process.name : "conhost.exe"]
```

```python
[{'process': {'pid': 4}, 'network': {'direction': 'ingress', 'protocol': 'http'}, 'destination': {'port': 5985}, 'source': {'ip': '1b43:3a53:aa79:ec58:8d14:2981:f18d:f2a7'}, 'event': {'category': ['network']}, 'host': {'id': 'Utk'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'winrshost.exe'}, 'name': 'NIo'}, 'host': {'id': 'Utk'}, '@timestamp': 1},
 {'process': {'pid': 4}, 'network': {'direction': 'incoming', 'protocol': 'http'}, 'destination': {'port': 5986}, 'source': {'ip': 'baf5:6682:de3c:cb58:a9e1:79f2:73bd:f2be'}, 'event': {'category': ['network']}, 'host': {'id': 'FlE'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'winrshost.exe'}, 'name': 'zsw'}, 'host': {'id': 'FlE'}, '@timestamp': 3}]
```



### InstallUtil Process Making Network Connections

Branch count: 2  
Document count: 4  
Index: geneve-ut-274

```python
/* the benefit of doing this as an eql sequence vs kql is this will limit to alerting only on the first network connection */

sequence by process.entity_id
  [process where event.type in ("start", "process_started") and process.name : "installutil.exe"]
  [network where process.name : "installutil.exe" and network.direction : ("outgoing", "egress")]
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'installutil.exe', 'entity_id': 'ZFy'}, '@timestamp': 0},
 {'process': {'name': 'installutil.exe', 'entity_id': 'ZFy'}, 'network': {'direction': 'egress'}, 'event': {'category': ['network']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'installutil.exe', 'entity_id': 'Utk'}, '@timestamp': 2},
 {'process': {'name': 'installutil.exe', 'entity_id': 'Utk'}, 'network': {'direction': 'egress'}, 'event': {'category': ['network']}, '@timestamp': 3}]
```



### Installation of Custom Shim Databases

Branch count: 8  
Document count: 16  
Index: geneve-ut-275

```python
sequence by process.entity_id with maxspan = 5m
  [process where event.type in ("start", "process_started") and
    not (process.name : "sdbinst.exe" and process.parent.name : "msiexec.exe")]
  [registry where event.type in ("creation", "change") and
    registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\*.sdb"]
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'ZFy', 'entity_id': 'XIU'}, '@timestamp': 0},
 {'event': {'type': ['creation'], 'category': ['registry']}, 'registry': {'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\kNIoixTF.sdb'}, 'process': {'entity_id': 'XIU'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'lEz', 'entity_id': 'swu'}, '@timestamp': 2},
 {'event': {'type': ['change'], 'category': ['registry']}, 'registry': {'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\LeOAagaiFq.sdb'}, 'process': {'entity_id': 'swu'}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'syz'}, 'entity_id': 'KNy'}, '@timestamp': 4},
 {'event': {'type': ['creation'], 'category': ['registry']}, 'registry': {'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\QDpUEUDqxVTO.sdb'}, 'process': {'entity_id': 'KNy'}, '@timestamp': 5},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'LWt'}, 'entity_id': 'imr'}, '@timestamp': 6},
 {'event': {'type': ['change'], 'category': ['registry']}, 'registry': {'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\Tm.sdb'}, 'process': {'entity_id': 'imr'}, '@timestamp': 7},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'shC', 'entity_id': 'eLW'}, '@timestamp': 8},
 {'event': {'type': ['creation'], 'category': ['registry']}, 'registry': {'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\L.sdb'}, 'process': {'entity_id': 'eLW'}, '@timestamp': 9},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'Sjo', 'entity_id': 'Grm'}, '@timestamp': 10},
 {'event': {'type': ['change'], 'category': ['registry']}, 'registry': {'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\wDUNrZjeyLuZfIz.sdb'}, 'process': {'entity_id': 'Grm'}, '@timestamp': 11},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'miE'}, 'entity_id': 'Gga'}, '@timestamp': 12},
 {'event': {'type': ['creation'], 'category': ['registry']}, 'registry': {'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\K.sdb'}, 'process': {'entity_id': 'Gga'}, '@timestamp': 13},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'EIp'}, 'entity_id': 'duD'}, '@timestamp': 14},
 {'event': {'type': ['change'], 'category': ['registry']}, 'registry': {'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\xFEiZBTXzJCW.sdb'}, 'process': {'entity_id': 'duD'}, '@timestamp': 15}]
```



### Installation of Security Support Provider

Branch count: 1  
Document count: 1  
Index: geneve-ut-276

```python
registry where
   registry.path : ("HKLM\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Security Packages*", 
                    "HKLM\\SYSTEM\\*ControlSet*\\Control\\Lsa\\OSConfig\\Security Packages*") and
   not process.executable : ("C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\SysWOW64\\msiexec.exe")
```

```python
[{'registry': {'path': 'HKLM\\SYSTEM\\XIUtkNIControlSetSvILO\\Control\\Lsa\\Security PackagesEzswu'}, 'process': {'executable': 'EEX'}, 'event': {'category': ['registry']}, '@timestamp': 0}]
```



### Interactive Terminal Spawned via Perl

Branch count: 6  
Document count: 6  
Index: geneve-ut-277

```python
event.category:process and event.type:(start or process_started) and process.name:perl and
  process.args:("exec \"/bin/sh\";" or "exec \"/bin/dash\";" or "exec \"/bin/bash\";")
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'perl', 'args': ['exec "/bin/sh";']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'perl', 'args': ['exec "/bin/dash";']}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'perl', 'args': ['exec "/bin/bash";']}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'perl', 'args': ['exec "/bin/sh";']}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'perl', 'args': ['exec "/bin/dash";']}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'perl', 'args': ['exec "/bin/bash";']}, '@timestamp': 5}]
```



### Interactive Terminal Spawned via Python

Branch count: 6  
Document count: 6  
Index: geneve-ut-278

```python
event.category:process and event.type:(start or process_started) and 
  process.name:python* and
  process.args:("import pty; pty.spawn(\"/bin/sh\")" or
                "import pty; pty.spawn(\"/bin/dash\")" or
                "import pty; pty.spawn(\"/bin/bash\")")
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'pythonXIUtkNI', 'args': ['import pty; pty.spawn("/bin/sh")']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'pythonixTFlEzswuEEXp', 'args': ['import pty; pty.spawn("/bin/dash")']}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'pythonN', 'args': ['import pty; pty.spawn("/bin/bash")']}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'pythoniFqsyzKNyyQDpU', 'args': ['import pty; pty.spawn("/bin/sh")']}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'pythonlOPZRgUvWCiMZOf', 'args': ['import pty; pty.spawn("/bin/dash")']}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'pythons', 'args': ['import pty; pty.spawn("/bin/bash")']}, '@timestamp': 5}]
```



### KRBTGT Delegation Backdoor

Branch count: 1  
Document count: 1  
Index: geneve-ut-279

```python
event.action:modified-user-account and event.code:4738 and winlog.event_data.AllowedToDelegateTo:*krbtgt*
```

```python
[{'event': {'action': 'modified-user-account', 'code': 4738}, 'winlog': {'event_data': {'AllowedToDelegateTo': 'XIUtkNIkrbtgtSvILO'}}, '@timestamp': 0}]
```



### Kerberos Cached Credentials Dumping

Branch count: 2  
Document count: 2  
Index: geneve-ut-280

```python
event.category:process and event.type:(start or process_started) and
  process.name:kcc and
  process.args:copy_cred_cache
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'kcc', 'args': ['copy_cred_cache']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'kcc', 'args': ['copy_cred_cache']}, '@timestamp': 1}]
```



### Kerberos Traffic from Unusual Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-282

```python
network where event.type == "start" and network.direction : ("outgoing", "egress") and
 destination.port == 88 and source.port >= 49152 and
 process.executable != "C:\\Windows\\System32\\lsass.exe" and destination.address !="127.0.0.1" and destination.address !="::1" and
 /* insert false positives here */
 not process.name in ("swi_fc.exe", "fsIPcam.exe", "IPCamera.exe", "MicrosoftEdgeCP.exe", "MicrosoftEdge.exe", "iexplore.exe", "chrome.exe", "msedge.exe", "opera.exe", "firefox.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['network']}, 'network': {'direction': 'outgoing'}, 'destination': {'port': 88, 'address': 'tkN'}, 'source': {'port': 62863}, 'process': {'executable': 'XIU', 'name': 'Ioi'}, '@timestamp': 0}]
```



### Kernel Module Removal

Branch count: 2  
Document count: 2  
Index: geneve-ut-283

```python
event.category:process and event.type:(start or process_started) and
  process.args:((rmmod and sudo) or (modprobe and sudo and ("--remove" or "-r")))
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['rmmod', 'sudo']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'args': ['rmmod', 'sudo']}, '@timestamp': 1}]
```



### Keychain Password Retrieval via Command Line

Branch count: 1  
Document count: 1  
Index: geneve-ut-284

```python
process where event.type == "start" and
 process.name : "security" and process.args : "-wa" and process.args : ("find-generic-password", "find-internet-password") and
 process.args : ("Chrome*", "Chromium", "Opera", "Safari*", "Brave", "Microsoft Edge", "Edge", "Firefox*") and
 not process.parent.executable : "/Applications/Keeper Password Manager.app/Contents/Frameworks/Keeper Password Manager Helper*/Contents/MacOS/Keeper Password Manager Helper*"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'security', 'args': ['-wa', 'find-generic-password', 'find-internet-password', 'Chrome*', 'Chromium', 'Opera', 'Safari*', 'Brave', 'Microsoft Edge', 'Edge', 'Firefox*'], 'parent': {'executable': 'ZFy'}}, '@timestamp': 0}]
```



### LSASS Memory Dump Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-285

```python
file where file.name : ("lsass*.dmp", "dumpert.dmp", "Andrew.dmp", "SQLDmpr*.mdmp", "Coredump.dmp")
```

```python
[{'file': {'name': 'lsassyXIUtkNIoixTFl.dmp'}, 'event': {'category': ['file']}, '@timestamp': 0}]
```



### LSASS Memory Dump Handle Access

Branch count: 2  
Document count: 2  
Index: geneve-ut-286

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

```python
[{'event': {'action': 'File System', 'code': '4656'}, 'winlog': {'event_data': {'ObjectName': '\\Device\\HarddiskVolumeE\\Windows\\System32\\lsass.exe', 'AccessMask': '0x1fffff', 'ProcessName': 'XIU'}}, '@timestamp': 0},
 {'event': {'action': 'File System', 'code': '4656'}, 'winlog': {'event_data': {'ObjectName': '\\Device\\HarddiskVolumeEn\\Windows\\System32\\lsass.exe', 'AccessMaskDescription': 'Read from process memory', 'ProcessName': 'NIo'}}, '@timestamp': 1}]
```



### Lateral Movement via Startup Folder

Branch count: 4  
Document count: 4  
Index: geneve-ut-287

```python
file where event.type in ("creation", "change") and
 /* via RDP TSClient mounted share or SMB */
  (process.name : "mstsc.exe" or process.pid == 4) and
   file.path : "C:\\*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*"
```

```python
[{'event': {'type': ['creation'], 'category': ['file']}, 'process': {'name': 'mstsc.exe'}, 'file': {'path': 'C:\\XIUtkNI\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SvILO'}, '@timestamp': 0},
 {'event': {'type': ['creation'], 'category': ['file']}, 'process': {'pid': 4}, 'file': {'path': 'C:\\OHmxBnLeOA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\N'}, '@timestamp': 1},
 {'event': {'type': ['change'], 'category': ['file']}, 'process': {'name': 'mstsc.exe'}, 'file': {'path': 'C:\\iFqsyzKNyyQDpU\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\mlOPZRgUvW'}, '@timestamp': 2},
 {'event': {'type': ['change'], 'category': ['file']}, 'process': {'pid': 4}, 'file': {'path': 'C:\\mrF\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\fHa'}, '@timestamp': 3}]
```



### Lateral Tool Transfer

Branch count: 2  
Document count: 4  
Index: geneve-ut-288

```python
sequence by host.id with maxspan=30s
  [network where event.type == "start" and process.pid == 4 and destination.port == 445 and
   network.direction : ("incoming", "ingress") and
   network.transport == "tcp" and source.ip != "127.0.0.1" and source.ip != "::1"
  ] by process.entity_id
  /* add more executable extensions here if they are not noisy in your environment */
  [file where event.type in ("creation", "change") and process.pid == 4 and file.extension : ("exe", "dll", "bat", "cmd")] by process.entity_id
```

```python
[{'event': {'type': ['start'], 'category': ['network']}, 'process': {'pid': 4, 'entity_id': 'NIo'}, 'destination': {'port': 445}, 'network': {'direction': 'ingress', 'transport': 'tcp'}, 'source': {'ip': '1b43:3a53:aa79:ec58:8d14:2981:f18d:f2a7'}, 'host': {'id': 'Utk'}, '@timestamp': 0},
 {'event': {'type': ['creation'], 'category': ['file']}, 'process': {'pid': 4, 'entity_id': 'NIo'}, 'file': {'extension': 'cmd'}, 'host': {'id': 'Utk'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['network']}, 'process': {'pid': 4, 'entity_id': 'Hmx'}, 'destination': {'port': 445}, 'network': {'direction': 'ingress', 'transport': 'tcp'}, 'source': {'ip': '9a3d:9c72:baf5:6682:de3c:cb58:a9e1:79f3'}, 'host': {'id': 'OoO'}, '@timestamp': 2},
 {'event': {'type': ['change'], 'category': ['file']}, 'process': {'pid': 4, 'entity_id': 'Hmx'}, 'file': {'extension': 'dll'}, 'host': {'id': 'OoO'}, '@timestamp': 3}]
```



### Launch Agent Creation or Modification and Immediate Loading

Branch count: 2  
Document count: 4  
Index: geneve-ut-289

```python
sequence by host.id with maxspan=1m
 [file where event.type != "deletion" and 
  file.path : ("/System/Library/LaunchAgents/*", "/Library/LaunchAgents/*", "/Users/*/Library/LaunchAgents/*")
 ]
 [process where event.type in ("start", "process_started") and process.name == "launchctl" and process.args == "load"]
```

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'path': '/Users/fUyyFjSvILO/Library/LaunchAgents/Ezswu'}, 'host': {'id': 'EEX'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'launchctl', 'args': ['load']}, 'host': {'id': 'EEX'}, '@timestamp': 1},
 {'event': {'type': ['pWq'], 'category': ['file']}, 'file': {'path': '/Library/LaunchAgents/aiFqsyzKNyyQDpU'}, 'host': {'id': 'EUD'}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'launchctl', 'args': ['load']}, 'host': {'id': 'EUD'}, '@timestamp': 3}]
```



### Linux Restricted Shell Breakout via  apt/apt-get Changelog Escape

Branch count: 12  
Document count: 12  
Index: geneve-ut-291

```python
process where event.type == "start" and process.name == "sensible-pager" and
  process.args in ("/bin/sh", "/bin/bash", "/bin/dash", "sh", "bash", "dash") and
  process.parent.name in ("apt", "apt-get") and process.parent.args == "changelog"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sensible-pager', 'args': ['/bin/sh'], 'parent': {'name': 'apt', 'args': ['changelog']}}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sensible-pager', 'args': ['/bin/sh'], 'parent': {'name': 'apt-get', 'args': ['changelog']}}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sensible-pager', 'args': ['/bin/bash'], 'parent': {'name': 'apt', 'args': ['changelog']}}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sensible-pager', 'args': ['/bin/bash'], 'parent': {'name': 'apt-get', 'args': ['changelog']}}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sensible-pager', 'args': ['/bin/dash'], 'parent': {'name': 'apt', 'args': ['changelog']}}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sensible-pager', 'args': ['/bin/dash'], 'parent': {'name': 'apt-get', 'args': ['changelog']}}, '@timestamp': 5},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sensible-pager', 'args': ['sh'], 'parent': {'name': 'apt', 'args': ['changelog']}}, '@timestamp': 6},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sensible-pager', 'args': ['sh'], 'parent': {'name': 'apt-get', 'args': ['changelog']}}, '@timestamp': 7},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sensible-pager', 'args': ['bash'], 'parent': {'name': 'apt', 'args': ['changelog']}}, '@timestamp': 8},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sensible-pager', 'args': ['bash'], 'parent': {'name': 'apt-get', 'args': ['changelog']}}, '@timestamp': 9},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sensible-pager', 'args': ['dash'], 'parent': {'name': 'apt', 'args': ['changelog']}}, '@timestamp': 10},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sensible-pager', 'args': ['dash'], 'parent': {'name': 'apt-get', 'args': ['changelog']}}, '@timestamp': 11}]
```



### Linux Restricted Shell Breakout via awk Commands

Branch count: 12  
Document count: 12  
Index: geneve-ut-292

```python
process where event.type == "start" and process.name in ("sh", "bash", "dash") and
  process.parent.name in ("nawk", "mawk", "awk", "gawk") and process.parent.args : "BEGIN {system(*)}"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'name': 'nawk', 'args': ['BEGIN {system(*)}']}}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'name': 'mawk', 'args': ['BEGIN {system(*)}']}}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'name': 'awk', 'args': ['BEGIN {system(*)}']}}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'name': 'gawk', 'args': ['BEGIN {system(*)}']}}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'name': 'nawk', 'args': ['BEGIN {system(*)}']}}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'name': 'mawk', 'args': ['BEGIN {system(*)}']}}, '@timestamp': 5},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'name': 'awk', 'args': ['BEGIN {system(*)}']}}, '@timestamp': 6},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'name': 'gawk', 'args': ['BEGIN {system(*)}']}}, '@timestamp': 7},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'dash', 'parent': {'name': 'nawk', 'args': ['BEGIN {system(*)}']}}, '@timestamp': 8},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'dash', 'parent': {'name': 'mawk', 'args': ['BEGIN {system(*)}']}}, '@timestamp': 9},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'dash', 'parent': {'name': 'awk', 'args': ['BEGIN {system(*)}']}}, '@timestamp': 10},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'dash', 'parent': {'name': 'gawk', 'args': ['BEGIN {system(*)}']}}, '@timestamp': 11}]
```



### Linux Restricted Shell Breakout via busybox Shell Evasion

Branch count: 4  
Document count: 4  
Index: geneve-ut-293

```python
process where event.type == "start" and process.name == "busybox" and process.args_count == 2 and process.args in ("/bin/sh", "/bin/ash", "sh", "ash")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'busybox', 'args_count': 2, 'args': ['/bin/sh']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'busybox', 'args_count': 2, 'args': ['/bin/ash']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'busybox', 'args_count': 2, 'args': ['sh']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'busybox', 'args_count': 2, 'args': ['ash']}, '@timestamp': 3}]
```



### Linux Restricted Shell Breakout via crash Shell evasion

Branch count: 1  
Document count: 1  
Index: geneve-ut-296

```python
process where event.type == "start" and process.parent.name == "crash" and process.parent.args == "-h" and process.name == "sh"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'crash', 'args': ['-h']}, 'name': 'sh'}, '@timestamp': 0}]
```



### Linux Restricted Shell Breakout via env Shell Evasion

Branch count: 1  
Document count: 1  
Index: geneve-ut-297

```python
process where event.type == "start" and process.name : "env" and process.args_count == 2 and process.args : ("/bin/sh", "/bin/bash", "sh", "bash")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'env', 'args_count': 2, 'args': ['/bin/sh', '/bin/bash', 'sh', 'bash']}, '@timestamp': 0}]
```



### Linux Restricted Shell Breakout via nice Shell evasion

Branch count: 18  
Document count: 18  
Index: geneve-ut-299

```python
process where event.type == "start" and process.name in ("bash", "sh", "dash") and
  process.parent.name == "nice" and process.parent.args in ("/bin/bash", "/bin/sh", "/bin/dash", "sh", "bash", "dash")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'name': 'nice', 'args': ['/bin/bash']}}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'name': 'nice', 'args': ['/bin/sh']}}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'name': 'nice', 'args': ['/bin/dash']}}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'name': 'nice', 'args': ['sh']}}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'name': 'nice', 'args': ['bash']}}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'name': 'nice', 'args': ['dash']}}, '@timestamp': 5},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'name': 'nice', 'args': ['/bin/bash']}}, '@timestamp': 6},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'name': 'nice', 'args': ['/bin/sh']}}, '@timestamp': 7},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'name': 'nice', 'args': ['/bin/dash']}}, '@timestamp': 8},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'name': 'nice', 'args': ['sh']}}, '@timestamp': 9},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'name': 'nice', 'args': ['bash']}}, '@timestamp': 10},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'name': 'nice', 'args': ['dash']}}, '@timestamp': 11},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'dash', 'parent': {'name': 'nice', 'args': ['/bin/bash']}}, '@timestamp': 12},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'dash', 'parent': {'name': 'nice', 'args': ['/bin/sh']}}, '@timestamp': 13},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'dash', 'parent': {'name': 'nice', 'args': ['/bin/dash']}}, '@timestamp': 14},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'dash', 'parent': {'name': 'nice', 'args': ['sh']}}, '@timestamp': 15},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'dash', 'parent': {'name': 'nice', 'args': ['bash']}}, '@timestamp': 16},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'dash', 'parent': {'name': 'nice', 'args': ['dash']}}, '@timestamp': 17}]
```



### Linux Restricted Shell Breakout via the mysql command

Branch count: 3  
Document count: 3  
Index: geneve-ut-303

```python
process where event.type == "start" and process.name in ("bash", "sh", "dash") and
  process.parent.name == "mysql" and process.parent.args == "-e" and
  process.parent.args : ("\\!*sh", "\\!*bash", "\\!*dash", "\\!*/bin/sh", "\\!*/bin/bash", "\\!*/bin/dash")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'name': 'mysql', 'args': ['\\!*sh', '\\!*bash', '\\!*dash', '\\!*/bin/sh', '\\!*/bin/bash', '\\!*/bin/dash', '-e']}}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'name': 'mysql', 'args': ['\\!*sh', '\\!*bash', '\\!*dash', '\\!*/bin/sh', '\\!*/bin/bash', '\\!*/bin/dash', '-e']}}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'dash', 'parent': {'name': 'mysql', 'args': ['\\!*sh', '\\!*bash', '\\!*dash', '\\!*/bin/sh', '\\!*/bin/bash', '\\!*/bin/dash', '-e']}}, '@timestamp': 2}]
```



### Local Scheduled Task Creation

Branch count: 6  
Document count: 12  
Index: geneve-ut-306

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

```python
[{'event': {'type': ['ZFy'], 'category': ['process']}, 'process': {'name': 'winrshost.exe', 'entity_id': 'IUt'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'schtasks.exe', 'args': ['/create', '-create', '/RU', '/SC', '/TN', '/TR', '/F', '/XML'], 'Ext': {'token': {'integrity_level_name': 'kNI'}}, 'parent': {'entity_id': 'IUt'}}, 'winlog': {'event_data': {'IntegrityLevel': 'oix'}}, '@timestamp': 1},
 {'event': {'type': ['TFl'], 'category': ['process']}, 'process': {'name': 'wmic.exe', 'entity_id': 'OHm'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'schtasks.exe'}, 'args': ['/create', '-create', '/RU', '/SC', '/TN', '/TR', '/F', '/XML'], 'Ext': {'token': {'integrity_level_name': 'xBn'}}, 'parent': {'entity_id': 'OHm'}}, 'winlog': {'event_data': {'IntegrityLevel': 'LeO'}}, '@timestamp': 3},
 {'event': {'type': ['Aag'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'WmiPrvSe.exe'}, 'entity_id': 'Rcy'}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'schtasks.exe', 'args': ['/create', '-create', '/RU', '/SC', '/TN', '/TR', '/F', '/XML'], 'Ext': {'token': {'integrity_level_name': 'mEE'}}, 'parent': {'entity_id': 'Rcy'}}, 'winlog': {'event_data': {'IntegrityLevel': 'wVP'}}, '@timestamp': 5},
 {'event': {'type': ['YMG'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'rundll32.exe'}, 'entity_id': 'pUE'}, '@timestamp': 6},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'schtasks.exe'}, 'args': ['/create', '-create', '/RU', '/SC', '/TN', '/TR', '/F', '/XML'], 'Ext': {'token': {'integrity_level_name': 'UDq'}}, 'parent': {'entity_id': 'pUE'}}, 'winlog': {'event_data': {'IntegrityLevel': 'xVT'}}, '@timestamp': 7},
 {'event': {'type': ['OLW'], 'category': ['process']}, 'process': {'code_signature': {'trusted': False}, 'entity_id': 'tim'}, '@timestamp': 8},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'schtasks.exe', 'args': ['/create', '-create', '/RU', '/SC', '/TN', '/TR', '/F', '/XML'], 'Ext': {'token': {'integrity_level_name': 'rFg'}}, 'parent': {'entity_id': 'tim'}}, 'winlog': {'event_data': {'IntegrityLevel': 'Tms'}}, '@timestamp': 9},
 {'event': {'type': ['hCe'], 'category': ['process']}, 'process': {'code_signature': {'trusted': False}, 'entity_id': 'LWY'}, '@timestamp': 10},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'schtasks.exe'}, 'args': ['/create', '-create', '/RU', '/SC', '/TN', '/TR', '/F', '/XML'], 'Ext': {'token': {'integrity_level_name': 'cYs'}}, 'parent': {'entity_id': 'LWY'}}, 'winlog': {'event_data': {'IntegrityLevel': 'cnU'}}, '@timestamp': 11}]
```



### MFA Disabled for Google Workspace Organization

Branch count: 2  
Document count: 2  
Index: geneve-ut-307

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:(ENFORCE_STRONG_AUTHENTICATION or ALLOW_STRONG_AUTHENTICATION) and google_workspace.admin.new_value:false
```

```python
[{'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'ENFORCE_STRONG_AUTHENTICATION'}, 'google_workspace': {'admin': {'new_value': False}}, '@timestamp': 0},
 {'event': {'dataset': 'google_workspace.admin', 'provider': 'admin', 'category': ['iam'], 'action': 'ALLOW_STRONG_AUTHENTICATION'}, 'google_workspace': {'admin': {'new_value': False}}, '@timestamp': 1}]
```



### Malware - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-309

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:file_classification_event or endgame.event_subtype_full:file_classification_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'file_classification_event'}, 'endgame': {'metadata': {'type': 'detection'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'detection'}, 'event_subtype_full': 'file_classification_event'}, '@timestamp': 1}]
```



### Malware - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-310

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:file_classification_event or endgame.event_subtype_full:file_classification_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'file_classification_event'}, 'endgame': {'metadata': {'type': 'prevention'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'prevention'}, 'event_subtype_full': 'file_classification_event'}, '@timestamp': 1}]
```



### Microsoft 365 Exchange Anti-Phish Policy Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-311

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-AntiPhishPolicy" and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Remove-AntiPhishPolicy', 'outcome': 'success'}, '@timestamp': 0}]
```



### Microsoft 365 Exchange Anti-Phish Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-312

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-AntiPhishRule" or "Disable-AntiPhishRule") and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Remove-AntiPhishRule', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Disable-AntiPhishRule', 'outcome': 'success'}, '@timestamp': 1}]
```



### Microsoft 365 Exchange DKIM Signing Configuration Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-313

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Set-DkimSigningConfig" and o365.audit.Parameters.Enabled:False and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Set-DkimSigningConfig', 'outcome': 'success'}, 'o365': {'audit': {'Parameters': {'Enabled': 'False'}}}, '@timestamp': 0}]
```



### Microsoft 365 Exchange DLP Policy Removed

Branch count: 1  
Document count: 1  
Index: geneve-ut-314

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-DlpPolicy" and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Remove-DlpPolicy', 'outcome': 'success'}, '@timestamp': 0}]
```



### Microsoft 365 Exchange Malware Filter Policy Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-315

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-MalwareFilterPolicy" and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Remove-MalwareFilterPolicy', 'outcome': 'success'}, '@timestamp': 0}]
```



### Microsoft 365 Exchange Malware Filter Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-316

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-MalwareFilterRule" or "Disable-MalwareFilterRule") and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Remove-MalwareFilterRule', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Disable-MalwareFilterRule', 'outcome': 'success'}, '@timestamp': 1}]
```



### Microsoft 365 Exchange Management Group Role Assignment

Branch count: 1  
Document count: 1  
Index: geneve-ut-317

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"New-ManagementRoleAssignment" and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'New-ManagementRoleAssignment', 'outcome': 'success'}, '@timestamp': 0}]
```



### Microsoft 365 Exchange Safe Attachment Rule Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-318

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Disable-SafeAttachmentRule" and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Disable-SafeAttachmentRule', 'outcome': 'success'}, '@timestamp': 0}]
```



### Microsoft 365 Exchange Safe Link Policy Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-319

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Disable-SafeLinksRule" and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Disable-SafeLinksRule', 'outcome': 'success'}, '@timestamp': 0}]
```



### Microsoft 365 Exchange Transport Rule Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-320

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"New-TransportRule" and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'New-TransportRule', 'outcome': 'success'}, '@timestamp': 0}]
```



### Microsoft 365 Exchange Transport Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-321

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-TransportRule" or "Disable-TransportRule") and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Remove-TransportRule', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Disable-TransportRule', 'outcome': 'success'}, '@timestamp': 1}]
```



### Microsoft 365 Global Administrator Role Assigned

Branch count: 1  
Document count: 1  
Index: geneve-ut-322

```python
event.dataset:o365.audit and event.code:"AzureActiveDirectory" and event.action:"Add member to role." and
o365.audit.ModifiedProperties.Role_DisplayName.NewValue:"Global Administrator"
```

```python
[{'event': {'dataset': 'o365.audit', 'code': 'AzureActiveDirectory', 'action': 'Add member to role.'}, 'o365': {'audit': {'ModifiedProperties': {'Role_DisplayName': {'NewValue': 'Global Administrator'}}}}, '@timestamp': 0}]
```



### Microsoft 365 Impossible travel activity

Branch count: 1  
Document count: 1  
Index: geneve-ut-323

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"Impossible travel activity" and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'SecurityComplianceCenter', 'category': ['web'], 'action': 'Impossible travel activity', 'outcome': 'success'}, '@timestamp': 0}]
```



### Microsoft 365 Inbox Forwarding Rule Created

Branch count: 3  
Document count: 3  
Index: geneve-ut-324

```python
event.dataset:o365.audit and event.provider:Exchange and
event.category:web and event.action:"New-InboxRule" and
    (
        o365audit.Parameters.ForwardTo:* or
        o365audit.Parameters.ForwardAsAttachmentTo:* or
        o365audit.Parameters.RedirectTo:*
    ) 
    and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'New-InboxRule', 'outcome': 'success'}, 'o365audit': {'Parameters': {'ForwardTo': 'ZFy'}}, '@timestamp': 0},
 {'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'New-InboxRule', 'outcome': 'success'}, 'o365audit': {'Parameters': {'ForwardAsAttachmentTo': 'XIU'}}, '@timestamp': 1},
 {'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'New-InboxRule', 'outcome': 'success'}, 'o365audit': {'Parameters': {'RedirectTo': 'tkN'}}, '@timestamp': 2}]
```



### Microsoft 365 Mass download by a single user

Branch count: 1  
Document count: 1  
Index: geneve-ut-325

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"Mass download by a single user" and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'SecurityComplianceCenter', 'category': ['web'], 'action': 'Mass download by a single user', 'outcome': 'success'}, '@timestamp': 0}]
```



### Microsoft 365 Potential ransomware activity

Branch count: 1  
Document count: 1  
Index: geneve-ut-326

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"Potential ransomware activity" and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'SecurityComplianceCenter', 'category': ['web'], 'action': 'Potential ransomware activity', 'outcome': 'success'}, '@timestamp': 0}]
```



### Microsoft 365 Teams Custom Application Interaction Allowed

Branch count: 1  
Document count: 1  
Index: geneve-ut-327

```python
event.dataset:o365.audit and event.provider:MicrosoftTeams and
event.category:web and event.action:TeamsTenantSettingChanged and
o365.audit.Name:"Allow sideloading and interaction of custom apps" and
o365.audit.NewValue:True and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'MicrosoftTeams', 'category': ['web'], 'action': 'TeamsTenantSettingChanged', 'outcome': 'success'}, 'o365': {'audit': {'Name': 'Allow sideloading and interaction of custom apps', 'NewValue': 'True'}}, '@timestamp': 0}]
```



### Microsoft 365 Teams External Access Enabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-328

```python
event.dataset:o365.audit and event.provider:(SkypeForBusiness or MicrosoftTeams) and
event.category:web and event.action:"Set-CsTenantFederationConfiguration" and
o365.audit.Parameters.AllowFederatedUsers:True and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'SkypeForBusiness', 'category': ['web'], 'action': 'Set-CsTenantFederationConfiguration', 'outcome': 'success'}, 'o365': {'audit': {'Parameters': {'AllowFederatedUsers': 'True'}}}, '@timestamp': 0},
 {'event': {'dataset': 'o365.audit', 'provider': 'MicrosoftTeams', 'category': ['web'], 'action': 'Set-CsTenantFederationConfiguration', 'outcome': 'success'}, 'o365': {'audit': {'Parameters': {'AllowFederatedUsers': 'True'}}}, '@timestamp': 1}]
```



### Microsoft 365 Teams Guest Access Enabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-329

```python
event.dataset:o365.audit and event.provider:(SkypeForBusiness or MicrosoftTeams) and
event.category:web and event.action:"Set-CsTeamsClientConfiguration" and
o365.audit.Parameters.AllowGuestUser:True and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'SkypeForBusiness', 'category': ['web'], 'action': 'Set-CsTeamsClientConfiguration', 'outcome': 'success'}, 'o365': {'audit': {'Parameters': {'AllowGuestUser': 'True'}}}, '@timestamp': 0},
 {'event': {'dataset': 'o365.audit', 'provider': 'MicrosoftTeams', 'category': ['web'], 'action': 'Set-CsTeamsClientConfiguration', 'outcome': 'success'}, 'o365': {'audit': {'Parameters': {'AllowGuestUser': 'True'}}}, '@timestamp': 1}]
```



### Microsoft 365 Unusual Volume of File Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-330

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"Unusual volume of file deletion" and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'SecurityComplianceCenter', 'category': ['web'], 'action': 'Unusual volume of file deletion', 'outcome': 'success'}, '@timestamp': 0}]
```



### Microsoft 365 User Restricted from Sending Email

Branch count: 1  
Document count: 1  
Index: geneve-ut-331

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"User restricted from sending email" and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'SecurityComplianceCenter', 'category': ['web'], 'action': 'User restricted from sending email', 'outcome': 'success'}, '@timestamp': 0}]
```



### Microsoft Build Engine Loading Windows Credential Libraries

Branch count: 2  
Document count: 4  
Index: geneve-ut-332

```python
sequence by process.entity_id
 [process where event.type == "start" and (process.name : "MSBuild.exe" or process.pe.original_file_name == "MSBuild.exe")]
 [library where dll.name : ("vaultcli.dll", "SAMLib.DLL")]
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'MSBuild.exe', 'entity_id': 'ZFy'}, '@timestamp': 0},
 {'dll': {'name': 'SAMLib.DLL'}, 'event': {'category': ['library']}, 'process': {'entity_id': 'ZFy'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'MSBuild.exe'}, 'entity_id': 'Utk'}, '@timestamp': 2},
 {'dll': {'name': 'SAMLib.DLL'}, 'event': {'category': ['library']}, 'process': {'entity_id': 'Utk'}, '@timestamp': 3}]
```



### Microsoft Build Engine Started an Unusual Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-333

```python
process where event.type in ("start", "process_started") and
  process.parent.name : "MSBuild.exe" and
  process.name : ("csc.exe", "iexplore.exe", "powershell.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'MSBuild.exe'}, 'name': 'powershell.exe'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'MSBuild.exe'}, 'name': 'iexplore.exe'}, '@timestamp': 1}]
```



### Microsoft Build Engine Started by a Script Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-334

```python
process where event.type == "start" and
  (process.name : "MSBuild.exe" or process.pe.original_file_name == "MSBuild.exe") and
  process.parent.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cscript.exe", "wscript.exe", "mshta.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'MSBuild.exe', 'parent': {'name': 'powershell_ise.exe'}}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'MSBuild.exe'}, 'parent': {'name': 'wscript.exe'}}, '@timestamp': 1}]
```



### Microsoft Build Engine Started by a System Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-335

```python
process where event.type in ("start", "process_started") and
  process.name : "MSBuild.exe" and
  process.parent.name : ("explorer.exe", "wmiprvse.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'MSBuild.exe', 'parent': {'name': 'wmiprvse.exe'}}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'MSBuild.exe', 'parent': {'name': 'wmiprvse.exe'}}, '@timestamp': 1}]
```



### Microsoft Build Engine Started by an Office Application

Branch count: 2  
Document count: 2  
Index: geneve-ut-336

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'MSBuild.exe', 'parent': {'name': 'winword.exe'}}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'MSBuild.exe', 'parent': {'name': 'powerpnt.exe'}}, '@timestamp': 1}]
```



### Microsoft Build Engine Using an Alternate Name

Branch count: 2  
Document count: 2  
Index: geneve-ut-337

```python
process where event.type in ("start", "process_started") and
  process.pe.original_file_name == "MSBuild.exe" and
  not process.name : "MSBuild.exe"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'MSBuild.exe'}, 'name': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'MSBuild.exe'}, 'name': 'XIU'}, '@timestamp': 1}]
```



### Microsoft Exchange Server UM Spawning Suspicious Processes

Branch count: 1  
Document count: 1  
Index: geneve-ut-338

```python
process where event.type == "start" and
  process.parent.name : ("UMService.exe", "UMWorkerProcess.exe") and
    not process.name : ("werfault.exe", "wermgr.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'UMWorkerProcess.exe'}, 'name': 'vCf'}, '@timestamp': 0}]
```



### Microsoft Exchange Server UM Writing Suspicious Files

Branch count: 3  
Document count: 3  
Index: geneve-ut-339

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

```python
[{'event': {'type': ['creation'], 'category': ['file']}, 'process': {'name': 'umservice.exe'}, 'file': {'extension': 'php', 'path': 'y:\\inetpub\\wwwroot\\aspnet_client\\kNIoixTF'}, '@timestamp': 0},
 {'event': {'type': ['creation'], 'category': ['file']}, 'process': {'name': 'UMWorkerProcess.exe'}, 'file': {'extension': 'js', 'path': 'P:\\mxBnLe\\Microsoft\\Exchange ServerWqNVRcymEEwVP\\FrontEnd\\HttpProxy\\owa\\auth\\MGzNfmlO', 'name': 'PZR'}, '@timestamp': 1},
 {'event': {'type': ['creation'], 'category': ['file']}, 'process': {'name': 'UMWorkerProcess.exe'}, 'file': {'extension': 'php', 'path': 'I:\\iMZ\\Microsoft\\Exchange ServergTmshCeLWYcYs\\FrontEnd\\HttpProxy\\ecp\\auth\\o', 'name': 'Grm'}, '@timestamp': 2}]
```



### Microsoft Exchange Worker Spawning Suspicious Processes

Branch count: 5  
Document count: 5  
Index: geneve-ut-340

```python
process where event.type == "start" and
  process.parent.name : "w3wp.exe" and process.parent.args : "MSExchange*AppPool" and
  (process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe") or
  process.pe.original_file_name in ("cmd.exe", "powershell.exe", "pwsh.dll", "powershell_ise.exe"))
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'w3wp.exe', 'args': ['MSExchange*AppPool']}, 'name': 'pwsh.exe'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'w3wp.exe', 'args': ['MSExchange*AppPool']}, 'pe': {'original_file_name': 'cmd.exe'}}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'w3wp.exe', 'args': ['MSExchange*AppPool']}, 'pe': {'original_file_name': 'powershell.exe'}}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'w3wp.exe', 'args': ['MSExchange*AppPool']}, 'pe': {'original_file_name': 'pwsh.dll'}}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'w3wp.exe', 'args': ['MSExchange*AppPool']}, 'pe': {'original_file_name': 'powershell_ise.exe'}}, '@timestamp': 4}]
```



### Microsoft IIS Connection Strings Decryption

Branch count: 4  
Document count: 4  
Index: geneve-ut-341

```python
process where event.type in ("start", "process_started") and
  (process.name : "aspnet_regiis.exe" or process.pe.original_file_name == "aspnet_regiis.exe") and
  process.args : "connectionStrings" and process.args : "-pdf"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'aspnet_regiis.exe', 'args': ['connectionStrings', '-pdf']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'aspnet_regiis.exe'}, 'args': ['connectionStrings', '-pdf']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'aspnet_regiis.exe', 'args': ['connectionStrings', '-pdf']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'aspnet_regiis.exe'}, 'args': ['connectionStrings', '-pdf']}, '@timestamp': 3}]
```



### Microsoft IIS Service Account Password Dumped

Branch count: 4  
Document count: 4  
Index: geneve-ut-342

```python
process where event.type in ("start", "process_started") and
   (process.name : "appcmd.exe" or process.pe.original_file_name == "appcmd.exe") and 
   process.args : "/list" and process.args : "/text*password"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'appcmd.exe', 'args': ['/list', '/text*password']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'appcmd.exe'}, 'args': ['/list', '/text*password']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'appcmd.exe', 'args': ['/list', '/text*password']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'appcmd.exe'}, 'args': ['/list', '/text*password']}, '@timestamp': 3}]
```



### Mimikatz Memssp Log File Detected

Branch count: 1  
Document count: 1  
Index: geneve-ut-344

```python
file where file.name : "mimilsa.log" and process.name : "lsass.exe"
```

```python
[{'file': {'name': 'mimilsa.log'}, 'process': {'name': 'lsass.exe'}, 'event': {'category': ['file']}, '@timestamp': 0}]
```



### Mimikatz Powershell Module Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-345

```python
process where event.type in ("start", "process_started") and process.name : ("cmd.exe", "powershell.exe", "pwsh.exe")
and process.args : ("*DumpCreds", "*Mimikatz*")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'pwsh.exe', 'args': ['*DumpCreds', '*Mimikatz*']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'powershell.exe', 'args': ['*DumpCreds', '*Mimikatz*']}, '@timestamp': 1}]
```



### Mknod Process Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-346

```python
event.category:process and event.type:(start or process_started) and process.name:mknod
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'mknod'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'mknod'}, '@timestamp': 1}]
```



### Modification of Boot Configuration

Branch count: 5  
Document count: 5  
Index: geneve-ut-348

```python
process where event.type in ("start", "process_started") and
  (process.name : "bcdedit.exe" or process.pe.original_file_name == "bcdedit.exe") and
  (process.args : "/set" and process.args : "bootstatuspolicy" and process.args : "ignoreallfailures") or
  (process.args : "no" and process.args : "recoveryenabled")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bcdedit.exe', 'args': ['/set', 'bootstatuspolicy', 'ignoreallfailures']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'bcdedit.exe'}, 'args': ['/set', 'bootstatuspolicy', 'ignoreallfailures']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'bcdedit.exe', 'args': ['/set', 'bootstatuspolicy', 'ignoreallfailures']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'bcdedit.exe'}, 'args': ['/set', 'bootstatuspolicy', 'ignoreallfailures']}, '@timestamp': 3},
 {'process': {'args': ['no', 'recoveryenabled']}, 'event': {'category': ['process']}, '@timestamp': 4}]
```



### Modification of Dynamic Linker Preload Shared Object

Branch count: 1  
Document count: 1  
Index: geneve-ut-349

```python
event.category:file and not event.type:deletion and file.path:/etc/ld.so.preload
```

```python
[{'event': {'category': ['file'], 'type': ['ZFy']}, 'file': {'path': '/etc/ld.so.preload'}, '@timestamp': 0}]
```



### Modification of Environment Variable via Launchctl

Branch count: 1  
Document count: 1  
Index: geneve-ut-350

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
                                 "/Applications/IntelliJ IDEA CE.app/Contents/jbr/Contents/Home/lib/jspawnhelper")
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'launchctl', 'args': ['setenv'], 'parent': {'executable': 'ZFy'}}, '@timestamp': 0}]
```



### Modification of OpenSSH Binaries

Branch count: 5  
Document count: 5  
Index: geneve-ut-351

```python
event.category:file and event.type:change and 
 process.name:* and
 (file.path:(/usr/sbin/sshd or /usr/bin/ssh or /usr/bin/sftp or /usr/bin/scp) or file.name:libkeyutils.so) and
 not process.executable:/usr/bin/dpkg
```

```python
[{'event': {'category': ['file'], 'type': ['change']}, 'process': {'name': 'ZFy', 'executable': 'XIU'}, 'file': {'path': '/usr/sbin/sshd'}, '@timestamp': 0},
 {'event': {'category': ['file'], 'type': ['change']}, 'process': {'name': 'tkN', 'executable': 'Ioi'}, 'file': {'path': '/usr/bin/ssh'}, '@timestamp': 1},
 {'event': {'category': ['file'], 'type': ['change']}, 'process': {'name': 'xTF', 'executable': 'lEz'}, 'file': {'path': '/usr/bin/sftp'}, '@timestamp': 2},
 {'event': {'category': ['file'], 'type': ['change']}, 'process': {'name': 'swu', 'executable': 'EEX'}, 'file': {'path': '/usr/bin/scp'}, '@timestamp': 3},
 {'event': {'category': ['file'], 'type': ['change']}, 'process': {'name': 'pWq', 'executable': 'NVR'}, 'file': {'name': 'libkeyutils.so'}, '@timestamp': 4}]
```



### Modification of Safari Settings via Defaults Command

Branch count: 1  
Document count: 1  
Index: geneve-ut-352

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

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'defaults', 'args': ['com.apple.Safari', 'write']}, '@timestamp': 0}]
```



### Modification of Standard Authentication Module or Configuration

Branch count: 2  
Document count: 2  
Index: geneve-ut-353

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

```python
[{'event': {'category': ['file'], 'type': ['change']}, 'file': {'name': 'pam_XIUtkNI.so', 'path': 'TFl'}, 'process': {'executable': 'oix'}, '@timestamp': 0},
 {'event': {'category': ['file'], 'type': ['change']}, 'file': {'path': '/private/etc/pam.d/swuEEXpWqNV'}, 'process': {'executable': 'Rcy'}, '@timestamp': 1}]
```



### Modification or Removal of an Okta Application Sign-On Policy

Branch count: 2  
Document count: 2  
Index: geneve-ut-355

```python
event.dataset:okta.system and event.action:(application.policy.sign_on.update or application.policy.sign_on.rule.delete)
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'application.policy.sign_on.update'}, '@timestamp': 0},
 {'event': {'dataset': 'okta.system', 'action': 'application.policy.sign_on.rule.delete'}, '@timestamp': 1}]
```



### Mounting Hidden or WebDav Remote Shares

Branch count: 8  
Document count: 8  
Index: geneve-ut-356

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'net.exe', 'args': ['use', '\\\\*\\*$*', '\\\\*@SSL\\*', 'http*']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net.exe'}, 'args': ['use', '\\\\*\\*$*', '\\\\*@SSL\\*', 'http*']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'net1.exe', 'parent': {'name': 'ZFy'}, 'args': ['use', '\\\\*\\*$*', '\\\\*@SSL\\*', 'http*']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net1.exe'}, 'parent': {'name': 'XIU'}, 'args': ['use', '\\\\*\\*$*', '\\\\*@SSL\\*', 'http*']}, '@timestamp': 3},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'net.exe', 'args': ['use', '\\\\*\\*$*', '\\\\*@SSL\\*', 'http*']}, '@timestamp': 4},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net.exe'}, 'args': ['use', '\\\\*\\*$*', '\\\\*@SSL\\*', 'http*']}, '@timestamp': 5},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'net1.exe', 'parent': {'name': 'tkN'}, 'args': ['use', '\\\\*\\*$*', '\\\\*@SSL\\*', 'http*']}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net1.exe'}, 'parent': {'name': 'Ioi'}, 'args': ['use', '\\\\*\\*$*', '\\\\*@SSL\\*', 'http*']}, '@timestamp': 7}]
```



### MsBuild Making Network Connections

Branch count: 1  
Document count: 2  
Index: geneve-ut-357

```python
sequence by process.entity_id
  [process where process.name : "MSBuild.exe" and event.type == "start"]
  [network where process.name : "MSBuild.exe" and
     not cidrmatch(destination.ip, "127.0.0.1", "::1")]
```

```python
[{'process': {'name': 'MSBuild.exe', 'entity_id': 'ZFy'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'MSBuild.exe', 'entity_id': 'ZFy'}, 'destination': {'ip': '229.172.181.141'}, 'event': {'category': ['network']}, '@timestamp': 1}]
```



### MsBuild Network Connection Sequence

Branch count: 4  
Document count: 8  
Index: geneve-ut-358

```python
/* duplicate of MsBuild Making Network Connections - 0e79980b-4250-4a50-a509-69294c14e84b */

sequence by process.entity_id
  [process where event.type in ("start", "process_started") and process.name : "MSBuild.exe"]
  [network where process.name : "MSBuild.exe" and
     not (destination.ip == "127.0.0.1" and source.ip == "127.0.0.1")]
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'MSBuild.exe', 'entity_id': 'ZFy'}, '@timestamp': 0},
 {'process': {'name': 'MSBuild.exe', 'entity_id': 'ZFy'}, 'destination': {'ip': '229.172.181.141'}, 'event': {'category': ['network']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'MSBuild.exe', 'entity_id': 'Uyy'}, '@timestamp': 2},
 {'process': {'name': 'MSBuild.exe', 'entity_id': 'Uyy'}, 'source': {'ip': '73.157.79.25'}, 'event': {'category': ['network']}, '@timestamp': 3},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'MSBuild.exe', 'entity_id': 'SvI'}, '@timestamp': 4},
 {'process': {'name': 'MSBuild.exe', 'entity_id': 'SvI'}, 'destination': {'ip': '70.123.63.77'}, 'event': {'category': ['network']}, '@timestamp': 5},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'MSBuild.exe', 'entity_id': 'Ezs'}, '@timestamp': 6},
 {'process': {'name': 'MSBuild.exe', 'entity_id': 'Ezs'}, 'source': {'ip': '116.114.240.76'}, 'event': {'category': ['network']}, '@timestamp': 7}]
```



### MsXsl Making Network Connections

Branch count: 2  
Document count: 4  
Index: geneve-ut-359

```python
/* duplicate of Network Connection via MsXsl - b86afe07-0d98-4738-b15d-8d7465f95ff5 */

sequence by process.entity_id
  [process where event.type in ("start", "process_started") and process.name : "msxsl.exe"]
  [network where process.name : "msxsl.exe" and network.direction : ("outgoing", "egress")]
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'msxsl.exe', 'entity_id': 'ZFy'}, '@timestamp': 0},
 {'process': {'name': 'msxsl.exe', 'entity_id': 'ZFy'}, 'network': {'direction': 'egress'}, 'event': {'category': ['network']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'msxsl.exe', 'entity_id': 'Utk'}, '@timestamp': 2},
 {'process': {'name': 'msxsl.exe', 'entity_id': 'Utk'}, 'network': {'direction': 'egress'}, 'event': {'category': ['network']}, '@timestamp': 3}]
```



### Mshta Making Network Connections

Branch count: 2  
Document count: 4  
Index: geneve-ut-360

```python
sequence by process.entity_id with maxspan=10m
  [process where event.type in ("start", "process_started") and process.name : "mshta.exe" and
     not process.parent.name : "Microsoft.ConfigurationManagement.exe" and
     not (process.parent.executable : "C:\\Amazon\\Amazon Assistant\\amazonAssistantService.exe" or
          process.parent.executable : "C:\\TeamViewer\\TeamViewer.exe") and
     not process.args : "ADSelfService_Enroll.hta"]
  [network where process.name : "mshta.exe"]
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'mshta.exe', 'parent': {'name': 'ZFy', 'executable': 'XIU'}, 'args': ['tkN'], 'entity_id': 'Ioi'}, '@timestamp': 0},
 {'process': {'name': 'mshta.exe', 'entity_id': 'Ioi'}, 'event': {'category': ['network']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'mshta.exe', 'parent': {'name': 'xTF', 'executable': 'lEz'}, 'args': ['swu'], 'entity_id': 'EEX'}, '@timestamp': 2},
 {'process': {'name': 'mshta.exe', 'entity_id': 'EEX'}, 'event': {'category': ['network']}, '@timestamp': 3}]
```



### Multi-Factor Authentication Disabled for an Azure User

Branch count: 2  
Document count: 2  
Index: geneve-ut-361

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Disable Strong Authentication" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'operation_name': 'Disable Strong Authentication'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'operation_name': 'Disable Strong Authentication'}}, '@timestamp': 1}]
```



### NTDS or SAM Database File Copied

Branch count: 8  
Document count: 8  
Index: geneve-ut-362

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['copy', 'xcopy', 'Copy-Item', 'move', 'cp', 'mv', '*\\ntds.dit', '*\\config\\SAM', '\\*\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\*', '*/system32/config/SAM*']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['copy', 'xcopy', 'Copy-Item', 'move', 'cp', 'mv', '*\\ntds.dit', '*\\config\\SAM', '\\*\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\*', '*/system32/config/SAM*']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'XCOPY.EXE'}, 'args': ['copy', 'xcopy', 'Copy-Item', 'move', 'cp', 'mv', '*\\ntds.dit', '*\\config\\SAM', '\\*\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\*', '*/system32/config/SAM*']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'esentutl.exe'}, 'args': ['*/y*', '*/vss*', '*/d*', '*\\ntds.dit', '*\\config\\SAM', '\\*\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\*', '*/system32/config/SAM*']}, '@timestamp': 3},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['copy', 'xcopy', 'Copy-Item', 'move', 'cp', 'mv', '*\\ntds.dit', '*\\config\\SAM', '\\*\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\*', '*/system32/config/SAM*']}, '@timestamp': 4},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['copy', 'xcopy', 'Copy-Item', 'move', 'cp', 'mv', '*\\ntds.dit', '*\\config\\SAM', '\\*\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\*', '*/system32/config/SAM*']}, '@timestamp': 5},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'XCOPY.EXE'}, 'args': ['copy', 'xcopy', 'Copy-Item', 'move', 'cp', 'mv', '*\\ntds.dit', '*\\config\\SAM', '\\*\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\*', '*/system32/config/SAM*']}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'esentutl.exe'}, 'args': ['*/y*', '*/vss*', '*/d*', '*\\ntds.dit', '*\\config\\SAM', '\\*\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\*', '*/system32/config/SAM*']}, '@timestamp': 7}]
```



### Netcat Network Activity

Branch count: 25  
Document count: 50  
Index: geneve-ut-363

```python
sequence by process.entity_id
  [process where (process.name == "nc" or process.name == "ncat" or process.name == "netcat" or
                  process.name == "netcat.openbsd" or process.name == "netcat.traditional") and
     event.type == "start"]
  [network where (process.name == "nc" or process.name == "ncat" or process.name == "netcat" or
                  process.name == "netcat.openbsd" or process.name == "netcat.traditional")]
```

```python
[{'process': {'name': 'nc', 'entity_id': 'ZFy'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'nc', 'entity_id': 'ZFy'}, 'event': {'category': ['network']}, '@timestamp': 1},
 {'process': {'name': 'nc', 'entity_id': 'XIU'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 2},
 {'process': {'name': 'ncat', 'entity_id': 'XIU'}, 'event': {'category': ['network']}, '@timestamp': 3},
 {'process': {'name': 'nc', 'entity_id': 'tkN'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 4},
 {'process': {'name': 'netcat', 'entity_id': 'tkN'}, 'event': {'category': ['network']}, '@timestamp': 5},
 {'process': {'name': 'nc', 'entity_id': 'Ioi'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 6},
 {'process': {'name': 'netcat.openbsd', 'entity_id': 'Ioi'}, 'event': {'category': ['network']}, '@timestamp': 7},
 {'process': {'name': 'nc', 'entity_id': 'xTF'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 8},
 {'process': {'name': 'netcat.traditional', 'entity_id': 'xTF'}, 'event': {'category': ['network']}, '@timestamp': 9},
 {'process': {'name': 'ncat', 'entity_id': 'lEz'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 10},
 {'process': {'name': 'nc', 'entity_id': 'lEz'}, 'event': {'category': ['network']}, '@timestamp': 11},
 {'process': {'name': 'ncat', 'entity_id': 'swu'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 12},
 {'process': {'name': 'ncat', 'entity_id': 'swu'}, 'event': {'category': ['network']}, '@timestamp': 13},
 {'process': {'name': 'ncat', 'entity_id': 'EEX'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 14},
 {'process': {'name': 'netcat', 'entity_id': 'EEX'}, 'event': {'category': ['network']}, '@timestamp': 15},
 {'process': {'name': 'ncat', 'entity_id': 'pWq'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 16},
 {'process': {'name': 'netcat.openbsd', 'entity_id': 'pWq'}, 'event': {'category': ['network']}, '@timestamp': 17},
 {'process': {'name': 'ncat', 'entity_id': 'NVR'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 18},
 {'process': {'name': 'netcat.traditional', 'entity_id': 'NVR'}, 'event': {'category': ['network']}, '@timestamp': 19},
 {'process': {'name': 'netcat', 'entity_id': 'cym'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 20},
 {'process': {'name': 'nc', 'entity_id': 'cym'}, 'event': {'category': ['network']}, '@timestamp': 21},
 {'process': {'name': 'netcat', 'entity_id': 'EEw'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 22},
 {'process': {'name': 'ncat', 'entity_id': 'EEw'}, 'event': {'category': ['network']}, '@timestamp': 23},
 {'process': {'name': 'netcat', 'entity_id': 'VPY'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 24},
 {'process': {'name': 'netcat', 'entity_id': 'VPY'}, 'event': {'category': ['network']}, '@timestamp': 25},
 {'process': {'name': 'netcat', 'entity_id': 'MGz'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 26},
 {'process': {'name': 'netcat.openbsd', 'entity_id': 'MGz'}, 'event': {'category': ['network']}, '@timestamp': 27},
 {'process': {'name': 'netcat', 'entity_id': 'Nfm'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 28},
 {'process': {'name': 'netcat.traditional', 'entity_id': 'Nfm'}, 'event': {'category': ['network']}, '@timestamp': 29},
 {'process': {'name': 'netcat.openbsd', 'entity_id': 'lOP'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 30},
 {'process': {'name': 'nc', 'entity_id': 'lOP'}, 'event': {'category': ['network']}, '@timestamp': 31},
 {'process': {'name': 'netcat.openbsd', 'entity_id': 'ZRg'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 32},
 {'process': {'name': 'ncat', 'entity_id': 'ZRg'}, 'event': {'category': ['network']}, '@timestamp': 33},
 {'process': {'name': 'netcat.openbsd', 'entity_id': 'UvW'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 34},
 {'process': {'name': 'netcat', 'entity_id': 'UvW'}, 'event': {'category': ['network']}, '@timestamp': 35},
 {'process': {'name': 'netcat.openbsd', 'entity_id': 'CiM'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 36},
 {'process': {'name': 'netcat.openbsd', 'entity_id': 'CiM'}, 'event': {'category': ['network']}, '@timestamp': 37},
 {'process': {'name': 'netcat.openbsd', 'entity_id': 'ZOf'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 38},
 {'process': {'name': 'netcat.traditional', 'entity_id': 'ZOf'}, 'event': {'category': ['network']}, '@timestamp': 39},
 {'process': {'name': 'netcat.traditional', 'entity_id': 'HaT'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 40},
 {'process': {'name': 'nc', 'entity_id': 'HaT'}, 'event': {'category': ['network']}, '@timestamp': 41},
 {'process': {'name': 'netcat.traditional', 'entity_id': 'Dgz'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 42},
 {'process': {'name': 'ncat', 'entity_id': 'Dgz'}, 'event': {'category': ['network']}, '@timestamp': 43},
 {'process': {'name': 'netcat.traditional', 'entity_id': 'RJi'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 44},
 {'process': {'name': 'netcat', 'entity_id': 'RJi'}, 'event': {'category': ['network']}, '@timestamp': 45},
 {'process': {'name': 'netcat.traditional', 'entity_id': 'LSj'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 46},
 {'process': {'name': 'netcat.openbsd', 'entity_id': 'LSj'}, 'event': {'category': ['network']}, '@timestamp': 47},
 {'process': {'name': 'netcat.traditional', 'entity_id': 'oGr'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 48},
 {'process': {'name': 'netcat.traditional', 'entity_id': 'oGr'}, 'event': {'category': ['network']}, '@timestamp': 49}]
```



### Network Connection via Certutil

Branch count: 1  
Document count: 2  
Index: geneve-ut-364

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

```python
[{'process': {'name': 'certutil.exe', 'entity_id': 'ZFy'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'certutil.exe', 'entity_id': 'ZFy'}, 'destination': {'ip': '170.121.236.89'}, 'event': {'category': ['network']}, '@timestamp': 1}]
```



### Network Connection via Compiled HTML File

Branch count: 1  
Document count: 2  
Index: geneve-ut-365

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

```python
[{'process': {'name': 'hh.exe', 'entity_id': 'ZFy'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'hh.exe', 'entity_id': 'ZFy'}, 'destination': {'ip': '170.121.236.89'}, 'event': {'category': ['network']}, '@timestamp': 1}]
```



### Network Connection via MsXsl

Branch count: 1  
Document count: 2  
Index: geneve-ut-366

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

```python
[{'process': {'name': 'msxsl.exe', 'entity_id': 'ZFy'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'msxsl.exe', 'entity_id': 'ZFy'}, 'destination': {'ip': '170.121.236.89'}, 'event': {'category': ['network']}, '@timestamp': 1}]
```



### Network Connection via Mshta

Branch count: 1  
Document count: 2  
Index: geneve-ut-367

```python
/* duplicate of Mshta Making Network Connections - c2d90150-0133-451c-a783-533e736c12d7 */

sequence by process.entity_id
  [process where process.name : "mshta.exe" and event.type == "start"]
  [network where process.name : "mshta.exe"]
```

```python
[{'process': {'name': 'mshta.exe', 'entity_id': 'ZFy'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'mshta.exe', 'entity_id': 'ZFy'}, 'event': {'category': ['network']}, '@timestamp': 1}]
```



### Network Connection via Registration Utility

Branch count: 2  
Document count: 4  
Index: geneve-ut-368

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'regsvr32.exe', 'Ext': {'token': {'integrity_level_name': 'TvC'}}, 'entity_id': 'yFj'}, 'winlog': {'event_data': {'IntegrityLevel': 'fUy'}}, '@timestamp': 0},
 {'process': {'name': 'RegAsm.exe', 'entity_id': 'yFj'}, 'destination': {'ip': '115.189.242.190'}, 'network': {'protocol': 'ILO'}, 'event': {'category': ['network']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'RegSvcs.exe', 'parent': {'name': 'Ezs', 'executable': 'wuE'}, 'entity_id': 'EXp'}, '@timestamp': 2},
 {'process': {'name': 'regsvr32.exe', 'entity_id': 'EXp'}, 'destination': {'ip': '0.167.86.71'}, 'network': {'protocol': 'NVR'}, 'event': {'category': ['network']}, '@timestamp': 3}]
```



### Network Connection via Signed Binary

Branch count: 1  
Document count: 2  
Index: geneve-ut-369

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

```python
[{'process': {'name': 'makecab.exe', 'entity_id': 'vCf'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'makecab.exe', 'entity_id': 'vCf'}, 'destination': {'ip': '54.2.158.30'}, 'event': {'category': ['network']}, '@timestamp': 1}]
```



### Network Sniffing via Tcpdump

Branch count: 2  
Document count: 2  
Index: geneve-ut-371

```python
event.category:process and event.type:(start or process_started) and process.name:tcpdump
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tcpdump'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'tcpdump'}, '@timestamp': 1}]
```



### New ActiveSyncAllowedDeviceID Added via PowerShell

Branch count: 2  
Document count: 2  
Index: geneve-ut-373

```python
process where event.type in ("start", "process_started") and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and process.args : "Set-CASMailbox*ActiveSyncAllowedDeviceIDs*"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'pwsh.exe', 'args': ['Set-CASMailbox*ActiveSyncAllowedDeviceIDs*']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'powershell_ise.exe', 'args': ['Set-CASMailbox*ActiveSyncAllowedDeviceIDs*']}, '@timestamp': 1}]
```



### New or Modified Federation Domain

Branch count: 6  
Document count: 6  
Index: geneve-ut-374

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Set-AcceptedDomain" or 
"Set-MsolDomainFederationSettings" or "Add-FederatedDomain" or "New-AcceptedDomain" or "Remove-AcceptedDomain" or "Remove-FederatedDomain") and 
event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Set-AcceptedDomain', 'outcome': 'success'}, '@timestamp': 0},
 {'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Set-MsolDomainFederationSettings', 'outcome': 'success'}, '@timestamp': 1},
 {'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Add-FederatedDomain', 'outcome': 'success'}, '@timestamp': 2},
 {'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'New-AcceptedDomain', 'outcome': 'success'}, '@timestamp': 3},
 {'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Remove-AcceptedDomain', 'outcome': 'success'}, '@timestamp': 4},
 {'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'category': ['web'], 'action': 'Remove-FederatedDomain', 'outcome': 'success'}, '@timestamp': 5}]
```



### Nmap Process Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-375

```python
event.category:process and event.type:(start or process_started) and process.name:nmap
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'nmap'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'nmap'}, '@timestamp': 1}]
```



### Nping Process Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-376

```python
event.category:process and event.type:(start or process_started) and process.name:nping
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'nping'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'nping'}, '@timestamp': 1}]
```



### O365 Email Reported by User as Malware or Phish

Branch count: 1  
Document count: 1  
Index: geneve-ut-378

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.action:AlertTriggered and rule.name:"Email reported by user as malware or phish"
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'SecurityComplianceCenter', 'action': 'AlertTriggered'}, 'rule': {'name': 'Email reported by user as malware or phish'}, '@timestamp': 0}]
```



### O365 Exchange Suspicious Mailbox Right Delegation

Branch count: 3  
Document count: 3  
Index: geneve-ut-380

```python
event.dataset:o365.audit and event.provider:Exchange and event.action:Add-MailboxPermission and 
o365.audit.Parameters.AccessRights:(FullAccess or SendAs or SendOnBehalf) and event.outcome:success and
not user.id : "NT AUTHORITY\SYSTEM (Microsoft.Exchange.Servicehost)"
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'action': 'Add-MailboxPermission', 'outcome': 'success'}, 'o365': {'audit': {'Parameters': {'AccessRights': 'FullAccess'}}}, 'user': {'id': 'ZFy'}, '@timestamp': 0},
 {'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'action': 'Add-MailboxPermission', 'outcome': 'success'}, 'o365': {'audit': {'Parameters': {'AccessRights': 'SendAs'}}}, 'user': {'id': 'XIU'}, '@timestamp': 1},
 {'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'action': 'Add-MailboxPermission', 'outcome': 'success'}, 'o365': {'audit': {'Parameters': {'AccessRights': 'SendOnBehalf'}}}, 'user': {'id': 'tkN'}, '@timestamp': 2}]
```



### O365 Mailbox Audit Logging Bypass

Branch count: 1  
Document count: 1  
Index: geneve-ut-381

```python
event.dataset:o365.audit and event.provider:Exchange and event.action:Set-MailboxAuditBypassAssociation and event.outcome:success
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'Exchange', 'action': 'Set-MailboxAuditBypassAssociation', 'outcome': 'success'}, '@timestamp': 0}]
```



### Okta User Session Impersonation

Branch count: 1  
Document count: 1  
Index: geneve-ut-383

```python
event.dataset:okta.system and event.action:user.session.impersonation.initiate
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'user.session.impersonation.initiate'}, '@timestamp': 0}]
```



### OneDrive Malware File Upload

Branch count: 1  
Document count: 1  
Index: geneve-ut-384

```python
event.dataset:o365.audit and event.provider:OneDrive and event.code:SharePointFileOperation and event.action:FileMalwareDetected
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'OneDrive', 'code': 'SharePointFileOperation', 'action': 'FileMalwareDetected'}, '@timestamp': 0}]
```



### Outbound Scheduled Task Activity via PowerShell

Branch count: 1  
Document count: 2  
Index: geneve-ut-385

```python
sequence by host.id, process.entity_id with maxspan = 5s
 [library where dll.name : "taskschd.dll" and process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe")]
 [network where process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and destination.port == 135 and not destination.address in ("127.0.0.1", "::1")]
```

```python
[{'dll': {'name': 'taskschd.dll'}, 'process': {'name': 'pwsh.exe', 'entity_id': 'fUy'}, 'event': {'category': ['library']}, 'host': {'id': 'TvC'}, '@timestamp': 0},
 {'process': {'name': 'powershell_ise.exe', 'entity_id': 'fUy'}, 'destination': {'port': 135, 'address': 'NIo'}, 'event': {'category': ['network']}, 'host': {'id': 'TvC'}, '@timestamp': 1}]
```



### PPTP (Point to Point Tunneling Protocol) Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-386

```python
event.category:(network or network_traffic) and network.transport:tcp and destination.port:1723
```

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1723}, '@timestamp': 0},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1723}, '@timestamp': 1}]
```



### Peripheral Device Discovery

Branch count: 4  
Document count: 4  
Index: geneve-ut-388

```python
process where event.type in ("start", "process_started") and
  (process.name : "fsutil.exe" or process.pe.original_file_name == "fsutil.exe") and 
  process.args : "fsinfo" and process.args : "drives"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'fsutil.exe', 'args': ['fsinfo', 'drives']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'fsutil.exe'}, 'args': ['fsinfo', 'drives']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'fsutil.exe', 'args': ['fsinfo', 'drives']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'fsutil.exe'}, 'args': ['fsinfo', 'drives']}, '@timestamp': 3}]
```



### Permission Theft - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-389

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:token_protection_event or endgame.event_subtype_full:token_protection_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'token_protection_event'}, 'endgame': {'metadata': {'type': 'detection'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'detection'}, 'event_subtype_full': 'token_protection_event'}, '@timestamp': 1}]
```



### Permission Theft - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-390

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:token_protection_event or endgame.event_subtype_full:token_protection_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'token_protection_event'}, 'endgame': {'metadata': {'type': 'prevention'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'prevention'}, 'event_subtype_full': 'token_protection_event'}, '@timestamp': 1}]
```



### Persistence via BITS Job Notify Cmdline

Branch count: 1  
Document count: 1  
Index: geneve-ut-391

```python
process where event.type == "start" and
  process.parent.name : "svchost.exe" and process.parent.args : "BITS" and
  not process.executable :
              ("?:\\Windows\\System32\\WerFaultSecure.exe",
               "?:\\Windows\\System32\\WerFault.exe",
               "?:\\Windows\\System32\\wermgr.exe",
               "?:\\WINDOWS\\system32\\directxdatabaseupdater.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['BITS']}, 'executable': 'ZFy'}, '@timestamp': 0}]
```



### Persistence via DirectoryService Plugin Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-392

```python
event.category:file and not event.type:deletion and
  file.path:/Library/DirectoryServices/PlugIns/*.dsplug
```

```python
[{'event': {'category': ['file'], 'type': ['ZFy']}, 'file': {'path': '/Library/DirectoryServices/PlugIns/UyyFjSvILOoOHmx.dsplug'}, '@timestamp': 0}]
```



### Persistence via Docker Shortcut Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-393

```python
event.category : file and event.action : modification and 
 file.path : /Users/*/Library/Preferences/com.apple.dock.plist and 
 not process.name : (xpcproxy or cfprefsd or plutil or jamf or PlistBuddy or InstallerRemotePluginService)
```

```python
[{'event': {'category': ['file'], 'action': 'modification'}, 'file': {'path': '/Users/XIUtkNI/Library/Preferences/com.apple.dock.plist'}, 'process': {'name': 'oix'}, '@timestamp': 0}]
```



### Persistence via Folder Action Script

Branch count: 66  
Document count: 132  
Index: geneve-ut-394

```python
sequence by host.id with maxspan=5s
 [process where event.type in ("start", "process_started", "info") and process.name == "com.apple.foundation.UserScriptService"] by process.pid
 [process where event.type in ("start", "process_started") and process.name in ("osascript", "python", "tcl", "node", "perl", "ruby", "php", "bash", "csh", "zsh", "sh")] by process.parent.pid
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 4052611751}, 'host': {'id': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'osascript', 'parent': {'pid': 4052611751}}, 'host': {'id': 'ZFy'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2056249324}, 'host': {'id': 'CfU'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'python', 'parent': {'pid': 2056249324}}, 'host': {'id': 'CfU'}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 1235046169}, 'host': {'id': 'kNI'}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'tcl', 'parent': {'pid': 1235046169}}, 'host': {'id': 'kNI'}, '@timestamp': 5},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 3136644739}, 'host': {'id': 'SvI'}, '@timestamp': 6},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'node', 'parent': {'pid': 3136644739}}, 'host': {'id': 'SvI'}, '@timestamp': 7},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2094521982}, 'host': {'id': 'FlE'}, '@timestamp': 8},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'perl', 'parent': {'pid': 2094521982}}, 'host': {'id': 'FlE'}, '@timestamp': 9},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2255904345}, 'host': {'id': 'Hmx'}, '@timestamp': 10},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'ruby', 'parent': {'pid': 2255904345}}, 'host': {'id': 'Hmx'}, '@timestamp': 11},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 1305990393}, 'host': {'id': 'EEX'}, '@timestamp': 12},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'php', 'parent': {'pid': 1305990393}}, 'host': {'id': 'EEX'}, '@timestamp': 13},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 570412576}, 'host': {'id': 'OAa'}, '@timestamp': 14},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'pid': 570412576}}, 'host': {'id': 'OAa'}, '@timestamp': 15},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2040616183}, 'host': {'id': 'VRc'}, '@timestamp': 16},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'csh', 'parent': {'pid': 2040616183}}, 'host': {'id': 'VRc'}, '@timestamp': 17},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2075775563}, 'host': {'id': 'qsy'}, '@timestamp': 18},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'zsh', 'parent': {'pid': 2075775563}}, 'host': {'id': 'qsy'}, '@timestamp': 19},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 4163567191}, 'host': {'id': 'wVP'}, '@timestamp': 20},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'pid': 4163567191}}, 'host': {'id': 'wVP'}, '@timestamp': 21},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 1266848455}, 'host': {'id': 'yQD'}, '@timestamp': 22},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'osascript', 'parent': {'pid': 1266848455}}, 'host': {'id': 'yQD'}, '@timestamp': 23},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 977141374}, 'host': {'id': 'Nfm'}, '@timestamp': 24},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'python', 'parent': {'pid': 977141374}}, 'host': {'id': 'Nfm'}, '@timestamp': 25},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 3936445964}, 'host': {'id': 'Dqx'}, '@timestamp': 26},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'tcl', 'parent': {'pid': 3936445964}}, 'host': {'id': 'Dqx'}, '@timestamp': 27},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 1757971487}, 'host': {'id': 'RgU'}, '@timestamp': 28},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'node', 'parent': {'pid': 1757971487}}, 'host': {'id': 'RgU'}, '@timestamp': 29},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 1010327188}, 'host': {'id': 'Wti'}, '@timestamp': 30},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'perl', 'parent': {'pid': 1010327188}}, 'host': {'id': 'Wti'}, '@timestamp': 31},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 424121613}, 'host': {'id': 'MZO'}, '@timestamp': 32},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'ruby', 'parent': {'pid': 424121613}}, 'host': {'id': 'MZO'}, '@timestamp': 33},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 649571089}, 'host': {'id': 'Tms'}, '@timestamp': 34},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'php', 'parent': {'pid': 649571089}}, 'host': {'id': 'Tms'}, '@timestamp': 35},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 3611702861}, 'host': {'id': 'Dgz'}, '@timestamp': 36},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'pid': 3611702861}}, 'host': {'id': 'Dgz'}, '@timestamp': 37},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 4137067386}, 'host': {'id': 'WYc'}, '@timestamp': 38},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'csh', 'parent': {'pid': 4137067386}}, 'host': {'id': 'WYc'}, '@timestamp': 39},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2681595795}, 'host': {'id': 'Sjo'}, '@timestamp': 40},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'zsh', 'parent': {'pid': 2681595795}}, 'host': {'id': 'Sjo'}, '@timestamp': 41},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 3962003952}, 'host': {'id': 'UJM'}, '@timestamp': 42},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'pid': 3962003952}}, 'host': {'id': 'UJM'}, '@timestamp': 43},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 3302194335}, 'host': {'id': 'wDU'}, '@timestamp': 44},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'osascript', 'parent': {'pid': 3302194335}}, 'host': {'id': 'wDU'}, '@timestamp': 45},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 335194986}, 'host': {'id': 'zIg'}, '@timestamp': 46},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'python', 'parent': {'pid': 335194986}}, 'host': {'id': 'zIg'}, '@timestamp': 47},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 1690413928}, 'host': {'id': 'eyL'}, '@timestamp': 48},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'tcl', 'parent': {'pid': 1690413928}}, 'host': {'id': 'eyL'}, '@timestamp': 49},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2576449812}, 'host': {'id': 'moE'}, '@timestamp': 50},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'node', 'parent': {'pid': 2576449812}}, 'host': {'id': 'moE'}, '@timestamp': 51},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2553210391}, 'host': {'id': 'zmi'}, '@timestamp': 52},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'perl', 'parent': {'pid': 2553210391}}, 'host': {'id': 'zmi'}, '@timestamp': 53},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 875903594}, 'host': {'id': 'pgI'}, '@timestamp': 54},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'ruby', 'parent': {'pid': 875903594}}, 'host': {'id': 'pgI'}, '@timestamp': 55},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2886210066}, 'host': {'id': 'vKE'}, '@timestamp': 56},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'php', 'parent': {'pid': 2886210066}}, 'host': {'id': 'vKE'}, '@timestamp': 57},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 1020915657}, 'host': {'id': 'YnD'}, '@timestamp': 58},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'pid': 1020915657}}, 'host': {'id': 'YnD'}, '@timestamp': 59},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 3189187129}, 'host': {'id': 'DJL'}, '@timestamp': 60},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'csh', 'parent': {'pid': 3189187129}}, 'host': {'id': 'DJL'}, '@timestamp': 61},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 731296981}, 'host': {'id': 'xFE'}, '@timestamp': 62},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'zsh', 'parent': {'pid': 731296981}}, 'host': {'id': 'xFE'}, '@timestamp': 63},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 1747979819}, 'host': {'id': 'ocs'}, '@timestamp': 64},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'pid': 1747979819}}, 'host': {'id': 'ocs'}, '@timestamp': 65},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2331735818}, 'host': {'id': 'XzJ'}, '@timestamp': 66},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'osascript', 'parent': {'pid': 2331735818}}, 'host': {'id': 'XzJ'}, '@timestamp': 67},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2827813567}, 'host': {'id': 'Aol'}, '@timestamp': 68},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'python', 'parent': {'pid': 2827813567}}, 'host': {'id': 'Aol'}, '@timestamp': 69},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2610465613}, 'host': {'id': 'yqv'}, '@timestamp': 70},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'tcl', 'parent': {'pid': 2610465613}}, 'host': {'id': 'yqv'}, '@timestamp': 71},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2119610071}, 'host': {'id': 'LbR'}, '@timestamp': 72},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'node', 'parent': {'pid': 2119610071}}, 'host': {'id': 'LbR'}, '@timestamp': 73},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 1319961685}, 'host': {'id': 'dmT'}, '@timestamp': 74},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'perl', 'parent': {'pid': 1319961685}}, 'host': {'id': 'dmT'}, '@timestamp': 75},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 96872843}, 'host': {'id': 'rfy'}, '@timestamp': 76},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'ruby', 'parent': {'pid': 96872843}}, 'host': {'id': 'rfy'}, '@timestamp': 77},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 321018594}, 'host': {'id': 'nVT'}, '@timestamp': 78},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'php', 'parent': {'pid': 321018594}}, 'host': {'id': 'nVT'}, '@timestamp': 79},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 1484942953}, 'host': {'id': 'agT'}, '@timestamp': 80},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'pid': 1484942953}}, 'host': {'id': 'agT'}, '@timestamp': 81},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 364282236}, 'host': {'id': 'MVU'}, '@timestamp': 82},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'csh', 'parent': {'pid': 364282236}}, 'host': {'id': 'MVU'}, '@timestamp': 83},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 3793706889}, 'host': {'id': 'LwO'}, '@timestamp': 84},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'zsh', 'parent': {'pid': 3793706889}}, 'host': {'id': 'LwO'}, '@timestamp': 85},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2433853372}, 'host': {'id': 'bdC'}, '@timestamp': 86},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'pid': 2433853372}}, 'host': {'id': 'bdC'}, '@timestamp': 87},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 3097938760}, 'host': {'id': 'Ivl'}, '@timestamp': 88},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'osascript', 'parent': {'pid': 3097938760}}, 'host': {'id': 'Ivl'}, '@timestamp': 89},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 4017982120}, 'host': {'id': 'SsF'}, '@timestamp': 90},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'python', 'parent': {'pid': 4017982120}}, 'host': {'id': 'SsF'}, '@timestamp': 91},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 3187763082}, 'host': {'id': 'uAM'}, '@timestamp': 92},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'tcl', 'parent': {'pid': 3187763082}}, 'host': {'id': 'uAM'}, '@timestamp': 93},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2039378787}, 'host': {'id': 'Pmm'}, '@timestamp': 94},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'node', 'parent': {'pid': 2039378787}}, 'host': {'id': 'Pmm'}, '@timestamp': 95},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 846858696}, 'host': {'id': 'kOO'}, '@timestamp': 96},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'perl', 'parent': {'pid': 846858696}}, 'host': {'id': 'kOO'}, '@timestamp': 97},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 1687397388}, 'host': {'id': 'ebK'}, '@timestamp': 98},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'ruby', 'parent': {'pid': 1687397388}}, 'host': {'id': 'ebK'}, '@timestamp': 99},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2122179744}, 'host': {'id': 'hBC'}, '@timestamp': 100},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'php', 'parent': {'pid': 2122179744}}, 'host': {'id': 'hBC'}, '@timestamp': 101},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2937055128}, 'host': {'id': 'dJs'}, '@timestamp': 102},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'pid': 2937055128}}, 'host': {'id': 'dJs'}, '@timestamp': 103},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 1072533441}, 'host': {'id': 'dyQ'}, '@timestamp': 104},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'csh', 'parent': {'pid': 1072533441}}, 'host': {'id': 'dyQ'}, '@timestamp': 105},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2451257571}, 'host': {'id': 'qhw'}, '@timestamp': 106},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'zsh', 'parent': {'pid': 2451257571}}, 'host': {'id': 'qhw'}, '@timestamp': 107},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2685579375}, 'host': {'id': 'gZp'}, '@timestamp': 108},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'pid': 2685579375}}, 'host': {'id': 'gZp'}, '@timestamp': 109},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2215758242}, 'host': {'id': 'QRL'}, '@timestamp': 110},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'osascript', 'parent': {'pid': 2215758242}}, 'host': {'id': 'QRL'}, '@timestamp': 111},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 3594559144}, 'host': {'id': 'dbF'}, '@timestamp': 112},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'python', 'parent': {'pid': 3594559144}}, 'host': {'id': 'dbF'}, '@timestamp': 113},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2806789095}, 'host': {'id': 'yvI'}, '@timestamp': 114},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'tcl', 'parent': {'pid': 2806789095}}, 'host': {'id': 'yvI'}, '@timestamp': 115},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 3446719455}, 'host': {'id': 'iLn'}, '@timestamp': 116},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'node', 'parent': {'pid': 3446719455}}, 'host': {'id': 'iLn'}, '@timestamp': 117},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 3559344598}, 'host': {'id': 'nGb'}, '@timestamp': 118},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'perl', 'parent': {'pid': 3559344598}}, 'host': {'id': 'nGb'}, '@timestamp': 119},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2580185788}, 'host': {'id': 'Ufu'}, '@timestamp': 120},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'ruby', 'parent': {'pid': 2580185788}}, 'host': {'id': 'Ufu'}, '@timestamp': 121},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 2468689419}, 'host': {'id': 'NMV'}, '@timestamp': 122},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'php', 'parent': {'pid': 2468689419}}, 'host': {'id': 'NMV'}, '@timestamp': 123},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 4070540704}, 'host': {'id': 'RaQ'}, '@timestamp': 124},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'bash', 'parent': {'pid': 4070540704}}, 'host': {'id': 'RaQ'}, '@timestamp': 125},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 4273915087}, 'host': {'id': 'dVl'}, '@timestamp': 126},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'csh', 'parent': {'pid': 4273915087}}, 'host': {'id': 'dVl'}, '@timestamp': 127},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 3093363983}, 'host': {'id': 'gyX'}, '@timestamp': 128},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'zsh', 'parent': {'pid': 3093363983}}, 'host': {'id': 'gyX'}, '@timestamp': 129},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'com.apple.foundation.UserScriptService', 'pid': 1824210849}, 'host': {'id': 'MZn'}, '@timestamp': 130},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'sh', 'parent': {'pid': 1824210849}}, 'host': {'id': 'MZn'}, '@timestamp': 131}]
```



### Persistence via Hidden Run Key Detected

Branch count: 1  
Document count: 1  
Index: geneve-ut-395

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

```python
[{'registry': {'path': 'HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\'}, 'event': {'category': ['registry']}, '@timestamp': 0}]
```



### Persistence via KDE AutoStart Script or Desktop File Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-396

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
    )
```

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'extension': 'sh', 'path': '/home/UyyFjSvILOoOHmx/.kde/Autostart/EEXpWqNVR'}, '@timestamp': 0},
 {'event': {'type': ['cym'], 'category': ['file']}, 'file': {'extension': 'desktop', 'path': '/root/.local/share/autostart/zKNyyQDpUE'}, '@timestamp': 1}]
```



### Persistence via Kernel Module Modification

Branch count: 8  
Document count: 8  
Index: geneve-ut-397

```python
event.category:process and event.type:(start or process_started) and process.name:(insmod or kmod or modprobe or rmod)
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'insmod'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'kmod'}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'modprobe'}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'rmod'}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'insmod'}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'kmod'}, '@timestamp': 5},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'modprobe'}, '@timestamp': 6},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'rmod'}, '@timestamp': 7}]
```



### Persistence via Microsoft Office AddIns

Branch count: 1  
Document count: 1  
Index: geneve-ut-399

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

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'extension': 'xlam', 'path': 'C:\\Users\\Ut\\AppData\\Roaming\\Microsoft\\Word\\Startup\\yFjS'}, '@timestamp': 0}]
```



### Persistence via Microsoft Outlook VBA

Branch count: 1  
Document count: 1  
Index: geneve-ut-400

```python
file where event.type != "deletion" and
 file.path : "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Outlook\\VbaProject.OTM"
```

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'path': 'C:\\Users\\UyyFjSvILOoOHmx\\AppData\\Roaming\\Microsoft\\Outlook\\VbaProject.OTM'}, '@timestamp': 0}]
```



### Persistence via Scheduled Job Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-401

```python
file where event.type != "deletion" and
 file.path : "?:\\Windows\\Tasks\\*" and file.extension : "job"
```

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'path': 'y:\\Windows\\Tasks\\kNIoixTF', 'extension': 'job'}, '@timestamp': 0}]
```



### Persistence via TelemetryController Scheduled Task Hijack

Branch count: 2  
Document count: 2  
Index: geneve-ut-402

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'CompatTelRunner.exe'}, 'args': ['-cv*'], 'name': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'CompatTelRunner.exe'}, 'args': ['-cv*'], 'name': 'XIU'}, '@timestamp': 1}]
```



### Persistence via Update Orchestrator Service Hijack

Branch count: 1  
Document count: 1  
Index: geneve-ut-403

```python
process where event.type == "start" and
  process.parent.executable : "C:\\Windows\\System32\\svchost.exe" and
  process.parent.args : "UsoSvc" and
  not process.executable :
         (
          "C:\\Windows\\System32\\UsoClient.exe",
          "C:\\Windows\\System32\\MusNotification.exe",
          "C:\\Windows\\System32\\MusNotificationUx.exe",
          "C:\\Windows\\System32\\MusNotifyIcon.exe",
          "C:\\Windows\\System32\\WerFault.exe",
          "C:\\Windows\\System32\\WerMgr.exe"
          )
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'executable': 'C:\\Windows\\System32\\svchost.exe', 'args': ['UsoSvc']}, 'executable': 'ZFy'}, '@timestamp': 0}]
```



### Persistence via WMI Event Subscription

Branch count: 4  
Document count: 4  
Index: geneve-ut-404

```python
process where event.type in ("start", "process_started") and
  (process.name : "wmic.exe" or process.pe.original_file_name == "wmic.exe") and
  process.args : "create" and
  process.args : ("ActiveScriptEventConsumer", "CommandLineEventConsumer")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'wmic.exe', 'args': ['create', 'ActiveScriptEventConsumer', 'CommandLineEventConsumer']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'wmic.exe'}, 'args': ['create', 'ActiveScriptEventConsumer', 'CommandLineEventConsumer']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'wmic.exe', 'args': ['create', 'ActiveScriptEventConsumer', 'CommandLineEventConsumer']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'wmic.exe'}, 'args': ['create', 'ActiveScriptEventConsumer', 'CommandLineEventConsumer']}, '@timestamp': 3}]
```



### Persistent Scripts in the Startup Directory

Branch count: 2  
Document count: 2  
Index: geneve-ut-406

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

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'user': {'domain': 'XIU'}, 'file': {'path': 'C:\\kNIoixTF\\Programs\\Startup\\oOHm.lnk'}, 'process': {'name': 'wscript.exe'}, '@timestamp': 0},
 {'file': {'path': 'C:\\EEXpWqNVR\\Programs\\Startup\\F.wsf'}, 'event': {'category': ['file']}, '@timestamp': 1}]
```



### Port Forwarding Rule Addition

Branch count: 1  
Document count: 1  
Index: geneve-ut-407

```python
registry where registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Services\\PortProxy\\v4tov4\\*"
```

```python
[{'registry': {'path': 'HKLM\\SYSTEM\\XIUtkNIControlSetSvILO\\Services\\PortProxy\\v4tov4\\Ezswu'}, 'event': {'category': ['registry']}, '@timestamp': 0}]
```



### Possible Consent Grant Attack via Azure-Registered Application

Branch count: 18  
Document count: 18  
Index: geneve-ut-408

```python
event.dataset:(azure.activitylogs or azure.auditlogs or o365.audit) and 
  (
    azure.activitylogs.operation_name:"Consent to application" or
    azure.auditlogs.operation_name:"Consent to application" or
    o365.audit.Operation:"Consent to application."
  ) and
  event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'Consent to application'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'Consent to application'}}, '@timestamp': 1},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'operation_name': 'Consent to application'}}, '@timestamp': 2},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'operation_name': 'Consent to application'}}, '@timestamp': 3},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'Success'}, 'o365': {'audit': {'Operation': 'Consent to application.'}}, '@timestamp': 4},
 {'event': {'dataset': 'azure.activitylogs', 'outcome': 'success'}, 'o365': {'audit': {'Operation': 'Consent to application.'}}, '@timestamp': 5},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'Consent to application'}}, '@timestamp': 6},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'Consent to application'}}, '@timestamp': 7},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'operation_name': 'Consent to application'}}, '@timestamp': 8},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'operation_name': 'Consent to application'}}, '@timestamp': 9},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'o365': {'audit': {'Operation': 'Consent to application.'}}, '@timestamp': 10},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'o365': {'audit': {'Operation': 'Consent to application.'}}, '@timestamp': 11},
 {'event': {'dataset': 'o365.audit', 'outcome': 'Success'}, 'azure': {'activitylogs': {'operation_name': 'Consent to application'}}, '@timestamp': 12},
 {'event': {'dataset': 'o365.audit', 'outcome': 'success'}, 'azure': {'activitylogs': {'operation_name': 'Consent to application'}}, '@timestamp': 13},
 {'event': {'dataset': 'o365.audit', 'outcome': 'Success'}, 'azure': {'auditlogs': {'operation_name': 'Consent to application'}}, '@timestamp': 14},
 {'event': {'dataset': 'o365.audit', 'outcome': 'success'}, 'azure': {'auditlogs': {'operation_name': 'Consent to application'}}, '@timestamp': 15},
 {'event': {'dataset': 'o365.audit', 'outcome': 'Success'}, 'o365': {'audit': {'Operation': 'Consent to application.'}}, '@timestamp': 16},
 {'event': {'dataset': 'o365.audit', 'outcome': 'success'}, 'o365': {'audit': {'Operation': 'Consent to application.'}}, '@timestamp': 17}]
```



### Possible Okta DoS Attack

Branch count: 4  
Document count: 4  
Index: geneve-ut-410

```python
event.dataset:okta.system and event.action:(application.integration.rate_limit_exceeded or system.org.rate_limit.warning or system.org.rate_limit.violation or core.concurrency.org.limit.violation)
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'application.integration.rate_limit_exceeded'}, '@timestamp': 0},
 {'event': {'dataset': 'okta.system', 'action': 'system.org.rate_limit.warning'}, '@timestamp': 1},
 {'event': {'dataset': 'okta.system', 'action': 'system.org.rate_limit.violation'}, '@timestamp': 2},
 {'event': {'dataset': 'okta.system', 'action': 'core.concurrency.org.limit.violation'}, '@timestamp': 3}]
```



### Potential Abuse of Repeated MFA Push Notifications

Branch count: 1  
Document count: 3  
Index: geneve-ut-411

```python
sequence by user.email with maxspan=10m
  [any where event.module == "okta" and event.action == "user.mfa.okta_verify.deny_push"]
  [any where event.module == "okta" and event.action == "user.mfa.okta_verify.deny_push"]
  [any where event.module == "okta" and event.action == "user.authentication.sso"]
```

```python
[{'event': {'module': 'okta', 'action': 'user.mfa.okta_verify.deny_push'}, 'user': {'email': 'ZFy'}, '@timestamp': 0},
 {'event': {'module': 'okta', 'action': 'user.mfa.okta_verify.deny_push'}, 'user': {'email': 'ZFy'}, '@timestamp': 1},
 {'event': {'module': 'okta', 'action': 'user.authentication.sso'}, 'user': {'email': 'ZFy'}, '@timestamp': 2}]
```



### Potential Application Shimming via Sdbinst

Branch count: 2  
Document count: 2  
Index: geneve-ut-413

```python
process where event.type in ("start", "process_started") and process.name : "sdbinst.exe"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sdbinst.exe'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'sdbinst.exe'}, '@timestamp': 1}]
```



### Potential Command and Control via Internet Explorer

Branch count: 1  
Document count: 3  
Index: geneve-ut-414

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

```python
[{'dll': {'name': 'IEProxy.dll'}, 'process': {'name': 'rundll32.exe'}, 'event': {'category': ['library']}, 'host': {'id': 'vCf'}, 'user': {'name': 'Uyy'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'iexplore.exe', 'args': ['-Embedding']}}, 'host': {'id': 'vCf'}, 'user': {'name': 'Uyy'}, '@timestamp': 1},
 {'network': {'protocol': 'dns'}, 'process': {'name': 'iexplore.exe'}, 'dns': {'question': {'name': 'FjS'}}, 'event': {'category': ['network']}, 'host': {'id': 'vCf'}, 'user': {'name': 'Uyy'}, '@timestamp': 2}]
```



### Potential Cookies Theft via Browser Debugging

Branch count: 21  
Document count: 21  
Index: geneve-ut-415

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'Microsoft Edge', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'chrome.exe', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'Google Chrome', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'google-chrome-stable', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'google-chrome-beta', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'google-chrome', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 5},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'msedge.exe', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'Microsoft Edge', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 7},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'chrome.exe', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 8},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'Google Chrome', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 9},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'google-chrome-stable', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 10},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'google-chrome-beta', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 11},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'google-chrome', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 12},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'msedge.exe', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 13},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'Microsoft Edge', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 14},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'chrome.exe', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 15},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'Google Chrome', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 16},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'google-chrome-stable', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 17},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'google-chrome-beta', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 18},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'google-chrome', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 19},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'msedge.exe', 'args': ['--remote-debugging-port=*', '--remote-debugging-targets=*', '--remote-debugging-pipe=*', '--user-data-dir=*']}, '@timestamp': 20}]
```



### Potential Credential Access via DCSync

Branch count: 1  
Document count: 1  
Index: geneve-ut-416

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

```python
[{'event': {'action': 'Directory Service Access', 'code': '4662'}, 'winlog': {'event_data': {'Properties': 'yXIUtkNIoixTFlDS-Replication-Get-Changes-AllOHmxBnLeOA', 'AccessMask': '0x100', 'SubjectUserName': 'aga'}}, '@timestamp': 0}]
```



### Potential Credential Access via DuplicateHandle in LSASS

Branch count: 1  
Document count: 1  
Index: geneve-ut-417

```python
process where event.code == "10" and 

 /* LSASS requesting DuplicateHandle access right to another process */
 process.name : "lsass.exe" and winlog.event_data.GrantedAccess == "0x40" and

 /* call is coming from an unknown executable region */
 winlog.event_data.CallTrace : "*UNKNOWN*"
```

```python
[{'event': {'code': '10', 'category': ['process']}, 'process': {'name': 'lsass.exe'}, 'winlog': {'event_data': {'GrantedAccess': '0x40', 'CallTrace': 'XIUtkNIUNKNOWNSvILO'}}, '@timestamp': 0}]
```



### Potential Credential Access via LSASS Memory Dump

Branch count: 1  
Document count: 1  
Index: geneve-ut-418

```python
process where event.code == "10" and
  winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe" and

   /* DLLs exporting MiniDumpWriteDump API to create an lsass mdmp*/
  winlog.event_data.CallTrace : ("*dbghelp*", "*dbgcore*") and

   /* case of lsass crashing */
  not process.executable : ("?:\\Windows\\System32\\WerFault.exe", "?:\\Windows\\System32\\WerFaultSecure.exe")
```

```python
[{'event': {'code': '10', 'category': ['process']}, 'winlog': {'event_data': {'TargetImage': 'A:\\WINDOWS\\system32\\lsass.exe', 'CallTrace': 'UyyFjSvILOoOHmxdbgcoreEEXpWqNVR'}}, 'process': {'executable': 'cym'}, '@timestamp': 0}]
```



### Potential Credential Access via Renamed COM+ Services DLL

Branch count: 2  
Document count: 4  
Index: geneve-ut-419

```python
sequence by process.entity_id with maxspan=1m
 [process where event.category == "process" and
    process.name : "rundll32.exe"]
 [process where event.category == "process" and event.dataset : "windows.sysmon_operational" and event.code == "7" and
   (file.pe.original_file_name : "COMSVCS.DLL" or file.pe.imphash : "EADBCCBB324829ACB5F2BBE87E5549A8") and
    /* renamed COMSVCS */
    not file.name : "COMSVCS.DLL"]
```

```python
[{'event': {'category': ['process', 'process']}, 'process': {'name': 'rundll32.exe', 'entity_id': 'ZFy'}, '@timestamp': 0},
 {'event': {'category': ['process', 'process'], 'dataset': 'windows.sysmon_operational', 'code': '7'}, 'file': {'pe': {'original_file_name': 'COMSVCS.DLL'}, 'name': 'XIU'}, 'process': {'entity_id': 'ZFy'}, '@timestamp': 1},
 {'event': {'category': ['process', 'process']}, 'process': {'name': 'rundll32.exe', 'entity_id': 'tkN'}, '@timestamp': 2},
 {'event': {'category': ['process', 'process'], 'dataset': 'windows.sysmon_operational', 'code': '7'}, 'file': {'pe': {'imphash': 'EADBCCBB324829ACB5F2BBE87E5549A8'}, 'name': 'Ioi'}, 'process': {'entity_id': 'tkN'}, '@timestamp': 3}]
```



### Potential DLL Side-Loading via Microsoft Antimalware Service Executable

Branch count: 2  
Document count: 2  
Index: geneve-ut-421

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'MsMpEng.exe'}, 'name': 'ZFy'}, '@timestamp': 0},
 {'process': {'name': 'MsMpEng.exe', 'executable': 'XIU'}, 'event': {'category': ['process']}, '@timestamp': 1}]
```



### Potential DLL SideLoading via Trusted Microsoft Programs

Branch count: 4  
Document count: 4  
Index: geneve-ut-422

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'WinWord.exe'}, 'name': 'ZFy', 'executable': 'XIU'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'EXPLORER.EXE'}, 'name': 'tkN', 'executable': 'Ioi'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'w3wp.exe'}, 'name': 'xTF', 'executable': 'lEz'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'DISM.EXE'}, 'name': 'swu', 'executable': 'EEX'}, '@timestamp': 3}]
```



### Potential DNS Tunneling via Iodine

Branch count: 4  
Document count: 4  
Index: geneve-ut-423

```python
event.category:process and event.type:(start or process_started) and process.name:(iodine or iodined)
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'iodine'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'iodined'}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'iodine'}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'iodined'}, '@timestamp': 3}]
```



### Potential Disabling of SELinux

Branch count: 2  
Document count: 2  
Index: geneve-ut-425

```python
event.category:process and event.type:(start or process_started) and process.name:setenforce and process.args:0
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'setenforce', 'args': [0]}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'setenforce', 'args': [0]}, '@timestamp': 1}]
```



### Potential Evasion via Filter Manager

Branch count: 2  
Document count: 2  
Index: geneve-ut-426

```python
process where event.type in ("start", "process_started") and 
 process.name : "fltMC.exe" and process.args : "unload"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'fltMC.exe', 'args': ['unload']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'fltMC.exe', 'args': ['unload']}, '@timestamp': 1}]
```



### Potential JAVA/JNDI Exploitation Attempt

Branch count: 5  
Document count: 10  
Index: geneve-ut-428

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

```python
[{'event': {'action': 'connection_attempted', 'category': ['network']}, 'process': {'name': 'java', 'pid': 4052611751}, 'destination': {'port': 1389}, 'host': {'id': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'java', 'pid': 4052611751}, 'name': 'sh'}, 'host': {'id': 'ZFy'}, '@timestamp': 1},
 {'event': {'action': 'connection_attempted', 'category': ['network']}, 'process': {'name': 'java', 'pid': 906141214}, 'destination': {'port': 389}, 'host': {'id': 'IUt'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'java', 'pid': 906141214}, 'name': 'rubyFjSvILOoOHmxB'}, 'host': {'id': 'IUt'}, '@timestamp': 3},
 {'event': {'action': 'connection_attempted', 'category': ['network']}, 'process': {'name': 'java', 'pid': 3305599734}, 'destination': {'port': 1099}, 'host': {'id': 'nLe'}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'java', 'pid': 3305599734}, 'name': 'sh'}, 'host': {'id': 'nLe'}, '@timestamp': 5},
 {'event': {'action': 'connection_attempted', 'category': ['network']}, 'process': {'name': 'java', 'pid': 3588492870}, 'destination': {'port': 53}, 'host': {'id': 'qNV'}, '@timestamp': 6},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'java', 'pid': 3588492870}, 'name': 'dash'}, 'host': {'id': 'qNV'}, '@timestamp': 7},
 {'event': {'action': 'connection_attempted', 'category': ['network']}, 'process': {'name': 'java', 'pid': 2543124572}, 'destination': {'port': 5353}, 'host': {'id': 'cym'}, '@timestamp': 8},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'java', 'pid': 2543124572}, 'name': 'rubyzKNyyQDpUE'}, 'host': {'id': 'cym'}, '@timestamp': 9}]
```



### Potential Kerberos Attack via Bifrost

Branch count: 6  
Document count: 6  
Index: geneve-ut-429

```python
event.category:process and event.type:start and 
 process.args:("-action" and ("-kerberoast" or askhash or asktgs or asktgt or s4u or ("-ticket" and ptt) or (dump and (tickets or keytab))))
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['-action', '-kerberoast']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['-action', 'askhash']}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['-action', 'asktgs']}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['-action', 'asktgt']}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['-action', 's4u']}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['-action', '-ticket', 'ptt']}, '@timestamp': 5}]
```



### Potential LSA Authentication Package Abuse

Branch count: 1  
Document count: 1  
Index: geneve-ut-430

```python
registry where event.type == "change" and
  registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Authentication Packages" and
  /* exclude SYSTEM SID - look for changes by non-SYSTEM user */
  not user.id : "S-1-5-18"
```

```python
[{'event': {'type': ['change'], 'category': ['registry']}, 'registry': {'path': 'HKLM\\SYSTEM\\XIUtkNIControlSetSvILO\\Control\\Lsa\\Authentication Packages'}, 'user': {'id': 'oOH'}, '@timestamp': 0}]
```



### Potential LSASS Clone Creation via PssCaptureSnapShot

Branch count: 1  
Document count: 1  
Index: geneve-ut-431

```python
process where event.code:"4688" and
  process.executable : "?:\\Windows\\System32\\lsass.exe" and
  process.parent.executable : "?:\\Windows\\System32\\lsass.exe"
```

```python
[{'event': {'code': '4688', 'category': ['process']}, 'process': {'executable': 'A:\\Windows\\System32\\lsass.exe', 'parent': {'executable': 'y:\\Windows\\System32\\lsass.exe'}}, '@timestamp': 0}]
```



### Potential Microsoft Office Sandbox Evasion

Branch count: 1  
Document count: 1  
Index: geneve-ut-433

```python
event.category:file and not event.type:deletion and file.name:~$*.zip
```

```python
[{'event': {'category': ['file'], 'type': ['ZFy']}, 'file': {'name': '~$UyyFjSvILOoOHmx.zip'}, '@timestamp': 0}]
```



### Potential Modification of Accessibility Binaries

Branch count: 3  
Document count: 3  
Index: geneve-ut-434

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'winlogon.exe'}, 'args': ['C:\\Windows\\System32\\osk.exe', 'C:\\Windows\\System32\\Magnify.exe', 'C:\\Windows\\System32\\Narrator.exe', 'C:\\Windows\\System32\\Sethc.exe', 'utilman.exe', 'ATBroker.exe', 'DisplaySwitch.exe', 'sethc.exe'], 'pe': {'original_file_name': 'vCf'}}, 'user': {'name': 'SYSTEM'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'winlogon.exe'}, 'args': ['C:\\Windows\\System32\\osk.exe', 'C:\\Windows\\System32\\Magnify.exe', 'C:\\Windows\\System32\\Narrator.exe', 'C:\\Windows\\System32\\Sethc.exe', 'utilman.exe', 'ATBroker.exe', 'DisplaySwitch.exe', 'sethc.exe'], 'pe': {'original_file_name': 'yyF'}}, 'user': {'name': 'SYSTEM'}, '@timestamp': 1},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'parent': {'name': 'Utilman.exe'}, 'args': ['C:\\Windows\\System32\\osk.exe', 'C:\\Windows\\System32\\Magnify.exe', 'C:\\Windows\\System32\\Narrator.exe', 'C:\\Windows\\System32\\Sethc.exe', 'utilman.exe', 'ATBroker.exe', 'DisplaySwitch.exe', 'sethc.exe'], 'pe': {'original_file_name': 'oix'}}, 'user': {'name': 'SYSTEM'}, '@timestamp': 2}]
```



### Potential OpenSSH Backdoor Logging Activity

Branch count: 3  
Document count: 3  
Index: geneve-ut-435

```python
file where event.type == "change" and process.executable : ("/usr/sbin/sshd", "/usr/bin/ssh") and
  (
    file.name : (".*", "~*") or
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

```python
[{'event': {'type': ['change'], 'category': ['file']}, 'process': {'executable': '/usr/sbin/sshd'}, 'file': {'name': '~IUtkNIoix'}, '@timestamp': 0},
 {'event': {'type': ['change'], 'category': ['file']}, 'process': {'executable': '/usr/bin/ssh'}, 'file': {'extension': '8'}, '@timestamp': 1},
 {'event': {'type': ['change'], 'category': ['file']}, 'process': {'executable': '/usr/sbin/sshd'}, 'file': {'path': '/var/run/udevd.pid'}, '@timestamp': 2}]
```



### Potential Persistence via Atom Init Script Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-437

```python
event.category:"file" and not event.type:"deletion" and
 file.path:/Users/*/.atom/init.coffee and not process.name:(Atom or xpcproxy) and not user.name:root
```

```python
[{'event': {'category': ['file'], 'type': ['ZFy']}, 'file': {'path': '/Users/UyyFjSvILOoOHmx/.atom/init.coffee'}, 'process': {'name': 'BnL'}, 'user': {'name': 'eOA'}, '@timestamp': 0}]
```



### Potential Persistence via Cron Job

Branch count: 6  
Document count: 6  
Index: geneve-ut-438

```python
event.category:process and event.type:(start or process_started or info) and
  not user.name:root and
  ((process.name:crontab and not process.args:("-l" or "-r" or "-e" or "-help" or "-h")) or
    (process.parent.name:cron and not process.name:"running job" and
       not process.executable:(/Applications/Docker.app/Contents/Resources/bin/docker or
                               /usr/bin/killall or
                               /usr/sbin/sendmail or
                               /usr/bin/env or
                               /usr/bin/timeshift or
                               /bin/rm)))
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'user': {'name': 'ZFy'}, 'process': {'name': 'crontab', 'args': ['XIU']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'user': {'name': 'tkN'}, 'process': {'parent': {'name': 'cron'}, 'name': 'Ioi', 'executable': 'xTF'}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'user': {'name': 'lEz'}, 'process': {'name': 'crontab', 'args': ['swu']}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'user': {'name': 'EEX'}, 'process': {'parent': {'name': 'cron'}, 'name': 'pWq', 'executable': 'NVR'}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['info']}, 'user': {'name': 'cym'}, 'process': {'name': 'crontab', 'args': ['EEw']}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['info']}, 'user': {'name': 'VPY'}, 'process': {'parent': {'name': 'cron'}, 'name': 'MGz', 'executable': 'Nfm'}, '@timestamp': 5}]
```



### Potential Persistence via Login Hook

Branch count: 1  
Document count: 1  
Index: geneve-ut-439

```python
event.category:"file" and not event.type:"deletion" and
 file.name:"com.apple.loginwindow.plist" and
 process.name:(* and not (systemmigrationd or DesktopServicesHelper or diskmanagementd or rsync or launchd or cfprefsd or xpcproxy or ManagedClient or MCXCompositor))
```

```python
[{'event': {'category': ['file'], 'type': ['ZFy']}, 'file': {'name': 'com.apple.loginwindow.plist'}, 'process': {'name': 'XIU'}, '@timestamp': 0}]
```



### Potential Persistence via Periodic Tasks

Branch count: 3  
Document count: 3  
Index: geneve-ut-440

```python
event.category:"file" and not event.type:"deletion" and
 file.path:(/private/etc/periodic/* or /private/etc/defaults/periodic.conf or /private/etc/periodic.conf)
```

```python
[{'event': {'category': ['file'], 'type': ['ZFy']}, 'file': {'path': '/private/etc/periodic/UyyFjSvILOoOHmx'}, '@timestamp': 0},
 {'event': {'category': ['file'], 'type': ['BnL']}, 'file': {'path': '/private/etc/defaults/periodic.conf'}, '@timestamp': 1},
 {'event': {'category': ['file'], 'type': ['eOA']}, 'file': {'path': '/private/etc/periodic.conf'}, '@timestamp': 2}]
```



### Potential PrintNightmare File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-444

```python
/* This rule is compatible with both Sysmon and Elastic Endpoint */

file where process.name : "spoolsv.exe" and 
 file.name : ("kernelbase.dll", "ntdll.dll", "kernel32.dll", "winhttp.dll", "user32.dll") and
 file.path : "?:\\Windows\\System32\\spool\\drivers\\x64\\3\\*"
```

```python
[{'process': {'name': 'spoolsv.exe'}, 'file': {'name': 'winhttp.dll', 'path': 'A:\\Windows\\System32\\spool\\drivers\\x64\\3\\IUtkNIoix'}, 'event': {'category': ['file']}, '@timestamp': 0}]
```



### Potential Privacy Control Bypass via TCCDB Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-446

```python
process where event.type in ("start", "process_started") and process.name : "sqlite*" and 
 process.args : "/*/Application Support/com.apple.TCC/TCC.db"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sqliteXIUtkNI', 'args': ['/*/Application Support/com.apple.TCC/TCC.db']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'sqliteixTFlEzswuEEXp', 'args': ['/*/Application Support/com.apple.TCC/TCC.db']}, '@timestamp': 1}]
```



### Potential Privilege Escalation via InstallerFileTakeOver

Branch count: 4  
Document count: 4  
Index: geneve-ut-447

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'Ext': {'token': {'integrity_level_name': 'System'}}, 'name': 'elevation_service.exe', 'pe': {'original_file_name': 'ZFy'}}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'Ext': {'token': {'integrity_level_name': 'System'}}, 'parent': {'name': 'elevation_service.exe'}, 'name': 'rundll32.exe'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'winlog': {'event_data': {'IntegrityLevel': 'System'}}, 'process': {'name': 'elevation_service.exe', 'pe': {'original_file_name': 'IUt'}}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'winlog': {'event_data': {'IntegrityLevel': 'System'}}, 'process': {'parent': {'name': 'elevation_service.exe'}, 'name': 'cmd.exe'}, '@timestamp': 3}]
```



### Potential Privilege Escalation via PKEXEC

Branch count: 1  
Document count: 1  
Index: geneve-ut-448

```python
file where file.path : "/*GCONV_PATH*"
```

```python
[{'file': {'path': '/XIUtkNIGCONV_PATHSvILO'}, 'event': {'category': ['file']}, '@timestamp': 0}]
```



### Potential Privilege Escalation via Sudoers File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-449

```python
event.category:process and event.type:start and process.args:(echo and *NOPASSWD*ALL*)
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['*NOPASSWD*ALL*', 'echo']}, '@timestamp': 0}]
```



### Potential Privileged Escalation via SamAccountName Spoofing

Branch count: 1  
Document count: 1  
Index: geneve-ut-450

```python
iam where event.action == "renamed-user-account" and
  /* machine account name renamed to user like account name */
  winlog.event_data.OldTargetUserName : "*$" and not winlog.event_data.NewTargetUserName : "*$"
```

```python
[{'event': {'action': 'renamed-user-account', 'category': ['iam']}, 'winlog': {'event_data': {'OldTargetUserName': 'XIUtkNI$', 'NewTargetUserName': 'oix'}}, '@timestamp': 0}]
```



### Potential Process Herpaderping Attempt

Branch count: 1  
Document count: 2  
Index: geneve-ut-451

```python
sequence with maxspan=5s
   [process where event.type == "start" and not process.parent.executable : "C:\\Windows\\SoftwareDistribution\\*.exe"] by host.id, process.executable, process.parent.entity_id
   [file where event.type == "change" and event.action == "overwrite" and file.extension == "exe"] by host.id, file.path, process.entity_id
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'executable': 'ZFy', 'entity_id': 'Ioi'}, 'executable': 'tkN'}, 'host': {'id': 'XIU'}, '@timestamp': 0},
 {'event': {'type': ['change'], 'action': 'overwrite', 'category': ['file']}, 'file': {'extension': 'exe', 'path': 'tkN'}, 'host': {'id': 'XIU'}, 'process': {'entity_id': 'Ioi'}, '@timestamp': 1}]
```



### Potential Protocol Tunneling via EarthWorm

Branch count: 1  
Document count: 1  
Index: geneve-ut-453

```python
process where event.type == "start" and
 process.args : "-s" and process.args : "-d" and process.args : "rssocks"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['-s', '-d', 'rssocks']}, '@timestamp': 0}]
```



### Potential Remote Desktop Shadowing Activity

Branch count: 3  
Document count: 3  
Index: geneve-ut-455

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

```python
[{'event': {'category': ['registry']}, 'registry': {'path': 'HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\Shadow'}, '@timestamp': 0},
 {'event': {'category': ['process']}, 'process': {'name': 'RdpSaUacHelper.exe', 'parent': {'name': 'svchost.exe'}}, '@timestamp': 1},
 {'process': {'pe': {'original_file_name': 'mstsc.exe'}, 'args': ['/shadow:*']}, '@timestamp': 2}]
```



### Potential Remote Desktop Tunneling Detected

Branch count: 2  
Document count: 2  
Index: geneve-ut-456

```python
process where event.type in ("start", "process_started") and
  /* RDP port and usual SSH tunneling related switches in command line */
  process.args : "*:3389" and
  process.args : ("-L", "-P", "-R", "-pw", "-ssh")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['*:3389', '-L', '-P', '-R', '-pw', '-ssh']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'args': ['*:3389', '-L', '-P', '-R', '-pw', '-ssh']}, '@timestamp': 1}]
```



### Potential Reverse Shell Activity via Terminal

Branch count: 10  
Document count: 10  
Index: geneve-ut-457

```python
process where event.type in ("start", "process_started") and
  process.name in ("sh", "bash", "zsh", "dash", "zmodload") and
  process.args:("*/dev/tcp/*", "*/dev/udp/*", "zsh/net/tcp", "zsh/net/udp")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'args': ['*/dev/tcp/*', '*/dev/udp/*', 'zsh/net/tcp', 'zsh/net/udp']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'bash', 'args': ['*/dev/tcp/*', '*/dev/udp/*', 'zsh/net/tcp', 'zsh/net/udp']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'zsh', 'args': ['*/dev/tcp/*', '*/dev/udp/*', 'zsh/net/tcp', 'zsh/net/udp']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'dash', 'args': ['*/dev/tcp/*', '*/dev/udp/*', 'zsh/net/tcp', 'zsh/net/udp']}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'zmodload', 'args': ['*/dev/tcp/*', '*/dev/udp/*', 'zsh/net/tcp', 'zsh/net/udp']}, '@timestamp': 4},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'sh', 'args': ['*/dev/tcp/*', '*/dev/udp/*', 'zsh/net/tcp', 'zsh/net/udp']}, '@timestamp': 5},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'bash', 'args': ['*/dev/tcp/*', '*/dev/udp/*', 'zsh/net/tcp', 'zsh/net/udp']}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'zsh', 'args': ['*/dev/tcp/*', '*/dev/udp/*', 'zsh/net/tcp', 'zsh/net/udp']}, '@timestamp': 7},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'dash', 'args': ['*/dev/tcp/*', '*/dev/udp/*', 'zsh/net/tcp', 'zsh/net/udp']}, '@timestamp': 8},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'zmodload', 'args': ['*/dev/tcp/*', '*/dev/udp/*', 'zsh/net/tcp', 'zsh/net/udp']}, '@timestamp': 9}]
```



### Potential Secure File Deletion via SDelete Utility

Branch count: 1  
Document count: 1  
Index: geneve-ut-459

```python
file where event.type == "change" and file.name : "*AAA.AAA"
```

```python
[{'event': {'type': ['change'], 'category': ['file']}, 'file': {'name': 'XIUtkNIAAA.AAA'}, '@timestamp': 0}]
```



### Potential Shadow Credentials added to AD Object

Branch count: 1  
Document count: 1  
Index: geneve-ut-460

```python
event.action:"Directory Service Changes" and event.code:"5136" and winlog.event_data.AttributeLDAPDisplayName:"msDS-KeyCredentialLink"
```

```python
[{'event': {'action': 'Directory Service Changes', 'code': '5136'}, 'winlog': {'event_data': {'AttributeLDAPDisplayName': 'msDS-KeyCredentialLink'}}, '@timestamp': 0}]
```



### Potential Shell via Web Server

Branch count: 16  
Document count: 16  
Index: geneve-ut-462

```python
event.category:process and event.type:(start or process_started) and process.name:(bash or dash) and
  user.name:(apache or nginx or www or "www-data")
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'bash'}, 'user': {'name': 'apache'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'bash'}, 'user': {'name': 'nginx'}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'bash'}, 'user': {'name': 'www'}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'bash'}, 'user': {'name': 'www-data'}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'dash'}, 'user': {'name': 'apache'}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'dash'}, 'user': {'name': 'nginx'}, '@timestamp': 5},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'dash'}, 'user': {'name': 'www'}, '@timestamp': 6},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'dash'}, 'user': {'name': 'www-data'}, '@timestamp': 7},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'bash'}, 'user': {'name': 'apache'}, '@timestamp': 8},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'bash'}, 'user': {'name': 'nginx'}, '@timestamp': 9},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'bash'}, 'user': {'name': 'www'}, '@timestamp': 10},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'bash'}, 'user': {'name': 'www-data'}, '@timestamp': 11},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'dash'}, 'user': {'name': 'apache'}, '@timestamp': 12},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'dash'}, 'user': {'name': 'nginx'}, '@timestamp': 13},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'dash'}, 'user': {'name': 'www'}, '@timestamp': 14},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'dash'}, 'user': {'name': 'www-data'}, '@timestamp': 15}]
```



### Potential Windows Error Manager Masquerading

Branch count: 1  
Document count: 2  
Index: geneve-ut-463

```python
sequence by host.id, process.entity_id with maxspan = 5s
  [process where event.type:"start" and process.name : ("wermgr.exe", "WerFault.exe") and process.args_count == 1]
  [network where process.name : ("wermgr.exe", "WerFault.exe") and network.protocol != "dns" and
    network.direction : ("outgoing", "egress") and destination.ip !="::1" and destination.ip !="127.0.0.1"
  ]
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'wermgr.exe', 'args_count': 1, 'entity_id': 'Uyy'}, 'host': {'id': 'vCf'}, '@timestamp': 0},
 {'process': {'name': 'WerFault.exe', 'entity_id': 'Uyy'}, 'network': {'protocol': 'oix', 'direction': 'egress'}, 'destination': {'ip': 'a728:d9ab:7cd7:de7d:c77f:b9c1:95ef:56af'}, 'event': {'category': ['network']}, 'host': {'id': 'vCf'}, '@timestamp': 1}]
```



### PowerShell Kerberos Ticket Request

Branch count: 1  
Document count: 1  
Index: geneve-ut-464

```python
event.category:process and 
  powershell.file.script_block_text : (
    KerberosRequestorSecurityToken
  )
```

```python
[{'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'KerberosRequestorSecurityToken'}}, '@timestamp': 0}]
```



### PowerShell Keylogging Script

Branch count: 4  
Document count: 4  
Index: geneve-ut-465

```python
event.category:process and 
  ( 
   powershell.file.script_block_text : (GetAsyncKeyState or NtUserGetAsyncKeyState or GetKeyboardState or "Get-Keystrokes") or 
   powershell.file.script_block_text : (
        (SetWindowsHookA or SetWindowsHookW or SetWindowsHookEx or SetWindowsHookExA or NtUserSetWindowsHookEx) and
        (GetForegroundWindow or GetWindowTextA or GetWindowTextW or "WM_KEYBOARD_LL")
   )
   )
```

```python
[{'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'GetAsyncKeyState'}}, '@timestamp': 0},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'NtUserGetAsyncKeyState'}}, '@timestamp': 1},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'GetKeyboardState'}}, '@timestamp': 2},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'Get-Keystrokes'}}, '@timestamp': 3}]
```



### PowerShell MiniDump Script

Branch count: 3  
Document count: 3  
Index: geneve-ut-466

```python
event.category:process and powershell.file.script_block_text:(MiniDumpWriteDump or MiniDumpWithFullMemory or pmuDetirWpmuDiniM)
```

```python
[{'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'MiniDumpWriteDump'}}, '@timestamp': 0},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'MiniDumpWithFullMemory'}}, '@timestamp': 1},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'pmuDetirWpmuDiniM'}}, '@timestamp': 2}]
```



### PowerShell PSReflect Script

Branch count: 9  
Document count: 9  
Index: geneve-ut-467

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

```python
[{'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'New-InMemoryModule'}}, '@timestamp': 0},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'Add-Win32Type'}}, '@timestamp': 1},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'psenum'}}, '@timestamp': 2},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'DefineDynamicAssembly'}}, '@timestamp': 3},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'DefineDynamicModule'}}, '@timestamp': 4},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'Reflection.TypeAttributes'}}, '@timestamp': 5},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'Reflection.Emit.OpCodes'}}, '@timestamp': 6},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'Reflection.Emit.CustomAttributeBuilder'}}, '@timestamp': 7},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'Runtime.InteropServices.DllImportAttribute'}}, '@timestamp': 8}]
```



### PowerShell Suspicious Discovery Related Windows API Functions

Branch count: 11  
Document count: 11  
Index: geneve-ut-469

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

```python
[{'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'NetShareEnum'}}, '@timestamp': 0},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'NetWkstaUserEnum'}}, '@timestamp': 1},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'NetSessionEnum'}}, '@timestamp': 2},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'NetLocalGroupEnum'}}, '@timestamp': 3},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'NetLocalGroupGetMembers'}}, '@timestamp': 4},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'DsGetSiteName'}}, '@timestamp': 5},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'DsEnumerateDomainTrusts'}}, '@timestamp': 6},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'WTSEnumerateSessionsEx'}}, '@timestamp': 7},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'WTSQuerySessionInformation'}}, '@timestamp': 8},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'LsaGetLogonSessionData'}}, '@timestamp': 9},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'QueryServiceObjectSecurity'}}, '@timestamp': 10}]
```



### PowerShell spawning Cmd

Branch count: 2  
Document count: 2  
Index: geneve-ut-473

```python
event.category:process and event.type:(start or process_started) and
  process.parent.name:powershell.exe and process.name:cmd.exe
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'parent': {'name': 'powershell.exe'}, 'name': 'cmd.exe'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'parent': {'name': 'powershell.exe'}, 'name': 'cmd.exe'}, '@timestamp': 1}]
```



### Privilege Escalation via Named Pipe Impersonation

Branch count: 4  
Document count: 4  
Index: geneve-ut-474

```python
process where event.type in ("start", "process_started") and
 process.pe.original_file_name in ("Cmd.Exe", "PowerShell.EXE") and 
 process.args : "echo" and process.args : ">" and process.args : "\\\\.\\pipe\\*"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['echo', '>', '\\\\.\\pipe\\*']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['echo', '>', '\\\\.\\pipe\\*']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['echo', '>', '\\\\.\\pipe\\*']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['echo', '>', '\\\\.\\pipe\\*']}, '@timestamp': 3}]
```



### Privilege Escalation via Rogue Named Pipe Impersonation

Branch count: 1  
Document count: 1  
Index: geneve-ut-475

```python
file where event.action : "Pipe Created*" and
 /* normal sysmon named pipe creation events truncate the pipe keyword */
  file.name : "\\*\\Pipe\\*"
```

```python
[{'event': {'action': 'Pipe CreatedXIUtkNI', 'category': ['file']}, 'file': {'name': '\\ixTFlEzswuEEXp\\Pipe\\AagaiFqsyzKNyyQ'}, '@timestamp': 0}]
```



### Privilege Escalation via Root Crontab File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-476

```python
event.category:file and not event.type:deletion and
 file.path:/private/var/at/tabs/root and not process.executable:/usr/bin/crontab
```

```python
[{'event': {'category': ['file'], 'type': ['ZFy']}, 'file': {'path': '/private/var/at/tabs/root'}, 'process': {'executable': 'XIU'}, '@timestamp': 0}]
```



### Process Activity via Compiled HTML File

Branch count: 2  
Document count: 2  
Index: geneve-ut-478

```python
process where event.type in ("start", "process_started") and 
 process.parent.name : "hh.exe" and 
 process.name : ("mshta.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cscript.exe", "wscript.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'hh.exe'}, 'name': 'powershell_ise.exe'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'hh.exe'}, 'name': 'wscript.exe'}, '@timestamp': 1}]
```



### Process Discovery via Tasklist

Branch count: 2  
Document count: 2  
Index: geneve-ut-479

```python
event.category:process and event.type:(start or process_started) and process.name:tasklist.exe
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tasklist.exe'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'tasklist.exe'}, '@timestamp': 1}]
```



### Process Execution from an Unusual Directory

Branch count: 3  
Document count: 3  
Index: geneve-ut-480

```python
process where event.type in ("start", "process_started", "info") and
 /* add suspicious execution paths here */
process.executable : ("C:\\PerfLogs\\*.exe","C:\\Users\\Public\\*.exe","C:\\Users\\Default\\*.exe","C:\\Windows\\Tasks\\*.exe","C:\\Intel\\*.exe","C:\\AMD\\Temp\\*.exe","C:\\Windows\\AppReadiness\\*.exe",
"C:\\Windows\\ServiceState\\*.exe","C:\\Windows\\security\\*.exe","C:\\Windows\\IdentityCRL\\*.exe","C:\\Windows\\Branding\\*.exe","C:\\Windows\\csc\\*.exe",
 "C:\\Windows\\DigitalLocker\\*.exe","C:\\Windows\\en-US\\*.exe","C:\\Windows\\wlansvc\\*.exe","C:\\Windows\\Prefetch\\*.exe","C:\\Windows\\Fonts\\*.exe",
 "C:\\Windows\\diagnostics\\*.exe","C:\\Windows\\TAPI\\*.exe","C:\\Windows\\INF\\*.exe","C:\\Windows\\System32\\Speech\\*.exe","C:\\windows\\tracing\\*.exe",
 "c:\\windows\\IME\\*.exe","c:\\Windows\\Performance\\*.exe","c:\\windows\\intel\\*.exe","c:\\windows\\ms\\*.exe","C:\\Windows\\dot3svc\\*.exe","C:\\Windows\\ServiceProfiles\\*.exe",
 "C:\\Windows\\panther\\*.exe","C:\\Windows\\RemotePackages\\*.exe","C:\\Windows\\OCR\\*.exe","C:\\Windows\\appcompat\\*.exe","C:\\Windows\\apppatch\\*.exe","C:\\Windows\\addins\\*.exe",
 "C:\\Windows\\Setup\\*.exe","C:\\Windows\\Help\\*.exe","C:\\Windows\\SKB\\*.exe","C:\\Windows\\Vss\\*.exe","C:\\Windows\\Web\\*.exe","C:\\Windows\\servicing\\*.exe","C:\\Windows\\CbsTemp\\*.exe",
 "C:\\Windows\\Logs\\*.exe","C:\\Windows\\WaaS\\*.exe","C:\\Windows\\twain_32\\*.exe","C:\\Windows\\ShellExperiences\\*.exe","C:\\Windows\\ShellComponents\\*.exe","C:\\Windows\\PLA\\*.exe",
 "C:\\Windows\\Migration\\*.exe","C:\\Windows\\debug\\*.exe","C:\\Windows\\Cursors\\*.exe","C:\\Windows\\Containers\\*.exe","C:\\Windows\\Boot\\*.exe","C:\\Windows\\bcastdvr\\*.exe",
 "C:\\Windows\\assembly\\*.exe","C:\\Windows\\TextInput\\*.exe","C:\\Windows\\security\\*.exe","C:\\Windows\\schemas\\*.exe","C:\\Windows\\SchCache\\*.exe","C:\\Windows\\Resources\\*.exe",
 "C:\\Windows\\rescache\\*.exe","C:\\Windows\\Provisioning\\*.exe","C:\\Windows\\PrintDialog\\*.exe","C:\\Windows\\PolicyDefinitions\\*.exe","C:\\Windows\\media\\*.exe",
 "C:\\Windows\\Globalization\\*.exe","C:\\Windows\\L2Schemas\\*.exe","C:\\Windows\\LiveKernelReports\\*.exe","C:\\Windows\\ModemLogs\\*.exe","C:\\Windows\\ImmersiveControlPanel\\*.exe") and
 not process.name : ("SpeechUXWiz.exe","SystemSettings.exe","TrustedInstaller.exe","PrintDialog.exe","MpSigStub.exe","LMS.exe","mpam-*.exe")
 /* uncomment once in winlogbeat */
 /* and not (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true) */
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'executable': 'C:\\Windows\\servicing\\XIUtkNI.exe', 'name': 'oix'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'executable': 'C:\\Windows\\PrintDialog\\Ezswu.exe', 'name': 'EEX'}, '@timestamp': 1},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'executable': 'C:\\Windows\\System32\\Speech\\WqNVRcymEEwVP.exe', 'name': 'YMG'}, '@timestamp': 2}]
```



### Process Injection - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-481

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:kernel_shellcode_event or endgame.event_subtype_full:kernel_shellcode_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'kernel_shellcode_event'}, 'endgame': {'metadata': {'type': 'detection'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'detection'}, 'event_subtype_full': 'kernel_shellcode_event'}, '@timestamp': 1}]
```



### Process Injection - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-482

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:kernel_shellcode_event or endgame.event_subtype_full:kernel_shellcode_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'kernel_shellcode_event'}, 'endgame': {'metadata': {'type': 'prevention'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'prevention'}, 'event_subtype_full': 'kernel_shellcode_event'}, '@timestamp': 1}]
```



### Process Injection by the Microsoft Build Engine

Branch count: 1  
Document count: 1  
Index: geneve-ut-483

```python
process.name:MSBuild.exe and event.action:"CreateRemoteThread detected (rule: CreateRemoteThread)"
```

```python
[{'process': {'name': 'MSBuild.exe'}, 'event': {'action': 'CreateRemoteThread detected (rule: CreateRemoteThread)'}, '@timestamp': 0}]
```



### Process Termination followed by Deletion

Branch count: 1  
Document count: 2  
Index: geneve-ut-484

```python
sequence by host.id with maxspan=5s
   [process where event.type == "end" and 
    process.code_signature.trusted == false and
    not process.executable : ("C:\\Windows\\SoftwareDistribution\\*.exe", "C:\\Windows\\WinSxS\\*.exe")
   ] by process.executable
   [file where event.type == "deletion" and file.extension : ("exe", "scr", "com")] by file.path
```

```python
[{'event': {'type': ['end'], 'category': ['process']}, 'process': {'code_signature': {'trusted': False}, 'executable': 'ZFy'}, 'host': {'id': 'XIU'}, '@timestamp': 0},
 {'event': {'type': ['deletion'], 'category': ['file']}, 'file': {'extension': 'exe', 'path': 'ZFy'}, 'host': {'id': 'XIU'}, '@timestamp': 1}]
```



### Program Files Directory Masquerading

Branch count: 1  
Document count: 1  
Index: geneve-ut-485

```python
process where event.type == "start" and
 process.executable : "C:\\*Program*Files*\\*.exe" and
 not process.executable : ("C:\\Program Files\\*.exe", "C:\\Program Files (x86)\\*.exe", "C:\\Users\\*.exe", "C:\\ProgramData\\*.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'executable': 'C:\\XIUtkNIProgramSvILOFilesEzswu\\nLeOAagaiF.exe'}, '@timestamp': 0}]
```



### Proxy Port Activity to the Internet

Branch count: 24  
Document count: 24  
Index: geneve-ut-487

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:(1080 or 3128 or 8080) or event.dataset:zeek.socks) and
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
    192.168.0.0/16 or
    224.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  )
```

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1080, 'ip': 'e6ea:94e4:e5ac:b58c:1b43:3a53:aa79:ec59'}, 'source': {'ip': '10.214.62.131'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1080, 'ip': '119.10.44.216'}, 'source': {'ip': '172.31.81.251'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1080, 'ip': '104.129.204.102'}, 'source': {'ip': '192.168.147.58'}, '@timestamp': 2},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3128, 'ip': '149.239.86.175'}, 'source': {'ip': '10.111.13.86'}, '@timestamp': 3},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3128, 'ip': '112.141.185.70'}, 'source': {'ip': '172.27.169.243'}, '@timestamp': 4},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3128, 'ip': 'b781:36ad:968a:1fd9:42e0:603d:9566:7ca8'}, 'source': {'ip': '192.168.197.122'}, '@timestamp': 5},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 8080, 'ip': '21ff:ce1f:c206:4389:a7:5646:506a:fac3'}, 'source': {'ip': '10.155.175.169'}, '@timestamp': 6},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 8080, 'ip': '156.105.128.203'}, 'source': {'ip': '172.21.27.73'}, '@timestamp': 7},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 8080, 'ip': '93.16.168.118'}, 'source': {'ip': '192.168.162.120'}, '@timestamp': 8},
 {'event': {'category': ['network'], 'dataset': 'zeek.socks'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.247.115.164'}, 'destination': {'ip': 'cde8:687a:c169:7ee6:e8d4:8f4f:b2cc:3459'}, '@timestamp': 9},
 {'event': {'category': ['network'], 'dataset': 'zeek.socks'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.30.255.121'}, 'destination': {'ip': 'e2fc:2265:c4e2:24bd:4b82:92c6:7ee8:2ac8'}, '@timestamp': 10},
 {'event': {'category': ['network'], 'dataset': 'zeek.socks'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.120.95'}, 'destination': {'ip': '147.172.30.18'}, '@timestamp': 11},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1080, 'ip': '200.44.53.86'}, 'source': {'ip': '10.231.61.22'}, '@timestamp': 12},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1080, 'ip': 'bd8d:8e9f:3c38:5e93:2a21:f2e3:2a70:2899'}, 'source': {'ip': '172.27.220.217'}, '@timestamp': 13},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1080, 'ip': '3.79.219.137'}, 'source': {'ip': '192.168.64.185'}, '@timestamp': 14},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3128, 'ip': 'b861:3a65:7d92:a4ae:175d:4ee4:1dd9:801e'}, 'source': {'ip': '10.77.111.86'}, '@timestamp': 15},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3128, 'ip': '46.77.189.36'}, 'source': {'ip': '172.17.96.216'}, '@timestamp': 16},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3128, 'ip': '159.213.231.147'}, 'source': {'ip': '192.168.139.227'}, '@timestamp': 17},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 8080, 'ip': '926e:7af:547b:40e6:6d4a:85e0:ec27:61f0'}, 'source': {'ip': '10.118.248.208'}, '@timestamp': 18},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 8080, 'ip': '169.49.132.205'}, 'source': {'ip': '172.31.220.4'}, '@timestamp': 19},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 8080, 'ip': '23.217.57.149'}, 'source': {'ip': '192.168.96.227'}, '@timestamp': 20},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.socks'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.59.195.236'}, 'destination': {'ip': '18bd:8fde:45bf:faed:fdf6:3054:3d28:170f'}, '@timestamp': 21},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.socks'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.23.169.85'}, 'destination': {'ip': '255.18.123.234'}, '@timestamp': 22},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.socks'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.63.15'}, 'destination': {'ip': '171.232.70.1'}, '@timestamp': 23}]
```



### PsExec Network Connection

Branch count: 1  
Document count: 2  
Index: geneve-ut-488

```python
sequence by process.entity_id
  [process where process.name : "PsExec.exe" and event.type == "start"]
  [network where process.name : "PsExec.exe"]
```

```python
[{'process': {'name': 'PsExec.exe', 'entity_id': 'ZFy'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'PsExec.exe', 'entity_id': 'ZFy'}, 'event': {'category': ['network']}, '@timestamp': 1}]
```



### Python Script Execution via Command Line

Branch count: 2  
Document count: 2  
Index: geneve-ut-489

```python
process where event.type in ("start", "process_started") and
 process.name : "python*" and process.args : "-c" and process.args : "*import*sys*"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'pythonXIUtkNI', 'args': ['-c', '*import*sys*']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'pythonixTFlEzswuEEXp', 'args': ['-c', '*import*sys*']}, '@timestamp': 1}]
```



### Query Registry via reg.exe

Branch count: 4  
Document count: 4  
Index: geneve-ut-490

```python
process where event.type in ("start", "process_started") and
  (process.name : "reg.exe" or process.pe.original_file_name == "reg.exe") and
  process.args == "query"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'reg.exe', 'args': ['query']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'reg.exe'}, 'args': ['query']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'reg.exe', 'args': ['query']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'reg.exe'}, 'args': ['query']}, '@timestamp': 3}]
```



### RDP (Remote Desktop Protocol) from the Internet

Branch count: 12  
Document count: 12  
Index: geneve-ut-491

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

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3389, 'ip': '10.214.62.131'}, 'source': {'ip': '222.151.68.226'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3389, 'ip': '172.28.20.160'}, 'source': {'ip': '170.121.236.89'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3389, 'ip': '192.168.96.70'}, 'source': {'ip': '54.2.158.30'}, '@timestamp': 2},
 {'event': {'category': ['network'], 'dataset': 'zeek.rdp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '219.54.168.90'}, 'destination': {'ip': '10.209.3.152'}, '@timestamp': 3},
 {'event': {'category': ['network'], 'dataset': 'zeek.rdp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '169.225.121.243'}, 'destination': {'ip': '172.24.207.103'}, '@timestamp': 4},
 {'event': {'category': ['network'], 'dataset': 'zeek.rdp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '199.127.185.194'}, 'destination': {'ip': '192.168.186.159'}, '@timestamp': 5},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3389, 'ip': '10.197.122.33'}, 'source': {'ip': '112.141.185.70'}, '@timestamp': 6},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3389, 'ip': '172.18.192.161'}, 'source': {'ip': '149.102.124.168'}, '@timestamp': 7},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3389, 'ip': '192.168.1.78'}, 'source': {'ip': '197.7.114.246'}, '@timestamp': 8},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.rdp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': 'd5e4:e45:48d:758d:eac9:ff60:21ff:ce20'}, 'destination': {'ip': '10.29.111.63'}, '@timestamp': 9},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.rdp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '121.161.84.247'}, 'destination': {'ip': '172.23.250.187'}, '@timestamp': 10},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.rdp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '151.149.0.92'}, 'destination': {'ip': '192.168.247.115'}, '@timestamp': 11}]
```



### RDP (Remote Desktop Protocol) to the Internet

Branch count: 12  
Document count: 12  
Index: geneve-ut-492

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:3389 or event.dataset:zeek.rdp) and
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
    192.168.0.0/16 or
    224.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  )
```

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3389, 'ip': 'e6ea:94e4:e5ac:b58c:1b43:3a53:aa79:ec59'}, 'source': {'ip': '10.214.62.131'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3389, 'ip': '119.10.44.216'}, 'source': {'ip': '172.31.81.251'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3389, 'ip': '104.129.204.102'}, 'source': {'ip': '192.168.147.58'}, '@timestamp': 2},
 {'event': {'category': ['network'], 'dataset': 'zeek.rdp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.111.13.86'}, 'destination': {'ip': '149.239.86.175'}, '@timestamp': 3},
 {'event': {'category': ['network'], 'dataset': 'zeek.rdp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.27.169.243'}, 'destination': {'ip': '112.141.185.70'}, '@timestamp': 4},
 {'event': {'category': ['network'], 'dataset': 'zeek.rdp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.197.122'}, 'destination': {'ip': 'b781:36ad:968a:1fd9:42e0:603d:9566:7ca8'}, '@timestamp': 5},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3389, 'ip': '21ff:ce1f:c206:4389:a7:5646:506a:fac3'}, 'source': {'ip': '10.155.175.169'}, '@timestamp': 6},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3389, 'ip': '156.105.128.203'}, 'source': {'ip': '172.21.27.73'}, '@timestamp': 7},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3389, 'ip': '93.16.168.118'}, 'source': {'ip': '192.168.162.120'}, '@timestamp': 8},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.rdp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.247.115.164'}, 'destination': {'ip': 'cde8:687a:c169:7ee6:e8d4:8f4f:b2cc:3459'}, '@timestamp': 9},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.rdp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.30.255.121'}, 'destination': {'ip': 'e2fc:2265:c4e2:24bd:4b82:92c6:7ee8:2ac8'}, '@timestamp': 10},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.rdp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.120.95'}, 'destination': {'ip': '147.172.30.18'}, '@timestamp': 11}]
```



### RPC (Remote Procedure Call) from the Internet

Branch count: 12  
Document count: 12  
Index: geneve-ut-494

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

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 135, 'ip': '10.214.62.131'}, 'source': {'ip': '222.151.68.226'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 135, 'ip': '172.28.20.160'}, 'source': {'ip': '170.121.236.89'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 135, 'ip': '192.168.96.70'}, 'source': {'ip': '54.2.158.30'}, '@timestamp': 2},
 {'event': {'category': ['network'], 'dataset': 'zeek.dce_rpc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '219.54.168.90'}, 'destination': {'ip': '10.209.3.152'}, '@timestamp': 3},
 {'event': {'category': ['network'], 'dataset': 'zeek.dce_rpc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '169.225.121.243'}, 'destination': {'ip': '172.24.207.103'}, '@timestamp': 4},
 {'event': {'category': ['network'], 'dataset': 'zeek.dce_rpc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '199.127.185.194'}, 'destination': {'ip': '192.168.186.159'}, '@timestamp': 5},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 135, 'ip': '10.197.122.33'}, 'source': {'ip': '112.141.185.70'}, '@timestamp': 6},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 135, 'ip': '172.18.192.161'}, 'source': {'ip': '149.102.124.168'}, '@timestamp': 7},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 135, 'ip': '192.168.1.78'}, 'source': {'ip': '197.7.114.246'}, '@timestamp': 8},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.dce_rpc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': 'd5e4:e45:48d:758d:eac9:ff60:21ff:ce20'}, 'destination': {'ip': '10.29.111.63'}, '@timestamp': 9},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.dce_rpc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '121.161.84.247'}, 'destination': {'ip': '172.23.250.187'}, '@timestamp': 10},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.dce_rpc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '151.149.0.92'}, 'destination': {'ip': '192.168.247.115'}, '@timestamp': 11}]
```



### RPC (Remote Procedure Call) to the Internet

Branch count: 12  
Document count: 12  
Index: geneve-ut-495

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

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 135, 'ip': '170.121.236.89'}, 'source': {'ip': '10.214.62.131'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 135, 'ip': '54.2.158.30'}, 'source': {'ip': '172.28.20.160'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 135, 'ip': '219.54.168.90'}, 'source': {'ip': '192.168.96.70'}, '@timestamp': 2},
 {'event': {'category': ['network'], 'dataset': 'zeek.dce_rpc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.209.3.152'}, 'destination': {'ip': '169.225.121.243'}, '@timestamp': 3},
 {'event': {'category': ['network'], 'dataset': 'zeek.dce_rpc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.24.207.103'}, 'destination': {'ip': '199.127.185.194'}, '@timestamp': 4},
 {'event': {'category': ['network'], 'dataset': 'zeek.dce_rpc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.186.159'}, 'destination': {'ip': '112.141.185.70'}, '@timestamp': 5},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 135, 'ip': '149.102.124.168'}, 'source': {'ip': '10.197.122.33'}, '@timestamp': 6},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 135, 'ip': '197.7.114.246'}, 'source': {'ip': '172.18.192.161'}, '@timestamp': 7},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 135, 'ip': 'd5e4:e45:48d:758d:eac9:ff60:21ff:ce20'}, 'source': {'ip': '192.168.1.78'}, '@timestamp': 8},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.dce_rpc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.29.111.63'}, 'destination': {'ip': '121.161.84.247'}, '@timestamp': 9},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.dce_rpc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.23.250.187'}, 'destination': {'ip': '151.149.0.92'}, '@timestamp': 10},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.dce_rpc'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.247.115'}, 'destination': {'ip': '178.204.52.89'}, '@timestamp': 11}]
```



### Ransomware - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-496

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:ransomware_event or endgame.event_subtype_full:ransomware_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'ransomware_event'}, 'endgame': {'metadata': {'type': 'detection'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'detection'}, 'event_subtype_full': 'ransomware_event'}, '@timestamp': 1}]
```



### Ransomware - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-497

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:ransomware_event or endgame.event_subtype_full:ransomware_event)
```

```python
[{'event': {'kind': 'alert', 'module': 'endgame', 'action': 'ransomware_event'}, 'endgame': {'metadata': {'type': 'prevention'}}, '@timestamp': 0},
 {'event': {'kind': 'alert', 'module': 'endgame'}, 'endgame': {'metadata': {'type': 'prevention'}, 'event_subtype_full': 'ransomware_event'}, '@timestamp': 1}]
```



### Registry Persistence via AppCert DLL

Branch count: 1  
Document count: 1  
Index: geneve-ut-500

```python
registry where
/* uncomment once stable length(bytes_written_string) > 0 and */
  registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Control\\Session Manager\\AppCertDLLs\\*"
```

```python
[{'registry': {'path': 'HKLM\\SYSTEM\\XIUtkNIControlSetSvILO\\Control\\Session Manager\\AppCertDLLs\\Ezswu'}, 'event': {'category': ['registry']}, '@timestamp': 0}]
```



### Registry Persistence via AppInit DLL

Branch count: 1  
Document count: 1  
Index: geneve-ut-501

```python
registry where
   registry.path : ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls", 
                    "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls") and
   not process.executable : ("C:\\Windows\\System32\\msiexec.exe", 
                             "C:\\Windows\\SysWOW64\\msiexec.exe", 
                             "C:\\Program Files\\Commvault\\ContentStore*\\Base\\cvd.exe",
                             "C:\\Program Files (x86)\\Commvault\\ContentStore*\\Base\\cvd.exe")
```

```python
[{'registry': {'path': 'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls'}, 'process': {'executable': 'vCf'}, 'event': {'category': ['registry']}, '@timestamp': 0}]
```



### Remote Desktop Enabled in Windows Firewall by Netsh

Branch count: 4  
Document count: 4  
Index: geneve-ut-502

```python
process where event.type in ("start", "process_started") and
 (process.name : "netsh.exe" or process.pe.original_file_name == "netsh.exe") and
 process.args : ("localport=3389", "RemoteDesktop", "group=\"remote desktop\"") and
 process.args : ("action=allow", "enable=Yes", "enable")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'netsh.exe', 'args': ['localport=3389', 'RemoteDesktop', 'group="remote desktop"', 'action=allow', 'enable=Yes', 'enable']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'netsh.exe'}, 'args': ['localport=3389', 'RemoteDesktop', 'group="remote desktop"', 'action=allow', 'enable=Yes', 'enable']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'netsh.exe', 'args': ['localport=3389', 'RemoteDesktop', 'group="remote desktop"', 'action=allow', 'enable=Yes', 'enable']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'netsh.exe'}, 'args': ['localport=3389', 'RemoteDesktop', 'group="remote desktop"', 'action=allow', 'enable=Yes', 'enable']}, '@timestamp': 3}]
```



### Remote Execution via File Shares

Branch count: 4  
Document count: 8  
Index: geneve-ut-503

```python
sequence with maxspan=1m
  [file where event.type in ("creation", "change") and process.pid == 4 and file.extension : "exe"] by host.id, file.path
  [process where event.type in ("start", "process_started")] by host.id, process.executable
```

```python
[{'event': {'type': ['creation'], 'category': ['file']}, 'process': {'pid': 4}, 'file': {'extension': 'exe', 'path': 'XIU'}, 'host': {'id': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'host': {'id': 'ZFy'}, 'process': {'executable': 'XIU'}, '@timestamp': 1},
 {'event': {'type': ['creation'], 'category': ['file']}, 'process': {'pid': 4}, 'file': {'extension': 'exe', 'path': 'Ioi'}, 'host': {'id': 'tkN'}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'host': {'id': 'tkN'}, 'process': {'executable': 'Ioi'}, '@timestamp': 3},
 {'event': {'type': ['change'], 'category': ['file']}, 'process': {'pid': 4}, 'file': {'extension': 'exe', 'path': 'lEz'}, 'host': {'id': 'xTF'}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'host': {'id': 'xTF'}, 'process': {'executable': 'lEz'}, '@timestamp': 5},
 {'event': {'type': ['change'], 'category': ['file']}, 'process': {'pid': 4}, 'file': {'extension': 'exe', 'path': 'EEX'}, 'host': {'id': 'swu'}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'host': {'id': 'swu'}, 'process': {'executable': 'EEX'}, '@timestamp': 7}]
```



### Remote File Copy to a Hidden Share

Branch count: 2  
Document count: 2  
Index: geneve-ut-504

```python
process where event.type in ("start", "process_started") and
  process.name : ("cmd.exe", "powershell.exe", "robocopy.exe", "xcopy.exe") and 
  process.args : ("copy*", "move*", "cp", "mv") and process.args : "*$*"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'xcopy.exe', 'args': ['copy*', 'move*', 'cp', 'mv', '*$*']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'xcopy.exe', 'args': ['copy*', 'move*', 'cp', 'mv', '*$*']}, '@timestamp': 1}]
```



### Remote File Copy via TeamViewer

Branch count: 1  
Document count: 1  
Index: geneve-ut-505

```python
file where event.type == "creation" and process.name : "TeamViewer.exe" and
  file.extension : ("exe", "dll", "scr", "com", "bat", "ps1", "vbs", "vbe", "js", "wsh", "hta")
```

```python
[{'event': {'type': ['creation'], 'category': ['file']}, 'process': {'name': 'TeamViewer.exe'}, 'file': {'extension': 'vbs'}, '@timestamp': 0}]
```



### Remote File Download via Desktopimgdownldr Utility

Branch count: 4  
Document count: 4  
Index: geneve-ut-506

```python
process where event.type in ("start", "process_started") and
  (process.name : "desktopimgdownldr.exe" or process.pe.original_file_name == "desktopimgdownldr.exe") and
  process.args : "/lockscreenurl:http*"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'desktopimgdownldr.exe', 'args': ['/lockscreenurl:http*']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'desktopimgdownldr.exe'}, 'args': ['/lockscreenurl:http*']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'desktopimgdownldr.exe', 'args': ['/lockscreenurl:http*']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'desktopimgdownldr.exe'}, 'args': ['/lockscreenurl:http*']}, '@timestamp': 3}]
```



### Remote File Download via MpCmdRun

Branch count: 2  
Document count: 2  
Index: geneve-ut-507

```python
process where event.type == "start" and
  (process.name : "MpCmdRun.exe" or process.pe.original_file_name == "MpCmdRun.exe") and
   process.args : "-DownloadFile" and process.args : "-url" and process.args : "-path"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'MpCmdRun.exe', 'args': ['-DownloadFile', '-url', '-path']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'MpCmdRun.exe'}, 'args': ['-DownloadFile', '-url', '-path']}, '@timestamp': 1}]
```



### Remote File Download via PowerShell

Branch count: 1  
Document count: 2  
Index: geneve-ut-508

```python
sequence by host.id, process.entity_id with maxspan=30s
  [network where process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and network.protocol == "dns" and
   not dns.question.name : ("localhost", "*.microsoft.com", "*.azureedge.net", "*.powershellgallery.com", "*.windowsupdate.com", "metadata.google.internal") and 
   not user.domain : "NT AUTHORITY"]
    [file where process.name : "powershell.exe" and event.type == "creation" and file.extension : ("exe", "dll", "ps1", "bat") and 
   not file.name : "__PSScriptPolicy*.ps1"]
```

```python
[{'process': {'name': 'pwsh.exe', 'entity_id': 'SvI'}, 'network': {'protocol': 'dns'}, 'dns': {'question': {'name': 'TvC'}}, 'user': {'domain': 'fUy'}, 'event': {'category': ['network']}, 'host': {'id': 'yFj'}, '@timestamp': 0},
 {'process': {'name': 'powershell.exe', 'entity_id': 'SvI'}, 'event': {'type': ['creation'], 'category': ['file']}, 'file': {'extension': 'dll', 'name': 'oOH'}, 'host': {'id': 'yFj'}, '@timestamp': 1}]
```



### Remote File Download via Script Interpreter

Branch count: 1  
Document count: 2  
Index: geneve-ut-509

```python
sequence by host.id, process.entity_id
  [network where process.name : ("wscript.exe", "cscript.exe") and network.protocol != "dns" and
   network.direction : ("outgoing", "egress") and network.type == "ipv4" and destination.ip != "127.0.0.1"
  ]
  [file where event.type == "creation" and file.extension : ("exe", "dll")]
```

```python
[{'process': {'name': 'wscript.exe', 'entity_id': 'SvI'}, 'network': {'protocol': 'vCf', 'direction': 'outgoing', 'type': 'ipv4'}, 'destination': {'ip': '54.2.158.30'}, 'event': {'category': ['network']}, 'host': {'id': 'yFj'}, '@timestamp': 0},
 {'event': {'type': ['creation'], 'category': ['file']}, 'file': {'extension': 'dll'}, 'host': {'id': 'yFj'}, 'process': {'entity_id': 'SvI'}, '@timestamp': 1}]
```



### Remote SSH Login Enabled via systemsetup Command

Branch count: 2  
Document count: 2  
Index: geneve-ut-510

```python
event.category:process and event.type:(start or process_started) and
 process.name:systemsetup and
 process.args:("-setremotelogin" and on)
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'systemsetup', 'args': ['-setremotelogin', 'on']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'systemsetup', 'args': ['-setremotelogin', 'on']}, '@timestamp': 1}]
```



### Remote Scheduled Task Creation

Branch count: 1  
Document count: 2  
Index: geneve-ut-511

```python
/* Task Scheduler service incoming connection followed by TaskCache registry modification  */

sequence by host.id, process.entity_id with maxspan = 1m
   [network where process.name : "svchost.exe" and
   network.direction : ("incoming", "ingress") and source.port >= 49152 and destination.port >= 49152 and
   source.ip != "127.0.0.1" and source.ip != "::1"
   ]
   [registry where registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions"]
```

```python
[{'process': {'name': 'svchost.exe', 'entity_id': 'vIL'}, 'network': {'direction': 'ingress'}, 'source': {'port': 62863, 'ip': 'c443:b67a:770a:2cd7:3602:9e1d:7a8f:dfec'}, 'destination': {'port': 52641}, 'event': {'category': ['network']}, 'host': {'id': 'FjS'}, '@timestamp': 0},
 {'registry': {'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\Ezswu\\Actions'}, 'event': {'category': ['registry']}, 'host': {'id': 'FjS'}, 'process': {'entity_id': 'vIL'}, '@timestamp': 1}]
```



### Remote System Discovery Commands

Branch count: 3  
Document count: 3  
Index: geneve-ut-512

```python
process where event.type in ("start", "process_started") and
  (process.name : "nbtstat.exe" and process.args : ("-n", "-s")) or
  (process.name : "arp.exe" and process.args : "-a")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'nbtstat.exe', 'args': ['-n', '-s']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'nbtstat.exe', 'args': ['-n', '-s']}, '@timestamp': 1},
 {'process': {'name': 'arp.exe', 'args': ['-a']}, 'event': {'category': ['process']}, '@timestamp': 2}]
```



### Remotely Started Services via RPC

Branch count: 8  
Document count: 16  
Index: geneve-ut-513

```python
sequence with maxspan=1s
   [network where process.name : "services.exe" and
      network.direction : ("incoming", "ingress") and network.transport == "tcp" and 
      source.port >= 49152 and destination.port >= 49152 and source.ip != "127.0.0.1" and source.ip != "::1"
   ] by host.id, process.entity_id

   [process where event.type in ("start", "process_started") and process.parent.name : "services.exe" and 
       not (process.name : "svchost.exe" and process.args : "tiledatamodelsvc") and 
       not (process.name : "msiexec.exe" and process.args : "/V")

    /* uncomment if psexec is noisy in your environment */
    /* and not process.name : "PSEXESVC.exe" */
   ] by host.id, process.parent.entity_id
```

```python
[{'process': {'name': 'services.exe', 'entity_id': 'vIL'}, 'network': {'direction': 'ingress', 'transport': 'tcp'}, 'source': {'port': 62863, 'ip': 'c443:b67a:770a:2cd7:3602:9e1d:7a8f:dfec'}, 'destination': {'port': 52641}, 'event': {'category': ['network']}, 'host': {'id': 'FjS'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'services.exe', 'entity_id': 'vIL'}, 'name': 'OoO'}, 'host': {'id': 'FjS'}, '@timestamp': 1},
 {'process': {'name': 'services.exe', 'entity_id': 'WqN'}, 'network': {'direction': 'ingress', 'transport': 'tcp'}, 'source': {'port': 57092, 'ip': '42e0:603d:9566:7ca7:8676:5e58:62bd:10dc'}, 'destination': {'port': 63558}, 'event': {'category': ['network']}, 'host': {'id': 'EXp'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'services.exe', 'entity_id': 'WqN'}, 'name': 'VRc', 'args': ['ymE']}, 'host': {'id': 'EXp'}, '@timestamp': 3},
 {'process': {'name': 'services.exe', 'entity_id': 'mlO'}, 'network': {'direction': 'ingress', 'transport': 'tcp'}, 'source': {'port': 63609, 'ip': '8fd8:c24b:a168:4644:d2ea:bc0e:bba3:4c90'}, 'destination': {'port': 64544}, 'event': {'category': ['network']}, 'host': {'id': 'zNf'}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'services.exe', 'entity_id': 'mlO'}, 'args': ['PZR'], 'name': 'gUv'}, 'host': {'id': 'zNf'}, '@timestamp': 5},
 {'process': {'name': 'services.exe', 'entity_id': 'Tms'}, 'network': {'direction': 'ingress', 'transport': 'tcp'}, 'source': {'port': 54584, 'ip': '189.141.142.160'}, 'destination': {'port': 54544}, 'event': {'category': ['network']}, 'host': {'id': 'rFg'}, '@timestamp': 6},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'services.exe', 'entity_id': 'Tms'}, 'args': ['hCe']}, 'host': {'id': 'rFg'}, '@timestamp': 7},
 {'process': {'name': 'services.exe', 'entity_id': 'myw'}, 'network': {'direction': 'incoming', 'transport': 'tcp'}, 'source': {'port': 50563, 'ip': '9.221.168.172'}, 'destination': {'port': 60857}, 'event': {'category': ['network']}, 'host': {'id': 'oGr'}, '@timestamp': 8},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'services.exe', 'entity_id': 'myw'}, 'name': 'DUN'}, 'host': {'id': 'oGr'}, '@timestamp': 9},
 {'process': {'name': 'services.exe', 'entity_id': 'moE'}, 'network': {'direction': 'ingress', 'transport': 'tcp'}, 'source': {'port': 53489, 'ip': '23.217.57.149'}, 'destination': {'port': 55352}, 'event': {'category': ['network']}, 'host': {'id': 'XgN'}, '@timestamp': 10},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'services.exe', 'entity_id': 'moE'}, 'name': 'FCE', 'args': ['Zpg']}, 'host': {'id': 'XgN'}, '@timestamp': 11},
 {'process': {'name': 'services.exe', 'entity_id': 'nDm'}, 'network': {'direction': 'incoming', 'transport': 'tcp'}, 'source': {'port': 55834, 'ip': '180.77.58.27'}, 'destination': {'port': 62921}, 'event': {'category': ['network']}, 'host': {'id': 'kuY'}, '@timestamp': 12},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'services.exe', 'entity_id': 'nDm'}, 'args': ['xXc'], 'name': 'xFE'}, 'host': {'id': 'kuY'}, '@timestamp': 13},
 {'process': {'name': 'services.exe', 'entity_id': 'WOc'}, 'network': {'direction': 'incoming', 'transport': 'tcp'}, 'source': {'port': 58206, 'ip': '8713:9758:f2ae:3dcd:6830:e2a:dffa:77e'}, 'destination': {'port': 50783}, 'event': {'category': ['network']}, 'host': {'id': 'zJC'}, '@timestamp': 14},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'services.exe', 'entity_id': 'WOc'}, 'args': ['yqv']}, 'host': {'id': 'zJC'}, '@timestamp': 15}]
```



### Renamed AutoIt Scripts Interpreter

Branch count: 3  
Document count: 3  
Index: geneve-ut-514

```python
process where event.type in ("start", "process_started", "info") and
  process.pe.original_file_name : "AutoIt*.exe" and not process.name : "AutoIt*.exe"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'AutoItXIUtkNI.exe'}, 'name': 'oix'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'AutoItEzswu.exe'}, 'name': 'EEX'}, '@timestamp': 1},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'AutoItWqNVRcymEEwVP.exe'}, 'name': 'YMG'}, '@timestamp': 2}]
```



### SMB (Windows File Sharing) Activity to the Internet

Branch count: 18  
Document count: 18  
Index: geneve-ut-517

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

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 139, 'ip': '170.121.236.89'}, 'source': {'ip': '10.214.62.131'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 139, 'ip': '54.2.158.30'}, 'source': {'ip': '172.28.20.160'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 139, 'ip': '219.54.168.90'}, 'source': {'ip': '192.168.96.70'}, '@timestamp': 2},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 445, 'ip': '169.225.121.243'}, 'source': {'ip': '10.209.3.152'}, '@timestamp': 3},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 445, 'ip': '199.127.185.194'}, 'source': {'ip': '172.24.207.103'}, '@timestamp': 4},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 445, 'ip': '112.141.185.70'}, 'source': {'ip': '192.168.186.159'}, '@timestamp': 5},
 {'event': {'category': ['network'], 'dataset': 'zeek.smb'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.197.122.33'}, 'destination': {'ip': '149.102.124.168'}, '@timestamp': 6},
 {'event': {'category': ['network'], 'dataset': 'zeek.smb'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.18.192.161'}, 'destination': {'ip': '197.7.114.246'}, '@timestamp': 7},
 {'event': {'category': ['network'], 'dataset': 'zeek.smb'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.1.78'}, 'destination': {'ip': 'd5e4:e45:48d:758d:eac9:ff60:21ff:ce20'}, '@timestamp': 8},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 139, 'ip': '121.161.84.247'}, 'source': {'ip': '10.29.111.63'}, '@timestamp': 9},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 139, 'ip': '151.149.0.92'}, 'source': {'ip': '172.23.250.187'}, '@timestamp': 10},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 139, 'ip': '178.204.52.89'}, 'source': {'ip': '192.168.247.115'}, '@timestamp': 11},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 445, 'ip': '7ee8:2ac7:8fd8:c24b:a168:4644:d2ea:bc0f'}, 'source': {'ip': '10.239.247.149'}, '@timestamp': 12},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 445, 'ip': '60.47.190.229'}, 'source': {'ip': '172.19.127.35'}, '@timestamp': 13},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 445, 'ip': 'd693:36a4:eaa1:660b:fe6b:8957:739e:8b1b'}, 'source': {'ip': '192.168.165.29'}, '@timestamp': 14},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.smb'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.209.145.8'}, 'destination': {'ip': '139.59.60.34'}, '@timestamp': 15},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.smb'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.21.68.62'}, 'destination': {'ip': '189.141.142.160'}, '@timestamp': 16},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.smb'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.64.185'}, 'destination': {'ip': '60.8.116.38'}, '@timestamp': 17}]
```



### SMTP on Port 26/TCP

Branch count: 4  
Document count: 4  
Index: geneve-ut-518

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:26 or (event.dataset:zeek.smtp and destination.port:26))
```

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 26}, '@timestamp': 0},
 {'event': {'category': ['network'], 'dataset': 'zeek.smtp'}, 'network': {'transport': 'tcp'}, 'destination': {'port': 26}, '@timestamp': 1},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 26}, '@timestamp': 2},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.smtp'}, 'network': {'transport': 'tcp'}, 'destination': {'port': 26}, '@timestamp': 3}]
```



### SMTP to the Internet

Branch count: 24  
Document count: 24  
Index: geneve-ut-519

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:(25 or 465 or 587) or event.dataset:zeek.smtp) and
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
    192.168.0.0/16 or
    224.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  )
```

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 25, 'ip': 'e6ea:94e4:e5ac:b58c:1b43:3a53:aa79:ec59'}, 'source': {'ip': '10.214.62.131'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 25, 'ip': '119.10.44.216'}, 'source': {'ip': '172.31.81.251'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 25, 'ip': '104.129.204.102'}, 'source': {'ip': '192.168.147.58'}, '@timestamp': 2},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 465, 'ip': '149.239.86.175'}, 'source': {'ip': '10.111.13.86'}, '@timestamp': 3},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 465, 'ip': '112.141.185.70'}, 'source': {'ip': '172.27.169.243'}, '@timestamp': 4},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 465, 'ip': 'b781:36ad:968a:1fd9:42e0:603d:9566:7ca8'}, 'source': {'ip': '192.168.197.122'}, '@timestamp': 5},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 587, 'ip': '21ff:ce1f:c206:4389:a7:5646:506a:fac3'}, 'source': {'ip': '10.155.175.169'}, '@timestamp': 6},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 587, 'ip': '156.105.128.203'}, 'source': {'ip': '172.21.27.73'}, '@timestamp': 7},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 587, 'ip': '93.16.168.118'}, 'source': {'ip': '192.168.162.120'}, '@timestamp': 8},
 {'event': {'category': ['network'], 'dataset': 'zeek.smtp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.247.115.164'}, 'destination': {'ip': 'cde8:687a:c169:7ee6:e8d4:8f4f:b2cc:3459'}, '@timestamp': 9},
 {'event': {'category': ['network'], 'dataset': 'zeek.smtp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.30.255.121'}, 'destination': {'ip': 'e2fc:2265:c4e2:24bd:4b82:92c6:7ee8:2ac8'}, '@timestamp': 10},
 {'event': {'category': ['network'], 'dataset': 'zeek.smtp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.120.95'}, 'destination': {'ip': '147.172.30.18'}, '@timestamp': 11},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 25, 'ip': '200.44.53.86'}, 'source': {'ip': '10.231.61.22'}, '@timestamp': 12},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 25, 'ip': 'bd8d:8e9f:3c38:5e93:2a21:f2e3:2a70:2899'}, 'source': {'ip': '172.27.220.217'}, '@timestamp': 13},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 25, 'ip': '3.79.219.137'}, 'source': {'ip': '192.168.64.185'}, '@timestamp': 14},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 465, 'ip': 'b861:3a65:7d92:a4ae:175d:4ee4:1dd9:801e'}, 'source': {'ip': '10.77.111.86'}, '@timestamp': 15},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 465, 'ip': '46.77.189.36'}, 'source': {'ip': '172.17.96.216'}, '@timestamp': 16},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 465, 'ip': '159.213.231.147'}, 'source': {'ip': '192.168.139.227'}, '@timestamp': 17},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 587, 'ip': '926e:7af:547b:40e6:6d4a:85e0:ec27:61f0'}, 'source': {'ip': '10.118.248.208'}, '@timestamp': 18},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 587, 'ip': '169.49.132.205'}, 'source': {'ip': '172.31.220.4'}, '@timestamp': 19},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 587, 'ip': '23.217.57.149'}, 'source': {'ip': '192.168.96.227'}, '@timestamp': 20},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.smtp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.59.195.236'}, 'destination': {'ip': '18bd:8fde:45bf:faed:fdf6:3054:3d28:170f'}, '@timestamp': 21},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.smtp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.23.169.85'}, 'destination': {'ip': '255.18.123.234'}, '@timestamp': 22},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.smtp'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.63.15'}, 'destination': {'ip': '171.232.70.1'}, '@timestamp': 23}]
```



### SQL Traffic to the Internet

Branch count: 30  
Document count: 30  
Index: geneve-ut-520

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:(1433 or 1521 or 3306 or 5432) or event.dataset:zeek.mysql) and
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
    192.168.0.0/16 or
    224.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  )
```

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1433, 'ip': 'e6ea:94e4:e5ac:b58c:1b43:3a53:aa79:ec59'}, 'source': {'ip': '10.214.62.131'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1433, 'ip': '119.10.44.216'}, 'source': {'ip': '172.31.81.251'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1433, 'ip': '104.129.204.102'}, 'source': {'ip': '192.168.147.58'}, '@timestamp': 2},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1521, 'ip': '149.239.86.175'}, 'source': {'ip': '10.111.13.86'}, '@timestamp': 3},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1521, 'ip': '112.141.185.70'}, 'source': {'ip': '172.27.169.243'}, '@timestamp': 4},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1521, 'ip': 'b781:36ad:968a:1fd9:42e0:603d:9566:7ca8'}, 'source': {'ip': '192.168.197.122'}, '@timestamp': 5},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3306, 'ip': '21ff:ce1f:c206:4389:a7:5646:506a:fac3'}, 'source': {'ip': '10.155.175.169'}, '@timestamp': 6},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3306, 'ip': '156.105.128.203'}, 'source': {'ip': '172.21.27.73'}, '@timestamp': 7},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3306, 'ip': '93.16.168.118'}, 'source': {'ip': '192.168.162.120'}, '@timestamp': 8},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5432, 'ip': 'cde8:687a:c169:7ee6:e8d4:8f4f:b2cc:3459'}, 'source': {'ip': '10.247.115.164'}, '@timestamp': 9},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5432, 'ip': 'e2fc:2265:c4e2:24bd:4b82:92c6:7ee8:2ac8'}, 'source': {'ip': '172.30.255.121'}, '@timestamp': 10},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5432, 'ip': '147.172.30.18'}, 'source': {'ip': '192.168.120.95'}, '@timestamp': 11},
 {'event': {'category': ['network'], 'dataset': 'zeek.mysql'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.231.61.22'}, 'destination': {'ip': '200.44.53.86'}, '@timestamp': 12},
 {'event': {'category': ['network'], 'dataset': 'zeek.mysql'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.27.220.217'}, 'destination': {'ip': 'bd8d:8e9f:3c38:5e93:2a21:f2e3:2a70:2899'}, '@timestamp': 13},
 {'event': {'category': ['network'], 'dataset': 'zeek.mysql'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.64.185'}, 'destination': {'ip': '3.79.219.137'}, '@timestamp': 14},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1433, 'ip': 'b861:3a65:7d92:a4ae:175d:4ee4:1dd9:801e'}, 'source': {'ip': '10.77.111.86'}, '@timestamp': 15},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1433, 'ip': '46.77.189.36'}, 'source': {'ip': '172.17.96.216'}, '@timestamp': 16},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1433, 'ip': '159.213.231.147'}, 'source': {'ip': '192.168.139.227'}, '@timestamp': 17},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1521, 'ip': '926e:7af:547b:40e6:6d4a:85e0:ec27:61f0'}, 'source': {'ip': '10.118.248.208'}, '@timestamp': 18},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1521, 'ip': '169.49.132.205'}, 'source': {'ip': '172.31.220.4'}, '@timestamp': 19},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 1521, 'ip': '23.217.57.149'}, 'source': {'ip': '192.168.96.227'}, '@timestamp': 20},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3306, 'ip': '18bd:8fde:45bf:faed:fdf6:3054:3d28:170f'}, 'source': {'ip': '10.59.195.236'}, '@timestamp': 21},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3306, 'ip': '255.18.123.234'}, 'source': {'ip': '172.23.169.85'}, '@timestamp': 22},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 3306, 'ip': '171.232.70.1'}, 'source': {'ip': '192.168.63.15'}, '@timestamp': 23},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5432, 'ip': '9446:8c3:3561:6e50:b44d:3a1a:9a8:8583'}, 'source': {'ip': '10.104.106.116'}, '@timestamp': 24},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5432, 'ip': '17.69.6.234'}, 'source': {'ip': '172.25.72.17'}, '@timestamp': 25},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5432, 'ip': 'a93:413a:bae1:671e:f1b6:7f1d:aef1:adfa'}, 'source': {'ip': '192.168.121.179'}, '@timestamp': 26},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.mysql'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.175.89.93'}, 'destination': {'ip': '46bd:619:2b96:b4d4:dfad:f7af:94b6:498b'}, '@timestamp': 27},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.mysql'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.27.70.224'}, 'destination': {'ip': '273:dc58:7d95:53eb:8713:9758:f2ae:3dce'}, '@timestamp': 28},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.mysql'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.143.78'}, 'destination': {'ip': '11.182.218.120'}, '@timestamp': 29}]
```



### SSH (Secure Shell) from the Internet

Branch count: 12  
Document count: 12  
Index: geneve-ut-521

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:22 or event.dataset:zeek.ssh) and
  not source.ip:(
    10.0.0.0/8 or
    127.0.0.0/8 or
    169.254.0.0/16 or
    172.16.0.0/12 or
    192.168.0.0/16 or
    224.0.0.0/4 or
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

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 22, 'ip': '10.193.74.7'}, 'source': {'ip': 'aa79:ec58:8d14:2981:f18d:f2a6:6b1f:4182'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 22, 'ip': '172.25.51.169'}, 'source': {'ip': '9a9f:e89a:c443:b67a:770a:2cd7:3602:9e1e'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 22, 'ip': '192.168.111.13'}, 'source': {'ip': '104.129.204.102'}, '@timestamp': 2},
 {'event': {'category': ['network'], 'dataset': 'zeek.ssh'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '149.239.86.175'}, 'destination': {'ip': '10.186.159.60'}, '@timestamp': 3},
 {'event': {'category': ['network'], 'dataset': 'zeek.ssh'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '112.141.185.70'}, 'destination': {'ip': '172.28.87.162'}, '@timestamp': 4},
 {'event': {'category': ['network'], 'dataset': 'zeek.ssh'}, 'network': {'transport': 'tcp'}, 'source': {'ip': 'b781:36ad:968a:1fd9:42e0:603d:9566:7ca8'}, 'destination': {'ip': '192.168.155.175'}, '@timestamp': 5},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 22, 'ip': '10.81.180.150'}, 'source': {'ip': '21ff:ce1f:c206:4389:a7:5646:506a:fac3'}, '@timestamp': 6},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 22, 'ip': '172.26.39.143'}, 'source': {'ip': '156.105.128.203'}, '@timestamp': 7},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 22, 'ip': '192.168.247.115'}, 'source': {'ip': '93.16.168.118'}, '@timestamp': 8},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.ssh'}, 'network': {'transport': 'tcp'}, 'source': {'ip': 'cde8:687a:c169:7ee6:e8d4:8f4f:b2cc:3459'}, 'destination': {'ip': '10.239.247.149'}, '@timestamp': 9},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.ssh'}, 'network': {'transport': 'tcp'}, 'source': {'ip': 'e2fc:2265:c4e2:24bd:4b82:92c6:7ee8:2ac8'}, 'destination': {'ip': '172.23.133.247'}, '@timestamp': 10},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.ssh'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '147.172.30.18'}, 'destination': {'ip': '192.168.231.61'}, '@timestamp': 11}]
```



### SSH (Secure Shell) to the Internet

Branch count: 12  
Document count: 12  
Index: geneve-ut-522

```python
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:22 or event.dataset:zeek.ssh) and
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
    192.168.0.0/16 or
    224.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  )
```

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 22, 'ip': 'e6ea:94e4:e5ac:b58c:1b43:3a53:aa79:ec59'}, 'source': {'ip': '10.214.62.131'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 22, 'ip': '119.10.44.216'}, 'source': {'ip': '172.31.81.251'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 22, 'ip': '104.129.204.102'}, 'source': {'ip': '192.168.147.58'}, '@timestamp': 2},
 {'event': {'category': ['network'], 'dataset': 'zeek.ssh'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.111.13.86'}, 'destination': {'ip': '149.239.86.175'}, '@timestamp': 3},
 {'event': {'category': ['network'], 'dataset': 'zeek.ssh'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.27.169.243'}, 'destination': {'ip': '112.141.185.70'}, '@timestamp': 4},
 {'event': {'category': ['network'], 'dataset': 'zeek.ssh'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.197.122'}, 'destination': {'ip': 'b781:36ad:968a:1fd9:42e0:603d:9566:7ca8'}, '@timestamp': 5},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 22, 'ip': '21ff:ce1f:c206:4389:a7:5646:506a:fac3'}, 'source': {'ip': '10.155.175.169'}, '@timestamp': 6},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 22, 'ip': '156.105.128.203'}, 'source': {'ip': '172.21.27.73'}, '@timestamp': 7},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 22, 'ip': '93.16.168.118'}, 'source': {'ip': '192.168.162.120'}, '@timestamp': 8},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.ssh'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '10.247.115.164'}, 'destination': {'ip': 'cde8:687a:c169:7ee6:e8d4:8f4f:b2cc:3459'}, '@timestamp': 9},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.ssh'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '172.30.255.121'}, 'destination': {'ip': 'e2fc:2265:c4e2:24bd:4b82:92c6:7ee8:2ac8'}, '@timestamp': 10},
 {'event': {'category': ['network_traffic'], 'dataset': 'zeek.ssh'}, 'network': {'transport': 'tcp'}, 'source': {'ip': '192.168.120.95'}, 'destination': {'ip': '147.172.30.18'}, '@timestamp': 11}]
```



### SSH Authorized Keys File Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-523

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
              /var/lib/docker/*)
```

```python
[{'event': {'category': ['file'], 'type': ['change']}, 'file': {'name': 'authorized_keys'}, 'process': {'executable': 'ZFy'}, '@timestamp': 0},
 {'event': {'category': ['file'], 'type': ['change']}, 'file': {'name': 'authorized_keys2'}, 'process': {'executable': 'XIU'}, '@timestamp': 1},
 {'event': {'category': ['file'], 'type': ['creation']}, 'file': {'name': 'authorized_keys'}, 'process': {'executable': 'tkN'}, '@timestamp': 2},
 {'event': {'category': ['file'], 'type': ['creation']}, 'file': {'name': 'authorized_keys2'}, 'process': {'executable': 'Ioi'}, '@timestamp': 3}]
```



### Scheduled Task Created by a Windows Script

Branch count: 1  
Document count: 2  
Index: geneve-ut-525

```python
sequence by host.id with maxspan = 30s
  [library where dll.name : "taskschd.dll" and process.name : ("cscript.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe")]
  [registry where registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions"]
```

```python
[{'dll': {'name': 'taskschd.dll'}, 'process': {'name': 'wscript.exe'}, 'event': {'category': ['library']}, 'host': {'id': 'TvC'}, '@timestamp': 0},
 {'registry': {'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\UyyFjSvILOoOHmx\\Actions'}, 'event': {'category': ['registry']}, 'host': {'id': 'TvC'}, '@timestamp': 1}]
```



### Screensaver Plist File Modified by Unexpected Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-528

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

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'name': 'com.apple.screensaver.UyyFjSvILOoOHmx.plist', 'path': '/Users/nLeOAagaiF/Library/Preferences/ByHost/mEEwVP'}, 'process': {'executable': 'YMG'}, '@timestamp': 0}]
```



### Searching for Saved Credentials via VaultCmd

Branch count: 4  
Document count: 4  
Index: geneve-ut-529

```python
process where event.type in ("start", "process_started") and
  (process.pe.original_file_name:"vaultcmd.exe" or process.name:"vaultcmd.exe") and
  process.args:"/list*"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'vaultcmd.exe'}, 'args': ['/list*']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'vaultcmd.exe', 'args': ['/list*']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'vaultcmd.exe'}, 'args': ['/list*']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'vaultcmd.exe', 'args': ['/list*']}, '@timestamp': 3}]
```



### Security Software Discovery using WMIC

Branch count: 4  
Document count: 4  
Index: geneve-ut-530

```python
process where event.type in ("start", "process_started") and
   (process.name:"wmic.exe" or process.pe.original_file_name:"wmic.exe") and
    process.args:"/namespace:\\\\root\\SecurityCenter2" and process.args:"Get"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'wmic.exe', 'args': ['/namespace:\\\\root\\SecurityCenter2', 'Get']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'wmic.exe'}, 'args': ['/namespace:\\\\root\\SecurityCenter2', 'Get']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'wmic.exe', 'args': ['/namespace:\\\\root\\SecurityCenter2', 'Get']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'wmic.exe'}, 'args': ['/namespace:\\\\root\\SecurityCenter2', 'Get']}, '@timestamp': 3}]
```



### Security Software Discovery via Grep

Branch count: 2  
Document count: 2  
Index: geneve-ut-531

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'grep', 'parent': {'executable': 'XIU'}, 'args': ['Little Snitch*', 'Avast*', 'Avira*', 'ESET*', 'BlockBlock*', '360Sec*', 'LuLu*', 'KnockKnock*', 'kav', 'KIS', 'RTProtectionDaemon*', 'Malware*', 'VShieldScanner*', 'WebProtection*', 'webinspectord*', 'McAfee*', 'isecespd*', 'macmnsvc*', 'masvc*', 'kesl*', 'avscan*', 'guard*', 'rtvscand*', 'symcfgd*', 'scmdaemon*', 'symantec*', 'sophos*', 'osquery*', 'elastic-endpoint*']}, 'user': {'id': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'grep', 'parent': {'executable': 'Ioi'}, 'args': ['Little Snitch*', 'Avast*', 'Avira*', 'ESET*', 'BlockBlock*', '360Sec*', 'LuLu*', 'KnockKnock*', 'kav', 'KIS', 'RTProtectionDaemon*', 'Malware*', 'VShieldScanner*', 'WebProtection*', 'webinspectord*', 'McAfee*', 'isecespd*', 'macmnsvc*', 'masvc*', 'kesl*', 'avscan*', 'guard*', 'rtvscand*', 'symcfgd*', 'scmdaemon*', 'symantec*', 'sophos*', 'osquery*', 'elastic-endpoint*']}, 'user': {'id': 'tkN'}, '@timestamp': 1}]
```



### Sensitive Files Compression

Branch count: 95  
Document count: 95  
Index: geneve-ut-532

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

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/root/.ssh/id_rsa']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/root/.ssh/id_rsa.pub']}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/root/.ssh/id_ed25519']}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/root/.ssh/id_ed25519.pub']}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/root/.ssh/authorized_keys']}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/root/.ssh/authorized_keys2']}, '@timestamp': 5},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/root/.ssh/known_hosts']}, '@timestamp': 6},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/root/.bash_history']}, '@timestamp': 7},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/etc/hosts']}, '@timestamp': 8},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/home/*/.ssh/id_rsa', '/home/*/.ssh/id_rsa.pub', '/home/*/.ssh/id_ed25519', '/home/*/.ssh/id_ed25519.pub', '/home/*/.ssh/authorized_keys', '/home/*/.ssh/authorized_keys2', '/home/*/.ssh/known_hosts', '/home/*/.bash_history']}, '@timestamp': 9},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/root/.aws/credentials']}, '@timestamp': 10},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/root/.aws/config']}, '@timestamp': 11},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/home/*/.aws/credentials', '/home/*/.aws/config']}, '@timestamp': 12},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/root/.docker/config.json']}, '@timestamp': 13},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/home/*/.docker/config.json']}, '@timestamp': 14},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/etc/group']}, '@timestamp': 15},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/etc/passwd']}, '@timestamp': 16},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/etc/shadow']}, '@timestamp': 17},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'zip', 'args': ['/etc/gshadow']}, '@timestamp': 18},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/root/.ssh/id_rsa']}, '@timestamp': 19},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/root/.ssh/id_rsa.pub']}, '@timestamp': 20},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/root/.ssh/id_ed25519']}, '@timestamp': 21},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/root/.ssh/id_ed25519.pub']}, '@timestamp': 22},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/root/.ssh/authorized_keys']}, '@timestamp': 23},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/root/.ssh/authorized_keys2']}, '@timestamp': 24},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/root/.ssh/known_hosts']}, '@timestamp': 25},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/root/.bash_history']}, '@timestamp': 26},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/etc/hosts']}, '@timestamp': 27},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/home/*/.ssh/id_rsa', '/home/*/.ssh/id_rsa.pub', '/home/*/.ssh/id_ed25519', '/home/*/.ssh/id_ed25519.pub', '/home/*/.ssh/authorized_keys', '/home/*/.ssh/authorized_keys2', '/home/*/.ssh/known_hosts', '/home/*/.bash_history']}, '@timestamp': 28},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/root/.aws/credentials']}, '@timestamp': 29},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/root/.aws/config']}, '@timestamp': 30},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/home/*/.aws/credentials', '/home/*/.aws/config']}, '@timestamp': 31},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/root/.docker/config.json']}, '@timestamp': 32},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/home/*/.docker/config.json']}, '@timestamp': 33},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/etc/group']}, '@timestamp': 34},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/etc/passwd']}, '@timestamp': 35},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/etc/shadow']}, '@timestamp': 36},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'tar', 'args': ['/etc/gshadow']}, '@timestamp': 37},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/root/.ssh/id_rsa']}, '@timestamp': 38},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/root/.ssh/id_rsa.pub']}, '@timestamp': 39},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/root/.ssh/id_ed25519']}, '@timestamp': 40},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/root/.ssh/id_ed25519.pub']}, '@timestamp': 41},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/root/.ssh/authorized_keys']}, '@timestamp': 42},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/root/.ssh/authorized_keys2']}, '@timestamp': 43},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/root/.ssh/known_hosts']}, '@timestamp': 44},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/root/.bash_history']}, '@timestamp': 45},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/etc/hosts']}, '@timestamp': 46},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/home/*/.ssh/id_rsa', '/home/*/.ssh/id_rsa.pub', '/home/*/.ssh/id_ed25519', '/home/*/.ssh/id_ed25519.pub', '/home/*/.ssh/authorized_keys', '/home/*/.ssh/authorized_keys2', '/home/*/.ssh/known_hosts', '/home/*/.bash_history']}, '@timestamp': 47},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/root/.aws/credentials']}, '@timestamp': 48},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/root/.aws/config']}, '@timestamp': 49},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/home/*/.aws/credentials', '/home/*/.aws/config']}, '@timestamp': 50},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/root/.docker/config.json']}, '@timestamp': 51},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/home/*/.docker/config.json']}, '@timestamp': 52},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/etc/group']}, '@timestamp': 53},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/etc/passwd']}, '@timestamp': 54},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/etc/shadow']}, '@timestamp': 55},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'gzip', 'args': ['/etc/gshadow']}, '@timestamp': 56},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/root/.ssh/id_rsa']}, '@timestamp': 57},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/root/.ssh/id_rsa.pub']}, '@timestamp': 58},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/root/.ssh/id_ed25519']}, '@timestamp': 59},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/root/.ssh/id_ed25519.pub']}, '@timestamp': 60},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/root/.ssh/authorized_keys']}, '@timestamp': 61},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/root/.ssh/authorized_keys2']}, '@timestamp': 62},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/root/.ssh/known_hosts']}, '@timestamp': 63},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/root/.bash_history']}, '@timestamp': 64},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/etc/hosts']}, '@timestamp': 65},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/home/*/.ssh/id_rsa', '/home/*/.ssh/id_rsa.pub', '/home/*/.ssh/id_ed25519', '/home/*/.ssh/id_ed25519.pub', '/home/*/.ssh/authorized_keys', '/home/*/.ssh/authorized_keys2', '/home/*/.ssh/known_hosts', '/home/*/.bash_history']}, '@timestamp': 66},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/root/.aws/credentials']}, '@timestamp': 67},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/root/.aws/config']}, '@timestamp': 68},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/home/*/.aws/credentials', '/home/*/.aws/config']}, '@timestamp': 69},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/root/.docker/config.json']}, '@timestamp': 70},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/home/*/.docker/config.json']}, '@timestamp': 71},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/etc/group']}, '@timestamp': 72},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/etc/passwd']}, '@timestamp': 73},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/etc/shadow']}, '@timestamp': 74},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'hdiutil', 'args': ['/etc/gshadow']}, '@timestamp': 75},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/root/.ssh/id_rsa']}, '@timestamp': 76},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/root/.ssh/id_rsa.pub']}, '@timestamp': 77},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/root/.ssh/id_ed25519']}, '@timestamp': 78},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/root/.ssh/id_ed25519.pub']}, '@timestamp': 79},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/root/.ssh/authorized_keys']}, '@timestamp': 80},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/root/.ssh/authorized_keys2']}, '@timestamp': 81},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/root/.ssh/known_hosts']}, '@timestamp': 82},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/root/.bash_history']}, '@timestamp': 83},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/etc/hosts']}, '@timestamp': 84},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/home/*/.ssh/id_rsa', '/home/*/.ssh/id_rsa.pub', '/home/*/.ssh/id_ed25519', '/home/*/.ssh/id_ed25519.pub', '/home/*/.ssh/authorized_keys', '/home/*/.ssh/authorized_keys2', '/home/*/.ssh/known_hosts', '/home/*/.bash_history']}, '@timestamp': 85},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/root/.aws/credentials']}, '@timestamp': 86},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/root/.aws/config']}, '@timestamp': 87},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/home/*/.aws/credentials', '/home/*/.aws/config']}, '@timestamp': 88},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/root/.docker/config.json']}, '@timestamp': 89},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/home/*/.docker/config.json']}, '@timestamp': 90},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/etc/group']}, '@timestamp': 91},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/etc/passwd']}, '@timestamp': 92},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/etc/shadow']}, '@timestamp': 93},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '7z', 'args': ['/etc/gshadow']}, '@timestamp': 94}]
```



### Sensitive Privilege SeEnableDelegationPrivilege assigned to a User

Branch count: 1  
Document count: 1  
Index: geneve-ut-533

```python
event.action: "Authorization Policy Change" and event.code:4704 and winlog.event_data.PrivilegeList:"SeEnableDelegationPrivilege"
```

```python
[{'event': {'action': 'Authorization Policy Change', 'code': 4704}, 'winlog': {'event_data': {'PrivilegeList': 'SeEnableDelegationPrivilege'}}, '@timestamp': 0}]
```



### Service Command Lateral Movement

Branch count: 4  
Document count: 8  
Index: geneve-ut-534

```python
sequence by process.entity_id with maxspan = 1m
  [process where event.type in ("start", "process_started") and
     (process.name : "sc.exe" or process.pe.original_file_name : "sc.exe") and
      process.args : "\\\\*" and process.args : ("binPath=*", "binpath=*") and
      process.args : ("create", "config", "failure", "start")]
  [network where process.name : "sc.exe" and destination.ip != "127.0.0.1"]
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sc.exe', 'args': ['\\\\*', 'binPath=*', 'binpath=*', 'create', 'config', 'failure', 'start'], 'entity_id': 'ZFy'}, '@timestamp': 0},
 {'process': {'name': 'sc.exe', 'entity_id': 'ZFy'}, 'destination': {'ip': '229.172.181.141'}, 'event': {'category': ['network']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'sc.exe'}, 'args': ['\\\\*', 'binPath=*', 'binpath=*', 'create', 'config', 'failure', 'start'], 'entity_id': 'Uyy'}, '@timestamp': 2},
 {'process': {'name': 'sc.exe', 'entity_id': 'Uyy'}, 'destination': {'ip': '73.157.79.25'}, 'event': {'category': ['network']}, '@timestamp': 3},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'sc.exe', 'args': ['\\\\*', 'binPath=*', 'binpath=*', 'create', 'config', 'failure', 'start'], 'entity_id': 'SvI'}, '@timestamp': 4},
 {'process': {'name': 'sc.exe', 'entity_id': 'SvI'}, 'destination': {'ip': '70.123.63.77'}, 'event': {'category': ['network']}, '@timestamp': 5},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'sc.exe'}, 'args': ['\\\\*', 'binPath=*', 'binpath=*', 'create', 'config', 'failure', 'start'], 'entity_id': 'Ezs'}, '@timestamp': 6},
 {'process': {'name': 'sc.exe', 'entity_id': 'Ezs'}, 'destination': {'ip': '116.114.240.76'}, 'event': {'category': ['network']}, '@timestamp': 7}]
```



### Service Control Spawned via Script Interpreter

Branch count: 2  
Document count: 2  
Index: geneve-ut-535

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sc.exe', 'parent': {'name': 'wscript.exe'}, 'args': ['config', 'create', 'start', 'delete', 'stop', 'pause']}, 'user': {'id': 'vCf'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'sc.exe'}, 'parent': {'name': 'wmic.exe'}, 'args': ['config', 'create', 'start', 'delete', 'stop', 'pause']}, 'user': {'id': 'yyF'}, '@timestamp': 1}]
```



### SharePoint Malware File Upload

Branch count: 1  
Document count: 1  
Index: geneve-ut-538

```python
event.dataset:o365.audit and event.provider:SharePoint and event.code:SharePointFileOperation and event.action:FileMalwareDetected
```

```python
[{'event': {'dataset': 'o365.audit', 'provider': 'SharePoint', 'code': 'SharePointFileOperation', 'action': 'FileMalwareDetected'}, '@timestamp': 0}]
```



### Shell Execution via Apple Scripting

Branch count: 6  
Document count: 12  
Index: geneve-ut-539

```python
sequence by host.id with maxspan=5s
 [process where event.type in ("start", "process_started", "info") and process.name == "osascript"] by process.pid
 [process where event.type in ("start", "process_started") and process.name == "sh" and process.args == "-c"] by process.parent.pid
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'osascript', 'pid': 4052611751}, 'host': {'id': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'args': ['-c'], 'parent': {'pid': 4052611751}}, 'host': {'id': 'ZFy'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'osascript', 'pid': 2056249324}, 'host': {'id': 'CfU'}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'sh', 'args': ['-c'], 'parent': {'pid': 2056249324}}, 'host': {'id': 'CfU'}, '@timestamp': 3},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'osascript', 'pid': 1235046169}, 'host': {'id': 'kNI'}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'args': ['-c'], 'parent': {'pid': 1235046169}}, 'host': {'id': 'kNI'}, '@timestamp': 5},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'osascript', 'pid': 3136644739}, 'host': {'id': 'SvI'}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'sh', 'args': ['-c'], 'parent': {'pid': 3136644739}}, 'host': {'id': 'SvI'}, '@timestamp': 7},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'osascript', 'pid': 2094521982}, 'host': {'id': 'FlE'}, '@timestamp': 8},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'sh', 'args': ['-c'], 'parent': {'pid': 2094521982}}, 'host': {'id': 'FlE'}, '@timestamp': 9},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'osascript', 'pid': 2255904345}, 'host': {'id': 'Hmx'}, '@timestamp': 10},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'sh', 'args': ['-c'], 'parent': {'pid': 2255904345}}, 'host': {'id': 'Hmx'}, '@timestamp': 11}]
```



### Signed Proxy Execution via MS WorkFolders

Branch count: 2  
Document count: 2  
Index: geneve-ut-540

```python
process where event.type in ("start","process_started")
    and process.name : "control.exe" and process.parent.name : "WorkFolders.exe"
    and not process.executable : ("?:\\Windows\\System32\\control.exe", "?:\\Windows\\SysWOW64\\control.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'control.exe', 'parent': {'name': 'WorkFolders.exe'}, 'executable': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'control.exe', 'parent': {'name': 'WorkFolders.exe'}, 'executable': 'XIU'}, '@timestamp': 1}]
```



### Socat Process Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-541

```python
event.category:process and event.type:(start or process_started) and process.name:socat and not process.args:-V
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'socat', 'args': ['ZFy']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'socat', 'args': ['XIU']}, '@timestamp': 1}]
```



### Startup Folder Persistence via Unsigned Process

Branch count: 2  
Document count: 4  
Index: geneve-ut-551

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'code_signature': {'trusted': False}, 'executable': 'C:\\Windows\\Tasks\\yXIUtkNIoixTFl.exe', 'entity_id': 'wuE'}, 'host': {'id': 'Ezs'}, '@timestamp': 0},
 {'event': {'type': ['EXp'], 'category': ['file']}, 'user': {'domain': 'WqN'}, 'file': {'path': 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\iFqsyzKNyyQDpU'}, 'host': {'id': 'Ezs'}, 'process': {'entity_id': 'wuE'}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'code_signature': {'trusted': False}, 'executable': 'C:\\Windows\\Tasks\\UDqx.exe', 'entity_id': 'LWt'}, 'host': {'id': 'VTO'}, '@timestamp': 2},
 {'event': {'type': ['imr'], 'category': ['file']}, 'user': {'domain': 'FgT'}, 'file': {'path': 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\s'}, 'host': {'id': 'VTO'}, 'process': {'entity_id': 'LWt'}, '@timestamp': 3}]
```



### Startup Persistence by a Suspicious Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-552

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

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'user': {'domain': 'XIU'}, 'file': {'path': 'C:\\Users\\kNIoixTF\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\oOHm'}, 'process': {'name': 'regsvr32.exe'}, '@timestamp': 0}]
```



### Strace Process Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-555

```python
event.category:process and event.type:(start or process_started) and process.name:strace
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'strace'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'strace'}, '@timestamp': 1}]
```



### Sublime Plugin or Application Script Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-556

```python
file where event.type in ("change", "creation") and file.extension : "py" and
  file.path : 
    (
      "/Users/*/Library/Application Support/Sublime Text*/Packages/*.py", 
      "/Applications/Sublime Text.app/Contents/MacOS/sublime.py"
    ) and
  not process.executable : 
    (
      "/Applications/Sublime Text*.app/Contents/MacOS/Sublime Text*", 
      "/usr/local/Cellar/git/*/bin/git", 
      "/usr/libexec/xpcproxy", 
      "/System/Library/PrivateFrameworks/DesktopServicesPriv.framework/Versions/A/Resources/DesktopServicesHelper", 
      "/Applications/Sublime Text.app/Contents/MacOS/plugin_host"
    )
```

```python
[{'event': {'type': ['change'], 'category': ['file']}, 'file': {'extension': 'py', 'path': '/Users/XIUtkNI/Library/Application Support/Sublime TextSvILO/Packages/Ezswu.py'}, 'process': {'executable': 'EEX'}, '@timestamp': 0},
 {'event': {'type': ['creation'], 'category': ['file']}, 'file': {'extension': 'py', 'path': '/Users/WqNVRcymEEwVP/Library/Application Support/Sublime TextMGzNfmlO/Packages/xVTOLWtimrFgT.py'}, 'process': {'executable': 'msh'}, '@timestamp': 1}]
```



### Sudoers File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-558

```python
event.category:file and event.type:change and file.path:(/etc/sudoers* or /private/etc/sudoers*)
```

```python
[{'event': {'category': ['file'], 'type': ['change']}, 'file': {'path': '/private/etc/sudoersXIUtkNI'}, '@timestamp': 0}]
```



### Suspicious .NET Code Compilation

Branch count: 2  
Document count: 2  
Index: geneve-ut-559

```python
process where event.type in ("start", "process_started") and
  process.name : ("csc.exe", "vbc.exe") and
  process.parent.name : ("wscript.exe", "mshta.exe", "cscript.exe", "wmic.exe", "svchost.exe", "rundll32.exe", "cmstp.exe", "regsvr32.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'vbc.exe', 'parent': {'name': 'wmic.exe'}}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'csc.exe', 'parent': {'name': 'wmic.exe'}}, '@timestamp': 1}]
```



### Suspicious .NET Reflection via PowerShell

Branch count: 2  
Document count: 2  
Index: geneve-ut-560

```python
event.category:process and 
  powershell.file.script_block_text : (
    "[System.Reflection.Assembly]::Load" or
    "[Reflection.Assembly]::Load"
  )
```

```python
[{'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': '[System.Reflection.Assembly]::Load'}}, '@timestamp': 0},
 {'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': '[Reflection.Assembly]::Load'}}, '@timestamp': 1}]
```



### Suspicious Activity Reported by Okta User

Branch count: 1  
Document count: 1  
Index: geneve-ut-561

```python
event.dataset:okta.system and event.action:user.account.report_suspicious_activity_by_enduser
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'user.account.report_suspicious_activity_by_enduser'}, '@timestamp': 0}]
```



### Suspicious Automator Workflows Execution

Branch count: 2  
Document count: 4  
Index: geneve-ut-562

```python
sequence by host.id with maxspan=30s
 [process where event.type in ("start", "process_started") and process.name == "automator"]
 [network where process.name:"com.apple.automator.runner"]
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'automator'}, 'host': {'id': 'ZFy'}, '@timestamp': 0},
 {'process': {'name': 'com.apple.automator.runner'}, 'event': {'category': ['network']}, 'host': {'id': 'ZFy'}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'automator'}, 'host': {'id': 'XIU'}, '@timestamp': 2},
 {'process': {'name': 'com.apple.automator.runner'}, 'event': {'category': ['network']}, 'host': {'id': 'XIU'}, '@timestamp': 3}]
```



### Suspicious Calendar File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-564

```python
event.category:file and event.action:modification and
  file.path:/Users/*/Library/Calendars/*.calendar/Events/*.ics and
  process.executable:
  (* and not 
    (
      /System/Library/* or 
      /System/Applications/Calendar.app/Contents/MacOS/* or 
      /usr/libexec/xpcproxy or 
      /sbin/launchd or 
      /Applications/*
    )
  )
```

```python
[{'event': {'category': ['file'], 'action': 'modification'}, 'file': {'path': '/Users/XIUtkNI/Library/Calendars/SvILO.calendar/Events/Ezswu.ics'}, 'process': {'executable': 'EEX'}, '@timestamp': 0}]
```



### Suspicious CertUtil Commands

Branch count: 2  
Document count: 2  
Index: geneve-ut-565

```python
process where event.type == "start" and
  (process.name : "certutil.exe" or process.pe.original_file_name == "CertUtil.exe") and 
  process.args : ("?decode", "?encode", "?urlcache", "?verifyctl", "?encodehex", "?decodehex", "?exportPFX")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'certutil.exe', 'args': ['?decode', '?encode', '?urlcache', '?verifyctl', '?encodehex', '?decodehex', '?exportPFX']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'CertUtil.exe'}, 'args': ['?decode', '?encode', '?urlcache', '?verifyctl', '?encodehex', '?decodehex', '?exportPFX']}, '@timestamp': 1}]
```



### Suspicious Child Process of Adobe Acrobat Reader Update Service

Branch count: 2  
Document count: 2  
Index: geneve-ut-566

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

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'parent': {'name': 'com.adobe.ARMDC.SMJobBlessHelper'}, 'executable': 'ZFy'}, 'user': {'name': 'root'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'parent': {'name': 'com.adobe.ARMDC.SMJobBlessHelper'}, 'executable': 'XIU'}, 'user': {'name': 'root'}, '@timestamp': 1}]
```



### Suspicious Cmd Execution via WMI

Branch count: 2  
Document count: 2  
Index: geneve-ut-567

```python
process where event.type in ("start", "process_started") and
 process.parent.name : "WmiPrvSE.exe" and process.name : "cmd.exe" and
 process.args : "\\\\127.0.0.1\\*" and process.args : ("2>&1", "1>")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'WmiPrvSE.exe'}, 'name': 'cmd.exe', 'args': ['\\\\127.0.0.1\\*', '2>&1', '1>']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'WmiPrvSE.exe'}, 'name': 'cmd.exe', 'args': ['\\\\127.0.0.1\\*', '2>&1', '1>']}, '@timestamp': 1}]
```



### Suspicious DLL Loaded for Persistence or Privilege Escalation

Branch count: 2  
Document count: 2  
Index: geneve-ut-568

```python
library where dll.name :
  (
  "wlbsctrl.dll",
  "wbemcomn.dll",
  "WptsExtensions.dll",
  "Tsmsisrv.dll",
  "TSVIPSrv.dll",
  "Msfte.dll",
  "wow64log.dll",
  "WindowsCoreDeviceInfo.dll",
  "Ualapi.dll",
  "wlanhlp.dll",
  "phoneinfo.dll",
  "EdgeGdi.dll",
  "cdpsgshims.dll",
  "windowsperformancerecordercontrol.dll",
  "diagtrack_win.dll"
  ) and 
not (dll.code_signature.subject_name : ("Microsoft Windows", "Microsoft Corporation") and dll.code_signature.status : "trusted")
```

```python
[{'dll': {'name': 'wow64log.dll', 'code_signature': {'subject_name': 'FyX'}}, 'event': {'category': ['library']}, '@timestamp': 0},
 {'dll': {'name': 'wbemcomn.dll', 'code_signature': {'status': 'fUy'}}, 'event': {'category': ['library']}, '@timestamp': 1}]
```



### Suspicious Emond Child Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-569

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'emond'}, 'name': 'touch'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'emond'}, 'name': 'pwsh'}, '@timestamp': 1}]
```



### Suspicious Endpoint Security Parent Process

Branch count: 3  
Document count: 3  
Index: geneve-ut-570

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'esensor.exe', 'parent': {'executable': 'vCf'}}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'esensor.exe', 'parent': {'executable': 'yyF'}}, '@timestamp': 1},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'name': 'elastic-endpoint.exe', 'parent': {'executable': 'oix'}}, '@timestamp': 2}]
```



### Suspicious Execution from a Mounted Device

Branch count: 1  
Document count: 1  
Index: geneve-ut-572

```python
process where event.type == "start" and process.executable : "C:\\*" and
  (process.working_directory : "?:\\" and not process.working_directory: "C:\\") and
  process.parent.name : "explorer.exe" and
  process.name : ("rundll32.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "regsvr32.exe",
                  "cscript.exe", "wscript.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'executable': 'C:\\XIUtkNI', 'working_directory': 'k:\\', 'parent': {'name': 'explorer.exe'}, 'name': 'rundll32.exe'}, '@timestamp': 0}]
```



### Suspicious Execution via Scheduled Task

Branch count: 16  
Document count: 16  
Index: geneve-ut-573

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'cscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'wscript.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'Cmd.Exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'MSHTA.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 5},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'REGSVR32.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 6},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'MSBuild.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 7},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'InstallUtil.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 8},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'RegAsm.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 9},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'RegSvcs.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 10},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'msxsl.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 11},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'CONTROL.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 12},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'EXPLORER.EXE'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 13},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'Microsoft.Workflow.Compiler.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 14},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['Schedule']}, 'pe': {'original_file_name': 'msiexec.exe'}, 'args': ['C:\\Users\\*', 'C:\\ProgramData\\*', 'C:\\Windows\\Temp\\*', 'C:\\Windows\\Tasks\\*', 'C:\\PerfLogs\\*', 'C:\\Intel\\*', 'C:\\Windows\\Debug\\*', 'C:\\HP\\*']}, '@timestamp': 15}]
```



### Suspicious Explorer Child Process

Branch count: 16  
Document count: 16  
Index: geneve-ut-574

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'regsvr32.exe', 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'cscript.exe'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'wscript.exe'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'PowerShell.EXE'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 5},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'MSHTA.EXE'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 6},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'REGSVR32.EXE'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 7},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'wscript.exe', 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 8},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'cscript.exe'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 9},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'wscript.exe'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 10},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'PowerShell.EXE'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 11},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 12},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'Cmd.Exe'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 13},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'MSHTA.EXE'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 14},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'REGSVR32.EXE'}, 'parent': {'name': 'explorer.exe', 'args': ['-Embedding']}}, '@timestamp': 15}]
```



### Suspicious Hidden Child Process of Launchd

Branch count: 2  
Document count: 2  
Index: geneve-ut-575

```python
event.category:process and event.type:(start or process_started) and
 process.name:.* and process.parent.executable:/sbin/launchd
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': '.XIUtkNI', 'parent': {'executable': '/sbin/launchd'}}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': '.ixTFlEzswuEEXp', 'parent': {'executable': '/sbin/launchd'}}, '@timestamp': 1}]
```



### Suspicious Image Load (taskschd.dll) from MS Office

Branch count: 1  
Document count: 1  
Index: geneve-ut-576

```python
library where process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE", "MSACCESS.EXE") and
  event.action : "load" and
  event.category : "library" and
  dll.name : "taskschd.dll"
```

```python
[{'process': {'name': 'WINWORD.EXE'}, 'event': {'action': 'load', 'category': ['library', 'library']}, 'dll': {'name': 'taskschd.dll'}, '@timestamp': 0}]
```



### Suspicious JAVA Child Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-578

```python
process where event.type in ("start", "process_started") and
  process.parent.name : "java" and
  process.name : ("sh", "bash", "dash", "ksh", "tcsh", "zsh", "curl", "wget")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'java'}, 'name': 'zsh'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'java'}, 'name': 'wget'}, '@timestamp': 1}]
```



### Suspicious MS Office Child Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-579

```python
process where event.type in ("start", "process_started") and
  process.parent.name : ("eqnedt32.exe", "excel.exe", "fltldr.exe", "msaccess.exe", "mspub.exe", "powerpnt.exe", "winword.exe") and
  process.name : ("Microsoft.Workflow.Compiler.exe", "arp.exe", "atbroker.exe", "bginfo.exe", "bitsadmin.exe", "cdb.exe", "certutil.exe",
                "cmd.exe", "cmstp.exe", "control.exe", "cscript.exe", "csi.exe", "dnx.exe", "dsget.exe", "dsquery.exe", "forfiles.exe", 
                "fsi.exe", "ftp.exe", "gpresult.exe", "hostname.exe", "ieexec.exe", "iexpress.exe", "installutil.exe", "ipconfig.exe", 
                "mshta.exe", "msxsl.exe", "nbtstat.exe", "net.exe", "net1.exe", "netsh.exe", "netstat.exe", "nltest.exe", "odbcconf.exe", 
                "ping.exe", "powershell.exe", "pwsh.exe", "qprocess.exe", "quser.exe", "qwinsta.exe", "rcsi.exe", "reg.exe", "regasm.exe", 
                "regsvcs.exe", "regsvr32.exe", "sc.exe", "schtasks.exe", "systeminfo.exe", "tasklist.exe", "tracert.exe", "whoami.exe",
                "wmic.exe", "wscript.exe", "xwizard.exe", "explorer.exe", "rundll32.exe", "hh.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'mspub.exe'}, 'name': 'xwizard.exe'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'msaccess.exe'}, 'name': 'mshta.exe'}, '@timestamp': 1}]
```



### Suspicious MS Outlook Child Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-580

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'outlook.exe'}, 'name': 'reg.exe'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'outlook.exe'}, 'name': 'nltest.exe'}, '@timestamp': 1}]
```



### Suspicious Managed Code Hosting Process

Branch count: 1  
Document count: 2  
Index: geneve-ut-581

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'wscript.exe', 'entity_id': 'vCf'}, '@timestamp': 0},
 {'event': {'type': ['Uyy'], 'category': ['file']}, 'file': {'name': 'mshta.exe.log'}, 'process': {'entity_id': 'vCf'}, '@timestamp': 1}]
```



### Suspicious PDF Reader Child Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-582

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'FoxitReader.exe'}, 'name': 'nbtstat.exe'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'AcroRd32.exe'}, 'name': 'mshta.exe'}, '@timestamp': 1}]
```



### Suspicious Portable Executable Encoded in Powershell Script

Branch count: 1  
Document count: 1  
Index: geneve-ut-583

```python
event.category:process and 
  powershell.file.script_block_text : (
    TVqQAAMAAAAEAAAA
  )
```

```python
[{'event': {'category': ['process']}, 'powershell': {'file': {'script_block_text': 'TVqQAAMAAAAEAAAA'}}, '@timestamp': 0}]
```



### Suspicious Print Spooler File Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-586

```python
file where event.type : "deletion" and
 not process.name : ("spoolsv.exe", "dllhost.exe", "explorer.exe") and
 file.path : "?:\\Windows\\System32\\spool\\drivers\\x64\\3\\*.dll"
```

```python
[{'event': {'type': ['deletion'], 'category': ['file']}, 'process': {'name': 'ZFy'}, 'file': {'path': 'y:\\Windows\\System32\\spool\\drivers\\x64\\3\\kNIoixTF.dll'}, '@timestamp': 0}]
```



### Suspicious PrintSpooler SPL File Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-588

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

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'extension': 'spl', 'path': 'y:\\Windows\\System32\\spool\\PRINTERS\\kNIoixTF'}, 'process': {'name': 'lEz'}, '@timestamp': 0}]
```



### Suspicious PrintSpooler Service Executable File Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-589

```python
file where event.type != "deletion" and process.name : "spoolsv.exe" and
  file.extension : ("exe", "dll") and
  not file.path : ("?:\\Windows\\System32\\spool\\*", "?:\\Windows\\Temp\\*", "?:\\Users\\*")
```

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'process': {'name': 'spoolsv.exe'}, 'file': {'extension': 'dll', 'path': 'Utk'}, '@timestamp': 0}]
```



### Suspicious Process Creation CallTrace

Branch count: 1  
Document count: 2  
Index: geneve-ut-591

```python
sequence by host.id with maxspan=1m
  [process where event.code == "1" and
   /* sysmon process creation */
   process.parent.name : ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "eqnedt32.exe",
                          "fltldr.exe", "mspub.exe", "msaccess.exe", "powershell.exe", "pwsh.exe",
                          "cscript.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
                          "wmic.exe", "cmstp.exe", "msxsl.exe")] by process.parent.entity_id, process.entity_id
  [process where event.code == "10" and
   /* Sysmon process access event from unknown module */
   winlog.event_data.CallTrace : "*UNKNOWN*"] by process.entity_id, winlog.event_data.TargetProcessGUID
```

```python
[{'event': {'code': '1', 'category': ['process']}, 'process': {'parent': {'name': 'winword.exe', 'entity_id': 'Uyy'}, 'entity_id': 'FjS'}, 'host': {'id': 'vCf'}, '@timestamp': 0},
 {'event': {'code': '10', 'category': ['process']}, 'winlog': {'event_data': {'CallTrace': 'ILOoOHmxUNKNOWNEEXpWqNVR', 'TargetProcessGUID': 'FjS'}}, 'host': {'id': 'vCf'}, 'process': {'entity_id': 'Uyy'}, '@timestamp': 1}]
```



### Suspicious Process Execution via Renamed PsExec Executable

Branch count: 3  
Document count: 3  
Index: geneve-ut-592

```python
process where event.type in ("start", "process_started", "info") and
  process.pe.original_file_name : "psexesvc.exe" and not process.name : "PSEXESVC.exe"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'psexesvc.exe'}, 'name': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'psexesvc.exe'}, 'name': 'XIU'}, '@timestamp': 1},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'psexesvc.exe'}, 'name': 'tkN'}, '@timestamp': 2}]
```



### Suspicious Process from Conhost

Branch count: 2  
Document count: 2  
Index: geneve-ut-593

```python
process where event.type in ("start", "process_started") and
  process.parent.name : "conhost.exe" and
  not process.executable : ("?:\\Windows\\splwow64.exe", "?:\\Windows\\System32\\WerFault.exe", "?:\\Windows\\System32\\conhost.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'conhost.exe'}, 'executable': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'conhost.exe'}, 'executable': 'XIU'}, '@timestamp': 1}]
```



### Suspicious RDP ActiveX Client Loaded

Branch count: 1  
Document count: 1  
Index: geneve-ut-594

```python
library where dll.name : "mstscax.dll" and
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

```python
[{'dll': {'name': 'mstscax.dll'}, 'process': {'executable': '\\\\XIUtkNI'}, 'event': {'category': ['library']}, '@timestamp': 0}]
```



### Suspicious Remote Registry Access via SeBackupPrivilege

Branch count: 1  
Document count: 2  
Index: geneve-ut-595

```python
sequence by host.id, winlog.event_data.SubjectLogonId with maxspan=1m
 [iam where event.action == "logged-in-special"  and
  winlog.event_data.PrivilegeList : "SeBackupPrivilege"]
 [any where event.action == "Detailed File Share" and winlog.event_data.RelativeTargetName : "winreg"]
```

```python
[{'event': {'action': 'logged-in-special', 'category': ['iam']}, 'winlog': {'event_data': {'PrivilegeList': 'SeBackupPrivilege', 'SubjectLogonId': 'XIU'}}, 'host': {'id': 'ZFy'}, '@timestamp': 0},
 {'event': {'action': 'Detailed File Share'}, 'winlog': {'event_data': {'RelativeTargetName': 'winreg', 'SubjectLogonId': 'XIU'}}, 'host': {'id': 'ZFy'}, '@timestamp': 1}]
```



### Suspicious Script Object Execution

Branch count: 2  
Document count: 4  
Index: geneve-ut-596

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'code_signature': {'subject_name': 'Microsoft Corporation', 'trusted': True}, 'executable': 'ZFy', 'entity_id': 'XIU'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['library']}, 'dll': {'name': 'scrobj.dll'}, 'process': {'entity_id': 'XIU'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'code_signature': {'subject_name': 'Microsoft Windows', 'trusted': True}, 'executable': 'tkN', 'entity_id': 'Ioi'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['library']}, 'dll': {'name': 'scrobj.dll'}, 'process': {'entity_id': 'Ioi'}, '@timestamp': 3}]
```



### Suspicious SolarWinds Child Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-597

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'SolarWinds.BusinessLayerHostx64.exe'}, 'name': 'vCf'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'SolarWinds.BusinessLayerHostx64.exe'}, 'name': 'yyF'}, '@timestamp': 1}]
```



### Suspicious WMI Image Load from MS Office

Branch count: 1  
Document count: 1  
Index: geneve-ut-599

```python
library where process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE", "MSACCESS.EXE") and
  event.action : "load" and
  event.category : "library" and
  dll.name : "wmiutils.dll"
```

```python
[{'process': {'name': 'WINWORD.EXE'}, 'event': {'action': 'load', 'category': ['library', 'library']}, 'dll': {'name': 'wmiutils.dll'}, '@timestamp': 0}]
```



### Suspicious WerFault Child Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-601

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'WerFault.exe'}, 'name': 'ZFy', 'args': ['XIU']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'WerFault.exe'}, 'name': 'tkN', 'args': ['Ioi']}, '@timestamp': 1}]
```



### Suspicious Zoom Child Process

Branch count: 3  
Document count: 3  
Index: geneve-ut-602

```python
process where event.type in ("start", "process_started", "info") and
 process.parent.name : "Zoom.exe" and process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'Zoom.exe'}, 'name': 'pwsh.exe'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'Zoom.exe'}, 'name': 'pwsh.exe'}, '@timestamp': 1},
 {'event': {'type': ['info'], 'category': ['process']}, 'process': {'parent': {'name': 'Zoom.exe'}, 'name': 'cmd.exe'}, '@timestamp': 2}]
```



### Suspicious macOS MS Office Child Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-603

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'Microsoft Word'}, 'name': 'sh', 'args': ['vCf']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'Microsoft PowerPoint'}, 'name': 'sh', 'args': ['kNI']}, '@timestamp': 1}]
```



### Svchost spawning Cmd

Branch count: 2  
Document count: 2  
Index: geneve-ut-604

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe'}, 'name': 'cmd.exe', 'pe': {'original_file_name': 'ZFy'}}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe'}, 'name': 'cmd.exe', 'args': ['XIU']}, '@timestamp': 1}]
```



### System Log File Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-606

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
    )
```

```python
[{'event': {'type': ['deletion'], 'category': ['file']}, 'file': {'path': '/var/log/wtmp'}, '@timestamp': 0}]
```



### System Shells via Services

Branch count: 2  
Document count: 2  
Index: geneve-ut-607

```python
process where event.type in ("start", "process_started") and
  process.parent.name : "services.exe" and
  process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe") and

  /* Third party FP's */
  not process.args : "NVDisplay.ContainerLocalSystem"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'services.exe'}, 'name': 'pwsh.exe', 'args': ['vCf']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'services.exe'}, 'name': 'pwsh.exe', 'args': ['yyF']}, '@timestamp': 1}]
```



### SystemKey Access via Command Line

Branch count: 4  
Document count: 4  
Index: geneve-ut-608

```python
event.category:process and event.type:(start or process_started) and
  process.args:("/private/var/db/SystemKey" or "/var/db/SystemKey")
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['/private/var/db/SystemKey']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['/var/db/SystemKey']}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'args': ['/private/var/db/SystemKey']}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'args': ['/var/db/SystemKey']}, '@timestamp': 3}]
```



### TCC Bypass via Mounted APFS Snapshot Access

Branch count: 2  
Document count: 2  
Index: geneve-ut-609

```python
event.category : process and event.type : (start or process_started) and process.name : mount_apfs and
  process.args : (/System/Volumes/Data and noowners)
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'mount_apfs', 'args': ['/System/Volumes/Data', 'noowners']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'mount_apfs', 'args': ['/System/Volumes/Data', 'noowners']}, '@timestamp': 1}]
```



### TCP Port 8000 Activity to the Internet

Branch count: 6  
Document count: 6  
Index: geneve-ut-610

```python
event.category:(network or network_traffic) and network.transport:tcp and destination.port:8000 and
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
    192.168.0.0/16 or
    224.0.0.0/4 or
    "::1" or
    "FE80::/10" or
    "FF00::/8"
  )
```

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 8000, 'ip': 'e6ea:94e4:e5ac:b58c:1b43:3a53:aa79:ec59'}, 'source': {'ip': '10.214.62.131'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 8000, 'ip': '119.10.44.216'}, 'source': {'ip': '172.31.81.251'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 8000, 'ip': '104.129.204.102'}, 'source': {'ip': '192.168.147.58'}, '@timestamp': 2},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 8000, 'ip': '149.239.86.175'}, 'source': {'ip': '10.111.13.86'}, '@timestamp': 3},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 8000, 'ip': '112.141.185.70'}, 'source': {'ip': '172.27.169.243'}, '@timestamp': 4},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 8000, 'ip': 'b781:36ad:968a:1fd9:42e0:603d:9566:7ca8'}, 'source': {'ip': '192.168.197.122'}, '@timestamp': 5}]
```



### Tampering of Bash Command-Line History

Branch count: 10  
Document count: 10  
Index: geneve-ut-611

```python
process where event.type in ("start", "process_started") and
 (
  (process.args : ("rm", "echo") and process.args : (".bash_history", "/root/.bash_history", "/home/*/.bash_history")) or
  (process.name : "history" and process.args : "-c") or
  (process.args : "export" and process.args : ("HISTFILE=/dev/null", "HISTFILESIZE=0")) or
  (process.args : "unset" and process.args : "HISTFILE") or
  (process.args : "set" and process.args : "history" and process.args : "+o")
 )
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['rm', 'echo', '.bash_history', '/root/.bash_history', '/home/*/.bash_history']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'history', 'args': ['-c']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['export', 'HISTFILE=/dev/null', 'HISTFILESIZE=0']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['unset', 'HISTFILE']}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['set', 'history', '+o']}, '@timestamp': 4},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'args': ['rm', 'echo', '.bash_history', '/root/.bash_history', '/home/*/.bash_history']}, '@timestamp': 5},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'history', 'args': ['-c']}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'args': ['export', 'HISTFILE=/dev/null', 'HISTFILESIZE=0']}, '@timestamp': 7},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'args': ['unset', 'HISTFILE']}, '@timestamp': 8},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'args': ['set', 'history', '+o']}, '@timestamp': 9}]
```



### Telnet Port Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-612

```python
event.category:(network or network_traffic) and network.transport:tcp and destination.port:23
```

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 23}, '@timestamp': 0},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 23}, '@timestamp': 1}]
```



### Third-party Backup Files Deleted via Unexpected Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-613

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

```python
[{'event': {'type': ['deletion'], 'category': ['file']}, 'file': {'extension': 'VIB'}, 'process': {'executable': 'TvC'}, '@timestamp': 0},
 {'event': {'type': ['deletion'], 'category': ['file']}, 'file': {'extension': 'BKF'}, 'process': {'executable': 'fUy'}, '@timestamp': 1}]
```



### Threat Detected by Okta ThreatInsight

Branch count: 1  
Document count: 1  
Index: geneve-ut-614

```python
event.dataset:okta.system and event.action:security.threat.detected
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'security.threat.detected'}, '@timestamp': 0}]
```



### Timestomping using Touch Command

Branch count: 1  
Document count: 1  
Index: geneve-ut-618

```python
process where event.type == "start" and
 process.name : "touch" and user.id != "0" and
 process.args : ("-r", "-t", "-a*","-m*") and
 not process.args : ("/usr/lib/go-*/bin/go", "/usr/lib/dracut/dracut-functions.sh", "/tmp/KSInstallAction.*/m/.patch/*")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'touch', 'args': ['-r', '-t', '-a*', '-m*']}, 'user': {'id': 'ZFy'}, '@timestamp': 0}]
```



### Tor Activity to the Internet

Branch count: 12  
Document count: 12  
Index: geneve-ut-619

```python
event.category:(network or network_traffic) and network.transport:tcp and destination.port:(9001 or 9030) and
  source.ip:(10.0.0.0/8 or
             172.16.0.0/12 or
             192.168.0.0/16) and

  not destination.ip:(10.0.0.0/8 or
                      127.0.0.0/8 or
                      169.254.0.0/16 or
                      172.16.0.0/12 or
                      192.168.0.0/16 or
                      224.0.0.0/4 or
                      "::1" or
                      "FE80::/10" or
                      "FF00::/8")
```

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 9001, 'ip': 'e6ea:94e4:e5ac:b58c:1b43:3a53:aa79:ec59'}, 'source': {'ip': '10.214.62.131'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 9001, 'ip': '119.10.44.216'}, 'source': {'ip': '172.31.81.251'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 9001, 'ip': '104.129.204.102'}, 'source': {'ip': '192.168.147.58'}, '@timestamp': 2},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 9030, 'ip': '149.239.86.175'}, 'source': {'ip': '10.111.13.86'}, '@timestamp': 3},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 9030, 'ip': '112.141.185.70'}, 'source': {'ip': '172.27.169.243'}, '@timestamp': 4},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 9030, 'ip': 'b781:36ad:968a:1fd9:42e0:603d:9566:7ca8'}, 'source': {'ip': '192.168.197.122'}, '@timestamp': 5},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 9001, 'ip': '21ff:ce1f:c206:4389:a7:5646:506a:fac3'}, 'source': {'ip': '10.155.175.169'}, '@timestamp': 6},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 9001, 'ip': '156.105.128.203'}, 'source': {'ip': '172.21.27.73'}, '@timestamp': 7},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 9001, 'ip': '93.16.168.118'}, 'source': {'ip': '192.168.162.120'}, '@timestamp': 8},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 9030, 'ip': 'cde8:687a:c169:7ee6:e8d4:8f4f:b2cc:3459'}, 'source': {'ip': '10.247.115.164'}, '@timestamp': 9},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 9030, 'ip': 'e2fc:2265:c4e2:24bd:4b82:92c6:7ee8:2ac8'}, 'source': {'ip': '172.30.255.121'}, '@timestamp': 10},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 9030, 'ip': '147.172.30.18'}, 'source': {'ip': '192.168.120.95'}, '@timestamp': 11}]
```



### Trusted Developer Application Usage

Branch count: 4  
Document count: 4  
Index: geneve-ut-620

```python
event.category:process and event.type:(start or process_started) and process.name:(MSBuild.exe or msxsl.exe)
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'MSBuild.exe'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'msxsl.exe'}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'MSBuild.exe'}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'msxsl.exe'}, '@timestamp': 3}]
```



### UAC Bypass Attempt via Elevated COM Internet Explorer Add-On Installer

Branch count: 2  
Document count: 2  
Index: geneve-ut-621

```python
process where event.type in ("start", "process_started") and
 process.executable : "C:\\*\\AppData\\*\\Temp\\IDC*.tmp\\*.exe" and
 process.parent.name : "ieinstal.exe" and process.parent.args : "-Embedding"

 /* uncomment once in winlogbeat */
 /* and not (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true) */
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'executable': 'C:\\XIUtkNI\\AppData\\SvILO\\Temp\\IDCEzswu.tmp\\nLeOAagaiF.exe', 'parent': {'name': 'ieinstal.exe', 'args': ['-Embedding']}}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'executable': 'C:\\syzK\\AppData\\PYMGzNfmlOPZR\\Temp\\IDCOL.tmp\\WCiMZOfHaTDgzRJ.exe', 'parent': {'name': 'ieinstal.exe', 'args': ['-Embedding']}}, '@timestamp': 1}]
```



### UAC Bypass Attempt via Privileged IFileOperation COM Interface

Branch count: 1  
Document count: 1  
Index: geneve-ut-622

```python
file where event.type : "change" and process.name : "dllhost.exe" and
  /* Known modules names side loaded into process running with high or system integrity level for UAC Bypass, update here for new modules */
  file.name : ("wow64log.dll", "comctl32.dll", "DismCore.dll", "OskSupport.dll", "duser.dll", "Accessibility.ni.dll") and
  /* has no impact on rule logic just to avoid OS install related FPs */
  not file.path : ("C:\\Windows\\SoftwareDistribution\\*", "C:\\Windows\\WinSxS\\*")
```

```python
[{'event': {'type': ['change'], 'category': ['file']}, 'process': {'name': 'dllhost.exe'}, 'file': {'name': 'duser.dll', 'path': 'TvC'}, '@timestamp': 0}]
```



### UAC Bypass Attempt via Windows Directory Masquerading

Branch count: 2  
Document count: 2  
Index: geneve-ut-623

```python
process where event.type in ("start", "process_started") and
  process.args : ("C:\\Windows \\system32\\*.exe", "C:\\Windows \\SysWOW64\\*.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['C:\\Windows \\system32\\*.exe', 'C:\\Windows \\SysWOW64\\*.exe']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'args': ['C:\\Windows \\system32\\*.exe', 'C:\\Windows \\SysWOW64\\*.exe']}, '@timestamp': 1}]
```



### UAC Bypass Attempt with IEditionUpgradeManager Elevated COM Interface

Branch count: 2  
Document count: 2  
Index: geneve-ut-624

```python
process where event.type in ("start", "process_started") and process.name : "Clipup.exe" and
  not process.executable : "C:\\Windows\\System32\\ClipUp.exe" and process.parent.name : "dllhost.exe" and
  /* CLSID of the Elevated COM Interface IEditionUpgradeManager */
  process.parent.args : "/Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'Clipup.exe', 'executable': 'ZFy', 'parent': {'name': 'dllhost.exe', 'args': ['/Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}']}}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'Clipup.exe', 'executable': 'XIU', 'parent': {'name': 'dllhost.exe', 'args': ['/Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}']}}, '@timestamp': 1}]
```



### UAC Bypass via DiskCleanup Scheduled Task Hijack

Branch count: 1  
Document count: 1  
Index: geneve-ut-625

```python
process where event.type == "start" and
 process.args : "/autoclean" and process.args : "/d" and
 not process.executable : ("C:\\Windows\\System32\\cleanmgr.exe",
                           "C:\\Windows\\SysWOW64\\cleanmgr.exe",
                           "C:\\Windows\\System32\\taskhostw.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['/autoclean', '/d'], 'executable': 'ZFy'}, '@timestamp': 0}]
```



### UAC Bypass via ICMLuaUtil Elevated COM Interface

Branch count: 4  
Document count: 4  
Index: geneve-ut-626

```python
process where event.type in ("start", "process_started") and
 process.parent.name == "dllhost.exe" and
 process.parent.args in ("/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}", "/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}") and
 process.pe.original_file_name != "WerFault.exe"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'dllhost.exe', 'args': ['/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}']}, 'pe': {'original_file_name': 'ZFy'}}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'dllhost.exe', 'args': ['/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}']}, 'pe': {'original_file_name': 'XIU'}}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'dllhost.exe', 'args': ['/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}']}, 'pe': {'original_file_name': 'tkN'}}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'dllhost.exe', 'args': ['/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}']}, 'pe': {'original_file_name': 'Ioi'}}, '@timestamp': 3}]
```



### UAC Bypass via Windows Firewall Snap-In Hijack

Branch count: 2  
Document count: 2  
Index: geneve-ut-627

```python
process where event.type in ("start", "process_started") and
 process.parent.name == "mmc.exe" and
 /* process.Ext.token.integrity_level_name == "high" can be added in future for tuning */
 /* args of the Windows Firewall SnapIn */
  process.parent.args == "WF.msc" and process.name != "WerFault.exe"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'mmc.exe', 'args': ['WF.msc']}, 'name': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'mmc.exe', 'args': ['WF.msc']}, 'name': 'XIU'}, '@timestamp': 1}]
```



### Unauthorized Access to an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-628

```python
event.dataset:okta.system and event.action:app.generic.unauth_app_access_attempt
```

```python
[{'event': {'dataset': 'okta.system', 'action': 'app.generic.unauth_app_access_attempt'}, '@timestamp': 0}]
```



### Unexpected Child Process of macOS Screensaver Engine

Branch count: 1  
Document count: 1  
Index: geneve-ut-630

```python
process where event.type == "start" and process.parent.name == "ScreenSaverEngine"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'ScreenSaverEngine'}}, '@timestamp': 0}]
```



### Unusual Child Process from a System Virtual Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-632

```python
process where event.type in ("start", "process_started") and
  process.parent.pid == 4 and
  not process.executable : ("Registry", "MemCompression", "?:\\Windows\\System32\\smss.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'pid': 4}, 'executable': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'pid': 4}, 'executable': 'XIU'}, '@timestamp': 1}]
```



### Unusual Child Process of dns.exe

Branch count: 1  
Document count: 1  
Index: geneve-ut-633

```python
process where event.type == "start" and process.parent.name : "dns.exe" and
  not process.name : "conhost.exe"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'dns.exe'}, 'name': 'ZFy'}, '@timestamp': 0}]
```



### Unusual Child Processes of RunDLL32

Branch count: 8  
Document count: 16  
Index: geneve-ut-634

```python
sequence with maxspan=1h
  [process where event.type in ("start", "process_started") and
     (process.name : "rundll32.exe" or process.pe.original_file_name == "RUNDLL32.EXE") and
      process.args_count == 1
  ] by process.entity_id
  [process where event.type in ("start", "process_started") and process.parent.name : "rundll32.exe"
  ] by process.parent.entity_id
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'rundll32.exe', 'args_count': 1, 'entity_id': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'rundll32.exe', 'entity_id': 'ZFy'}}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'rundll32.exe', 'args_count': 1, 'entity_id': 'XIU'}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'rundll32.exe', 'entity_id': 'XIU'}}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'args_count': 1, 'entity_id': 'tkN'}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'rundll32.exe', 'entity_id': 'tkN'}}, '@timestamp': 5},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'args_count': 1, 'entity_id': 'Ioi'}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'rundll32.exe', 'entity_id': 'Ioi'}}, '@timestamp': 7},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'rundll32.exe', 'args_count': 1, 'entity_id': 'xTF'}, '@timestamp': 8},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'rundll32.exe', 'entity_id': 'xTF'}}, '@timestamp': 9},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'rundll32.exe', 'args_count': 1, 'entity_id': 'lEz'}, '@timestamp': 10},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'rundll32.exe', 'entity_id': 'lEz'}}, '@timestamp': 11},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'args_count': 1, 'entity_id': 'swu'}, '@timestamp': 12},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'rundll32.exe', 'entity_id': 'swu'}}, '@timestamp': 13},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'RUNDLL32.EXE'}, 'args_count': 1, 'entity_id': 'EEX'}, '@timestamp': 14},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'rundll32.exe', 'entity_id': 'EEX'}}, '@timestamp': 15}]
```



### Unusual Executable File Creation by a System Critical Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-638

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

```python
[{'event': {'type': ['ZFy'], 'category': ['file']}, 'file': {'extension': 'dll'}, 'process': {'name': 'userinit.exe'}, '@timestamp': 0}]
```



### Unusual File Creation - Alternate Data Stream

Branch count: 1  
Document count: 1  
Index: geneve-ut-639

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

```python
[{'event': {'type': ['creation'], 'category': ['file']}, 'file': {'path': 'C:\\XIUtkNI:SvILO', 'extension': 'exe'}, '@timestamp': 0}]
```



### Unusual File Modification by dns.exe

Branch count: 3  
Document count: 3  
Index: geneve-ut-640

```python
file where process.name : "dns.exe" and event.type in ("creation", "deletion", "change") and
  not file.name : "dns.log"
```

```python
[{'process': {'name': 'dns.exe'}, 'event': {'type': ['creation'], 'category': ['file']}, 'file': {'name': 'ZFy'}, '@timestamp': 0},
 {'process': {'name': 'dns.exe'}, 'event': {'type': ['deletion'], 'category': ['file']}, 'file': {'name': 'XIU'}, '@timestamp': 1},
 {'process': {'name': 'dns.exe'}, 'event': {'type': ['change'], 'category': ['file']}, 'file': {'name': 'tkN'}, '@timestamp': 2}]
```



### Unusual Network Activity from a Windows System Binary

Branch count: 2  
Document count: 4  
Index: geneve-ut-655

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'xwizard.exe', 'entity_id': 'TvC'}, '@timestamp': 0},
 {'process': {'name': 'cdb.exe', 'entity_id': 'TvC'}, 'event': {'category': ['network']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'msdt.exe', 'entity_id': 'yyF'}, '@timestamp': 2},
 {'process': {'name': 'csi.exe', 'entity_id': 'yyF'}, 'event': {'category': ['network']}, '@timestamp': 3}]
```



### Unusual Network Connection via DllHost

Branch count: 2  
Document count: 4  
Index: geneve-ut-656

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'dllhost.exe', 'args_count': 1, 'entity_id': 'XIU'}, 'host': {'id': 'ZFy'}, '@timestamp': 0},
 {'process': {'name': 'dllhost.exe', 'entity_id': 'XIU'}, 'destination': {'ip': '122.143.223.236'}, 'event': {'category': ['network']}, 'host': {'id': 'ZFy'}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'dllhost.exe', 'args_count': 1, 'entity_id': 'oix'}, 'host': {'id': 'kNI'}, '@timestamp': 2},
 {'process': {'name': 'dllhost.exe', 'entity_id': 'oix'}, 'destination': {'ip': '467b:3f4c:3786:ab02:c5ea:f06e:9a3d:9c73'}, 'event': {'category': ['network']}, 'host': {'id': 'kNI'}, '@timestamp': 3}]
```



### Unusual Network Connection via RunDLL32

Branch count: 2  
Document count: 4  
Index: geneve-ut-657

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'rundll32.exe', 'args_count': 1, 'entity_id': 'XIU'}, 'host': {'id': 'ZFy'}, '@timestamp': 0},
 {'process': {'name': 'rundll32.exe', 'entity_id': 'XIU'}, 'destination': {'ip': '122.143.223.236'}, 'event': {'category': ['network']}, 'host': {'id': 'ZFy'}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'rundll32.exe', 'args_count': 1, 'entity_id': 'oix'}, 'host': {'id': 'kNI'}, '@timestamp': 2},
 {'process': {'name': 'rundll32.exe', 'entity_id': 'oix'}, 'destination': {'ip': '467b:3f4c:3786:ab02:c5ea:f06e:9a3d:9c73'}, 'event': {'category': ['network']}, 'host': {'id': 'kNI'}, '@timestamp': 3}]
```



### Unusual Parent Process for cmd.exe

Branch count: 2  
Document count: 2  
Index: geneve-ut-659

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'parent': {'name': 'sppsvc.exe'}}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'cmd.exe', 'parent': {'name': 'regsvr32.exe'}}, '@timestamp': 1}]
```



### Unusual Parent-Child Relationship

Branch count: 48  
Document count: 48  
Index: geneve-ut-660

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'ZFy'}, 'name': 'autochk.exe'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'XIU'}, 'name': 'fontdrvhost.exe'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'yyF'}, 'name': 'RuntimeBroker.exe'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'oix'}, 'name': 'SearchIndexer.exe'}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'TFl'}, 'name': 'SearchProtocolHost.exe'}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'Ezs'}, 'name': 'dllhost.exe'}, '@timestamp': 5},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'wuE'}, 'name': 'smss.exe'}, '@timestamp': 6},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'EXp'}, 'name': 'csrss.exe'}, '@timestamp': 7},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'WqN'}, 'name': 'wininit.exe'}, '@timestamp': 8},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'VRc'}, 'name': 'winlogon.exe'}, '@timestamp': 9},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'ymE'}, 'name': 'lsass.exe'}, '@timestamp': 10},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'wVP'}, 'name': 'LogonUI.exe'}, '@timestamp': 11},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'YMG'}, 'name': 'services.exe'}, '@timestamp': 12},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'zNf'}, 'name': 'svchost.exe'}, '@timestamp': 13},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'mlO'}, 'name': 'spoolsv.exe'}, '@timestamp': 14},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'PZR'}, 'name': 'taskhost.exe'}, '@timestamp': 15},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'gUv'}, 'name': 'taskhostw.exe'}, '@timestamp': 16},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'WCi'}, 'name': 'userinit.exe'}, '@timestamp': 17},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'MZO'}, 'name': 'winrshost.exe'}, '@timestamp': 18},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'taskhost.exe'}, 'name': 'msh'}, '@timestamp': 19},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'autochk.exe'}, 'name': 'CeL'}, '@timestamp': 20},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'smss.exe'}, 'name': 'WYc'}, '@timestamp': 21},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'wermgr.exe'}, 'name': 'Ysc'}, '@timestamp': 22},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'conhost.exe'}, 'name': 'nUJ'}, '@timestamp': 23},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'MVr'}, 'name': 'autochk.exe'}, '@timestamp': 24},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'Htz'}, 'name': 'dwm.exe'}, '@timestamp': 25},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'jey'}, 'name': 'consent.exe'}, '@timestamp': 26},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'Nmo'}, 'name': 'SearchIndexer.exe'}, '@timestamp': 27},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'EFC'}, 'name': 'SearchProtocolHost.exe'}, '@timestamp': 28},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'EZp'}, 'name': 'dllhost.exe'}, '@timestamp': 29},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'gIk'}, 'name': 'smss.exe'}, '@timestamp': 30},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'bku'}, 'name': 'csrss.exe'}, '@timestamp': 31},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'YnD'}, 'name': 'wininit.exe'}, '@timestamp': 32},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'mxX'}, 'name': 'winlogon.exe'}, '@timestamp': 33},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'cxF'}, 'name': 'LsaIso.exe'}, '@timestamp': 34},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'ocs'}, 'name': 'LogonUI.exe'}, '@timestamp': 35},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'vBa'}, 'name': 'services.exe'}, '@timestamp': 36},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'yAo'}, 'name': 'svchost.exe'}, '@timestamp': 37},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'lIY'}, 'name': 'spoolsv.exe'}, '@timestamp': 38},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'ARL'}, 'name': 'taskhost.exe'}, '@timestamp': 39},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'bRz'}, 'name': 'taskhostw.exe'}, '@timestamp': 40},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'WYs'}, 'name': 'userinit.exe'}, '@timestamp': 41},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'rfy'}, 'name': 'winrshost.exe'}, '@timestamp': 42},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'csrss.exe'}, 'name': 'OYU'}, '@timestamp': 43},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'autochk.exe'}, 'name': 'agT'}, '@timestamp': 44},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'smss.exe'}, 'name': 'rNY'}, '@timestamp': 45},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'wermgr.exe'}, 'name': 'jLw'}, '@timestamp': 46},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'conhost.exe'}, 'name': 'OTv'}, '@timestamp': 47}]
```



### Unusual Process Execution - Temp

Branch count: 2  
Document count: 2  
Index: geneve-ut-663

```python
event.category:process and event.type:(start or process_started) and process.working_directory:/tmp
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'working_directory': '/tmp'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'working_directory': '/tmp'}, '@timestamp': 1}]
```



### Unusual Process Execution Path - Alternate Data Stream

Branch count: 1  
Document count: 1  
Index: geneve-ut-664

```python
process where event.type == "start" and
  process.args : "?:\\*:*" and process.args_count == 1
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['?:\\*:*'], 'args_count': 1}, '@timestamp': 0}]
```



### Unusual Process Network Connection

Branch count: 1  
Document count: 2  
Index: geneve-ut-667

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

```python
[{'process': {'name': 'odbcconf.exe', 'entity_id': 'TvC'}, 'event': {'type': ['start'], 'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'bginfo.exe', 'entity_id': 'TvC'}, 'event': {'category': ['network']}, '@timestamp': 1}]
```



### Unusual Service Host Child Process - Childless Service

Branch count: 2  
Document count: 2  
Index: geneve-ut-668

```python
process where event.type in ("start", "process_started") and
     process.parent.name : "svchost.exe" and

     /* based on svchost service arguments -s svcname where the service is known to be childless */

    process.parent.args : ("WdiSystemHost","LicenseManager",
      "StorSvc","CDPSvc","cdbhsvc","BthAvctpSvc","SstpSvc","WdiServiceHost",
      "imgsvc","TrkWks","WpnService","IKEEXT","PolicyAgent","CryptSvc",
      "netprofm","ProfSvc","StateRepository","camsvc","LanmanWorkstation",
      "NlaSvc","EventLog","hidserv","DisplayEnhancementService","ShellHWDetection",
      "AppHostSvc","fhsvc","CscService","PushToInstall") and

      /* unknown FPs can be added here */

     not process.name : ("WerFault.exe","WerFaultSecure.exe","wermgr.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['WdiSystemHost', 'LicenseManager', 'StorSvc', 'CDPSvc', 'cdbhsvc', 'BthAvctpSvc', 'SstpSvc', 'WdiServiceHost', 'imgsvc', 'TrkWks', 'WpnService', 'IKEEXT', 'PolicyAgent', 'CryptSvc', 'netprofm', 'ProfSvc', 'StateRepository', 'camsvc', 'LanmanWorkstation', 'NlaSvc', 'EventLog', 'hidserv', 'DisplayEnhancementService', 'ShellHWDetection', 'AppHostSvc', 'fhsvc', 'CscService', 'PushToInstall']}, 'name': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'args': ['WdiSystemHost', 'LicenseManager', 'StorSvc', 'CDPSvc', 'cdbhsvc', 'BthAvctpSvc', 'SstpSvc', 'WdiServiceHost', 'imgsvc', 'TrkWks', 'WpnService', 'IKEEXT', 'PolicyAgent', 'CryptSvc', 'netprofm', 'ProfSvc', 'StateRepository', 'camsvc', 'LanmanWorkstation', 'NlaSvc', 'EventLog', 'hidserv', 'DisplayEnhancementService', 'ShellHWDetection', 'AppHostSvc', 'fhsvc', 'CscService', 'PushToInstall']}, 'name': 'XIU'}, '@timestamp': 1}]
```



### User Account Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-681

```python
process where event.type in ("start", "process_started") and
  process.name : ("net.exe", "net1.exe") and
  not process.parent.name : "net.exe" and
  (process.args : "user" and process.args : ("/ad", "/add"))
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'net1.exe', 'parent': {'name': 'vCf'}, 'args': ['user', '/ad', '/add']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'net1.exe', 'parent': {'name': 'yyF'}, 'args': ['user', '/ad', '/add']}, '@timestamp': 1}]
```



### User Added as Owner for Azure Application

Branch count: 2  
Document count: 2  
Index: geneve-ut-682

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add owner to application" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'operation_name': 'Add owner to application'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'operation_name': 'Add owner to application'}}, '@timestamp': 1}]
```



### User Added as Owner for Azure Service Principal

Branch count: 2  
Document count: 2  
Index: geneve-ut-683

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add owner to service principal" and event.outcome:(Success or success)
```

```python
[{'event': {'dataset': 'azure.auditlogs', 'outcome': 'Success'}, 'azure': {'auditlogs': {'operation_name': 'Add owner to service principal'}}, '@timestamp': 0},
 {'event': {'dataset': 'azure.auditlogs', 'outcome': 'success'}, 'azure': {'auditlogs': {'operation_name': 'Add owner to service principal'}}, '@timestamp': 1}]
```



### User Added to Privileged Group in Active Directory

Branch count: 1  
Document count: 1  
Index: geneve-ut-684

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

```python
[{'event': {'action': 'added-member-to-group', 'category': ['iam']}, 'group': {'name': 'Schema Admins'}, '@timestamp': 0}]
```



### User Discovery via Whoami

Branch count: 2  
Document count: 2  
Index: geneve-ut-685

```python
event.category:process and event.type:(start or process_started) and process.name:whoami
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'whoami'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'name': 'whoami'}, '@timestamp': 1}]
```



### User account exposed to Kerberoasting

Branch count: 1  
Document count: 1  
Index: geneve-ut-686

```python
event.action:"Directory Service Changes" and event.code:5136 and winlog.event_data.ObjectClass:"user" 
and winlog.event_data.AttributeLDAPDisplayName:"servicePrincipalName"
```

```python
[{'event': {'action': 'Directory Service Changes', 'code': 5136}, 'winlog': {'event_data': {'ObjectClass': 'user', 'AttributeLDAPDisplayName': 'servicePrincipalName'}}, '@timestamp': 0}]
```



### VNC (Virtual Network Computing) from the Internet

Branch count: 6  
Document count: 6  
Index: geneve-ut-687

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

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5809, 'ip': '10.193.74.7'}, 'source': {'ip': '107.31.65.130'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5807, 'ip': '172.25.51.169'}, 'source': {'ip': '119.10.44.216'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5802, 'ip': '192.168.140.246'}, 'source': {'ip': '115.189.242.190'}, '@timestamp': 2},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5809, 'ip': '10.232.229.224'}, 'source': {'ip': '3e09:df7f:5d4f:9e31:a728:d9ab:7cd7:de7e'}, '@timestamp': 3},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5806, 'ip': '172.18.192.161'}, 'source': {'ip': '149.102.124.168'}, '@timestamp': 4},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5804, 'ip': '192.168.9.26'}, 'source': {'ip': 'a7:5646:506a:fac2:8499:c98f:ee87:44c3'}, '@timestamp': 5}]
```



### VNC (Virtual Network Computing) to the Internet

Branch count: 6  
Document count: 6  
Index: geneve-ut-688

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

```python
[{'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5809, 'ip': '170.121.236.89'}, 'source': {'ip': '10.214.62.131'}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5801, 'ip': '119.10.44.216'}, 'source': {'ip': '172.31.81.251'}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5809, 'ip': '104.129.204.102'}, 'source': {'ip': '192.168.147.58'}, '@timestamp': 2},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5807, 'ip': '199.127.185.194'}, 'source': {'ip': '10.140.246.126'}, '@timestamp': 3},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5807, 'ip': '116.114.240.76'}, 'source': {'ip': '172.23.193.59'}, '@timestamp': 4},
 {'event': {'category': ['network_traffic']}, 'network': {'transport': 'tcp'}, 'destination': {'port': 5806, 'ip': '197.7.114.246'}, 'source': {'ip': '192.168.44.10'}, '@timestamp': 5}]
```



### Virtual Machine Fingerprinting

Branch count: 10  
Document count: 10  
Index: geneve-ut-689

```python
event.category:process and event.type:(start or process_started) and
  process.args:("/sys/class/dmi/id/bios_version" or
                "/sys/class/dmi/id/product_name" or
                "/sys/class/dmi/id/chassis_vendor" or
                "/proc/scsi/scsi" or
                "/proc/ide/hd0/model") and
  not user.name:root
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['/sys/class/dmi/id/bios_version']}, 'user': {'name': 'ZFy'}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['/sys/class/dmi/id/product_name']}, 'user': {'name': 'XIU'}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['/sys/class/dmi/id/chassis_vendor']}, 'user': {'name': 'tkN'}, '@timestamp': 2},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['/proc/scsi/scsi']}, 'user': {'name': 'Ioi'}, '@timestamp': 3},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['/proc/ide/hd0/model']}, 'user': {'name': 'xTF'}, '@timestamp': 4},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'args': ['/sys/class/dmi/id/bios_version']}, 'user': {'name': 'lEz'}, '@timestamp': 5},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'args': ['/sys/class/dmi/id/product_name']}, 'user': {'name': 'swu'}, '@timestamp': 6},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'args': ['/sys/class/dmi/id/chassis_vendor']}, 'user': {'name': 'EEX'}, '@timestamp': 7},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'args': ['/proc/scsi/scsi']}, 'user': {'name': 'pWq'}, '@timestamp': 8},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'args': ['/proc/ide/hd0/model']}, 'user': {'name': 'NVR'}, '@timestamp': 9}]
```



### Virtual Machine Fingerprinting via Grep

Branch count: 2  
Document count: 2  
Index: geneve-ut-690

```python
process where event.type == "start" and
 process.name in ("grep", "egrep") and user.id != "0" and
 process.args : ("parallels*", "vmware*", "virtualbox*") and process.args : "Manufacturer*" and 
 not process.parent.executable in ("/Applications/Docker.app/Contents/MacOS/Docker", "/usr/libexec/kcare/virt-what")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'grep', 'args': ['parallels*', 'vmware*', 'virtualbox*', 'Manufacturer*'], 'parent': {'executable': 'XIU'}}, 'user': {'id': 'ZFy'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'egrep', 'args': ['parallels*', 'vmware*', 'virtualbox*', 'Manufacturer*'], 'parent': {'executable': 'Ioi'}}, 'user': {'id': 'tkN'}, '@timestamp': 1}]
```



### Volume Shadow Copy Deleted or Resized via VssAdmin

Branch count: 8  
Document count: 8  
Index: geneve-ut-692

```python
process where event.type in ("start", "process_started")
  and (process.name : "vssadmin.exe" or process.pe.original_file_name == "VSSADMIN.EXE") and
  process.args in ("delete", "resize") and process.args : "shadows*"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'vssadmin.exe', 'args': ['shadows*', 'delete']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'vssadmin.exe', 'args': ['shadows*', 'resize']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'VSSADMIN.EXE'}, 'args': ['shadows*', 'delete']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'VSSADMIN.EXE'}, 'args': ['shadows*', 'resize']}, '@timestamp': 3},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'vssadmin.exe', 'args': ['shadows*', 'delete']}, '@timestamp': 4},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'vssadmin.exe', 'args': ['shadows*', 'resize']}, '@timestamp': 5},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'VSSADMIN.EXE'}, 'args': ['shadows*', 'delete']}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'VSSADMIN.EXE'}, 'args': ['shadows*', 'resize']}, '@timestamp': 7}]
```



### Volume Shadow Copy Deletion via PowerShell

Branch count: 2  
Document count: 2  
Index: geneve-ut-693

```python
process where event.type in ("start", "process_started") and
  process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and 
  process.args : ("*Get-WmiObject*", "*gwmi*", "*Get-CimInstance*", "*gcim*") and
  process.args : ("*Win32_ShadowCopy*") and
  process.args : ("*.Delete()*", "*Remove-WmiObject*", "*rwmi*", "*Remove-CimInstance*", "*rcim*")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'pwsh.exe', 'args': ['*Get-WmiObject*', '*gwmi*', '*Get-CimInstance*', '*gcim*', '*Win32_ShadowCopy*', '*.Delete()*', '*Remove-WmiObject*', '*rwmi*', '*Remove-CimInstance*', '*rcim*']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'powershell_ise.exe', 'args': ['*Get-WmiObject*', '*gwmi*', '*Get-CimInstance*', '*gcim*', '*Win32_ShadowCopy*', '*.Delete()*', '*Remove-WmiObject*', '*rwmi*', '*Remove-CimInstance*', '*rcim*']}, '@timestamp': 1}]
```



### Volume Shadow Copy Deletion via WMIC

Branch count: 4  
Document count: 4  
Index: geneve-ut-694

```python
process where event.type in ("start", "process_started") and
  (process.name : "WMIC.exe" or process.pe.original_file_name == "wmic.exe") and
  process.args : "delete" and process.args : "shadowcopy"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'WMIC.exe', 'args': ['delete', 'shadowcopy']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'wmic.exe'}, 'args': ['delete', 'shadowcopy']}, '@timestamp': 1},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'WMIC.exe', 'args': ['delete', 'shadowcopy']}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'wmic.exe'}, 'args': ['delete', 'shadowcopy']}, '@timestamp': 3}]
```



### WMI Incoming Lateral Movement

Branch count: 2  
Document count: 4  
Index: geneve-ut-695

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

```python
[{'process': {'name': 'svchost.exe'}, 'network': {'direction': 'ingress'}, 'source': {'ip': '1b43:3a53:aa79:ec58:8d14:2981:f18d:f2a7', 'port': 61522}, 'destination': {'port': 64839}, 'event': {'category': ['network']}, 'host': {'id': 'kNI'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'WmiPrvSE.exe'}, 'args': ['oix']}, 'host': {'id': 'kNI'}, '@timestamp': 1},
 {'process': {'name': 'svchost.exe'}, 'network': {'direction': 'incoming'}, 'source': {'ip': 'a728:d9ab:7cd7:de7d:c77f:b9c1:95ef:56af', 'port': 61095}, 'destination': {'port': 57092}, 'event': {'category': ['network']}, 'host': {'id': 'wuE'}, '@timestamp': 2},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'WmiPrvSE.exe'}, 'args': ['EXp']}, 'host': {'id': 'wuE'}, '@timestamp': 3}]
```



### WPAD Service Exploit

Branch count: 4  
Document count: 20  
Index: geneve-ut-696

```python
/* preference would be to use user.sid rather than domain+name, once it is available in ECS + datasources */
/* didn't trigger successfully during testing */

sequence with maxspan=5s
  [process where event.type in ("start", "process_started") and process.name : "svchost.exe" and
     user.domain : "NT AUTHORITY" and user.name : "LOCAL SERVICE"] by process.entity_id
  [network where network.protocol : "dns" and process.name : "svchost.exe" and
     dns.question.name : "wpad" and process.name : "svchost.exe"] by process.entity_id
  [network where process.name : "svchost.exe"
     and network.direction : ("outgoing", "egress") and destination.port == 80] by process.entity_id
  [library where event.type : "start" and process.name : "svchost.exe" and
     dll.name : "jscript.dll" and process.name : "svchost.exe"] by process.entity_id
  [process where event.type in ("start", "process_started") and
     process.parent.name : "svchost.exe"] by process.parent.entity_id
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'svchost.exe', 'entity_id': 'ZFy'}, 'user': {'domain': 'NT AUTHORITY', 'name': 'LOCAL SERVICE'}, '@timestamp': 0},
 {'network': {'protocol': 'dns'}, 'process': {'name': 'svchost.exe', 'entity_id': 'ZFy'}, 'dns': {'question': {'name': 'wpad'}}, 'event': {'category': ['network']}, '@timestamp': 1},
 {'process': {'name': 'svchost.exe', 'entity_id': 'ZFy'}, 'network': {'direction': 'egress'}, 'destination': {'port': 80}, 'event': {'category': ['network']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['library']}, 'process': {'name': 'svchost.exe', 'entity_id': 'ZFy'}, 'dll': {'name': 'jscript.dll'}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'entity_id': 'ZFy'}}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'svchost.exe', 'entity_id': 'Utk'}, 'user': {'domain': 'NT AUTHORITY', 'name': 'LOCAL SERVICE'}, '@timestamp': 5},
 {'network': {'protocol': 'dns'}, 'process': {'name': 'svchost.exe', 'entity_id': 'Utk'}, 'dns': {'question': {'name': 'wpad'}}, 'event': {'category': ['network']}, '@timestamp': 6},
 {'process': {'name': 'svchost.exe', 'entity_id': 'Utk'}, 'network': {'direction': 'egress'}, 'destination': {'port': 80}, 'event': {'category': ['network']}, '@timestamp': 7},
 {'event': {'type': ['start'], 'category': ['library']}, 'process': {'name': 'svchost.exe', 'entity_id': 'Utk'}, 'dll': {'name': 'jscript.dll'}, '@timestamp': 8},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'entity_id': 'Utk'}}, '@timestamp': 9},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'svchost.exe', 'entity_id': 'oix'}, 'user': {'domain': 'NT AUTHORITY', 'name': 'LOCAL SERVICE'}, '@timestamp': 10},
 {'network': {'protocol': 'dns'}, 'process': {'name': 'svchost.exe', 'entity_id': 'oix'}, 'dns': {'question': {'name': 'wpad'}}, 'event': {'category': ['network']}, '@timestamp': 11},
 {'process': {'name': 'svchost.exe', 'entity_id': 'oix'}, 'network': {'direction': 'egress'}, 'destination': {'port': 80}, 'event': {'category': ['network']}, '@timestamp': 12},
 {'event': {'type': ['start'], 'category': ['library']}, 'process': {'name': 'svchost.exe', 'entity_id': 'oix'}, 'dll': {'name': 'jscript.dll'}, '@timestamp': 13},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'entity_id': 'oix'}}, '@timestamp': 14},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'svchost.exe', 'entity_id': 'oOH'}, 'user': {'domain': 'NT AUTHORITY', 'name': 'LOCAL SERVICE'}, '@timestamp': 15},
 {'network': {'protocol': 'dns'}, 'process': {'name': 'svchost.exe', 'entity_id': 'oOH'}, 'dns': {'question': {'name': 'wpad'}}, 'event': {'category': ['network']}, '@timestamp': 16},
 {'process': {'name': 'svchost.exe', 'entity_id': 'oOH'}, 'network': {'direction': 'egress'}, 'destination': {'port': 80}, 'event': {'category': ['network']}, '@timestamp': 17},
 {'event': {'type': ['start'], 'category': ['library']}, 'process': {'name': 'svchost.exe', 'entity_id': 'oOH'}, 'dll': {'name': 'jscript.dll'}, '@timestamp': 18},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'svchost.exe', 'entity_id': 'oOH'}}, '@timestamp': 19}]
```



### Web Application Suspicious Activity: POST Request Declined

Branch count: 1  
Document count: 1  
Index: geneve-ut-698

```python
http.response.status_code:403 and http.request.method:post
```

```python
[{'http': {'response': {'status_code': 403}, 'request': {'method': 'post'}}, '@timestamp': 0}]
```



### Web Application Suspicious Activity: Unauthorized Method

Branch count: 1  
Document count: 1  
Index: geneve-ut-699

```python
http.response.status_code:405
```

```python
[{'http': {'response': {'status_code': 405}}, '@timestamp': 0}]
```



### Web Application Suspicious Activity: sqlmap User Agent

Branch count: 1  
Document count: 1  
Index: geneve-ut-700

```python
user_agent.original:"sqlmap/1.3.11#stable (http://sqlmap.org)"
```

```python
[{'user_agent': {'original': 'sqlmap/1.3.11#stable (http://sqlmap.org)'}, '@timestamp': 0}]
```



### WebProxy Settings Modification

Branch count: 3  
Document count: 3  
Index: geneve-ut-701

```python
event.category : process and event.type : start and
 process.name : networksetup and process.args : (("-setwebproxy" or "-setsecurewebproxy" or "-setautoproxyurl") and not (Bluetooth or off)) and
 not process.parent.executable : ("/Library/PrivilegedHelperTools/com.80pct.FreedomHelper" or
                                  "/Applications/Fiddler Everywhere.app/Contents/Resources/app/out/WebServer/Fiddler.WebUi" or
                                  "/usr/libexec/xpcproxy")
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'networksetup', 'args': ['-setwebproxy'], 'parent': {'executable': 'ZFy'}}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'networksetup', 'args': ['-setsecurewebproxy'], 'parent': {'executable': 'XIU'}}, '@timestamp': 1},
 {'event': {'category': ['process'], 'type': ['start']}, 'process': {'name': 'networksetup', 'args': ['-setautoproxyurl'], 'parent': {'executable': 'tkN'}}, '@timestamp': 2}]
```



### WebServer Access Logs Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-702

```python
file where event.type == "deletion" and
  file.path : ("C:\\inetpub\\logs\\LogFiles\\*.log", 
               "/var/log/apache*/access.log",
               "/etc/httpd/logs/access_log", 
               "/var/log/httpd/access_log", 
               "/var/www/*/logs/access.log")
```

```python
[{'event': {'type': ['deletion'], 'category': ['file']}, 'file': {'path': 'C:\\inetpub\\logs\\LogFiles\\yXIUtkNIoixTFl.log'}, '@timestamp': 0}]
```



### Webshell Detection: Script Process Child of Common Web Processes

Branch count: 1  
Document count: 1  
Index: geneve-ut-703

```python
process where event.type == "start" and
  process.parent.name : ("w3wp.exe", "httpd.exe", "nginx.exe", "php.exe", "php-cgi.exe", "tomcat.exe") and 
  process.name : ("cmd.exe", "cscript.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "wmic.exe", "wscript.exe")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'tomcat.exe'}, 'name': 'wscript.exe'}, '@timestamp': 0}]
```



### Whoami Process Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-705

```python
process where event.type in ("start", "process_started") and process.name : "whoami.exe"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'whoami.exe'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'whoami.exe'}, '@timestamp': 1}]
```



### Windows Defender Exclusions Added via PowerShell

Branch count: 4  
Document count: 4  
Index: geneve-ut-708

```python
process where event.type == "start" and
 (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or process.pe.original_file_name in ("powershell.exe", "pwsh.dll", "powershell_ise.exe")) and
  process.args : ("*Add-MpPreference*", "*Set-MpPreference*") and
  process.args : ("*-Exclusion*")
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'pwsh.exe', 'args': ['*Add-MpPreference*', '*Set-MpPreference*', '*-Exclusion*']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'powershell.exe'}, 'args': ['*Add-MpPreference*', '*Set-MpPreference*', '*-Exclusion*']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'pwsh.dll'}, 'args': ['*Add-MpPreference*', '*Set-MpPreference*', '*-Exclusion*']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'powershell_ise.exe'}, 'args': ['*Add-MpPreference*', '*Set-MpPreference*', '*-Exclusion*']}, '@timestamp': 3}]
```



### Windows Event Logs Cleared

Branch count: 2  
Document count: 2  
Index: geneve-ut-709

```python
event.action:("audit-log-cleared" or "Log clear")
```

```python
[{'event': {'action': 'audit-log-cleared'}, '@timestamp': 0},
 {'event': {'action': 'Log clear'}, '@timestamp': 1}]
```



### Windows Firewall Disabled via PowerShell

Branch count: 2  
Document count: 2  
Index: geneve-ut-710

```python
process where event.action == "start" and
  (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or process.pe.original_file_name == "PowerShell.EXE") and
   process.args : "*Set-NetFirewallProfile*" and
  (process.args : "*-Enabled*" and process.args : "*False*") and
  (process.args : "*-All*" or process.args : ("*Public*", "*Domain*", "*Private*"))
```

```python
[{'event': {'action': 'start', 'category': ['process']}, 'process': {'name': 'pwsh.exe', 'args': ['*Set-NetFirewallProfile*', '*-Enabled*', '*False*', '*-All*', '*Public*', '*Domain*', '*Private*']}, '@timestamp': 0},
 {'event': {'action': 'start', 'category': ['process']}, 'process': {'pe': {'original_file_name': 'PowerShell.EXE'}, 'args': ['*Set-NetFirewallProfile*', '*-Enabled*', '*False*', '*-All*', '*Public*', '*Domain*', '*Private*']}, '@timestamp': 1}]
```



### Windows Network Enumeration

Branch count: 16  
Document count: 16  
Index: geneve-ut-711

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

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'net.exe', 'args': ['view']}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'net.exe', 'args': ['time', '\\\\*']}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net.exe'}, 'args': ['view']}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net.exe'}, 'args': ['time', '\\\\*']}, '@timestamp': 3},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'net1.exe', 'parent': {'name': 'ZFy'}, 'args': ['view']}, '@timestamp': 4},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'name': 'net1.exe', 'parent': {'name': 'XIU'}, 'args': ['time', '\\\\*']}, '@timestamp': 5},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net1.exe'}, 'parent': {'name': 'tkN'}, 'args': ['view']}, '@timestamp': 6},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net1.exe'}, 'parent': {'name': 'Ioi'}, 'args': ['time', '\\\\*']}, '@timestamp': 7},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'net.exe', 'args': ['view']}, '@timestamp': 8},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'net.exe', 'args': ['time', '\\\\*']}, '@timestamp': 9},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net.exe'}, 'args': ['view']}, '@timestamp': 10},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net.exe'}, 'args': ['time', '\\\\*']}, '@timestamp': 11},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'net1.exe', 'parent': {'name': 'xTF'}, 'args': ['view']}, '@timestamp': 12},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'name': 'net1.exe', 'parent': {'name': 'lEz'}, 'args': ['time', '\\\\*']}, '@timestamp': 13},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net1.exe'}, 'parent': {'name': 'swu'}, 'args': ['view']}, '@timestamp': 14},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'pe': {'original_file_name': 'net1.exe'}, 'parent': {'name': 'EEX'}, 'args': ['time', '\\\\*']}, '@timestamp': 15}]
```



### Windows Registry File Creation in SMB Share

Branch count: 1  
Document count: 1  
Index: geneve-ut-712

```python
file where event.type == "creation" and
 /* regf file header */
 file.Ext.header_bytes : "72656766*" and file.size >= 30000 and
 process.pid == 4 and user.id : "s-1-5-21*"
```

```python
[{'event': {'type': ['creation'], 'category': ['file']}, 'file': {'Ext': {'header_bytes': '72656766XIUtkNI'}, 'size': 7897998920714667080}, 'process': {'pid': 4}, 'user': {'id': 's-1-5-21xTFlEzs'}, '@timestamp': 0}]
```



### Windows Script Executing PowerShell

Branch count: 2  
Document count: 2  
Index: geneve-ut-713

```python
process where event.type in ("start", "process_started") and
  process.parent.name : ("cscript.exe", "wscript.exe") and process.name : "powershell.exe"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'wscript.exe'}, 'name': 'powershell.exe'}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'wscript.exe'}, 'name': 'powershell.exe'}, '@timestamp': 1}]
```



### Windows Script Interpreter Executing Process via WMI

Branch count: 4  
Document count: 8  
Index: geneve-ut-714

```python
sequence by host.id with maxspan = 5s
    [library where dll.name : "wmiutils.dll" and process.name : ("wscript.exe", "cscript.exe")]
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

```python
[{'dll': {'name': 'wmiutils.dll'}, 'process': {'name': 'wscript.exe'}, 'event': {'category': ['library']}, 'host': {'id': 'vCf'}, '@timestamp': 0},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'wmiprvse.exe'}, 'pe': {'original_file_name': 'Microsoft.Workflow.Compiler.exe'}}, 'user': {'domain': 'Uyy'}, 'host': {'id': 'vCf'}, '@timestamp': 1},
 {'dll': {'name': 'wmiutils.dll'}, 'process': {'name': 'wscript.exe'}, 'event': {'category': ['library']}, 'host': {'id': 'SvI'}, '@timestamp': 2},
 {'event': {'type': ['start'], 'category': ['process']}, 'process': {'parent': {'name': 'wmiprvse.exe'}, 'executable': 'C:\\Users\\swuEEXpWqNV.exe'}, 'user': {'domain': 'LOo'}, 'host': {'id': 'SvI'}, '@timestamp': 3},
 {'dll': {'name': 'wmiutils.dll'}, 'process': {'name': 'cscript.exe'}, 'event': {'category': ['library']}, 'host': {'id': 'cym'}, '@timestamp': 4},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'wmiprvse.exe'}, 'pe': {'original_file_name': 'wscript.exe'}}, 'user': {'domain': 'EEw'}, 'host': {'id': 'cym'}, '@timestamp': 5},
 {'dll': {'name': 'wmiutils.dll'}, 'process': {'name': 'wscript.exe'}, 'event': {'category': ['library']}, 'host': {'id': 'MGz'}, '@timestamp': 6},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'parent': {'name': 'wmiprvse.exe'}, 'executable': 'C:\\ProgramData\\OPZRgUvWCi.exe'}, 'user': {'domain': 'Nfm'}, 'host': {'id': 'MGz'}, '@timestamp': 7}]
```



### Windows Service Installed via an Unusual Client

Branch count: 2  
Document count: 2  
Index: geneve-ut-715

```python
event.action:"service-installed"  and (winlog.event_data.ClientProcessId:"0" or winlog.event_data.ParentProcessId:"0")
```

```python
[{'event': {'action': 'service-installed'}, 'winlog': {'event_data': {'ClientProcessId': '0'}}, '@timestamp': 0},
 {'event': {'action': 'service-installed'}, 'winlog': {'event_data': {'ParentProcessId': '0'}}, '@timestamp': 1}]
```



### Zoom Meeting with no Passcode

Branch count: 1  
Document count: 1  
Index: geneve-ut-716

```python
event.type:creation and event.module:zoom and event.dataset:zoom.webhook and
  event.action:meeting.created and not zoom.meeting.password:*
```

```python
[{'event': {'type': ['creation'], 'module': 'zoom', 'dataset': 'zoom.webhook', 'action': 'meeting.created'}, '@timestamp': 0}]
```



### macOS Installer Spawns Network Event

Branch count: 2  
Document count: 4  
Index: geneve-ut-717

```python
sequence by process.entity_id with maxspan=1m
  [process where event.type == "start" and host.os.family == "macos" and
    process.parent.executable in ("/usr/sbin/installer", "/System/Library/CoreServices/Installer.app/Contents/MacOS/Installer") ]
  [network where not cidrmatch(destination.ip,
    "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32",
    "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24",
    "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10", "FF00::/8")]
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'host': {'os': {'family': 'macos'}}, 'process': {'parent': {'executable': '/usr/sbin/installer'}, 'entity_id': 'ZFy'}, '@timestamp': 0},
 {'destination': {'ip': '170.121.236.89'}, 'event': {'category': ['network']}, 'process': {'entity_id': 'ZFy'}, '@timestamp': 1},
 {'event': {'type': ['start'], 'category': ['process']}, 'host': {'os': {'family': 'macos'}}, 'process': {'parent': {'executable': '/System/Library/CoreServices/Installer.app/Contents/MacOS/Installer'}, 'entity_id': 'fUy'}, '@timestamp': 2},
 {'destination': {'ip': '196.67.182.123'}, 'event': {'category': ['network']}, 'process': {'entity_id': 'fUy'}, '@timestamp': 3}]
```
