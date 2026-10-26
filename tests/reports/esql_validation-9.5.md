# ES|QL rules validation

Documents generated for ES|QL are indexed and the query itself is run against Elasticsearch, it must return them.
This is what is checked for each branch of the query. Only what Geneve generates documents for is listed
as validated, failed or error; the rest is skipped and the reason is the one of the documents report.

Elasticsearch version: 9.5.0-SNAPSHOT (rules 9.5.8)

| validated | failed | error | skipped |
|---|---|---|---|
| 20 | 0 | 0 | 243 |

## Validated (20)

* AWS IAM Credentials Added to a Bedrock API Key Phantom User, 3 branch(es)
* Anthropic Admin API Key Created, 1 branch(es)
* Anthropic Admin API Key Deleted, 1 branch(es)
* Anthropic Admin Role Assigned to User, 1 branch(es)
* Anthropic Compliance API Key Created, 2 branch(es)
* Anthropic Compliance API Logging Disabled, 1 branch(es)
* Anthropic Compliance Audit Log Export Accessed, 1 branch(es)
* Anthropic Extra Usage Spend Limit Deleted, 1 branch(es)
* Anthropic Magic Link Second Factor Disabled, 1 branch(es)
* Anthropic Organization Data Export Accessed, 1 branch(es)
* Anthropic Organization Deletion, 3 branch(es)
* Anthropic Organization Domain Boundary Changed, 4 branch(es)
* Anthropic Organization IP Restriction Deleted, 1 branch(es)
* Anthropic Organization User Invite Sent, 1 branch(es)
* Anthropic Primary Owner Transferred, 1 branch(es)
* Anthropic SSO Disabled or Connection Removed, 3 branch(es)
* Kubernetes Creation or Modification of Sensitive Role, 9936 branch(es)
* Kubernetes RBAC Wildcard Elevation on Existing Role, 4 branch(es)
* SSFileCopyReceiver Writing to Common Persistence Locations, 23 branch(es)
* SSFileCopySender Executed as Root, 1 branch(es)

## Skipped (243)

* 103 x NotImplementedError: Unsupported command: EVAL
* 50 x NotImplementedError: Unsupported command: STATS
* 17 x NotImplementedError: Unsupported command: MV_EXPAND
* 16 x NotImplementedError: Unsupported command: GROK
* 11 x NotImplementedError: Unsupported operator: RLIKE
* 9 x NotImplementedError: Unsupported function: to_lower
* 7 x NotImplementedError: Unsupported function: to_string
* 3 x NotImplementedError: Unsupported command: DISSECT
* 3 x NotImplementedError: Unsupported function: TO_LOWER
* 2 x EsqlParseError: Error at line:8,column:3
* 2 x NotImplementedError: Unsupported command: IP_LOCATION
* 2 x NotImplementedError: Unsupported function: TO_IP
* 2 x NotImplementedError: Unsupported right operand, it must be a literal
* 1 x EsqlParseError: Error at line:14,column:53
* 1 x EsqlParseError: Error at line:3,column:38
* 1 x EsqlParseError: Error at line:43,column:41
* 1 x EsqlParseError: Error at line:44,column:107
* 1 x EsqlParseError: Error at line:5,column:43
* 1 x EsqlParseError: Error at line:6,column:43
* 1 x EsqlParseError: Error at line:7,column:33
* 1 x NotImplementedError: Unsupported command: INLINE
* 1 x NotImplementedError: Unsupported conflicting constraints on email.subject: only one equality or pattern per field is supported
* 1 x NotImplementedError: Unsupported function: CONTAINS
* 1 x NotImplementedError: Unsupported function: NOW
* 1 x NotImplementedError: Unsupported function: TO_INTEGER
* 1 x NotImplementedError: Unsupported function: TO_UPPER
* 1 x NotImplementedError: Unsupported function: now
* 1 x NotImplementedError: Unsupported function: to_ip
* 1 x NotImplementedError: Unsupported pipe before WHERE: KEEP

