# ES|QL rules validation

Documents generated for ES|QL are indexed and the query itself is run against Elasticsearch, it must return them.
This is what is checked for each branch of the query. Only what Geneve generates documents for is listed
as validated, failed or error; the rest is skipped and the reason is the one of the documents report.

Elasticsearch version: 9.5.0-SNAPSHOT (rules 9.5.8)

| validated | failed | error | skipped |
|---|---|---|---|
| 38 | 0 | 0 | 225 |

## Validated (38)

* AWS Bedrock Detected Multiple Attempts to use Denied Models by a Single User, 1 branch(es)
* AWS Bedrock Guardrails Detected Multiple Violations by a Single User Over a Session, 1 branch(es)
* AWS IAM Credentials Added to a Bedrock API Key Phantom User, 3 branch(es)
* AWS Lambda Function High-Frequency Invocation by a Single Principal, 1 branch(es)
* Agent Spoofing - Multiple Hosts Using Same Agent, 1 branch(es)
* Alerts in Different ATT&CK Tactics by Host, 1 branch(es)
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
* Azure OpenAI Insecure Output Handling, 1 branch(es)
* Entra ID MFA TOTP Brute Force Attempted, 2 branch(es)
* GitHub Exfiltration via High Number of Repository Clones by User, 1 branch(es)
* High Number of Closed Pull Requests by User, 1 branch(es)
* High Number of Protected Branch Force Pushes by User, 1 branch(es)
* Kubernetes Creation or Modification of Sensitive Role, 9936 branch(es)
* Kubernetes RBAC Wildcard Elevation on Existing Role, 4 branch(es)
* Multiple Alerts in Same ATT&CK Tactic by Host, 4 branch(es)
* Multiple Machine Learning Alerts by Influencer Field, 1 branch(es)
* Multiple Okta User Authentication Events with Same Device Token Hash, 2 branch(es)
* Okta User Sessions Started from Different Geolocations, 2 branch(es)
* Potential Spike in Web Server Error Logs, 1 branch(es)
* Potential Widespread Malware Infection Across Multiple Hosts, 3 branch(es)
* SSFileCopyReceiver Writing to Common Persistence Locations, 23 branch(es)
* SSFileCopySender Executed as Root, 1 branch(es)
* Several Failed Protected Branch Force Pushes by User, 1 branch(es)
* Suspicious AWS S3 Connection via Script Interpreter, 9 branch(es)

## Skipped (225)

* 101 x NotImplementedError: Unsupported command: EVAL
* 19 x NotImplementedError: Unsupported aggregate function: MIN
* 16 x NotImplementedError: Unsupported command: MV_EXPAND
* 15 x NotImplementedError: Unsupported command: GROK
* 11 x NotImplementedError: Unsupported operator: RLIKE
* 9 x NotImplementedError: Unsupported function: to_lower
* 7 x NotImplementedError: Unsupported function: to_string
* 5 x NotImplementedError: Unsupported aggregate function: MAX
* 3 x NotImplementedError: Unsupported command: DISSECT
* 3 x NotImplementedError: Unsupported condition on the values of Esql.rule_severity_values
* 3 x NotImplementedError: Unsupported function: TO_LOWER
* 2 x EsqlParseError: Error at line:8,column:3
* 2 x NotImplementedError: Unsupported command: IP_LOCATION
* 2 x NotImplementedError: Unsupported function: TO_IP
* 2 x NotImplementedError: Unsupported right operand, it must be a literal
* 1 x EsqlParseError: Error at line:14,column:53
* 1 x EsqlParseError: Error at line:21,column:34
* 1 x EsqlParseError: Error at line:3,column:38
* 1 x EsqlParseError: Error at line:40,column:54
* 1 x EsqlParseError: Error at line:43,column:41
* 1 x EsqlParseError: Error at line:44,column:107
* 1 x EsqlParseError: Error at line:5,column:43
* 1 x EsqlParseError: Error at line:59,column:16
* 1 x EsqlParseError: Error at line:6,column:43
* 1 x EsqlParseError: Error at line:7,column:33
* 1 x EsqlParseError: Error at line:9,column:76
* 1 x NotImplementedError: Unsupported aggregate function: SUM
* 1 x NotImplementedError: Unsupported command: INLINE
* 1 x NotImplementedError: Unsupported condition on the values of Esql.kibana_alert_risk_score_values
* 1 x NotImplementedError: Unsupported conflicting constraints on email.subject: only one equality or pattern per field is supported
* 1 x NotImplementedError: Unsupported field in WHERE after STATS: concat_vuln_severity_values
* 1 x NotImplementedError: Unsupported function: CONTAINS
* 1 x NotImplementedError: Unsupported function: NOW
* 1 x NotImplementedError: Unsupported function: TO_INTEGER
* 1 x NotImplementedError: Unsupported function: TO_UPPER
* 1 x NotImplementedError: Unsupported function: length
* 1 x NotImplementedError: Unsupported function: now
* 1 x NotImplementedError: Unsupported function: to_ip
* 1 x NotImplementedError: Unsupported number of different values of kubernetes.audit.annotations.`authorization_k8s_io/decision`: between 2 and 2 in 6 documents
* 1 x NotImplementedError: Unsupported second STATS

