# ES|QL rules validation

Documents generated for ES|QL are indexed and the query itself is run against Elasticsearch, it must return them.
This is what is checked for each branch of the query. Only what Geneve generates documents for is listed
as validated, failed or error; the rest is skipped and the reason is the one of the documents report.

Elasticsearch version: 9.5.0-SNAPSHOT (rules 9.5.9)

| validated | failed | error | skipped |
|---|---|---|---|
| 108 | 0 | 0 | 212 |

## Validated (108)

* AWS Bedrock API Key Used for Destructive or Anti-Recovery Action, 8 branch(es)
* AWS Bedrock AgentCore Runtime Prompt Containing Credentials, 5 branch(es)
* AWS Bedrock Detected Multiple Attempts to use Denied Models by a Single User, 1 branch(es)
* AWS Bedrock Detected Multiple Validation Exception Errors by a Single User, 1 branch(es)
* AWS Bedrock Guardrails Detected Multiple Violations by a Single User Over a Session, 1 branch(es)
* AWS Bedrock Invocations without Guardrails Detected by a Single User Over a Session, 1 branch(es)
* AWS Bedrock Model Prompt or Completion Containing Credentials, 28 branch(es)
* AWS EC2 Multi-Region DescribeInstances API Calls, 1 branch(es)
* AWS IAM Credentials Added to a Bedrock API Key Phantom User, 3 branch(es)
* AWS IAM User Console Login from Multiple Geolocations, 1 branch(es)
* AWS Lambda Function High-Frequency Invocation by a Single Principal, 1 branch(es)
* AWS S3 Rapid Bucket Posture API Calls from a Single Principal, 5 branch(es)
* Agent Spoofing - Multiple Hosts Using Same Agent, 1 branch(es)
* Alerts in Different ATT&CK Tactics by Host, 1 branch(es)
* Anthropic Admin API Key Created, 1 branch(es)
* Anthropic Admin API Key Deleted, 1 branch(es)
* Anthropic Admin Role Assigned to User, 3 branch(es)
* Anthropic Compliance API Key Created, 2 branch(es)
* Anthropic Compliance API Logging Disabled, 1 branch(es)
* Anthropic Compliance Audit Log Export Accessed, 1 branch(es)
* Anthropic Excessive Chat Access Failures, 1 branch(es)
* Anthropic Excessive Chat Creation, 1 branch(es)
* Anthropic Excessive Chat Deletion, 1 branch(es)
* Anthropic Excessive Chat Snapshot Creation, 1 branch(es)
* Anthropic Extra Usage Spend Limit Deleted, 1 branch(es)
* Anthropic High File Upload Activity, 1 branch(es)
* Anthropic Magic Link Second Factor Disabled, 1 branch(es)
* Anthropic Multiple Authentication Failures, 1 branch(es)
* Anthropic Organization Data Export Accessed, 1 branch(es)
* Anthropic Organization Deletion, 3 branch(es)
* Anthropic Organization Domain Boundary Changed, 4 branch(es)
* Anthropic Organization IP Restriction Deleted, 1 branch(es)
* Anthropic Organization User Invite Sent, 1 branch(es)
* Anthropic Primary Owner Transferred, 1 branch(es)
* Anthropic SSO Disabled or Connection Removed, 3 branch(es)
* Azure OpenAI Insecure Output Handling, 1 branch(es)
* Cobalt Strike Command and Control Beacon, 9 branch(es)
* Entra ID Actor Token User Impersonation Abuse, 5 branch(es)
* Entra ID MFA TOTP Brute Force Attempted, 2 branch(es)
* Entra ID Multiple Device Registrations by a Single User, 1 branch(es)
* File Transfer Utility Launched from Unusual Parent, 186 branch(es)
* GCP Vertex AI Caller Activity From High Number of Countries, 3 branch(es)
* GCP Vertex AI Elevated Safety Rating on Response, 2 branch(es)
* GCP Vertex AI High GenerateContent Volume From Single IP, 4 branch(es)
* GCP Vertex AI Publisher Model Config Modified, 2 branch(es)
* GCP Vertex AI Response Blocked by Safety Filters, 1 branch(es)
* GCP Vertex AI Safety Filters Set to BLOCK_NONE, 1 branch(es)
* GKE Rapid Secret GET Activity Against Multiple Objects, 2 branch(es)
* GitHub Exfiltration via High Number of Repository Clones by User, 1 branch(es)
* GitHub OAuth Application Authorized, 1 branch(es)
* Google Workspace Device Registration Burst for Single User, 1 branch(es)
* Halfbaked Command and Control Beacon, 16 branch(es)
* High Number of Closed Pull Requests by User, 1 branch(es)
* High Number of Egress Network Connections from Unusual Executable, 12 branch(es)
* High Number of Protected Branch Force Pushes by User, 1 branch(es)
* Kubernetes Creation or Modification of Sensitive Role, 9936 branch(es)
* Kubernetes RBAC Wildcard Elevation on Existing Role, 4 branch(es)
* Kubernetes Rapid Secret GET Activity Against Multiple Objects, 1 branch(es)
* Microsoft Foundry Jailbreak Detected, 3 branch(es)
* Multiple Alerts in Same ATT&CK Tactic by Host, 4 branch(es)
* Multiple Device Token Hashes for Single Okta Session, 1 branch(es)
* Multiple Machine Learning Alerts by Influencer Field, 1 branch(es)
* Multiple Okta User Authentication Events with Same Device Token Hash, 2 branch(es)
* Okta User Sessions Started from Different Geolocations, 2 branch(es)
* OpenAI ChatGPT Enterprise Account Owner Role Assigned, 2 branch(es)
* OpenAI ChatGPT Enterprise App Authentication Linked, 1 branch(es)
* OpenAI ChatGPT Enterprise Authentication from a Suspicious User Agent, 81 branch(es)
* OpenAI ChatGPT Enterprise Codex Access Token Created, 1 branch(es)
* OpenAI ChatGPT Enterprise Codex Security Scan Configuration Changed, 2 branch(es)
* OpenAI ChatGPT Enterprise Conversation Shared, 1 branch(es)
* OpenAI ChatGPT Enterprise Custom Agent Published, 1 branch(es)
* OpenAI ChatGPT Enterprise Custom Agent Trigger Changed, 2 branch(es)
* OpenAI ChatGPT Enterprise Domain Created, 1 branch(es)
* OpenAI ChatGPT Enterprise Excessive Conversation Deletion, 1 branch(es)
* OpenAI ChatGPT Enterprise High Codex MCP Tool Diversity, 1 branch(es)
* OpenAI ChatGPT Enterprise High File Download Activity, 1 branch(es)
* OpenAI ChatGPT Enterprise Memory Deleted, 1 branch(es)
* OpenAI ChatGPT Enterprise Multiple Authentication Failures, 1 branch(es)
* OpenAI ChatGPT Enterprise Resources Sharing Updated, 4 branch(es)
* OpenAI ChatGPT Enterprise Slack Query Burst, 1 branch(es)
* OpenAI ChatGPT Enterprise User Activity From High Number of Countries, 1 branch(es)
* OpenAI ChatGPT Enterprise User Invite Sent, 1 branch(es)
* OpenAI ChatGPT Enterprise Workspace Feature Toggled, 1 branch(es)
* OpenAI ChatGPT Enterprise Workspace Log File Deleted, 1 branch(es)
* OpenAI ChatGPT Enterprise Workspace Log Files Accessed, 2 branch(es)
* Possible FIN7 DGA Command and Control Behavior, 48 branch(es)
* Potential Entra ID PRT Extraction via BrowserCore, 1 branch(es)
* Potential Linux Local Account Brute Force Detected, 1 branch(es)
* Potential Malware-Driven SSH Brute Force Attempt, 8 branch(es)
* Potential Okta Brute Force (Multi-Source), 16 branch(es)
* Potential Password Spraying Attack via SSH, 2 branch(es)
* Potential Port Scanning Activity from Compromised Host, 1 branch(es)
* Potential SSH Brute Force Detected via macOS Security Events, 4 branch(es)
* Potential Spike in Web Server Error Logs, 1 branch(es)
* Potential Subnet Scanning Activity from Compromised Host, 1 branch(es)
* Potential Widespread Malware Infection Across Multiple Hosts, 3 branch(es)
* Privilege Escalation via Parallels Appliance Extract Argument Injection, 2 branch(es)
* SSFileCopyReceiver Writing to Common Persistence Locations, 23 branch(es)
* SSFileCopySender Executed as Root, 1 branch(es)
* Several Failed Protected Branch Force Pushes by User, 1 branch(es)
* Successful AMQP Multi-Queue Purge Burst, 1 branch(es)
* Suspicious AWS S3 Connection via Script Interpreter, 9 branch(es)
* Unusual File Creation by Web Server, 44 branch(es)
* Unusual High Denied Sensitive Information Policy Blocks Detected, 1 branch(es)
* Unusual High Denied Topic Blocks Detected, 1 branch(es)
* Unusual High Word Policy Blocks Detected, 1 branch(es)
* Unusual Process Resolving AWS ECS Agent Communication Service Endpoint, 4 branch(es)
* Web Server Potential Spike in Error Response Codes, 4 branch(es)

## Skipped (212)

* 11 x NotImplementedError: Unsupported right operand, it must be a literal
* 10 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: Esql.recent
* 8 x NotImplementedError: Unsupported second STATS
* 7 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.script_block_length
* 6 x IndexError: Cannot choose from an empty set
* 4 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.dest_host
* 4 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.executed_command
* 3 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.message_text
* 3 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.source_geo_lat
* 3 x NotImplementedError: Unsupported command: COMPLETION
* 3 x NotImplementedError: Unsupported command: IP_LOCATION
* 3 x NotImplementedError: Unsupported condition on the values of Esql.rule_severity_values
* 3 x NotImplementedError: Unsupported function: NOW
* 2 x EsqlParseError: Error at line:8,column:3
* 2 x NotImplementedError: Field type solver: constant_keyword
* 2 x NotImplementedError: Unsupported LIKE pattern, backslash escapes and character classes are not supported: 'hkey_users\\\\*\\\\software\\\\microsoft\\\\windows\\
* 2 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: Esql.date_diff
* 2 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.client_ip
* 2 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.method
* 2 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.prompt_text
* 2 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.script_block_pattern_count
* 2 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.source_ip
* 2 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.stage
* 2 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.ua_lower
* 2 x NotImplementedError: Unsupported WHERE on a field made by EVAL: request_text
* 2 x NotImplementedError: Unsupported command: INLINE
* 2 x NotImplementedError: Unsupported function: TO_IP
* 1 x EsqlParseError: Error at line:14,column:53
* 1 x EsqlParseError: Error at line:3,column:3
* 1 x EsqlParseError: Error at line:3,column:38
* 1 x EsqlParseError: Error at line:40,column:41
* 1 x EsqlParseError: Error at line:44,column:107
* 1 x EsqlParseError: Error at line:5,column:3
* 1 x EsqlParseError: Error at line:5,column:43
* 1 x EsqlParseError: Error at line:6,column:43
* 1 x EsqlParseError: Error at line:7,column:33
* 1 x NotImplementedError: Unsupported LIKE pattern, backslash escapes and character classes are not supported: '*..\\\\..\\\\..\\\\..*'
* 1 x NotImplementedError: Unsupported LIKE pattern, backslash escapes and character classes are not supported: '?:\\\\windows\\\\system32\\\\mrt.exe'
* 1 x NotImplementedError: Unsupported LIKE pattern, backslash escapes and character classes are not supported: 'c:\\\\*'
* 1 x NotImplementedError: Unsupported LIKE pattern, backslash escapes and character classes are not supported: 'c:\\\\program files\\\\*.exe'
* 1 x NotImplementedError: Unsupported WHERE on a field made by DISSECT: Esql.aws_cloudtrail_request_parameters_service_code
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: Esql.activity_fidelity_score
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: Esql.attempts_per_user
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: Esql.brute_force_type
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: Esql.dt_per_attempt
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: Esql.duration_minutes
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: Esql.error_rate
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: Esql.event_bf_type
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: Esql.event_duration_seconds
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: Esql.ml_risk_score
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: Esql.recent_minutes
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: concat_vuln_severity_values
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: delta_sec
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL after STATS: process.executable
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.attachment_search
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.audience_types
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.aws_ssm_command_id
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.azure_signinlogs_properties_app_id_coalesce
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.cloud_vendor
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.correlation_ip
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.csr_request
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.dns_tld
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.download_raw_file
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.gmail_action
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.is_device_session
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.is_high_value
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.lowercase_prompt
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.message_type
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.ml_policy_violations_mv_count
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.normalized_requester
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.o365_audit_ExtendedProperties_RequestType_lower
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.opcode
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.reply_text
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.rmm_vendor
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.scopes
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.ssh_enabled
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.target_endpoints
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.target_user_name
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.url_original_url_decoded_to_lower
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.user
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql.user_agent_original_to_lower
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql_priv.aws_bedrock_agentcore_request_payload_prompt_lower
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql_priv.aws_cloudtrail_access_key_id_correlation
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: Esql_priv.aws_cloudtrail_lifecycle_script
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: cloud_target
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: is_curl_download
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: is_genai_spawn
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: is_pkg_install
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: is_susp_powershell
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: message_type
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: message_upper
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: multi_spaces
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: parent_domain
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: response_text
* 1 x NotImplementedError: Unsupported WHERE on a field made by EVAL: session.id
* 1 x NotImplementedError: Unsupported WHERE on a field made by GROK: Esql.aws_cloudtrail_request_parameters_role_arn
* 1 x NotImplementedError: Unsupported WHERE on a field made by GROK: Esql.executable
* 1 x NotImplementedError: Unsupported WHERE on a field made by GROK: Esql.inbox_rule_name
* 1 x NotImplementedError: Unsupported WHERE on a field made by GROK: Esql.model_id
* 1 x NotImplementedError: Unsupported WHERE on a field made by GROK: Esql.plist_path
* 1 x NotImplementedError: Unsupported WHERE on a field made by GROK: Esql.screenconnect_server
* 1 x NotImplementedError: Unsupported WHERE on a field made by GROK: Esql.script_block_id
* 1 x NotImplementedError: Unsupported WHERE on a field made by GROK: chunk_index
* 1 x NotImplementedError: Unsupported WHERE on a field made by GROK: user
* 1 x NotImplementedError: Unsupported aggregate Esql.azure_ai_foundry_result_signature_failed_count, it must be a function
* 1 x NotImplementedError: Unsupported aggregate Esql.count_distinct_sensitive_ports, it must be a function
* 1 x NotImplementedError: Unsupported aggregate Esql.create_count, it must be a function
* 1 x NotImplementedError: Unsupported command: RENAME
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.alert_count_long_term_key_new_ip_rule
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.any_payload_keyword_max
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.attempt_total
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.authz_forbid_count
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.azure_open_ai_properties_request_length_avg
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.azure_open_ai_properties_response_length_max
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.device_code_auth_count
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.failure_count
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.is_browser_case_max
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.miner_register_sum
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.oauth_token_count_distinct
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.patterns_count_distinct
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.sensitive_query_count
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.total_tokens_sum
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.unique_resources
* 1 x NotImplementedError: Unsupported condition on the aggregate Esql.url_original_count_distinct
* 1 x NotImplementedError: Unsupported condition on the aggregate host_with_cpu_spike
* 1 x NotImplementedError: Unsupported condition on the values of Esql.kibana_alert_risk_score_values
* 1 x NotImplementedError: Unsupported conflicting constraints on aws.cloudtrail.request_parameters: only one equality or pattern per field is supported
* 1 x NotImplementedError: Unsupported conflicting constraints on email.subject: only one equality or pattern per field is supported
* 1 x NotImplementedError: Unsupported conflicting constraints on process.args: only one equality or pattern per field is supported
* 1 x NotImplementedError: Unsupported conflicting constraints on process.command_line: only one equality or pattern per field is supported
* 1 x NotImplementedError: Unsupported field in WHERE after STATS: access_key
* 1 x NotImplementedError: Unsupported field name: {?bucket.name.key
* 1 x NotImplementedError: Unsupported function: CONTAINS
* 1 x NotImplementedError: Unsupported function: MV_COUNT
* 1 x NotImplementedError: Unsupported function: TO_INTEGER
* 1 x NotImplementedError: Unsupported function: TO_UPPER
* 1 x NotImplementedError: Unsupported function: length
* 1 x NotImplementedError: Unsupported function: now
* 1 x NotImplementedError: Unsupported function: to_ip
* 1 x NotImplementedError: Unsupported left operand, it must be a field
* 1 x NotImplementedError: Unsupported number of different values of event.outcome: between 2 and 2 in 6 documents
* 1 x NotImplementedError: Unsupported number of different values of kubernetes.audit.annotations.`authorization_k8s_io/decision`: between 2 and 2 in 6 documents
* 1 x NotImplementedError: Unsupported predicate on metadata field: _ignored

