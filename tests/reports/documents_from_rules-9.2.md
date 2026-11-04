# Documents generation from detection rules

This report captures the error reported while generating documents from detection rules. Here you
can learn what rules are still problematic and for which no documents can be generated at the moment.

Curious about the inner workings? Read [here](signals_generation.md).

Rules version: 9.2.19

## Table of contents
   1. [Skipped rules](#skipped-rules)
      1. [Unsupported rule type: new_terms (214)](#unsupported-rule-type-new_terms-214)
      1. [Unsupported rule type: machine_learning (95)](#unsupported-rule-type-machine_learning-95)
      1. [Unsupported rule type: threshold (28)](#unsupported-rule-type-threshold-28)
      1. [Unsupported WHERE on a field made by EVAL: Esql.script_block_length (7)](#unsupported-where-on-a-field-made-by-eval-esqlscript_block_length-7)
      1. [Unsupported right operand, it must be a literal (7)](#unsupported-right-operand-it-must-be-a-literal-7)
      1. [Unsupported rule type: threat_match (6)](#unsupported-rule-type-threat_match-6)
      1. [Unsupported second STATS (6)](#unsupported-second-stats-6)
      1. [Unsupported query language: lucene (5)](#unsupported-query-language-lucene-5)
      1. [Unsupported WHERE on a field made by EVAL: Esql.executed_command (4)](#unsupported-where-on-a-field-made-by-eval-esqlexecuted_command-4)
      1. [Unsupported function: NOW (3)](#unsupported-function-now-3)
      1. [Unsupported WHERE on a field made by EVAL after STATS: Esql.brute_force_type (2)](#unsupported-where-on-a-field-made-by-eval-after-stats-esqlbrute_force_type-2)
      1. [Unsupported WHERE on a field made by EVAL: Esql.script_block_pattern_count (2)](#unsupported-where-on-a-field-made-by-eval-esqlscript_block_pattern_count-2)
      1. [Unsupported WHERE on a field made by EVAL: Esql.source_ip (2)](#unsupported-where-on-a-field-made-by-eval-esqlsource_ip-2)
      1. [Unsupported function: TO_IP (2)](#unsupported-function-to_ip-2)
      1. [Error at line:3,column:38
Invalid syntax
| where event.category == "process" and event.type == "start" and
  match(process.name, "svchost.exe", { "fuzziness": 1, "max_expansions": 10 }) and
                                     ^ (1)](#error-at-line3column38
invalid-syntax
-where-eventcategory--process-and-eventtype--start-and
--matchprocessname-svchostexe--fuzziness-1-max_expansions-10--and
--------------------------------------1)
      1. [Error at line:37,column:3
Invalid syntax
  *confluence/conf/server.xml
  */.config/gcloud/application_default_credentials.json or
  ^ (1)](#error-at-line37column3
invalid-syntax
--confluenceconfserverxml
--configgcloudapplication_default_credentialsjson-or
---1)
      1. [Error at line:43,column:41
Invalid syntax

| where file.name not like ("PSFzf.psm1", "Tenable_API_AssetLists_IPv6Seeder.ps1", "Utility.ps1")
                                        ^ (1)](#error-at-line43column41
invalid-syntax

-where-filename-not-like-psfzfpsm1-tenable_api_assetlists_ipv6seederps1-utilityps1
-----------------------------------------1)
      1. [Error at line:44,column:107
Invalid syntax
    file.directory like (
        "C:\\\\ProgramData\\\\Microsoft\\\\Windows Defender Advanced Threat Protection\\\\DataCollection*",
                                                                                                          ^ (1)](#error-at-line44column107
invalid-syntax
----filedirectory-like-
--------cprogramdatamicrosoftwindows-defender-advanced-threat-protectiondatacollection
-----------------------------------------------------------------------------------------------------------1)
      1. [Error at line:5,column:43
Invalid syntax
// Filter for scripts that contain the "char" keyword using MATCH, boosts the query performance
| where powershell.file.script_block_text : "char"
                                          ^ (1)](#error-at-line5column43
invalid-syntax
-filter-for-scripts-that-contain-the-char-keyword-using-match-boosts-the-query-performance
-where-powershellfilescript_block_text--char
-------------------------------------------1)
      1. [Error at line:6,column:43
Invalid syntax
// match will ignore the | and look for the individual words
| where powershell.file.script_block_text : "rahc|metsys|stekcos|tcejboimw|ecalper|ecnerferpe|noitcennoc|nioj|eman|vne|gnirts|tcejbo-wen|_23niw|noisserpxe|ekovni|daolnwod"
                                          ^ (1)](#error-at-line6column43
invalid-syntax
-match-will-ignore-the--and-look-for-the-individual-words
-where-powershellfilescript_block_text--rahcmetsysstekcostcejboimwecalperecnerferpenoitcennocniojemanvnegnirtstcejbo-wen_23niwnoisserpxeekovnidaolnwod
-------------------------------------------1)
      1. [Error at line:7,column:19
Invalid syntax
  process.name:(curl or wget) or
  process.args:(* curl* or */bin/curl* or *wget*)
                  ^ (1)](#error-at-line7column19
invalid-syntax
--processnamecurl-or-wget-or
--processargs-curl-or-bincurl-or-wget
-------------------1)
      1. [Error at line:7,column:33
Invalid syntax
    github.reasons.code == "workflow_updates" and
    match(github.reasons.message::STRING, "refusing to allow a GitHub App to create or update workflow")
                                ^ (1)](#error-at-line7column33
invalid-syntax
----githubreasonscode--workflow_updates-and
----matchgithubreasonsmessagestring-refusing-to-allow-a-github-app-to-create-or-update-workflow
---------------------------------1)
      1. [Unsupported LIKE pattern, only a backslash can be escaped with a backslash: '*...\\*' (1)](#unsupported-like-pattern-only-a-backslash-can-be-escaped-with-a-backslash--1)
      1. [Unsupported WHERE on a field made by DISSECT: Esql.aws_cloudtrail_request_parameters_service_code (1)](#unsupported-where-on-a-field-made-by-dissect-esqlaws_cloudtrail_request_parameters_service_code-1)
      1. [Unsupported WHERE on a field made by DISSECT: Esql.external_idp_old_issuer (1)](#unsupported-where-on-a-field-made-by-dissect-esqlexternal_idp_old_issuer-1)
      1. [Unsupported WHERE on a field made by EVAL after STATS: Esql.activity_fidelity_score (1)](#unsupported-where-on-a-field-made-by-eval-after-stats-esqlactivity_fidelity_score-1)
      1. [Unsupported WHERE on a field made by EVAL after STATS: Esql.attempts_per_user (1)](#unsupported-where-on-a-field-made-by-eval-after-stats-esqlattempts_per_user-1)
      1. [Unsupported WHERE on a field made by EVAL after STATS: Esql.dt_per_attempt (1)](#unsupported-where-on-a-field-made-by-eval-after-stats-esqldt_per_attempt-1)
      1. [Unsupported WHERE on a field made by EVAL after STATS: Esql.duration_minutes (1)](#unsupported-where-on-a-field-made-by-eval-after-stats-esqlduration_minutes-1)
      1. [Unsupported WHERE on a field made by EVAL after STATS: Esql.error_rate (1)](#unsupported-where-on-a-field-made-by-eval-after-stats-esqlerror_rate-1)
      1. [Unsupported WHERE on a field made by EVAL after STATS: Esql.event_bf_type (1)](#unsupported-where-on-a-field-made-by-eval-after-stats-esqlevent_bf_type-1)
      1. [Unsupported WHERE on a field made by EVAL after STATS: Esql.event_duration_seconds (1)](#unsupported-where-on-a-field-made-by-eval-after-stats-esqlevent_duration_seconds-1)
      1. [Unsupported WHERE on a field made by EVAL after STATS: Esql.ml_risk_score (1)](#unsupported-where-on-a-field-made-by-eval-after-stats-esqlml_risk_score-1)
      1. [Unsupported WHERE on a field made by EVAL after STATS: Esql.risk_alerts_count_ratio (1)](#unsupported-where-on-a-field-made-by-eval-after-stats-esqlrisk_alerts_count_ratio-1)
      1. [Unsupported WHERE on a field made by EVAL after STATS: concat_vuln_severity_values (1)](#unsupported-where-on-a-field-made-by-eval-after-stats-concat_vuln_severity_values-1)
      1. [Unsupported WHERE on a field made by EVAL after STATS: delta_sec (1)](#unsupported-where-on-a-field-made-by-eval-after-stats-delta_sec-1)
      1. [Unsupported WHERE on a field made by EVAL after STATS: isLocal (1)](#unsupported-where-on-a-field-made-by-eval-after-stats-islocal-1)
      1. [Unsupported WHERE on a field made by EVAL after STATS: process.executable (1)](#unsupported-where-on-a-field-made-by-eval-after-stats-processexecutable-1)
      1. [Unsupported WHERE on a field made by EVAL: Esql.aws_ssm_command_id (1)](#unsupported-where-on-a-field-made-by-eval-esqlaws_ssm_command_id-1)
      1. [Unsupported WHERE on a field made by EVAL: Esql.cloud_vendor (1)](#unsupported-where-on-a-field-made-by-eval-esqlcloud_vendor-1)
      1. [Unsupported WHERE on a field made by EVAL: Esql.is_high_value (1)](#unsupported-where-on-a-field-made-by-eval-esqlis_high_value-1)
      1. [Unsupported WHERE on a field made by EVAL: Esql.ml_policy_violations_mv_count (1)](#unsupported-where-on-a-field-made-by-eval-esqlml_policy_violations_mv_count-1)
      1. [Unsupported WHERE on a field made by EVAL: Esql.rmm_vendor (1)](#unsupported-where-on-a-field-made-by-eval-esqlrmm_vendor-1)
      1. [Unsupported WHERE on a field made by EVAL: Esql.server_webdav_server (1)](#unsupported-where-on-a-field-made-by-eval-esqlserver_webdav_server-1)
      1. [Unsupported WHERE on a field made by EVAL: Esql.signin_source_asn (1)](#unsupported-where-on-a-field-made-by-eval-esqlsignin_source_asn-1)
      1. [Unsupported WHERE on a field made by EVAL: Esql.target_endpoints (1)](#unsupported-where-on-a-field-made-by-eval-esqltarget_endpoints-1)
      1. [Unsupported WHERE on a field made by EVAL: Esql.target_user_name (1)](#unsupported-where-on-a-field-made-by-eval-esqltarget_user_name-1)
      1. [Unsupported WHERE on a field made by EVAL: Esql.url_original_url_decoded_to_lower (1)](#unsupported-where-on-a-field-made-by-eval-esqlurl_original_url_decoded_to_lower-1)
      1. [Unsupported WHERE on a field made by EVAL: Esql_priv.aws_cloudtrail_lifecycle_script (1)](#unsupported-where-on-a-field-made-by-eval-esql_privaws_cloudtrail_lifecycle_script-1)
      1. [Unsupported WHERE on a field made by EVAL: cloud_target (1)](#unsupported-where-on-a-field-made-by-eval-cloud_target-1)
      1. [Unsupported WHERE on a field made by EVAL: message_upper (1)](#unsupported-where-on-a-field-made-by-eval-message_upper-1)
      1. [Unsupported WHERE on a field made by EVAL: multi_spaces (1)](#unsupported-where-on-a-field-made-by-eval-multi_spaces-1)
      1. [Unsupported WHERE on a field made by EVAL: parent_domain (1)](#unsupported-where-on-a-field-made-by-eval-parent_domain-1)
      1. [Unsupported WHERE on a field made by GROK: Esql.inbox_rule_name (1)](#unsupported-where-on-a-field-made-by-grok-esqlinbox_rule_name-1)
      1. [Unsupported WHERE on a field made by GROK: Esql.model_id (1)](#unsupported-where-on-a-field-made-by-grok-esqlmodel_id-1)
      1. [Unsupported WHERE on a field made by GROK: Esql.screenconnect_server (1)](#unsupported-where-on-a-field-made-by-grok-esqlscreenconnect_server-1)
      1. [Unsupported WHERE on a field made by GROK: Esql.script_block_id (1)](#unsupported-where-on-a-field-made-by-grok-esqlscript_block_id-1)
      1. [Unsupported WHERE on a field made by GROK: chunk_index (1)](#unsupported-where-on-a-field-made-by-grok-chunk_index-1)
      1. [Unsupported aggregate Esql.count_distinct_sensitive_ports, it must be a function (1)](#unsupported-aggregate-esqlcount_distinct_sensitive_ports-it-must-be-a-function-1)
      1. [Unsupported command: COMPLETION (1)](#unsupported-command-completion-1)
      1. [Unsupported command: RENAME (1)](#unsupported-command-rename-1)
      1. [Unsupported conflicting constraints on aws.cloudtrail.request_parameters: only one equality or pattern per field is supported (1)](#unsupported-conflicting-constraints-on-awscloudtrailrequest_parameters-only-one-equality-or-pattern-per-field-is-supported-1)
      1. [Unsupported conflicting constraints on email.subject: only one equality or pattern per field is supported (1)](#unsupported-conflicting-constraints-on-emailsubject-only-one-equality-or-pattern-per-field-is-supported-1)
      1. [Unsupported conflicting constraints on process.args: only one equality or pattern per field is supported (1)](#unsupported-conflicting-constraints-on-processargs-only-one-equality-or-pattern-per-field-is-supported-1)
      1. [Unsupported conflicting constraints on process.command_line: only one equality or pattern per field is supported (1)](#unsupported-conflicting-constraints-on-processcommand_line-only-one-equality-or-pattern-per-field-is-supported-1)
      1. [Unsupported field name: {?bucket.name.key (1)](#unsupported-field-name-bucketnamekey-1)
      1. [Unsupported function: TO_INTEGER (1)](#unsupported-function-to_integer-1)
      1. [Unsupported function: length (1)](#unsupported-function-length-1)
      1. [Unsupported function: now (1)](#unsupported-function-now-1)
      1. [Unsupported function: to_ip (1)](#unsupported-function-to_ip-1)
      1. [Unsupported left operand, it must be a field (1)](#unsupported-left-operand-it-must-be-a-field-1)
      1. [Unsupported predicate on metadata field: _ignored (1)](#unsupported-predicate-on-metadata-field-_ignored-1)
   1. [Generation errors](#generation-errors)
      1. [Unsupported function: match (33)](#unsupported-function-match-33)
      1. [Unsupported function: stringContains (25)](#unsupported-function-stringcontains-25)
      1. [Root with too many branches (limit: 10000) (21)](#root-with-too-many-branches-limit-10000-21)
      1. [Unsupported LHS type: <class 'eql.ast.FunctionCall'> (11)](#unsupported-lhs-type-class-eqlastfunctioncall-11)
      1. [Unsupported argument type(s): <class 'eql.ast.Field'> (10)](#unsupported-argument-types-class-eqlastfield-10)
      1. [Root without branches (9)](#root-without-branches-9)
      1. [Unsupported function: startsWith (4)](#unsupported-function-startswith-4)
      1. [<class 'eql.ast.Sample'> (3)](#class-eqlastsample-3)
      1. [Unsupported &keyword 'process.Ext.relative_file_creation_time' constraint: <= (3)](#unsupported-keyword-processextrelative_file_creation_time-constraint--3)
      1. [Unsupported argument type(s): <class 'eql.ast.FunctionCall'> (3)](#unsupported-argument-types-class-eqlastfunctioncall-3)
      1. [Unsupported argument type: <class 'eql.ast.FunctionCall'> (3)](#unsupported-argument-type-class-eqlastfunctioncall-3)
      1. [Unsupported condition on the values of Esql.rule_severity_values (3)](#unsupported-condition-on-the-values-of-esqlrule_severity_values-3)
      1. [Unsupported function: endswith (3)](#unsupported-function-endswith-3)
      1. [Unsupported &keyword 'file.Ext.windows.zone_identifier' constraint: > (2)](#unsupported-keyword-fileextwindowszone_identifier-constraint--2)
      1. [Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)](#unsupported-keyword-processparentextrealpid-constraint--2)
      1. [Unsupported condition on the aggregate Esql.url_original_count_distinct (2)](#unsupported-condition-on-the-aggregate-esqlurl_original_count_distinct-2)
      1. [Unsupported is_negated: {'is_negated': True} (2)](#unsupported-is_negated-is_negated-true-2)
      1. ['NoneType' object is not subscriptable (1)](#nonetype-object-is-not-subscriptable-1)
      1. [<class 'eql.ast.SubqueryBy'> (1)](#class-eqlastsubqueryby-1)
      1. [Field type solver: flattened (1)](#field-type-solver-flattened-1)
      1. [Unsolvable constraints: event.action (3 different values are needed, the conditions allow 2) (1)](#unsolvable-constraints-eventaction-3-different-values-are-needed-the-conditions-allow-2-1)
      1. [Unsolvable constraints: file.extension (cannot be non-null) (1)](#unsolvable-constraints-fileextension-cannot-be-non-null-1)
      1. [Unsolvable constraints: fortinet.firewall.cfgattr (not in Strings({'*srcaddr[all]*'}): ('*dstaddr[all]*')) (1)](#unsolvable-constraints-fortinetfirewallcfgattr-not-in-stringssrcaddrall-dstaddrall-1)
      1. [Unsolvable constraints: http.request.body.content (not in Strings({'*/swip/Upload.ashx*'}): ('POST*')) (1)](#unsolvable-constraints-httprequestbodycontent-not-in-stringsswipuploadashx-post-1)
      1. [Unsolvable constraints: http.request.body.content (not in Strings({'*Content-Disposition: form-data*'}): ('*filename=*')) (1)](#unsolvable-constraints-httprequestbodycontent-not-in-stringscontent-disposition-form-data-filename-1)
      1. [Unsolvable constraints: kubernetes.audit.requestObject.spec.containers.image (cannot be null) (1)](#unsolvable-constraints-kubernetesauditrequestobjectspeccontainersimage-cannot-be-null-1)
      1. [Unsolvable constraints: message (not in Strings({'segfault'}): ('agetty')) (1)](#unsolvable-constraints-message-not-in-stringssegfault-agetty-1)
      1. [Unsolvable constraints: network_traffic.redis.query (not in Strings({'*CONFIG SET dir*'}): ('*/.ssh*')) (1)](#unsolvable-constraints-network_trafficredisquery-not-in-stringsconfig-set-dir-ssh-1)
      1. [Unsolvable constraints: network_traffic.redis.query (not in Strings({'*CONFIG SET dir*'}): ('*/etc/cron*')) (1)](#unsolvable-constraints-network_trafficredisquery-not-in-stringsconfig-set-dir-etccron-1)
      1. [Unsolvable constraints: network_traffic.redis.query (not in Strings({'*EVAL*'}): ('*string.rep*')) (1)](#unsolvable-constraints-network_trafficredisquery-not-in-stringseval-stringrep-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscopyfromscreen-systemdrawingbitmap-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Cryptography.AESManaged'}): ('CipherMode')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringscryptographyaesmanaged-ciphermode-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Invoke-WmiMethod'}): ('ComputerName')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsinvoke-wmimethod-computername-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'LsaCallAuthenticationPackage'}): ('KerbRetrieveEncodedTicketMessage')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringslsacallauthenticationpackage-kerbretrieveencodedticketmessage-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Microsoft.Office.Interop.Outlook'}): ('MAPI')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsmicrosoftofficeinteropoutlook-mapi-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'NdrClientCall'}): ('GetProcAddress')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsndrclientcall-getprocaddress-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'New-MailboxExportRequest'}): ('-FilePath')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsnew-mailboxexportrequest--filepath-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Set-MpPreference'}): ('DisableArchiveScanning')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsset-mppreference-disablearchivescanning-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsvirtualalloc-writeprocessmemory-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[System.Reflection.Assembly]::Load'}): ('FromBase64String')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringssystemreflectionassemblyload-frombase64string-1)
      1. [Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[string]::join'}): ('$pSHoMe[')) (1)](#unsolvable-constraints-powershellfilescript_block_text-not-in-stringsstringjoin-pshome-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*\\*\*$*'}): ('* copy*')) (1)](#unsolvable-constraints-processcommand_line-not-in-strings--copy-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*com.apple.Safari*'}): ('*IncludeDevelopMenu*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringscomapplesafari-includedevelopmenu-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*csrutil*status*'}): ('*enabled*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringscsrutilstatus-enabled-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*drive.google.com*'}): ('*export=download*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsdrivegooglecom-exportdownload-1)
      1. [Unsolvable constraints: process.command_line (not in Strings({'*id_dsa*'}): ('*/home/*')) (1)](#unsolvable-constraints-processcommand_line-not-in-stringsid_dsa-home-1)
      1. [Unsolvable constraints: process.pid (out of boundary, 1 <= 0 <= 4294967295) (1)](#unsolvable-constraints-processpid-out-of-boundary-1--0--4294967295-1)
      1. [Unsolvable constraints: request (not in Strings({'*MSOTlPn_Uri*'}): ('*DisplayMode*')) (1)](#unsolvable-constraints-request-not-in-stringsmsotlpn_uri-displaymode-1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*'}): ('*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings1131f6ad-9c07-11d1-f79f-00c04fc2dcd2s-1-5-21--1131f6aa-9c07-11d1-f79f-00c04fc2dcd2s-1-5-21--1)
      1. [Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)](#unsolvable-constraints-winlogevent_dataattributevalue-not-in-strings827d319e-6eac-11d2-a4ea-00c04f79f83a-803e14a0-b4fb-11d0-a0d0-00a0c90f574b-1)
      1. [Unsolvable constraints: winlog.event_data.param1 (not in Strings({'*FullControl*'}): ('*setsharingmode*')) (1)](#unsolvable-constraints-winlogevent_dataparam1-not-in-stringsfullcontrol-setsharingmode-1)
      1. [Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: < (1)](#unsupported-keyword-dllextrelative_file_creation_time-constraint--1)
      1. [Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: <= (1)](#unsupported-keyword-dllextrelative_file_creation_time-constraint--1)
      1. [Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)](#unsupported-keyword-fileextentropy-constraint--1)
      1. [Unsupported &keyword 'kibana.alert.risk_score' constraint: > (1)](#unsupported-keyword-kibanaalertrisk_score-constraint--1)
      1. [Unsupported &keyword 'ml_is_dga.malicious_probability' constraint: > (1)](#unsupported-keyword-ml_is_dgamalicious_probability-constraint--1)
      1. [Unsupported &keyword 'o365.audit.OperationCount' constraint: >= (1)](#unsupported-keyword-o365auditoperationcount-constraint--1)
      1. [Unsupported &keyword 'powershell.file.script_block_entropy_bits' constraint: >= (1)](#unsupported-keyword-powershellfilescript_block_entropy_bits-constraint--1)
      1. [Unsupported &keyword 'powershell.file.script_block_length' constraint: > (1)](#unsupported-keyword-powershellfilescript_block_length-constraint--1)
      1. [Unsupported &keyword 'problemchild.prediction_probability' constraint: <= (1)](#unsupported-keyword-problemchildprediction_probability-constraint--1)
      1. [Unsupported &keyword 'problemchild.prediction_probability' constraint: > (1)](#unsupported-keyword-problemchildprediction_probability-constraint--1)
      1. [Unsupported &keyword 'system.process.cpu.total.norm.pct' constraint: >= (1)](#unsupported-keyword-systemprocesscputotalnormpct-constraint--1)
      1. [Unsupported condition on the aggregate Esql.alert_count_long_term_key_new_ip_rule (1)](#unsupported-condition-on-the-aggregate-esqlalert_count_long_term_key_new_ip_rule-1)
      1. [Unsupported condition on the aggregate Esql.any_payload_keyword_max (1)](#unsupported-condition-on-the-aggregate-esqlany_payload_keyword_max-1)
      1. [Unsupported condition on the aggregate Esql.authz_forbid_count (1)](#unsupported-condition-on-the-aggregate-esqlauthz_forbid_count-1)
      1. [Unsupported condition on the aggregate Esql.azure_open_ai_properties_request_length_avg (1)](#unsupported-condition-on-the-aggregate-esqlazure_open_ai_properties_request_length_avg-1)
      1. [Unsupported condition on the aggregate Esql.azure_open_ai_properties_response_length_max (1)](#unsupported-condition-on-the-aggregate-esqlazure_open_ai_properties_response_length_max-1)
      1. [Unsupported condition on the aggregate Esql.device_code_auth_count (1)](#unsupported-condition-on-the-aggregate-esqldevice_code_auth_count-1)
      1. [Unsupported condition on the aggregate Esql.dhcpv4_client_mac_count_distinct (1)](#unsupported-condition-on-the-aggregate-esqldhcpv4_client_mac_count_distinct-1)
      1. [Unsupported condition on the aggregate Esql.is_browser_case_max (1)](#unsupported-condition-on-the-aggregate-esqlis_browser_case_max-1)
      1. [Unsupported condition on the aggregate Esql.oauth_token_count_distinct (1)](#unsupported-condition-on-the-aggregate-esqloauth_token_count_distinct-1)
      1. [Unsupported condition on the aggregate Esql.patterns_count_distinct (1)](#unsupported-condition-on-the-aggregate-esqlpatterns_count_distinct-1)
      1. [Unsupported condition on the aggregate host_with_cpu_spike (1)](#unsupported-condition-on-the-aggregate-host_with_cpu_spike-1)
      1. [Unsupported condition on the values of Esql.kibana_alert_risk_score_values (1)](#unsupported-condition-on-the-values-of-esqlkibana_alert_risk_score_values-1)
      1. [Unsupported field in WHERE after STATS: access_key (1)](#unsupported-field-in-where-after-stats-access_key-1)
      1. [Unsupported number of different values of kubernetes.audit.annotations.`authorization_k8s_io/decision`: between 2 and 2 in 6 documents (1)](#unsupported-number-of-different-values-of-kubernetesauditannotationsauthorization_k8s_iodecision-between-2-and-2-in-6-documents-1)

## Skipped rules

### Unsupported rule type: new_terms (214)

214 rules:

* AWS API Activity from Uncommon S3 Client by Rare User
* AWS Account Discovery By Rare User
* AWS Bedrock Agent or Action Group Manipulation
* AWS Bedrock Knowledge Base or RAG Data Source Tampering
* AWS Bedrock Resource-Based Policy Modified or Deleted
* AWS Bedrock Third-Party or External Knowledge Base Associated to Agent
* AWS CLI Command with Custom Endpoint URL
* AWS Discovery API Calls from VPN ASN for the First Time by Identity
* AWS DynamoDB Scan by Unusual User
* AWS DynamoDB Table Exported to S3
* AWS EC2 CreateKeyPair by New Principal from Non-Cloud AS Organization
* AWS EC2 Role GetCallerIdentity from New Source AS Organization
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
* AWS Lambda Function Invoked by an Unusual Principal
* AWS Lambda Function Invoked from an Unusual Source ASN
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
* Azure AD Graph Access with Unusual Client and User
* Azure AD Graph Access with Unusual User and ASN
* Azure Arc Cluster Credential Access by Identity from Unusual Source
* Azure Compute Restore Point Collection Deleted by Unusual User
* Azure Compute Snapshot Deletion by Unusual User and Resource Group
* Azure Compute VM Command Executed
* Azure Diagnostic Settings Deleted
* Azure Key Vault Modified
* Azure Key Vault Unusual Secret Key Usage
* Azure Storage Account Blob Public Access Enabled
* Azure Storage Account Deletion by Unusual User
* Azure Storage Account Keys Accessed by Privileged User
* Azure Storage Blob Retrieval via AzCopy
* Azure VM Extension CRUD Operation with Unusual Source ASN
* Azure VM Managed Run Command Created or Updated with Unusual Principal
* Azure VM Serial Console Connection with Unusual User and ASN
* DPKG Package Installed by Unusual Parent Process
* Delegated Managed Service Account Modification by an Unusual User
* Deprecated - Suspicious PrintSpooler Service Executable File Creation
* Deprecated - Unusual Discovery Activity by User
* Deprecated TLS Version or Weak Cipher Negotiated Externally
* Discovery of Internet Capabilities via Built-in Tools
* Entra ID Conditional Access Policy (CAP) Modified
* Entra ID Device with ROADtools Default OS Build (Entity Analytics)
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
* First Time Seen Account Performing DCSync
* First Time Seen Driver Loaded
* First Time Seen Google Workspace OAuth Login from Third-Party Application
* First Time Seen NewCredentials Logon Process
* First Time Seen Remote Monitoring and Management Tool
* First Time Seen Removable Device
* FortiGate Administrator Account Creation from Unusual Source
* GKE Secrets List from Unusual Source AS Organization
* GKE User Exec into Pod
* GenAI Process Connection to Unusual Domain
* GitHub Actions Unusual Bot Push to Repository
* Github Activity on a Private Repository from an Unusual IP
* Google Workspace User Login with Unusual ASN
* Google Workspace User Sign-in from Atypical Device Type
* Interactive Shell Launched via Unusual Parent Process in a Container
* Kernel Object File Creation
* Kill Command Execution
* Kubernetes Anonymous Request Authorized by Unusual User Agent
* Kubernetes Denied Service Account Request via Unusual User Agent
* Kubernetes Forbidden Request from Unusual User Agent
* Kubernetes Pod Creation Using Common Debug or Base Images
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
* M365 Identity Device Code Grant by an Unusual User (Non-Compliant Device)
* M365 Identity Device Code Grant with Unusual User and ASN
* M365 Identity Login from Atypical Region
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
* New USB Storage Device Mounted
* Okta Sign-In Events via Third-Party IdP
* Potential Credential Access via DCSync
* Potential HTTP Downgrade Attack
* Potential ICMP Tunneling Activity to the Internet
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
* SMB (Windows File Sharing) Activity from the Internet
* SMB (Windows File Sharing) Activity to the Internet
* SSH Authorized Keys File Activity
* Sensitive Files Compression
* Shared Object Created by Previously Unknown Process
* Successful Application SSO from Rare Unknown Client Device
* Successful SSH Authentication from Unusual IP Address
* Successful SSH Authentication from Unusual SSH Public Key
* Successful SSH Authentication from Unusual User
* Suspicious Instance Metadata Service (IMDS) API Request
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
* Unusual Child Execution via Web Server
* Unusual Command Execution via Web Server
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
* Entra ID Excessive Account Lockouts Detected
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

### Unsupported WHERE on a field made by EVAL: Esql.script_block_length (7)

7 rules:

* Dynamic IEX Reconstruction via Method String Access
* Potential Dynamic IEX Reconstruction via Environment Variables
* Potential PowerShell Obfuscation via Backtick-Escaped Variable Expansion
* Potential PowerShell Obfuscation via High Special Character Proportion
* Potential PowerShell Obfuscation via Special Character Overuse
* Potential PowerShell Obfuscation via String Concatenation
* Potential PowerShell Obfuscation via String Reordering

### Unsupported right operand, it must be a literal (7)

7 rules:

* AWS IAM User Created Access Keys For Another User
* AWS Lambda Function Invoked Cross-Account
* AWS S3 Object Encryption Using External KMS Key
* Newly Observed Elastic Defend Behavior Alert
* Newly Observed High Severity Detection Alert
* Okta AiTM Session Cookie Replay
* Okta Successful Login After Credential Attack

### Unsupported rule type: threat_match (6)

6 rules:

* Rapid7 Threat Command CVEs Correlation
* Threat Intel Email Indicator Match
* Threat Intel Hash Indicator Match
* Threat Intel IP Address Indicator Match
* Threat Intel URL Indicator Match
* Threat Intel Windows Registry Indicator Match

### Unsupported second STATS (6)

6 rules:

* Multiple Elastic Defend Alerts from a Single Process Tree
* Potential Account Takeover - Logon from New Source IP
* Potential Account Takeover - Mixed Logon Types
* Potential Okta Credential Stuffing (Single Source)
* Potential Okta Password Spray (Single Source)
* Unusual High Confidence Content Filter Blocks Detected

### Unsupported query language: lucene (5)

5 rules:

* Cobalt Strike Command and Control Beacon
* Halfbaked Command and Control Beacon
* Inbound Connection to an Unsecure Elasticsearch Node
* Possible FIN7 DGA Command and Control Behavior
* Potential cPanel WHM CRLF Authentication Bypass (CVE-2026-41940)

### Unsupported WHERE on a field made by EVAL: Esql.executed_command (4)

4 rules:

* Kubernetes Pod Exec Cloud Instance Metadata Access
* Kubernetes Pod Exec Potential Reverse Shell
* Kubernetes Pod Exec Sensitive File or Credential Path Access
* Kubernetes Pod Exec with Curl or Wget to HTTPS

### Unsupported function: NOW (3)

3 rules:

* AWS Credentials Used from GitHub Actions and Non-CI/CD Infrastructure
* AWS Rare Source AS Organization Activity
* Kubernetes Secret or ConfigMap Access via Azure Arc Proxy

### Unsupported WHERE on a field made by EVAL after STATS: Esql.brute_force_type (2)

2 rules:

* Entra ID User Sign-in Brute Force Attempted
* M365 Identity User Brute Force Attempted

### Unsupported WHERE on a field made by EVAL: Esql.script_block_pattern_count (2)

2 rules:

* Potential PowerShell Obfuscation via Concatenated Dynamic Command Invocation
* Potential PowerShell Obfuscation via Invalid Escape Sequences

### Unsupported WHERE on a field made by EVAL: Esql.source_ip (2)

2 rules:

* Elastic Defend and Network Security Alerts Correlation
* Suspected Lateral Movement from Compromised Host

### Unsupported function: TO_IP (2)

2 rules:

* Multiple Logon Failure from the same Source Address
* Privileged Accounts Brute Force

### Error at line:3,column:38
Invalid syntax
| where event.category == "process" and event.type == "start" and
  match(process.name, "svchost.exe", { "fuzziness": 1, "max_expansions": 10 }) and
                                     ^ (1)

1 rules:

* Potential Masquerading as Svchost

### Error at line:37,column:3
Invalid syntax
  *confluence/conf/server.xml
  */.config/gcloud/application_default_credentials.json or
  ^ (1)

1 rules:

* Kubernetes and Cloud Credential Path Access via Process Arguments

### Error at line:43,column:41
Invalid syntax

| where file.name not like ("PSFzf.psm1", "Tenable_API_AssetLists_IPv6Seeder.ps1", "Utility.ps1")
                                        ^ (1)

1 rules:

* PowerShell Obfuscation via Negative Index String Reversal

### Error at line:44,column:107
Invalid syntax
    file.directory like (
        "C:\\\\ProgramData\\\\Microsoft\\\\Windows Defender Advanced Threat Protection\\\\DataCollection*",
                                                                                                          ^ (1)

1 rules:

* Potential PowerShell Obfuscation via High Numeric Character Proportion

### Error at line:5,column:43
Invalid syntax
// Filter for scripts that contain the "char" keyword using MATCH, boosts the query performance
| where powershell.file.script_block_text : "char"
                                          ^ (1)

1 rules:

* Potential PowerShell Obfuscation via Character Array Reconstruction

### Error at line:6,column:43
Invalid syntax
// match will ignore the | and look for the individual words
| where powershell.file.script_block_text : "rahc|metsys|stekcos|tcejboimw|ecalper|ecnerferpe|noitcennoc|nioj|eman|vne|gnirts|tcejbo-wen|_23niw|noisserpxe|ekovni|daolnwod"
                                          ^ (1)

1 rules:

* Potential PowerShell Obfuscation via Reverse Keywords

### Error at line:7,column:19
Invalid syntax
  process.name:(curl or wget) or
  process.args:(* curl* or */bin/curl* or *wget*)
                  ^ (1)

1 rules:

* Curl or Wget Execution from Container Context

### Error at line:7,column:33
Invalid syntax
    github.reasons.code == "workflow_updates" and
    match(github.reasons.message::STRING, "refusing to allow a GitHub App to create or update workflow")
                                ^ (1)

1 rules:

* GitHub Actions Workflow Modification Blocked

### Unsupported LIKE pattern, only a backslash can be escaped with a backslash: '*...\\*' (1)

1 rules:

* Web Server Local File Inclusion Activity

### Unsupported WHERE on a field made by DISSECT: Esql.aws_cloudtrail_request_parameters_service_code (1)

1 rules:

* AWS Service Quotas Multi-Region GetServiceQuota Requests

### Unsupported WHERE on a field made by DISSECT: Esql.external_idp_old_issuer (1)

1 rules:

* Entra ID Federated Identity Credential Issuer Modified

### Unsupported WHERE on a field made by EVAL after STATS: Esql.activity_fidelity_score (1)

1 rules:

* AWS Access Token Used from Multiple Addresses

### Unsupported WHERE on a field made by EVAL after STATS: Esql.attempts_per_user (1)

1 rules:

* Potential Okta Password Spray (Multi-Source)

### Unsupported WHERE on a field made by EVAL after STATS: Esql.dt_per_attempt (1)

1 rules:

* Potential Okta Brute Force (Device Token Rotation)

### Unsupported WHERE on a field made by EVAL after STATS: Esql.duration_minutes (1)

1 rules:

* Splunk Enterprise PostgreSQL Backup-to-Restore Potential RCE Sequence

### Unsupported WHERE on a field made by EVAL after STATS: Esql.error_rate (1)

1 rules:

* Azure AD Graph High 4xx Error Ratio from User

### Unsupported WHERE on a field made by EVAL after STATS: Esql.event_bf_type (1)

1 rules:

* Entra ID Sign-in Brute Force Attempted (Microsoft 365)

### Unsupported WHERE on a field made by EVAL after STATS: Esql.event_duration_seconds (1)

1 rules:

* M365 Identity User Account Lockouts

### Unsupported WHERE on a field made by EVAL after STATS: Esql.ml_risk_score (1)

1 rules:

* Potential Abuse of Resources by High Token Count and Large Response Sizes

### Unsupported WHERE on a field made by EVAL after STATS: Esql.risk_alerts_count_ratio (1)

1 rules:

* Alerts in Different ATT&CK Tactics by Host

### Unsupported WHERE on a field made by EVAL after STATS: concat_vuln_severity_values (1)

1 rules:

* Multiple Vulnerabilities by Asset via Wiz

### Unsupported WHERE on a field made by EVAL after STATS: delta_sec (1)

1 rules:

* Azure Run Command Correlated with Process Execution

### Unsupported WHERE on a field made by EVAL after STATS: isLocal (1)

1 rules:

* Lateral Movement Alerts from a Newly Observed Source Address

### Unsupported WHERE on a field made by EVAL after STATS: process.executable (1)

1 rules:

* Detection Alert on a Process Exhibiting CPU Spike

### Unsupported WHERE on a field made by EVAL: Esql.aws_ssm_command_id (1)

1 rules:

* AWS EC2 LOLBin Execution via SSM SendCommand

### Unsupported WHERE on a field made by EVAL: Esql.cloud_vendor (1)

1 rules:

* Multiple Cloud Secrets Accessed by Source Address

### Unsupported WHERE on a field made by EVAL: Esql.is_high_value (1)

1 rules:

* Microsoft Graph Multi-Category Reconnaissance Burst

### Unsupported WHERE on a field made by EVAL: Esql.ml_policy_violations_mv_count (1)

1 rules:

* AWS Bedrock Guardrails Detected Multiple Policy Violations Within a Single Blocked Request

### Unsupported WHERE on a field made by EVAL: Esql.rmm_vendor (1)

1 rules:

* Multiple Remote Management Tool Vendors on Same Host

### Unsupported WHERE on a field made by EVAL: Esql.server_webdav_server (1)

1 rules:

* Rare Connection to WebDAV Target

### Unsupported WHERE on a field made by EVAL: Esql.signin_source_asn (1)

1 rules:

* Entra ID OAuth User Impersonation to Microsoft Graph

### Unsupported WHERE on a field made by EVAL: Esql.target_endpoints (1)

1 rules:

* Azure AD Graph Potential Enumeration (ROADrecon)

### Unsupported WHERE on a field made by EVAL: Esql.target_user_name (1)

1 rules:

* Elastic Defend and Email Alerts Correlation

### Unsupported WHERE on a field made by EVAL: Esql.url_original_url_decoded_to_lower (1)

1 rules:

* Web Server Potential Remote File Inclusion Activity

### Unsupported WHERE on a field made by EVAL: Esql_priv.aws_cloudtrail_lifecycle_script (1)

1 rules:

* AWS SageMaker Notebook Lifecycle Configuration With Suspicious Script Content

### Unsupported WHERE on a field made by EVAL: cloud_target (1)

1 rules:

* Multi-Cloud CLI Token and Credential Access Commands

### Unsupported WHERE on a field made by EVAL: message_upper (1)

1 rules:

* Potential SQL Injection Against Microsoft SQL Server

### Unsupported WHERE on a field made by EVAL: multi_spaces (1)

1 rules:

* Command Line Obfuscation via Whitespace Padding

### Unsupported WHERE on a field made by EVAL: parent_domain (1)

1 rules:

* First Time Seen DNS Query to RMM Domain

### Unsupported WHERE on a field made by GROK: Esql.inbox_rule_name (1)

1 rules:

* M365 Exchange Inbox Rule with Obfuscated Name

### Unsupported WHERE on a field made by GROK: Esql.model_id (1)

1 rules:

* AWS Bedrock High-Frequency Single-Model Inference API Probing

### Unsupported WHERE on a field made by GROK: Esql.screenconnect_server (1)

1 rules:

* Newly Observed ScreenConnect Host Server

### Unsupported WHERE on a field made by GROK: Esql.script_block_id (1)

1 rules:

* Potential Malicious PowerShell Based on Alert Correlation

### Unsupported WHERE on a field made by GROK: chunk_index (1)

1 rules:

* Potential DNS Exfiltration via Excessive Chunked Queries

### Unsupported aggregate Esql.count_distinct_sensitive_ports, it must be a function (1)

1 rules:

* Potential Network Scan Detected

### Unsupported command: COMPLETION (1)

1 rules:

* Correlated Alerts on Similar User Identities

### Unsupported command: RENAME (1)

1 rules:

* Entra ID Illicit Consent Grant via Registered Application

### Unsupported conflicting constraints on aws.cloudtrail.request_parameters: only one equality or pattern per field is supported (1)

1 rules:

* AWS ECR Repository or Registry Policy Granted Public Access

### Unsupported conflicting constraints on email.subject: only one equality or pattern per field is supported (1)

1 rules:

* M365 Azure Monitor Alert Email with Financial or Billing Theme

### Unsupported conflicting constraints on process.args: only one equality or pattern per field is supported (1)

1 rules:

* Unusual Base64 Encoding/Decoding Activity

### Unsupported conflicting constraints on process.command_line: only one equality or pattern per field is supported (1)

1 rules:

* Potential Credential Discovery via Recursive Grep

### Unsupported field name: {?bucket.name.key (1)

1 rules:

* AWS S3 Static Site JavaScript File Uploaded

### Unsupported function: TO_INTEGER (1)

1 rules:

* Newly Observed Palo Alto Network Alert

### Unsupported function: length (1)

1 rules:

* Multiple Alerts Involving a User

### Unsupported function: now (1)

1 rules:

* Entra ID Concurrent Sign-in with Suspicious Properties

### Unsupported function: to_ip (1)

1 rules:

* M365 or Entra ID Identity Sign-in from a Suspicious Source

### Unsupported left operand, it must be a field (1)

1 rules:

* AWS Discovery API Calls via CLI from a Single Resource

### Unsupported predicate on metadata field: _ignored (1)

1 rules:

* Long Base64 Encoded Command via Scripting Interpreter

## Generation errors

### Unsupported function: match (33)

33 rules:
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
* Potential SSH Reverse Port Forwarding
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

### Unsupported function: stringContains (25)

25 rules:
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
* AWS Lambda Function Policy Updated to Allow Cross-Account Invocation
* AWS Lambda Function Policy Updated to Allow Public Invocation
* AWS Lambda Function URL Created with Public Access
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

### Root with too many branches (limit: 10000) (21)

21 rules:
* Connection to Common Large Language Model Endpoints
* Connection to Commonly Abused Web Services
* Execution from Unusual Directory - Command Line
* Execution of a Downloaded Windows Script
* External IP Lookup from Non-Browser Process
* GenAI or MCP Server Child Process Execution
* Potential Copy Fail (CVE-2026-31431) Exploitation via AF_ALG Socket
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
* Suspicious Child Execution via Web Server
* Suspicious Command Execution via Web Server
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

### Unsupported argument type(s): <class 'eql.ast.Field'> (10)

10 rules:
* External User Added to Google Workspace Group
* Image Loaded with Invalid Signature
* Interactive Logon by an Unusual Process
* M365 Exchange Inbox Forwarding Rule Created
* Payload Downloaded by Interpreter and Piped to Interpreter
* Potential Privilege Escalation via SUID/SGID
* Potential Ransomware Note File Dropped via SMB
* Suspicious File Renamed via SMB
* Unusual Network Activity from a Windows System Binary
* Windows Service Installed via an Unusual Client

### Root without branches (9)

9 rules:
* Initramfs Extraction via CPIO
* Interactive Terminal Spawned via Perl
* Kubectl Configuration Discovery
* Linux User or Group Deletion
* Linux init (PID 1) Secret Dump via GDB
* Passwordless Sudo Probing
* Potential Docker Escape via Nsenter
* Potential Linux Backdoor User Account Creation
* Suspicious Data Encryption via OpenSSL Utility

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

### Unsupported &keyword 'process.Ext.relative_file_creation_time' constraint: <= (3)

3 rules:
* Java Dropped and Executed With DNS Lookup
* Suspicious Execution from VS Code Extension
* Suspicious Inter-Process Communication via Outlook

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

### Unsupported condition on the values of Esql.rule_severity_values (3)

3 rules:
* Alerts From Multiple Integrations by Destination Address
* Alerts From Multiple Integrations by Source Address
* Alerts From Multiple Integrations by User Name

### Unsupported function: endswith (3)

3 rules:
* Potential Computer Account NTLM Relay Activity
* Potential Machine Account Relay Attack via SMB
* Unusual Execution via Microsoft Common Console File

### Unsupported &keyword 'file.Ext.windows.zone_identifier' constraint: > (2)

2 rules:
* Downloaded Shortcut Files
* File with Suspicious Extension Downloaded

### Unsupported &keyword 'process.parent.Ext.real.pid' constraint: > (2)

2 rules:
* Parent Process PID Spoofing
* Privileges Elevation via Parent Process PID Spoofing

### Unsupported condition on the aggregate Esql.url_original_count_distinct (2)

2 rules:
* Web Server Discovery or Fuzzing Activity
* Web Server Suspicious User Agent Requests

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

### Field type solver: flattened (1)

1 rules:
* Entra ID ADRS Token Request by Microsoft Authentication Broker

### Unsolvable constraints: event.action (3 different values are needed, the conditions allow 2) (1)

1 rules:
* AWS EC2 Stop, Start, and User Data Modification Correlation

### Unsolvable constraints: file.extension (cannot be non-null) (1)

1 rules:
* Pluggable Authentication Module or Configuration Creation

### Unsolvable constraints: fortinet.firewall.cfgattr (not in Strings({'*srcaddr[all]*'}): ('*dstaddr[all]*')) (1)

1 rules:
* FortiGate Overly Permissive Firewall Policy Created

### Unsolvable constraints: http.request.body.content (not in Strings({'*/swip/Upload.ashx*'}): ('POST*')) (1)

1 rules:
* Deprecated - SUNBURST Command and Control Activity

### Unsolvable constraints: http.request.body.content (not in Strings({'*Content-Disposition: form-data*'}): ('*filename=*')) (1)

1 rules:
* Initial Access via File Upload Followed by GET Request

### Unsolvable constraints: kubernetes.audit.requestObject.spec.containers.image (cannot be null) (1)

1 rules:
* Kubernetes Container Created with Excessive Linux Capabilities

### Unsolvable constraints: message (not in Strings({'segfault'}): ('agetty')) (1)

1 rules:
* Segfault from Sensitive Process Detected

### Unsolvable constraints: network_traffic.redis.query (not in Strings({'*CONFIG SET dir*'}): ('*/.ssh*')) (1)

1 rules:
* Potential Redis CONFIG SET SSH Authorized Key Injection

### Unsolvable constraints: network_traffic.redis.query (not in Strings({'*CONFIG SET dir*'}): ('*/etc/cron*')) (1)

1 rules:
* Potential Redis CONFIG SET Cron Directory Persistence (RedisRaider)

### Unsolvable constraints: network_traffic.redis.query (not in Strings({'*EVAL*'}): ('*string.rep*')) (1)

1 rules:
* Potential Redis Lua Use-After-Free RCE Attempt (CVE-2025-49844 / RediShell)

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'CopyFromScreen'}): ('System.Drawing.Bitmap')) (1)

1 rules:
* PowerShell Suspicious Script with Screenshot Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Cryptography.AESManaged'}): ('CipherMode')) (1)

1 rules:
* PowerShell Script with Encryption/Decryption Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Invoke-WmiMethod'}): ('ComputerName')) (1)

1 rules:
* Deprecated - PowerShell Script with Remote Execution Capabilities via WinRM

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'LsaCallAuthenticationPackage'}): ('KerbRetrieveEncodedTicketMessage')) (1)

1 rules:
* PowerShell Kerberos Ticket Dump

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Microsoft.Office.Interop.Outlook'}): ('MAPI')) (1)

1 rules:
* PowerShell Mailbox Collection Script

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'NdrClientCall'}): ('GetProcAddress')) (1)

1 rules:
* Potential AMSI Bypass via RPC Runtime Hooking

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'New-MailboxExportRequest'}): ('-FilePath')) (1)

1 rules:
* Exchange Mailbox Export via PowerShell

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'Set-MpPreference'}): ('DisableArchiveScanning')) (1)

1 rules:
* PowerShell Script with Windows Defender Tampering Capabilities

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'VirtualAlloc'}): ('WriteProcessMemory')) (1)

1 rules:
* Potential Process Injection via PowerShell

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[System.Reflection.Assembly]::Load'}): ('FromBase64String')) (1)

1 rules:
* Suspicious .NET Reflection via PowerShell

### Unsolvable constraints: powershell.file.script_block_text (not in Strings({'[string]::join'}): ('$pSHoMe[')) (1)

1 rules:
* Deprecated - Potential PowerShell Obfuscated Script

### Unsolvable constraints: process.command_line (not in Strings({'*\\*\*$*'}): ('* copy*')) (1)

1 rules:
* Remote File Copy to a Hidden Share

### Unsolvable constraints: process.command_line (not in Strings({'*com.apple.Safari*'}): ('*IncludeDevelopMenu*')) (1)

1 rules:
* Modification of Safari Settings via Defaults Command

### Unsolvable constraints: process.command_line (not in Strings({'*csrutil*status*'}): ('*enabled*')) (1)

1 rules:
* Suspicious SIP Check by macOS Application

### Unsolvable constraints: process.command_line (not in Strings({'*drive.google.com*'}): ('*export=download*')) (1)

1 rules:
* Suspicious File Downloaded from Google Drive

### Unsolvable constraints: process.command_line (not in Strings({'*id_dsa*'}): ('*/home/*')) (1)

1 rules:
* Private Key Searching Activity

### Unsolvable constraints: process.pid (out of boundary, 1 <= 0 <= 4294967295) (1)

1 rules:
* Service Creation via Local Kerberos Authentication

### Unsolvable constraints: request (not in Strings({'*MSOTlPn_Uri*'}): ('*DisplayMode*')) (1)

1 rules:
* Potential Toolshell Initial Exploit (CVE-2025-53770 & CVE-2025-53771)

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*'}): ('*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-*')) (1)

1 rules:
* Potential Active Directory Replication Account Backdoor

### Unsolvable constraints: winlog.event_data.AttributeValue (not in Strings({'*827D319E-6EAC-11D2-A4EA-00C04F79F83A*'}): ('*803E14A0-B4FB-11D0-A0D0-00A0C90F574B*')) (1)

1 rules:
* Group Policy Abuse for Privilege Addition

### Unsolvable constraints: winlog.event_data.param1 (not in Strings({'*FullControl*'}): ('*setsharingmode*')) (1)

1 rules:
* Quick Assist Full Control Sharing Mode Enabled

### Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: < (1)

1 rules:
* Potential Windows Session Hijacking via CcmExec

### Unsupported &keyword 'dll.Ext.relative_file_creation_time' constraint: <= (1)

1 rules:
* Unsigned DLL Loaded by Svchost

### Unsupported &keyword 'file.Ext.entropy' constraint: >= (1)

1 rules:
* Suspicious HTML File Creation

### Unsupported &keyword 'kibana.alert.risk_score' constraint: > (1)

1 rules:
* FortiGate SSL VPN Login Followed by SIEM Alert by User

### Unsupported &keyword 'ml_is_dga.malicious_probability' constraint: > (1)

1 rules:
* Machine Learning Detected a DNS Request With a High DGA Probability Score

### Unsupported &keyword 'o365.audit.OperationCount' constraint: >= (1)

1 rules:
* M365 Exchange Mailbox Items Accessed Excessively

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

### Unsupported &keyword 'system.process.cpu.total.norm.pct' constraint: >= (1)

1 rules:
* Newly Observed Process Exhibiting High CPU Usage

### Unsupported condition on the aggregate Esql.alert_count_long_term_key_new_ip_rule (1)

1 rules:
* AWS IAM Long-Term Access Key Correlated with Elevated Detection Alerts

### Unsupported condition on the aggregate Esql.any_payload_keyword_max (1)

1 rules:
* Web Server Potential Command Injection Request

### Unsupported condition on the aggregate Esql.authz_forbid_count (1)

1 rules:
* Kubernetes Potential Endpoint Permission Enumeration Attempt by Anonymous User Detected

### Unsupported condition on the aggregate Esql.azure_open_ai_properties_request_length_avg (1)

1 rules:
* Potential Denial of Azure OpenAI ML Service

### Unsupported condition on the aggregate Esql.azure_open_ai_properties_response_length_max (1)

1 rules:
* Potential Azure OpenAI Model Theft

### Unsupported condition on the aggregate Esql.device_code_auth_count (1)

1 rules:
* Entra ID OAuth Device Code Flow with Concurrent Sign-ins

### Unsupported condition on the aggregate Esql.dhcpv4_client_mac_count_distinct (1)

1 rules:
* Potential DHCP Starvation via High Client MAC Cardinality

### Unsupported condition on the aggregate Esql.is_browser_case_max (1)

1 rules:
* Entra ID OAuth Flow by Microsoft Authentication Broker to Device Registration Service (DRS)

### Unsupported condition on the aggregate Esql.oauth_token_count_distinct (1)

1 rules:
* M365 Identity OAuth Flow by First-Party Microsoft App from Multiple IPs

### Unsupported condition on the aggregate Esql.patterns_count_distinct (1)

1 rules:
* Suspicious Python Shell Command Execution

### Unsupported condition on the aggregate host_with_cpu_spike (1)

1 rules:
* Multiple Alerts on a Host Exhibiting CPU Spike

### Unsupported condition on the values of Esql.kibana_alert_risk_score_values (1)

1 rules:
* Multiple External EDR Alerts by Host

### Unsupported field in WHERE after STATS: access_key (1)

1 rules:
* AWS Lateral Movement from Kubernetes SA via AssumeRoleWithWebIdentity

### Unsupported number of different values of kubernetes.audit.annotations.`authorization_k8s_io/decision`: between 2 and 2 in 6 documents (1)

1 rules:
* Kubernetes Potential Endpoint Permission Enumeration Attempt Detected
