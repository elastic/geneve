# Alerts generation from detection rules

This report captures the detection rules signals generation coverage. Here you can
learn what rules are supported and what not and why.

Curious about the inner workings? Read [here](signals_generation.md).

Rules version: 9.3.3

## Table of contents
   1. [Failed rules (27)](#failed-rules-27)
   1. [Unsuccessful rules with signals (22)](#unsuccessful-rules-with-signals-22)
   1. [Rules with no signals (7)](#rules-with-no-signals-7)
   1. [Rules with too few signals (24)](#rules-with-too-few-signals-24)
   1. [Rules with the correct signals (980)](#rules-with-the-correct-signals-980)

## Failed rules (27)

### Cloud Credential Search Detected via Defend for Containers

Branch count: 8325  
Document count: 8325  
Index: geneve-ut-0245  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name in ("grep", "egrep", "fgrep", "find", "locate", "mlocate", "cat", "sed", "awk") or
  (
    /* Account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "grep", "/bin/grep", "/usr/bin/grep", "/usr/local/bin/grep",
      "egrep", "/bin/egrep", "/usr/bin/egrep", "/usr/local/bin/egrep",
      "fgrep", "/bin/fgrep", "/usr/bin/fgrep", "/usr/local/bin/fgrep",
      "find", "/bin/find", "/usr/bin/find", "/usr/local/bin/find",
      "locate", "/bin/locate", "/usr/bin/locate", "/usr/local/bin/locate",
      "mlocate", "/bin/mlocate", "/usr/bin/mlocate", "/usr/local/bin/mlocate",
      "cat", "/bin/cat", "/usr/bin/cat", "/usr/local/bin/cat",
      "sed", "/bin/sed", "/usr/bin/sed", "/usr/local/bin/sed",
      "awk", "/bin/awk", "/usr/bin/awk", "/usr/local/bin/awk"
    ) and 
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
)
and
process.args like~ (
  /* AWS Credentials */
  "*aws_access_key_id*", "*aws_secret_access_key*", "*aws_session_token*", "*accesskeyid*", "*secretaccesskey*",
  "*access_key*", "*.aws/credentials*",

  /* Azure Credentials */
  "*AZURE_CLIENT_ID*", "*AZURE_TENANT_ID*", "*AZURE_CLIENT_SECRET*", "*AZURE_FEDERATED_TOKEN_FILE*",
  "*IDENTITY_ENDPOINT*", "*IDENTITY_HEADER*", "*MSI_ENDPOINT*", "*MSI_SECRET*",
  "*/.azure/*", "*/var/run/secrets/azure/*",

  /* GCP Credentials */
  "*/.config/gcloud/*", "*application_default_credentials.json*",
  "*type: service_account*", "*client_email*", "*private_key_id*", "*private_key*",
  "*/var/run/secrets/google/*", "*GOOGLE_APPLICATION_CREDENTIALS*"
) and process.interactive == true and container.id like "*"
```



### Connection to Common Large Language Model Endpoints

Branch count: 1836  
Document count: 1836  
Index: geneve-ut-0259  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
network where host.os.type == "windows" and dns.question.name != null and
(
  process.name : ("MSBuild.exe", "mshta.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "rundll32.exe",
  "bitsadmin.exe", "InstallUtil.exe", "RegAsm.exe", "vbc.exe", "RegSvcs.exe", "python.exe", "regsvr32.exe", "dllhost.exe",
  "node.exe", "javaw.exe", "java.exe", "*.pif", "*.com") or

  ?process.code_signature.subject_name : ("AutoIt Consulting Ltd", "OpenJS Foundation", "Python Software Foundation") or

  (
    process.executable : ("?:\\Users\\*.exe", "?:\\ProgramData\\*.exe") and
    (?process.code_signature.trusted == false or ?process.code_signature.exists == false)
  )
 ) and
    dns.question.name : (
    // Major LLM APIs
    "api.openai.com",
    "*.openai.azure.com",
    "api.anthropic.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "api.ai21.com",
    "api.groq.com",
    "api.perplexity.ai",
    "api.x.ai",
    "api.deepseek.com",
    "api.gemini.google.com",
    "generativelanguage.googleapis.com",
    "api.azure.com",
    "api.bedrock.aws",
    "bedrock-runtime.amazonaws.com",

    // Hugging Face & other ML infra
    "api-inference.huggingface.co",
    "inference-endpoint.huggingface.cloud",
    "*.hf.space",
    "*.replicate.com",
    "api.replicate.com",
    "api.runpod.ai",
    "*.runpod.io",
    "api.modal.com",
    "*.forefront.ai",

    // Consumer-facing AI chat portals
    "chat.openai.com",
    "chatgpt.com",
    "copilot.microsoft.com",
    "bard.google.com",
    "gemini.google.com",
    "claude.ai",
    "perplexity.ai",
    "poe.com",
    "chat.forefront.ai",
    "chat.deepseek.com"
  ) and

  not process.executable : (
          "?:\\Program Files\\*.exe",
          "?:\\Program Files (x86)\\*.exe",
          "?:\\Windows\\System32\\svchost.exe",
          "?:\\Windows\\SystemApps\\Microsoft.LockApp_*\\LockApp.exe",
          "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
          "?:\\Users\\*\\AppData\\Local\\BraveSoftware\\*\\Application\\brave.exe",
          "?:\\Users\\*\\AppData\\Local\\Vivaldi\\Application\\vivaldi.exe",
          "?:\\Users\\*\\AppData\\Local\\Programs\\Opera*\\opera.exe",
          "?:\\Users\\*\\AppData\\Local\\Programs\\Fiddler\\Fiddler.exe"
        ) and
    not (?process.code_signature.trusted == true and
         ?process.code_signature.subject_name : ("Anthropic, PBC", "Google LLC", "Mozilla Corporation", "Brave Software, Inc.", "Island Technology Inc.", "Opera Norway AS"))
```



### Direct Interactive Kubernetes API Request by Common Utilities

Branch count: 516  
Document count: 1032  
Index: geneve-ut-0312  
Failure message(s):  
  SDE says:
> verification_exception
	Root causes:
		verification_exception: Found 1 problem
line 26:129: Unknown column [kubernetes.audit.user.extra.authentication.kubernetes.io/pod-name]  

```python
sequence with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
     process.name in ("wget", "curl", "openssl", "socat", "ncat", "kubectl") or
     (
       /* Account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
       process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
       process.args in (
         "wget", "/bin/wget", "/usr/bin/wget", "/usr/local/bin/wget",
         "ssl_client", "/bin/ssl_client", "/usr/bin/ssl_client", "/usr/local/bin/ssl_client",
         "curl", "/bin/curl", "/usr/bin/curl", "/usr/local/bin/curl",
         "openssl", "/bin/openssl", "/usr/bin/openssl", "/usr/local/bin/openssl",
         "socat", "/bin/socat", "/usr/bin/socat", "/usr/local/bin/socat",
         "ncat", "/bin/ncat", "/usr/bin/ncat", "/usr/local/bin/ncat",
         "kubectl", "/bin/kubectl", "/usr/bin/kubectl", "/usr/local/bin/kubectl"
       ) and
       /* default exclusion list to not FP on default multi-process commands */
       not process.args in (
         "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
         "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
         "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
         "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
       )
     )
   ) and process.interactive == true and container.id like "*"
  ] by orchestrator.resource.name
  [any where event.dataset == "kubernetes.audit_logs" and kubernetes.audit.stage in ("ResponseComplete", "ResponseStarted")] by `kubernetes.audit.user.extra.authentication.kubernetes.io/pod-name`
```



### Direct Interactive Kubernetes API Request by Unusual Utilities

Branch count: 528  
Document count: 1056  
Index: geneve-ut-0313  
Failure message(s):  
  SDE says:
> verification_exception
	Root causes:
		verification_exception: Found 1 problem
line 47:8: Unknown column [kubernetes.audit.user.extra.authentication.kubernetes.io/pod-name]  

```python
sequence with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.interactive == true and
  container.id like "*" and
  /* Covered by the rule "Direct Interactive Kubernetes API Request by Common Utilities" */
  not (
     process.name in ("wget", "curl", "openssl", "socat", "ncat", "kubectl") or
     (
       /* Account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
       process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
       process.args in (
         "wget", "/bin/wget", "/usr/bin/wget", "/usr/local/bin/wget",
         "ssl_client", "/bin/ssl_client", "/usr/bin/ssl_client", "/usr/local/bin/ssl_client",
         "curl", "/bin/curl", "/usr/bin/curl", "/usr/local/bin/curl",
         "openssl", "/bin/openssl", "/usr/bin/openssl", "/usr/local/bin/openssl",
         "socat", "/bin/socat", "/usr/bin/socat", "/usr/local/bin/socat",
         "ncat", "/bin/ncat", "/usr/bin/ncat", "/usr/local/bin/ncat",
         "kubectl", "/bin/kubectl", "/usr/bin/kubectl", "/usr/local/bin/kubectl"
       ) and
       /* default exclusion list to not FP on default multi-process commands */
       not process.args in (
         "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
         "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
         "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
         "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
       )
     ) or
     /* General exclusions for utilities that are not typically used for Kubernetes API requests */
     process.name in ("sleep", "head", "tail")
   )] by orchestrator.resource.name
  [any where
     event.dataset == "kubernetes.audit_logs" and
     kubernetes.audit.stage in ("ResponseStarted","ResponseComplete") and
     kubernetes.audit.verb in ("get", "list", "watch", "create", "patch", "update") and
     (
       kubernetes.audit.objectRef.resource in (
         "pods", "secrets", "serviceaccounts", "configmaps",
         "roles", "rolebindings", "clusterroles", "clusterrolebindings",
         "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs",
         "nodes", "namespaces",
         "selfsubjectaccessreviews", "selfsubjectrulesreviews", "subjectaccessreviews"
       )
       or (
         kubernetes.audit.objectRef.resource == "pods" and
         kubernetes.audit.objectRef.subresource in ("exec", "attach", "portforward", "log")
       )
     )
  ] by `kubernetes.audit.user.extra.authentication.kubernetes.io/pod-name`
```



### Entra ID Device Registration Detected (ROADtools)

Branch count: 1  
Document count: 3  
Index: geneve-ut-0356  
Failure message(s):  
  SDE says:
> verification_exception
	Root causes:
		verification_exception: Found 4 problems
line 6:9: Unknown column [azure.auditlogs.properties.target_resources.0.modified_properties.1.display_name]
line 7:9: Unknown column [azure.auditlogs.properties.target_resources.0.modified_properties.1.new_value], did you mean [azure.auditlogs.properties.additional_details.value]?
line 9:5: Unknown column [azure.auditlogs.properties.target_resources.0.modified_properties.3.new_value], did you mean [azure.auditlogs.properties.additional_details.value]?
line 12:5: Unknown column [azure.auditlogs.properties.target_resources.0.modified_properties.2.new_value], did you mean [azure.auditlogs.properties.additional_details.value]?  

```python
sequence by azure.correlation_id with maxspan=1m
[any where event.dataset == "azure.auditlogs" and
    azure.auditlogs.identity == "Device Registration Service" and
    azure.auditlogs.operation_name == "Add device" and
    azure.auditlogs.properties.additional_details.value like "Microsoft.OData.Client/*" and (
        `azure.auditlogs.properties.target_resources.0.modified_properties.1.display_name` == "CloudAccountEnabled" and
        `azure.auditlogs.properties.target_resources.0.modified_properties.1.new_value` == "[true]"
    ) and
    `azure.auditlogs.properties.target_resources.0.modified_properties.3.new_value` like "*10.0.19041.928*"]
[any where event.dataset == "azure.auditlogs" and
    azure.auditlogs.operation_name == "Add registered users to device" and
    `azure.auditlogs.properties.target_resources.0.modified_properties.2.new_value` like "*urn:ms-drs:enterpriseregistration.windows.net*"]
[any where event.dataset == "azure.auditlogs" and
    azure.auditlogs.operation_name == "Add registered owner to device"]
```



### Execution of a Downloaded Windows Script

Branch count: 8448  
Document count: 16896  
Index: geneve-ut-0420  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
sequence by host.id, user.id with maxspan=3m
[file where host.os.type == "windows" and event.action == "creation" and user.id != "S-1-5-18" and
  process.name : ("chrome.exe", "msedge.exe", "brave.exe", "browser.exe", "dragon.exe", "vivaldi.exe", "explorer.exe", "winrar.exe", "7zFM.exe", "7zG.exe", "Bandizip.exe") and
  file.extension in~ ("js", "jse", "vbs", "vbe", "wsh", "hta", "cmd", "bat") and
  (file.origin_url != null or file.origin_referrer_url != null)]
[process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : ("chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "browser.exe", "dragon.exe", "vivaldi.exe", "explorer.exe", "winrar.exe", "7zFM.exe", "7zG.exe", "Bandizip.exe") and 
 process.args_count >= 2 and
 (
  process.name in~ ("wscript.exe", "mshta.exe") or
  (process.name : "cmd.exe" and process.command_line : ("*.cmd*", "*.bat*"))
  )]
```



### File Creation, Execution and Self-Deletion in Suspicious Directory

Branch count: 4608  
Document count: 13824  
Index: geneve-ut-0446  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
sequence by host.id, user.id with maxspan=1m
  [file where host.os.type == "linux" and event.action == "creation" and
   process.name in ("curl", "wget", "fetch", "ftp", "sftp", "scp", "rsync", "ld") and
   file.path : ("/dev/shm/*", "/run/shm/*", "/tmp/*", "/var/tmp/*",
     "/run/*", "/var/run/*", "/var/www/*", "/proc/*/fd/*")] by file.name
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
   not process.parent.executable like (
     "/tmp/VeeamApp*", "/tmp/rajh/spack-stage/*", "plz-out/bin/vault/bridge/test/e2e/base/bridge-dev",
     "/usr/bin/ranlib", "/usr/bin/ar", "plz-out/bin/vault/bridge/test/e2e/base/local-k8s"
   )] by process.name
  [file where host.os.type == "linux" and event.action == "deletion" and
   file.path : (
     "/dev/shm/*", "/run/shm/*", "/tmp/*", "/var/tmp/*", "/run/*", "/var/run/*", "/var/www/*", "/proc/*/fd/*"
    ) and not process.name in ("rm", "ld", "conftest", "link", "gcc", "getarch", "ld")] by file.name
```



### File Execution Permission Modification Detected via Defend for Containers

Branch count: 3626  
Document count: 3626  
Index: geneve-ut-0449  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
file where host.os.type == "linux" and event.type in ("change", "creation") and (
  process.name == "chmod" or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod"
    ) and
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man"
    )
  )
) and process.args in ("4755", "755", "777", "0777", "444", "+x", "a+x") and
process.args like ("/dev/shm/*", "/tmp/*", "/var/tmp/*", "/run/*", "/var/run/*", "/mnt/*", "/media/*") and
process.interactive == true and container.id like "*" and not process.args == "-x"
```



### Forbidden Direct Interactive Kubernetes API Request

Branch count: 516  
Document count: 1032  
Index: geneve-ut-0480  
Failure message(s):  
  SDE says:
> verification_exception
	Root causes:
		verification_exception: Found 1 problem
line 28:8: Unknown column [kubernetes.audit.user.extra.authentication.kubernetes.io/pod-name]  

```python
sequence with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
     process.name in ("wget", "curl", "openssl", "socat", "ncat", "kubectl") or
     (
       /* Account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
       process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
       process.args in (
         "wget", "/bin/wget", "/usr/bin/wget", "/usr/local/bin/wget",
         "ssl_client", "/bin/ssl_client", "/usr/bin/ssl_client", "/usr/local/bin/ssl_client",
         "curl", "/bin/curl", "/usr/bin/curl", "/usr/local/bin/curl",
         "openssl", "/bin/openssl", "/usr/bin/openssl", "/usr/local/bin/openssl",
         "socat", "/bin/socat", "/usr/bin/socat", "/usr/local/bin/socat",
         "ncat", "/bin/ncat", "/usr/bin/ncat", "/usr/local/bin/ncat",
         "kubectl", "/bin/kubectl", "/usr/bin/kubectl", "/usr/local/bin/kubectl"
       ) and
       /* default exclusion list to not FP on default multi-process commands */
       not process.args in (
         "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
         "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
         "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
         "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
       )
     )
   ) and process.interactive == true and container.id like "*"
  ] by orchestrator.resource.name
  [any where event.dataset == "kubernetes.audit_logs" and kubernetes.audit.stage in ("ResponseComplete", "ResponseStarted") and
  `kubernetes.audit.annotations.authorization_k8s_io/decision` == "forbid"
  ] by `kubernetes.audit.user.extra.authentication.kubernetes.io/pod-name`
```



### Git Hook Child Process

Branch count: 2300  
Document count: 2300  
Index: geneve-ut-0523  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.parent.name in (
  "applypatch-msg", "commit-msg", "fsmonitor-watchman", "post-update", "post-checkout", "post-commit",
  "pre-applypatch", "pre-commit", "pre-merge-commit", "prepare-commit-msg", "pre-push", "pre-rebase", "pre-receive",
  "push-to-checkout", "update", "post-receive", "pre-auto-gc", "post-rewrite", "sendemail-validate", "p4-pre-submit",
  "post-index-change", "post-merge", "post-applypatch"
) and
(
  process.name in ("nohup", "setsid", "disown", "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") or
  process.name like ("php*", "perl*", "ruby*", "lua*") or
  process.executable like (
    "/boot/*", "/dev/shm/*", "/etc/cron.*/*", "/etc/init.d/*", "/etc/update-motd.d/*",
    "/run/*", "/srv/*", "/tmp/*", "/var/tmp/*", "/var/log/*"
  )
) and
not process.name in ("git", "dirname")
```



### Multi-Base64 Decoding Attempt from Suspicious Location

Branch count: 2352  
Document count: 4704  
Index: geneve-ut-0786  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
sequence by process.parent.entity_id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.executable != null and
   process.name in ("base64", "base64plain", "base64url", "base64mime", "base64pem", "base32", "base16") and
   // Only including potentially suspicious locations
   process.args like~ ("-d*", "--d*") and process.working_directory like (
     "/tmp/*", "/var/tmp*", "/dev/shm/*", "/var/www/*", "/home/*", "/root/*"
   ) and not (
     process.parent.executable in (
       "/usr/share/ec2-instance-connect/eic_curl_authorized_keys", "/etc/cron.daily/vivaldi",
       "/etc/cron.daily/opera-browser"
     ) or
     process.working_directory like (
       "/opt/microsoft/omsagent/plugin", "/opt/rapid7/ir_agent/*", "/tmp/newroot/*"
      ) or
      (process.parent.name == "zsh" and process.parent.command_line like "*extendedglob*")
   )]
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.executable != null and
   process.name in ("base64", "base64plain", "base64url", "base64mime", "base64pem", "base32", "base16") and
   process.args like~ ("-d*", "--d*")]
```



### Netcat File Transfer or Listener Detected via Defend for Containers

Branch count: 1110  
Document count: 1110  
Index: geneve-ut-0810  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name in ("nc","ncat","netcat","netcat.openbsd","netcat.traditional") or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "nc", "/bin/nc", "/usr/bin/nc", "/usr/local/bin/nc",
      "ncat", "/bin/ncat", "/usr/bin/ncat", "/usr/local/bin/ncat",
      "netcat", "/bin/netcat", "/usr/bin/netcat", "/usr/local/bin/netcat",
      "netcat.openbsd", "/bin/netcat.openbsd", "/usr/bin/netcat.openbsd", "/usr/local/bin/netcat.openbsd",
      "netcat.traditional", "/bin/netcat.traditional", "/usr/bin/netcat.traditional", "/usr/local/bin/netcat.traditional"
    ) and 
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.args like~ (
  /* bind shell to specific port or listener */
  "-*l*","-*p*",
  /* reverse shell to command-line interpreter used for command execution */
  "-*e*",
  /* file transfer via stdout/pipe */
  ">","<", "|"
) and process.interactive == true and container.id like "*"
```



### Pod or Container Creation with Suspicious Command-Line

Branch count: 8448  
Document count: 8448  
Index: geneve-ut-0895  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and (
  (process.name == "kubectl" and process.args == "run" and process.args == "--restart=Never" and process.args == "--") or
  (process.name in ("docker", "nerdctl", "ctl") and process.args == "run")
) and 
process.args in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
process.command_line like~ (
  "*atd*", "*cron*", "*/etc/rc.local*", "*/dev/tcp/*", "*/etc/init.d*", "*/etc/update-motd.d*", "*/etc/ld.so*", "*/etc/sudoers*", "*base64 *",
  "*/etc/profile*", "*/etc/ssh*", "*/home/*/.ssh/*", "*/root/.ssh*" , "*~/.ssh/*", "*autostart*", "*xxd *", "*/etc/shadow*", "*./.*",
  "*import*pty*spawn*", "*import*subprocess*call*", "*TCPSocket.new*", "*TCPSocket.open*", "*io.popen*", "*os.execute*", "*fsockopen*",
  "*disown*", "* ncat *", "* nc *", "* netcat *",  "* nc.traditional *", "*socat*", "*telnet*", "*/tmp/*", "*/dev/shm/*", "*/var/tmp/*",
  "*/boot/*", "*/sys/*", "*/lost+found/*", "*/media/*", "*/proc/*", "*/var/backups/*", "*/var/log/*", "*/var/mail/*", "*/var/spool/*"
)
```



### Potential Backdoor Execution Through PAM_EXEC

Branch count: 3600  
Document count: 7200  
Index: geneve-ut-0909  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
sequence by process.entity_id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "change" and event.action == "session_id_change" and process.name in ("ssh", "sshd")]
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.name in ("ssh", "sshd") and
   process.args_count == 2 and process.args like (
     "sh", "dash", "bash", "zsh",
     "perl*", "python*", "php*", "ruby*", "lua*",

     "/bin/sh", "/bin/dash", "/bin/bash", "/bin/zsh",
     "/bin/perl*", "/bin/python*", "/bin/php*", "/bin/ruby*", "/bin/lua*",

     "/usr/bin/sh", "/usr/bin/dash", "/usr/bin/bash", "/usr/bin/zsh",
     "/usr/bin/perl*", "/usr/bin/python*", "/usr/bin/php*", "/usr/bin/ruby*", "/usr/bin/lua*",

     "/usr/local/bin/sh", "/usr/local/bin/dash", "/usr/local/bin/bash", "/usr/local/bin/zsh",
     "/usr/local/bin/perl*", "/usr/local/bin/python*", "/usr/local/bin/php*", "/usr/local/bin/ruby*", "/usr/local/bin/lua*"
   ) and (
     process.name like ".*" or
     process.executable like (
       "/tmp/*", "/var/tmp/*", "/dev/shm/*", "./*", "/boot/*", "/sys/*", "/lost+found/*", "/media/*", "/proc/*", "/bin/*", "/usr/bin/*",
       "/sbin/*", "/usr/sbin/*", "/lib/*", "/lib64/*", "/usr/lib/*", "/usr/lib64/*", "/opt/*", "/var/lib/*", "/run/*", "/var/backups/*",
       "/var/log/*", "/var/mail/*", "/var/spool/*"
     )
   )
  ]
```



### Potential Git CVE-2025-48384 Exploitation

Branch count: 2500  
Document count: 5000  
Index: geneve-ut-0963  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
sequence by host.id with maxspan=1m
  [process where host.os.type in ("linux", "macos") and event.type == "start" and event.action in ("exec", "executed", "process_started", "start", "ProcessRollup2") and
   process.name == "git" and process.args == "clone" and process.args == "--recursive" and process.args like~ "http*"] by process.entity_id
  [process where host.os.type in ("linux", "macos") and event.type == "start" and event.action in ("exec", "executed", "process_started", "start", "ProcessRollup2") and
   process.name in (
    "dash", "sh", "static-sh", "bash", "bash-static", "zsh", "ash", "csh", "ksh", "tcsh", "busybox", "fish", "ksh93", "rksh",
    "rksh93", "lksh", "mksh", "mksh-static", "csharp", "posh", "rc", "sash", "yash", "zsh5", "zsh5-static"
   )] by process.parent.entity_id
```



### Potential Kubectl Masquerading via Unexpected Process

Branch count: 1085  
Document count: 1085  
Index: geneve-ut-0977  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "executed", "process_started") and
(
  process.executable like~ ("/tmp/*", "/var/tmp/*", "/dev/shm/*", "/root/*", "/var/www/*", "./kubectl") or
  process.name like ".*"
) and
process.args like~ (

  // get and describe commands
  "*get po*", "*get deploy*", "*get node*", "*get svc*", "*get service*", "*get secret*", "*get clusterrole*", "*get ingress*",
  "*get configmap*", "*describe po*", "*describe deploy*", "*describe node*", "*describe svc*", "*describe service*",
  "*describe secret*", "*describe configmap*", "*describe clusterrole*", "*describe ingress*",

  // exec commands
  "*exec -it*", "*exec --stdin*", "*exec --tty*",

  // networking commands
  "*port-forward* ", "*proxy --port*", "*run --image=*", "*expose*",

  // authentication/impersonation commands
  "*auth can-i*", "*--kubeconfig*", "*--as *", "*--as=*", "*--as-group*", "*--as-uid*"
) and not (
  process.executable like "/tmp/newroot/*" or
  process.name == ".flatpak-wrapped"
)
```



### Potential Linux Tunneling and/or Port Forwarding

Branch count: 1212  
Document count: 1212  
Index: geneve-ut-0989  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and (
  (
    // gost & pivotnacci - spawned without process.parent.name
    (process.name == "gost" and process.args : ("-L*", "-C*", "-R*")) or (process.name == "pivotnacci")) or (
    // ssh
    (process.name == "ssh" and (process.args in ("-R", "-L", "-D", "-w") and process.args_count >= 4 and 
     not (process.args == "chmod" or process.command_line like "*rungencmd*"))) or
    // sshuttle
    (process.name == "sshuttle" and process.args in ("-r", "--remote", "-l", "--listen") and process.args_count >= 4) or
    // socat
    (process.name == "socat" and process.args : ("TCP4-LISTEN:*", "SOCKS*") and process.args_count >= 3) or
    // chisel
    (process.name : "chisel*" and process.args in ("client", "server")) or
    // iodine(d), dnscat, hans, ptunnel-ng, ssf, 3proxy & ngrok 
    (process.name in ("iodine", "iodined", "dnscat", "hans", "hans-ubuntu", "ptunnel-ng", "ssf", "3proxy", "ngrok", "wstunnel"))
  ) and process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
)
```



### Potential Privilege Escalation via Service ImagePath Modification

Branch count: 1794  
Document count: 1794  
Index: geneve-ut-1053  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
registry where host.os.type == "windows" and event.type == "change" and process.executable != null and
  registry.data.strings != null and registry.value == "ImagePath" and
  registry.key : (
    "*\\ADWS", "*\\AppHostSvc", "*\\AppReadiness", "*\\AudioEndpointBuilder", "*\\AxInstSV", "*\\camsvc", "*\\CertSvc",
    "*\\COMSysApp", "*\\CscService", "*\\defragsvc", "*\\DeviceAssociationService", "*\\DeviceInstall", "*\\DevQueryBroker",
    "*\\Dfs", "*\\DFSR", "*\\diagnosticshub.standardcollector.service", "*\\DiagTrack", "*\\DmEnrollmentSvc", "*\\DNS",
    "*\\dot3svc", "*\\Eaphost", "*\\GraphicsPerfSvc", "*\\hidserv", "*\\HvHost", "*\\IISADMIN", "*\\IKEEXT",
    "*\\InstallService", "*\\iphlpsvc", "*\\IsmServ", "*\\LanmanServer", "*\\MSiSCSI", "*\\NcbService", "*\\Netlogon",
    "*\\Netman", "*\\NtFrs", "*\\PlugPlay", "*\\Power", "*\\PrintNotify", "*\\ProfSvc", "*\\PushToInstall", "*\\RSoPProv",
    "*\\sacsvr", "*\\SENS", "*\\SensorDataService", "*\\SgrmBroker", "*\\ShellHWDetection", "*\\shpamsvc", "*\\StorSvc",
    "*\\svsvc", "*\\swprv", "*\\SysMain", "*\\Themes", "*\\TieringEngineService", "*\\TokenBroker", "*\\TrkWks",
    "*\\UALSVC", "*\\UserManager", "*\\vm3dservice", "*\\vmicguestinterface", "*\\vmicheartbeat", "*\\vmickvpexchange",
    "*\\vmicrdv", "*\\vmicshutdown", "*\\vmicvmsession", "*\\vmicvss", "*\\vmvss", "*\\VSS", "*\\w3logsvc", "*\\W3SVC",
    "*\\WalletService", "*\\WAS", "*\\wercplsupport", "*\\WerSvc", "*\\Winmgmt", "*\\wisvc", "*\\wmiApSrv",
    "*\\WPDBusEnum", "*\\WSearch"
  ) and
  not (
    registry.data.strings : (
        "?:\\Windows\\system32\\*.exe",
        "%systemroot%\\system32\\*.exe",
        "%windir%\\system32\\*.exe",
        "%SystemRoot%\\system32\\svchost.exe -k *",
        "%windir%\\system32\\svchost.exe -k *"
    ) and
        not registry.data.strings : (
            "*\\cmd.exe",
            "*\\cscript.exe",
            "*\\ieexec.exe",
            "*\\iexpress.exe",
            "*\\installutil.exe",
            "*\\Microsoft.Workflow.Compiler.exe",
            "*\\msbuild.exe",
            "*\\mshta.exe",
            "*\\msiexec.exe",
            "*\\msxsl.exe",
            "*\\net.exe",
            "*\\powershell.exe",
            "*\\pwsh.exe",
            "*\\reg.exe",
            "*\\RegAsm.exe",
            "*\\RegSvcs.exe",
            "*\\regsvr32.exe",
            "*\\rundll32.exe",
            "*\\vssadmin.exe",
            "*\\wbadmin.exe",
            "*\\wmic.exe",
            "*\\wscript.exe"
        )
  )
```



### Sensitive File Compression Detected via Defend for Containers

Branch count: 8880  
Document count: 8880  
Index: geneve-ut-1260  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name in ("zip", "tar", "gzip", "hdiutil", "7z", "rar", "7zip", "p7zip") or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "zip", "/bin/zip", "/usr/bin/zip", "/usr/local/bin/zip",
      "tar", "/bin/tar", "/usr/bin/tar", "/usr/local/bin/tar",
      "gzip", "/bin/gzip", "/usr/bin/gzip", "/usr/local/bin/gzip",
      "hdiutil", "/bin/hdiutil", "/usr/bin/hdiutil", "/usr/local/bin/hdiutil",
      "7z", "/bin/7z", "/usr/bin/7z", "/usr/local/bin/7z",
      "rar", "/bin/rar", "/usr/bin/rar", "/usr/local/bin/rar",
      "7zip", "/bin/7zip", "/usr/bin/7zip", "/usr/local/bin/7zip",
      "p7zip", "/bin/p7zip", "/usr/bin/p7zip", "/usr/local/bin/p7zip"
    ) and 
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.args like~ (
  "*/root/.ssh/*", "*/home/*/.ssh/*", "*/root/.bash_history*", "*/etc/hosts*", "*/root/.aws/*", "*/home/*/.aws/*",
  "*/root/.docker/*", "*/home/*/.docker/*", "*/etc/group*", "*/etc/passwd*", "*/etc/shadow*", "*/etc/gshadow*",
  "*/.azure/*", "*/var/run/secrets/azure/*", "*/.config/gcloud/*", "*application_default_credentials.json*",
  "*type: service_account*", "*client_email*", "*private_key_id*", "*private_key*", "*/var/run/secrets/google/*",
  "*GOOGLE_APPLICATION_CREDENTIALS*", "*AZURE_CLIENT_ID*", "*AZURE_TENANT_ID*", "*AZURE_CLIENT_SECRET*",
  "*AZURE_FEDERATED_TOKEN_FILE*", "*IDENTITY_ENDPOINT*", "*IDENTITY_HEADER*", "*MSI_ENDPOINT*", "*MSI_SECRET*"
) and process.interactive == true and container.id like "*"
```



### Sensitive Keys Or Passwords Search Detected via Defend for Containers

Branch count: 2997  
Document count: 2997  
Index: geneve-ut-1263  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name in ("grep", "egrep", "fgrep", "find", "locate", "mlocate", "cat", "sed", "awk") or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "grep", "/bin/grep", "/usr/bin/grep", "/usr/local/bin/grep",
      "egrep", "/bin/egrep", "/usr/bin/egrep", "/usr/local/bin/egrep",
      "fgrep", "/bin/fgrep", "/usr/bin/fgrep", "/usr/local/bin/fgrep",
      "find", "/bin/find", "/usr/bin/find", "/usr/local/bin/find",
      "locate", "/bin/locate", "/usr/bin/locate", "/usr/local/bin/locate",
      "mlocate", "/bin/mlocate", "/usr/bin/mlocate", "/usr/local/bin/mlocate",
      "cat", "/bin/cat", "/usr/bin/cat", "/usr/local/bin/cat",
      "sed", "/bin/sed", "/usr/bin/sed", "/usr/local/bin/sed",
      "awk", "/bin/awk", "/usr/bin/awk", "/usr/local/bin/awk"
    ) and 
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.args like~ (
  "*BEGIN PRIVATE*", "*BEGIN OPENSSH PRIVATE*", "*BEGIN RSA PRIVATE*", "*BEGIN DSA PRIVATE*", "*BEGIN EC PRIVATE*",
  "*password*", "*ssh*", "*id_rsa*", "*id_dsa*"
) and process.interactive == true and container.id like "*"
```



### Service Account Token or Certificate Access Followed by Kubernetes API Request

Branch count: 4  
Document count: 8  
Index: geneve-ut-1270  
Failure message(s):  
  SDE says:
> verification_exception
	Root causes:
		verification_exception: Found 1 problem
line 5:129: Unknown column [kubernetes.audit.user.extra.authentication.kubernetes.io/pod-name]  

```python
sequence with maxspan=60s
  [file where host.os.type == "linux" and event.type == "change" and event.action == "open" and
   file.path in ("/var/run/secrets/kubernetes.io/serviceaccount/token", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt") and
   process.interactive == true and container.id like "*"] by orchestrator.resource.name
  [any where event.dataset == "kubernetes.audit_logs" and kubernetes.audit.stage in ("ResponseComplete", "ResponseStarted")] by `kubernetes.audit.user.extra.authentication.kubernetes.io/pod-name`
```



### Suspicious APT Package Manager Execution

Branch count: 1368  
Document count: 2736  
Index: geneve-ut-1338  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
sequence by host.id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "ProcessRollup2") and
   process.parent.name == "apt" and process.args == "-c" and process.name in (
     "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish"
   ) and not process.executable == "/usr/lib/venv-salt-minion/bin/python.original"
  ] by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "ProcessRollup2") and process.name like (
     "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "python*", "php*",
     "perl", "ruby", "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk"
   ) and not (
     ?process.parent.executable like (
       "/run/k3s/containerd*", "/tmp/newroot/*", "/usr/share/debconf/frontend", "/var/tmp/buildah*", "./merged/*",
       "./*/vz/root/*", "/usr/bin/adequate" 
      ) or
     process.executable like ("/usr/lib/venv-salt-minion/bin/python.original", "./merged/var/lib/containers/*") or
     process.command_line in (
       "python3 /usr/sbin/omv-mkaptidx", "python3 /usr/local/bin/abr-upgrade --upgrade",
       "sh -c apt-get indextargets -o Dir::State::lists=/var/lib/apt/lists/ --format='$(FILENAME)' 'Created-By: Packages'",
       "/usr/bin/perl /usr/sbin/dpkg-preconfigure --apt", "/bin/sh -e /usr/lib/update-notifier/update-motd-updates-available",
       "/usr/bin/python3 /usr/lib/cnf-update-db", "/usr/bin/python3 /usr/bin/apt-listchanges --apt",
       "/usr/bin/perl -w /usr/sbin/dpkg-preconfigure --apt", "/bin/sh /usr/lib/needrestart/apt-pinvoke",
       "/bin/sh /usr/bin/kali-check-apt-sources", "/bin/sh /usr/lib/needrestart/apt-pinvoke -m u",
       "/usr/bin/perl /usr/sbin/needrestart",  "/usr/bin/perl -w /usr/bin/apt-show-versions -i",
       "/usr/bin/perl -w /usr/bin/apt-show-versions -i", "/usr/bin/perl -w /bin/apt-show-versions -i",
       "/usr/bin/perl /bin/adequate --help",  "/usr/bin/perl /usr/sbin/needrestart -m u", 
       "/usr/bin/perl -w /usr/share/debconf/frontend /usr/sbin/needrestart",
       "/usr/bin/python3 /sbin/katello-tracer-upload",
       "/usr/bin/python3 /usr/bin/package-profile-upload"
     ) or
     ?process.parent.command_line like ("sh -c if [ -x*", "sh -c -- if [ -x*") or
     process.args in ("/usr/sbin/needrestart", "/usr/lib/needrestart/apt-pinvoke", "/usr/share/proxmox-ve/pve-apt-hook", "/usr/bin/dpkg-source") or
     ?process.parent.args == "/usr/share/debconf/frontend"
    )
  ] by process.parent.entity_id
```



### Suspicious Execution via Scheduled Task

Branch count: 6144  
Document count: 6144  
Index: geneve-ut-1369  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
process where host.os.type == "windows" and event.type == "start" and
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
       "C:\\HP\\*") and

    not (process.name : "cmd.exe" and process.args : ("*.bat", "*.cmd")) and
    not (process.name : "cscript.exe" and process.args : "?:\\Windows\\system32\\calluxxprovider.vbs") and
    not (
       process.name : "powershell.exe" and
       process.args : (
           "-File", "-PSConsoleFile",
           "C:\\ProgramData\\Microsoft\\AutopatchSetupScheduled\\SetupAutopatchClientV2Package.ps1",
           "C:\\ProgramData\\Microsoft\\AutopatchSetupScheduled\\SetupAutopatchClientPackage.ps1",
           "C:\\Windows\\Temp\\MSS\\MDESetup\\Invoke-MDESetup.ps1"
       ) and user.id : "S-1-5-18"
    ) and
    not (process.name : "msiexec.exe" and user.id : "S-1-5-18") and
    not (process.name : "powershell.exe" and
         process.command_line : ("C:\\ProgramData\\ElasticAgent-HealthCheck.ps1",
                                 "C:\\ProgramData\\ssh\\puttysetup.ps1"))
```



### Suspicious File Creation via Pkg Install Script

Branch count: 4032  
Document count: 8064  
Index: geneve-ut-1374  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
sequence by process.entity_id with maxspan=30s
  [process where host.os.type == "macos" and event.type == "start" and process.name in ("bash", "sh", "zsh") and
    process.args like~ ("/tmp/PKInstallSandbox.*/Scripts/com.*/preinstall", 
                        "/tmp/PKInstallSandbox.*/Scripts/*/postinstall") and
    process.args like ("/Users/*", "/Volumes/*") and 
    not process.args like~ "/Users/*/Library/Caches/*"]
  [file where host.os.type == "macos" and event.action != "deletion" and process.name in ("mv", "cp") and
    (file.extension in ("py", "js", "sh", "scpt", "terminal", "tcl", "app", "pkg", "dmg", "command") or
      file.Ext.header_bytes like~ ("cffaedfe*", "cafebabe*")) and
    file.path like ("/private/etc/*", "/var/tmp/*", "/tmp/*", "/var/folders/*", "/Users/Shared/*",
                    "/Library/Graphics/*", "/Library/Containers/*", "/Users/*/Library/Containers/*", 
                    "/Users/*/Library/Services/*", "/Users/*/Library/Preferences/*", "/var/root/*",
                    "/Library/WebServer/*", "/Library/Fonts/*", "/usr/local/bin/*") and 
    not file.name == "CodeResources"]
```



### System Public IP Discovery via DNS Query

Branch count: 1053  
Document count: 1053  
Index: geneve-ut-1470  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
network where host.os.type == "windows" and dns.question.name != null and process.name != null and
(
  process.name : ("MSBuild.exe", "mshta.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "rundll32.exe",
  "bitsadmin.exe", "InstallUtil.exe", "RegAsm.exe", "vbc.exe", "RegSvcs.exe", "python.exe", "regsvr32.exe", "dllhost.exe",
  "node.exe", "javaw.exe", "java.exe", "*.pif", "*.com") or

  (?process.code_signature.trusted == false or ?process.code_signature.exists == false) or

  ?process.code_signature.subject_name : ("AutoIt Consulting Ltd", "OpenJS Foundation", "Python Software Foundation") or

  ?process.executable : ("?:\\Users\\*.exe", "?:\\ProgramData\\*.exe")
 ) and
 dns.question.name :
         (
          "ip-api.com",
          "checkip.dyndns.org",
          "api.ipify.org",
          "api.ipify.com",
          "whatismyip.akamai.com",
          "bot.whatismyipaddress.com",
          "ifcfg.me",
          "ident.me",
          "ipof.in",
          "ip.tyk.nu",
          "icanhazip.com",
          "curlmyip.com",
          "wgetip.com",
          "eth0.me",
          "ipecho.net",
          "ip.appspot.com",
          "api.myip.com",
          "geoiptool.com",
          "api.2ip.ua",
          "api.ip.sb",
          "ipinfo.io",
          "checkip.amazonaws.com",
          "wtfismyip.com",
          "iplogger.*",
          "freegeoip.net",
          "freegeoip.app",
          "ipinfo.io",
          "geoplugin.net",
          "myip.dnsomatic.com",
          "www.geoplugin.net",
          "api64.ipify.org",
          "ip4.seeip.org",
          "*.geojs.io",
          "*portmap.io",
          "api.2ip.ua",
          "api.db-ip.com",
          "geolocation-db.com",
          "httpbin.org",
          "myip.opendns.com"
         )
```



### Tool Enumeration Detected via Defend for Containers

Branch count: 2035  
Document count: 2035  
Index: geneve-ut-1497  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name == "which" or
  (
    /* Account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in ("which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which") and
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.args in (

  /* TCP IP */
  "curl", "wget", "socat", "nc", "netcat", "ncat", "busybox", "python3", "python", "perl", "node", "openssl", "ruby", "lua",

  /* networking */
  "getent", "dig", "nslookup", "host", "ip", "tcpdump", "tshark",

  /* container management */
  "kubectl", "docker", "kubelet", "kube-proxy", "containerd", "systemd", "crictl",

  /* compilation */
  "gcc", "g++", "clang", "clang++", "cc", "c++", "c99", "c89", "cc1*", "musl-gcc", "musl-clang", "tcc", "zig", "ccache", "distcc", "make",

  /* scanning */
  "nmap", "zenmap", "nuclei", "netdiscover", "legion", "masscan", "zmap", "zgrab", "ngrep", "telnet", "mitmproxy", "zmap",
  "masscan", "zgrab"
) and
process.interactive == true and container.id like "*"
```



### Web Server Child Shell Spawn Detected via Defend for Containers

Branch count: 2070  
Document count: 2070  
Index: geneve-ut-1655  
Failure message(s):  
  SDE says:
> This rule reached the maximum alert limit for the rule execution. Some alerts were not created.  

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.parent.name in (
      "apache", "nginx", "apache2", "httpd", "lighttpd", "caddy", "mongrel_rails", "gunicorn",
      "uwsgi", "openresty", "cherokee", "h2o", "resin", "puma", "unicorn", "traefik", "tornado", "hypercorn",
      "daphne", "twistd", "yaws", "webfsd", "httpd.worker", "flask", "rails", "mongrel", "php-cgi",
      "php-fcgi", "php-cgi.cagefs", "catalina.sh", "hiawatha", "lswsctrl"
  ) or
  process.parent.name like "php-fpm*" or
  user.name in ("apache", "www-data", "httpd", "nginx", "lighttpd", "tomcat", "tomcat8", "tomcat9") or
  user.id in ("33", "498", "48") or
  (process.parent.name == "java" and process.parent.working_directory like "/u0?/*") or
  process.parent.working_directory like "/var/www/*"
) and (
  (process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox")) or
  (process.args in (
    "bash", "/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash",
    "dash", "/bin/dash", "/usr/bin/dash", "/usr/local/bin/dash",
    "sh", "/bin/sh", "/usr/bin/sh", "/usr/local/bin/sh",
    "tcsh", "/bin/tcsh", "/usr/bin/tcsh", "/usr/local/bin/tcsh",
    "csh", "/bin/csh", "/usr/bin/csh", "/usr/local/bin/csh",
    "zsh", "/bin/zsh", "/usr/bin/zsh", "/usr/local/bin/zsh",
    "ksh", "/bin/ksh", "/usr/bin/ksh", "/usr/local/bin/ksh",
    "fish", "/bin/fish", "/usr/bin/fish", "/usr/local/bin/fish",
    "busybox", "/bin/busybox", "/usr/bin/busybox", "/usr/local/bin/busybox"
  ))
) and process.args == "-c" and container.id like "?*"
```



## Unsuccessful rules with signals (22)

### Cloud Credential Search Detected via Defend for Containers

Branch count: 8325  
Document count: 8325  
Index: geneve-ut-0245

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name in ("grep", "egrep", "fgrep", "find", "locate", "mlocate", "cat", "sed", "awk") or
  (
    /* Account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "grep", "/bin/grep", "/usr/bin/grep", "/usr/local/bin/grep",
      "egrep", "/bin/egrep", "/usr/bin/egrep", "/usr/local/bin/egrep",
      "fgrep", "/bin/fgrep", "/usr/bin/fgrep", "/usr/local/bin/fgrep",
      "find", "/bin/find", "/usr/bin/find", "/usr/local/bin/find",
      "locate", "/bin/locate", "/usr/bin/locate", "/usr/local/bin/locate",
      "mlocate", "/bin/mlocate", "/usr/bin/mlocate", "/usr/local/bin/mlocate",
      "cat", "/bin/cat", "/usr/bin/cat", "/usr/local/bin/cat",
      "sed", "/bin/sed", "/usr/bin/sed", "/usr/local/bin/sed",
      "awk", "/bin/awk", "/usr/bin/awk", "/usr/local/bin/awk"
    ) and 
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
)
and
process.args like~ (
  /* AWS Credentials */
  "*aws_access_key_id*", "*aws_secret_access_key*", "*aws_session_token*", "*accesskeyid*", "*secretaccesskey*",
  "*access_key*", "*.aws/credentials*",

  /* Azure Credentials */
  "*AZURE_CLIENT_ID*", "*AZURE_TENANT_ID*", "*AZURE_CLIENT_SECRET*", "*AZURE_FEDERATED_TOKEN_FILE*",
  "*IDENTITY_ENDPOINT*", "*IDENTITY_HEADER*", "*MSI_ENDPOINT*", "*MSI_SECRET*",
  "*/.azure/*", "*/var/run/secrets/azure/*",

  /* GCP Credentials */
  "*/.config/gcloud/*", "*application_default_credentials.json*",
  "*type: service_account*", "*client_email*", "*private_key_id*", "*private_key*",
  "*/var/run/secrets/google/*", "*GOOGLE_APPLICATION_CREDENTIALS*"
) and process.interactive == true and container.id like "*"
```



### Connection to Common Large Language Model Endpoints

Branch count: 1836  
Document count: 1836  
Index: geneve-ut-0259

```python
network where host.os.type == "windows" and dns.question.name != null and
(
  process.name : ("MSBuild.exe", "mshta.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "rundll32.exe",
  "bitsadmin.exe", "InstallUtil.exe", "RegAsm.exe", "vbc.exe", "RegSvcs.exe", "python.exe", "regsvr32.exe", "dllhost.exe",
  "node.exe", "javaw.exe", "java.exe", "*.pif", "*.com") or

  ?process.code_signature.subject_name : ("AutoIt Consulting Ltd", "OpenJS Foundation", "Python Software Foundation") or

  (
    process.executable : ("?:\\Users\\*.exe", "?:\\ProgramData\\*.exe") and
    (?process.code_signature.trusted == false or ?process.code_signature.exists == false)
  )
 ) and
    dns.question.name : (
    // Major LLM APIs
    "api.openai.com",
    "*.openai.azure.com",
    "api.anthropic.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "api.ai21.com",
    "api.groq.com",
    "api.perplexity.ai",
    "api.x.ai",
    "api.deepseek.com",
    "api.gemini.google.com",
    "generativelanguage.googleapis.com",
    "api.azure.com",
    "api.bedrock.aws",
    "bedrock-runtime.amazonaws.com",

    // Hugging Face & other ML infra
    "api-inference.huggingface.co",
    "inference-endpoint.huggingface.cloud",
    "*.hf.space",
    "*.replicate.com",
    "api.replicate.com",
    "api.runpod.ai",
    "*.runpod.io",
    "api.modal.com",
    "*.forefront.ai",

    // Consumer-facing AI chat portals
    "chat.openai.com",
    "chatgpt.com",
    "copilot.microsoft.com",
    "bard.google.com",
    "gemini.google.com",
    "claude.ai",
    "perplexity.ai",
    "poe.com",
    "chat.forefront.ai",
    "chat.deepseek.com"
  ) and

  not process.executable : (
          "?:\\Program Files\\*.exe",
          "?:\\Program Files (x86)\\*.exe",
          "?:\\Windows\\System32\\svchost.exe",
          "?:\\Windows\\SystemApps\\Microsoft.LockApp_*\\LockApp.exe",
          "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
          "?:\\Users\\*\\AppData\\Local\\BraveSoftware\\*\\Application\\brave.exe",
          "?:\\Users\\*\\AppData\\Local\\Vivaldi\\Application\\vivaldi.exe",
          "?:\\Users\\*\\AppData\\Local\\Programs\\Opera*\\opera.exe",
          "?:\\Users\\*\\AppData\\Local\\Programs\\Fiddler\\Fiddler.exe"
        ) and
    not (?process.code_signature.trusted == true and
         ?process.code_signature.subject_name : ("Anthropic, PBC", "Google LLC", "Mozilla Corporation", "Brave Software, Inc.", "Island Technology Inc.", "Opera Norway AS"))
```



### Execution of a Downloaded Windows Script

Branch count: 8448  
Document count: 16896  
Index: geneve-ut-0420

```python
sequence by host.id, user.id with maxspan=3m
[file where host.os.type == "windows" and event.action == "creation" and user.id != "S-1-5-18" and
  process.name : ("chrome.exe", "msedge.exe", "brave.exe", "browser.exe", "dragon.exe", "vivaldi.exe", "explorer.exe", "winrar.exe", "7zFM.exe", "7zG.exe", "Bandizip.exe") and
  file.extension in~ ("js", "jse", "vbs", "vbe", "wsh", "hta", "cmd", "bat") and
  (file.origin_url != null or file.origin_referrer_url != null)]
[process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : ("chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "browser.exe", "dragon.exe", "vivaldi.exe", "explorer.exe", "winrar.exe", "7zFM.exe", "7zG.exe", "Bandizip.exe") and 
 process.args_count >= 2 and
 (
  process.name in~ ("wscript.exe", "mshta.exe") or
  (process.name : "cmd.exe" and process.command_line : ("*.cmd*", "*.bat*"))
  )]
```



### File Creation, Execution and Self-Deletion in Suspicious Directory

Branch count: 4608  
Document count: 13824  
Index: geneve-ut-0446

```python
sequence by host.id, user.id with maxspan=1m
  [file where host.os.type == "linux" and event.action == "creation" and
   process.name in ("curl", "wget", "fetch", "ftp", "sftp", "scp", "rsync", "ld") and
   file.path : ("/dev/shm/*", "/run/shm/*", "/tmp/*", "/var/tmp/*",
     "/run/*", "/var/run/*", "/var/www/*", "/proc/*/fd/*")] by file.name
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
   not process.parent.executable like (
     "/tmp/VeeamApp*", "/tmp/rajh/spack-stage/*", "plz-out/bin/vault/bridge/test/e2e/base/bridge-dev",
     "/usr/bin/ranlib", "/usr/bin/ar", "plz-out/bin/vault/bridge/test/e2e/base/local-k8s"
   )] by process.name
  [file where host.os.type == "linux" and event.action == "deletion" and
   file.path : (
     "/dev/shm/*", "/run/shm/*", "/tmp/*", "/var/tmp/*", "/run/*", "/var/run/*", "/var/www/*", "/proc/*/fd/*"
    ) and not process.name in ("rm", "ld", "conftest", "link", "gcc", "getarch", "ld")] by file.name
```



### File Execution Permission Modification Detected via Defend for Containers

Branch count: 3626  
Document count: 3626  
Index: geneve-ut-0449

```python
file where host.os.type == "linux" and event.type in ("change", "creation") and (
  process.name == "chmod" or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod"
    ) and
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man"
    )
  )
) and process.args in ("4755", "755", "777", "0777", "444", "+x", "a+x") and
process.args like ("/dev/shm/*", "/tmp/*", "/var/tmp/*", "/run/*", "/var/run/*", "/mnt/*", "/media/*") and
process.interactive == true and container.id like "*" and not process.args == "-x"
```



### Git Hook Child Process

Branch count: 2300  
Document count: 2300  
Index: geneve-ut-0523

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.parent.name in (
  "applypatch-msg", "commit-msg", "fsmonitor-watchman", "post-update", "post-checkout", "post-commit",
  "pre-applypatch", "pre-commit", "pre-merge-commit", "prepare-commit-msg", "pre-push", "pre-rebase", "pre-receive",
  "push-to-checkout", "update", "post-receive", "pre-auto-gc", "post-rewrite", "sendemail-validate", "p4-pre-submit",
  "post-index-change", "post-merge", "post-applypatch"
) and
(
  process.name in ("nohup", "setsid", "disown", "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") or
  process.name like ("php*", "perl*", "ruby*", "lua*") or
  process.executable like (
    "/boot/*", "/dev/shm/*", "/etc/cron.*/*", "/etc/init.d/*", "/etc/update-motd.d/*",
    "/run/*", "/srv/*", "/tmp/*", "/var/tmp/*", "/var/log/*"
  )
) and
not process.name in ("git", "dirname")
```



### Multi-Base64 Decoding Attempt from Suspicious Location

Branch count: 2352  
Document count: 4704  
Index: geneve-ut-0786

```python
sequence by process.parent.entity_id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.executable != null and
   process.name in ("base64", "base64plain", "base64url", "base64mime", "base64pem", "base32", "base16") and
   // Only including potentially suspicious locations
   process.args like~ ("-d*", "--d*") and process.working_directory like (
     "/tmp/*", "/var/tmp*", "/dev/shm/*", "/var/www/*", "/home/*", "/root/*"
   ) and not (
     process.parent.executable in (
       "/usr/share/ec2-instance-connect/eic_curl_authorized_keys", "/etc/cron.daily/vivaldi",
       "/etc/cron.daily/opera-browser"
     ) or
     process.working_directory like (
       "/opt/microsoft/omsagent/plugin", "/opt/rapid7/ir_agent/*", "/tmp/newroot/*"
      ) or
      (process.parent.name == "zsh" and process.parent.command_line like "*extendedglob*")
   )]
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.executable != null and
   process.name in ("base64", "base64plain", "base64url", "base64mime", "base64pem", "base32", "base16") and
   process.args like~ ("-d*", "--d*")]
```



### Netcat File Transfer or Listener Detected via Defend for Containers

Branch count: 1110  
Document count: 1110  
Index: geneve-ut-0810

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name in ("nc","ncat","netcat","netcat.openbsd","netcat.traditional") or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "nc", "/bin/nc", "/usr/bin/nc", "/usr/local/bin/nc",
      "ncat", "/bin/ncat", "/usr/bin/ncat", "/usr/local/bin/ncat",
      "netcat", "/bin/netcat", "/usr/bin/netcat", "/usr/local/bin/netcat",
      "netcat.openbsd", "/bin/netcat.openbsd", "/usr/bin/netcat.openbsd", "/usr/local/bin/netcat.openbsd",
      "netcat.traditional", "/bin/netcat.traditional", "/usr/bin/netcat.traditional", "/usr/local/bin/netcat.traditional"
    ) and 
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.args like~ (
  /* bind shell to specific port or listener */
  "-*l*","-*p*",
  /* reverse shell to command-line interpreter used for command execution */
  "-*e*",
  /* file transfer via stdout/pipe */
  ">","<", "|"
) and process.interactive == true and container.id like "*"
```



### Pod or Container Creation with Suspicious Command-Line

Branch count: 8448  
Document count: 8448  
Index: geneve-ut-0895

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and (
  (process.name == "kubectl" and process.args == "run" and process.args == "--restart=Never" and process.args == "--") or
  (process.name in ("docker", "nerdctl", "ctl") and process.args == "run")
) and 
process.args in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
process.command_line like~ (
  "*atd*", "*cron*", "*/etc/rc.local*", "*/dev/tcp/*", "*/etc/init.d*", "*/etc/update-motd.d*", "*/etc/ld.so*", "*/etc/sudoers*", "*base64 *",
  "*/etc/profile*", "*/etc/ssh*", "*/home/*/.ssh/*", "*/root/.ssh*" , "*~/.ssh/*", "*autostart*", "*xxd *", "*/etc/shadow*", "*./.*",
  "*import*pty*spawn*", "*import*subprocess*call*", "*TCPSocket.new*", "*TCPSocket.open*", "*io.popen*", "*os.execute*", "*fsockopen*",
  "*disown*", "* ncat *", "* nc *", "* netcat *",  "* nc.traditional *", "*socat*", "*telnet*", "*/tmp/*", "*/dev/shm/*", "*/var/tmp/*",
  "*/boot/*", "*/sys/*", "*/lost+found/*", "*/media/*", "*/proc/*", "*/var/backups/*", "*/var/log/*", "*/var/mail/*", "*/var/spool/*"
)
```



### Potential Backdoor Execution Through PAM_EXEC

Branch count: 3600  
Document count: 7200  
Index: geneve-ut-0909

```python
sequence by process.entity_id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "change" and event.action == "session_id_change" and process.name in ("ssh", "sshd")]
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.name in ("ssh", "sshd") and
   process.args_count == 2 and process.args like (
     "sh", "dash", "bash", "zsh",
     "perl*", "python*", "php*", "ruby*", "lua*",

     "/bin/sh", "/bin/dash", "/bin/bash", "/bin/zsh",
     "/bin/perl*", "/bin/python*", "/bin/php*", "/bin/ruby*", "/bin/lua*",

     "/usr/bin/sh", "/usr/bin/dash", "/usr/bin/bash", "/usr/bin/zsh",
     "/usr/bin/perl*", "/usr/bin/python*", "/usr/bin/php*", "/usr/bin/ruby*", "/usr/bin/lua*",

     "/usr/local/bin/sh", "/usr/local/bin/dash", "/usr/local/bin/bash", "/usr/local/bin/zsh",
     "/usr/local/bin/perl*", "/usr/local/bin/python*", "/usr/local/bin/php*", "/usr/local/bin/ruby*", "/usr/local/bin/lua*"
   ) and (
     process.name like ".*" or
     process.executable like (
       "/tmp/*", "/var/tmp/*", "/dev/shm/*", "./*", "/boot/*", "/sys/*", "/lost+found/*", "/media/*", "/proc/*", "/bin/*", "/usr/bin/*",
       "/sbin/*", "/usr/sbin/*", "/lib/*", "/lib64/*", "/usr/lib/*", "/usr/lib64/*", "/opt/*", "/var/lib/*", "/run/*", "/var/backups/*",
       "/var/log/*", "/var/mail/*", "/var/spool/*"
     )
   )
  ]
```



### Potential Git CVE-2025-48384 Exploitation

Branch count: 2500  
Document count: 5000  
Index: geneve-ut-0963

```python
sequence by host.id with maxspan=1m
  [process where host.os.type in ("linux", "macos") and event.type == "start" and event.action in ("exec", "executed", "process_started", "start", "ProcessRollup2") and
   process.name == "git" and process.args == "clone" and process.args == "--recursive" and process.args like~ "http*"] by process.entity_id
  [process where host.os.type in ("linux", "macos") and event.type == "start" and event.action in ("exec", "executed", "process_started", "start", "ProcessRollup2") and
   process.name in (
    "dash", "sh", "static-sh", "bash", "bash-static", "zsh", "ash", "csh", "ksh", "tcsh", "busybox", "fish", "ksh93", "rksh",
    "rksh93", "lksh", "mksh", "mksh-static", "csharp", "posh", "rc", "sash", "yash", "zsh5", "zsh5-static"
   )] by process.parent.entity_id
```



### Potential Kubectl Masquerading via Unexpected Process

Branch count: 1085  
Document count: 1085  
Index: geneve-ut-0977

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "executed", "process_started") and
(
  process.executable like~ ("/tmp/*", "/var/tmp/*", "/dev/shm/*", "/root/*", "/var/www/*", "./kubectl") or
  process.name like ".*"
) and
process.args like~ (

  // get and describe commands
  "*get po*", "*get deploy*", "*get node*", "*get svc*", "*get service*", "*get secret*", "*get clusterrole*", "*get ingress*",
  "*get configmap*", "*describe po*", "*describe deploy*", "*describe node*", "*describe svc*", "*describe service*",
  "*describe secret*", "*describe configmap*", "*describe clusterrole*", "*describe ingress*",

  // exec commands
  "*exec -it*", "*exec --stdin*", "*exec --tty*",

  // networking commands
  "*port-forward* ", "*proxy --port*", "*run --image=*", "*expose*",

  // authentication/impersonation commands
  "*auth can-i*", "*--kubeconfig*", "*--as *", "*--as=*", "*--as-group*", "*--as-uid*"
) and not (
  process.executable like "/tmp/newroot/*" or
  process.name == ".flatpak-wrapped"
)
```



### Potential Linux Tunneling and/or Port Forwarding

Branch count: 1212  
Document count: 1212  
Index: geneve-ut-0989

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and (
  (
    // gost & pivotnacci - spawned without process.parent.name
    (process.name == "gost" and process.args : ("-L*", "-C*", "-R*")) or (process.name == "pivotnacci")) or (
    // ssh
    (process.name == "ssh" and (process.args in ("-R", "-L", "-D", "-w") and process.args_count >= 4 and 
     not (process.args == "chmod" or process.command_line like "*rungencmd*"))) or
    // sshuttle
    (process.name == "sshuttle" and process.args in ("-r", "--remote", "-l", "--listen") and process.args_count >= 4) or
    // socat
    (process.name == "socat" and process.args : ("TCP4-LISTEN:*", "SOCKS*") and process.args_count >= 3) or
    // chisel
    (process.name : "chisel*" and process.args in ("client", "server")) or
    // iodine(d), dnscat, hans, ptunnel-ng, ssf, 3proxy & ngrok 
    (process.name in ("iodine", "iodined", "dnscat", "hans", "hans-ubuntu", "ptunnel-ng", "ssf", "3proxy", "ngrok", "wstunnel"))
  ) and process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
)
```



### Potential Privilege Escalation via Service ImagePath Modification

Branch count: 1794  
Document count: 1794  
Index: geneve-ut-1053

```python
registry where host.os.type == "windows" and event.type == "change" and process.executable != null and
  registry.data.strings != null and registry.value == "ImagePath" and
  registry.key : (
    "*\\ADWS", "*\\AppHostSvc", "*\\AppReadiness", "*\\AudioEndpointBuilder", "*\\AxInstSV", "*\\camsvc", "*\\CertSvc",
    "*\\COMSysApp", "*\\CscService", "*\\defragsvc", "*\\DeviceAssociationService", "*\\DeviceInstall", "*\\DevQueryBroker",
    "*\\Dfs", "*\\DFSR", "*\\diagnosticshub.standardcollector.service", "*\\DiagTrack", "*\\DmEnrollmentSvc", "*\\DNS",
    "*\\dot3svc", "*\\Eaphost", "*\\GraphicsPerfSvc", "*\\hidserv", "*\\HvHost", "*\\IISADMIN", "*\\IKEEXT",
    "*\\InstallService", "*\\iphlpsvc", "*\\IsmServ", "*\\LanmanServer", "*\\MSiSCSI", "*\\NcbService", "*\\Netlogon",
    "*\\Netman", "*\\NtFrs", "*\\PlugPlay", "*\\Power", "*\\PrintNotify", "*\\ProfSvc", "*\\PushToInstall", "*\\RSoPProv",
    "*\\sacsvr", "*\\SENS", "*\\SensorDataService", "*\\SgrmBroker", "*\\ShellHWDetection", "*\\shpamsvc", "*\\StorSvc",
    "*\\svsvc", "*\\swprv", "*\\SysMain", "*\\Themes", "*\\TieringEngineService", "*\\TokenBroker", "*\\TrkWks",
    "*\\UALSVC", "*\\UserManager", "*\\vm3dservice", "*\\vmicguestinterface", "*\\vmicheartbeat", "*\\vmickvpexchange",
    "*\\vmicrdv", "*\\vmicshutdown", "*\\vmicvmsession", "*\\vmicvss", "*\\vmvss", "*\\VSS", "*\\w3logsvc", "*\\W3SVC",
    "*\\WalletService", "*\\WAS", "*\\wercplsupport", "*\\WerSvc", "*\\Winmgmt", "*\\wisvc", "*\\wmiApSrv",
    "*\\WPDBusEnum", "*\\WSearch"
  ) and
  not (
    registry.data.strings : (
        "?:\\Windows\\system32\\*.exe",
        "%systemroot%\\system32\\*.exe",
        "%windir%\\system32\\*.exe",
        "%SystemRoot%\\system32\\svchost.exe -k *",
        "%windir%\\system32\\svchost.exe -k *"
    ) and
        not registry.data.strings : (
            "*\\cmd.exe",
            "*\\cscript.exe",
            "*\\ieexec.exe",
            "*\\iexpress.exe",
            "*\\installutil.exe",
            "*\\Microsoft.Workflow.Compiler.exe",
            "*\\msbuild.exe",
            "*\\mshta.exe",
            "*\\msiexec.exe",
            "*\\msxsl.exe",
            "*\\net.exe",
            "*\\powershell.exe",
            "*\\pwsh.exe",
            "*\\reg.exe",
            "*\\RegAsm.exe",
            "*\\RegSvcs.exe",
            "*\\regsvr32.exe",
            "*\\rundll32.exe",
            "*\\vssadmin.exe",
            "*\\wbadmin.exe",
            "*\\wmic.exe",
            "*\\wscript.exe"
        )
  )
```



### Sensitive File Compression Detected via Defend for Containers

Branch count: 8880  
Document count: 8880  
Index: geneve-ut-1260

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name in ("zip", "tar", "gzip", "hdiutil", "7z", "rar", "7zip", "p7zip") or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "zip", "/bin/zip", "/usr/bin/zip", "/usr/local/bin/zip",
      "tar", "/bin/tar", "/usr/bin/tar", "/usr/local/bin/tar",
      "gzip", "/bin/gzip", "/usr/bin/gzip", "/usr/local/bin/gzip",
      "hdiutil", "/bin/hdiutil", "/usr/bin/hdiutil", "/usr/local/bin/hdiutil",
      "7z", "/bin/7z", "/usr/bin/7z", "/usr/local/bin/7z",
      "rar", "/bin/rar", "/usr/bin/rar", "/usr/local/bin/rar",
      "7zip", "/bin/7zip", "/usr/bin/7zip", "/usr/local/bin/7zip",
      "p7zip", "/bin/p7zip", "/usr/bin/p7zip", "/usr/local/bin/p7zip"
    ) and 
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.args like~ (
  "*/root/.ssh/*", "*/home/*/.ssh/*", "*/root/.bash_history*", "*/etc/hosts*", "*/root/.aws/*", "*/home/*/.aws/*",
  "*/root/.docker/*", "*/home/*/.docker/*", "*/etc/group*", "*/etc/passwd*", "*/etc/shadow*", "*/etc/gshadow*",
  "*/.azure/*", "*/var/run/secrets/azure/*", "*/.config/gcloud/*", "*application_default_credentials.json*",
  "*type: service_account*", "*client_email*", "*private_key_id*", "*private_key*", "*/var/run/secrets/google/*",
  "*GOOGLE_APPLICATION_CREDENTIALS*", "*AZURE_CLIENT_ID*", "*AZURE_TENANT_ID*", "*AZURE_CLIENT_SECRET*",
  "*AZURE_FEDERATED_TOKEN_FILE*", "*IDENTITY_ENDPOINT*", "*IDENTITY_HEADER*", "*MSI_ENDPOINT*", "*MSI_SECRET*"
) and process.interactive == true and container.id like "*"
```



### Sensitive Keys Or Passwords Search Detected via Defend for Containers

Branch count: 2997  
Document count: 2997  
Index: geneve-ut-1263

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name in ("grep", "egrep", "fgrep", "find", "locate", "mlocate", "cat", "sed", "awk") or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "grep", "/bin/grep", "/usr/bin/grep", "/usr/local/bin/grep",
      "egrep", "/bin/egrep", "/usr/bin/egrep", "/usr/local/bin/egrep",
      "fgrep", "/bin/fgrep", "/usr/bin/fgrep", "/usr/local/bin/fgrep",
      "find", "/bin/find", "/usr/bin/find", "/usr/local/bin/find",
      "locate", "/bin/locate", "/usr/bin/locate", "/usr/local/bin/locate",
      "mlocate", "/bin/mlocate", "/usr/bin/mlocate", "/usr/local/bin/mlocate",
      "cat", "/bin/cat", "/usr/bin/cat", "/usr/local/bin/cat",
      "sed", "/bin/sed", "/usr/bin/sed", "/usr/local/bin/sed",
      "awk", "/bin/awk", "/usr/bin/awk", "/usr/local/bin/awk"
    ) and 
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.args like~ (
  "*BEGIN PRIVATE*", "*BEGIN OPENSSH PRIVATE*", "*BEGIN RSA PRIVATE*", "*BEGIN DSA PRIVATE*", "*BEGIN EC PRIVATE*",
  "*password*", "*ssh*", "*id_rsa*", "*id_dsa*"
) and process.interactive == true and container.id like "*"
```



### Suspicious APT Package Manager Execution

Branch count: 1368  
Document count: 2736  
Index: geneve-ut-1338

```python
sequence by host.id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "ProcessRollup2") and
   process.parent.name == "apt" and process.args == "-c" and process.name in (
     "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish"
   ) and not process.executable == "/usr/lib/venv-salt-minion/bin/python.original"
  ] by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "ProcessRollup2") and process.name like (
     "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "python*", "php*",
     "perl", "ruby", "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk"
   ) and not (
     ?process.parent.executable like (
       "/run/k3s/containerd*", "/tmp/newroot/*", "/usr/share/debconf/frontend", "/var/tmp/buildah*", "./merged/*",
       "./*/vz/root/*", "/usr/bin/adequate" 
      ) or
     process.executable like ("/usr/lib/venv-salt-minion/bin/python.original", "./merged/var/lib/containers/*") or
     process.command_line in (
       "python3 /usr/sbin/omv-mkaptidx", "python3 /usr/local/bin/abr-upgrade --upgrade",
       "sh -c apt-get indextargets -o Dir::State::lists=/var/lib/apt/lists/ --format='$(FILENAME)' 'Created-By: Packages'",
       "/usr/bin/perl /usr/sbin/dpkg-preconfigure --apt", "/bin/sh -e /usr/lib/update-notifier/update-motd-updates-available",
       "/usr/bin/python3 /usr/lib/cnf-update-db", "/usr/bin/python3 /usr/bin/apt-listchanges --apt",
       "/usr/bin/perl -w /usr/sbin/dpkg-preconfigure --apt", "/bin/sh /usr/lib/needrestart/apt-pinvoke",
       "/bin/sh /usr/bin/kali-check-apt-sources", "/bin/sh /usr/lib/needrestart/apt-pinvoke -m u",
       "/usr/bin/perl /usr/sbin/needrestart",  "/usr/bin/perl -w /usr/bin/apt-show-versions -i",
       "/usr/bin/perl -w /usr/bin/apt-show-versions -i", "/usr/bin/perl -w /bin/apt-show-versions -i",
       "/usr/bin/perl /bin/adequate --help",  "/usr/bin/perl /usr/sbin/needrestart -m u", 
       "/usr/bin/perl -w /usr/share/debconf/frontend /usr/sbin/needrestart",
       "/usr/bin/python3 /sbin/katello-tracer-upload",
       "/usr/bin/python3 /usr/bin/package-profile-upload"
     ) or
     ?process.parent.command_line like ("sh -c if [ -x*", "sh -c -- if [ -x*") or
     process.args in ("/usr/sbin/needrestart", "/usr/lib/needrestart/apt-pinvoke", "/usr/share/proxmox-ve/pve-apt-hook", "/usr/bin/dpkg-source") or
     ?process.parent.args == "/usr/share/debconf/frontend"
    )
  ] by process.parent.entity_id
```



### Suspicious Execution via Scheduled Task

Branch count: 6144  
Document count: 6144  
Index: geneve-ut-1369

```python
process where host.os.type == "windows" and event.type == "start" and
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
       "C:\\HP\\*") and

    not (process.name : "cmd.exe" and process.args : ("*.bat", "*.cmd")) and
    not (process.name : "cscript.exe" and process.args : "?:\\Windows\\system32\\calluxxprovider.vbs") and
    not (
       process.name : "powershell.exe" and
       process.args : (
           "-File", "-PSConsoleFile",
           "C:\\ProgramData\\Microsoft\\AutopatchSetupScheduled\\SetupAutopatchClientV2Package.ps1",
           "C:\\ProgramData\\Microsoft\\AutopatchSetupScheduled\\SetupAutopatchClientPackage.ps1",
           "C:\\Windows\\Temp\\MSS\\MDESetup\\Invoke-MDESetup.ps1"
       ) and user.id : "S-1-5-18"
    ) and
    not (process.name : "msiexec.exe" and user.id : "S-1-5-18") and
    not (process.name : "powershell.exe" and
         process.command_line : ("C:\\ProgramData\\ElasticAgent-HealthCheck.ps1",
                                 "C:\\ProgramData\\ssh\\puttysetup.ps1"))
```



### Suspicious File Creation via Pkg Install Script

Branch count: 4032  
Document count: 8064  
Index: geneve-ut-1374

```python
sequence by process.entity_id with maxspan=30s
  [process where host.os.type == "macos" and event.type == "start" and process.name in ("bash", "sh", "zsh") and
    process.args like~ ("/tmp/PKInstallSandbox.*/Scripts/com.*/preinstall", 
                        "/tmp/PKInstallSandbox.*/Scripts/*/postinstall") and
    process.args like ("/Users/*", "/Volumes/*") and 
    not process.args like~ "/Users/*/Library/Caches/*"]
  [file where host.os.type == "macos" and event.action != "deletion" and process.name in ("mv", "cp") and
    (file.extension in ("py", "js", "sh", "scpt", "terminal", "tcl", "app", "pkg", "dmg", "command") or
      file.Ext.header_bytes like~ ("cffaedfe*", "cafebabe*")) and
    file.path like ("/private/etc/*", "/var/tmp/*", "/tmp/*", "/var/folders/*", "/Users/Shared/*",
                    "/Library/Graphics/*", "/Library/Containers/*", "/Users/*/Library/Containers/*", 
                    "/Users/*/Library/Services/*", "/Users/*/Library/Preferences/*", "/var/root/*",
                    "/Library/WebServer/*", "/Library/Fonts/*", "/usr/local/bin/*") and 
    not file.name == "CodeResources"]
```



### System Public IP Discovery via DNS Query

Branch count: 1053  
Document count: 1053  
Index: geneve-ut-1470

```python
network where host.os.type == "windows" and dns.question.name != null and process.name != null and
(
  process.name : ("MSBuild.exe", "mshta.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "rundll32.exe",
  "bitsadmin.exe", "InstallUtil.exe", "RegAsm.exe", "vbc.exe", "RegSvcs.exe", "python.exe", "regsvr32.exe", "dllhost.exe",
  "node.exe", "javaw.exe", "java.exe", "*.pif", "*.com") or

  (?process.code_signature.trusted == false or ?process.code_signature.exists == false) or

  ?process.code_signature.subject_name : ("AutoIt Consulting Ltd", "OpenJS Foundation", "Python Software Foundation") or

  ?process.executable : ("?:\\Users\\*.exe", "?:\\ProgramData\\*.exe")
 ) and
 dns.question.name :
         (
          "ip-api.com",
          "checkip.dyndns.org",
          "api.ipify.org",
          "api.ipify.com",
          "whatismyip.akamai.com",
          "bot.whatismyipaddress.com",
          "ifcfg.me",
          "ident.me",
          "ipof.in",
          "ip.tyk.nu",
          "icanhazip.com",
          "curlmyip.com",
          "wgetip.com",
          "eth0.me",
          "ipecho.net",
          "ip.appspot.com",
          "api.myip.com",
          "geoiptool.com",
          "api.2ip.ua",
          "api.ip.sb",
          "ipinfo.io",
          "checkip.amazonaws.com",
          "wtfismyip.com",
          "iplogger.*",
          "freegeoip.net",
          "freegeoip.app",
          "ipinfo.io",
          "geoplugin.net",
          "myip.dnsomatic.com",
          "www.geoplugin.net",
          "api64.ipify.org",
          "ip4.seeip.org",
          "*.geojs.io",
          "*portmap.io",
          "api.2ip.ua",
          "api.db-ip.com",
          "geolocation-db.com",
          "httpbin.org",
          "myip.opendns.com"
         )
```



### Tool Enumeration Detected via Defend for Containers

Branch count: 2035  
Document count: 2035  
Index: geneve-ut-1497

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name == "which" or
  (
    /* Account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in ("which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which") and
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.args in (

  /* TCP IP */
  "curl", "wget", "socat", "nc", "netcat", "ncat", "busybox", "python3", "python", "perl", "node", "openssl", "ruby", "lua",

  /* networking */
  "getent", "dig", "nslookup", "host", "ip", "tcpdump", "tshark",

  /* container management */
  "kubectl", "docker", "kubelet", "kube-proxy", "containerd", "systemd", "crictl",

  /* compilation */
  "gcc", "g++", "clang", "clang++", "cc", "c++", "c99", "c89", "cc1*", "musl-gcc", "musl-clang", "tcc", "zig", "ccache", "distcc", "make",

  /* scanning */
  "nmap", "zenmap", "nuclei", "netdiscover", "legion", "masscan", "zmap", "zgrab", "ngrep", "telnet", "mitmproxy", "zmap",
  "masscan", "zgrab"
) and
process.interactive == true and container.id like "*"
```



### Web Server Child Shell Spawn Detected via Defend for Containers

Branch count: 2070  
Document count: 2070  
Index: geneve-ut-1655

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.parent.name in (
      "apache", "nginx", "apache2", "httpd", "lighttpd", "caddy", "mongrel_rails", "gunicorn",
      "uwsgi", "openresty", "cherokee", "h2o", "resin", "puma", "unicorn", "traefik", "tornado", "hypercorn",
      "daphne", "twistd", "yaws", "webfsd", "httpd.worker", "flask", "rails", "mongrel", "php-cgi",
      "php-fcgi", "php-cgi.cagefs", "catalina.sh", "hiawatha", "lswsctrl"
  ) or
  process.parent.name like "php-fpm*" or
  user.name in ("apache", "www-data", "httpd", "nginx", "lighttpd", "tomcat", "tomcat8", "tomcat9") or
  user.id in ("33", "498", "48") or
  (process.parent.name == "java" and process.parent.working_directory like "/u0?/*") or
  process.parent.working_directory like "/var/www/*"
) and (
  (process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox")) or
  (process.args in (
    "bash", "/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash",
    "dash", "/bin/dash", "/usr/bin/dash", "/usr/local/bin/dash",
    "sh", "/bin/sh", "/usr/bin/sh", "/usr/local/bin/sh",
    "tcsh", "/bin/tcsh", "/usr/bin/tcsh", "/usr/local/bin/tcsh",
    "csh", "/bin/csh", "/usr/bin/csh", "/usr/local/bin/csh",
    "zsh", "/bin/zsh", "/usr/bin/zsh", "/usr/local/bin/zsh",
    "ksh", "/bin/ksh", "/usr/bin/ksh", "/usr/local/bin/ksh",
    "fish", "/bin/fish", "/usr/bin/fish", "/usr/local/bin/fish",
    "busybox", "/bin/busybox", "/usr/bin/busybox", "/usr/local/bin/busybox"
  ))
) and process.args == "-c" and container.id like "?*"
```



## Rules with no signals (7)

### Kubernetes Forbidden Creation Request

Branch count: 1  
Document count: 1  
Index: geneve-ut-0647

```python
any where event.dataset == "kubernetes.audit_logs" and kubernetes.audit.verb == "create" and
kubernetes.audit.stage == "ResponseComplete" and `kubernetes.audit.annotations.authorization_k8s_io/decision` == "forbid"
```



### Kubernetes Sensitive RBAC Change Followed by Workload Modification

Branch count: 36  
Document count: 72  
Index: geneve-ut-0657

```python
sequence by user.name with maxspan=5m
  [any where event.dataset == "kubernetes.audit_logs" and
   `kubernetes.audit.annotations.authorization_k8s_io/decision` == "allow" and
    kubernetes.audit.objectRef.resource in ("roles", "clusterroles") and
    kubernetes.audit.verb in ("create", "update", "patch")]
  [any where event.dataset == "kubernetes.audit_logs" and
   `kubernetes.audit.annotations.authorization_k8s_io/decision` == "allow" and
    kubernetes.audit.objectRef.resource in ("daemonsets", "deployments", "cronjobs") and
    kubernetes.audit.verb in ("create", "patch") and
    /* reduce control-plane / bootstrap noise */
    not kubernetes.audit.user.groups == "system:masters"
  ]
```



### Kubernetes User Exec into Pod

Branch count: 128  
Document count: 128  
Index: geneve-ut-0663

```python
any where event.dataset == "kubernetes.audit_logs" and kubernetes.audit.verb in ("get", "create") and
kubernetes.audit.objectRef.subresource == "exec" and kubernetes.audit.stage in ("ResponseComplete", "ResponseStarted") and
kubernetes.audit.level == "Request" and `kubernetes.audit.annotations.authorization_k8s_io/decision` == "allow" and
not (
  (kubernetes.audit.objectRef.namespace == "trident" and kubernetes.audit.objectRef.name like "trident-controller-*") or
  (kubernetes.audit.objectRef.namespace == "vuls" and kubernetes.audit.requestURI like "/api/v1/namespaces/vuls/pods/vuls-*/exec?command=sh&command=-c&command=*+%2Fvuls%2Fresults*") or
  (kubernetes.audit.objectRef.namespace == "git-runners" and kubernetes.audit.requestURI like (
     "/api/v1/namespaces/git-runners/pods/runner-*/exec?command=sh&command=-c&command=if+%5B+-x+%2Fusr%2Flocal%2Fbin%2Fbash+%5D%3B+then%0A%09exec+%2Fusr%2Flocal%2Fbin%2Fbash+%0Aelif+%5B+-x+%2Fusr%2Fbin%2Fbash+%5D%3B+then%0A%09exec+%2Fusr%2Fbin%2Fbash+%0Aelif+%5B+-x+%2Fbin%2Fbash+%5D%3B+then%0A%09exec+%2Fbin%2Fbash+%0Aelif+%5B+-x+%2Fusr%2Flocal%2Fbin%2Fsh+%5D%3B+then%0A%09exec+%2Fusr%2Flocal%2Fbin%2Fsh+%0Aelif+%5B+-x+%2Fusr%2Fbin%2Fsh+%5D%3B+then%0A%09exec+%2Fusr%2Fbin%2Fsh+%0Aelif+%5B+-x+%2Fbin%2Fsh+%5D%3B+then%0A%09exec+%2Fbin%2Fsh+%0Aelif+%5B+-x+%2Fbusybox%2Fsh+%5D%3B+then%0A%09exec+%2Fbusybox%2Fsh+%0Aelse%0A%09echo+shell+not+found%0A%09exit+1%0Afi%0A%0A&container=*&container=*&stderr=true&stdin=true&stdout=true",
     "/api/v1/namespaces/git-runners/pods/runner-*/exec?command=gitlab-runner-helper&command=read-logs&command=--path&command=%2Flogs-*%2Foutput.log&command=--offset&command=0&command=--wait-file-timeout&command=1m0s&container=*&container=*&stderr=true&stdout=true"
  )) or
  (kubernetes.audit.objectRef.namespace == "elasticsearch-cluster" and kubernetes.audit.requestURI like (
    "/api/v1/namespaces/elasticsearch-cluster/pods/*/exec?command=df&command=-h&container=elasticsearch&stdin=true&stdout=true&tty=true",
    "/api/v1/namespaces/elasticsearch-cluster/pods/*/exec?command=df&command=-h&container=elasticsearch&stderr=true&stdout=true",
    "/api/v1/namespaces/elasticsearch-cluster/pods/*/exec?command=df&command=-h&container=kibana&stderr=true&stdout=true"
  )) or
  (kubernetes.audit.objectRef.namespace == "kube-system" and kubernetes.audit.requestURI like (
    "/api/v1/namespaces/kube-system/pods/*/exec?command=%2Fproxy-agent&command=--help&container=konnectivity-agent&stderr=true&stdout=true",
    "api/v1/namespaces/kube-system/pods/*/exec?command=cilium&command=endpoint&command=list&command=-o&command=json&container=cilium-agent&stderr=true&stdout=true",
    "/api/v1/namespaces/kube-system/pods/*/exec?command=cilium&command=status&command=-o&command=json&container=cilium-agent&stderr=true&stdout=true",
    "/api/v1/namespaces/kube-system/pods/*/exec?command=sh&command=-c&command=clear%3B+%28bash+%7C%7C+ash+%7C%7C+sh%29&container=*&stdin=true&stdout=true&tty=true"
  ))
)
```



### Linux Group Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-0675

```python
iam where host.os.type == "linux" and event.type == "group" and event.type == "creation" and event.outcome == "success"
```



### Linux User Account Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-0682

```python
iam where host.os.type == "linux" and event.type == "user" and event.type == "creation" and event.outcome == "success"
```



### Potential Network Share Discovery

Branch count: 4  
Document count: 8  
Index: geneve-ut-1011

```python
sequence by user.name, source.port, source.ip with maxspan=15s 
 [file where event.action == "network-share-object-access-checked" and 
  winlog.event_data.ShareName in ("\\\\*\\ADMIN$", "\\\\*\\C$") and 
  source.ip != null and source.ip != "0.0.0.0" and source.ip != "::1" and source.ip != "::" and source.ip != "127.0.0.1"]
 [file where event.action == "network-share-object-access-checked" and 
  winlog.event_data.ShareName in ("\\\\*\\ADMIN$", "\\\\*\\C$") and 
  source.ip != null and source.ip != "0.0.0.0" and source.ip != "::1" and source.ip != "::" and source.ip != "127.0.0.1"]
```



### Potential Privacy Control Bypass via TCCDB Modification

Branch count: 16  
Document count: 16  
Index: geneve-ut-1041

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name == "sqlite*" and
 process.args like "/*/Application Support/com.apple.TCC/TCC.db" and
 (process.parent.name like~ ("osascript", "bash", "sh", "zsh", "Terminal", "Python*") or (process.parent.code_signature.exists == false or process.parent.code_signature.trusted == false))
```



## Rules with too few signals (24)

### Cloud Credential Search Detected via Defend for Containers

Branch count: 8325  
Document count: 8325  
Index: geneve-ut-0245  
Failure message(s):  
  got 1000 signals, expected 8325  

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name in ("grep", "egrep", "fgrep", "find", "locate", "mlocate", "cat", "sed", "awk") or
  (
    /* Account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "grep", "/bin/grep", "/usr/bin/grep", "/usr/local/bin/grep",
      "egrep", "/bin/egrep", "/usr/bin/egrep", "/usr/local/bin/egrep",
      "fgrep", "/bin/fgrep", "/usr/bin/fgrep", "/usr/local/bin/fgrep",
      "find", "/bin/find", "/usr/bin/find", "/usr/local/bin/find",
      "locate", "/bin/locate", "/usr/bin/locate", "/usr/local/bin/locate",
      "mlocate", "/bin/mlocate", "/usr/bin/mlocate", "/usr/local/bin/mlocate",
      "cat", "/bin/cat", "/usr/bin/cat", "/usr/local/bin/cat",
      "sed", "/bin/sed", "/usr/bin/sed", "/usr/local/bin/sed",
      "awk", "/bin/awk", "/usr/bin/awk", "/usr/local/bin/awk"
    ) and 
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
)
and
process.args like~ (
  /* AWS Credentials */
  "*aws_access_key_id*", "*aws_secret_access_key*", "*aws_session_token*", "*accesskeyid*", "*secretaccesskey*",
  "*access_key*", "*.aws/credentials*",

  /* Azure Credentials */
  "*AZURE_CLIENT_ID*", "*AZURE_TENANT_ID*", "*AZURE_CLIENT_SECRET*", "*AZURE_FEDERATED_TOKEN_FILE*",
  "*IDENTITY_ENDPOINT*", "*IDENTITY_HEADER*", "*MSI_ENDPOINT*", "*MSI_SECRET*",
  "*/.azure/*", "*/var/run/secrets/azure/*",

  /* GCP Credentials */
  "*/.config/gcloud/*", "*application_default_credentials.json*",
  "*type: service_account*", "*client_email*", "*private_key_id*", "*private_key*",
  "*/var/run/secrets/google/*", "*GOOGLE_APPLICATION_CREDENTIALS*"
) and process.interactive == true and container.id like "*"
```



### Connection to Common Large Language Model Endpoints

Branch count: 1836  
Document count: 1836  
Index: geneve-ut-0259  
Failure message(s):  
  got 1000 signals, expected 1836  

```python
network where host.os.type == "windows" and dns.question.name != null and
(
  process.name : ("MSBuild.exe", "mshta.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "rundll32.exe",
  "bitsadmin.exe", "InstallUtil.exe", "RegAsm.exe", "vbc.exe", "RegSvcs.exe", "python.exe", "regsvr32.exe", "dllhost.exe",
  "node.exe", "javaw.exe", "java.exe", "*.pif", "*.com") or

  ?process.code_signature.subject_name : ("AutoIt Consulting Ltd", "OpenJS Foundation", "Python Software Foundation") or

  (
    process.executable : ("?:\\Users\\*.exe", "?:\\ProgramData\\*.exe") and
    (?process.code_signature.trusted == false or ?process.code_signature.exists == false)
  )
 ) and
    dns.question.name : (
    // Major LLM APIs
    "api.openai.com",
    "*.openai.azure.com",
    "api.anthropic.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "api.ai21.com",
    "api.groq.com",
    "api.perplexity.ai",
    "api.x.ai",
    "api.deepseek.com",
    "api.gemini.google.com",
    "generativelanguage.googleapis.com",
    "api.azure.com",
    "api.bedrock.aws",
    "bedrock-runtime.amazonaws.com",

    // Hugging Face & other ML infra
    "api-inference.huggingface.co",
    "inference-endpoint.huggingface.cloud",
    "*.hf.space",
    "*.replicate.com",
    "api.replicate.com",
    "api.runpod.ai",
    "*.runpod.io",
    "api.modal.com",
    "*.forefront.ai",

    // Consumer-facing AI chat portals
    "chat.openai.com",
    "chatgpt.com",
    "copilot.microsoft.com",
    "bard.google.com",
    "gemini.google.com",
    "claude.ai",
    "perplexity.ai",
    "poe.com",
    "chat.forefront.ai",
    "chat.deepseek.com"
  ) and

  not process.executable : (
          "?:\\Program Files\\*.exe",
          "?:\\Program Files (x86)\\*.exe",
          "?:\\Windows\\System32\\svchost.exe",
          "?:\\Windows\\SystemApps\\Microsoft.LockApp_*\\LockApp.exe",
          "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
          "?:\\Users\\*\\AppData\\Local\\BraveSoftware\\*\\Application\\brave.exe",
          "?:\\Users\\*\\AppData\\Local\\Vivaldi\\Application\\vivaldi.exe",
          "?:\\Users\\*\\AppData\\Local\\Programs\\Opera*\\opera.exe",
          "?:\\Users\\*\\AppData\\Local\\Programs\\Fiddler\\Fiddler.exe"
        ) and
    not (?process.code_signature.trusted == true and
         ?process.code_signature.subject_name : ("Anthropic, PBC", "Google LLC", "Mozilla Corporation", "Brave Software, Inc.", "Island Technology Inc.", "Opera Norway AS"))
```



### Execution of a Downloaded Windows Script

Branch count: 8448  
Document count: 16896  
Index: geneve-ut-0420  
Failure message(s):  
  got 1000 signals, expected 8448  

```python
sequence by host.id, user.id with maxspan=3m
[file where host.os.type == "windows" and event.action == "creation" and user.id != "S-1-5-18" and
  process.name : ("chrome.exe", "msedge.exe", "brave.exe", "browser.exe", "dragon.exe", "vivaldi.exe", "explorer.exe", "winrar.exe", "7zFM.exe", "7zG.exe", "Bandizip.exe") and
  file.extension in~ ("js", "jse", "vbs", "vbe", "wsh", "hta", "cmd", "bat") and
  (file.origin_url != null or file.origin_referrer_url != null)]
[process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : ("chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "browser.exe", "dragon.exe", "vivaldi.exe", "explorer.exe", "winrar.exe", "7zFM.exe", "7zG.exe", "Bandizip.exe") and 
 process.args_count >= 2 and
 (
  process.name in~ ("wscript.exe", "mshta.exe") or
  (process.name : "cmd.exe" and process.command_line : ("*.cmd*", "*.bat*"))
  )]
```



### File Creation, Execution and Self-Deletion in Suspicious Directory

Branch count: 4608  
Document count: 13824  
Index: geneve-ut-0446  
Failure message(s):  
  got 1000 signals, expected 4608  

```python
sequence by host.id, user.id with maxspan=1m
  [file where host.os.type == "linux" and event.action == "creation" and
   process.name in ("curl", "wget", "fetch", "ftp", "sftp", "scp", "rsync", "ld") and
   file.path : ("/dev/shm/*", "/run/shm/*", "/tmp/*", "/var/tmp/*",
     "/run/*", "/var/run/*", "/var/www/*", "/proc/*/fd/*")] by file.name
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
   not process.parent.executable like (
     "/tmp/VeeamApp*", "/tmp/rajh/spack-stage/*", "plz-out/bin/vault/bridge/test/e2e/base/bridge-dev",
     "/usr/bin/ranlib", "/usr/bin/ar", "plz-out/bin/vault/bridge/test/e2e/base/local-k8s"
   )] by process.name
  [file where host.os.type == "linux" and event.action == "deletion" and
   file.path : (
     "/dev/shm/*", "/run/shm/*", "/tmp/*", "/var/tmp/*", "/run/*", "/var/run/*", "/var/www/*", "/proc/*/fd/*"
    ) and not process.name in ("rm", "ld", "conftest", "link", "gcc", "getarch", "ld")] by file.name
```



### File Execution Permission Modification Detected via Defend for Containers

Branch count: 3626  
Document count: 3626  
Index: geneve-ut-0449  
Failure message(s):  
  got 1000 signals, expected 3626  

```python
file where host.os.type == "linux" and event.type in ("change", "creation") and (
  process.name == "chmod" or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod"
    ) and
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man"
    )
  )
) and process.args in ("4755", "755", "777", "0777", "444", "+x", "a+x") and
process.args like ("/dev/shm/*", "/tmp/*", "/var/tmp/*", "/run/*", "/var/run/*", "/mnt/*", "/media/*") and
process.interactive == true and container.id like "*" and not process.args == "-x"
```



### Git Hook Child Process

Branch count: 2300  
Document count: 2300  
Index: geneve-ut-0523  
Failure message(s):  
  got 1000 signals, expected 2300  

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.parent.name in (
  "applypatch-msg", "commit-msg", "fsmonitor-watchman", "post-update", "post-checkout", "post-commit",
  "pre-applypatch", "pre-commit", "pre-merge-commit", "prepare-commit-msg", "pre-push", "pre-rebase", "pre-receive",
  "push-to-checkout", "update", "post-receive", "pre-auto-gc", "post-rewrite", "sendemail-validate", "p4-pre-submit",
  "post-index-change", "post-merge", "post-applypatch"
) and
(
  process.name in ("nohup", "setsid", "disown", "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") or
  process.name like ("php*", "perl*", "ruby*", "lua*") or
  process.executable like (
    "/boot/*", "/dev/shm/*", "/etc/cron.*/*", "/etc/init.d/*", "/etc/update-motd.d/*",
    "/run/*", "/srv/*", "/tmp/*", "/var/tmp/*", "/var/log/*"
  )
) and
not process.name in ("git", "dirname")
```



### Multi-Base64 Decoding Attempt from Suspicious Location

Branch count: 2352  
Document count: 4704  
Index: geneve-ut-0786  
Failure message(s):  
  got 1000 signals, expected 2352  

```python
sequence by process.parent.entity_id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.executable != null and
   process.name in ("base64", "base64plain", "base64url", "base64mime", "base64pem", "base32", "base16") and
   // Only including potentially suspicious locations
   process.args like~ ("-d*", "--d*") and process.working_directory like (
     "/tmp/*", "/var/tmp*", "/dev/shm/*", "/var/www/*", "/home/*", "/root/*"
   ) and not (
     process.parent.executable in (
       "/usr/share/ec2-instance-connect/eic_curl_authorized_keys", "/etc/cron.daily/vivaldi",
       "/etc/cron.daily/opera-browser"
     ) or
     process.working_directory like (
       "/opt/microsoft/omsagent/plugin", "/opt/rapid7/ir_agent/*", "/tmp/newroot/*"
      ) or
      (process.parent.name == "zsh" and process.parent.command_line like "*extendedglob*")
   )]
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.executable != null and
   process.name in ("base64", "base64plain", "base64url", "base64mime", "base64pem", "base32", "base16") and
   process.args like~ ("-d*", "--d*")]
```



### Netcat File Transfer or Listener Detected via Defend for Containers

Branch count: 1110  
Document count: 1110  
Index: geneve-ut-0810  
Failure message(s):  
  got 1000 signals, expected 1110  

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name in ("nc","ncat","netcat","netcat.openbsd","netcat.traditional") or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "nc", "/bin/nc", "/usr/bin/nc", "/usr/local/bin/nc",
      "ncat", "/bin/ncat", "/usr/bin/ncat", "/usr/local/bin/ncat",
      "netcat", "/bin/netcat", "/usr/bin/netcat", "/usr/local/bin/netcat",
      "netcat.openbsd", "/bin/netcat.openbsd", "/usr/bin/netcat.openbsd", "/usr/local/bin/netcat.openbsd",
      "netcat.traditional", "/bin/netcat.traditional", "/usr/bin/netcat.traditional", "/usr/local/bin/netcat.traditional"
    ) and 
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.args like~ (
  /* bind shell to specific port or listener */
  "-*l*","-*p*",
  /* reverse shell to command-line interpreter used for command execution */
  "-*e*",
  /* file transfer via stdout/pipe */
  ">","<", "|"
) and process.interactive == true and container.id like "*"
```



### Pod or Container Creation with Suspicious Command-Line

Branch count: 8448  
Document count: 8448  
Index: geneve-ut-0895  
Failure message(s):  
  got 1000 signals, expected 8448  

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and (
  (process.name == "kubectl" and process.args == "run" and process.args == "--restart=Never" and process.args == "--") or
  (process.name in ("docker", "nerdctl", "ctl") and process.args == "run")
) and 
process.args in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
process.command_line like~ (
  "*atd*", "*cron*", "*/etc/rc.local*", "*/dev/tcp/*", "*/etc/init.d*", "*/etc/update-motd.d*", "*/etc/ld.so*", "*/etc/sudoers*", "*base64 *",
  "*/etc/profile*", "*/etc/ssh*", "*/home/*/.ssh/*", "*/root/.ssh*" , "*~/.ssh/*", "*autostart*", "*xxd *", "*/etc/shadow*", "*./.*",
  "*import*pty*spawn*", "*import*subprocess*call*", "*TCPSocket.new*", "*TCPSocket.open*", "*io.popen*", "*os.execute*", "*fsockopen*",
  "*disown*", "* ncat *", "* nc *", "* netcat *",  "* nc.traditional *", "*socat*", "*telnet*", "*/tmp/*", "*/dev/shm/*", "*/var/tmp/*",
  "*/boot/*", "*/sys/*", "*/lost+found/*", "*/media/*", "*/proc/*", "*/var/backups/*", "*/var/log/*", "*/var/mail/*", "*/var/spool/*"
)
```



### Potential Backdoor Execution Through PAM_EXEC

Branch count: 3600  
Document count: 7200  
Index: geneve-ut-0909  
Failure message(s):  
  got 1000 signals, expected 3600  

```python
sequence by process.entity_id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "change" and event.action == "session_id_change" and process.name in ("ssh", "sshd")]
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.name in ("ssh", "sshd") and
   process.args_count == 2 and process.args like (
     "sh", "dash", "bash", "zsh",
     "perl*", "python*", "php*", "ruby*", "lua*",

     "/bin/sh", "/bin/dash", "/bin/bash", "/bin/zsh",
     "/bin/perl*", "/bin/python*", "/bin/php*", "/bin/ruby*", "/bin/lua*",

     "/usr/bin/sh", "/usr/bin/dash", "/usr/bin/bash", "/usr/bin/zsh",
     "/usr/bin/perl*", "/usr/bin/python*", "/usr/bin/php*", "/usr/bin/ruby*", "/usr/bin/lua*",

     "/usr/local/bin/sh", "/usr/local/bin/dash", "/usr/local/bin/bash", "/usr/local/bin/zsh",
     "/usr/local/bin/perl*", "/usr/local/bin/python*", "/usr/local/bin/php*", "/usr/local/bin/ruby*", "/usr/local/bin/lua*"
   ) and (
     process.name like ".*" or
     process.executable like (
       "/tmp/*", "/var/tmp/*", "/dev/shm/*", "./*", "/boot/*", "/sys/*", "/lost+found/*", "/media/*", "/proc/*", "/bin/*", "/usr/bin/*",
       "/sbin/*", "/usr/sbin/*", "/lib/*", "/lib64/*", "/usr/lib/*", "/usr/lib64/*", "/opt/*", "/var/lib/*", "/run/*", "/var/backups/*",
       "/var/log/*", "/var/mail/*", "/var/spool/*"
     )
   )
  ]
```



### Potential Git CVE-2025-48384 Exploitation

Branch count: 2500  
Document count: 5000  
Index: geneve-ut-0963  
Failure message(s):  
  got 1000 signals, expected 2500  

```python
sequence by host.id with maxspan=1m
  [process where host.os.type in ("linux", "macos") and event.type == "start" and event.action in ("exec", "executed", "process_started", "start", "ProcessRollup2") and
   process.name == "git" and process.args == "clone" and process.args == "--recursive" and process.args like~ "http*"] by process.entity_id
  [process where host.os.type in ("linux", "macos") and event.type == "start" and event.action in ("exec", "executed", "process_started", "start", "ProcessRollup2") and
   process.name in (
    "dash", "sh", "static-sh", "bash", "bash-static", "zsh", "ash", "csh", "ksh", "tcsh", "busybox", "fish", "ksh93", "rksh",
    "rksh93", "lksh", "mksh", "mksh-static", "csharp", "posh", "rc", "sash", "yash", "zsh5", "zsh5-static"
   )] by process.parent.entity_id
```



### Potential Kubectl Masquerading via Unexpected Process

Branch count: 1085  
Document count: 1085  
Index: geneve-ut-0977  
Failure message(s):  
  got 1000 signals, expected 1085  

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "executed", "process_started") and
(
  process.executable like~ ("/tmp/*", "/var/tmp/*", "/dev/shm/*", "/root/*", "/var/www/*", "./kubectl") or
  process.name like ".*"
) and
process.args like~ (

  // get and describe commands
  "*get po*", "*get deploy*", "*get node*", "*get svc*", "*get service*", "*get secret*", "*get clusterrole*", "*get ingress*",
  "*get configmap*", "*describe po*", "*describe deploy*", "*describe node*", "*describe svc*", "*describe service*",
  "*describe secret*", "*describe configmap*", "*describe clusterrole*", "*describe ingress*",

  // exec commands
  "*exec -it*", "*exec --stdin*", "*exec --tty*",

  // networking commands
  "*port-forward* ", "*proxy --port*", "*run --image=*", "*expose*",

  // authentication/impersonation commands
  "*auth can-i*", "*--kubeconfig*", "*--as *", "*--as=*", "*--as-group*", "*--as-uid*"
) and not (
  process.executable like "/tmp/newroot/*" or
  process.name == ".flatpak-wrapped"
)
```



### Potential Linux Tunneling and/or Port Forwarding

Branch count: 1212  
Document count: 1212  
Index: geneve-ut-0989  
Failure message(s):  
  got 1000 signals, expected 1212  

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and (
  (
    // gost & pivotnacci - spawned without process.parent.name
    (process.name == "gost" and process.args : ("-L*", "-C*", "-R*")) or (process.name == "pivotnacci")) or (
    // ssh
    (process.name == "ssh" and (process.args in ("-R", "-L", "-D", "-w") and process.args_count >= 4 and 
     not (process.args == "chmod" or process.command_line like "*rungencmd*"))) or
    // sshuttle
    (process.name == "sshuttle" and process.args in ("-r", "--remote", "-l", "--listen") and process.args_count >= 4) or
    // socat
    (process.name == "socat" and process.args : ("TCP4-LISTEN:*", "SOCKS*") and process.args_count >= 3) or
    // chisel
    (process.name : "chisel*" and process.args in ("client", "server")) or
    // iodine(d), dnscat, hans, ptunnel-ng, ssf, 3proxy & ngrok 
    (process.name in ("iodine", "iodined", "dnscat", "hans", "hans-ubuntu", "ptunnel-ng", "ssf", "3proxy", "ngrok", "wstunnel"))
  ) and process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
)
```



### Potential Privilege Escalation via Enlightenment

Branch count: 6  
Document count: 12  
Index: geneve-ut-1045  
Failure message(s):  
  got 5 signals, expected 6  

```python
sequence by host.id, process.parent.entity_id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
    process.name == "enlightenment_sys" and process.args in ("/bin/mount/", "-o","noexec","nosuid","nodev","uid=*") ]
  [process where host.os.type == "linux" and event.action == "uid_change" and event.type == "change" and user.id == "0"]
```



### Potential Privilege Escalation via Service ImagePath Modification

Branch count: 1794  
Document count: 1794  
Index: geneve-ut-1053  
Failure message(s):  
  got 1000 signals, expected 1794  

```python
registry where host.os.type == "windows" and event.type == "change" and process.executable != null and
  registry.data.strings != null and registry.value == "ImagePath" and
  registry.key : (
    "*\\ADWS", "*\\AppHostSvc", "*\\AppReadiness", "*\\AudioEndpointBuilder", "*\\AxInstSV", "*\\camsvc", "*\\CertSvc",
    "*\\COMSysApp", "*\\CscService", "*\\defragsvc", "*\\DeviceAssociationService", "*\\DeviceInstall", "*\\DevQueryBroker",
    "*\\Dfs", "*\\DFSR", "*\\diagnosticshub.standardcollector.service", "*\\DiagTrack", "*\\DmEnrollmentSvc", "*\\DNS",
    "*\\dot3svc", "*\\Eaphost", "*\\GraphicsPerfSvc", "*\\hidserv", "*\\HvHost", "*\\IISADMIN", "*\\IKEEXT",
    "*\\InstallService", "*\\iphlpsvc", "*\\IsmServ", "*\\LanmanServer", "*\\MSiSCSI", "*\\NcbService", "*\\Netlogon",
    "*\\Netman", "*\\NtFrs", "*\\PlugPlay", "*\\Power", "*\\PrintNotify", "*\\ProfSvc", "*\\PushToInstall", "*\\RSoPProv",
    "*\\sacsvr", "*\\SENS", "*\\SensorDataService", "*\\SgrmBroker", "*\\ShellHWDetection", "*\\shpamsvc", "*\\StorSvc",
    "*\\svsvc", "*\\swprv", "*\\SysMain", "*\\Themes", "*\\TieringEngineService", "*\\TokenBroker", "*\\TrkWks",
    "*\\UALSVC", "*\\UserManager", "*\\vm3dservice", "*\\vmicguestinterface", "*\\vmicheartbeat", "*\\vmickvpexchange",
    "*\\vmicrdv", "*\\vmicshutdown", "*\\vmicvmsession", "*\\vmicvss", "*\\vmvss", "*\\VSS", "*\\w3logsvc", "*\\W3SVC",
    "*\\WalletService", "*\\WAS", "*\\wercplsupport", "*\\WerSvc", "*\\Winmgmt", "*\\wisvc", "*\\wmiApSrv",
    "*\\WPDBusEnum", "*\\WSearch"
  ) and
  not (
    registry.data.strings : (
        "?:\\Windows\\system32\\*.exe",
        "%systemroot%\\system32\\*.exe",
        "%windir%\\system32\\*.exe",
        "%SystemRoot%\\system32\\svchost.exe -k *",
        "%windir%\\system32\\svchost.exe -k *"
    ) and
        not registry.data.strings : (
            "*\\cmd.exe",
            "*\\cscript.exe",
            "*\\ieexec.exe",
            "*\\iexpress.exe",
            "*\\installutil.exe",
            "*\\Microsoft.Workflow.Compiler.exe",
            "*\\msbuild.exe",
            "*\\mshta.exe",
            "*\\msiexec.exe",
            "*\\msxsl.exe",
            "*\\net.exe",
            "*\\powershell.exe",
            "*\\pwsh.exe",
            "*\\reg.exe",
            "*\\RegAsm.exe",
            "*\\RegSvcs.exe",
            "*\\regsvr32.exe",
            "*\\rundll32.exe",
            "*\\vssadmin.exe",
            "*\\wbadmin.exe",
            "*\\wmic.exe",
            "*\\wscript.exe"
        )
  )
```



### Privilege Escalation via CAP_CHOWN/CAP_FOWNER Capabilities

Branch count: 32  
Document count: 64  
Index: geneve-ut-1145  
Failure message(s):  
  got 24 signals, expected 32  

```python
sequence by host.id, process.pid with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name != null and process.thread.capabilities.effective : ("CAP_CHOWN", "CAP_FOWNER") and
   process.command_line : ("*sudoers*", "*passwd*", "*shadow*", "*/root/*") and user.id != "0"]
  [file where host.os.type == "linux" and event.action == "changed-file-ownership-of" and event.type == "change" and
   event.outcome == "success" and file.path in (
     "/etc/passwd",
     "/etc/shadow",
     "/etc/sudoers",
     "/root/.ssh/*"
   ) and user.id != "0"
  ]
```



### Sensitive File Compression Detected via Defend for Containers

Branch count: 8880  
Document count: 8880  
Index: geneve-ut-1260  
Failure message(s):  
  got 1000 signals, expected 8880  

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name in ("zip", "tar", "gzip", "hdiutil", "7z", "rar", "7zip", "p7zip") or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "zip", "/bin/zip", "/usr/bin/zip", "/usr/local/bin/zip",
      "tar", "/bin/tar", "/usr/bin/tar", "/usr/local/bin/tar",
      "gzip", "/bin/gzip", "/usr/bin/gzip", "/usr/local/bin/gzip",
      "hdiutil", "/bin/hdiutil", "/usr/bin/hdiutil", "/usr/local/bin/hdiutil",
      "7z", "/bin/7z", "/usr/bin/7z", "/usr/local/bin/7z",
      "rar", "/bin/rar", "/usr/bin/rar", "/usr/local/bin/rar",
      "7zip", "/bin/7zip", "/usr/bin/7zip", "/usr/local/bin/7zip",
      "p7zip", "/bin/p7zip", "/usr/bin/p7zip", "/usr/local/bin/p7zip"
    ) and 
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.args like~ (
  "*/root/.ssh/*", "*/home/*/.ssh/*", "*/root/.bash_history*", "*/etc/hosts*", "*/root/.aws/*", "*/home/*/.aws/*",
  "*/root/.docker/*", "*/home/*/.docker/*", "*/etc/group*", "*/etc/passwd*", "*/etc/shadow*", "*/etc/gshadow*",
  "*/.azure/*", "*/var/run/secrets/azure/*", "*/.config/gcloud/*", "*application_default_credentials.json*",
  "*type: service_account*", "*client_email*", "*private_key_id*", "*private_key*", "*/var/run/secrets/google/*",
  "*GOOGLE_APPLICATION_CREDENTIALS*", "*AZURE_CLIENT_ID*", "*AZURE_TENANT_ID*", "*AZURE_CLIENT_SECRET*",
  "*AZURE_FEDERATED_TOKEN_FILE*", "*IDENTITY_ENDPOINT*", "*IDENTITY_HEADER*", "*MSI_ENDPOINT*", "*MSI_SECRET*"
) and process.interactive == true and container.id like "*"
```



### Sensitive Keys Or Passwords Search Detected via Defend for Containers

Branch count: 2997  
Document count: 2997  
Index: geneve-ut-1263  
Failure message(s):  
  got 1000 signals, expected 2997  

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name in ("grep", "egrep", "fgrep", "find", "locate", "mlocate", "cat", "sed", "awk") or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "grep", "/bin/grep", "/usr/bin/grep", "/usr/local/bin/grep",
      "egrep", "/bin/egrep", "/usr/bin/egrep", "/usr/local/bin/egrep",
      "fgrep", "/bin/fgrep", "/usr/bin/fgrep", "/usr/local/bin/fgrep",
      "find", "/bin/find", "/usr/bin/find", "/usr/local/bin/find",
      "locate", "/bin/locate", "/usr/bin/locate", "/usr/local/bin/locate",
      "mlocate", "/bin/mlocate", "/usr/bin/mlocate", "/usr/local/bin/mlocate",
      "cat", "/bin/cat", "/usr/bin/cat", "/usr/local/bin/cat",
      "sed", "/bin/sed", "/usr/bin/sed", "/usr/local/bin/sed",
      "awk", "/bin/awk", "/usr/bin/awk", "/usr/local/bin/awk"
    ) and 
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.args like~ (
  "*BEGIN PRIVATE*", "*BEGIN OPENSSH PRIVATE*", "*BEGIN RSA PRIVATE*", "*BEGIN DSA PRIVATE*", "*BEGIN EC PRIVATE*",
  "*password*", "*ssh*", "*id_rsa*", "*id_dsa*"
) and process.interactive == true and container.id like "*"
```



### Suspicious APT Package Manager Execution

Branch count: 1368  
Document count: 2736  
Index: geneve-ut-1338  
Failure message(s):  
  got 1000 signals, expected 1368  

```python
sequence by host.id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "ProcessRollup2") and
   process.parent.name == "apt" and process.args == "-c" and process.name in (
     "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish"
   ) and not process.executable == "/usr/lib/venv-salt-minion/bin/python.original"
  ] by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "ProcessRollup2") and process.name like (
     "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "python*", "php*",
     "perl", "ruby", "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk"
   ) and not (
     ?process.parent.executable like (
       "/run/k3s/containerd*", "/tmp/newroot/*", "/usr/share/debconf/frontend", "/var/tmp/buildah*", "./merged/*",
       "./*/vz/root/*", "/usr/bin/adequate" 
      ) or
     process.executable like ("/usr/lib/venv-salt-minion/bin/python.original", "./merged/var/lib/containers/*") or
     process.command_line in (
       "python3 /usr/sbin/omv-mkaptidx", "python3 /usr/local/bin/abr-upgrade --upgrade",
       "sh -c apt-get indextargets -o Dir::State::lists=/var/lib/apt/lists/ --format='$(FILENAME)' 'Created-By: Packages'",
       "/usr/bin/perl /usr/sbin/dpkg-preconfigure --apt", "/bin/sh -e /usr/lib/update-notifier/update-motd-updates-available",
       "/usr/bin/python3 /usr/lib/cnf-update-db", "/usr/bin/python3 /usr/bin/apt-listchanges --apt",
       "/usr/bin/perl -w /usr/sbin/dpkg-preconfigure --apt", "/bin/sh /usr/lib/needrestart/apt-pinvoke",
       "/bin/sh /usr/bin/kali-check-apt-sources", "/bin/sh /usr/lib/needrestart/apt-pinvoke -m u",
       "/usr/bin/perl /usr/sbin/needrestart",  "/usr/bin/perl -w /usr/bin/apt-show-versions -i",
       "/usr/bin/perl -w /usr/bin/apt-show-versions -i", "/usr/bin/perl -w /bin/apt-show-versions -i",
       "/usr/bin/perl /bin/adequate --help",  "/usr/bin/perl /usr/sbin/needrestart -m u", 
       "/usr/bin/perl -w /usr/share/debconf/frontend /usr/sbin/needrestart",
       "/usr/bin/python3 /sbin/katello-tracer-upload",
       "/usr/bin/python3 /usr/bin/package-profile-upload"
     ) or
     ?process.parent.command_line like ("sh -c if [ -x*", "sh -c -- if [ -x*") or
     process.args in ("/usr/sbin/needrestart", "/usr/lib/needrestart/apt-pinvoke", "/usr/share/proxmox-ve/pve-apt-hook", "/usr/bin/dpkg-source") or
     ?process.parent.args == "/usr/share/debconf/frontend"
    )
  ] by process.parent.entity_id
```



### Suspicious Execution via Scheduled Task

Branch count: 6144  
Document count: 6144  
Index: geneve-ut-1369  
Failure message(s):  
  got 1000 signals, expected 6144  

```python
process where host.os.type == "windows" and event.type == "start" and
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
       "C:\\HP\\*") and

    not (process.name : "cmd.exe" and process.args : ("*.bat", "*.cmd")) and
    not (process.name : "cscript.exe" and process.args : "?:\\Windows\\system32\\calluxxprovider.vbs") and
    not (
       process.name : "powershell.exe" and
       process.args : (
           "-File", "-PSConsoleFile",
           "C:\\ProgramData\\Microsoft\\AutopatchSetupScheduled\\SetupAutopatchClientV2Package.ps1",
           "C:\\ProgramData\\Microsoft\\AutopatchSetupScheduled\\SetupAutopatchClientPackage.ps1",
           "C:\\Windows\\Temp\\MSS\\MDESetup\\Invoke-MDESetup.ps1"
       ) and user.id : "S-1-5-18"
    ) and
    not (process.name : "msiexec.exe" and user.id : "S-1-5-18") and
    not (process.name : "powershell.exe" and
         process.command_line : ("C:\\ProgramData\\ElasticAgent-HealthCheck.ps1",
                                 "C:\\ProgramData\\ssh\\puttysetup.ps1"))
```



### Suspicious File Creation via Pkg Install Script

Branch count: 4032  
Document count: 8064  
Index: geneve-ut-1374  
Failure message(s):  
  got 1000 signals, expected 4032  

```python
sequence by process.entity_id with maxspan=30s
  [process where host.os.type == "macos" and event.type == "start" and process.name in ("bash", "sh", "zsh") and
    process.args like~ ("/tmp/PKInstallSandbox.*/Scripts/com.*/preinstall", 
                        "/tmp/PKInstallSandbox.*/Scripts/*/postinstall") and
    process.args like ("/Users/*", "/Volumes/*") and 
    not process.args like~ "/Users/*/Library/Caches/*"]
  [file where host.os.type == "macos" and event.action != "deletion" and process.name in ("mv", "cp") and
    (file.extension in ("py", "js", "sh", "scpt", "terminal", "tcl", "app", "pkg", "dmg", "command") or
      file.Ext.header_bytes like~ ("cffaedfe*", "cafebabe*")) and
    file.path like ("/private/etc/*", "/var/tmp/*", "/tmp/*", "/var/folders/*", "/Users/Shared/*",
                    "/Library/Graphics/*", "/Library/Containers/*", "/Users/*/Library/Containers/*", 
                    "/Users/*/Library/Services/*", "/Users/*/Library/Preferences/*", "/var/root/*",
                    "/Library/WebServer/*", "/Library/Fonts/*", "/usr/local/bin/*") and 
    not file.name == "CodeResources"]
```



### System Public IP Discovery via DNS Query

Branch count: 1053  
Document count: 1053  
Index: geneve-ut-1470  
Failure message(s):  
  got 1000 signals, expected 1053  

```python
network where host.os.type == "windows" and dns.question.name != null and process.name != null and
(
  process.name : ("MSBuild.exe", "mshta.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "rundll32.exe",
  "bitsadmin.exe", "InstallUtil.exe", "RegAsm.exe", "vbc.exe", "RegSvcs.exe", "python.exe", "regsvr32.exe", "dllhost.exe",
  "node.exe", "javaw.exe", "java.exe", "*.pif", "*.com") or

  (?process.code_signature.trusted == false or ?process.code_signature.exists == false) or

  ?process.code_signature.subject_name : ("AutoIt Consulting Ltd", "OpenJS Foundation", "Python Software Foundation") or

  ?process.executable : ("?:\\Users\\*.exe", "?:\\ProgramData\\*.exe")
 ) and
 dns.question.name :
         (
          "ip-api.com",
          "checkip.dyndns.org",
          "api.ipify.org",
          "api.ipify.com",
          "whatismyip.akamai.com",
          "bot.whatismyipaddress.com",
          "ifcfg.me",
          "ident.me",
          "ipof.in",
          "ip.tyk.nu",
          "icanhazip.com",
          "curlmyip.com",
          "wgetip.com",
          "eth0.me",
          "ipecho.net",
          "ip.appspot.com",
          "api.myip.com",
          "geoiptool.com",
          "api.2ip.ua",
          "api.ip.sb",
          "ipinfo.io",
          "checkip.amazonaws.com",
          "wtfismyip.com",
          "iplogger.*",
          "freegeoip.net",
          "freegeoip.app",
          "ipinfo.io",
          "geoplugin.net",
          "myip.dnsomatic.com",
          "www.geoplugin.net",
          "api64.ipify.org",
          "ip4.seeip.org",
          "*.geojs.io",
          "*portmap.io",
          "api.2ip.ua",
          "api.db-ip.com",
          "geolocation-db.com",
          "httpbin.org",
          "myip.opendns.com"
         )
```



### Tool Enumeration Detected via Defend for Containers

Branch count: 2035  
Document count: 2035  
Index: geneve-ut-1497  
Failure message(s):  
  got 1000 signals, expected 2035  

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name == "which" or
  (
    /* Account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in ("which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which") and
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.args in (

  /* TCP IP */
  "curl", "wget", "socat", "nc", "netcat", "ncat", "busybox", "python3", "python", "perl", "node", "openssl", "ruby", "lua",

  /* networking */
  "getent", "dig", "nslookup", "host", "ip", "tcpdump", "tshark",

  /* container management */
  "kubectl", "docker", "kubelet", "kube-proxy", "containerd", "systemd", "crictl",

  /* compilation */
  "gcc", "g++", "clang", "clang++", "cc", "c++", "c99", "c89", "cc1*", "musl-gcc", "musl-clang", "tcc", "zig", "ccache", "distcc", "make",

  /* scanning */
  "nmap", "zenmap", "nuclei", "netdiscover", "legion", "masscan", "zmap", "zgrab", "ngrep", "telnet", "mitmproxy", "zmap",
  "masscan", "zgrab"
) and
process.interactive == true and container.id like "*"
```



### Web Server Child Shell Spawn Detected via Defend for Containers

Branch count: 2070  
Document count: 2070  
Index: geneve-ut-1655  
Failure message(s):  
  got 1000 signals, expected 2070  

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.parent.name in (
      "apache", "nginx", "apache2", "httpd", "lighttpd", "caddy", "mongrel_rails", "gunicorn",
      "uwsgi", "openresty", "cherokee", "h2o", "resin", "puma", "unicorn", "traefik", "tornado", "hypercorn",
      "daphne", "twistd", "yaws", "webfsd", "httpd.worker", "flask", "rails", "mongrel", "php-cgi",
      "php-fcgi", "php-cgi.cagefs", "catalina.sh", "hiawatha", "lswsctrl"
  ) or
  process.parent.name like "php-fpm*" or
  user.name in ("apache", "www-data", "httpd", "nginx", "lighttpd", "tomcat", "tomcat8", "tomcat9") or
  user.id in ("33", "498", "48") or
  (process.parent.name == "java" and process.parent.working_directory like "/u0?/*") or
  process.parent.working_directory like "/var/www/*"
) and (
  (process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox")) or
  (process.args in (
    "bash", "/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash",
    "dash", "/bin/dash", "/usr/bin/dash", "/usr/local/bin/dash",
    "sh", "/bin/sh", "/usr/bin/sh", "/usr/local/bin/sh",
    "tcsh", "/bin/tcsh", "/usr/bin/tcsh", "/usr/local/bin/tcsh",
    "csh", "/bin/csh", "/usr/bin/csh", "/usr/local/bin/csh",
    "zsh", "/bin/zsh", "/usr/bin/zsh", "/usr/local/bin/zsh",
    "ksh", "/bin/ksh", "/usr/bin/ksh", "/usr/local/bin/ksh",
    "fish", "/bin/fish", "/usr/bin/fish", "/usr/local/bin/fish",
    "busybox", "/bin/busybox", "/usr/bin/busybox", "/usr/local/bin/busybox"
  ))
) and process.args == "-c" and container.id like "?*"
```



## Rules with the correct signals (980)

### A scheduled task was created

Branch count: 1  
Document count: 1  
Index: geneve-ut-0000

```python
iam where host.os.type == "windows" and event.action == "scheduled-task-created" and

 /* excluding tasks created by the computer account */
 not user.name : "*$" and

 /* TaskContent is not parsed, exclude by full taskname noisy ones */
 not winlog.event_data.TaskName : (
              "\\CreateExplorerShellUnelevatedTask",
              "\\Hewlett-Packard\\HPDeviceCheck",
              "\\Hewlett-Packard\\HP Support Assistant\\WarrantyChecker",
              "\\Hewlett-Packard\\HP Support Assistant\\WarrantyChecker_backup",
              "\\Hewlett-Packard\\HP Web Products Detection",
              "\\Microsoft\\VisualStudio\\Updates\\BackgroundDownload",
              "\\OneDrive Standalone Update Task-S-1-5-21*",
              "\\OneDrive Standalone Update Task-S-1-12-1-*"
 )
```



### APT Package Manager Configuration File Creation

Branch count: 8  
Document count: 8  
Index: geneve-ut-0001

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and
file.path : "/etc/apt/apt.conf.d/*" and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/libexec/netplan/generate",
    "/usr/local/bin/apt-get", "/usr/bin/apt-get", "./usr/bin/podman", "/usr/bin/buildah", "/.envbuilder/bin/envbuilder",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/bin/pvedaemon", "/usr/bin/percona-release", "/usr/bin/crio"
  ) or
  file.path :("/etc/apt/apt.conf.d/*.tmp*") or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove", "dpkg-new") or
  file.Ext.original.extension == "dpkg-new" or
  file.Ext.original.name == ".source" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/*", "/usr/libexec/*",
    "/etc/kernel/*", "/opt/saltstack/salt/bin/python*"
  ) or
  process.executable == null or
  process.name in ("pveupdate", "perl", "executor", "crio", "docker-init", "dockerd", "pvedaemon") or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") or
  /* adding known file paths to reduce false positives */
  file.path in (
    "/etc/apt/apt.conf.d/50unattended-upgrades",
    "/etc/apt/apt.conf.d/02autoremove-postgresql",
    "/etc/apt/apt.conf.d/99rain-noautoupgrades",
    "/etc/apt/apt.conf.d/99no-check-valid-until",
    "/etc/apt/apt.conf.d/50isar-apt",
    "/etc/apt/apt.conf.d/99gitlab-ci-cache",
    "/etc/apt/apt.conf.d/50unattended-upgrades.ucf-dist",
    "/etc/apt/apt.conf.d/01autoremove-kernels",
    "/etc/apt/apt.conf.d/01autoremove",
    "/etc/apt/apt.conf.d/95proxies",
    "/etc/apt/apt.conf.d/99-noninteractive"
  )
)
```



### AWS CloudTrail Log Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-0010

```python
event.dataset: "aws.cloudtrail" 
    and event.provider: "cloudtrail.amazonaws.com" 
    and event.action: "CreateTrail" 
    and event.outcome: "success"
```



### AWS CloudTrail Log Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-0011

```python
event.dataset: "aws.cloudtrail"
    and event.provider: "cloudtrail.amazonaws.com"
    and event.action: "DeleteTrail"
    and event.outcome: "success"
```



### AWS CloudTrail Log Evasion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0012

```python
event.dataset: aws.cloudtrail and event.provider: iam.amazonaws.com and aws.cloudtrail.flattened.request_parameters.reason: "requestParameters too large" and aws.cloudtrail.flattened.request_parameters.omitted : true and event.outcome: success
```



### AWS CloudTrail Log Suspended

Branch count: 1  
Document count: 1  
Index: geneve-ut-0013

```python
event.dataset: "aws.cloudtrail" 
    and event.provider: "cloudtrail.amazonaws.com" 
    and event.action: "StopLogging" 
    and event.outcome: "success"
```



### AWS CloudTrail Log Updated

Branch count: 1  
Document count: 1  
Index: geneve-ut-0014

```python
event.dataset: "aws.cloudtrail" 
    and event.provider: "cloudtrail.amazonaws.com" 
    and event.action: "UpdateTrail" 
    and event.outcome: "success"
```



### AWS CloudWatch Alarm Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0015

```python
event.dataset: "aws.cloudtrail" 
  and event.provider: "monitoring.amazonaws.com" 
  and event.action: "DeleteAlarms"
  and event.outcome: "success"
  and source.ip: *
  and not user_agent.original : "AWS Internal"
```



### AWS CloudWatch Log Group Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0016

```python
event.dataset: "aws.cloudtrail" 
  and event.provider: "logs.amazonaws.com" 
  and event.action: "DeleteLogGroup" 
  and event.outcome: "success"
  and source.ip: * 
  and not user_agent.original : "AWS Internal"
```



### AWS CloudWatch Log Stream Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0017

```python
event.dataset: "aws.cloudtrail" 
  and event.provider: "logs.amazonaws.com" 
  and event.action: "DeleteLogStream" 
  and event.outcome: "success"
  and source.ip: * 
  and not user_agent.original : "AWS Internal"
```



### AWS Config Resource Deletion

Branch count: 9  
Document count: 9  
Index: geneve-ut-0018

```python
event.dataset: aws.cloudtrail 
    and event.provider: config.amazonaws.com 
    and event.outcome: success
    and event.action: (DeleteConfigRule or DeleteOrganizationConfigRule or DeleteConfigurationAggregator or
    DeleteConfigurationRecorder or DeleteConformancePack or DeleteOrganizationConformancePack or
    DeleteDeliveryChannel or DeleteRemediationConfiguration or DeleteRetentionConfiguration)
    and not aws.cloudtrail.user_identity.invoked_by: (securityhub.amazonaws.com or fms.amazonaws.com or controltower.amazonaws.com or config-conforms.amazonaws.com)
```



### AWS Configuration Recorder Stopped

Branch count: 1  
Document count: 1  
Index: geneve-ut-0019

```python
event.dataset: aws.cloudtrail 
    and event.provider: config.amazonaws.com 
    and event.action: StopConfigurationRecorder 
    and event.outcome: success
```



### AWS Credentials Searched For Inside A Container

Branch count: 63  
Document count: 63  
Index: geneve-ut-0020

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.entry_leader.entry_meta.type == "container" and
process.name in ("grep", "egrep", "fgrep", "find", "locate", "mlocate", "cat", "sed", "awk") and
process.command_line like~ (
  "*aws_access_key_id*", "*aws_secret_access_key*", "*aws_session_token*", "*accesskeyid*", "*secretaccesskey*",
  "*access_key*", "*.aws/credentials*"
)
```



### AWS EC2 AMI Shared with Another Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-0024

```python
event.dataset: "aws.cloudtrail" and event.provider: "ec2.amazonaws.com"
    and event.action: ModifyImageAttribute and event.outcome: success
    and aws.cloudtrail.request_parameters: *add=*
    and not aws.cloudtrail.user_identity.invoked_by: "assets.marketplace.amazonaws.com"
```



### AWS EC2 Deprecated AMI Discovery

Branch count: 1  
Document count: 1  
Index: geneve-ut-0025

```python
event.dataset: "aws.cloudtrail"
    and event.provider: "ec2.amazonaws.com"
    and event.action: "DescribeImages"
    and event.outcome: "success"
    and aws.cloudtrail.flattened.request_parameters.includeDeprecated: "true"
```



### AWS EC2 Encryption Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-0028

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:DisableEbsEncryptionByDefault and event.outcome:success
```



### AWS EC2 Export Task

Branch count: 3  
Document count: 3  
Index: geneve-ut-0029

```python
event.dataset: "aws.cloudtrail" and 
    event.provider: "ec2.amazonaws.com" and 
    event.action: ("CreateInstanceExportTask" or "ExportImage" or "CreateStoreImageTask") and 
    event.outcome: "success"
```



### AWS EC2 Full Network Packet Capture Detected

Branch count: 1  
Document count: 1  
Index: geneve-ut-0030

```python
event.dataset: "aws.cloudtrail" and 
    event.provider: "ec2.amazonaws.com" and
    event.action: "CreateTrafficMirrorSession" and
    event.outcome: "success"
```



### AWS EC2 Instance Connect SSH Public Key Uploaded

Branch count: 2  
Document count: 2  
Index: geneve-ut-0031

```python
event.dataset: aws.cloudtrail
    and event.provider: ec2-instance-connect.amazonaws.com
    and event.action: (SendSSHPublicKey or SendSerialConsoleSSHPublicKey)
    and event.outcome: success
```



### AWS EC2 Network Access Control List Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-0036

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(CreateNetworkAcl or CreateNetworkAclEntry) and event.outcome:success
```



### AWS EC2 Network Access Control List Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-0037

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(DeleteNetworkAcl or DeleteNetworkAclEntry) and event.outcome:success
```



### AWS EC2 Security Group Configuration Change

Branch count: 7  
Document count: 7  
Index: geneve-ut-0040

```python
event.dataset: "aws.cloudtrail"
    and event.provider: "ec2.amazonaws.com"  and event.outcome: "success"
    and (event.action:(
            "AuthorizeSecurityGroupIngress" or
            "AuthorizeSecurityGroupEgress" or
            "CreateSecurityGroup" or
            "ModifySecurityGroupRules" or
            "RevokeSecurityGroupEgress" or
            "RevokeSecurityGroupIngress") or 
            (event.action: "ModifyInstanceAttribute" and aws.cloudtrail.flattened.request_parameters.groupSet.items.groupId:*))
```



### AWS EC2 Serial Console Access Enabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-0041

```python
event.dataset: "aws.cloudtrail"
    and event.provider: "ec2.amazonaws.com"
    and event.action: "EnableSerialConsoleAccess"
    and event.outcome: "success"
```



### AWS EFS File System Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-0044

```python
event.dataset: "aws.cloudtrail" 
    and event.provider: "elasticfilesystem.amazonaws.com" 
    and event.action: "DeleteFileSystem" 
    and event.outcome: "success"
```



### AWS EventBridge Rule Disabled or Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-0045

```python
event.dataset: aws.cloudtrail 
    and event.provider: events.amazonaws.com 
    and event.action: (DeleteRule or DisableRule) 
    and event.outcome: success
```



### AWS GuardDuty Detector Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0047

```python
event.dataset: aws.cloudtrail 
  and event.provider: guardduty.amazonaws.com 
  and event.action: DeleteDetector 
  and event.outcome: success
```



### AWS IAM Deactivation of MFA Device

Branch count: 1  
Document count: 1  
Index: geneve-ut-0056

```python
event.dataset: aws.cloudtrail 
    and event.provider: iam.amazonaws.com 
    and event.action: DeactivateMFADevice 
    and event.outcome: success
```



### AWS IAM Group Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-0057

```python
event.dataset: aws.cloudtrail and 
    event.provider: iam.amazonaws.com and 
    event.action: CreateGroup and 
    event.outcome: success
```



### AWS IAM Group Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0058

```python
event.dataset: aws.cloudtrail and 
    event.provider: iam.amazonaws.com and 
    event.action: DeleteGroup and 
    event.outcome: success
```



### AWS IAM Login Profile Added to User

Branch count: 1  
Document count: 1  
Index: geneve-ut-0060

```python
event.dataset: aws.cloudtrail and event.provider: "iam.amazonaws.com"
    and event.action: "CreateLoginProfile" and event.outcome: success
```



### AWS IAM Roles Anywhere Profile Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-0062

```python
event.dataset: aws.cloudtrail
    and event.provider: rolesanywhere.amazonaws.com
    and event.action: CreateProfile
    and event.outcome: success
```



### AWS IAM SAML Provider Updated

Branch count: 2  
Document count: 2  
Index: geneve-ut-0064

```python
event.dataset: "aws.cloudtrail"
    and event.provider: "iam.amazonaws.com"
    and event.action: "UpdateSAMLProvider"
    and event.outcome: "success"
    and not (source.address: "sso.amazonaws.com" and user_agent.original: "sso.amazonaws.com")
```



### AWS IAM User Addition to Group

Branch count: 1  
Document count: 1  
Index: geneve-ut-0065

```python
event.dataset: aws.cloudtrail and 
    event.provider: iam.amazonaws.com and 
    event.action: AddUserToGroup and 
    event.outcome: success
```



### AWS KMS Customer Managed Key Disabled or Scheduled for Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-0068

```python
event.dataset: "aws.cloudtrail"
    and event.provider: "kms.amazonaws.com" 
    and event.action: ("DisableKey" or "ScheduleKeyDeletion") 
    and event.outcome: "success"
```



### AWS Lambda Function Created or Updated

Branch count: 2  
Document count: 2  
Index: geneve-ut-0069

```python
event.dataset: "aws.cloudtrail"
    and event.provider: "lambda.amazonaws.com"
    and event.outcome: "success"
    and event.action: (CreateFunction* or UpdateFunctionCode*)
```



### AWS Lambda Layer Added to Existing Function

Branch count: 2  
Document count: 2  
Index: geneve-ut-0071

```python
event.dataset: aws.cloudtrail
    and event.provider: lambda.amazonaws.com
    and event.outcome: success
    and event.action: (PublishLayerVersion* or UpdateFunctionConfiguration*)
```



### AWS Management Console Root Login

Branch count: 1  
Document count: 1  
Index: geneve-ut-0073

```python
event.dataset:aws.cloudtrail and 
event.provider:signin.amazonaws.com and 
event.action:ConsoleLogin and 
aws.cloudtrail.user_identity.type:Root and 
event.outcome:success
```



### AWS RDS DB Instance Restored

Branch count: 2  
Document count: 2  
Index: geneve-ut-0075

```python
event.dataset: "aws.cloudtrail"
    and event.provider: "rds.amazonaws.com"
    and event.action: ("RestoreDBInstanceFromDBSnapshot" or "RestoreDBInstanceFromS3")
    and event.outcome: "success"
```



### AWS RDS DB Instance or Cluster Deleted

Branch count: 3  
Document count: 3  
Index: geneve-ut-0076

```python
event.dataset: aws.cloudtrail 
    and event.provider: rds.amazonaws.com 
    and event.action: (DeleteDBCluster or DeleteGlobalCluster or DeleteDBInstance)
    and event.outcome: success
```



### AWS RDS DB Snapshot Created

Branch count: 2  
Document count: 2  
Index: geneve-ut-0079

```python
event.dataset: "aws.cloudtrail" and event.provider: "rds.amazonaws.com" 
    and event.action: ("CreateDBSnapshot" or "CreateDBClusterSnapshot") and event.outcome: "success"
```



### AWS RDS Snapshot Export

Branch count: 1  
Document count: 1  
Index: geneve-ut-0082

```python
event.dataset: aws.cloudtrail 
    and event.provider: rds.amazonaws.com 
    and event.action: StartExportTask 
    and event.outcome: success
```



### AWS Route 53 Domain Transfer Lock Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-0083

```python
event.dataset: aws.cloudtrail 
    and event.provider: route53domains.amazonaws.com 
    and event.action: DisableDomainTransferLock 
    and event.outcome: success
```



### AWS Route 53 Domain Transferred to Another Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-0084

```python
event.dataset: aws.cloudtrail 
    and event.provider: route53domains.amazonaws.com 
    and event.action: TransferDomainToAnotherAwsAccount 
    and event.outcome: success
```



### AWS Route 53 Private Hosted Zone Associated With a VPC

Branch count: 1  
Document count: 1  
Index: geneve-ut-0085

```python
event.dataset: aws.cloudtrail 
    and event.provider: route53.amazonaws.com 
    and event.action: AssociateVPCWithHostedZone 
    and event.outcome: success
```



### AWS Route 53 Resolver Query Log Configuration Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-0086

```python
event.dataset: aws.cloudtrail 
    and event.provider: route53resolver.amazonaws.com
    and event.action: DeleteResolverQueryLogConfig 
    and event.outcome: success
```



### AWS S3 Bucket Configuration Deletion

Branch count: 5  
Document count: 5  
Index: geneve-ut-0087

```python
event.dataset:aws.cloudtrail and 
    event.provider:s3.amazonaws.com and
    event.action:(DeleteBucketPolicy or 
                    DeleteBucketReplication or 
                    DeleteBucketCors or 
                    DeleteBucketEncryption or 
                    DeleteBucketLifecycle) and 
    event.outcome:success
```



### AWS SQS Queue Purge

Branch count: 1  
Document count: 1  
Index: geneve-ut-0101

```python
event.dataset: "aws.cloudtrail"
    and event.provider: "sqs.amazonaws.com"
    and event.action: "PurgeQueue"
    and event.outcome: "success"
```



### AWS STS GetSessionToken Usage

Branch count: 1  
Document count: 1  
Index: geneve-ut-0109

```python
event.dataset: aws.cloudtrail 
  and event.provider: sts.amazonaws.com 
  and event.action: GetSessionToken 
  and event.outcome: success
```



### AWS Sign-In Console Login with Federated User

Branch count: 1  
Document count: 1  
Index: geneve-ut-0115

```python
event.dataset: "aws.cloudtrail" and 
    event.provider: "signin.amazonaws.com" and 
    event.action : "ConsoleLogin" and 
    aws.cloudtrail.user_identity.type: "FederatedUser" and
    event.outcome: "success"
```



### AWS Sign-In Root Password Recovery Requested

Branch count: 1  
Document count: 1  
Index: geneve-ut-0116

```python
event.dataset:aws.cloudtrail and 
event.provider:signin.amazonaws.com and 
event.action:PasswordRecoveryRequested and 
event.outcome:success
```



### AWS Sign-In Token Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-0117

```python
event.dataset: "aws.cloudtrail" and 
    event.provider: "signin.amazonaws.com" and 
    event.action : "GetSigninToken" and 
    event.outcome: "success"
```



### AWS VPC Flow Logs Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0119

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:DeleteFlowLogs and event.outcome:success
```



### AWS WAF Access Control List Deletion

Branch count: 3  
Document count: 3  
Index: geneve-ut-0120

```python
event.dataset: aws.cloudtrail 
    and event.provider: (waf.amazonaws.com or waf-regional.amazonaws.com or wafv2.amazonaws.com)
    and event.action: DeleteWebACL 
    and event.outcome: success
```



### AWS WAF Rule or Rule Group Deletion

Branch count: 6  
Document count: 6  
Index: geneve-ut-0121

```python
event.dataset: aws.cloudtrail 
    and event.provider: (waf.amazonaws.com or waf-regional.amazonaws.com or wafv2.amazonaws.com) 
    and event.action: (DeleteRule or DeleteRuleGroup) 
    and event.outcome: success
```



### Accepted Default Telnet Port Connection

Branch count: 7  
Document count: 7  
Index: geneve-ut-0124

```python
(event.dataset:(fortinet_fortigate.log or network_traffic.flow
        or sonicwall_firewall.log or suricata.eve or panw.panos)
    or event.category:(network or network_traffic))
    and event.type:connection and not event.action:(
        flow_dropped or flow_denied or denied or deny or
        flow_terminated or timeout or Reject or network_flow)
    and destination.port:23
```



### Access Control List Modification via setfacl

Branch count: 6  
Document count: 6  
Index: geneve-ut-0125

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "setfacl" and not (
  ?process.parent.executable in (
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/dirsrv/ds_systemd_ask_password_acl", "/usr/lib/systemd/systemd-udevd",
    "/usr/bin/udevadm", "/usr/sbin/ds_systemd_ask_password_acl", "/usr/bin/su", "/bin/su"
  ) or
  process.command_line == "/bin/setfacl --restore=-" or
  process.args == "/var/log/journal/" or
  ?process.parent.name in ("stats.pl", "perl", "find") or
  ?process.parent.command_line like~ "*ansible*" or
  ?process.parent.args == "/opt/audit-log-acl.sh"
)
```



### Access to a Sensitive LDAP Attribute

Branch count: 4  
Document count: 4  
Index: geneve-ut-0126

```python
any where host.os.type == "windows" and event.code == "4662" and

  not winlog.event_data.SubjectUserSid : "S-1-5-18" and

  winlog.event_data.Properties : (
   /* unixUserPassword */
  "*612cb747-c0e8-4f92-9221-fdd5f15b550d*",

  /* ms-PKI-AccountCredentials */
  "*b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7*",

  /*  ms-PKI-DPAPIMasterKeys */
  "*b3f93023-9239-4f7c-b99c-6745d87adbc2*",

  /* msPKI-CredentialRoamingTokens */
  "*b7ff5a38-0818-42b0-8110-d3d154c97f24*"
  ) and

  /*
   Excluding noisy AccessMasks
   0x0 undefined and 0x100 Control Access
   https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
   */
  not winlog.event_data.AccessMask in ("0x0", "0x100")
```



### Accessing Outlook Data Files

Branch count: 4  
Document count: 4  
Index: geneve-ut-0127

```python
process where host.os.type == "windows" and event.type == "start" and process.args : ("*.ost", "*.pst") and
  not process.name : "outlook.exe" and
  not (
        process.name : "rundll32.exe" and
        process.args : "*davclnt.dll,DavSetCookie*"
  )
```



### Account Configured with Never-Expiring Password

Branch count: 3  
Document count: 3  
Index: geneve-ut-0128

```python
any where host.os.type == "windows" and
(
  (
    event.code == "4738" and winlog.event_data.NewUACList == "USER_DONT_EXPIRE_PASSWORD" and not user.id == "S-1-5-18"
  ) or
  (
    event.code == "5136" and winlog.event_data.AttributeLDAPDisplayName == "userAccountControl" and
    winlog.event_data.AttributeValue in ("66048", "66080") and winlog.event_data.OperationType == "%%14674" and
    not (
      winlog.event_data.SubjectUserName : "*svc*" or
      winlog.event_data.ObjectDN : "*Service*"
    )
  )
)
```



### Account Password Reset Remotely

Branch count: 9  
Document count: 18  
Index: geneve-ut-0130

```python
sequence by winlog.computer_name with maxspan=1m
  [authentication where host.os.type == "windows" and event.action == "logged-in" and
    /* event 4624 need to be logged */
    winlog.logon.type : "Network" and event.outcome == "success" and source.ip != null and
    source.ip != "127.0.0.1" and source.ip != "::1" and
    not winlog.event_data.TargetUserName : ("svc*", "PIM_*", "_*_", "*-*-*", "*$")] by winlog.event_data.TargetLogonId
   /* event 4724 need to be logged */
  [iam where host.os.type == "windows" and event.action == "reset-password" and
   (
    /*
       This rule is very noisy if not scoped to privileged accounts, duplicate the
       rule and add your own naming convention and accounts of interest here.
     */
    winlog.event_data.TargetUserName: ("*Admin*", "*super*", "*SVC*", "*DC0*", "*service*", "*DMZ*", "*ADM*") or
    winlog.event_data.TargetSid : ("S-1-5-21-*-500", "S-1-12-1-*-500")
    )
  ] by winlog.event_data.SubjectLogonId
```



### Active Directory Discovery using AdExplorer

Branch count: 2  
Document count: 2  
Index: geneve-ut-0132

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "ADExplorer*.exe" or ?process.pe.original_file_name == "AdExp")
```



### Active Directory Group Modification by SYSTEM

Branch count: 1  
Document count: 1  
Index: geneve-ut-0134

```python
iam where host.os.type == "windows" and event.code == "4728" and
winlog.event_data.SubjectUserSid : "S-1-5-18" and

/* DOMAIN_USERS and local groups */
not group.id : "S-1-5-21-*-513"
```



### AdFind Command Activity

Branch count: 36  
Document count: 36  
Index: geneve-ut-0135

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "AdFind*.exe" or ?process.pe.original_file_name == "AdFind.exe") and
  process.args : ("objectcategory=computer", "(objectcategory=computer)",
                  "objectcategory=person", "(objectcategory=person)",
                  "objectcategory=subnet", "(objectcategory=subnet)",
                  "objectcategory=group", "(objectcategory=group)",
                  "objectcategory=organizationalunit", "(objectcategory=organizationalunit)",
                  "objectcategory=attributeschema", "(objectcategory=attributeschema)",
                  "domainlist", "dcmodes", "adinfo", "dclist", "computers_pwnotreqd", "trustdmp")
```



### Adding Hidden File Attribute via Attrib

Branch count: 8  
Document count: 8  
Index: geneve-ut-0136

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "attrib.exe" or ?process.pe.original_file_name == "ATTRIB.EXE") and process.args : "+h" and
  not (process.parent.name: "cmd.exe" and process.command_line: "attrib  +R +H +S +A *.cui") and

  not (
    process.parent.name: "draw.io.exe" and
    (
      process.command_line : ("*drawio.bkp*", "*drawio.dtmp*")
    )
  )
```



### AdminSDHolder Backdoor

Branch count: 1  
Document count: 1  
Index: geneve-ut-0137

```python
event.code:5136 and host.os.type:"windows" and winlog.event_data.ObjectDN:CN=AdminSDHolder,CN=System*
```



### Administrator Privileges Assigned to an Okta Group

Branch count: 1  
Document count: 1  
Index: geneve-ut-0139

```python
event.dataset:okta.system and event.action:group.privilege.grant
```



### Administrator Role Assigned to an Okta User

Branch count: 1  
Document count: 1  
Index: geneve-ut-0140

```python
event.dataset:okta.system and event.action:user.account.privilege.grant
```



### Adobe Hijack Persistence

Branch count: 4  
Document count: 4  
Index: geneve-ut-0141

```python
file where host.os.type == "windows" and event.type == "creation" and
  file.path : (
    "?:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe",
    "?:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe",

    /* Crowdstrike specific condition as it uses NT Object paths */
    "\\Device\\HarddiskVolume*\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe",
    "\\Device\\HarddiskVolume*\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe"
  ) and
  not process.name : ("msiexec.exe", "AdobeARM.exe")
```



### Adversary Behavior - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-0142

```python
event.kind:alert and event.module:endgame and (event.action:behavior_protection_event or endgame.event_subtype_full:behavior_protection_event)
```



### Apple Script Execution followed by Network Connection

Branch count: 1  
Document count: 2  
Index: geneve-ut-0154

```python
sequence by host.id, process.entity_id with maxspan=30s
 [process where host.os.type == "macos" and event.type == "start" and process.name == "osascript"]
 [network where host.os.type == "macos" and event.type == "start" and process.name == "osascript" and
   not cidrmatch(destination.ip, 
       "240.0.0.0/4", "233.252.0.0/24", "224.0.0.0/4", "198.19.0.0/16", "192.18.0.0/15", 
       "192.0.0.0/24", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", 
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", 
       "100.64.0.0/10", "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
       "::1", "FE80::/10", "FF00::/8")]
```



### Apple Scripting Execution with Administrator Privileges

Branch count: 10  
Document count: 10  
Index: geneve-ut-0155

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name == "osascript" and
 process.command_line : "osascript*with administrator privileges" and
 ((process.parent.code_signature.trusted == false or process.parent.code_signature.exists == false) or process.Ext.effective_parent.executable like ("/tmp/*", "/private/tmp/*", "/Users/Shared/*"))
```



### Application Added to Google Workspace Domain

Branch count: 1  
Document count: 1  
Index: geneve-ut-0156

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:ADD_APPLICATION
```



### Application Removed from Blocklist in Google Workspace

Branch count: 1  
Document count: 1  
Index: geneve-ut-0157

```python
event.dataset:"google_workspace.admin" and event.category:"iam" and event.type:"change"  and
  event.action:"CHANGE_APPLICATION_SETTING" and
  google_workspace.admin.application.name:"Google Workspace Marketplace" and
  google_workspace.admin.old_value: *allowed*false* and google_workspace.admin.new_value: *allowed*true*
```



### At Job Created or Modified

Branch count: 16  
Document count: 16  
Index: geneve-ut-0159

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and
file.path like ("/var/spool/cron/atjobs/*", "/var/spool/atjobs/*") and
not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/local/bin/dockerd", "./usr/bin/podman"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : ("/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*") or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*")
)
```



### At.exe Command Lateral Movement

Branch count: 1  
Document count: 1  
Index: geneve-ut-0160

```python
process where host.os.type == "windows" and event.type == "start" and process.name : "at.exe" and process.args : "\\\\*"
```



### Attempt to Clear Kernel Ring Buffer

Branch count: 12  
Document count: 12  
Index: geneve-ut-0161

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "dmesg" and process.args in ("-c", "--clear")
```



### Attempt to Clear Logs via Journalctl

Branch count: 18  
Document count: 18  
Index: geneve-ut-0162

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "journalctl" and process.args like ("--vacuum-time=*", "--vacuum-size=*", "--vacuum-files=*") and
not process.parent.args == "/etc/cron.daily/clean-journal-logs"
```



### Attempt to Create Okta API Token

Branch count: 1  
Document count: 1  
Index: geneve-ut-0163

```python
event.dataset:okta.system and event.action:system.api_token.create
```



### Attempt to Deactivate an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-0164

```python
event.dataset:okta.system and event.action:application.lifecycle.deactivate
```



### Attempt to Deactivate an Okta Network Zone

Branch count: 1  
Document count: 1  
Index: geneve-ut-0165

```python
event.dataset:okta.system and event.action:zone.deactivate
```



### Attempt to Deactivate an Okta Policy

Branch count: 1  
Document count: 1  
Index: geneve-ut-0166

```python
event.dataset:okta.system and event.action:policy.lifecycle.deactivate
```



### Attempt to Deactivate an Okta Policy Rule

Branch count: 1  
Document count: 1  
Index: geneve-ut-0167

```python
event.dataset:okta.system and event.action:policy.rule.deactivate
```



### Attempt to Delete an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-0168

```python
event.dataset:okta.system and event.action:application.lifecycle.delete
```



### Attempt to Delete an Okta Network Zone

Branch count: 1  
Document count: 1  
Index: geneve-ut-0169

```python
event.dataset:okta.system and event.action:zone.delete
```



### Attempt to Delete an Okta Policy

Branch count: 1  
Document count: 1  
Index: geneve-ut-0170

```python
event.dataset:okta.system and event.action:policy.lifecycle.delete
```



### Attempt to Delete an Okta Policy Rule

Branch count: 1  
Document count: 1  
Index: geneve-ut-0171

```python
event.dataset:okta.system and event.action:policy.rule.delete
```



### Attempt to Disable Auditd Service

Branch count: 64  
Document count: 64  
Index: geneve-ut-0172

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and (
  (process.name == "service" and process.args == "stop") or
  (process.name == "chkconfig" and process.args == "off") or
  (process.name == "update-rc.d" and process.args in ("remove", "disable")) or
  (process.name == "systemctl" and process.args in ("disable", "stop", "kill", "mask"))
) and
process.args in ("auditd", "auditd.service") and 
not ?process.parent.name == "auditd.prerm"
```



### Attempt to Disable Gatekeeper

Branch count: 2  
Document count: 2  
Index: geneve-ut-0173

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.name == "spctl" and
 process.args like~ "--master-disable"
```



### Attempt to Disable IPTables or Firewall

Branch count: 165  
Document count: 165  
Index: geneve-ut-0174

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
(
   /* disable FW */
  (
    (process.name == "ufw" and process.args == "disable") or
    (process.name == "iptables" and process.args in ("-F", "--flush", "-X", "--delete-chain") and process.args_count == 2) or
    (process.name in ("iptables", "ip6tables") and process.parent.args == "force-stop")
  ) or

   /* stop FW service */
  (
    (
      (process.name == "service" and process.args == "stop") or
      (process.name == "chkconfig" and process.args == "off") or
      (process.name == "update-rc.d" and process.args in ("remove", "disable")) or
      (process.name == "systemctl" and process.args in ("disable", "stop", "kill", "mask"))
    ) and
    process.args in ("firewalld", "ip6tables", "iptables", "firewalld.service", "ip6tables.service", "iptables.service")
  )
)
```



### Attempt to Disable Syslog Service

Branch count: 192  
Document count: 192  
Index: geneve-ut-0175

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and (
  (process.name == "service" and process.args == "stop") or
  (process.name == "chkconfig" and process.args == "off") or
  (process.name == "update-rc.d" and process.args in ("remove", "disable")) or
  (process.name == "systemctl" and process.args in ("disable", "stop", "kill", "mask"))
) and
process.args in ("syslog", "rsyslog", "syslog-ng", "syslog.service", "rsyslog.service", "syslog-ng.service") and
not (
  process.parent.name == "rsyslog-rotate" or
  process.args == "HUP"
)
```



### Attempt to Enable the Root Account

Branch count: 2  
Document count: 2  
Index: geneve-ut-0176

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.name == "dsenableroot" and 
 not process.args == "-d"
```



### Attempt to Establish VScode Remote Tunnel

Branch count: 6  
Document count: 6  
Index: geneve-ut-0177

```python
process where host.os.type == "windows" and event.type == "start" and
  process.args : "tunnel" and (process.args : "--accept-server-license-terms" or process.name : "code*.exe") and
  not (process.name == "code-tunnel.exe" and process.args == "status" and process.parent.name == "Code.exe")
```



### Attempt to Install Kali Linux via WSL

Branch count: 10  
Document count: 10  
Index: geneve-ut-0178

```python
process where host.os.type == "windows" and event.type == "start" and
(
  (process.name : "wsl.exe" and process.args : ("-d", "--distribution", "-i", "--install") and process.args : "kali*") or
  process.executable : (
    "?:\\Users\\*\\AppData\\Local\\packages\\kalilinux*",
    "?:\\Users\\*\\AppData\\Local\\Microsoft\\WindowsApps\\kali.exe",
    "?:\\Program Files*\\WindowsApps\\KaliLinux.*\\kali.exe",

    /* Crowdstrike specific exclusion as it uses NT Object paths */
    "\\Device\\HarddiskVolume*\\Users\\*\\AppData\\Local\\packages\\kalilinux*",
    "\\Device\\HarddiskVolume*\\Users\\*\\AppData\\Local\\Microsoft\\WindowsApps\\kali.exe",
    "\\Device\\HarddiskVolume*\\Program Files*\\WindowsApps\\KaliLinux.*\\kali.exe"
  )
)
```



### Attempt to Install Root Certificate

Branch count: 16  
Document count: 16  
Index: geneve-ut-0179

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  process.name == "security" and process.args like "add-trusted-cert" and
  (process.parent.name like~ ("osascript", "bash", "sh", "zsh", "Terminal", "Python*") or (process.parent.code_signature.exists == false or process.parent.code_signature.trusted == false))
```



### Attempt to Modify an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-0180

```python
event.dataset:okta.system and event.action:application.lifecycle.update
```



### Attempt to Modify an Okta Network Zone

Branch count: 3  
Document count: 3  
Index: geneve-ut-0181

```python
event.dataset:okta.system and event.action:(zone.update or network_zone.rule.disabled or zone.remove_blacklist)
```



### Attempt to Modify an Okta Policy

Branch count: 1  
Document count: 1  
Index: geneve-ut-0182

```python
event.dataset:okta.system and event.action:policy.lifecycle.update
```



### Attempt to Modify an Okta Policy Rule

Branch count: 1  
Document count: 1  
Index: geneve-ut-0183

```python
event.dataset:okta.system and event.action:policy.rule.update
```



### Attempt to Mount SMB Share via Command Line

Branch count: 8  
Document count: 8  
Index: geneve-ut-0184

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  (
    process.name == "mount_smbfs" or
    (process.name == "open" and process.args like~ "smb://*") or
    (process.name == "mount" and process.args like~ "smbfs") or
    (process.name == "osascript" and process.command_line : "osascript*mount volume*smb://*")
  ) and
  not process.parent.executable like "/Applications/Google Drive.app/Contents/MacOS/Google Drive"
```



### Attempt to Reset MFA Factors for an Okta User Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-0185

```python
event.dataset:okta.system and event.action:user.mfa.factor.reset_all
```



### Attempt to Revoke Okta API Token

Branch count: 1  
Document count: 1  
Index: geneve-ut-0186

```python
event.dataset:okta.system and event.action:system.api_token.revoke
```



### Attempt to Unload Elastic Endpoint Security Kernel Extension

Branch count: 6  
Document count: 6  
Index: geneve-ut-0187

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.name == "kextunload" and process.args like~ ("*.EndpointSecurity", "/System/Library/Extensions/EndpointSecurity.kext", "EndpointSecurity.kext")
```



### Attempted Bypass of Okta MFA

Branch count: 1  
Document count: 1  
Index: geneve-ut-0188

```python
event.dataset:okta.system and event.action:user.mfa.attempt_bypass
```



### Attempted Private Key Access

Branch count: 3  
Document count: 3  
Index: geneve-ut-0189

```python
process where host.os.type == "windows" and event.type == "start" and
  process.command_line : ("*.pem *", "*.pem", "*.id_rsa*") and
  not process.args : (
        "--rootcert",
        "--cert",
        "--crlfile"
  ) and
  not process.command_line : (
        "*--cacert*",
        "*--ssl-cert*",
        "*--tls-cert*",
        "*--tls_server_certs*"
  ) and
  not process.executable : (
    "?:\\ProgramData\\Logishrd\\LogiOptions\\Software\\*\\LogiLuUpdater.exe",
    "?:\\Program Files\\Elastic\\Agent\\data\\*\\osqueryd.exe",
    "?:\\Program Files\\Git\\cmd\\git.exe",
    "?:\\Program Files\\Git\\mingw64\\bin\\git.exe",
    "?:\\Program Files\\Guardicore\\gc-controller.exe",
    "?:\\Program Files\\Guardicore\\gc-deception-agent.exe",
    "?:\\Program Files\\Guardicore\\gc-detection-agent.exe",
    "?:\\Program Files\\Guardicore\\gc-enforcement-agent.exe",
    "?:\\Program Files\\Guardicore\\gc-guest-agent.exe",
    "?:\\Program Files\\Logi\\LogiBolt\\LogiBoltUpdater.exe",
    "?:\\Program Files (x86)\\Schneider Electric EcoStruxure\\Building Operation 5.0\\Device Administrator\\Python\\python.exe",
    "?:\\Program Files\\Splunk\\bin\\openssl.exe",
    "?:\\Program Files\\SplunkUniversalForwarder\\bin\\openssl.exe",
    "?:\\Users\\*\\AppData\\Local\\Logi\\LogiBolt\\LogiBoltUpdater.exe",
    "?:\\Windows\\system32\\icacls.exe",
    "?:\\Windows\\System32\\OpenSSH\\*"
  )
```



### Authorization Plugin Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-0192

```python
file where host.os.type == "macos" and event.action == "modification" and
  file.path like "/Library/Security/SecurityAgentPlugins/*" and
  not file.path like ("/Library/Security/SecurityAgentPlugins/KandjiPassport.bundle/*", "/Library/Security/SecurityAgentPlugins/TeamViewerAuthPlugin.bundle/*") and
  not process.name == "shove"
```



### Azure Automation Account Created

Branch count: 2  
Document count: 2  
Index: geneve-ut-0193

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WRITE" and event.outcome:(Success or success)
```



### Azure Automation Runbook Created or Modified

Branch count: 6  
Document count: 6  
Index: geneve-ut-0194

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
Index: geneve-ut-0195

```python
event.dataset:azure.activitylogs and
    azure.activitylogs.operation_name:"MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE" and
    event.outcome:(Success or success)
```



### Azure Automation Webhook Created

Branch count: 4  
Document count: 4  
Index: geneve-ut-0196

```python
event.dataset:azure.activitylogs and
  azure.activitylogs.operation_name:
    (
      "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/ACTION" or
      "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/WRITE"
    ) and
  event.outcome:(Success or success)
```



### Azure Blob Storage Container Access Level Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-0197

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE" and event.outcome:(Success or success)
```



### Azure Blob Storage Permissions Modified

Branch count: 4  
Document count: 4  
Index: geneve-ut-0198

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:(
     "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/BLOBS/MANAGEOWNERSHIP/ACTION" or
     "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/BLOBS/MODIFYPERMISSIONS/ACTION") and
  event.outcome:(Success or success)
```



### Azure Compute VM Command Executed

Branch count: 2  
Document count: 2  
Index: geneve-ut-0203

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION" and event.outcome:(Success or success)
```



### Azure Diagnostic Settings Alert Suppression Rule Created or Modified

Branch count: 1  
Document count: 1  
Index: geneve-ut-0204

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.SECURITY/ALERTSSUPPRESSIONRULES/WRITE" and
event.outcome: "success"
```



### Azure Event Hub Authorization Rule Created or Updated

Branch count: 2  
Document count: 2  
Index: geneve-ut-0206

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.EVENTHUB/NAMESPACES/AUTHORIZATIONRULES/WRITE" and event.outcome:(Success or success)
```



### Azure Event Hub Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-0207

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE" and event.outcome:(Success or success)
```



### Azure Kubernetes Services (AKS) Kubernetes Events Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-0211

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EVENTS.K8S.IO/EVENTS/DELETE" and
event.outcome:(Success or success)
```



### Azure Kubernetes Services (AKS) Kubernetes Pods Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-0212

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE" and
event.outcome:(Success or success)
```



### Azure Kubernetes Services (AKS) Kubernetes Rolebindings Created

Branch count: 4  
Document count: 4  
Index: geneve-ut-0213

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:
	("MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLEBINDINGS/WRITE" or
	 "MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLEBINDINGS/WRITE") and
event.outcome:(Success or success)
```



### Azure RBAC Built-In Administrator Roles Assigned

Branch count: 6  
Document count: 6  
Index: geneve-ut-0215

```python
event.dataset: azure.activitylogs and
    event.action: "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE" and
    azure.activitylogs.properties.requestbody.properties.roleDefinitionId:
    (
      *18d7d88d-d35e-4fb5-a5c3-7773c20a72d9* or
      *f58310d9-a9f6-439a-9e8d-f62e7b41a168* or
      *b24988ac-6180-42a0-ab88-20f7382dd24c* or
      *8e3af657-a8ff-443c-a75c-2fe8c4bcb635* or
      *92b92042-07d9-4307-87f7-36a593fc5850* or
      *a8889054-8d42-49c9-bc1c-52486c10e7cd*
  )
```



### Azure Recovery Services Resource Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-0216

```python
event.dataset:azure.activitylogs and
    azure.activitylogs.operation_name:MICROSOFT.RECOVERYSERVICES/*/DELETE and
    event.outcome:(Success or success)
```



### Azure Resource Group Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-0217

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE" and event.outcome:(Success or success)
```



### Azure Storage Account Key Regenerated

Branch count: 2  
Document count: 2  
Index: geneve-ut-0221

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION" and event.outcome:(Success or success)
```



### Azure VNet Firewall Front Door WAF Policy Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-0224

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/FRONTDOORWEBAPPLICATIONFIREWALLPOLICIES/DELETE" and event.outcome:(Success or success)
```



### Azure VNet Firewall Policy Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-0225

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE" and event.outcome:(Success or success)
```



### Azure VNet Full Network Packet Capture Enabled

Branch count: 6  
Document count: 6  
Index: geneve-ut-0226

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:
    (
        MICROSOFT.NETWORK/*/STARTPACKETCAPTURE/ACTION or
        MICROSOFT.NETWORK/*/VPNCONNECTIONS/STARTPACKETCAPTURE/ACTION or
        MICROSOFT.NETWORK/*/PACKETCAPTURES/WRITE
    ) and
event.outcome:(Success or success)
```



### Azure VNet Network Watcher Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-0227

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE" and event.outcome:(Success or success)
```



### BPF filter applied using TC

Branch count: 6  
Document count: 6  
Index: geneve-ut-0228

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.executable == "/usr/sbin/tc" and process.args == "filter" and process.args == "add" and process.args == "bpf" and
not ?process.parent.executable == "/usr/sbin/libvirtd"
```



### Backup Deletion with Wbadmin

Branch count: 6  
Document count: 6  
Index: geneve-ut-0229

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "wbadmin.exe" or ?process.pe.original_file_name == "WBADMIN.EXE") and
  process.args : ("catalog", "backup", "systemstatebackup") and process.args : "delete"
```



### Base16 or Base32 Encoding/Decoding Activity

Branch count: 24  
Document count: 24  
Index: geneve-ut-0230

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name in ("base16", "base32", "base32plain", "base32hex") and
not process.args in ("--help", "--version")
```



### Bash Shell Profile Modification

Branch count: 20  
Document count: 20  
Index: geneve-ut-0232

```python
event.category:file and host.os.type:(linux or macos) and event.type:change and not event.action:("rename" or "extended_attributes_delete") and
  file.name:(".bash_profile" or ".profile" or ".bashrc" or ".zshenv" or ".zshrc") and file.path:(/home/* or /Users/*) and 
  process.name:(* and not (sudo or vim or zsh or env or nano or bash or Terminal or xpcproxy or login or cat or cp or
  launchctl or java or dnf or tailwatchd or ldconfig or yum or semodule or cpanellogd or dockerd or authselect or chmod or
  dnf-automatic or git or dpkg or platform-python)) and
  not process.executable:(/Applications/* or /private/var/folders/* or /usr/local/* or /opt/saltstack/salt/bin/*)
```



### Behavior - Detected - Elastic Defend

Branch count: 2  
Document count: 2  
Index: geneve-ut-0233

```python
event.kind : alert and event.code : behavior and (event.type : allowed or (event.type: denied and event.outcome: failure))
```



### Behavior - Prevented - Elastic Defend

Branch count: 1  
Document count: 1  
Index: geneve-ut-0234

```python
event.kind : alert and event.code : behavior and event.type : denied and event.outcome : success
```



### Binary Content Copy via Cmd.exe

Branch count: 3  
Document count: 3  
Index: geneve-ut-0235

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "cmd.exe" and (
    (process.args : "type" and process.args : (">", ">>")) or
    (process.args : "copy" and process.args : "/b"))
```



### Binary Executed from Shared Memory Directory

Branch count: 8  
Document count: 8  
Index: geneve-ut-0236

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
user.id == "0" and process.executable like ("/dev/shm/*", "/run/shm/*", "/var/run/*", "/var/lock/*") and
not (
  process.executable : (
    "/var/run/docker/*", "/var/run/utsns/*", "/var/run/s6/*", "/var/run/cloudera-scm-agent/*",
    "/var/run/argo/argoexec", "/dev/shm/*.*/sandfly"
  ) or
  process.parent.command_line == "/usr/bin/runc init"
)
```



### Bitsadmin Activity

Branch count: 13  
Document count: 13  
Index: geneve-ut-0237

```python
process where host.os.type == "windows" and event.type == "start" and
  (
   (process.name : "bitsadmin.exe" and process.args : (
        "*Transfer*", "*Create*", "AddFile", "*SetNotifyFlags*", "*SetNotifyCmdLine*",
        "*SetMinRetryDelay*", "*SetCustomHeaders*", "*Resume*")
   ) or
   (process.name : "powershell.exe" and process.args : (
        "*Start-BitsTransfer*", "*Add-BitsFile*",
        "*Resume-BitsTransfer*", "*Set-BitsTransfer*", "*BITS.Manager*")
   )
  )
```



### Browser Extension Install

Branch count: 3  
Document count: 3  
Index: geneve-ut-0239

```python
file where host.os.type == "windows" and event.type : "creation" and
(
  /* Firefox-Based Browsers */
  (
    file.name : "*.xpi" and
    file.path : "?:\\Users\\*\\AppData\\Roaming\\*\\Profiles\\*\\Extensions\\*.xpi" and
    not
    (
      process.name : "firefox.exe" and
      file.name : (
        "langpack-*@firefox.mozilla.org.xpi",
        "*@dictionaries.addons.mozilla.org.xpi",
        "newtab@mozilla.org.xpi",
        "uBlock0@raymondhill.net.xpi",
        /* AdBlockPlus */
        "{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}.xpi",
        /* Bitwarden */
        "{446900e4-71c2-419f-a6a7-df9c091e268b}.xpi",
        "addon@darkreader.org.xpi",
        /* 1Password */
        "{d634138d-c276-4fc8-924b-40a0ea21d284}.xpi",
        "support@lastpass.com.xpi",
        /* Grammarly */
        "87677a2c52b84ad3a151a4a72f5bd3c4@jetpack.xpi",
        "sentinelone_visibility@sentinelone.com.xpi",
        "keepassxc-browser@keepassxc.org.xpi"
      )
    )
  ) or
  /* Chromium-Based Browsers */
  (
    file.name : "*.crx" and
    file.path : "?:\\Users\\*\\AppData\\Local\\*\\*\\User Data\\Webstore Downloads\\*"
  )
)
```



### Browser Process Spawned from an Unusual Parent

Branch count: 16  
Document count: 16  
Index: geneve-ut-0240

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("chrome.exe", "msedge.exe") and
  process.parent.executable != null and process.command_line != null and
  (
  process.command_line :
           ("\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\"",
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"",
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --headless --disable-logging --log-level=3 --v=0",
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --headless --log-level=3",
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --headless",
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --remote-debugging-port=922? --profile-directory=\"Default\"*",
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --headless --restore-last-session --remote-debugging-port=45452*") or

  (process.args : "--remote-debugging-port=922?" and process.args : "--window-position=-*,-*")
   ) and
  not process.parent.executable :
                         ("C:\\Windows\\explorer.exe",
                          "C:\\Program Files (x86)\\*.exe",
                          "C:\\Program Files\\*.exe",
                          "C:\\Windows\\System32\\rdpinit.exe",
                          "C:\\Windows\\System32\\sihost.exe",
                          "C:\\Windows\\System32\\RuntimeBroker.exe",
                          "C:\\Windows\\System32\\SECOCL64.exe")
```



### Bypass UAC via Event Viewer

Branch count: 1  
Document count: 1  
Index: geneve-ut-0241

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "eventvwr.exe" and
  not process.executable : (
        "?:\\Windows\\SysWOW64\\mmc.exe",
        "?:\\Windows\\System32\\mmc.exe",
        "?:\\Windows\\SysWOW64\\WerFault.exe",
        "?:\\Windows\\System32\\WerFault.exe",

        /* Crowdstrike specific exclusion as it uses NT Object paths */
        "\\Device\\HarddiskVolume*\\Windows\\Sys?????\\mmc.exe",
        "\\Device\\HarddiskVolume*\\Windows\\Sys?????\\WerFault.exe"
  )
```



### Chkconfig Service Add

Branch count: 6  
Document count: 6  
Index: geneve-ut-0242

```python
process where host.os.type == "linux" and event.action in ("exec", "exec_event", "start") and
process.executable != null and
( 
  (process.executable : "/usr/sbin/chkconfig" and process.args : "--add") or
  (process.args : "*chkconfig" and process.args : "--add")
) and not (
  process.parent.name in ("rpm", "qualys-scan-util", "qualys-cloud-agent", "update-alternatives") or
  process.parent.executable in ("/opt/commvault/.gxsetup/silent_install/install", "/usr/sbin/alternatives") or
  process.parent.args : ("/var/tmp/rpm*", "/var/lib/waagent/*", "/usr/bin/puppet*") or
  process.args in ("jexec", "sapinit", "httpd", "dbora" , "selfprotection")
)
```



### Clearing Windows Console History

Branch count: 36  
Document count: 36  
Index: geneve-ut-0243

```python
process where host.os.type == "windows" and event.type == "start" and
  (
    process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or
    ?process.pe.original_file_name in ("PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE")
  ) and
  (
    process.args : "*Clear-History*" or
    (process.args : ("*Remove-Item*", "rm") and process.args : ("*ConsoleHost_history.txt*", "*(Get-PSReadlineOption).HistorySavePath*")) or
    (process.args : "*Set-PSReadlineOption*" and process.args : "*SaveNothing*")
  )
```



### Clearing Windows Event Logs

Branch count: 12  
Document count: 12  
Index: geneve-ut-0244

```python
process where host.os.type == "windows" and event.type == "start" and
(
  (
    (process.name : "wevtutil.exe" or ?process.pe.original_file_name == "wevtutil.exe") and
    process.args : ("/e:false", "cl", "clear-log")
  ) or
  (
    (
      process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or
      ?process.pe.original_file_name in ("PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE")
    ) and
    process.args : "Clear-EventLog"
  )
)
```



### Code Signing Policy Modification Through Built-in tools

Branch count: 16  
Document count: 16  
Index: geneve-ut-0247

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name: "bcdedit.exe" or ?process.pe.original_file_name == "bcdedit.exe") and process.args: ("-set", "/set") and 
  process.args: ("TESTSIGNING", "nointegritychecks", "loadoptions", "DISABLE_INTEGRITY_CHECKS")
```



### Code Signing Policy Modification Through Registry

Branch count: 4  
Document count: 4  
Index: geneve-ut-0248

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.value: "BehaviorOnFailedVerify" and registry.data.strings : ("0", "0x00000000", "1", "0x00000001") and 
  not process.executable : 
                      ("?:\\Windows\\System32\\svchost.exe", 
                       "?:\\Windows\\CCM\\CcmExec.exe",
                       "\\Device\\HarddiskVolume*\\Windows\\system32\\svchost.exe", 
                       "\\Device\\HarddiskVolume*\\Windows\\CCM\\CcmExec.exe")
  /*
    Full registry key path omitted due to data source variations:
    "HKEY_USERS\\*\\Software\\Policies\\Microsoft\\Windows NT\\Driver Signing\\BehaviorOnFailedVerify"
  */
```



### Command Execution via ForFiles

Branch count: 4  
Document count: 4  
Index: geneve-ut-0249

```python
process where host.os.type == "windows" and event.type == "start" and user.id != "S-1-5-18" and
 (process.name : "forfiles.exe" or ?process.pe.original_file_name == "forfiles.exe") and process.args : ("/c", "-c") and
 not process.args : ("-d", "/d", "cmd /c copy @file*", "cmd /c DEL /Q /F @*", "cmd /c del @*", "D:\\*")
```



### Command Execution via SolarWinds Process

Branch count: 12  
Document count: 12  
Index: geneve-ut-0250

```python
process where host.os.type == "windows" and event.type == "start" and process.name: ("cmd.exe", "powershell.exe") and
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
Index: geneve-ut-0253

```python
sequence by process.entity_id
  [process where host.os.type == "windows" and process.name : "cmd.exe" and event.type == "start"]
  [network where host.os.type == "windows" and process.name : "cmd.exe" and
     not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
                                  "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32",
                                  "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
                                  "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
                                  "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
                                  "FE80::/10", "FF00::/8") and
    not dns.question.name : (
          "wpad", "localhost", "ocsp.comodoca.com", "ocsp.digicert.com", "ocsp.sectigo.com", "crl.comodoca.com"
    )]
```



### Command Shell Activity Started via RunDLL32

Branch count: 2  
Document count: 2  
Index: geneve-ut-0254

```python
process where host.os.type == "windows" and event.type == "start" and
 process.name : ("cmd.exe", "powershell.exe") and
  process.parent.name : "rundll32.exe" and process.parent.command_line != null and
  /* common FPs can be added here */
  not process.parent.args : ("C:\\Windows\\System32\\SHELL32.dll,RunAsNewUser_RunDLL",
                             "C:\\WINDOWS\\*.tmp,zzzzInvokeManagedCustomActionOutOfProc")
```



### Command and Scripting Interpreter via Windows Scripts

Branch count: 16  
Document count: 16  
Index: geneve-ut-0255

```python
process where host.os.type == "windows" and event.type == "start" and
  process.command_line != null and
  (
    process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe", "cmd.exe") or
    ?process.pe.original_file_name : ("powershell.exe", "pwsh.dll", "powershell_ise.exe", "Cmd.Exe")
  ) and
  process.parent.name : ("wscript.exe", "mshta.exe")
```



### Component Object Model Hijacking

Branch count: 60  
Document count: 60  
Index: geneve-ut-0256

```python
registry where host.os.type == "windows" and event.type == "change" and
  /* not necessary but good for filtering privileged installations */
  user.domain != "NT AUTHORITY" and process.executable != null and 
  (
    (
      registry.path : "HK*\\InprocServer32\\" and
      registry.data.strings: ("scrobj.dll", "?:\\*\\scrobj.dll") and
      not registry.path : "*\\{06290BD*-48AA-11D2-8432-006008C3FBFC}\\*"
    ) or

    (
      registry.path : "HKLM\\*\\InProcServer32\\*" and
        registry.data.strings : ("*\\Users\\*", "*\\ProgramData\\*")
    ) or

    /* in general COM Registry changes on Users Hive is less noisy and worth alerting */
    (
      registry.path : (
        "HKEY_USERS\\*\\InprocServer32\\",
        "HKEY_USERS\\*\\LocalServer32\\",
        "HKEY_USERS\\*\\DelegateExecute",
        "HKEY_USERS\\*\\TreatAs\\",
        "HKEY_USERS\\*\\ScriptletURL*", 
        "HKEY_USERS\\*\\TypeLib*\\Win*"
      ) and
      not registry.data.strings : (
            /* COM related to Windows Spotlight feature */
            "{4813071a-41ad-44a2-9835-886d2f63ca30}",

            /* AppX/MSIX DelegateExecute handlers: execute, protocol, file */
            "{A56A841F-E974-45C1-8001-7E3F8A085917}",
            "{4ED3A719-CEA8-4BD9-910D-E252F997AFC2}",
            "{BFEC0C93-0B7D-4F2C-B09C-AFFFC4BDAE78}"
      )
    )
  ) and 

  not (
    process.code_signature.trusted == true and
    process.code_signature.subject_name in (
        "Island Technology Inc.", "Google LLC", "Grammarly, Inc.", "Dropbox, Inc", "REFINITIV US LLC", "HP Inc.", "Adobe Inc.",
        "Citrix Systems, Inc.", "Veeam Software Group GmbH", "Zhuhai Kingsoft Office Software Co., Ltd.", "Oracle America, Inc.",
        "Brave Software, Inc.", "DeepL SE", "Opera Norway AS"
    )
  ) and 

  /* excludes Microsoft signed noisy processes */
  not
  (
    process.name : (
      "OneDrive.exe", "OneDriveSetup.exe", "FileSyncConfig.exe", "Teams.exe", "MicrosoftEdgeUpdate.exe", "msrdcw.exe",
      "MicrosoftEdgeUpdateComRegisterShell64.exe", "setup.exe"
    ) and
    process.code_signature.trusted == true and process.code_signature.subject_name in ("Microsoft Windows", "Microsoft Corporation")
  ) and

  not process.executable : (
        "?:\\$WINDOWS.~BT\\Sources\\SetupHost.exe",
        "?:\\Program Files (x86)\\*.exe",
        "?:\\Program Files\\*.exe",
        "?:\\ProgramData\\4Team\\4Team-Updater\\4Team-Updater-Helper.exe",
        "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
        "?:\\Users\\*\\AppData\\Local\\Wondershare\\Wondershare NativePush\\WsToastNotification.exe",
        "?:\\Windows\\System32\\DriverStore\\FileRepository\\*.exe",
        "?:\\Windows\\System32\\msiexec.exe",
        "?:\\Windows\\System32\\svchost.exe",
        "?:\\Windows\\SysWOW64\\regsvr32.exe",
        "?:\\Windows\\System32\\regsvr32.exe",
        "\\Device\\Mup\\*\\Kufer\\KuferSQL\\BasysSQL.exe"
  )
```



### Compression DLL Loaded by Unusual Process

Branch count: 12  
Document count: 12  
Index: geneve-ut-0257

```python
library where host.os.type == "windows" and event.action == "load" and
  dll.name : ("System.IO.Compression.FileSystem.ni.dll", "System.IO.Compression.ni.dll") and
  not 
  (
    (
      process.executable : (
        "?:\\Program Files\\*",
        "?:\\Program Files (x86)\\*",
        "?:\\Windows\\Microsoft.NET\\Framework*\\mscorsvw.exe",
        "?:\\Windows\\System32\\sdiagnhost.exe",
        "?:\\Windows\\System32\\inetsrv\\w3wp.exe",
        "?:\\Windows\\SysWOW64\\inetsrv\\w3wp.exe",
        "?:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\DataCollection\\*\\OpenHandleCollector.exe"
      ) and process.code_signature.trusted == true
    ) or
    (
      process.name : "NuGet.exe" and process.code_signature.trusted == true and user.id : ("S-1-5-18", "S-1-5-20")
    )
  )
```



### Connection to Commonly Abused Free SSL Certificate Providers

Branch count: 24  
Document count: 24  
Index: geneve-ut-0260

```python
network where host.os.type == "windows" and network.protocol == "dns" and
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



### Connection to External Network via Telnet

Branch count: 2  
Document count: 4  
Index: geneve-ut-0262

```python
sequence by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start") and process.name == "telnet"]
  [network where host.os.type == "linux" and process.name == "telnet" and not cidrmatch(
     destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
     "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
     "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
     "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
     "FF00::/8"
    )
  ]
```



### Connection to Internal Network via Telnet

Branch count: 2  
Document count: 4  
Index: geneve-ut-0263

```python
sequence by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start") and process.name == "telnet"]
  [network where host.os.type == "linux" and process.name == "telnet" and cidrmatch(
     destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
     "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
     "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
     "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
     "FF00::/8"
    )
  ]
```



### Container Workload Protection

Branch count: 1  
Document count: 1  
Index: geneve-ut-0266

```python
event.kind:alert and event.module:cloud_defend
```



### Control Panel Process with Unusual Arguments

Branch count: 12  
Document count: 12  
Index: geneve-ut-0267

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "control.exe" and
  process.command_line : (
    "*.jpg*", "*.png*",
    "*.gif*", "*.bmp*",
    "*.jpeg*", "*.TIFF*",
    "*.inf*", "*.cpl:*/*",
    "*../../..*",
    "*/AppData/Local/*",
    "*:\\Users\\Public\\*",
    "*\\AppData\\Local\\*"
)
```



### Creation of Hidden Launch Agent or Daemon

Branch count: 1  
Document count: 1  
Index: geneve-ut-0269

```python
file where host.os.type == "macos" and event.action == "launch_daemon" and
  Persistence.name : ".*"
```



### Creation of Hidden Login Item via Apple Script

Branch count: 2  
Document count: 2  
Index: geneve-ut-0270

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name == "osascript" and
 process.command_line : "osascript*login item*hidden:true*"
```



### Creation of SettingContent-ms Files

Branch count: 1  
Document count: 1  
Index: geneve-ut-0272

```python
file where host.os.type == "windows" and event.type == "creation" and
  file.extension : "settingcontent-ms" and
  not file.path : (
    "?:\\*\\AppData\\Local\\Packages\\windows.immersivecontrolpanel_*\\LocalState\\Indexed\\Settings\\*",
    "\\Device\\HarddiskVolume*\\Windows\\WinSxS\\amd64_microsoft-windows-s..*\\*.settingcontent-ms"
  )
```



### Creation of a DNS-Named Record

Branch count: 1  
Document count: 1  
Index: geneve-ut-0273

```python
any where host.os.type == "windows" and event.code == "5137" and winlog.event_data.ObjectClass == "dnsNode" and
    not winlog.event_data.SubjectUserName : "*$"
```



### Creation of a Hidden Local User Account

Branch count: 3  
Document count: 3  
Index: geneve-ut-0274

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
    "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\*$\\",
    "\\REGISTRY\\MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\*$\\",
    "MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\*$\\"
)
```



### Creation or Modification of Domain Backup DPAPI private key

Branch count: 2  
Document count: 2  
Index: geneve-ut-0275

```python
file where host.os.type == "windows" and event.type != "deletion" and file.name : ("ntds_capi_*.pfx", "ntds_capi_*.pvk")
```



### Creation or Modification of Root Certificate

Branch count: 156  
Document count: 156  
Index: geneve-ut-0276

```python
registry where host.os.type == "windows" and event.type == "change" and registry.value : "Blob" and
  registry.path :
    (
      "HKLM\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "HKLM\\Software\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "HKLM\\Software\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "HKLM\\Software\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "\\REGISTRY\\MACHINE\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "\\REGISTRY\\MACHINE\\Software\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "MACHINE\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "MACHINE\\Software\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "MACHINE\\Software\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "MACHINE\\Software\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob"
    ) and
  not process.executable : (
          "?:\\Program Files (x86)\\*.exe",
          "?:\\Program Files\\*.exe",
          "?:\\ProgramData\\bomgar-*\\*\\sra-pin.exe",
          "?:\\ProgramData\\bomgar-*\\*\\bomgar-scc.exe",
          "?:\\ProgramData\\CTES\\Ctes.exe",
          "?:\\ProgramData\\CTES\\Components\\SNG\\AbtSngSvc.exe",
          "?:\\ProgramData\\CTES\\Components\\SVC\\CtesHostSvc.exe",
          "?:\\ProgramData\\Lenovo\\Vantage\\Addins\\LenovoHardwareScanAddin\\*\\LdeApi.Server.exe",
          "?:\\ProgramData\\Logishrd\\LogiOptionsPlus\\Plugins\\64\\certmgr.exe",
          "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\*.exe",
          "?:\\ProgramData\\Quest\\KACE\\modules\\clientidentifier\\clientidentifier.exe",
          "?:\\ProgramData\\Sophos\\AutoUpdate\\Cache\\sophos_autoupdate1.dir\\*.exe",
          "?:\\ProgramData\\tychoncloud\\bin\\OVAL\\tvs.exe",
          "?:\\Windows\\CCM\\CcmEval.exe",
          "?:\\Windows\\CCM\\CcmExec.exe",
          "?:\\Windows\\ccmsetup\\autoupgrade\\ccmsetup*.exe",
          "?:\\Windows\\ccmsetup\\cache\\ccmsetup.exe",
          "?:\\Windows\\ccmsetup\\ccmsetup.exe",
          "?:\\Windows\\Cluster\\clussvc.exe",
          "?:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe",
          "?:\\Windows\\Lenovo\\ImController\\PluginHost86\\Lenovo.Modern.ImController.PluginHost.Device.exe",
          "?:\\Windows\\Lenovo\\ImController\\Service\\Lenovo.Modern.ImController.exe",
          "?:\\Windows\\Sysmon.exe",
          "?:\\Windows\\Sysmon64.exe",
          "?:\\Windows\\UUS\\amd64\\MoUsoCoreWorker.exe",
          "?:\\Windows\\UUS\\amd64\\WaaSMedicAgent.exe",
          "?:\\Windows\\UUS\\Packages\\Preview\\amd64\\MoUsoCoreWorker.exe",
          "?:\\Windows\\WinSxS\\*.exe"
  ) and
  not
  (
    process.executable : (
      "?:\\Windows\\System32\\*.exe",
      "?:\\Windows\\SysWOW64\\*.exe"
    ) and
    not process.name : (
        "rundll32.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "expand.exe",
        "regsvr32.exe", "cscript.exe", "wscript.exe", "wmiprvse.exe", "certutil.exe", "xcopy.exe"
    )
  )
```



### Creation or Modification of a new GPO Scheduled Task or Service

Branch count: 4  
Document count: 4  
Index: geneve-ut-0277

```python
file where host.os.type == "windows" and event.type != "deletion" and event.action != "open" and
 file.name : ("ScheduledTasks.xml", "Services.xml") and
  file.path : (
    "?:\\Windows\\SYSVOL\\domain\\Policies\\*\\MACHINE\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
    "?:\\Windows\\SYSVOL\\domain\\Policies\\*\\MACHINE\\Preferences\\Services\\Services.xml"
  ) and
  not process.executable : "C:\\Windows\\System32\\dfsrs.exe"
```



### Credential Access via TruffleHog Execution

Branch count: 2  
Document count: 2  
Index: geneve-ut-0278

```python
process where event.type == "start" and process.name : ("trufflehog.exe", "trufflehog") and
process.args == "--json" and process.args == "filesystem"
```



### Credential Acquisition via Registry Hive Dumping

Branch count: 8  
Document count: 8  
Index: geneve-ut-0279

```python
process where host.os.type == "windows" and event.type == "start" and
 (?process.pe.original_file_name == "reg.exe" or process.name : "reg.exe") and
 process.args : ("save", "export") and
 process.args : ("hklm\\sam", "hklm\\security")
```



### Credential Dumping - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-0280

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:cred_theft_event or endgame.event_subtype_full:cred_theft_event)
```



### Credential Dumping - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-0281

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:cred_theft_event or endgame.event_subtype_full:cred_theft_event)
```



### Credential Manipulation - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-0282

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:token_manipulation_event or endgame.event_subtype_full:token_manipulation_event)
```



### Credential Manipulation - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-0283

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:token_manipulation_event or endgame.event_subtype_full:token_manipulation_event)
```



### Cron Job Created or Modified

Branch count: 160  
Document count: 160  
Index: geneve-ut-0284

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and file.path like (
  "/etc/cron.allow", "/etc/cron.deny", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*",
  "/etc/cron.monthly/*", "/etc/crontab", "/var/spool/cron/crontabs/*", "/var/spool/anacron/*"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/local/bin/dockerd", "/opt/elasticbeanstalk/bin/platform-engine",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/opt/imunify360/venv/bin/python3",
    "/opt/eset/efs/lib/utild", "/usr/sbin/anacron", "/usr/bin/podman", "/kaniko/kaniko-executor",
    "/usr/bin/pvedaemon", "./usr/bin/podman", "/usr/lib/systemd/systemd", "./usr/bin/podman", "/usr/bin/coreutils",
    "/usr/sbin/univention-config-registry", "/usr/bin/dnf5", "./usr/lib/snapd/snap-update-ns"
  ) or
  file.path like ("/var/spool/cron/crontabs/tmp.*", "/etc/cron.d/jumpcloud-updater") or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable like (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/libexec/platform-python*",
    "/var/lib/waagent/Microsoft*"
  ) or
  process.executable == null or
  process.name in (
    "crond", "executor", "puppet", "droplet-agent.postinst", "cf-agent", "schedd", "imunify-notifier",
    "jumpcloud-agent", "crio", "dnf_install", "utild"
  ) or
  (process.name == "sed" and file.name like "sed*") or
  (process.name == "perl" and file.name like "e2scrub_all.tmp*")  or
  (process.name in ("vi", "vim") and file.name like "*~")
)
```



### Cupsd or Foomatic-rip Shell Execution

Branch count: 32  
Document count: 32  
Index: geneve-ut-0286

```python
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and process.parent.name == "foomatic-rip" and
  process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and not (
    process.command_line like (
      "*/tmp/foomatic-*", "*-sDEVICE=ps2write*", "*printf*", "/bin/sh -e -c cat", "/bin/bash -c cat",
      "/bin/bash -e -c cat"
    ) or
    process.args like "gs*"
  )
```



### Curl Execution via Shell Profile

Branch count: 144  
Document count: 288  
Index: geneve-ut-0287

```python
sequence with maxspan=10s
  [process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and
    process.name in ("bash", "zsh", "sh") and
    process.args in ("-zsh", "-sh", "-bash") and process.args_count == 1 and
    process.parent.name == "login"] by process.entity_id
  [process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and
    process.name in ("curl", "nscurl") and
    process.args in ("-o", "--output", "--download", "-dl", "-dir", "--directory", "-F", "--form") and
    not process.args like ("https://upload.elastic.co*", "https://vault-ci-prod.elastic.dev", "https://artifacts.elastic.co*")] by process.parent.entity_id
```



### Curl SOCKS Proxy Activity from Unusual Parent

Branch count: 144  
Document count: 144  
Index: geneve-ut-0288

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name == "curl" and (
  process.parent.executable like (
    "/dev/shm/*", "/tmp/*", "/var/tmp/*", "/var/run/*", "/root/*", "/boot/*", "/var/www/*", "/opt/.*",
    "/home/*"
  ) or
  process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") or
  process.parent.name like ".*"
) and (
  process.args like ("--socks5-hostname", "--proxy", "--preproxy", "socks5*") or
  process.args == "-x" or
  process.env_vars like~ ("http_proxy=socks5h://*", "HTTPS_PROXY=socks5h://*", "ALL_PROXY=socks5h://*")
) and not (
  process.parent.args == "/opt/rudder/share/commands/agent-run" or
  process.args == "http://localhost:8080/rudder/api/status"
)
```



### Curl SOCKS Proxy Detected via Defend for Containers

Branch count: 5  
Document count: 5  
Index: geneve-ut-0289

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name == "curl" and process.args like ("--socks5-hostname", "--proxy", "--preproxy", "socks5*", "-x") and
process.interactive == true and container.id like "?*"
```



### Curl or Wget Spawned via Node.js

Branch count: 624  
Document count: 624  
Index: geneve-ut-0291

```python
process where event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.parent.name in ("node", "bun", "node.exe", "bun.exe") and (
(
  process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "cmd.exe", "bash.exe", "powershell.exe") and
  process.command_line like~ ("*curl*http*", "*wget*http*")
) or 
(
  process.name in ("curl", "wget", "curl.exe", "wget.exe")
)
) and not (
  process.command_line like ("*127.0.0.1*", "*localhost*", "*/home/*/.claude/shell-snapshots/*", "*/root/.claude/shell-snapshots/snapshot*") or
  process.parent.executable like ("/*/.cursor-server/*node", "/root/.nvm/*/node", "/*/.vscode-server/*/node", "/home/*/.nvm/*/node", "/home/*/cursor-agent/*/node") 
)
```



### CyberArk Privileged Access Security Error

Branch count: 1  
Document count: 1  
Index: geneve-ut-0292

```python
event.dataset:cyberarkpas.audit and event.type:error
```



### CyberArk Privileged Access Security Recommended Monitor

Branch count: 20  
Document count: 20  
Index: geneve-ut-0293

```python
event.dataset:cyberarkpas.audit and
  event.code:(4 or 22 or 24 or 31 or 38 or 57 or 60 or 130 or 295 or 300 or 302 or
              308 or 319 or 344 or 346 or 359 or 361 or 378 or 380 or 411) and
  not event.type:error
```



### D-Bus Service Created

Branch count: 64  
Document count: 64  
Index: geneve-ut-0294

```python
file where host.os.type == "linux" and event.type == "creation" and process.executable != null and
file.extension in ("service", "conf") and file.path like (
  "/usr/share/dbus-1/system-services/*", "/etc/dbus-1/system.d/*",
  "/lib/dbus-1/system-services/*", "/run/dbus/system.d/*",
  "/home/*/.local/share/dbus-1/services/*", "/home/*/.dbus/session-bus/*",
  "/usr/share/dbus-1/services/*", "/etc/dbus-1/session.d/*"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/bin/crio", "/usr/sbin/crond",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/kaniko/kaniko-executor",
    "/usr/local/bin/dockerd", "/usr/bin/podman", "/bin/install", "/proc/self/exe", "/usr/lib/systemd/systemd",
    "/usr/sbin/sshd", "/usr/bin/gitlab-runner", "/opt/gitlab/embedded/bin/ruby", "/usr/sbin/gdm", "/usr/bin/install",
    "/usr/local/manageengine/uems_agent/bin/dcregister", "./usr/bin/podman", "/.envbuilder/bin/envbuilder"
  ) or
  process.executable like (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*",
    "/var/lib/docker/overlay2/*/dockerd", "/var/lib/containers/storage/overlay/*/dockerd"
  ) or
  process.name like (
    "ssm-agent-worker", "platform-python*", "dnf_install", "cloudflared", "lxc-pve-prestart-hook",
    "convert-usrmerge", "elastic-agent", "google_metadata_script_runner", "update-alternatives", "gitlab-runner",
    "install", "crio", "apt-get", "package-cleanup", "dcservice", "dcregister", "jumpcloud-agent", "executor"
  ) or
  (process.name == "sed" and file.name like "sed*") or
  (process.name == "perl" and file.name like "e2scrub_all.tmp*") 
)
```



### DNF Package Manager Plugin File Creation

Branch count: 16  
Document count: 16  
Index: geneve-ut-0295

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and
file.path like ("/usr/lib/python*/site-packages/dnf-plugins/*", "/etc/dnf/plugins/*") and not (
  process.executable in (
    "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf", "/usr/bin/microdnf", "/bin/rpm",
    "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum", "/bin/dnf", "/usr/bin/dnf",
    "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet", "/bin/puppet",
    "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client", "/bin/autossl_check",
    "/usr/bin/autossl_check", "/proc/self/exe", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd",
    "/usr/libexec/netplan/generate", "./usr/bin/podman", "/usr/bin/dnf5", "/bin/needs-restarting",
    "/usr/bin/crio", "/usr/bin/insights-client", "/kaniko/executor"
  ) or
  file.extension in ("swp", "swpx", "swx") or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/*", "/usr/libexec/*",
    "/etc/kernel/*"
  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") or
  file.path like~ "/etc/dnf/plugins/.ansible_tmp*" or
  process.name like~ ("ssm-agent-worker, NinjaOrbit", "python*")
)
```



### DNS Enumeration Detected via Defend for Containers

Branch count: 556  
Document count: 556  
Index: geneve-ut-0296

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.interactive == true and container.id like "*" and 
(
  /* getent hosts is often used without a target arg */
  (process.name == "getent" and process.args == "hosts") or

  /* explicit DNS query tools */
  (
    process.name in ("nslookup", "dig", "host") or
    (
      /* Account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
      process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
      process.args in (
        "nslookup", "/bin/nslookup", "/usr/bin/nslookup", "/usr/local/bin/nslookup",
        "dig", "/bin/dig", "/usr/bin/dig", "/usr/local/bin/dig",
        "host", "/bin/host", "/usr/bin/host", "/usr/local/bin/host"
      ) and
      /* default exclusion list to not FP on default multi-process commands */
      not process.args in (
        "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
        "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
        "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
        "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
      )
    )
  ) and
  process.args like~ (
    "kubernetes.default",
    "kubernetes",
    "*.svc",
    "*.svc.cluster.local",
    "*.cluster.local"
  )
)
```



### DNS Global Query Block List Modified or Disabled

Branch count: 3  
Document count: 3  
Index: geneve-ut-0297

```python
registry where host.os.type == "windows" and event.type == "change" and registry.data.strings != null and
(
  (registry.value : "EnableGlobalQueryBlockList" and registry.data.strings : ("0", "0x00000000")) or
  (registry.value : "GlobalQueryBlockList" and not registry.data.strings : "wpad")
)
```



### DNS-over-HTTPS Enabled via Registry

Branch count: 5  
Document count: 5  
Index: geneve-ut-0300

```python
registry where host.os.type == "windows" and event.type == "change" and
  (registry.path : "*\\SOFTWARE\\Policies\\Microsoft\\Edge\\BuiltInDnsClientEnabled" and
  registry.data.strings : ("1", "0x00000001")) or
  (registry.path : "*\\SOFTWARE\\Google\\Chrome\\DnsOverHttpsMode" and
  registry.data.strings : "secure") or
  (registry.path : "*\\SOFTWARE\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS" and
  registry.data.strings : ("1", "0x00000001"))
```



### DebugFS Execution Detected via Defend for Containers

Branch count: 37  
Document count: 37  
Index: geneve-ut-0302

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name == "debugfs" or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "debugfs", "/bin/debugfs", "/usr/bin/debugfs", "/usr/local/bin/debugfs"
    ) and
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.args like "/dev/sd*" and not process.args == "-R" and
container.security_context.privileged == true and process.interactive == true and container.id like "*"
```



### Default Cobalt Strike Team Server Certificate

Branch count: 9  
Document count: 9  
Index: geneve-ut-0304

```python
(event.dataset: network_traffic.tls or event.category: (network or network_traffic))
  and (tls.server.hash.md5:950098276A495286EB2A2556FBAB6D83
  or tls.server.hash.sha1:6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C
  or tls.server.hash.sha256:87F2085C32B6A2CC709B365F55873E207A9CAA10BFFECF2FD16D3CF9D94D390C)
```



### Delete Volume USN Journal with Fsutil

Branch count: 2  
Document count: 2  
Index: geneve-ut-0307

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "fsutil.exe" or ?process.pe.original_file_name == "fsutil.exe") and
  process.args : "deletejournal" and process.args : "usn"
```



### Deprecated - EggShell Backdoor Execution

Branch count: 2  
Document count: 2  
Index: geneve-ut-0308

```python
event.category:process and event.type:(process_started or start) and process.name:espl and process.args:eyJkZWJ1ZyI6*
```



### Direct Interactive Kubernetes API Request Detected via Defend for Containers

Branch count: 56  
Document count: 56  
Index: geneve-ut-0311

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  (
    process.name == "curl" and
    process.args in ("-H", "--header") and
    process.args like "*Authorization: Bearer *" and
    (
      /* CA-specified */
      process.args in ("--cacert", "--capath") or
      /* insecure */
      process.args in ("-k", "--insecure")
    )
  ) or
  (
    process.name == "wget" and
    process.args like "--header*" and
    process.args like "*Authorization: Bearer *" and
    (
      /* CA-specified */
      process.args == "--ca-certificate" or
      /* insecure */
      process.args == "--no-check-certificate"
    )
  ) or
  (
    /* Account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in ("wget", "/bin/wget", "/usr/bin/wget", "/usr/local/bin/wget") and
    process.args like "--header*" and
    process.args like "*Authorization: Bearer*" and
    process.args == "--no-check-certificate"
  ) or
  (
    /* ssl_client is busybox-specific, so we need to handle it separately */
    process.name == "busybox" and
    process.args == "ssl_client" and
    process.args like "*Authorization: Bearer*"
  ) or
  (process.name == "openssl" and process.args == "s_client" and process.args == "-connect") or
  (process.name == "socat" and process.args like~ "*ssl*") or
  (process.name == "ncat" and process.args like "--ssl*") or
  (process.name == "kubectl" and process.args in ("get", "list", "watch", "create", "patch", "update"))
) and
process.interactive == true and container.id like "*"
```



### Directory Creation in /bin directory

Branch count: 24  
Document count: 24  
Index: geneve-ut-0314

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "start", "ProcessRollup2", "exec_event") and process.name == "mkdir" and
process.args like ("/bin/*", "/usr/bin/*", "/usr/local/bin/*", "/sbin/*", "/usr/sbin/*", "/usr/local/sbin/*") and
not process.args in ("/bin/mkdir", "/usr/bin/mkdir", "/usr/local/bin/mkdir", "/usr/local/bin/cursor", "/usr/bin/coreutils") and
not process.parent.executable in ("/usr/bin/make", "/bin/make")
```



### Disable Windows Event and Security Logs Using Built-in Tools

Branch count: 12  
Document count: 12  
Index: geneve-ut-0315

```python
process where host.os.type == "windows" and event.type == "start" and
(
  (
    (process.name:"logman.exe" or ?process.pe.original_file_name == "Logman.exe") and
    process.args : "EventLog-*" and process.args : ("stop", "delete")
  ) or
  (
    (
      process.name : ("pwsh.exe", "powershell.exe", "powershell_ise.exe") or
      ?process.pe.original_file_name in ("PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE")
    ) and
	  process.args : "Set-Service" and process.args: "EventLog" and process.args : "Disabled"
  )  or
  (
    (process.name:"auditpol.exe" or ?process.pe.original_file_name == "AUDITPOL.EXE") and process.args : "/success:disable"
  )
)
```



### Disable Windows Firewall Rules via Netsh

Branch count: 2  
Document count: 2  
Index: geneve-ut-0316

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "netsh.exe" and
  (
    (process.args : "disable" and process.args : "firewall" and process.args : "set") or
    (process.args : "advfirewall" and process.args : "off" and process.args : "state")
  )
```



### Disabling Lsa Protection via Registry Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-0317

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.data.strings != null and registry.value : "RunAsPPL" and
  registry.path : "*\\SYSTEM\\*ControlSet*\\Control\\Lsa\\RunAsPPL" and
  not registry.data.strings : ("1", "0x00000001", "2", "0x00000002")
```



### Disabling User Account Control via Registry Modification

Branch count: 6  
Document count: 6  
Index: geneve-ut-0318

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : ("EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop") and
  registry.data.strings : ("0", "0x00000000")

  /*
    Full registry key path omitted due to data source variations:
    HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA
    HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin
    HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop
  */
```



### Disabling Windows Defender Security Settings via PowerShell

Branch count: 24  
Document count: 24  
Index: geneve-ut-0319

```python
process where host.os.type == "windows" and event.type == "start" and
  (
    process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or
    ?process.pe.original_file_name in ("PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE")
  ) and
  process.args : "Set-MpPreference" and process.args : ("-Disable*", "Disabled", "NeverSend", "-Exclusion*")
```



### Discovery Command Output Written to Suspicious File

Branch count: 144  
Document count: 288  
Index: geneve-ut-0320

```python
sequence by process.entity_id with maxspan=15s
  [process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and
    process.parent.name in ("bash", "sh", "zsh") and
    process.name in ("whoami", "ifconfig", "system_profiler", "dscl", "arch", "csrutil") and
    process.args_count == 1]
  [file where host.os.type == "macos" and event.action == "modification" and
    file.path like ("/Users/Shared/*", "/tmp/*", "/private/tmp/*", "/Library/WebServer/*",
                    "/Library/Graphics/*", "/Library/Fonts/*", "/private/var/root/Library/HTTPStorages/*", "/*/.*") and
    not file.path like ("/private/tmp/*.fifo", "/private/tmp/tcl-tk*")]
```



### Discovery of Domain Groups

Branch count: 15  
Document count: 15  
Index: geneve-ut-0321

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started", "ProcessRollup2")
 and (
  process.name in ("ldapsearch", "dscacheutil") or (process.name == "dscl" and process.args : "*-list*")
)
```



### Docker Release File Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-0323

```python
file where host.os.type == "linux" and event.type == "creation" and file.name in ("release_agent", "notify_on_release") and
not process.executable in ("/usr/bin/podman", "/sbin/sos", "/sbin/sosreport", "/usr/bin/git")
```



### Docker Socket Enumeration

Branch count: 72  
Document count: 72  
Index: geneve-ut-0324

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name in ("curl", "socat", "nc", "netcat", "ncat", "nc.traditional") and
process.args like ("*/var/run/docker.sock*", "*/run/docker.sock*") and
process.parent.executable != null and
not (
  process.parent.executable in ("/usr/sbin/sshd", "/www/server/panel/BT-Panel") or
  process.parent.args in ("/usr/libexec/netdata/plugins.d/cgroup-name.sh", "/docker-entrypoint")
)
```



### Domain Added to Google Workspace Trusted Domains

Branch count: 1  
Document count: 1  
Index: geneve-ut-0325

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:ADD_TRUSTED_DOMAINS
```



### Downloaded URL Files

Branch count: 1  
Document count: 1  
Index: geneve-ut-0327

```python
file where host.os.type == "windows" and event.type == "creation" and file.extension == "url"
   and file.Ext.windows.zone_identifier == 3
```



### Dracut Module Creation

Branch count: 4  
Document count: 4  
Index: geneve-ut-0328

```python
file where host.os.type == "linux" and event.type == "creation" and process.executable != null and
file.path like~ ("/lib/dracut/modules.d/*", "/usr/lib/dracut/modules.d/*") and not (
  // Too many FPs from Python automation
  process.name like ("python*", "platform-python*") or
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/bin/crio", "/usr/sbin/crond",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/kaniko/kaniko-executor",
    "/usr/local/bin/dockerd", "/usr/bin/podman", "/bin/install", "/proc/self/exe", "/usr/lib/systemd/systemd",
    "/usr/sbin/sshd", "/usr/bin/gitlab-runner", "/opt/gitlab/embedded/bin/ruby", "/usr/sbin/gdm", "/usr/bin/install",
    "/usr/local/manageengine/uems_agent/bin/dcregister", "/usr/local/bin/pacman", "/usr/libexec/packagekitd",
    "./usr/bin/podman", "/usr/lib/dracut/dracut-install", "/usr/bin/dnf5", "/kaniko/executor", "/usr/bin/buildah",
    "/usr/sbin/yum-cron"
  ) or
  process.executable like~ (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*",
    "/var/lib/docker/overlay2/*/dockerd"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  (process.name == "sed" and file.name : "sed*")
)
```



### Dumping Account Hashes via Built-In Commands

Branch count: 8  
Document count: 8  
Index: geneve-ut-0329

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.name in ("defaults", "mkpassdb") and process.args like~ ("ShadowHashData", "-dump")
```



### Dumping of Keychain Content via Security Command

Branch count: 2  
Document count: 2  
Index: geneve-ut-0330

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and 
 process.args like~ "dump-keychain" and process.args == "-d"
```



### Dylib Injection via Process Environment Variables

Branch count: 2  
Document count: 4  
Index: geneve-ut-0331

```python
sequence by process.entity_id with maxspan=15s
  [process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and
    process.env_vars like ("DYLD_INSERT_LIBRARIES=?*", "LD_PRELOAD=?*") and
    not process.env_vars like ("DYLD_INSERT_LIBRARIES=", "LD_PRELOAD=", "LD_PRELOAD=<null>") and
    not process.executable like ("/Users/*/Library/Developer/Xcode/*", "/Users/*/Library/Developer/CoreSimulator/*") and
    not process.parent.executable like ("/usr/bin/xcrun", "/Applications/Xcode*.app/*", "/Library/Developer/*")]
  [library where host.os.type == "macos" and event.action == "load" and
    not dll.name like ("*.aot", "*.so") and
    not dll.code_signature.trusted == true and
    not dll.path like ("/System/*", "/usr/lib/*", "/opt/homebrew/*", "/private/var/folders/*",
                       "/Library/Apple/*", "/Library/Developer/*",
                       "/Users/*/Library/Developer/Xcode/*", "/Users/*/Library/Developer/CoreSimulator/*")]
```



### Dynamic Linker (ld.so) Creation

Branch count: 4  
Document count: 4  
Index: geneve-ut-0333

```python
file where host.os.type == "linux" and event.type == "creation" and process.executable != null and
file.path like~ ("/lib/ld-linux*.so*", "/lib64/ld-linux*.so*", "/usr/lib/ld-linux*.so*", "/usr/lib64/ld-linux*.so*") and
not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/libexec/platform-python",
    "/usr/lib/snapd/snap-update-ns", "./usr/bin/podman", "/usr/bin/crio", "/usr/bin/buildah", "/bin/dnf5",
    "/usr/bin/dnf5", "/usr/bin/pamac", "/dev/fd/3"
  ) or
  process.executable like (
    "/snap/docker/*/bin/dockerd", "/usr/bin/python*", "/nix/store/*/docker/dockerd", "/var/lib/docker/overlay2/*/dockerd",
    "/rpool/data/*usr/bin/dockerd"
  )
)
```



### Dynamic Linker Copy

Branch count: 30  
Document count: 60  
Index: geneve-ut-0334

```python
sequence by process.entity_id with maxspan=1m
[process where host.os.type == "linux" and event.type == "start" and process.name in ("cp", "rsync", "mv") and
   process.args in (
     "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/etc/ld.so.preload", "/lib64/ld-linux-x86-64.so.2",
     "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/usr/lib64/ld-linux-x86-64.so.2"
    )]
[file where host.os.type == "linux" and event.action == "creation" and (file.extension == "so" or file.name like "*.so.*")]
```



### Dynamic Linker Creation

Branch count: 48  
Document count: 48  
Index: geneve-ut-0335

```python
file where host.os.type == "linux" and event.action == "creation" and
file.path like ("/etc/ld.so.preload", "/etc/ld.so.conf.d/*", "/etc/ld.so.conf") and
not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/libexec/platform-python",
    "/usr/lib/snapd/snap-update-ns", "/usr/bin/vmware-config-tools.pl", "./usr/bin/podman", "/bin/nvidia-cdi-hook",
    "/usr/lib/dracut/dracut-install", "./usr/bin/nvidia-cdi-hook", "/.envbuilder/bin/envbuilder", "/usr/bin/buildah",
    "/usr/sbin/dnf", "/usr/bin/pamac", "/sbin/pacman", "/usr/bin/crio", "/usr/sbin/yum-cron"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*", "/opt/dynatrace/oneagent/*",
    "/usr/libexec/platform-python*"
  ) or
  process.executable == null or
  process.name in (
    "java", "executor", "ssm-agent-worker", "packagekitd", "crio", "dockerd-entrypoint.sh",
    "docker-init", "BootTimeChecker", "dockerd (deleted)", "dockerd"
  ) or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") or
  (process.name == "init" and file.name == "ld.wsl.conf") or
  (process.name == "sshd" and file.extension == "dpkg-new")
)
```



### Dynamic Linker Modification Detected via Defend for Containers

Branch count: 3  
Document count: 3  
Index: geneve-ut-0336

```python
file where host.os.type == "linux" and event.type != "deletion" and
file.path like ("/etc/ld.so.preload", "/etc/ld.so.conf.d/*", "/etc/ld.so.conf") and
process.interactive == true and container.id like "*"
```



### ESXI Discovery via Find

Branch count: 18  
Document count: 18  
Index: geneve-ut-0337

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "executed", "process_started", "ProcessRollup2") and
process.name == "find" and process.args like ("/etc/vmware/*", "/usr/lib/vmware/*", "/vmfs/*") and
not ?process.parent.executable == "/usr/lib/vmware/viewagent/bin/uninstall_viewagent.sh"
```



### ESXI Discovery via Grep

Branch count: 162  
Document count: 162  
Index: geneve-ut-0338

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "executed", "process_started", "ProcessRollup2") and
process.name in ("grep", "egrep", "pgrep") and
process.args in ("vmdk", "vmx", "vmxf", "vmsd", "vmsn", "vswp", "vmss", "nvram", "vmem") and
not ?process.parent.executable in ("/usr/share/qemu/init/qemu-kvm-init", "/etc/sysconfig/modules/kvm.modules")
```



### ESXI Timestomping using Touch Command

Branch count: 18  
Document count: 18  
Index: geneve-ut-0339

```python
process where host.os.type == "linux" and event.type == "start" and
 event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
 process.name == "touch" and process.args == "-r" and process.args : ("/etc/vmware/*", "/usr/lib/vmware/*", "/vmfs/*")
```



### Egress Connection from Entrypoint in Container

Branch count: 2  
Document count: 4  
Index: geneve-ut-0340

```python
sequence by host.id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.entry_leader.entry_meta.type == "container" and process.name == "entrypoint.sh"] by process.entity_id
  [network where event.type == "start" and event.action == "connection_attempted" and process.executable != null and
   not (
     destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
       destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
       "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
       "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
       "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
       "FF00::/8", "172.31.0.0/16"
       ) or
    // Excluding vast majority of noise
    (process.name like ("python*", "pip*") and destination.port == 443)
    )] by process.parent.entity_id
```



### Elastic Agent Service Terminated

Branch count: 248  
Document count: 248  
Index: geneve-ut-0341

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
  (process.name in ("systemctl", "service", "chkconfig", "update-rc.d") and
    process.args : ("elastic-agent", "elastic-agent.service") and
    process.args : ("stop", "disable", "remove", "off", "kill", "mask"))
  or
  /* pkill , killall used to stop Elastic Agent on Linux */
  ( event.type == "end" and process.name in ("pkill", "killall", "kill") and process.args: "elastic-agent")
  or
  /* Unload Elastic Agent extension on MacOS */
  (process.name : "kextunload" and
    process.args : "com.apple.iokit.EndpointSecurity" and
    event.action : "end"))
```



### Emond Rules Creation or Modification

Branch count: 3  
Document count: 3  
Index: geneve-ut-0345

```python
file where host.os.type == "macos" and event.action == "modification" and
 file.path like ("/private/etc/emond.d/rules/*.plist", "/etc/emon.d/rules/*.plist", "/private/var/db/emondClients/*")
```



### Enable Host Network Discovery via Netsh

Branch count: 2  
Document count: 2  
Index: geneve-ut-0346

```python
process where host.os.type == "windows" and event.type == "start" and
process.name : "netsh.exe" and
process.args : ("firewall", "advfirewall") and process.args : "group=Network Discovery" and process.args : "enable=Yes"
```



### Encoded Executable Stored in the Registry

Branch count: 1  
Document count: 1  
Index: geneve-ut-0347

```python
registry where host.os.type == "windows" and
/* update here with encoding combinations */
 registry.data.strings : "TVqQAAMAAAAEAAAA*"
```



### Encoded Payload Detected via Defend for Containers

Branch count: 12  
Document count: 12  
Index: geneve-ut-0348

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.interactive == true and (
  (process.name in ("base64", "base64plain", "base64url", "base64mime", "base64pem", "base32", "base16") and process.args like~ "*-*d*") or
  (process.name == "xxd" and process.args like~ ("-*r*", "-*p*")) or
  (process.name == "openssl" and process.args == "enc" and process.args in ("-d", "-base64", "-a")) or
  (process.name like "python*" and (
    (process.args == "base64" and process.args in ("-d", "-u", "-t")) or
    (process.args == "-c" and process.args like "*base64*" and process.args like "*b64decode*")
  )) or
  (process.name like "perl*" and process.args like "*decode_base64*") or
  (process.name like "ruby*" and process.args == "-e" and process.args like "*Base64.decode64*")
) and container.id like "?*"
```



### Encrypting Files with WinRar or 7z

Branch count: 20  
Document count: 20  
Index: geneve-ut-0349

```python
process where host.os.type == "windows" and event.type == "start" and
(
  (
    (
      process.name : ("rar.exe", "WinRAR.exe") or ?process.code_signature.subject_name == "win.rar GmbH" or
      ?process.pe.original_file_name == "WinRAR.exe"
    ) and
    process.args == "a" and process.args : ("-hp*", "-p*", "/hp*", "/p*")
  ) or
  (
    (process.name : ("7z.exe", "7za.exe") or ?process.pe.original_file_name in ("7z.exe", "7za.exe")) and
    process.args == "a" and process.args : "-p*"
  )
) and
  not process.parent.executable : (
        "C:\\Program Files\\*.exe",
        "C:\\Program Files (x86)\\*.exe",
        "?:\\ManageEngine\\*\\jre\\bin\\java.exe",
        "?:\\Nox\\bin\\Nox.exe",
        "\\Device\\HarddiskVolume?\\Program Files\\*.exe",
        "\\Device\\HarddiskVolume?\\Program Files (x86)\\*.exe",
        "\\Device\\HarddiskVolume?\\ManageEngine\\*\\jre\\bin\\java.exe",
        "\\Device\\HarddiskVolume?\\Nox\\bin\\Nox.exe"
      )
```



### Endpoint Security (Elastic Defend)

Branch count: 1  
Document count: 1  
Index: geneve-ut-0350

```python
event.kind:alert and event.module:(endpoint and not endgame)
```



### Entra ID Application Credential Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-0353

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Update application - Certificates and secrets management" and event.outcome:(success or Success)
```



### Entra ID External Guest User Invited

Branch count: 2  
Document count: 2  
Index: geneve-ut-0360

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Invite external user" and azure.auditlogs.properties.target_resources.*.display_name:guest and event.outcome:(Success or success)
```



### Entra ID Global Administrator Role Assigned

Branch count: 1  
Document count: 1  
Index: geneve-ut-0361

```python
event.dataset:azure.auditlogs and
    azure.auditlogs.properties.category:RoleManagement and
    azure.auditlogs.operation_name:"Add member to role" and
    azure.auditlogs.properties.target_resources.*.modified_properties.*.new_value: "\"Global Administrator\""
```



### Entra ID Global Administrator Role Assigned (PIM User)

Branch count: 4  
Document count: 4  
Index: geneve-ut-0362

```python
event.dataset:azure.auditlogs and azure.auditlogs.properties.category:RoleManagement and
    azure.auditlogs.operation_name:("Add eligible member to role in PIM completed (permanent)" or
                                    "Add member to role in PIM completed (timebound)") and
    azure.auditlogs.properties.target_resources.*.display_name:"Global Administrator" and
    event.outcome:(Success or success)
```



### Entra ID High Risk Sign-in

Branch count: 2  
Document count: 2  
Index: geneve-ut-0363

```python
event.dataset:azure.signinlogs and
  (
    azure.signinlogs.properties.risk_level_during_signin:high or
    azure.signinlogs.properties.risk_level_aggregated:high
  )
```



### Entra ID High Risk User Sign-in Heuristic

Branch count: 4  
Document count: 4  
Index: geneve-ut-0364

```python
event.dataset:azure.signinlogs and
  azure.signinlogs.properties.risk_state:("confirmedCompromised" or "atRisk") and event.outcome:(success or Success)
```



### Entra ID MFA Disabled for User

Branch count: 4  
Document count: 4  
Index: geneve-ut-0366

```python
event.dataset: "azure.auditlogs" and
    (azure.auditlogs.operation_name: "Disable Strong Authentication" or
    (
        azure.auditlogs.operation_name: "User deleted security info" and
        azure.auditlogs.properties.additional_details.key: "AuthenticationMethod"
    )) and event.outcome: (Success or success)
```



### Entra ID OAuth Device Code Grant by Microsoft Authentication Broker

Branch count: 3  
Document count: 3  
Index: geneve-ut-0370

```python
event.dataset:(azure.activitylogs or azure.signinlogs)
    and azure.signinlogs.properties.authentication_protocol:deviceCode
    and azure.signinlogs.properties.conditional_access_audiences.application_id:29d9ed98-a469-4536-ade2-f981bc1d605e
    and event.outcome:success or (
        azure.activitylogs.properties.appId:29d9ed98-a469-4536-ade2-f981bc1d605e
        and azure.activitylogs.properties.authentication_protocol:deviceCode)
```



### Entra ID OAuth PRT Issuance to Non-Managed Device Detected

Branch count: 1  
Document count: 2  
Index: geneve-ut-0373

```python
sequence by azure.signinlogs.properties.user_id, azure.signinlogs.properties.device_detail.device_id with maxspan=1h
  [authentication where
    event.dataset == "azure.signinlogs" and
    azure.signinlogs.category == "NonInteractiveUserSignInLogs" and
    azure.signinlogs.properties.app_id == "29d9ed98-a469-4536-ade2-f981bc1d605e" and
    azure.signinlogs.properties.incoming_token_type == "refreshToken" and
    azure.signinlogs.properties.device_detail.trust_type == "Azure AD joined" and
    azure.signinlogs.properties.device_detail.device_id != null and
    azure.signinlogs.properties.token_protection_status_details.sign_in_session_status == "unbound" and
    azure.signinlogs.properties.user_type == "Member" and
    azure.signinlogs.result_signature == "SUCCESS"
  ]
  [authentication where
    event.dataset == "azure.signinlogs" and
    azure.signinlogs.properties.incoming_token_type == "primaryRefreshToken" and
    azure.signinlogs.properties.resource_display_name != "Device Registration Service" and
    azure.signinlogs.result_signature == "SUCCESS" and
    azure.signinlogs.properties.device_detail.is_managed != true
    and not (
        azure.signinlogs.properties.app_display_name == "Windows Sign In" or
        user_agent.original == "Windows-AzureAD-Authentication-Provider/1.0"
    )
  ]
```



### Entra ID OAuth Phishing via First-Party Microsoft Application

Branch count: 78  
Document count: 78  
Index: geneve-ut-0374

```python
event.dataset: "azure.signinlogs" and
event.action: "Sign-in activity" and
event.outcome: "success" and
(
  (
    azure.signinlogs.properties.app_id: (
      "aebc6443-996d-45c2-90f0-388ff96faa56" or
      "04b07795-8ddb-461a-bbee-02f9e1bf7b46" or
      "1950a258-227b-4e31-a9cf-717495945fc2"
    ) and (
      azure.signinlogs.properties.resource_id: ("00000003-0000-0000-c000-000000000000" or "00000002-0000-0000-c000-000000000000") or
      azure.signinlogs.properties.resource_display_name: ("Microsoft Graph" or "Windows Azure Active Directory")
    )
  ) or
  (
    azure.signinlogs.properties.app_id: (
      "00b41c95-dab0-4487-9791-b9d2c32c80f2" or
      "1fec8e78-bce4-4aaf-ab1b-5451cc387264" or
      "26a7ee05-5602-4d76-a7ba-eae8b7b67941" or
      "27922004-5251-4030-b22d-91ecd9a37ea4" or
      "4813382a-8fa7-425e-ab75-3b753aab3abb" or
      "ab9b8c07-8f02-4f72-87fa-80105867a763" or
      "872cd9fa-d31f-45e0-9eab-6e460a02d1f1" or
      "af124e86-4e96-495a-b70a-90f90ab96707" or
      "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8" or
      "844cca35-0656-46ce-b636-13f48b0eecbd" or
      "87749df4-7ccf-48f8-aa87-704bad0e0e16" or
      "cf36b471-5b44-428c-9ce7-313bf84528de" or
      "0ec893e0-5785-4de6-99da-4ed124e5296c" or
      "22098786-6e16-43cc-a27d-191a01a1e3b5" or
      "4e291c71-d680-4d0e-9640-0a3358e31177" or
      "57336123-6e14-4acc-8dcf-287b6088aa28" or
      "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0" or
      "66375f6b-983f-4c2c-9701-d680650f588f" or
      "a40d7d7d-59aa-447e-a655-679a4107e548" or
      "a569458c-7f2b-45cb-bab9-b7dee514d112" or
      "b26aadf8-566f-4478-926f-589f601d9c74" or
      "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12" or
      "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0" or
      "e9c51622-460d-4d3d-952d-966a5b1da34c" or
      "eb539595-3fe1-474e-9c1d-feb3625d1be5" or
      "ecd6b820-32c2-49b6-98a6-444530e5a77a" or
      "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d" or
      "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34" or
      "be1918be-3fe3-4be9-b32b-b542fc27f02e" or
      "cab96880-db5b-4e15-90a7-f3f1d62ffe39" or
      "d7b530a4-7680-4c23-a8bf-c52c121d2e87" or
      "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3" or
      "e9b154d0-7658-433b-bb25-6b8e0a8a7c59"
    ) and (
      azure.signinlogs.properties.resource_id: "00000002-0000-0000-c000-000000000000" or
      azure.signinlogs.properties.resource_display_name: "Windows Azure Active Directory"
    )
  )
)
```



### Entra ID PowerShell Sign-in

Branch count: 2  
Document count: 2  
Index: geneve-ut-0379

```python
event.dataset:azure.signinlogs and
  azure.signinlogs.properties.app_display_name:"Azure Active Directory PowerShell" and
  azure.signinlogs.properties.token_issuer_type:AzureAD and event.outcome:(success or Success)
```



### Entra ID Privileged Identity Management (PIM) Role Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-0380

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Update role setting in PIM" and event.outcome:(Success or success)
```



### Entra ID Protection - Risk Detection

Branch count: 1  
Document count: 1  
Index: geneve-ut-0381

```python
event.dataset: "azure.identity_protection"
```



### Entra ID Protection - Risk Detection - Sign-in Risk

Branch count: 1  
Document count: 1  
Index: geneve-ut-0382

```python
event.dataset: "azure.identity_protection" and
    event.action: "User Risk Detection" and
    azure.identityprotection.properties.activity: "signin" and
    not azure.identityprotection.properties.risk_state: (
        "remediated" or "dismissed" or "confirmedSafe"
    )
```



### Entra ID Protection - Risk Detection - User Risk

Branch count: 2  
Document count: 2  
Index: geneve-ut-0383

```python
event.dataset: "azure.identity_protection" and
    event.action: ("User Risk Detection" or "Risky user") and
    azure.identityprotection.properties.activity: "user" and
    not azure.identityprotection.properties.risk_state: (
        "remediated" or "dismissed" or "confirmedSafe"
    )
```



### Entra ID Protection Admin Confirmed Compromise

Branch count: 2  
Document count: 2  
Index: geneve-ut-0384

```python
event.dataset: azure.identity_protection and
    azure.identityprotection.properties.risk_detail: (
        "adminConfirmedSigninCompromised" or
        "adminConfirmedUserCompromised"
    )
```



### Entra ID Protection Alerts for User Detected

Branch count: 1  
Document count: 2  
Index: geneve-ut-0385

```python
sequence by azure.identityprotection.properties.user_principal_name with maxspan=10m
[any where event.module == "azure" and event.dataset == "azure.identity_protection"] with runs=2
```



### Entra ID Protection User Alert and Device Registration

Branch count: 1  
Document count: 2  
Index: geneve-ut-0386

```python
sequence with maxspan=5m
[any where event.dataset == "azure.identity_protection"] by azure.identityprotection.properties.user_principal_name
[any where event.dataset == "azure.auditlogs" and event.action == "Register device"] by azure.auditlogs.properties.initiated_by.user.userPrincipalName
```



### Entra ID Service Principal Created

Branch count: 2  
Document count: 2  
Index: geneve-ut-0387

```python
event.dataset:azure.auditlogs
    and azure.auditlogs.operation_name:"Add service principal"
    and event.outcome:(success or Success)
    and not azure.auditlogs.identity: (
        "Managed Service Identity" or
        "Windows Azure Service Management API" or
        "Microsoft Azure AD Internal - Jit Provisioning" or
        "AAD App Management" or
        "Power Virtual Agents Service"
        )
```



### Entra ID Sign-in TeamFiltration User-Agent Detected

Branch count: 4  
Document count: 4  
Index: geneve-ut-0392

```python
event.dataset:("azure.signinlogs" or "o365.audit")
    and ((user_agent.name:"Electron" and user_agent.os.name:"Windows" and user_agent.version:"8.5.1") or
    user_agent.original:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.30866 Chrome/80.0.3987.165 Electron/8.5.1 Safari/537.36")
```



### Entra ID User Added as Registered Application Owner

Branch count: 2  
Document count: 2  
Index: geneve-ut-0393

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add owner to application" and event.outcome:(Success or success)
```



### Entra ID User Added as Service Principal Owner

Branch count: 2  
Document count: 2  
Index: geneve-ut-0394

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add owner to service principal" and event.outcome:(Success or success)
```



### Entra ID User Reported Suspicious Activity

Branch count: 1  
Document count: 1  
Index: geneve-ut-0395

```python
event.dataset: "azure.auditlogs"
    and azure.auditlogs.operation_name: "Suspicious activity reported"
    and azure.auditlogs.properties.additional_details.key: "AuthenticationMethod"
    and azure.auditlogs.properties.target_resources.*.type: "User"
    and event.outcome: "success"
```



### Enumerating Domain Trusts via DSQUERY.EXE

Branch count: 2  
Document count: 2  
Index: geneve-ut-0400

```python
process where host.os.type == "windows" and event.type == "start" and
    (process.name : "dsquery.exe" or ?process.pe.original_file_name: "dsquery.exe") and 
    process.args : "*objectClass=trustedDomain*"
```



### Enumerating Domain Trusts via NLTEST.EXE

Branch count: 21  
Document count: 21  
Index: geneve-ut-0401

```python
process where host.os.type == "windows" and event.type == "start" and
    process.name : "nltest.exe" and process.args : (
        "/DCLIST:*", "/DCNAME:*", "/DSGET*",
        "/LSAQUERYFTI:*", "/PARENTDOMAIN",
        "/DOMAIN_TRUSTS", "/BDC_QUERY:*"
        ) and 
not process.parent.name : "PDQInventoryScanner.exe" and
not (
  user.id in ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
  /* Don't apply the user.id exclusion to Sysmon for compatibility */
  not event.dataset : ("windows.sysmon_operational", "windows.sysmon")
)
```



### Enumeration of Administrator Accounts

Branch count: 64  
Document count: 64  
Index: geneve-ut-0403

```python
process where host.os.type == "windows" and event.type == "start" and
(
  (
    (
      (process.name : "net.exe" or ?process.pe.original_file_name == "net.exe") or
      ((process.name : "net1.exe" or ?process.pe.original_file_name == "net1.exe") and not process.parent.name : "net.exe")
    ) and
    process.args : ("group", "user", "localgroup") and
    process.args : ("*admin*", "Domain Admins", "Remote Desktop Users", "Enterprise Admins", "Organization Management")
    and not process.args : ("/add", "/delete")
  ) or
  (
    (process.name : "wmic.exe" or ?process.pe.original_file_name == "wmic.exe") and
    process.args : ("group", "useraccount")
  )
) and not user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20")
```



### Enumeration of Users or Groups via Built-in Commands

Branch count: 276  
Document count: 276  
Index: geneve-ut-0406

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  (
    process.name in ("ldapsearch", "dsmemberutil") or
    (process.name == "dscl" and
      process.args in ("read", "-read", "list", "-list", "ls", "search", "-search") and
      process.args like ("/Active Directory/*", "/Users*", "/Groups*"))
	) and
  ((process.Ext.effective_parent.executable like "/Volumes/*" or process.parent.executable like "/Volumes/*") or
   (process.Ext.effective_parent.name : ".*" or process.parent.name : ".*") or
   (process.parent.code_signature.trusted == false or process.parent.code_signature.exists == false))
```



### Environment Variable Enumeration Detected via Defend for Containers

Branch count: 74  
Document count: 74  
Index: geneve-ut-0407

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name in ("env", "printenv") or
  (
    /* Account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "env", "/bin/env", "/usr/bin/env", "/usr/local/bin/env",
      "printenv", "/bin/printenv", "/usr/bin/printenv", "/usr/local/bin/printenv"
    ) and
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and
process.interactive == true and container.id like "*"
```



### Executable Bit Set for Potential Persistence Script

Branch count: 648  
Document count: 648  
Index: geneve-ut-0410

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
process.args : (
  // Misc.
  "/etc/rc.local", "/etc/rc.common", "/etc/rc.d/rc.local", "/etc/init.d/*", "/etc/update-motd.d/*",
  "/etc/apt/apt.conf.d/*", "/etc/cron*", "/etc/init/*", "/etc/NetworkManager/dispatcher.d/*",
  "/lib/dracut/modules.d/*", "/usr/lib/dracut/modules.d/*",

  // XDG
  "/etc/xdg/autostart/*", "/home/*/.config/autostart/*", "/root/.config/autostart/*",
  "/home/*/.local/share/autostart/*", "/root/.local/share/autostart/*", "/home/*/.config/autostart-scripts/*",
  "/root/.config/autostart-scripts/*", "/etc/xdg/autostart/*", "/usr/share/autostart/*",

  // udev
  "/lib/udev/*", "/etc/udev/rules.d/*", "/usr/lib/udev/rules.d/*", "/run/udev/rules.d/*"

) and (
  (process.name == "chmod" and process.args : ("+x*", "1*", "3*", "5*", "7*")) or
  (process.name == "install" and process.args : "-m*" and process.args : ("7*", "5*", "3*", "1*"))
) and not (
  process.parent.executable : "/var/lib/dpkg/*" or
  process.command_line in ("chmod 777 /etc/update-motd.d/", "chmod 755 /etc/update-motd.d/")
)
```



### Executable File Download via Wget

Branch count: 10  
Document count: 20  
Index: geneve-ut-0412

```python
sequence by process.entity_id with maxspan=30s
  [network where host.os.type == "macos" and event.type == "start" and process.name == "wget"]
  [file where host.os.type == "macos" and event.action == "modification" and 
    process.name == "wget" and 
    file.path like ("/tmp/*", "/private/tmp/*", "/private/var/tmp/*", "/var/tmp/*", "/Users/Shared/*") and
    file.Ext.header_bytes like~ ("cffaedfe*", "cafebabe*")]
```



### Executable File with Unusual Extension

Branch count: 64  
Document count: 64  
Index: geneve-ut-0413

```python
file where host.os.type == "windows" and event.action != "deletion" and

 /* MZ header or its common base64 equivalent TVqQ */
 file.Ext.header_bytes : ("4d5a*", "54567151*") and

 (
   /* common image file extensions */
   file.extension : ("jpg", "jpeg", "emf", "tiff", "gif", "png", "bmp", "fpx", "eps", "svg", "inf") or

   /* common audio and video file extensions */
   file.extension : ("mp3", "wav", "avi", "mpeg", "flv", "wma", "wmv", "mov", "mp4", "3gp") or

   /* common document file extensions */
   file.extension : ("txt", "pdf", "doc", "docx", "rtf", "ppt", "pptx", "xls", "xlsx", "hwp", "html")
  ) and
  not process.pid == 4 and
  not process.executable : "?:\\Program Files (x86)\\Trend Micro\\Client Server Security Agent\\Ntrtscan.exe"
```



### Executable Masquerading as Kernel Process

Branch count: 8  
Document count: 8  
Index: geneve-ut-0414

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.name : ("kworker*", "kthread*") and process.executable != null
```



### Execution from a Removable Media with Network Connection

Branch count: 4  
Document count: 8  
Index: geneve-ut-0416

```python
sequence by process.entity_id with maxspan=5m
 [process where host.os.type == "windows" and event.action == "start" and

  /* Direct Exec from USB */
  (process.Ext.device.bus_type : "usb" or process.Ext.device.product_id : "USB *") and
  (process.code_signature.trusted == false or process.code_signature.exists == false) and

  not process.code_signature.status : ("errorExpired", "errorCode_endpoint*")]
 [network where host.os.type == "windows" and event.action == "connection_attempted"]
```



### Execution of COM object via Xwizard

Branch count: 4  
Document count: 4  
Index: geneve-ut-0417

```python
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "xwizard.exe" or ?process.pe.original_file_name : "xwizard.exe") and
 (
   (process.args : "RunWizard" and process.args : "{*}") or
   (process.executable != null and
     not process.executable : (
        "C:\\Windows\\SysWOW64\\xwizard.exe",
        "C:\\Windows\\System32\\xwizard.exe",

        /* Crowdstrike specific exclusion as it uses NT Object paths */
        "\\Device\\HarddiskVolume*\\Windows\\SysWOW64\\xwizard.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\xwizard.exe"
     )
   )
 )
```



### Execution of File Written or Modified by Microsoft Office

Branch count: 72  
Document count: 144  
Index: geneve-ut-0418

```python
sequence with maxspan=2h
  [file where host.os.type == "windows" and event.type != "deletion" and file.extension : "exe" and
     (process.name : "WINWORD.EXE" or
      process.name : "EXCEL.EXE" or
      process.name : "OUTLOOK.EXE" or
      process.name : "POWERPNT.EXE" or
      process.name : "eqnedt32.exe" or
      process.name : "fltldr.exe" or
      process.name : "MSPUB.EXE" or
      process.name : "MSACCESS.EXE")
  ] by host.id, file.path
  [process where host.os.type == "windows" and event.type == "start" and 
   not (process.name : "NewOutlookInstaller.exe" and process.code_signature.subject_name : "Microsoft Corporation" and process.code_signature.trusted == true) and 
   not (process.name : "ShareFileForOutlook-v*.exe" and process.code_signature.subject_name : "Citrix Systems, Inc." and process.code_signature.trusted == true)
  ] by host.id, process.executable
```



### Execution of Persistent Suspicious Program

Branch count: 54  
Document count: 162  
Index: geneve-ut-0419

```python
/* userinit followed by explorer followed by early child process of explorer (unlikely to be launched interactively) within 1m */
sequence by host.id, user.name with maxspan=1m
  [process where host.os.type == "windows" and event.type == "start" and process.name : "userinit.exe" and process.parent.name : "winlogon.exe"]
  [process where host.os.type == "windows" and event.type == "start" and process.name : "explorer.exe"]
  [process where host.os.type == "windows" and event.type == "start" and process.parent.name : "explorer.exe" and
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
Index: geneve-ut-0422

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and 
 process.args == "-e" and process.args : "const*require*child_process*"
```



### Execution via GitHub Actions Runner

Branch count: 468  
Document count: 468  
Index: geneve-ut-0423

```python
process where event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
 process.parent.name in ("Runner.Worker", "Runner.Worker.exe") and
 (
   process.name like ("curl", "curl.exe", "wget", "wget.exe", "powershell.exe", "cmd.exe", "pwsh.exe", "certutil.exe", "rundll32.exe", "bash", "sh", "zsh", "tar", "rm",
                     "sed", "osascript", "chmod", "nohup", "setsid", "dash", "ash", "tcsh", "csh", "ksh", "fish", "python*", "perl*", "ruby*", "lua*", "php*", "node", "node.exe") or
   process.executable : ("/tmp/*", "/private/tmp/*", "/var/tmp/*", "/dev/shm/*", "/run/*", "/var/run/*", "?:\\Users\\*")
 )
```



### Execution via Microsoft DotNet ClickOnce Host

Branch count: 2  
Document count: 4  
Index: geneve-ut-0426

```python
sequence by user.id with maxspan=5s
 [process where host.os.type == "windows" and event.action == "start" and
  process.name : "rundll32.exe" and process.command_line : ("*dfshim*ShOpenVerbApplication*", "*dfshim*#*")]
 [network where host.os.type == "windows" and process.name : "dfsvc.exe"]
```



### Execution via OpenClaw Agent

Branch count: 90  
Document count: 90  
Index: geneve-ut-0427

```python
process where event.type == "start" and
  process.parent.name : ("node", "node.exe") and 
  process.parent.command_line : ("*openclaw*", "*moltbot*", "*clawdbot*") and
   process.name : ("bash", "sh", "zsh", "bash.exe", "cmd.exe", "powershell.exe", "curl.exe", "curl", "base64", "xattr", "osascript", "python*", "chmod", "certutil.exe", "rundll32.exe")
```



### Execution via TSClient Mountpoint

Branch count: 1  
Document count: 1  
Index: geneve-ut-0428

```python
process where host.os.type == "windows" and event.type == "start" and process.executable : "\\Device\\Mup\\tsclient\\*.exe"
```



### Execution via Windows Command Debugging Utility

Branch count: 6  
Document count: 6  
Index: geneve-ut-0429

```python
process where host.os.type == "windows" and event.type == "start" and
 (?process.pe.original_file_name == "CDB.Exe" or process.name : "cdb.exe") and
  process.args : ("-cf", "-c", "-pd") and
  not process.executable : (
        "?:\\Program Files (x86)\\*\\cdb.exe",
        "?:\\Program Files\\*\\cdb.exe",

        /* Crowdstrike specific exclusion as it uses NT Object paths */
        "\\Device\\HarddiskVolume*\\Program Files (x86)\\*\\cdb.exe",
        "\\Device\\HarddiskVolume*\\Program Files\\*\\cdb.exe"
  )
```



### Execution via Windows Subsystem for Linux

Branch count: 4  
Document count: 4  
Index: geneve-ut-0430

```python
process where host.os.type == "windows" and event.type : "start" and
  process.parent.name : ("wsl.exe", "wslhost.exe") and
  not process.executable : (
        "?:\\Program Files (x86)\\*",
        "?:\\Program Files\\*",
        "?:\\Program Files*\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_*\\wsl*.exe",
        "?:\\Windows\\System32\\conhost.exe",
        "?:\\Windows\\System32\\lxss\\wslhost.exe",
        "?:\\Windows\\System32\\WerFault.exe",
        "?:\\Windows\\Sys?????\\wslconfig.exe"
  ) and
  not (
    /* Crowdstrike specific exclusion as it uses NT Object paths */
    event.dataset == "crowdstrike.fdr" and
      process.executable : (
        "\\Device\\HarddiskVolume*\\Program Files (x86)\\*",
        "\\Device\\HarddiskVolume*\\Program Files\\*",
        "\\Device\\HarddiskVolume*\\Program Files*\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_*\\wsl*.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\conhost.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\lxss\\wslhost.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\WerFault.exe",
        "\\Device\\HarddiskVolume*\\Windows\\Sys?????\\wslconfig.exe"
      )
  )
```



### Execution via local SxS Shared Module

Branch count: 2  
Document count: 2  
Index: geneve-ut-0431

```python
file where host.os.type == "windows" and file.extension : "dll" and
  file.path : (
    "C:\\*\\*.exe.local\\*.dll",
    /* Crowdstrike specific condition as it uses NT Object paths */
    "\\Device\\HarddiskVolume*\\*\\*.exe.local\\*.dll"
  )
```



### Execution with Explicit Credentials via Scripting

Branch count: 22  
Document count: 22  
Index: geneve-ut-0432

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.name == "security_authtrampoline" and
 process.parent.name like~ ("osascript", "com.apple.automator.runner", "sh", "bash", "dash", "zsh", "python*", "perl*", "php*", "ruby", "pwsh")
```



### Expired or Revoked Driver Loaded

Branch count: 2  
Document count: 2  
Index: geneve-ut-0433

```python
driver where host.os.type == "windows" and process.pid == 4 and
  dll.code_signature.status : ("errorExpired", "errorRevoked")
```



### Exploit - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-0434

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:exploit_event or endgame.event_subtype_full:exploit_event)
```



### Exploit - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-0435

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:exploit_event or endgame.event_subtype_full:exploit_event)
```



### Exporting Exchange Mailbox via PowerShell

Branch count: 6  
Document count: 6  
Index: geneve-ut-0436

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and
  process.command_line : ("*MailboxExportRequest*", "*-Mailbox*-ContentFilter*")
```



### External Alerts

Branch count: 1  
Document count: 1  
Index: geneve-ut-0437

```python
event.kind:alert and not event.module:(endgame or endpoint or cloud_defend)
```



### External IP Address Discovery via Curl

Branch count: 304  
Document count: 304  
Index: geneve-ut-0438

```python
process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and
  ((process.parent.executable like ("/Applications/*", "/Volumes/*", "/private/var/folders/*")) or
   (process.parent.name in ("bash", "sh", "zsh") and process.parent.command_line like "*http*") or
   (process.parent.code_signature.trusted == false or process.code_signature.exists == false)) and
  process.name in ("curl", "nscurl") and
  process.args_count <= 5 and
  process.command_line like ("*ip-api.com*", "*ipwho.is*", "*checkip.dyndns.org*", "*api.ipify.org*",
                             "*whatismyip.akamai.com*", "*ifcfg.me*", "*ifconfig.me*", "*ident.me*",
                             "*icanhazip.com*", "*ipecho.net*", "*api.myip.com*", "*checkip.amazonaws.com*",
                             "*wtfismyip.com*", "*iplogger.*", "*freegeoip.net*", "*ipinfo.io*",
                             "*geoplugin.net*", "*httpbin.org*", "*myip.opendns.com*")
```



### File Compressed or Archived into Common Format by Unsigned Process

Branch count: 62  
Document count: 62  
Index: geneve-ut-0441

```python
file where host.os.type == "windows" and event.type in ("creation", "change") and
 process.executable != null and process.code_signature.trusted != true and
 file.Ext.header_bytes : (
                          /* compression formats */
                          "1F9D*",             /* tar zip, tar.z (Lempel-Ziv-Welch algorithm) */
                          "1FA0*",             /* tar zip, tar.z (LZH algorithm) */
                          "425A68*",           /* Bzip2 */
                          "524E4301*",         /* Rob Northen Compression */
                          "524E4302*",         /* Rob Northen Compression */
                          "4C5A4950*",         /* LZIP */
                          "504B0*",            /* ZIP */
                          "526172211A07*",     /* RAR compressed */
                          "44434D0150413330*", /* Windows Update Binary Delta Compression file */
                          "50413330*",         /* Windows Update Binary Delta Compression file */
                          "377ABCAF271C*",     /* 7-Zip */
                          "1F8B*",             /* GZIP */
                          "FD377A585A00*",     /* XZ, tar.xz */
                          "7801*",	           /* zlib: No Compression (no preset dictionary) */
                          "785E*",	           /* zlib: Best speed (no preset dictionary) */
                          "789C*",	           /* zlib: Default Compression (no preset dictionary) */
                          "78DA*", 	           /* zlib: Best Compression (no preset dictionary) */
                          "7820*",	           /* zlib: No Compression (with preset dictionary) */
                          "787D*",	           /* zlib: Best speed (with preset dictionary) */
                          "78BB*",	           /* zlib: Default Compression (with preset dictionary) */
                          "78F9*",	           /* zlib: Best Compression (with preset dictionary) */
                          "62767832*",         /* LZFSE */
                          "28B52FFD*",         /* Zstandard, zst */
                          "5253564B44415441*", /* QuickZip rs compressed archive */
                          "2A2A4143452A2A*",   /* ACE */

                          /* archive formats */
                          "2D686C302D*",       /* lzh */
                          "2D686C352D*",       /* lzh */
                          "303730373037*",     /* cpio */
                          "78617221*",         /* xar */
                          "4F4152*",           /* oar */
                          "49536328*"          /* cab archive */
 )
```



### File Creation Time Changed

Branch count: 1  
Document count: 1  
Index: geneve-ut-0442

```python
file where host.os.type == "windows" and
  event.provider == "Microsoft-Windows-Sysmon" and
  /* File creation time change */
  event.code == "2" and
  not process.executable :
           ("?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Windows\\system32\\cleanmgr.exe",
            "?:\\Windows\\system32\\msiexec.exe",
            "?:\\Windows\\syswow64\\msiexec.exe",
            "?:\\Windows\\system32\\svchost.exe",
            "?:\\WINDOWS\\system32\\backgroundTaskHost.exe",
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
            "?:\\Users\\*\\AppData\\Local\\slack\\app-*\\slack.exe",
            "?:\\Users\\*\\AppData\\Local\\GitHubDesktop\\app-*\\GitHubDesktop.exe",
            "?:\\Users\\*\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
            "?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe") and
  not file.extension : ("temp", "tmp", "~tmp", "xml", "newcfg") and not user.name : ("SYSTEM", "Local Service", "Network Service") and
  not file.name : ("LOG", "temp-index", "license.rtf", "iconcache_*.db")
```



### File Creation and Execution Detected via Defend for Containers

Branch count: 5  
Document count: 10  
Index: geneve-ut-0443

```python
sequence by container.id, user.id with maxspan=3s
  [file where host.os.type == "linux" and event.type == "creation" and process.interactive == true and container.id like "?*" and
   file.path like ("/tmp/*", "/var/tmp/*", "/dev/shm/*", "/root/*", "/home/*") and
   not process.name in ("apt", "apt-get", "dnf", "microdnf", "yum", "zypper", "tdnf", "apk", "pacman", "rpm", "dpkg")] by file.path
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.interactive == true and container.id like "?*"] by process.executable
```



### File Creation by Cups or Foomatic-rip Child

Branch count: 64  
Document count: 128  
Index: geneve-ut-0444

```python
sequence by host.id with maxspan=10s
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start") and
   process.parent.name == "foomatic-rip" and
   process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")] by process.entity_id
  [file where host.os.type == "linux" and event.type != "deletion" and
   not (
     (process.name == "gs" and file.path like ("/tmp/gs_*", "/var/spool/cups/tmp/gs_*")) or
     (process.name == "pdftops" and file.path like "/tmp/0*")
   )] by process.parent.entity_id
```



### File Staged in Root Folder of Recycle Bin

Branch count: 1  
Document count: 1  
Index: geneve-ut-0451

```python
file where host.os.type == "windows" and event.type == "creation" and
  file.path : "?:\\$RECYCLE.BIN\\*" and
  not file.path : "?:\\$RECYCLE.BIN\\*\\*" and
  not file.name : "desktop.ini"
```



### File System Debugger Launched Inside a Container

Branch count: 1  
Document count: 1  
Index: geneve-ut-0452

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.entry_leader.entry_meta.type == "container" and process.name == "debugfs" and
process.command_line like~ "/dev/sd*" and not process.args == "-R"
```



### File Transfer or Listener Established via Netcat

Branch count: 180  
Document count: 180  
Index: geneve-ut-0454

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name in ("nc","ncat","netcat","netcat.openbsd","netcat.traditional") and
process.args like~ (
  /* bind shell to specific port or listener */
  "-*l*","-*p*",
  /* reverse shell to command-line interpreter used for command execution */
  "-*e*",
  /* file transfer via stdout/pipe */
  ">","<", "|"
)
```



### File and Directory Permissions Modification

Branch count: 16  
Document count: 16  
Index: geneve-ut-0455

```python
process where event.type == "start" and host.os.type == "windows" and
(
  ((process.name: "icacls.exe" or process.pe.original_file_name == "iCACLS.EXE") and process.args: ("*:F", "/reset", "/setowner", "*grant*")) or
  ((process.name: "cacls.exe" or process.pe.original_file_name == "CACLS.EXE") and process.args: ("/g", "*:f")) or
  ((process.name: "takeown.exe" or process.pe.original_file_name == "takeown.exe") and process.args: ("/F")) or
  ((process.name: "attrib.exe" or process.pe.original_file_name== "ATTRIB.EXE") and process.args: "-r")
) and not user.id : "S-1-5-18" and
not (
  process.args : ("C:\\ProgramData\\Lenovo\\*", "C:\\ProgramData\\Adobe\\*", "C:\\ProgramData\\ASUS\\ASUS*")
)
```



### File made Immutable by Chattr

Branch count: 12  
Document count: 12  
Index: geneve-ut-0456

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
?process.parent.executable != null and
process.name == "chattr" and process.args : ("-*i*", "+*i*") and
not (
  ?process.parent.executable: (
    "/lib/systemd/systemd", "/usr/local/uems_agent/bin/*", "/usr/lib/systemd/systemd", "/usr/local/emps/sbin/php-fpm",
    "/usr/local/emps/bin/php"
  ) or
  ?process.parent.name in (
    "systemd", "cf-agent", "ntpdate", "xargs", "px", "preinst", "auth", "cf-agent", "dcservice", "dcagentupgrader",
    "sudo", "ephemeral-disk-warning"
  ) or
  process.args like "/opt/ai-bolit/*"
)
```



### File or Directory Deletion Command

Branch count: 11  
Document count: 11  
Index: geneve-ut-0457

```python
process where host.os.type == "windows" and event.type == "start" and 
(
  (process.name: "rundll32.exe" and process.args: "*InetCpl.cpl,Clear*") or 
  (process.name: "reg.exe" and process.args:"delete") or 
  (
    process.name: "cmd.exe" and process.args: ("*rmdir*", "*rm *", "rm") and
    not process.args : (
          "*\\AppData\\Local\\Microsoft\\OneDrive\\*",
          "*\\AppData\\Local\\Temp\\DockerDesktop\\*",
          "*\\AppData\\Local\\Temp\\Report.*",
          "*\\AppData\\Local\\Temp\\*.PackageExtraction"
    )
  ) or
  (process.name: "powershell.exe" and process.args: ("*rmdir", "rm", "rd", "*Remove-Item*", "del", "*]::Delete(*"))
) and not user.id : "S-1-5-18"
```



### FortiGate Configuration File Downloaded

Branch count: 1  
Document count: 1  
Index: geneve-ut-0483

```python
any where event.dataset == "fortinet_fortigate.log" and
    event.code == "0100032095" and
    fortinet.firewall.action == "download"
```



### FortiGate SSO Login Followed by Administrator Account Creation

Branch count: 2  
Document count: 4  
Index: geneve-ut-0486

```python
sequence by observer.name with maxspan=15m
  [authentication where event.dataset == "fortinet_fortigate.log" and
    event.action == "login" and event.outcome == "success" and
    (fortinet.firewall.method == "sso" or fortinet.firewall.ui like~ "sso*")]
  [any where event.dataset == "fortinet_fortigate.log" and
    event.code == "0100044547" and
    fortinet.firewall.cfgpath == "system.admin" and
    fortinet.firewall.action == "Add"]
```



### FortiGate Super Admin Account Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-0487

```python
any where event.dataset == "fortinet_fortigate.log" and
    event.code == "0100044547" and
    fortinet.firewall.cfgpath == "system.admin" and
    fortinet.firewall.action == "Add" and
    fortinet.firewall.cfgattr like~ "*accprofile[super_admin]*"
```



### Forwarded Google Workspace Security Alert

Branch count: 1  
Document count: 1  
Index: geneve-ut-0488

```python
event.dataset: google_workspace.alert
```



### Full Disk Access Permission Check

Branch count: 10  
Document count: 10  
Index: geneve-ut-0489

```python
file where host.os.type == "macos" and event.action == "open" and
  file.path == "/Library/Preferences/com.apple.TimeMachine.plist" and
  (process.name in ("osascript", "perl", "node", "ruby", "bash", "sh", "Terminal") or
   process.name like "python*" or
   process.code_signature.trusted == false or
   process.code_signature.exists == false)
```



### Full User-Mode Dumps Enabled System-Wide

Branch count: 8  
Document count: 8  
Index: geneve-ut-0490

```python
registry where host.os.type == "windows" and
    registry.path : (
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\DumpType",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\DumpType"
    ) and
    registry.data.strings : ("2", "0x00000002") and
    not (process.executable : "?:\\Windows\\system32\\svchost.exe" and user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20"))
```



### GCP Firewall Rule Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-0491

```python
event.dataset:gcp.audit and event.action:(*.compute.firewalls.insert or google.appengine.*.Firewall.Create*Rule)
```



### GCP Firewall Rule Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-0492

```python
event.dataset:gcp.audit and event.action:(*.compute.firewalls.delete or google.appengine.*.Firewall.Delete*Rule)
```



### GCP Firewall Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-0493

```python
event.dataset:gcp.audit and event.action:(*.compute.firewalls.patch or google.appengine.*.Firewall.Update*Rule)
```



### GCP IAM Custom Role Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-0494

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.CreateRole and event.outcome:success
```



### GCP IAM Role Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0495

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DeleteRole and event.outcome:success
```



### GCP IAM Service Account Key Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0496

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DeleteServiceAccountKey and event.outcome:success
```



### GCP Logging Bucket Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0497

```python
event.dataset:gcp.audit and event.action:google.logging.v*.ConfigServiceV*.DeleteBucket and event.outcome:success
```



### GCP Logging Sink Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0498

```python
event.dataset:gcp.audit and event.action:google.logging.v*.ConfigServiceV*.DeleteSink and event.outcome:success
```



### GCP Logging Sink Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-0499

```python
event.dataset:gcp.audit and event.action:google.logging.v*.ConfigServiceV*.UpdateSink and event.outcome:success
```



### GCP Pub/Sub Subscription Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-0500

```python
event.dataset:gcp.audit and event.action:google.pubsub.v*.Subscriber.CreateSubscription and event.outcome:success
```



### GCP Pub/Sub Subscription Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0501

```python
event.dataset:gcp.audit and event.action:google.pubsub.v*.Subscriber.DeleteSubscription and event.outcome:success
```



### GCP Pub/Sub Topic Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-0502

```python
event.dataset:gcp.audit and event.action:google.pubsub.v*.Publisher.CreateTopic and event.outcome:success
```



### GCP Pub/Sub Topic Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0503

```python
event.dataset:gcp.audit and event.action:google.pubsub.v*.Publisher.DeleteTopic and event.outcome:success
```



### GCP Service Account Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-0504

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.CreateServiceAccount and event.outcome:success
```



### GCP Service Account Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0505

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DeleteServiceAccount and event.outcome:success
```



### GCP Service Account Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-0506

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DisableServiceAccount and event.outcome:success
```



### GCP Service Account Key Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-0507

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.CreateServiceAccountKey and event.outcome:success
```



### GCP Storage Bucket Configuration Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-0508

```python
event.dataset:gcp.audit and event.action:"storage.buckets.update" and event.outcome:success
```



### GCP Storage Bucket Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0509

```python
event.dataset:gcp.audit and event.action:"storage.buckets.delete"
```



### GCP Storage Bucket Permissions Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-0510

```python
event.dataset:gcp.audit and event.action:"storage.setIamPermissions" and event.outcome:success
```



### GCP Virtual Private Cloud Network Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0511

```python
event.dataset:gcp.audit and event.action:v*.compute.networks.delete and event.outcome:success
```



### GCP Virtual Private Cloud Route Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-0512

```python
event.dataset:gcp.audit and event.action:(v*.compute.routes.insert or "beta.compute.routes.insert")
```



### GCP Virtual Private Cloud Route Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0513

```python
event.dataset:gcp.audit and event.action:v*.compute.routes.delete and event.outcome:success
```



### GRUB Configuration File Creation

Branch count: 14  
Document count: 14  
Index: geneve-ut-0514

```python
file where host.os.type == "linux" and event.type == "creation" and process.executable != null and file.path like~ (
  "/etc/default/grub.d/*", "/etc/default/grub", "/etc/grub.d/*",
  "/boot/grub2/grub.cfg", "/boot/grub/grub.cfg", "/boot/efi/EFI/*/grub.cfg",
  "/etc/sysconfig/grub"
) and not (
  /* Too many FPs from Python automation */
  process.name like ("python*", "platform-python*") or
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/bin/crio", "/usr/sbin/crond",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/kaniko/kaniko-executor",
    "/usr/local/bin/dockerd", "/usr/bin/podman", "/bin/install", "/proc/self/exe", "/usr/lib/systemd/systemd",
    "/usr/sbin/sshd", "/usr/bin/gitlab-runner", "/opt/gitlab/embedded/bin/ruby", "/usr/sbin/gdm", "/usr/bin/install",
    "/usr/local/manageengine/uems_agent/bin/dcregister", "/usr/local/bin/pacman", "./usr/bin/podman", "/usr/bin/dnf5",
    "/usr/sbin/yum-cron"
  ) or
  process.executable like~ (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  (process.name == "sed" and file.name : "sed*")
)
```



### GRUB Configuration Generation through Built-in Utilities

Branch count: 24  
Document count: 24  
Index: geneve-ut-0515

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.parent.executable != null and process.name in ("grub-mkconfig", "grub2-mkconfig", "update-grub") and not (
  process.parent.name in ("run-parts", "sudo", "update-grub", "pacman", "dockerd", "dnf", "rpm", "yum") or
  process.parent.executable like (
    "/var/lib/dpkg/info/*", "/usr/lib/bootloader/grub2-efi/config", "/tmp/newroot/*", "/usr/lib/kernel/install.d/*",
    "/run/user/*/.bubblewrap/*/timeout"
  ) or
  process.parent.executable in (
    "/usr/bin/timeout", "/usr/sbin/nvidia-boot-update", "/usr/lib/oci-linux-config/misc_updates.sh",
    "/opt/puppetlabs/puppet/bin/puppet", "/usr/sbin/selinux-activate", "/usr/lib/skylight/stop-workspace",
    "/var/lib/aws-replication-agent/install_agent", "/usr/local/CTS/bin/apply_personality",
    "/opt/puppetlabs/puppet/bin/ruby"
  ) or
  (process.parent.name like ("python*", "platform-python*") and process.parent.command_line like "*ansible*")
)
```



### Gatekeeper Override and Execution

Branch count: 11  
Document count: 11  
Index: geneve-ut-0516

```python
configuration where host.os.type == "macos" and event.action == "gatekeeper_override" and
  file.path like ("/Volumes/*", "/Users/*/Applications/*", "/Applications/*",
                  "/tmp/*", "/private/tmp/*", "/var/tmp/*", "/private/var/tmp/*", "/Users/Shared/*",
                  "/Users/*/Downloads/*", "/Users/*/Desktop/*", "/Users/*/Documents/*")
```



### Git Hook Command Execution

Branch count: 576  
Document count: 1152  
Index: geneve-ut-0524

```python
sequence by host.id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "ProcessRollup2") and
   process.parent.name == "git" and process.args like ".git/hooks/*" and
   process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
  ] by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "ProcessRollup2") and
   process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")] by process.parent.entity_id
```



### Git Hook Created or Modified

Branch count: 4  
Document count: 4  
Index: geneve-ut-0525

```python
file where host.os.type == "linux" and event.type == "creation" and file.path like "*.git/hooks/*" and
file.extension == null and process.executable != null and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/usr/bin/pamac-daemon", "/bin/pamac-daemon",
    "/usr/local/bin/dockerd", "/sbin/dockerd", "/usr/bin/fuse-overlayfs", "/usr/local/bin/gitlab-runner",
    "/usr/bin/coreutils", "/usr/bin/nautilus"
  ) or
  process.executable like (
    "/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*", "/run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/*/r10k"
  ) or
  process.name in ("git", "dirname", "tar", "gitea", "git-lfs") or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*")
)
```



### Git Hook Egress Network Connection

Branch count: 16  
Document count: 32  
Index: geneve-ut-0526

```python
sequence by host.id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name == "git" and process.args like ".git/hooks/*" and
   process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
   not (process.name like "python*" and process.command_line like "*pip*")
  ] by process.entity_id
  [network where host.os.type == "linux" and event.type == "start" and event.action == "connection_attempted" and not (
     destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
       destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
       "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
       "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
       "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
       "FF00::/8", "172.31.0.0/16"
     )
   )
  ] by process.parent.entity_id
```



### Git Repository or File Download to Suspicious Directory

Branch count: 9  
Document count: 18  
Index: geneve-ut-0527

```python
sequence by process.entity_id, host.id with maxspan=10s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
     (process.name == "git" and process.args == "clone") or
     (process.name in ("wget", "curl") and process.command_line like~ "*github*")
  ) and not (
    process.parent.name in ("git", "cmake") or
     process.parent.args like "/root/.ansible/tmp/ansible*"
  )]
  [file where host.os.type == "linux" and event.type == "creation" and file.path like ("/tmp/*", "/var/tmp/*", "/dev/shm/*")]
```



### GitHub App Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-0530

```python
configuration where event.dataset == "github.audit" and github.category == "integration_installation" and event.type == "deletion"
```



### GitHub Authentication Token Access via Node.js

Branch count: 24  
Document count: 24  
Index: geneve-ut-0531

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "ProcessRollup2", "exec_event") and process.parent.name == "node" and
process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and process.args == "gh auth token"
```



### GitHub Owner Role Granted To User

Branch count: 1  
Document count: 1  
Index: geneve-ut-0533

```python
iam where event.dataset == "github.audit" and event.action == "org.update_member" and github.permission == "admin"
```



### GitHub PAT Access Revoked

Branch count: 1  
Document count: 1  
Index: geneve-ut-0534

```python
configuration where event.dataset == "github.audit" and event.action == "personal_access_token.access_revoked"
```



### GitHub Private Repository Turned Public

Branch count: 1  
Document count: 1  
Index: geneve-ut-0535

```python
configuration where event.dataset == "github.audit" and github.operation_type == "modify" and github.category == "repo" and
event.action == "repo.access" and github.previous_visibility == "private" and github.visibility == "public"
```



### GitHub Protected Branch Settings Changed

Branch count: 1  
Document count: 1  
Index: geneve-ut-0536

```python
configuration where event.dataset == "github.audit"
  and github.category == "protected_branch" and event.type == "change"
```



### GitHub Repo Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-0537

```python
configuration where event.dataset == "github.audit" and event.action == "repo.create"
```



### GitHub Repository Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-0538

```python
configuration where event.module == "github" and event.dataset == "github.audit" and event.action == "repo.destroy"
```



### GitHub Secret Scanning Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-0539

```python
configuration where event.dataset == "github.audit" and event.type == "change" and event.action == "repository_secret_scanning.disable"
```



### GitHub User Blocked From Organization

Branch count: 1  
Document count: 1  
Index: geneve-ut-0541

```python
configuration where event.dataset == "github.audit" and event.action == "org.block_user"
```



### Google Calendar C2 via Script Interpreter

Branch count: 5  
Document count: 10  
Index: geneve-ut-0543

```python
sequence by process.entity_id with maxspan=20s
  [network where host.os.type == "macos" and event.type == "start" and
    (process.name in ("node", "osascript") or process.name like "python*" or
     process.code_signature.trusted == false or process.code_signature.exists == false) and
    destination.domain like "calendar.app.google*"]
  [network where host.os.type == "macos" and event.type == "start" and destination.domain == null]
```



### Google Drive Ownership Transferred via Google Workspace

Branch count: 1  
Document count: 1  
Index: geneve-ut-0544

```python
event.dataset:"google_workspace.admin" and event.action:"CREATE_DATA_TRANSFER_REQUEST"
  and event.category:"iam" and google_workspace.admin.application.name:Drive*
```



### Google Workspace 2SV Policy Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-0546

```python
event.dataset:"google_workspace.login" and event.action:"2sv_disable"
```



### Google Workspace API Access Granted via Domain-Wide Delegation

Branch count: 1  
Document count: 1  
Index: geneve-ut-0547

```python
event.dataset:google_workspace.admin
  and event.provider:admin
  and event.category:iam
  and event.action:AUTHORIZE_API_CLIENT_ACCESS
  and event.outcome:success
```



### Google Workspace Admin Role Assigned to a User

Branch count: 1  
Document count: 1  
Index: geneve-ut-0548

```python
event.dataset:"google_workspace.admin" and event.category:"iam" and event.action:"ASSIGN_ROLE"
  and google_workspace.event.type:"DELEGATED_ADMIN_SETTINGS" and google_workspace.admin.role.name : *_ADMIN_ROLE
```



### Google Workspace Admin Role Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0549

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:DELETE_ROLE
```



### Google Workspace Bitlocker Setting Disabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-0550

```python
event.dataset:"google_workspace.admin" and event.action:"CHANGE_APPLICATION_SETTING" and event.category:(iam or configuration)
    and google_workspace.admin.new_value:"Disabled" and google_workspace.admin.setting.name:BitLocker*
```



### Google Workspace Custom Admin Role Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-0551

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:CREATE_ROLE
```



### Google Workspace Custom Gmail Route Created or Modified

Branch count: 4  
Document count: 4  
Index: geneve-ut-0552

```python
event.dataset:"google_workspace.admin" and event.action:("CREATE_GMAIL_SETTING" or "CHANGE_GMAIL_SETTING")
  and google_workspace.event.type:"EMAIL_SETTINGS" and google_workspace.admin.setting.name:("EMAIL_ROUTE" or "MESSAGE_SECURITY_RULE")
```



### Google Workspace Drive Encryption Key(s) Accessed from Anonymous User

Branch count: 105  
Document count: 105  
Index: geneve-ut-0553

```python
file where event.dataset == "google_workspace.drive" and event.action : ("copy", "view", "download") and
    google_workspace.drive.visibility: "people_with_link" and source.user.email == "" and
    file.extension: (
        "token","assig", "pssc", "keystore", "pub", "pgp.asc", "ps1xml", "pem", "gpg.sig", "der", "key",
        "p7r", "p12", "asc", "jks", "p7b", "signature", "gpg", "pgp.sig", "sst", "pgp", "gpgz", "pfx", "crt",
        "p8", "sig", "pkcs7", "jceks", "pkcs8", "psc1", "p7c", "csr", "cer", "spc", "ps2xml")
```



### Google Workspace MFA Enforcement Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-0554

```python
event.dataset:google_workspace.admin and event.provider:admin
  and event.category:iam and event.action:ENFORCE_STRONG_AUTHENTICATION
  and google_workspace.admin.new_value:false
```



### Google Workspace Object Copied to External Drive with App Consent

Branch count: 4  
Document count: 8  
Index: geneve-ut-0555

```python
sequence by source.user.email with maxspan=3m
[file where event.dataset == "google_workspace.drive" and event.action == "copy" and

    /* Should only match if the object lives in a Drive that is external to the user's GWS organization */
    google_workspace.drive.owner_is_team_drive == "false" and google_workspace.drive.copy_type == "external" and

    /* Google Script, Forms, Sheets and Document can have container-bound scripts */
    google_workspace.drive.file.type: ("script", "form", "spreadsheet", "document")]

[any where event.dataset == "google_workspace.token" and event.action == "authorize" and

    /* Ensures application ID references custom app in Google Workspace and not GCP */
    google_workspace.token.client.id : "*apps.googleusercontent.com"]
```



### Google Workspace Password Policy Modified

Branch count: 12  
Document count: 12  
Index: geneve-ut-0556

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



### Google Workspace Restrictions for Marketplace Modified to Allow Any App

Branch count: 2  
Document count: 2  
Index: geneve-ut-0557

```python
event.dataset:"google_workspace.admin" and event.action:"CHANGE_APPLICATION_SETTING" and event.category:(iam or configuration)
    and google_workspace.event.type:"APPLICATION_SETTINGS" and google_workspace.admin.application.name:"Google Workspace Marketplace"
        and google_workspace.admin.setting.name:"Apps Access Setting Allowlist access"  and google_workspace.admin.new_value:"ALLOW_ALL"
```



### Google Workspace Role Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-0558

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:(ADD_PRIVILEGE or UPDATE_ROLE)
```



### Google Workspace Suspended User Account Renewed

Branch count: 1  
Document count: 1  
Index: geneve-ut-0559

```python
event.dataset:google_workspace.admin and event.category:iam and event.action:UNSUSPEND_USER
```



### Google Workspace User Organizational Unit Changed

Branch count: 1  
Document count: 1  
Index: geneve-ut-0560

```python
event.dataset:"google_workspace.admin" and event.type:change and event.category:iam
    and google_workspace.event.type:"USER_SETTINGS" and event.action:"MOVE_USER_TO_ORG_UNIT"
```



### Group Policy Discovery via Microsoft GPResult Utility

Branch count: 8  
Document count: 8  
Index: geneve-ut-0562

```python
process where host.os.type == "windows" and event.type == "start" and
(process.name: "gpresult.exe" or ?process.pe.original_file_name == "gprslt.exe") and process.args: ("/z", "/v", "/r", "/x")
```



### Hidden Directory Creation via Unusual Parent

Branch count: 48  
Document count: 48  
Index: geneve-ut-0564

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "exec_event") and
process.name == "mkdir" and process.parent.executable like (
  "/dev/shm/*", "/tmp/*", "/var/tmp/*", "/var/run/*", "/root/*", "/boot/*", "/var/www/html/*", "/opt/.*"
) and process.args like (".*", "/*/.*") and process.args_count <= 3 and
not (
  process.command_line like ("mkdir -p .", "mkdir ./*") or
  process.args like ("/root/.ssh", "/home/*/.ssh", "/root/.cache/install4j") or
  process.parent.executable like (
    "/tmp/pear/temp/*", "/var/tmp/buildah*", "/tmp/python-build.*", "/tmp/cliphist-wofi-img", "/tmp/snap.rootfs_*",
    "/root/.acme.sh/acme.sh", "/tmp/buildpacks/*go/bin/test-compile", "/tmp/newroot/*", "/run/containerd/*"
  ) or
  process.parent.name in ("libtool", "jpenable", "configure")
)
```



### Hidden Files and Directories via Hidden Flag

Branch count: 1  
Document count: 1  
Index: geneve-ut-0565

```python
file where host.os.type == "linux" and event.type == "creation" and process.name == "chflags"
```



### Host File System Changes via Windows Subsystem for Linux

Branch count: 1  
Document count: 2  
Index: geneve-ut-0579

```python
sequence by process.entity_id with maxspan=5m
[process where host.os.type == "windows" and event.type == "start" and
 process.name : "dllhost.exe" and
  /* Plan9FileSystem CLSID - WSL Host File System Worker */
 process.command_line : "*{DFB65C4C-B34F-435D-AFE9-A86218684AA8}*"]
[file where host.os.type == "windows" and process.name : "dllhost.exe" and
  not file.path : (
        "?:\\Users\\*\\Downloads\\*",
        "?:\\Windows\\Prefetch\\DLLHOST.exe-????????.pf")]
```



### Hosts File Modified

Branch count: 18  
Document count: 18  
Index: geneve-ut-0580

```python
any where process.executable != null and

  /* file events for creation; file change events are not captured by some of the included sources for linux and so may
     miss this, which is the purpose of the process + command line args logic below */
  (
   event.category == "file" and event.type in ("change", "creation") and event.action != "rename" and
     file.path : ("/private/etc/hosts", "/etc/hosts", "?:\\Windows\\System32\\drivers\\etc\\hosts") and 
     not process.name in ("dockerd", "rootlesskit", "podman", "crio") and
     not process.executable : ("C:\\Program Files\\Fortinet\\FortiClient\\FCDBLog.exe",
                               "C:\\Program Files\\Fortinet\\FortiClient\\FortiWF.exe",
                               "C:\\Program Files\\Fortinet\\FortiClient\\fmon.exe",
                               "C:\\Program Files\\Seqrite\\Seqrite\\SCANNER.EXE",
                               "C:\\Windows\\System32\\SearchProtocolHost.exe",
                               "C:\\Windows\\Temp\\*.ins\\inst.exe",
                               "C:\\Windows\\System32\\svchost.exe",
                               "C:\\Program Files\\NordVPN\\nordvpn-service.exe",
                               "C:\\Program Files\\Tailscale\\tailscaled.exe",
                               "C:\\Program Files\\Docker\\Docker\\com.docker.service",
                               "C:\\Program Files\\Docker\\Docker\\InstallerCli.exe",
                               "C:\\Program Files\\Quick Heal\\Quick Heal AntiVirus Pro\\scanner.exe",
                               "C:\\Program Files (x86)\\Quick Heal AntiVirus Pro\\SCANNER.EXE",
                               "C:\\Program Files\\Quick Heal\\Quick Heal Internet Security\\scanner.exe",
                               "C:\\Program Files (x86)\\Cisco\\Cisco AnyConnect Secure Mobility Client\\vpnagent.exe",
                               "/Applications/Parallels Desktop.app/Contents/MacOS/prl_naptd",
                               "/opt/IBM/InformationServer/Server/DSEngine/bin/uvsh",
                               "/usr/local/demisto/server", 
                               "/usr/local/bin/defender")
  )
  or

  /* process events for change targeting linux only */
  (
   event.category == "process" and event.type in ("start") and
     process.name in ("nano", "vim", "vi", "emacs", "echo", "sed") and
     (process.args : ("/etc/hosts") or (process.working_directory == "/etc" and process.args == "hosts")) and 
     not process.parent.name in ("dhclient-script", "google_set_hostname") and
     not process.command_line == "sed -i /Added by Google/d /etc/hosts"
  )
```



### Hping Process Activity

Branch count: 18  
Document count: 18  
Index: geneve-ut-0581

```python
process where host.os.type == "linux" and event.type == "start" and
 event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
 process.name in ("hping", "hping2", "hping3")
```



### IIS HTTP Logging Disabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-0582

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "appcmd.exe" or ?process.pe.original_file_name == "appcmd.exe") and
  process.args : "/dontLog*:*True" and
  not process.parent.name : "iissetup.exe"
```



### IPSEC NAT Traversal Port Activity

Branch count: 3  
Document count: 3  
Index: geneve-ut-0583

```python
(event.dataset: network_traffic.flow or (event.category: (network or network_traffic))) and network.transport:udp and destination.port:4500
```



### ImageLoad via Windows Update Auto Update Client

Branch count: 8  
Document count: 8  
Index: geneve-ut-0587

```python
process where host.os.type == "windows" and event.type == "start" and
  (?process.pe.original_file_name == "wuauclt.exe" or process.name : "wuauclt.exe") and
   /* necessary windows update client args to load a dll */
   process.args : "/RunHandlerComServer" and process.args : "/UpdateDeploymentProvider" and
   /* common paths writeable by a standard user where the target DLL can be placed */
   process.args : ("C:\\Users\\*.dll", "C:\\ProgramData\\*.dll", "C:\\Windows\\Temp\\*.dll", "C:\\Windows\\Tasks\\*.dll")
```



### Incoming DCOM Lateral Movement via MSHTA

Branch count: 2  
Document count: 4  
Index: geneve-ut-0589

```python
sequence with maxspan=1m
  [process where host.os.type == "windows" and event.type == "start" and
     process.name : "mshta.exe" and process.args : "-Embedding"
  ] by host.id, process.entity_id
  [network where host.os.type == "windows" and event.type == "start" and process.name : "mshta.exe" and
     network.direction : ("incoming", "ingress") and network.transport == "tcp" and
     source.port > 49151 and destination.port > 49151 and source.ip != "127.0.0.1" and source.ip != "::1"
  ] by host.id, process.entity_id
```



### Incoming DCOM Lateral Movement with MMC

Branch count: 2  
Document count: 4  
Index: geneve-ut-0590

```python
sequence by host.id with maxspan=1m
 [network where host.os.type == "windows" and event.type == "start" and process.name : "mmc.exe" and source.port >= 49152 and
 destination.port >= 49152 and source.ip != "127.0.0.1" and source.ip != "::1" and
  network.direction : ("incoming", "ingress") and network.transport == "tcp"
 ] by process.entity_id
 [process where host.os.type == "windows" and event.type == "start" and process.parent.name : "mmc.exe"
 ] by process.parent.entity_id
```



### Incoming DCOM Lateral Movement with ShellBrowserWindow or ShellWindows

Branch count: 2  
Document count: 4  
Index: geneve-ut-0591

```python
sequence by host.id with maxspan=5s
 [network where host.os.type == "windows" and event.type == "start" and process.name : "explorer.exe" and
  network.direction : ("incoming", "ingress") and network.transport == "tcp" and
  source.port > 49151 and destination.port > 49151 and source.ip != "127.0.0.1" and source.ip != "::1"
 ] by process.entity_id
 [process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "explorer.exe"
 ] by process.parent.entity_id
```



### Incoming Execution via PowerShell Remoting

Branch count: 4  
Document count: 8  
Index: geneve-ut-0592

```python
sequence by host.id with maxspan = 30s
   [network where host.os.type == "windows" and network.direction : ("incoming", "ingress") and destination.port in (5985, 5986) and
    source.ip != "127.0.0.1" and source.ip != "::1"]
   [process where host.os.type == "windows" and
    event.type == "start" and process.parent.name : "wsmprovhost.exe" and not process.executable : "?:\\Windows\\System32\\conhost.exe"]
```



### Incoming Execution via WinRM Remote Shell

Branch count: 4  
Document count: 8  
Index: geneve-ut-0593

```python
sequence by host.id with maxspan=30s
   [network where host.os.type == "windows" and process.pid == 4 and network.direction : ("incoming", "ingress") and
    destination.port in (5985, 5986) and source.ip != "127.0.0.1" and source.ip != "::1"]
   [process where host.os.type == "windows" and
    event.type == "start" and process.parent.name : "winrshost.exe" and not process.executable : "?:\\Windows\\System32\\conhost.exe"]
```



### Indirect Command Execution via Forfiles/Pcalua

Branch count: 2  
Document count: 2  
Index: geneve-ut-0594

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : ("pcalua.exe", "forfiles.exe")
```



### Initramfs Unpacking via unmkinitramfs

Branch count: 5  
Document count: 5  
Index: geneve-ut-0598

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed") and
process.name == "unmkinitramfs" and not (
  ?process.parent.executable == "/usr/bin/lsinitramfs" or
  ?process.working_directory == "/usr/local/nutanix/ngt/python/bin"
)
```



### Insecure AWS EC2 VPC Security Group Ingress Rule Added

Branch count: 14  
Document count: 14  
Index: geneve-ut-0599

```python
event.dataset: "aws.cloudtrail"
    and event.provider: ec2.amazonaws.com
    and event.action: AuthorizeSecurityGroupIngress
    and event.outcome: success
    and aws.cloudtrail.flattened.request_parameters.ipPermissions.items.ipRanges.items.cidrIp: ("0.0.0.0/0" or "::/0")
    and aws.cloudtrail.flattened.request_parameters.ipPermissions.items.fromPort: (
        21 or 22 or 23 or 445 or 3389 or 5985 or 5986)
```



### InstallUtil Activity

Branch count: 1  
Document count: 1  
Index: geneve-ut-0600

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "installutil.exe" and not user.id : "S-1-5-18"
```



### InstallUtil Process Making Network Connections

Branch count: 2  
Document count: 4  
Index: geneve-ut-0601

```python
/* the benefit of doing this as an eql sequence vs kql is this will limit to alerting only on the first network connection */

sequence by process.entity_id
  [process where host.os.type == "windows" and event.type == "start" and process.name : "installutil.exe"]
  [network where host.os.type == "windows" and process.name : "installutil.exe" and network.direction : ("outgoing", "egress")]
```



### Installation of Custom Shim Databases

Branch count: 1  
Document count: 1  
Index: geneve-ut-0602

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\*.sdb" and
  not process.executable : (
        "?:\\Program Files (x86)\\DesktopCentral_Agent\\*\\Setup\\NwSapSetup.exe",
        "?:\\$WINDOWS.~BT\\Sources\\SetupPlatform.exe",
        "?:\\Program Files (x86)\\SAP\\SAPsetup\\setup\\NwSapSetup.exe",
        "?:\\Program Files (x86)\\SAP\\SapSetup\\OnRebootSvc\\NWSAPSetupOnRebootInstSvc.exe",
        "?:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Security for Windows Server\\kavfs.exe",

        /* Crowdstrike specific exclusion as it uses NT Object paths */
        "\\Device\\HarddiskVolume*\\Program Files (x86)\\DesktopCentral_Agent\\*\\Setup\\NwSapSetup.exe",
        "\\Device\\HarddiskVolume*\\$WINDOWS.~BT\\Sources\\SetupPlatform.exe",
        "\\Device\\HarddiskVolume*\\Program Files (x86)\\SAP\\SAPsetup\\setup\\NwSapSetup.exe",
        "\\Device\\HarddiskVolume*\\Program Files (x86)\\SAP\\SapSetup\\OnRebootSvc\\NWSAPSetupOnRebootInstSvc.exe",
        "\\Device\\HarddiskVolume*\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Security for Windows Server\\kavfs.exe"
  )
```



### Installation of Security Support Provider

Branch count: 2  
Document count: 2  
Index: geneve-ut-0603

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : "Security Packages" and
  registry.path : (
      "*\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Security Packages",
      "*\\SYSTEM\\*ControlSet*\\Control\\Lsa\\OSConfig\\Security Packages"
  ) and
  not process.executable : (
        "C:\\Windows\\System32\\msiexec.exe",
        "C:\\Windows\\SysWOW64\\msiexec.exe",
        /* Crowdstrike specific exclusion as it uses NT Object paths */
        "\\Device\\HarddiskVolume*\\Windows\\System32\\msiexec.exe",
        "\\Device\\HarddiskVolume*\\Windows\\SysWOW64\\msiexec.exe"
  )
```



### Interactive Exec Into Container Detected via Defend for Containers

Branch count: 9  
Document count: 9  
Index: geneve-ut-0604

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
process.entry_leader.entry_meta.type == "container" and

/* process is the inital process run in a container */
process.entry_leader.same_as_process == true and

/* interactive process */
process.interactive == true and container.id like "*"
```



### Interactive Privilege Boundary Enumeration Detected via Defend for Containers

Branch count: 25  
Document count: 25  
Index: geneve-ut-0606

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.interactive == true and (
  (process.name in ("id", "whoami", "capsh", "getcap", "lsns")) or
  (process.args in (
     "id", "/bin/id", "/usr/bin/id", "/usr/local/bin/id",
     "whoami", "/bin/whoami", "/usr/bin/whoami", "/usr/local/bin/whoami",
     "capsh", "/bin/capsh", "/usr/bin/capsh", "/usr/local/bin/capsh",
     "getcap", "/bin/getcap", "/usr/bin/getcap", "/usr/local/bin/getcap",
     "lsns", "/bin/lsns", "/usr/bin/lsns", "/usr/local/bin/lsns"
   ) and
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and container.id like "?*"
```



### Interactive Terminal Spawned via Python

Branch count: 459  
Document count: 459  
Index: geneve-ut-0610

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
(
  (process.parent.name : "python*" and process.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh",
   "fish") and process.parent.args_count >= 3 and process.parent.args : "*pty.spawn*" and process.parent.args : "-c") or
  (process.parent.name : "python*" and process.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
   process.args in (
     "sh", "dash", "bash", "zsh",
     "/bin/sh", "/bin/dash", "/bin/bash", "/bin/zsh",
     "/usr/bin/sh", "/usr/bin/dash", "/usr/bin/bash", "/usr/bin/zsh",
     "/usr/local/bin/sh", "/usr/local/bin/dash", "/usr/local/bin/bash", "/usr/local/bin/zsh"
   ) and process.args_count == 1 and process.parent.args_count == 1
  )
)
```



### KDE AutoStart Script or Desktop File Creation

Branch count: 32  
Document count: 32  
Index: geneve-ut-0611

```python
file where host.os.type == "linux" and event.type == "creation" and process.executable != null and
file.extension in ("sh", "desktop") and
file.path like (
  "/home/*/.config/autostart/*", "/root/.config/autostart/*",
  "/home/*/.kde/Autostart/*", "/root/.kde/Autostart/*",
  "/home/*/.kde4/Autostart/*", "/root/.kde4/Autostart/*",
  "/home/*/.kde/share/autostart/*", "/root/.kde/share/autostart/*",
  "/home/*/.kde4/share/autostart/*", "/root/.kde4/share/autostart/*",
  "/home/*/.local/share/autostart/*", "/root/.local/share/autostart/*",
  "/home/*/.config/autostart-scripts/*", "/root/.config/autostart-scripts/*",
  "/etc/xdg/autostart/*", "/usr/share/autostart/*"
) and
not (
  process.name in (
    "yum", "dpkg", "install", "dnf", "teams", "yum-cron", "dnf-automatic", "docker", "dockerd", "rpm", "pacman",
    "podman", "nautilus", "remmina", "cinnamon-settings.py", "executor", "xfce4-clipman", "jetbrains-toolbox",
    "ansible-admin", "apk"
  ) or
  process.executable in (
    "/usr/bin/dnf5", "/usr/libexec/xdg-desktop-portal", "/usr/sbin/mkhomedir_helper", "/sbin/mkhomedir_helper",
    "/usr/bin/crio", "/usr/sbin/useradd", "/usr/bin/nextcloud", "/usr/bin/sealert", "/opt/google/chrome/chrome",
    "/usr/bin/pamac-daemon", "/usr/sbin/sshd", "/usr/sbin/gdm", "/usr/libexec/platform-python"
  ) or
  process.executable like "/home/*/.MathWorks/*/glnxa64/mlcpostinstall"
)
```



### KRBTGT Delegation Backdoor

Branch count: 1  
Document count: 1  
Index: geneve-ut-0612

```python
iam where host.os.type == "windows" and event.code == "4738" and winlog.event_data.AllowedToDelegateTo : "*krbtgt*"
```



### Kerberos Cached Credentials Dumping

Branch count: 2  
Document count: 2  
Index: geneve-ut-0613

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  process.name == "kcc" and
  process.args like~ "copy_cred_cache"
```



### Kerberos Pre-authentication Disabled for User

Branch count: 1  
Document count: 1  
Index: geneve-ut-0614

```python
any where host.os.type == "windows" and event.code == "4738" and
  winlog.event_data.NewUACList == "USER_DONT_REQUIRE_PREAUTH"
```



### Kerberos Traffic from Unusual Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-0615

```python
network where host.os.type == "windows" and event.type == "start" and network.direction == "egress" and
  destination.port == 88 and source.port >= 49152 and process.pid != 4 and destination.address : "*" and
  not 
  (
    process.executable : (
        "\\device\\harddiskvolume?\\program files (x86)\\nmap\\nmap.exe",
        "\\device\\harddiskvolume?\\program files (x86)\\nmap oem\\nmap.exe",
        "\\device\\harddiskvolume?\\windows\\system32\\lsass.exe",
        "?:\\Program Files\\Amazon Corretto\\jdk1*\\bin\\java.exe",
        "?:\\Program Files\\BlackBerry\\UEM\\Proxy Server\\bin\\prunsrv.exe",
        "?:\\Program Files\\BlackBerry\\UEM\\Core\\tomcat-core\\bin\\tomcat9.exe",
        "?:\\Program Files\\DBeaver\\dbeaver.exe",
        "?:\\Program Files\\Docker\\Docker\\resources\\com.docker.backend.exe",
        "?:\\Program Files\\Docker\\Docker\\resources\\com.docker.vpnkit.exe",
        "?:\\Program Files\\Docker\\Docker\\resources\\vpnkit.exe",
        "?:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "?:\\Program Files\\Internet Explorer\\iexplore.exe",
        "?:\\Program Files\\JetBrains\\PyCharm Community Edition*\\bin\\pycharm64.exe",
        "?:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "?:\\Program Files\\Oracle\\VirtualBox\\VirtualBoxVM.exe",
        "?:\\Program Files\\Puppet Labs\\Puppet\\puppet\\bin\\ruby.exe",
        "?:\\Program Files\\rapid7\\nexpose\\nse\\.DLLCACHE\\nseserv.exe",
        "?:\\Program Files\\Silverfort\\Silverfort AD Adapter\\SilverfortServer.exe",
        "?:\\Program Files\\Tenable\\Nessus\\nessusd.exe",
        "?:\\Program Files\\VMware\\VMware View\\Server\\bin\\ws_TomcatService.exe",
        "?:\\Program Files (x86)\\Advanced Port Scanner\\advanced_port_scanner.exe",
        "?:\\Program Files (x86)\\DesktopCentral_Agent\\bin\\dcpatchscan.exe",
        "?:\\Program Files (x86)\\GFI\\LanGuard 12 Agent\\lnsscomm.exe",
        "?:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        "?:\\Program Files (x86)\\Internet Explorer\\iexplore.exe",
        "?:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "?:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
        "?:\\Program Files (x86)\\Microsoft Silverlight\\sllauncher.exe",
        "?:\\Program Files (x86)\\Nmap\\nmap.exe",
        "?:\\Program Files (x86)\\Nmap OEM\\nmap.exe",
        "?:\\Program Files (x86)\\nwps\\NetScanTools Pro\\NSTPRO.exe",
        "?:\\Program Files (x86)\\SAP BusinessObjects\\tomcat\\bin\\tomcat9.exe",
        "?:\\Program Files (x86)\\SuperScan\\scanner.exe",
        "?:\\Program Files (x86)\\Zscaler\\ZSATunnel\\ZSATunnel.exe",
        "?:\\Windows\\System32\\lsass.exe",
        "?:\\Windows\\System32\\MicrosoftEdgeCP.exe",
        "?:\\Windows\\System32\\svchost.exe",
        "?:\\Windows\\SysWOW64\\vmnat.exe",
        "?:\\Windows\\SystemApps\\Microsoft.MicrosoftEdge_*\\MicrosoftEdge.exe",
        "System"
    ) and process.code_signature.trusted == true
  ) and
 destination.address != "127.0.0.1" and destination.address != "::1"
```



### Kernel Driver Load

Branch count: 2  
Document count: 2  
Index: geneve-ut-0616

```python
driver where host.os.type == "linux" and event.action == "loaded-kernel-module" and
auditd.data.syscall in ("init_module", "finit_module")
```



### Kernel Driver Load by non-root User

Branch count: 2  
Document count: 2  
Index: geneve-ut-0617

```python
driver where host.os.type == "linux" and event.action == "loaded-kernel-module" and
auditd.data.syscall in ("init_module", "finit_module") and user.id != "0"
```



### Kernel Load or Unload via Kexec Detected

Branch count: 36  
Document count: 36  
Index: geneve-ut-0618

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "kexec" and process.args in ("--exec", "-e", "--load", "-l", "--unload", "-u") and
not (
  process.parent.name in ("kdumpctl", "unload.sh") or
  process.parent.args in ("/usr/bin/kdumpctl", "/usr/sbin/kdump-config", "/usr/lib/kdump/unload.sh")
)
```



### Kernel Module Load via insmod

Branch count: 12  
Document count: 12  
Index: geneve-ut-0619

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "insmod" and process.args : "*.ko" and
not (
  ?process.parent.executable like ("/opt/ds_agent/*", "/opt/TrendMicro/vls_agent/*", "/opt/intel/oneapi/*") or
  ?process.working_directory in ("/opt/vinchin/agent", "/var/opt/ds_agent/am", "/opt/ds_agent", "/var/opt/TrendMicro/vls_agent/am") or
  ?process.parent.executable in (
    "/usr/lib/uptrack/ksplice-apply", "/opt/commvault/commvault/Base/linux_drv", "/opt/cisco/amp/bin/cisco-amp-helper",
    "/usr/bin/kcarectl", "/usr/share/ksplice/ksplice-apply", "/opt/commvault/Base/linux_drv", "/usr/sbin/veeamsnap-loader",
    "/bin/falcoctl"
  ) or
  (?process.parent.name like ("python*", "platform-python*") and ?process.parent.args in ("--smart-update", "--auto-update"))
)
```



### Kernel Module Removal

Branch count: 120  
Document count: 120  
Index: geneve-ut-0620

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
(
  process.name == "rmmod" or
  (process.name == "modprobe" and process.args in ("--remove", "-r"))
) and
process.parent.name in ("sudo", "bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
not (
  ?process.parent.args like "/var/tmp/rpm-tmp*" or
  ?process.working_directory like~ ("/tmp/makeself*NVIDIA-Linux*", "/tmp/self*NVIDIA-Linux*")
)
```



### Kernel Seeking Activity

Branch count: 12  
Document count: 12  
Index: geneve-ut-0622

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
(process.parent.args like "/boot/*" or process.args like "/boot/*") and (
  (process.name == "tail" and (process.args like "-c*" or process.args == "--bytes")) or
  (process.name == "cmp" and process.args == "-i") or
  (process.name in ("hexdump", "xxd") and process.args == "-s") or
  (process.name == "dd" and process.args like "seek*")
) and process.parent.executable != null and
not (
  process.parent.executable in (
    "/usr/lib/needrestart/vmlinuz-get-version", "/bin/dracut", "/sbin/dracut", "/usr/sbin/dracut"
  ) or
  process.parent.args in (
    "/usr/bin/dracut", "/usr/lib/needrestart/vmlinuz-get-version", "/sbin/dracut", "/bin/dracut",
    "/usr/sbin/dracut", "/usr/bin/spectre-meltdown-checker", "/usr/lib/module-init-tools/lsinitrd-quick"
  )
)
```



### Kernel Unpacking Activity

Branch count: 26  
Document count: 26  
Index: geneve-ut-0623

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
(process.parent.args like "/boot/*" or process.args like "/boot/*") and (
  (process.name in ("file", "unlzma", "gunzip", "unxz", "bunzip2", "unzstd", "unzip", "tar")) or
  (process.name == "grep" and process.args == "ELF") or
  (process.name in ("lzop", "lz4") and process.args in ("-d", "--decode"))
) and
not (
  process.parent.name == "mkinitramfs" or
  process.parent.executable like (
    "/usr/lib/needrestart/vmlinuz-get-version", "/usr/libexec/platform-python*", "/tmp/newroot/usr/libexec/platform-python*",
    "/usr/bin/kdumpctl", "/usr/bin/stap-report", "/usr/sbin/nv-update-initrd"
  ) or
  process.parent.command_line like "*ansible*" or
  process.parent.args == "/usr/bin/kdumpctl"
)
```



### Keychain CommandLine Interaction via Unsigned or Untrusted Process

Branch count: 128  
Document count: 128  
Index: geneve-ut-0624

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and event.action == "exec" and
  process.args like ("/Users/*/Library/Keychains/*", "/Library/Keychains/*", "login.keychain-db", "login.keychain") and 
  ((process.code_signature.trusted == false or process.code_signature.exists == false) or 
   (process.name in ("bash", "sh", "zsh", "osascript", "cat", "echo", "cp") and 
   (process.parent.code_signature.trusted == false or process.parent.code_signature.exists == false)))
```



### Keychain Password Retrieval via Command Line

Branch count: 28  
Document count: 28  
Index: geneve-ut-0625

```python
process where host.os.type == "macos" and event.action == "exec" and
 process.name == "security" and
 process.args like ("-wa", "-ga") and process.args like~ ("find-generic-password", "find-internet-password") and
 process.command_line : ("*Chrome*", "*Chromium*", "*Opera*", "*Safari*", "*Brave*", "*Microsoft Edge*", "*Firefox*") and
 not process.parent.executable like "/Applications/Keeper Password Manager.app/Contents/Frameworks/Keeper Password Manager Helper*/Contents/MacOS/Keeper Password Manager Helper*"
```



### Kirbi File Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-0627

```python
file where host.os.type == "windows" and event.type == "creation" and file.extension : "kirbi"
```



### Kubeconfig File Creation or Modification

Branch count: 16  
Document count: 16  
Index: geneve-ut-0628

```python
file where host.os.type == "linux" and event.type != "deletion" and file.path like (
  "/root/.kube/config",
  "/home/*/.kube/config",
  "/etc/kubernetes/admin.conf",
  "/etc/kubernetes/super-admin.conf",
  "/etc/kubernetes/kubelet.conf",
  "/etc/kubernetes/controller-manager.conf",
  "/etc/kubernetes/scheduler.conf",
  "/var/lib/*/kubeconfig"
) and not (
  process.name in ("kubeadm", "kubelet", "vcluster", "minikube", "kind") or
  (process.name == "sed" and ?file.Ext.original.name like "sed*") or
  process.executable like (
    "/usr/local/bin/k3d", "/usr/local/aws-cli/*/dist/aws", "/usr/local/bin/ks", "/usr/local/bin/aws",
    "/usr/local/bin/kubectl"
  )
)
```



### Kubectl Apply Pod from URL

Branch count: 12  
Document count: 12  
Index: geneve-ut-0630

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "process_started", "executed") and
process.name == "kubectl" and process.args == "apply" and
process.args like ("http://*", "https://*") and
not process.args like~ ("*download.elastic.co*", "*github.com/kubernetes-sigs/*")
```



### Kubectl Network Configuration Modification

Branch count: 180  
Document count: 180  
Index: geneve-ut-0632

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.name == "kubectl" and (
  process.args == "port-forward" and process.args like "*:*" or
  process.args in ("proxy", "expose")
) and (
  process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") or
  (
    process.parent.executable like ("/tmp/*", "/var/tmp/*", "/dev/shm/*", "/root/*", "/home/*") or
    process.parent.name like (".*", "*.sh")
  )
)
```



### Kubectl Permission Discovery

Branch count: 6  
Document count: 6  
Index: geneve-ut-0633

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "kubectl" and process.args == "auth" and process.args == "can-i"
```



### Kubectl Workload and Cluster Discovery

Branch count: 20  
Document count: 20  
Index: geneve-ut-0634

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "executed", "process_started", "ProcessRollup2") and
process.name == "kubectl" and (
  (process.args in ("cluster-info", "api-resources", "api-versions", "version")) or
  (process.args in ("get", "describe") and process.args in (
    "namespaces", "nodes", "pods", "pod", "deployments", "deployment",
    "replicasets", "statefulsets", "daemonsets", "services", "service",
    "ingress", "ingresses", "endpoints", "configmaps", "events", "svc",
    "roles", "rolebindings", "clusterroles", "clusterrolebindings"
    )
  )
)
```



### Kubelet Certificate File Access Detected via Defend for Containers

Branch count: 36  
Document count: 36  
Index: geneve-ut-0635

```python
any where host.os.type == "linux" and process.interactive == true and container.id like "*" and (
  (event.category == "file" and event.type == "change" and event.action == "open" and file.path like "/var/lib/kubelet/pki/*") or
  (event.category == "process" and event.type == "start" and event.action == "exec" and
  (
    process.name in ("cat", "head", "tail", "more", "less", "sed", "awk") or
    process.args in (
      "cat", "/bin/cat", "/usr/bin/cat", "/usr/local/bin/cat",
      "head", "/bin/head", "/usr/bin/head", "/usr/local/bin/head",
      "tail", "/bin/tail", "/usr/bin/tail", "/usr/local/bin/tail",
      "more", "/bin/more", "/usr/bin/more", "/usr/local/bin/more",
      "less", "/bin/less", "/usr/bin/less", "/usr/local/bin/less",
      "sed", "/bin/sed", "/usr/bin/sed", "/usr/local/bin/sed",
      "awk", "/bin/awk", "/usr/bin/awk", "/usr/local/bin/awk"
    )
  ) and process.args like "*/var/lib/kubelet/pki/*")
)
```



### Kubernetes Anonymous User Create/Update/Patch Pods Request

Branch count: 36  
Document count: 36  
Index: geneve-ut-0638

```python
any where event.dataset == "kubernetes.audit_logs" and (
    kubernetes.audit.user.username in ("system:anonymous", "system:unauthenticated") or
    kubernetes.audit.user.username == null or
    kubernetes.audit.user.username == ""
  ) and kubernetes.audit.level in ("RequestResponse", "ResponseComplete", "Request") and kubernetes.audit.verb in ("create", "update", "patch") and
kubernetes.audit.objectRef.resource == "pods"
```



### Kubernetes Cluster-Admin Role Binding Created

Branch count: 2  
Document count: 2  
Index: geneve-ut-0639

```python
event.dataset: "kubernetes.audit_logs" and kubernetes.audit.objectRef.resource:("clusterrolebindings" or "rolebindings") and
kubernetes.audit.verb:"create" and kubernetes.audit.requestObject.roleRef.name:"cluster-admin" and
kubernetes.audit.annotations.authorization_k8s_io/decision:"allow" and
kubernetes.audit.level:"RequestResponse" and kubernetes.audit.stage:"ResponseComplete"
```



### Kubernetes Creation of a RoleBinding Referencing a ServiceAccount

Branch count: 2  
Document count: 2  
Index: geneve-ut-0641

```python
event.dataset: "kubernetes.audit_logs" and kubernetes.audit.requestObject.spec.serviceAccountName:* and
kubernetes.audit.verb:"create" and kubernetes.audit.objectRef.resource:("rolebindings" or "clusterrolebindings") and
kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
```



### Kubernetes Direct API Request via Curl or Wget

Branch count: 84  
Document count: 84  
Index: geneve-ut-0644

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "executed", "process_started", "ProcessRollup2") and
process.name in ("curl", "wget") and process.args like~ (
  "*http*//*/apis/authorization.k8s.io/*",
  "*http*//*/apis/rbac.authorization.k8s.io/*",
  "*http*//*/api/v1/secrets*",
  "*http*//*/api/v1/namespaces/*/secrets*",
  "*http*//*/api/v1/configmaps*",
  "*http*//*/api/v1/pods*",
  "*http*//*/apis/apps/v1/deployments*"
)
```



### Kubernetes Events Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-0645

```python
any where event.dataset == "kubernetes.audit_logs" and kubernetes.audit.verb == "delete" and
kubernetes.audit.objectRef.resource == "events" and kubernetes.audit.stage == "ResponseComplete"
```



### Kubernetes Exposed Service Created With Type NodePort

Branch count: 3  
Document count: 3  
Index: geneve-ut-0646

```python
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.objectRef.resource:"services"
  and kubernetes.audit.verb:("create" or "update" or "patch")
  and kubernetes.audit.requestObject.spec.type:"NodePort"
```



### Kubernetes Pod Created With HostIPC

Branch count: 3  
Document count: 3  
Index: geneve-ut-0649

```python
event.dataset : "kubernetes.audit_logs" and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow" and
kubernetes.audit.objectRef.resource:"pods" and kubernetes.audit.verb:("create" or "update" or "patch") and
kubernetes.audit.requestObject.spec.hostIPC:true and
not kubernetes.audit.requestObject.spec.containers.image: (
  docker.elastic.co/beats/elastic-agent* or rancher/system-agent* or registry.crowdstrike.com/falcon-sensor*
)
```



### Kubernetes Pod Created With HostNetwork

Branch count: 3  
Document count: 3  
Index: geneve-ut-0650

```python
event.dataset:kubernetes.audit_logs and kubernetes.audit.annotations.authorization_k8s_io/decision:allow and
kubernetes.audit.objectRef.resource:pods and kubernetes.audit.verb:(create or patch or update) and
kubernetes.audit.requestObject.spec.hostNetwork:true and
not (
  kubernetes.audit.requestObject.spec.containers.image:(
    *eks/observability/aws-for-fluent-bit* or *eks/observability/cloudwatch-agent* or *elastic-agent* or *quay/tigera* or *tigera/operator* or
    docker.io/bitnami/node-exporter* or docker.io/rancher/mirrored-calico-operator* or quay.io/calico/node* or quay.io/cephcsi/cephcsi* or
    quay.io/frrouting/frr* or quay.io/metallb/speaker* or quay.io/prometheus/node-exporter* or rancher/system-agent* or
    registry.crowdstrike.com/falcon-sensor* or registry.k8s.io/sig-storage/csi-node-driver-registrar*
  ) or
  kubernetes.audit.objectRef.namespace:(
    calico or calico-system or cilium or elastic or ingress-nginx or kube-system or noname-security-posture or openebs or sysdig-agent
  )
)
```



### Kubernetes Pod Created With HostPID

Branch count: 3  
Document count: 3  
Index: geneve-ut-0651

```python
event.dataset : "kubernetes.audit_logs" and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow" and
kubernetes.audit.objectRef.resource:"pods" and kubernetes.audit.verb:("create" or "update" or "patch") and
kubernetes.audit.requestObject.spec.hostPID:true and
not kubernetes.audit.requestObject.spec.containers.image: (
  ghcr.io/aquasecurity/node-collector* or rancher/system-agent* or ghcr.io/kubereboot/kured* or 
  *elastic/elastic-agent* or registry.k8s.io/sig-storage/csi-node-driver-registrar* or quay.io/prometheus/node-exporter* or
  docker.elastic.co/beats/elastic-agent* or quay.io/cephcsi/cephcsi* or registry.crowdstrike.com/falcon-sensor* or */sysdig/* or
  rancher/mirrored-longhornio-longhorn-manager* or gcr.io/datadoghq/agent* or mcr.microsoft.com/oss/*/kubernetes-csi*
)
```



### Kubernetes Pod Created with a Sensitive hostPath Volume

Branch count: 48  
Document count: 48  
Index: geneve-ut-0652

```python
event.dataset : "kubernetes.audit_logs" and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow" and
kubernetes.audit.objectRef.resource:"pods" and kubernetes.audit.verb:("create" or "update" or "patch") and
kubernetes.audit.requestObject.spec.volumes.hostPath.path: (
  "/" or "/proc" or "/root" or "/var" or "/var/run" or "/var/run/docker.sock" or "/var/run/crio/crio.sock" or
  "/var/run/cri-dockerd.sock" or "/var/lib/kubelet" or "/var/lib/kubelet/pki" or "/var/lib/docker/overlay2" or
  "/etc" or "/etc/kubernetes" or "/etc/kubernetes/manifests" or "/etc/kubernetes/pki" or "/home/admin"
) and
not kubernetes.audit.requestObject.spec.containers.image: (
  docker.elastic.co/beats/elastic-agent* or *elastic/elastic-agent* or docker.elastic.co/elastic-agent/elastic-agent* or
  *elastic-agent\:dev* or *cloudops-azure-devops-agent* or rancher/mirrored-longhornio-longhorn-instance-manager* or
  quay.io/calico* or ghcr.io/aquasecurity* or rancher/system-agent* or rancher/mirrored-longhornio-csi-node-driver-registrar* or
  rancher/mirrored-longhornio-livenessprobe* or quay.io/prometheus/node-exporter* or *eks/observability/cloudwatch-agent* or
  amazon/aws-efs-csi-driver* or public.ecr.aws/eks-distro/kubernetes-csi* or quay.io/cilium/cilium* or openebs/node-disk-manager* or
  openebs/cstor-csi-driver* or registry.k8s.io/sig-storage/csi-node-driver-registrar* or *.amazonaws.com/eks/csi-node-driver-registrar* or
  *.amazonaws.com/eks/livenessprobe* or *.amazonaws.com/eks/aws-efs-csi-driver* or mcr.microsoft.com/oss/v2/kubernetes-csi* or
  rancher/mirrored-cilium-cilium* or jenkins/inbound-agent* or gcr.io/datadoghq/agent* or rancher/mirrored-longhornio-longhorn-share-manager* or
  */sysdig/*
)
```



### Kubernetes Privileged Pod Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-0655

```python
event.dataset : "kubernetes.audit_logs" and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow" and
kubernetes.audit.objectRef.resource:pods and kubernetes.audit.verb:create and kubernetes.audit.requestObject.spec.containers.securityContext.privileged:true and
not kubernetes.audit.requestObject.spec.containers.image: (
  *amazonaws.com/betsie/pipeline/pipeline-core* or mirror.gcr.io/aquasec/trivy* or rancher/mirrored-longhornio-longhorn-instance-manager* or quay.io/calico* or
  rancher/system-agent* or openebs/m-exporter* or openebs/cstor-istgt* or ghcr.io/kubereboot/kured* or registry.k8s.io/sig-storage/csi-node-driver-registrar* or
  registry.k8s.io/csi-secrets-store* or registry.gitlab.com/gitlab-org/gitlab-runner/gitlab-runner-helper* or sonarsource/sonar-scanner-cli* or
  rancher/mirrored-longhornio-longhorn-engine* or jenkins/inbound-agent* or mcr.microsoft.com/oss/v2/kubernetes-csi* or registry.k8s.io/dns/k8s-dns-node-cache* or
  *amazonaws.com/eks/kube-proxy* or *amazonaws.com/eks/aws-efs-csi-driver* or *amazonaws.com/eks/livenessprobe* or *amazonaws.com/amazon-k8s-cni* or
  *amazonaws.com/amazon/aws-network-policy-agent* or mcr.microsoft.com/oss/kubernetes-csi* or openebs/node-disk-manager* or openebs/node-disk-exporter* or
  mcr.microsoft.com/oss/kubernetes/kube-proxy* or public.ecr.aws/eks-distro/kubernetes-csi/livenessprobe* or public.ecr.aws/eks-distro/kubernetes-csi/external-provisioner* or
  amazon/aws-efs-csi-driver* or registry.k8s.io/kube-proxy* or registry.crowdstrike.com/falcon-sensor* or *octopus-deploy/tentacle* or */sysdig/*
)
```



### Kubernetes Sensitive Configuration File Activity

Branch count: 6  
Document count: 6  
Index: geneve-ut-0656

```python
file where host.os.type == "linux" and event.type != "deletion" and file.path like (
  "/etc/kubernetes/manifests/*",
  "/etc/kubernetes/pki/*",
  "/etc/kubernetes/*.conf"
) and not (
  process.name in ("kubeadm", "kubelet", "dpkg", "sed") or
  (process.name in ("vi", "vim", "vim.basic") and file.extension in ("swx", "swp"))
)
```



### Kubernetes Service Account Modified RBAC Objects

Branch count: 16  
Document count: 16  
Index: geneve-ut-0658

```python
event.dataset:"kubernetes.audit_logs" and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow" and
kubernetes.audit.user.username:(
  system\:serviceaccount\:* and not (
    "system:serviceaccount:kube-system:clusterrole-aggregation-controller" or
    "system:serviceaccount:kube-system:generic-garbage-collector"
  )
) and
kubernetes.audit.objectRef.resource:("clusterrolebindings" or "clusterroles" or "rolebindings" or "roles") and
kubernetes.audit.verb:("create" or "delete" or "patch" or "update")
```



### Kubernetes Service Account Secret Access

Branch count: 72  
Document count: 72  
Index: geneve-ut-0659

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.command_line like (
    "*/run/secrets/kubernetes.io/serviceaccount*",
    "*/var/run/secrets/kubernetes.io/serviceaccount*",
    "*/secrets/kubernetes.io/serviceaccount*"
  ) or (
    process.working_directory like (
      "/run/secrets/kubernetes.io/serviceaccount",
      "/var/run/secrets/kubernetes.io/serviceaccount",
      "/secrets/kubernetes.io/serviceaccount"
    ) and
    process.args in ("ca.crt", "token")
  )
) and
not (
  process.command_line like "*/bin/test*" or
  process.args in (
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/secrets/kubernetes.io/serviceaccount/namespace"
  ) or
  process.command_line == "/usr/bin/coreutils --coreutils-prog-shebang=cat /usr/bin/cat /var/run/secrets/kubernetes.io/serviceaccount/token" or
  process.parent.command_line == "runc init" or
  (process.parent.name == "px-oci-mon" and process.name == "rsync") or
  (
    process.parent.command_line == "sh /install-cni.sh" and
    process.working_directory like (
      "/opt/cni/bin", "/run/containerd/io.containerd.runtime.v2.task/k8s.io/*/opt/cni/bin"
    )
  ) or
  (process.working_directory like "/home/runner/_work/*" and process.parent.args like "/home/runner/_work/_temp/*.sh") or
  process.working_directory == "/opt/cni/bin"
)
```



### Kubernetes Suspicious Assignment of Controller Service Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-0660

```python
event.dataset : "kubernetes.audit_logs" and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow" and
kubernetes.audit.verb : "create" and kubernetes.audit.objectRef.resource : "pods" and
kubernetes.audit.objectRef.namespace : "kube-system" and kubernetes.audit.requestObject.spec.serviceAccountName:*controller and
not kubernetes.audit.requestObject.spec.containers.image:(
  mirror.gcr.io/aquasec/trivy* or *amazonaws.com/eks/snapshot-controller* or rancher/mirrored-sig-storage-snapshot-controller* or
  public.ecr.aws/eks/aws-load-balancer-controller* or docker.io/bitnami/sealed-secrets-controller* or exoscale/csi-driver* or
  registry.k8s.io/autoscaling/vpa-admission-controller* or registry.k8s.io/sig-storage/csi-attacher* or registry.k8s.io/sig-storage/csi-provisioner*
)
```



### LSASS Memory Dump Creation

Branch count: 20  
Document count: 20  
Index: geneve-ut-0666

```python
file where host.os.type == "windows" and event.action != "deletion" and
  file.name : ("lsass*.dmp", "dumpert.dmp", "Andrew.dmp", "SQLDmpr*.mdmp", "Coredump.dmp") and

  not (
        process.executable : (
          "?:\\Program Files\\Microsoft SQL Server\\*\\Shared\\SqlDumper.exe",
          "?:\\Program Files\\Microsoft SQL Server Reporting Services\\SSRS\\ReportServer\\bin\\SqlDumper.exe",
          "?:\\Windows\\System32\\dllhost.exe"
        ) and
        file.path : (
          "?:\\*\\Reporting Services\\Logfiles\\SQLDmpr*.mdmp",
          "?:\\Program Files\\Microsoft SQL Server Reporting Services\\SSRS\\Logfiles\\SQLDmpr*.mdmp",
          "?:\\Program Files\\Microsoft SQL Server\\*\\Shared\\ErrorDumps\\SQLDmpr*.mdmp",
          "?:\\Program Files\\Microsoft SQL Server\\*\\MSSQL\\LOG\\SQLDmpr*.mdmp"
        )
      ) and

  not (
        process.executable : (
          "?:\\Windows\\system32\\WerFault.exe",
          "?:\\Windows\\System32\\WerFaultSecure.exe"
          ) and
        file.path : (
          "?:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\CrashDumps\\lsass.exe.*.dmp",
          "?:\\Windows\\System32\\%LOCALAPPDATA%\\CrashDumps\\lsass.exe.*.dmp"
        )
  )
```



### Lateral Movement via Startup Folder

Branch count: 8  
Document count: 8  
Index: geneve-ut-0671

```python
file where host.os.type == "windows" and event.type in ("creation", "change") and

 /* via RDP TSClient mounted share or SMB */
  (process.name : "mstsc.exe" or process.pid == 4) and

   file.path : ("?:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
                "?:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")
```



### Launch Service Creation and Immediate Loading

Branch count: 2  
Document count: 4  
Index: geneve-ut-0672

```python
sequence by host.id with maxspan=30s
 [file where host.os.type == "macos" and event.action == "launch_daemon"] by process.entity_id
 [process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name == "launchctl" and process.args == "load"] by process.parent.entity_id
```



### Linux Process Hooking via GDB

Branch count: 12  
Document count: 12  
Index: geneve-ut-0676

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started")
 and process.name == "gdb" and process.args in ("--pid", "-p") and
/* Covered by d4ff2f53-c802-4d2e-9fb9-9ecc08356c3f */
process.args != "1"
```



### Linux Restricted Shell Breakout via Linux Binary(s)

Branch count: 303  
Document count: 303  
Index: geneve-ut-0677

```python
process where host.os.type == "linux" and event.type == "start" and process.executable != null and
(
  /* launching shell from capsh */
  (process.name == "capsh" and process.args == "--" and not process.parent.executable == "/usr/bin/log4j-cve-2021-44228-hotpatch") or

  /* launching shells from unusual parents or parent+arg combos */
  (process.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and (
    (process.parent.name : "*awk" and process.parent.args : "BEGIN {system(*)}") or
    (process.parent.name == "git" and process.parent.args : ("!*sh", "exec *sh") and not process.name == "ssh" ) or
    (process.parent.name : ("byebug", "ftp", "strace", "zip", "tar") and
    (
      process.parent.args : "BEGIN {system(*)}" or
      (
        (process.parent.args : "exec=*sh" or (process.parent.args : "-I" and process.parent.args : "*sh")) or
        (process.args : "exec=*sh" or (process.args : "-I" and process.args : "*sh"))
        )
      )
    ) or

    /* shells specified in parent args */
    /* nice rule is broken in 8.2 */
    (process.parent.args : "*sh" and
      (
        (process.parent.name == "nice") or
        (process.parent.name == "cpulimit" and process.parent.args == "-f") or
        (process.parent.name == "find" and process.parent.args == "." and process.parent.args == "-exec" and
         process.parent.args == ";" and process.parent.args : "/bin/*sh") or
        (process.parent.name == "flock" and process.parent.args == "-u" and process.parent.args == "/")
      )
    )
  )) or

  /* shells specified in args */
  (process.args : "*sh" and (
    (process.parent.name == "crash" and process.parent.args == "-h") or
    (process.name == "sensible-pager" and process.parent.name in ("apt", "apt-get") and process.parent.args == "changelog")
    /* scope to include more sensible-pager invoked shells with different parent process to reduce noise and remove false positives */

  )) or
  (process.name == "busybox" and event.action == "exec" and process.args_count == 2 and process.args : "*sh" and not
   process.executable : "/var/lib/docker/overlay2/*/merged/bin/busybox" and not (process.parent.args == "init" and
   process.parent.args == "runc") and not process.parent.args in ("ls-remote", "push", "fetch") and not process.parent.name == "mkinitramfs" and
   not process.parent.executable == "/bin/busybox") or
  (process.name == "env" and process.args_count == 2 and process.args : "*sh") or
  (process.parent.name in ("vi", "vim") and process.parent.args == "-c" and process.parent.args : ":!*sh") or
  (process.parent.name in ("c89", "c99", "gcc") and process.parent.args : "*sh,-s" and process.parent.args == "-wrapper") or
  (process.parent.name == "expect" and process.parent.args == "-c" and process.parent.args : "spawn *sh;interact") or
  (process.parent.name == "mysql" and process.parent.args == "-e" and process.parent.args : "\\!*sh") or
  (process.parent.name == "ssh" and process.parent.args == "-o" and process.parent.args : "ProxyCommand=;*sh 0<&2 1>&2")
)
```



### Linux SSH X11 Forwarding

Branch count: 144  
Document count: 144  
Index: geneve-ut-0678

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.name in ("ssh", "sshd") and process.args in ("-X", "-Y") and process.args_count >= 3 and
process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
```



### Linux Telegram API Request

Branch count: 12  
Document count: 12  
Index: geneve-ut-0681

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "start", "exec_event", "ProcessRollup2", "executed", "exec_event", "process_started") and
process.name in ("curl", "wget") and process.command_line like "*api.telegram.org*"
```



### Linux User Account Credential Modification

Branch count: 32  
Document count: 32  
Index: geneve-ut-0683

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
process.command_line like (
  "*echo*> /etc/passwd*", "*echo*>/etc/passwd*",
  "*echo*> /etc/shadow*", "*echo*>/etc/shadow*"
) and
not (
  process.parent.command_line == "runc init" or
  process.parent.executable in ("/usr/bin/make", "/bin/make")
)
```



### Linux User Added to Privileged Group

Branch count: 360  
Document count: 360  
Index: geneve-ut-0684

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.executable != null and process.args in (
  "root", "admin", "wheel", "staff", "sudo","disk", "video", "shadow", "lxc", "lxd"
) and
(
  process.name in ("usermod", "adduser") or
  (process.name == "gpasswd" and process.args in ("-a", "--add", "-M", "--members"))
)
```



### Loadable Kernel Module Configuration File Creation

Branch count: 40  
Document count: 40  
Index: geneve-ut-0688

```python
file where host.os.type == "linux" and event.action == "creation" and process.executable != null and
file.path like (
  "/etc/modules", "/etc/modprobe.d/*", "/run/modprobe.d/*", "/usr/local/lib/modprobe.d/*", "/usr/lib/modprobe.d/*",
  "/lib/modprobe.d/*", "/etc/modules-load.d/*", "/run/modules-load.d/*", "/usr/local/lib/modules-load.d/*",
  "/usr/lib/modules-load.d/*"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/local/bin/dockerd", "/opt/elasticbeanstalk/bin/platform-engine",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/opt/imunify360/venv/bin/python3",
    "/opt/eset/efs/lib/utild", "/usr/sbin/anacron", "/usr/bin/podman", "/kaniko/kaniko-executor", "/usr/bin/prime-select",
    "/usr/lib/dracut/dracut-install", "/usr/bin/dnf5", "./usr/bin/podman", "/usr/libexec/packagekitd", "/usr/bin/buildah",
    "./usr/lib/snapd/snap-update-ns", "/usr/lib/snapd/snapd", "/usr/local/bin/podman", "/usr/sbin/yum-cron",
    "./usr/bin/qemu-aarch64-static", "/.envbuilder/bin/envbuilder"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable like (
    "/nix/store/*", "/var/lib/dpkg/info/kmod.postinst", "/tmp/vmis.*", "/snap/*", "/dev/fd/*",
    "/usr/libexec/platform-python*", "./snap/snapd/*/snap-update-ns"
  ) or
  process.executable == null or
  process.name in (
    "crond", "executor", "puppet", "droplet-agent.postinst", "cf-agent", "schedd", "imunify-notifier", "perl",
    "jumpcloud-agent", "crio", "dnf_install", "utild", "dockerd"
  ) or
  process.name like "python*" or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*")
)
```



### Local Account TokenFilter Policy Disabled

Branch count: 6  
Document count: 6  
Index: geneve-ut-0689

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : "LocalAccountTokenFilterPolicy" and
  registry.path : (
    "HKLM\\*\\LocalAccountTokenFilterPolicy",
    "\\REGISTRY\\MACHINE\\*\\LocalAccountTokenFilterPolicy",
    "MACHINE\\*\\LocalAccountTokenFilterPolicy"
  ) and registry.data.strings : ("1", "0x00000001") and
  not process.executable : (
    /* Intune */
    "C:\\Windows\\system32\\deviceenroller.exe",
    "C:\\Windows\\system32\\omadmclient.exe",

    /* Crowdstrike specific exclusion as it uses NT Object paths */
    "\\Device\\HarddiskVolume*\\system32\\deviceenroller.exe",
    "\\Device\\HarddiskVolume*\\system32\\omadmclient.exe"
  )
```



### Local Scheduled Task Creation

Branch count: 600  
Document count: 1200  
Index: geneve-ut-0690

```python
sequence with maxspan=1m
  [process where host.os.type == "windows" and event.type == "start" and
    ((process.name : ("cmd.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "mshta.exe",
                      "powershell.exe", "pwsh.exe", "powershell_ise.exe", "WmiPrvSe.exe", "wsmprovhost.exe", "winrshost.exe") or
    process.pe.original_file_name : ("cmd.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "mshta.exe",
                                     "powershell.exe", "pwsh.dll", "powershell_ise.exe", "WmiPrvSe.exe", "wsmprovhost.exe",
                                     "winrshost.exe")) or
    ?process.code_signature.trusted == false)] by process.entity_id
  [process where host.os.type == "windows" and event.type == "start" and
    (process.name : "schtasks.exe" or process.pe.original_file_name == "schtasks.exe") and
    process.args : ("/create", "-create") and process.args : ("/RU", "/SC", "/TN", "/TR", "/F", "/XML") and
    /* exclude SYSTEM Integrity Level - look for task creations by non-SYSTEM user */
    not (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System")
  ] by process.parent.entity_id
```



### M365 Exchange Anti-Phish Policy Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-0691

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-AntiPhishPolicy" and event.outcome:success
```



### M365 Exchange Anti-Phish Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-0692

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-AntiPhishRule" or "Disable-AntiPhishRule") and event.outcome:success
```



### M365 Exchange DKIM Signing Configuration Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-0693

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Set-DkimSigningConfig" and o365.audit.Parameters.Enabled:False and event.outcome:success
```



### M365 Exchange DLP Policy Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-0694

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-DlpPolicy" and event.outcome:success
```



### M365 Exchange Email Safe Attachment Rule Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-0695

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Disable-SafeAttachmentRule" and event.outcome:success
```



### M365 Exchange Email Safe Link Policy Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-0696

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Disable-SafeLinksRule" and event.outcome:success
```



### M365 Exchange Federated Domain Created or Modified

Branch count: 6  
Document count: 6  
Index: geneve-ut-0697

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Set-AcceptedDomain" or
"Set-MsolDomainFederationSettings" or "Add-FederatedDomain" or "New-AcceptedDomain" or "Remove-AcceptedDomain" or "Remove-FederatedDomain") and
event.outcome:success
```



### M365 Exchange Inbox Forwarding Rule Created

Branch count: 12  
Document count: 12  
Index: geneve-ut-0698

```python
event.dataset:o365.audit and event.provider:Exchange and
event.category:web and event.action:("New-InboxRule" or "Set-InboxRule") and
    (
        o365.audit.Parameters.ForwardTo:* or
        o365.audit.Parameters.ForwardAsAttachmentTo:* or
        o365.audit.Parameters.ForwardingAddress:* or
        o365.audit.Parameters.ForwardingSmtpAddress:* or
        o365.audit.Parameters.RedirectTo:* or
        o365.audit.Parameters.RedirectToRecipients:*
    )
    and event.outcome:success
```



### M365 Exchange Mail Flow Transport Rule Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-0700

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"New-TransportRule" and event.outcome:success
```



### M365 Exchange Mail Flow Transport Rule Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-0701

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-TransportRule" or "Disable-TransportRule") and event.outcome:success
```



### M365 Exchange Mailbox Audit Logging Bypass Added

Branch count: 1  
Document count: 1  
Index: geneve-ut-0703

```python
event.dataset:o365.audit and event.provider:Exchange and event.action:Set-MailboxAuditBypassAssociation and event.outcome:success
```



### M365 Exchange Malware Filter Policy Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-0706

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-MalwareFilterPolicy" and event.outcome:success
```



### M365 Exchange Malware Filter Rule Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-0707

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-MalwareFilterRule" or "Disable-MalwareFilterRule") and event.outcome:success
```



### M365 Exchange Management Group Role Assigned

Branch count: 1  
Document count: 1  
Index: geneve-ut-0708

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"New-ManagementRoleAssignment" and event.outcome:success
```



### M365 Identity Global Administrator Role Assigned

Branch count: 2  
Document count: 2  
Index: geneve-ut-0710

```python
event.dataset:o365.audit
    and event.code:"AzureActiveDirectory"
    and event.action:"Add member to role."
    and event.outcome: "success"
    and o365.audit.ModifiedProperties.Role_DisplayName.NewValue: (
        "Global Administrator" or "Company Administrator"
    )
    and o365.audit.AzureActiveDirectoryEventType: 1
    and o365.audit.RecordType: 8
```



### M365 Identity OAuth Flow by User Sign-in to Device Registration

Branch count: 4  
Document count: 12  
Index: geneve-ut-0714

```python
sequence by related.user with maxspan=30m
[authentication where event.action == "UserLoggedIn" and
 o365.audit.ExtendedProperties.RequestType == "OAuth2:Authorize" and o365.audit.ExtendedProperties.ResultStatusDetail == "Redirect" and
 o365.audit.UserType: ("0", "2", "3", "10")] // victim source.ip
[authentication where event.action == "UserLoggedIn" and
 o365.audit.ExtendedProperties.RequestType == "OAuth2:Token" and o365.audit.ExtendedProperties.ResultStatusDetail == "Success"] // attacker source.ip to convert oauth code to token
[web where event.dataset == "o365.audit" and event.action == "Add registered users to device."] // user.name is captured in related.user
```



### M365 Identity OAuth Phishing via First-Party Microsoft Application

Branch count: 246  
Document count: 246  
Index: geneve-ut-0716

```python
event.dataset: "o365.audit"
    and event.action: "UserLoggedIn"
    and o365.audit.ExtendedProperties.RequestType: "OAuth2:Authorize"
    and o365.audit.ExtendedProperties.ResultStatusDetail: "Redirect"
    and o365.audit.UserType: ("0" or "2" or "3" or "5" or "6" or "10")
    and (
        (
            o365.audit.ApplicationId: (
                "aebc6443-996d-45c2-90f0-388ff96faa56" or
                "04b07795-8ddb-461a-bbee-02f9e1bf7b46" or
                "1950a258-227b-4e31-a9cf-717495945fc2"
            )
            and o365.audit.Target.ID: (
                "00000003-0000-0000-c000-000000000000" or
                "00000002-0000-0000-c000-000000000000"
            )
        ) or
        (
            o365.audit.ApplicationId: (
                "00b41c95-dab0-4487-9791-b9d2c32c80f2" or
                "1fec8e78-bce4-4aaf-ab1b-5451cc387264" or
                "26a7ee05-5602-4d76-a7ba-eae8b7b67941" or
                "27922004-5251-4030-b22d-91ecd9a37ea4" or
                "4813382a-8fa7-425e-ab75-3b753aab3abb" or
                "ab9b8c07-8f02-4f72-87fa-80105867a763" or
                "d3590ed6-52b3-4102-aeff-aad2292ab01c" or
                "872cd9fa-d31f-45e0-9eab-6e460a02d1f1" or
                "af124e86-4e96-495a-b70a-90f90ab96707" or
                "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8" or
                "844cca35-0656-46ce-b636-13f48b0eecbd" or
                "87749df4-7ccf-48f8-aa87-704bad0e0e16" or
                "cf36b471-5b44-428c-9ce7-313bf84528de" or
                "0ec893e0-5785-4de6-99da-4ed124e5296c" or
                "22098786-6e16-43cc-a27d-191a01a1e3b5" or
                "4e291c71-d680-4d0e-9640-0a3358e31177" or
                "57336123-6e14-4acc-8dcf-287b6088aa28" or
                "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0" or
                "66375f6b-983f-4c2c-9701-d680650f588f" or
                "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223" or
                "a40d7d7d-59aa-447e-a655-679a4107e548" or
                "a569458c-7f2b-45cb-bab9-b7dee514d112" or
                "b26aadf8-566f-4478-926f-589f601d9c74" or
                "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12" or
                "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0" or
                "e9c51622-460d-4d3d-952d-966a5b1da34c" or
                "eb539595-3fe1-474e-9c1d-feb3625d1be5" or
                "ecd6b820-32c2-49b6-98a6-444530e5a77a" or
                "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d" or
                "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34" or
                "be1918be-3fe3-4be9-b32b-b542fc27f02e" or
                "cab96880-db5b-4e15-90a7-f3f1d62ffe39" or
                "d7b530a4-7680-4c23-a8bf-c52c121d2e87" or
                "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3" or
                "e9b154d0-7658-433b-bb25-6b8e0a8a7c59"
            )
            and o365.audit.Target.ID: "00000002-0000-0000-c000-000000000000"
        )
    )
```



### M365 OneDrive Malware File Upload

Branch count: 1  
Document count: 1  
Index: geneve-ut-0720

```python
event.dataset:o365.audit and event.provider:OneDrive and event.code:SharePointFileOperation and event.action:FileMalwareDetected
```



### M365 Security Compliance Email Reported by User as Malware or Phish

Branch count: 1  
Document count: 1  
Index: geneve-ut-0721

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.action:AlertTriggered and rule.name:"Email reported by user as malware or phish"
```



### M365 Security Compliance Potential Ransomware Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-0722

```python
event.dataset:o365.audit and
    event.provider:SecurityComplianceCenter and
    event.category:web and
    rule.name:("Ransomware activity" or "Potential ransomware activity") and
    event.outcome:success
```



### M365 Security Compliance Unusual Volume of File Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-0723

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"Unusual volume of file deletion" and event.outcome:success
```



### M365 Security Compliance User Restricted from Sending Email

Branch count: 1  
Document count: 1  
Index: geneve-ut-0724

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"User restricted from sending email" and event.outcome:success
```



### M365 SharePoint Malware File Detected

Branch count: 1  
Document count: 1  
Index: geneve-ut-0725

```python
event.dataset:o365.audit and event.provider:SharePoint and event.code:SharePointFileOperation and event.action:FileMalwareDetected
```



### M365 Teams Custom Application Interaction Enabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-0726

```python
event.dataset:o365.audit and event.provider:MicrosoftTeams and
event.category:web and event.action:TeamsTenantSettingChanged and
o365.audit.Name:"Allow sideloading and interaction of custom apps" and
o365.audit.NewValue:True and event.outcome:success
```



### M365 Teams External Access Enabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-0727

```python
event.dataset:o365.audit and event.provider:(SkypeForBusiness or MicrosoftTeams) and
event.category:web and event.action:"Set-CsTenantFederationConfiguration" and
o365.audit.Parameters.AllowFederatedUsers:True and event.outcome:success
```



### M365 Teams Guest Access Enabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-0728

```python
event.dataset:o365.audit and event.provider:(SkypeForBusiness or MicrosoftTeams) and
event.category:web and event.action:"Set-CsTeamsClientConfiguration" and
o365.audit.Parameters.AllowGuestUser:True and event.outcome:success
```



### M365 Threat Intelligence Signal

Branch count: 1  
Document count: 1  
Index: geneve-ut-0729

```python
event.dataset: "o365.audit" and event.provider: "ThreatIntelligence"
```



### MFA Disabled for Google Workspace Organization

Branch count: 2  
Document count: 2  
Index: geneve-ut-0732

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:(ENFORCE_STRONG_AUTHENTICATION or ALLOW_STRONG_AUTHENTICATION) and google_workspace.admin.new_value:false
```



### MS Office Macro Security Registry Modifications

Branch count: 4  
Document count: 4  
Index: geneve-ut-0733

```python
registry where host.os.type == "windows" and event.type == "change" and
    registry.value : ("AccessVBOM", "VbaWarnings") and
    registry.data.strings : ("0x00000001", "1")

/*
    Full registry key paths omitted due to data source variations:
    "HKCU\\S-1-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\AccessVBOM"
    "HKCU\\S-1-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\VbaWarnings"
*/
```



### Machine Learning Detected DGA activity using a known SUNBURST DNS domain

Branch count: 1  
Document count: 1  
Index: geneve-ut-0734

```python
ml_is_dga.malicious_prediction:1 and dns.question.registered_domain:avsvmcloud.com
```



### Machine Learning Detected a DNS Request Predicted to be a DGA Domain

Branch count: 1  
Document count: 1  
Index: geneve-ut-0735

```python
ml_is_dga.malicious_prediction:1 and not dns.question.registered_domain:avsvmcloud.com
```



### Malicious File - Detected - Elastic Defend

Branch count: 2  
Document count: 2  
Index: geneve-ut-0739

```python
event.kind : alert and event.code : malicious_file and (event.type : allowed or (event.type: denied and event.outcome: failure))
```



### Malicious File - Prevented - Elastic Defend

Branch count: 1  
Document count: 1  
Index: geneve-ut-0740

```python
event.kind : alert and event.code : malicious_file and event.type : denied and event.outcome : success
```



### Malware - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-0741

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:file_classification_event or endgame.event_subtype_full:file_classification_event)
```



### Malware - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-0742

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:file_classification_event or endgame.event_subtype_full:file_classification_event)
```



### Manual Dracut Execution

Branch count: 4  
Document count: 4  
Index: geneve-ut-0743

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.name == "dracut" and process.parent.executable != null and not (
  process.parent.executable like (
    "/usr/lib/kernel/*", "/etc/kernel/install.d/*", "/var/lib/dpkg/info/dracut.postinst",
    "/tmp/newroot/*", "/usr/lib/module-init-tools/*", "/usr/bin/xargs", "/sbin/dkms",
    "/sbin/mkinitrd", "/usr/bin/timeout", "/usr/sbin/dkms", "/usr/bin/systemd-inhibit"
  ) or
  process.parent.name in (
    "dracut-install", "dracut", "run-parts", "weak-modules", "mkdumprd", "new-kernel-pkg", "sudo"
  ) or
  process.parent.args like~ ("/usr/bin/dracut-rebuild", "/var/tmp/rpm-tmp.*") or
  process.parent.command_line like~ "/bin/sh -c if command -v mkinitcpio*"
)
```



### Manual Loading of a Suspicious Chromium Extension

Branch count: 6  
Document count: 6  
Index: geneve-ut-0744

```python
process where host.os.type == "macos" and event.action == "exec" and
  process.name in ("Google Chrome", "Brave Browser", "Microsoft Edge") and
  process.args like "--load-extension=/*" and
  not (process.args like "--load-extension=/Users/*/Library/Application Support/Cypress/*" and
       process.parent.executable like ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                                        "/Users/*/Library/Caches/Cypress/*/Cypress.app/Contents/MacOS/Cypress")) and
  not process.parent.executable like ("/opt/homebrew/Caskroom/chromedriver/*/chromedriver",
                                    "/Applications/Cypress.app/Contents/MacOS/Cypress",
                                    "/usr/local/bin/chromedriver")
```



### Manual Memory Dumping via Proc Filesystem

Branch count: 42  
Document count: 42  
Index: geneve-ut-0745

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name in ("cat", "grep", "tail", "less", "more", "egrep", "fgrep") and process.command_line like "/proc/*/mem"
```



### Manual Mount Discovery via /etc/exports or /etc/fstab

Branch count: 96  
Document count: 96  
Index: geneve-ut-0746

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name in ("cat", "grep", "tail", "less", "more", "egrep", "fgrep", "awk") and
process.command_line like ("/etc/exports", "/etc/fstab")
```



### Member Removed From GitHub Organization

Branch count: 1  
Document count: 1  
Index: geneve-ut-0748

```python
configuration where event.dataset == "github.audit" and event.action == "org.remove_member"
```



### Memory Threat - Detected - Elastic Defend

Branch count: 4  
Document count: 4  
Index: geneve-ut-0751

```python
event.kind : alert and event.code : (memory_signature or shellcode_thread) and (event.type : allowed or (event.type: denied and event.outcome: failure))
```



### Memory Threat - Prevented- Elastic Defend

Branch count: 2  
Document count: 2  
Index: geneve-ut-0752

```python
event.kind : alert and event.code : (memory_signature or shellcode_thread) and event.type : denied and event.outcome : success
```



### Message-of-the-Day (MOTD) File Creation

Branch count: 4  
Document count: 4  
Index: geneve-ut-0753

```python
file where host.os.type == "linux" and event.action == "creation" and file.path like "/etc/update-motd.d/*" and
not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client", "/usr/bin/buildah",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/usr/bin/pamac-daemon", "/.envbuilder/bin/envbuilder",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "./usr/bin/podman", "/opt/saltstack/salt/bin/python3.10",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/bin/crio"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  process.executable == null or
  process.name in ("executor", "dockerd", "crio") or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*")
)
```



### Microsoft Build Engine Started by a System Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-0756

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "MSBuild.exe" and
  process.parent.name : ("explorer.exe", "wmiprvse.exe")
```



### Microsoft Build Engine Started by an Office Application

Branch count: 8  
Document count: 8  
Index: geneve-ut-0757

```python
process where host.os.type == "windows" and event.type == "start" and
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

Branch count: 1  
Document count: 1  
Index: geneve-ut-0758

```python
process where host.os.type == "windows" and event.type == "start" and
  process.pe.original_file_name == "MSBuild.exe" and
  not process.name : "MSBuild.exe"
```



### Microsoft Exchange Server UM Spawning Suspicious Processes

Branch count: 2  
Document count: 2  
Index: geneve-ut-0759

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : ("UMService.exe", "UMWorkerProcess.exe") and
    not process.executable : (
          "?:\\Windows\\System32\\werfault.exe",
          "?:\\Windows\\System32\\wermgr.exe",
          "?:\\Program Files\\Microsoft\\Exchange Server\\V??\\Bin\\UMWorkerProcess.exe",
          "?:\\Program Files\\Microsoft\\Exchange Server\\Bin\\UMWorkerProcess.exe",
          "D:\\Exchange 2016\\Bin\\UMWorkerProcess.exe",
          "E:\\ExchangeServer\\Bin\\UMWorkerProcess.exe",
          "D:\\Exchange\\Bin\\UMWorkerProcess.exe",
          "D:\\Exchange Server\\Bin\\UMWorkerProcess.exe",
          "E:\\Exchange Server\\V15\\Bin\\UMWorkerProcess.exe",

          /* Crowdstrike specific exclusion as it uses NT Object paths */
          "\\Device\\HarddiskVolume*\\Windows\\System32\\werfault.exe",
          "\\Device\\HarddiskVolume*\\Windows\\System32\\wermgr.exe",
          "\\Device\\HarddiskVolume*\\Program Files\\Microsoft\\Exchange Server\\V??\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume*\\Program Files\\Microsoft\\Exchange Server\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume*\\Exchange 2016\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume*\\ExchangeServer\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume*\\Exchange\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume*\\Exchange Server\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume*\\Exchange Server\\V15\\Bin\\UMWorkerProcess.exe"
    )
```



### Microsoft Exchange Server UM Writing Suspicious Files

Branch count: 48  
Document count: 48  
Index: geneve-ut-0760

```python
file where host.os.type == "windows" and event.type == "creation" and
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



### Microsoft Exchange Transport Agent Install Script

Branch count: 4  
Document count: 4  
Index: geneve-ut-0761

```python
event.category: "process" and host.os.type:windows and
  powershell.file.script_block_text : (
    (
    "Install-TransportAgent" or
    "Enable-TransportAgent"
    )
  ) and
  not user.id : "S-1-5-18" and
  not powershell.file.script_block_text : (
    "'Install-TransportAgent', 'Invoke-MonitoringProbe', 'Mount-Database', 'Move-ActiveMailboxDatabase'," or
    "'Enable-TransportAgent', 'Enable-TransportRule', 'Export-ActiveSyncLog', 'Export-AutoDiscoverConfig'," or
    ("scriptCmd.GetSteppablePipeline" and "ForwardHelpTargetName Install-TransportAgent")
  )
```



### Microsoft Exchange Worker Spawning Suspicious Processes

Branch count: 8  
Document count: 8  
Index: geneve-ut-0762

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "w3wp.exe" and process.parent.args : "MSExchange*AppPool" and
  (
    (process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe") or
    ?process.pe.original_file_name in ("Cmd.Exe", "PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE"))
  )
```



### Microsoft IIS Connection Strings Decryption

Branch count: 2  
Document count: 2  
Index: geneve-ut-0765

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "aspnet_regiis.exe" or ?process.pe.original_file_name == "aspnet_regiis.exe") and
  process.args : "connectionStrings" and process.args : "-pdf"
```



### Microsoft IIS Service Account Password Dumped

Branch count: 2  
Document count: 2  
Index: geneve-ut-0766

```python
process where host.os.type == "windows" and event.type == "start" and
   (process.name : "appcmd.exe" or ?process.pe.original_file_name == "appcmd.exe") and
   process.args : "list" and process.args : "/text*"
```



### Microsoft Management Console File from Unusual Path

Branch count: 2  
Document count: 2  
Index: geneve-ut-0767

```python
process where host.os.type == "windows" and event.type == "start" and
  process.executable : (
    "?:\\Windows\\System32\\mmc.exe",

    /* Crowdstrike specific condition as it uses NT Object paths */
    "\\Device\\HarddiskVolume*\\Windows\\System32\\mmc.exe"
  ) and
  process.args : "*.msc" and
  not process.args : (
        "?:\\Windows\\System32\\*.msc",
        "?:\\Windows\\SysWOW64\\*.msc",
        "?:\\Program files\\*.msc",
        "?:\\Program Files (x86)\\*.msc",
        "?:\\Windows\\ADFS\\Microsoft.IdentityServer.msc"
  ) and
  not process.command_line : (
    "C:\\Windows\\system32\\mmc.exe eventvwr.msc /s",
    "mmc.exe eventvwr.msc /s",
    "\"C:\\Windows\\System32\\mmc.exe\" CompMgmt.msc*"
  )
```



### Microsoft Windows Defender Tampering

Branch count: 28  
Document count: 28  
Index: geneve-ut-0769

```python
registry where host.os.type == "windows" and event.type == "change" and process.executable != null and
  (
    (
      registry.value : (
        "PUAProtection", "DisallowExploitProtectionOverride", "TamperProtection", "EnableControlledFolderAccess",
        "SpynetReporting", "SubmitSamplesConsent"
      ) and registry.data.strings : ("0", "0x00000000")
    ) or
    (
      registry.value : (
        "DisableAntiSpyware", "DisableRealtimeMonitoring", "DisableIntrusionPreventionSystem", "DisableScriptScanning",
        "DisableIOAVProtection", "DisableEnhancedNotifications", "DisableBlockAtFirstSeen", "DisableBehaviorMonitoring"
      ) and registry.data.strings : ("1", "0x00000001")
    )
  ) and
  not process.executable : (
    "?:\\Windows\\system32\\svchost.exe", 
    "?:\\Windows\\CCM\\CcmExec.exe", 
    "?:\\Windows\\System32\\DeviceEnroller.exe", 
    "?:\\Program Files (x86)\\Trend Micro\\Security Agent\\tmuninst.exe",
    "\\Device\\HarddiskVolume*\\Windows\\system32\\svchost.exe", 
    "\\Device\\HarddiskVolume*\\Windows\\CCM\\CcmExec.exe", 
    "\\Device\\HarddiskVolume*\\Windows\\System32\\DeviceEnroller.exe", 
    "\\Device\\HarddiskVolume*\\Program Files (x86)\\Trend Micro\\Security Agent\\tmuninst.exe"
  )

/*
    Full registry key paths omitted due to data source variations:
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware"
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring"
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableIntrusionPreventionSystem"
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableScriptScanning"
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableIOAVProtection"
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting\\DisableEnhancedNotifications"
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet\\DisableBlockAtFirstSeen"
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableBehaviorMonitoring"
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\PUAProtection"
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection\\DisallowExploitProtectionOverride"
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Features\\TamperProtection"
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access\\EnableControlledFolderAccess"
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet\\SpynetReporting"
    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet\\SubmitSamplesConsent"
*/
```



### Mimikatz Memssp Log File Detected

Branch count: 1  
Document count: 1  
Index: geneve-ut-0770

```python
file where host.os.type == "windows" and file.name : "mimilsa.log" and process.name : "lsass.exe"
```



### Modification of AmsiEnable Registry Key

Branch count: 2  
Document count: 2  
Index: geneve-ut-0771

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : "AmsiEnable" and registry.data.strings: ("0", "0x00000000")

  /*
    Full registry key path omitted due to data source variations:
    HKEY_USERS\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable"
  */
```



### Modification of Boot Configuration

Branch count: 4  
Document count: 4  
Index: geneve-ut-0772

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "bcdedit.exe" or ?process.pe.original_file_name == "bcdedit.exe") and
    (
      (process.args : "/set" and process.args : "bootstatuspolicy" and process.args : "ignoreallfailures") or
      (process.args : "no" and process.args : "recoveryenabled")
    )
```



### Modification of Environment Variable via Unsigned or Untrusted Parent

Branch count: 4  
Document count: 4  
Index: geneve-ut-0774

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  process.name == "launchctl" and
  (process.parent.code_signature.exists == false or process.parent.code_signature.trusted == false) and
  process.args == "setenv"
```



### Modification of WDigest Security Provider

Branch count: 8  
Document count: 8  
Index: geneve-ut-0776

```python
registry where host.os.type == "windows" and event.type in ("creation", "change") and
    registry.value : "UseLogonCredential" and
    registry.path : "*\\SYSTEM\\*ControlSet*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential" and
    registry.data.strings : ("1", "0x00000001") and
    not (process.executable : "?:\\Windows\\System32\\svchost.exe" and user.id : "S-1-5-18")
```



### Modification of the msPKIAccountCredentials

Branch count: 1  
Document count: 1  
Index: geneve-ut-0777

```python
event.code:"5136" and host.os.type:"windows" and winlog.event_data.AttributeLDAPDisplayName:"msPKIAccountCredentials" and
  winlog.event_data.OperationType:"%%14674" and
  not winlog.event_data.SubjectUserSid : "S-1-5-18"
```



### Modification or Removal of an Okta Application Sign-On Policy

Branch count: 2  
Document count: 2  
Index: geneve-ut-0778

```python
event.dataset:okta.system and event.action:(application.policy.sign_on.update or application.policy.sign_on.rule.delete)
```



### Mofcomp Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-0779

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "mofcomp.exe" and process.args : "*.mof" and
  not user.id : "S-1-5-18" and
  not
  (
    process.parent.name : "ScenarioEngine.exe" and
    process.args : (
      "*\\MSSQL\\Binn\\*.mof",
      "*\\Microsoft SQL Server\\???\\Shared\\*.mof",
      "*\\OLAP\\bin\\*.mof"
    )
  )
```



### Mount Execution Detected via Defend for Containers

Branch count: 37  
Document count: 37  
Index: geneve-ut-0780

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  process.name == "mount" or
  (
    /* account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg */
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "busybox") and
    process.args in (
      "mount", "/bin/mount", "/usr/bin/mount", "/usr/local/bin/mount"
    ) and
    /* default exclusion list to not FP on default multi-process commands */
    not process.args in (
      "which", "/bin/which", "/usr/bin/which", "/usr/local/bin/which",
      "man", "/bin/man", "/usr/bin/man", "/usr/local/bin/man",
      "chmod", "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod",
      "chown", "/bin/chown", "/usr/bin/chown", "/usr/local/bin/chown"
    )
  )
) and container.security_context.privileged == true and process.interactive == true and container.id like "*"
```



### Mount Launched Inside a Container

Branch count: 1  
Document count: 1  
Index: geneve-ut-0781

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.entry_leader.entry_meta.type == "container" and process.name == "mount" and not (
  process.parent.command_line like "*grep*" or
  process.parent.executable like (
    "/usr/local/bin/dind", "/run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/*/longhorn-instance-manager",
    "/run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/*/longhorn-manager", "/usr/sbin/update-binfmts",
    "/usr/local/bin/engine-manager", "/usr/bin/timeout", "/opt/gitlab/embedded/bin/ruby", "/usr/local/sbin/longhorn-manager",
    "/longhorn-share-manager", "/usr/lib/systemd/systemd", "/lib/systemd/systemd"
  ) or
  process.parent.args in ("/usr/local/bin/instance-manager", "/usr/local/sbin/nsmounter")
)
```



### Mounting Hidden or WebDav Remote Shares

Branch count: 12  
Document count: 12  
Index: geneve-ut-0782

```python
process where host.os.type == "windows" and event.type == "start" and
 ((process.name : "net.exe" or ?process.pe.original_file_name == "net.exe") or ((process.name : "net1.exe" or ?process.pe.original_file_name == "net1.exe") and
 not process.parent.name : "net.exe")) and
 process.args : "use" and
 /* including hidden and webdav based online shares such as onedrive  */
 process.args : ("\\\\*\\*$*", "\\\\*@SSL\\*", "http*") and
 /* excluding shares deletion operation */
 not process.args : "/d*"
```



### MsBuild Making Network Connections

Branch count: 8  
Document count: 16  
Index: geneve-ut-0783

```python
sequence by process.entity_id with maxspan=30s

  /* Look for MSBuild.exe process execution */
  /* The events for this first sequence may be noisy, consider adding exceptions */
  [process where host.os.type == "windows" and event.type == "start" and
    (
      process.pe.original_file_name: "MSBuild.exe" or
      process.name: "MSBuild.exe"
    ) and
    not user.id == "S-1-5-18"]

  /* Followed by a network connection to an external address */
  /* Exclude domains that are known to be benign */
  [network where host.os.type == "windows" and
    event.action: ("connection_attempted", "lookup_requested") and
    (
      process.pe.original_file_name: "MSBuild.exe" or
      process.name: "MSBuild.exe"
    ) and
    not user.id == "S-1-5-18" and
    not cidrmatch(destination.ip, "127.0.0.1", "::1") and
    not dns.question.name : (
      "localhost",
      "dc.services.visualstudio.com",
      "vortex.data.microsoft.com",
      "api.nuget.org")]
```



### Mshta Making Network Connections

Branch count: 1  
Document count: 2  
Index: geneve-ut-0784

```python
sequence by process.entity_id with maxspan=10m
  [process where host.os.type == "windows" and event.type == "start" and process.name : "mshta.exe" and
     not process.parent.name : "Microsoft.ConfigurationManagement.exe" and
     not (process.parent.executable : "C:\\Amazon\\Amazon Assistant\\amazonAssistantService.exe" or
          process.parent.executable : "C:\\TeamViewer\\TeamViewer.exe") and
     not process.args : "ADSelfService_Enroll.hta"]
  [network where host.os.type == "windows" and process.name : "mshta.exe"]
```



### MsiExec Service Child Process With Network Connection

Branch count: 12  
Document count: 24  
Index: geneve-ut-0785

```python
sequence by process.entity_id with maxspan=1m
 [process where host.os.type == "windows" and event.type : "start" and
  process.parent.name : "msiexec.exe" and process.parent.args : "/v" and
  not process.executable :
        ("?:\\Windows\\System32\\msiexec.exe",
         "?:\\Windows\\sysWOW64\\msiexec.exe",
         "?:\\Windows\\system32\\srtasks.exe",
         "?:\\Windows\\syswow64\\srtasks.exe",
         "?:\\Windows\\sys*\\taskkill.exe",
         "?:\\Program Files\\*.exe",
         "?:\\Program Files (x86)\\*.exe",
         "?:\\Windows\\Installer\\MSI*.tmp",
         "?:\\Windows\\Microsoft.NET\\Framework*\\RegSvcs.exe",
         "C:\\Windows\\System32\\regsvr32.exe",
         "C:\\Windows\\Sys?????\\certutil.exe",
         "C:\\Windows\\System32\\WerFault.exe",
         "C:\\Windows\\System32\\wevtutil.exe",
         "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe") and
 not (process.name : ("rundll32.exe", "regsvr32.exe", "powershell.exe", "regasm.exe", "wscript.exe") and process.args : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*")) and
 not (?process.code_signature.subject_name : ("Bruno Software Inc", "Proton AG", "Axis Communications AB", "Citrix Systems, Inc.", "NSUS Limited", "Action1 Corporation", "Solarwinds Worldwide, LLC") and
      ?process.code_signature.trusted == true) and
 not (?process.pe.original_file_name in ("dxsetup.exe", "MofCompiler.exe", "ShellApp.exe") and
      ?process.code_signature.subject_name : "Microsoft Corporation" and ?process.code_signature.trusted == true) and
 not ?process.hash.sha256 in ("cfaef8c711db04d6c4a4381c66ac21b9e234e57febedb77fedc9316898b214bc",
                              "2f26f37cce780ca76f0dbac0de233f4c8d84c31b3f37380b9d5faacc3ee2d03e",
                              "7d9c691bfbf3beb78919dfd940fa6d325c3437425d5b0371df39aef6accf858d")
 ]
[network where host.os.type == "windows" and process.name != null and
 not dns.question.name : ("core.bdec.microsoft.com", "go.microsoft.com", "ocsp.digicert.com", "localhost", "www.google-analytics.com",
                          "ocsp.verisign.com", "*.symcb.com")]
```



### Multiple Logon Failure Followed by Logon Success

Branch count: 1  
Document count: 6  
Index: geneve-ut-0796

```python
sequence by winlog.computer_name, source.ip with maxspan=5s
  [authentication where host.os.type == "windows" and event.action == "logon-failed" and
    /* event 4625 need to be logged */
    winlog.logon.type : "Network" and user.id != null and 
    source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1" and 
    not winlog.event_data.TargetUserSid : "S-1-0-0" and not user.id : "S-1-0-0" and 
    not user.name : ("ANONYMOUS LOGON", "-", "*$") and not user.domain == "NT AUTHORITY" and

    /* noisy failure status codes often associated to authentication misconfiguration */
    not winlog.event_data.Status : ("0xC000015B", "0XC000005E", "0XC0000133", "0XC0000192")] with runs=5
  [authentication where host.os.type == "windows" and event.action == "logged-in" and
    /* event 4624 need to be logged */
    winlog.logon.type : "Network" and
    source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1" and
    not user.name : ("ANONYMOUS LOGON", "-", "*$") and not user.domain == "NT AUTHORITY"]
```



### Multiple Vault Web Credentials Read

Branch count: 1  
Document count: 2  
Index: geneve-ut-0803

```python
sequence by winlog.computer_name, winlog.process.pid with maxspan=1s

 /* 2 consecutive vault reads from same pid for web creds */

 [any where host.os.type == "windows" and event.code == "5382" and
  (winlog.event_data.SchemaFriendlyName : "Windows Web Password Credential" and winlog.event_data.Resource : "http*") and
  not winlog.event_data.SubjectLogonId : "0x3e7" and
  not winlog.event_data.Resource : "http://localhost/"]

 [any where host.os.type == "windows" and event.code == "5382" and
  (winlog.event_data.SchemaFriendlyName : "Windows Web Password Credential" and winlog.event_data.Resource : "http*") and
  not winlog.event_data.SubjectLogonId : "0x3e7" and
  not winlog.event_data.Resource : "http://localhost/"]
```



### NTDS Dump via Wbadmin

Branch count: 2  
Document count: 2  
Index: geneve-ut-0806

```python
process where host.os.type == "windows" and event.type == "start" and
    (process.name : "wbadmin.exe" or ?process.pe.original_file_name : "wbadmin.exe") and
     process.args : "recovery" and process.command_line : "*ntds.dit*"
```



### NTDS or SAM Database File Copied

Branch count: 210  
Document count: 210  
Index: geneve-ut-0807

```python
process where host.os.type == "windows" and event.type == "start" and
  (
    ((?process.pe.original_file_name in ("Cmd.Exe", "PowerShell.EXE", "XCOPY.EXE") or process.name : ("Cmd.Exe", "PowerShell.EXE", "XCOPY.EXE")) and
       process.args : ("copy", "xcopy", "Copy-Item", "move", "cp", "mv")
    ) or
    ((?process.pe.original_file_name : "esentutl.exe" or process.name : "esentutl.exe") and process.args : ("*/y*", "*/vss*", "*/d*"))
  ) and
  process.command_line : ("*\\ntds.dit*", "*\\config\\SAM*", "*\\*\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\*", "*/system32/config/SAM*", "*\\User Data\\*")
```



### Namespace Manipulation Using Unshare

Branch count: 9  
Document count: 9  
Index: geneve-ut-0808

```python
process where host.os.type == "linux" and event.type == "start" and event.action : ("exec", "exec_event", "start") and
process.executable: "/usr/bin/unshare" and not (
  process.parent.executable: ("/usr/bin/udevadm", "*/lib/systemd/systemd-udevd", "/usr/bin/unshare") or
  process.args == "/usr/bin/snap" and not process.parent.name in ("zz-proxmox-boot", "java") or
  process.parent.args like (
    "/etc/kernel/postinst.d/zz-proxmox-boot", "/opt/openssh/sbin/sshd", "/usr/sbin/sshd",
    "/snap/*", "/home/*/.local/share/JetBrains/Toolbox/*"
  )
)
```



### NetSupport Manager Execution from an Unusual Path

Branch count: 18  
Document count: 18  
Index: geneve-ut-0809

```python
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "client32.exe" or ?process.pe.original_file_name == "client32.exe" or process.parent.name : "client32.exe") and
 (
  process.executable :
               ("?:\\Users\\*.exe",
                "?:\\ProgramData\\*.exe",
                "\\Device\\HarddiskVolume?\\Users\\*.exe",
                "\\Device\\HarddiskVolume?\\ProgramData\\*.exe") or
  ?process.parent.executable : ("?:\\Users\\*\\client32.exe", "?:\\ProgramData\\*\\client32.exe")
  )
```



### Netcat Listener Established via rlwrap

Branch count: 20  
Document count: 20  
Index: geneve-ut-0811

```python
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  process.name == "rlwrap" and process.args in ("nc", "ncat", "netcat", "nc.openbsd", "socat") and
  process.args : "*l*" and process.args_count >= 4
```



### Netsh Helper DLL

Branch count: 3  
Document count: 3  
Index: geneve-ut-0812

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
    "HKLM\\Software\\Microsoft\\netsh\\*",
    "\\REGISTRY\\MACHINE\\Software\\Microsoft\\netsh\\*",
    "MACHINE\\Software\\Microsoft\\netsh\\*"
  )
```



### Network Activity Detected via cat

Branch count: 16  
Document count: 32  
Index: geneve-ut-0814

```python
sequence by host.id, process.entity_id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name == "cat" and process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")]
  [network where host.os.type == "linux" and event.action in ("connection_attempted", "disconnect_received") and
   process.name == "cat" and not (
     destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
       destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
       "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
       "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
       "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
       "FF00::/8"
     )
   )]
```



### Network Connection Initiated by Suspicious SSHD Child Process

Branch count: 35  
Document count: 70  
Index: geneve-ut-0816

```python
sequence by host.id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.executable == "/usr/sbin/sshd" and not process.command_line like ("*ansible*", "*BECOME-SUCCESS*")] by process.entity_id
  [network where host.os.type == "linux" and event.type == "start" and event.action == "connection_attempted" and (
     process.executable like (
       "/tmp/*", "/var/tmp/*", "/dev/shm/*", "./*", "/run/*", "/var/run/*", "/boot/*", "/sys/*", "/lost+found/*",
       "/proc/*", "/var/mail/*", "/var/www/*", "/home/*", "/root/*" 
     ) or
     process.name like~ (
       // Hidden processes
       ".*",
       // Suspicious file formats
       "*.elf", "*.sh", "*.py", "*.rb", "*.pl", "*.lua*", "*.php*", ".js",
       // Scheduled tasks
       "systemd", "cron", "crond",
       // Network utilities often used for reverse shells
       "nc", "netcat", "ncat", "telnet", "socat", "openssl", "nc.openbsd", "ngrok", "nc.traditional"
     )
   ) and  
   not (
     destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
       destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
       "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
       "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
       "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
       "FF00::/8", "172.31.0.0/16"
     ) or
     process.executable in ("/bin/yum", "/usr/bin/yum") or
     process.name in ("login_duo", "ssh", "sshd", "sshd-session", "sqlplus")
   )
  ] by process.parent.entity_id
```



### Network Connection by Cups or Foomatic-rip Child

Branch count: 8  
Document count: 16  
Index: geneve-ut-0817

```python
sequence by host.id with maxspan=10s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name == "foomatic-rip" and
   process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")] by process.entity_id
  [network where host.os.type == "linux" and event.type == "start" and
   event.action == "connection_attempted"] by process.parent.entity_id
```



### Network Connection to OAST Domain via Script Interpreter

Branch count: 4  
Document count: 8  
Index: geneve-ut-0819

```python
sequence by process.entity_id with maxspan=1m
  [process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and
    (process.name == "node" or process.name like ("python*", "ruby*", "perl*"))]
  [network where host.os.type == "macos" and event.type == "start" and destination.domain like "*.oast*"]
```



### Network Connection via Certutil

Branch count: 1  
Document count: 1  
Index: geneve-ut-0820

```python
network where host.os.type == "windows" and process.name : "certutil.exe" and
  not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
                                "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32",
                                "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
                                "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
                                "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
                                "FE80::/10", "FF00::/8") and
  not dns.question.name in ("localhost", "*.digicert.com", "ctldl.windowsupdate.com")
```



### Network Connection via Compiled HTML File

Branch count: 1  
Document count: 2  
Index: geneve-ut-0821

```python
sequence by process.entity_id
  [process where host.os.type == "windows" and process.name : "hh.exe" and event.type == "start"]
  [network where host.os.type == "windows" and process.name : "hh.exe" and
     not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
       "FE80::/10", "FF00::/8") and
     not dns.question.name : "localhost"]
```



### Network Connection via MsXsl

Branch count: 1  
Document count: 2  
Index: geneve-ut-0822

```python
sequence by process.entity_id
  [process where host.os.type == "windows" and process.name : "msxsl.exe" and event.type == "start"]
  [network where host.os.type == "windows" and process.name : "msxsl.exe" and
     not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
       "FE80::/10", "FF00::/8")]
```



### Network Connection via Recently Compiled Executable

Branch count: 152  
Document count: 608  
Index: geneve-ut-0823

```python
sequence by host.id with maxspan=1m
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name like~ (
     "gcc*", "g++*", "c++", "cc", "c99", "c89", "cc1*", "cc1plus*", "clang*", "clang++*",
     "musl-gcc", "musl-clang", "*-linux-gnu-gcc*", "*-linux-gnu-g++*", "*-pc-linux-gnu-gcc*",
     "tcc", "zig", "ccache", "distcc"
   )] by process.args
  [file where host.os.type == "linux" and event.action == "creation" and process.name like~ (
    "ld", "ld.*", "lld", "ld.lld", "mold", "collect2", "*-linux-gnu-ld*", "*-pc-linux-gnu-ld*"
   )] by file.name
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec"] by process.name
  [network where host.os.type == "linux" and event.action == "connection_attempted" and destination.ip != null and not (
     cidrmatch(destination.ip, "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1") or
     process.name in (
       "simpleX", "conftest", "ssh", "python", "ispnull", "pvtui", "npreal2d", "ruby", "source", "ssh", "git-remote-http",
       "sshd-session", "gendb", "sqlplus"
     )
   )] by process.name
```



### Network Connection via Registration Utility

Branch count: 18  
Document count: 36  
Index: geneve-ut-0824

```python
sequence by process.entity_id
  [process where host.os.type == "windows" and event.type == "start" and
   process.name : ("regsvr32.exe", "RegAsm.exe", "RegSvcs.exe") and
   not (
         (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System") and
         (process.parent.name : "msiexec.exe" or process.parent.executable : ("C:\\Program Files (x86)\\*.exe", "C:\\Program Files\\*.exe"))
       )
   ]
  [network where host.os.type == "windows" and process.name : ("regsvr32.exe", "RegAsm.exe", "RegSvcs.exe")  and
   not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
       "FE80::/10", "FF00::/8") and network.protocol != "dns"]
```



### Network Connection via Signed Binary

Branch count: 16  
Document count: 32  
Index: geneve-ut-0825

```python
sequence by process.entity_id
  [process where host.os.type == "windows" and (process.name : "expand.exe" or process.name : "extrac32.exe" or
                 process.name : "ieexec.exe" or process.name : "makecab.exe") and
                 event.type == "start"]
  [network where host.os.type == "windows" and (process.name : "expand.exe" or process.name : "extrac32.exe" or
                 process.name : "ieexec.exe" or process.name : "makecab.exe") and
    not cidrmatch(destination.ip,
      "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32",
      "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24",
      "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
      "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10", "FF00::/8")]
```



### Network Connections Initiated Through XDG Autostart Entry

Branch count: 2  
Document count: 4  
Index: geneve-ut-0826

```python
sequence by host.id, process.entity_id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
     (process.parent.executable == "/usr/bin/xfce4-session") or
     (process.executable == "/bin/sh" and process.args == "-e" and process.args == "-u" and
      process.args == "-c" and process.args : "export GIO_LAUNCHED_DESKTOP_FILE_PID=$$;*")
   )
  ]
  [network where host.os.type == "linux" and event.type == "start" and event.action == "connection_attempted" and not (
     destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
       destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
       "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
       "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
       "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
       "FF00::/8", "172.31.0.0/16"
       ) or
       process.name in (
         "telegram-desktop", "firefox", "gnome-calculator", "remmina", "spotify", "librewolf", "fortitraylauncher",
         "flameshot", "thunderbird", "update-manager", "warp-terminal", "obs", "transmission-gtk", "telegram",
         "mintupdate-launcher", "firefox-bin", "xbrlapi", "gnome-software"
       )
     )
  ]
```



### Network Logon Provider Registry Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-0827

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.data.strings : "?*" and registry.value : "ProviderPath" and
  registry.path : (
    "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\NetworkProvider\\ProviderPath",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\*\\NetworkProvider\\ProviderPath"
  ) and
  /* Excluding default NetworkProviders RDPNP, LanmanWorkstation and webclient. */
  not (
    user.id : "S-1-5-18" and
    registry.data.strings : (
        "%SystemRoot%\\System32\\ntlanman.dll",
        "%SystemRoot%\\System32\\drprov.dll",
        "%SystemRoot%\\System32\\davclnt.dll",
        "%SystemRoot%\\System32\\vmhgfs.dll",
        "?:\\Program Files (x86)\\Citrix\\ICA Client\\x64\\pnsson.dll",
        "?:\\Program Files\\Dell\\SARemediation\\agent\\DellMgmtNP.dll",
        "?:\\Program Files (x86)\\CheckPoint\\Endpoint Connect\\\\epcgina.dll"
    )
  )
```



### Network-Level Authentication (NLA) Disabled

Branch count: 6  
Document count: 6  
Index: geneve-ut-0830

```python
registry where host.os.type == "windows" and event.action != "deletion" and registry.value : "UserAuthentication" and
  registry.path : (
    "HKLM\\SYSTEM\\ControlSet*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication",
    "MACHINE\\SYSTEM\\*ControlSet*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication"
  ) and registry.data.strings :  ("0", "0x00000000")
```



### NetworkManager Dispatcher Script Creation

Branch count: 4  
Document count: 4  
Index: geneve-ut-0831

```python
file where host.os.type == "linux" and event.type == "creation" and file.path like "/etc/NetworkManager/dispatcher.d/*" and
not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe",  "/usr/bin/pamac-daemon", "./usr/bin/podman",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/bin/crio", "/usr/sbin/crond",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/kaniko/kaniko-executor",
    "/usr/local/bin/dockerd", "/usr/bin/podman", "/bin/install", "/proc/self/exe", "/usr/lib/systemd/systemd",
    "/usr/sbin/sshd", "/usr/bin/gitlab-runner", "/opt/gitlab/embedded/bin/ruby", "/usr/sbin/gdm", "/usr/bin/install",
    "/usr/local/manageengine/uems_agent/bin/dcregister", "/usr/local/bin/pacman", "./usr/bin/qemu-aarch64-static"
  ) or
  process.executable like~ (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  (process.name == "sed" and file.name : "sed*") or
  (
    process.executable like ("/kaniko/executor", "/usr/libexec/platform-python*") and
    file.path like "/etc/NetworkManager/dispatcher.d/11-dhclient*"
  )
)
```



### New ActiveSyncAllowedDeviceID Added via PowerShell

Branch count: 3  
Document count: 3  
Index: geneve-ut-0832

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and process.args : "Set-CASMailbox*ActiveSyncAllowedDeviceIDs*"
```



### New GitHub App Installed

Branch count: 1  
Document count: 1  
Index: geneve-ut-0833

```python
configuration where event.dataset == "github.audit" and event.action == "integration_installation.create"
```



### New GitHub Owner Added

Branch count: 1  
Document count: 1  
Index: geneve-ut-0834

```python
iam where event.dataset == "github.audit" and event.action == "org.add_member" and github.permission == "admin"
```



### New GitHub Personal Access Token (PAT) Added

Branch count: 1  
Document count: 1  
Index: geneve-ut-0835

```python
configuration where event.dataset == "github.audit" and github.operation_type == "create" and
github.category == "personal_access_token" and event.action == "personal_access_token.access_granted"
```



### New Okta Authentication Behavior Detected

Branch count: 1  
Document count: 1  
Index: geneve-ut-0837

```python
event.dataset:okta.system and okta.debug_context.debug_data.risk_behaviors:*
```



### New Okta Identity Provider (IdP) Added by Admin

Branch count: 1  
Document count: 1  
Index: geneve-ut-0838

```python
event.dataset: "okta.system" and event.action: "system.idp.lifecycle.create" and okta.outcome.result: "SUCCESS"
```



### New User Added To GitHub Organization

Branch count: 1  
Document count: 1  
Index: geneve-ut-0840

```python
configuration where event.dataset == "github.audit" and event.action == "org.add_member"
```



### Node.js Pre or Post-Install Script Execution

Branch count: 36  
Document count: 72  
Index: geneve-ut-0847

```python
sequence by host.id with maxspan=10s
  [process where host.os.type in ("linux", "macos") and event.type == "start" and event.action in ("exec", "ProcessRollup2", "start") and process.name == "node" and process.args == "install"] by process.entity_id
  [process where host.os.type in ("linux", "macos") and event.type == "start" and event.action in ("exec", "ProcessRollup2", "start") and process.parent.name == "node"] by process.parent.entity_id
```



### Nping Process Activity

Branch count: 6  
Document count: 6  
Index: geneve-ut-0848

```python
process where host.os.type == "linux" and event.type == "start" and
 event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
 process.name == "nping"
```



### Office Test Registry Persistence

Branch count: 1  
Document count: 1  
Index: geneve-ut-0850

```python
registry where host.os.type == "windows" and event.action != "deletion" and
    registry.path : "*\\Software\\Microsoft\\Office Test\\Special\\Perf\\*"
```



### Okta FastPass Phishing Detection

Branch count: 1  
Document count: 1  
Index: geneve-ut-0853

```python
event.dataset:okta.system and event.category:authentication and
  okta.event_type:user.authentication.auth_via_mfa and event.outcome:failure and okta.outcome.reason:"FastPass declined phishing attempt"
```



### Okta ThreatInsight Threat Suspected Promotion

Branch count: 2  
Document count: 2  
Index: geneve-ut-0856

```python
event.dataset:okta.system and (event.action:security.threat.detected or okta.debug_context.debug_data.threat_suspected: true)
```



### Okta User Session Impersonation

Branch count: 1  
Document count: 1  
Index: geneve-ut-0857

```python
event.dataset:okta.system and event.action:user.session.impersonation.initiate
```



### Ollama API Accessed from External Network

Branch count: 2  
Document count: 2  
Index: geneve-ut-0859

```python
network where event.action == "connection_accepted" and
  process.name in ("ollama", "ollama.exe") and
  destination.port == 11434 and
  source.ip != null and source.ip != "0.0.0.0" and
  not cidrmatch(source.ip, 
    "10.0.0.0/8", 
    "127.0.0.0/8", 
    "169.254.0.0/16", 
    "172.16.0.0/12", 
    "192.168.0.0/16",
    "100.64.0.0/10",
    "::1",
    "fe80::/10",
    "fc00::/7",
    "ff00::/8"
  )
```



### Ollama DNS Query to Untrusted Domain

Branch count: 2  
Document count: 2  
Index: geneve-ut-0860

```python
network where event.action == "lookup_requested" and
  process.name in ("ollama", "ollama.exe") and
  dns.question.name != null and
  not dns.question.name : (
    "ollama.ai", "*.ollama.ai", "ollama.com", "*.ollama.com",
    "github.com", "*.github.com", "*.githubusercontent.com",
    "*.r2.cloudflarestorage.com", "*.cloudflare.com", "*.cloudflarestorage.com",
    "localhost", "*.local", "*.internal", "*.localdomain"
  )
```



### OpenSSL Password Hash Generation

Branch count: 5  
Document count: 5  
Index: geneve-ut-0861

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed") and process.name == "openssl"
and process.args == "passwd" and ?process.args_count >= 4 and
not process.args in ("-help", "--help", "-h")
```



### Openssl Client or Server Activity

Branch count: 99  
Document count: 99  
Index: geneve-ut-0862

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
process.name == "openssl" and (
  (
    process.args == "s_client" and process.args : ("-connect", "*:*") and
    process.args in (
      "sh", "dash", "bash", "zsh",
      "/bin/sh", "/bin/dash", "/bin/bash", "/bin/zsh",
      "/usr/bin/sh", "/usr/bin/dash", "/usr/bin/bash", "/usr/bin/zsh",
      "/usr/local/bin/sh", "/usr/local/bin/dash", "/usr/local/bin/bash", "/usr/local/bin/zsh"
    ) and not process.args == "-showcerts"
  ) or
  (process.args == "s_server" and process.args == "-port")
) and
not process.parent.executable in (
  "/pro/xymon/client/ext/awsXymonCheck.sh", "/opt/antidot-svc/nrpe/plugins/check_cert", "/etc/zabbix/scripts/check_dane_tlsa.sh"
)
```



### Outbound Scheduled Task Activity via PowerShell

Branch count: 36  
Document count: 72  
Index: geneve-ut-0863

```python
sequence by host.id, process.entity_id with maxspan = 5s
 [any where host.os.type == "windows" and (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
  (?dll.name : "taskschd.dll" or file.name : "taskschd.dll") and process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe")]
 [network where host.os.type == "windows" and process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and destination.port == 135 and not cidrmatch(destination.ip, "127.0.0.0/8", "::1/128")]
```



### Outlook Home Page Registry Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-0864

```python
registry where host.os.type == "windows" and event.action != "deletion" and registry.value : "URL" and
    registry.path : (
        "*\\SOFTWARE\\Microsoft\\Office\\*\\Outlook\\Webview\\*",
        "*\\SOFTWARE\\Microsoft\\Office\\*\\Outlook\\Today\\*"
    ) and registry.data.strings : ("*://*", "*:\\*")
```



### PANW and Elastic Defend - Command and Control Correlation

Branch count: 2  
Document count: 4  
Index: geneve-ut-0865

```python
sequence by source.port, source.ip, destination.ip with maxspan=1m
 [network where event.module == "panw" and event.action == "c2_communication"]
 [network where event.module == "endpoint" and event.action in ("disconnect_received", "connection_attempted")]
```



### Pbpaste Execution via Unusual Parent Process

Branch count: 3  
Document count: 3  
Index: geneve-ut-0868

```python
process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and
  process.name == "pbpaste" and process.args_count == 1 and
  (process.parent.name in ("node", "osascript") or process.parent.name like "python*") and
  not process.parent.executable like "/Users/*/.pyenv/versions/*/bin/python3*"
```



### Peripheral Device Discovery

Branch count: 2  
Document count: 2  
Index: geneve-ut-0869

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "fsutil.exe" or ?process.pe.original_file_name == "fsutil.exe") and
  process.args : "fsinfo" and process.args : "drives"
```



### Perl Outbound Network Connection

Branch count: 1  
Document count: 2  
Index: geneve-ut-0870

```python
sequence by process.entity_id with maxspan=30s
  [process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and
    process.name == "perl" and not process.args like "/usr/bin/xpath"]
  [network where host.os.type == "macos" and event.type == "start" and process.name == "perl" and
    not cidrmatch(destination.ip, 
        "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", 
        "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "192.88.99.0/24",
        "224.0.0.0/4", "240.0.0.0/4", "::1", "FE80::/10", "FF00::/8")]
```



### Permission Theft - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-0871

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:token_protection_event or endgame.event_subtype_full:token_protection_event)
```



### Permission Theft - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-0872

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:token_protection_event or endgame.event_subtype_full:token_protection_event)
```



### Persistence via BITS Job Notify Cmdline

Branch count: 1  
Document count: 1  
Index: geneve-ut-0873

```python
process where host.os.type == "windows" and event.type == "start" and
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
Index: geneve-ut-0874

```python
file where host.os.type == "macos" and event.action == "modification" and
  file.path like "/Library/DirectoryServices/PlugIns/*.dsplug"
```



### Persistence via Docker Shortcut Modification

Branch count: 14  
Document count: 14  
Index: geneve-ut-0875

```python
file where host.os.type == "macos" and event.action == "modification" and
 file.path like "/Users/*/Library/Preferences/com.apple.dock.plist" and
 ((process.name like~ ("osascript", "python*", "sh", "bash", "zsh", "node") or Effective_process.name like~ ("osascript", "python*", "sh", "bash", "zsh", "node")) or
  (process.code_signature.exists == false or process.code_signature.trusted == false))
```



### Persistence via Folder Action Script

Branch count: 22  
Document count: 22  
Index: geneve-ut-0876

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.parent.name == "com.apple.foundation.UserScriptService" and 
 ((process.name like~ ("osascript", "python*", "tcl*", "node", "perl", "ruby", "php")) or 
  (process.name in ("bash", "csh", "zsh", "sh") and process.args == "-c")) and 
 not process.args like ("/Users/*/Library/Scripts/*", "/Users/*/Library/Application Scripts/*", "/Library/Scripts/*")
```



### Persistence via Login or Logout Hook

Branch count: 2  
Document count: 2  
Index: geneve-ut-0878

```python
process where host.os.type == "macos" and event.type == "start" and
 process.name == "defaults" and process.args == "write" and process.args : ("LoginHook", "LogoutHook") and
 not process.args :
       (
         "Support/JAMF/ManagementFrameworkScripts/logouthook.sh",
         "Support/JAMF/ManagementFrameworkScripts/loginhook.sh",
         "/Library/Application Support/JAMF/ManagementFrameworkScripts/logouthook.sh",
         "/Library/Application Support/JAMF/ManagementFrameworkScripts/loginhook.sh"
       )
```



### Persistence via Microsoft Office AddIns

Branch count: 36  
Document count: 36  
Index: geneve-ut-0879

```python
file where host.os.type == "windows" and event.type != "deletion" and
 file.extension : ("wll","xll","ppa","ppam","xla","xlam") and
 file.path : (
    "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Word\\Startup\\*",
    "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\AddIns\\*",
    "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\*",

    /* Crowdstrike specific condition as it uses NT Object paths */
    "\\Device\\HarddiskVolume*\\Users\\*\\AppData\\Roaming\\Microsoft\\Word\\Startup\\*",
    "\\Device\\HarddiskVolume*\\Users\\*\\AppData\\Roaming\\Microsoft\\AddIns\\*",
    "\\Device\\HarddiskVolume*\\Users\\*\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\*"
 )
```



### Persistence via Microsoft Outlook VBA

Branch count: 2  
Document count: 2  
Index: geneve-ut-0880

```python
file where host.os.type == "windows" and event.type != "deletion" and
  file.name : "VbaProject.OTM" and
  file.path : ("?:\\Users\\*\\AppData\\Roaming\\Microsoft\\Outlook\\VbaProject.OTM", "\\Device\\HarddiskVolume*\\Users\\*\\AppData\\Roaming\\Microsoft\\Outlook\\VbaProject.OTM")
```



### Persistence via PowerShell profile

Branch count: 12  
Document count: 12  
Index: geneve-ut-0881

```python
file where host.os.type == "windows" and event.type != "deletion" and
  file.name : ("profile.ps1", "Microsoft.Powershell_profile.ps1") and
  file.path : ("?:\\Users\\*\\Documents\\WindowsPowerShell\\*.ps1", 
                    "?:\\Users\\*\\Documents\\PowerShell\\*.ps1", 
                    "?:\\Windows\\System32\\WindowsPowerShell\\*.ps1", 
                    "\\Device\\HarddiskVolume*\\Users\\*\\Documents\\WindowsPowerShell\\*.ps1", 
                    "\\Device\\HarddiskVolume*\\Users\\*\\Documents\\PowerShell\\*.ps1", 
                    "\\Device\\HarddiskVolume*\\Windows\\System32\\WindowsPowerShell\\*.ps1")
```



### Persistence via Scheduled Job Creation

Branch count: 4  
Document count: 4  
Index: geneve-ut-0882

```python
file where host.os.type == "windows" and event.type != "deletion" and
  file.path : "?:\\Windows\\Tasks\\*" and file.extension : "job" and
  not (
    (
      process.executable : "?:\\Program Files\\CCleaner\\CCleaner64.exe" and
      file.path : "?:\\Windows\\Tasks\\CCleanerCrashReporting.job"
    ) or
    (
      process.executable : (
        "?:\\Program Files (x86)\\ManageEngine\\UEMS_Agent\\bin\\dcagentregister.exe",
        "?:\\Program Files (x86)\\DesktopCentral_Agent\\bin\\dcagentregister.exe"
      ) and
      file.path : "?:\\Windows\\Tasks\\DCAgentUpdater.job"
    )
  )
```



### Persistence via Suspicious Launch Agent or Launch Daemon

Branch count: 190  
Document count: 190  
Index: geneve-ut-0883

```python
file where host.os.type == "macos" and event.type != "deletion" and 
  file.extension == "plist" and
  file.path like ("/Library/LaunchAgents/*", "/Library/LaunchDaemons/*", 
                  "/Users/*/Library/LaunchAgents/*", "/System/Library/LaunchAgents/*",
                  "/System/Library/LaunchDaemons/*") and
  (process.executable like ("/private/tmp/*", "/private/var/root/Library/*", "/var/tmp/*", 
                            "/tmp/*", "/var/folders/*", "/Users/Shared/*", "/var/root/*",
                            "/Library/WebServer/*", "/Library/Graphics/*", "/Library/Fonts/*") or
   process.name like~ ("python*", "osascript", "bash", "zsh", "sh", "curl", "nscurl", "wget", "java")) and
  not process.executable like ("/System/*", "/Library/PrivilegedHelperTools/*") and
  not (process.code_signature.signing_id in ("com.apple.vim", "com.apple.cat", "com.apple.cfprefsd",
                                            "com.jetbrains.toolbox", "com.apple.pico", "com.apple.shove",
                                            "com.sublimetext.4", "com.apple.ditto") and process.code_signature.trusted == true)
```



### Persistence via TelemetryController Scheduled Task Hijack

Branch count: 1  
Document count: 1  
Index: geneve-ut-0884

```python
process where host.os.type == "windows" and event.type == "start" and
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
Index: geneve-ut-0885

```python
process where host.os.type == "windows" and event.type == "start" and
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
          "?:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\OfficeC2RClient.exe") and
  not process.name : ("MoUsoCoreWorker.exe", "OfficeC2RClient.exe")
```



### Persistence via WMI Event Subscription

Branch count: 4  
Document count: 4  
Index: geneve-ut-0886

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "wmic.exe" or ?process.pe.original_file_name == "wmic.exe") and
  process.args : "create" and
  process.args : ("ActiveScriptEventConsumer", "CommandLineEventConsumer")
```



### Persistence via WMI Standard Registry Provider

Branch count: 48  
Document count: 48  
Index: geneve-ut-0887

```python
registry where host.os.type == "windows" and event.type == "change" and
 registry.data.strings != null and process.name : "WmiPrvSe.exe" and
 registry.path : (
                  "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Command Processor\\Autorun",
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
                  "\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Command Processor\\Autorun",
                  "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                  "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                  "\\REGISTRY\\MACHINE\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                  "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
                  "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
                  "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
                  "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
                  "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
                  "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
                  "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\*\\ServiceDLL",
                  "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\*\\ImagePath",
                  "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*",
                  "\\REGISTRY\\USER\\*\\Environment\\UserInitMprLogonScript",
                  "\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load",
                  "\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
                  "\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Shell",
                  "\\REGISTRY\\USER\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff\\Script",
                  "\\REGISTRY\\USER\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon\\Script",
                  "\\REGISTRY\\USER\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown\\Script",
                  "\\REGISTRY\\USER\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Startup\\Script",
                  "\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Ctf\\LangBarAddin\\*\\FilePath",
                  "\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Exec",
                  "\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Script"
                  )
```



### Persistence via a Hidden Plist Filename

Branch count: 20  
Document count: 20  
Index: geneve-ut-0888

```python
file where host.os.type == "macos" and event.type != "deletion" and
  file.path like~ (
    "/System/Library/LaunchAgents/.*.plist",
    "/Library/LaunchAgents/.*.plist",
    "/Users/*/Library/LaunchAgents/.*.plist",
    "/System/Library/LaunchDaemons/.*.plist",
    "/Library/LaunchDaemons/.*.plist"
  ) and
  not (file.name like ".chef-com*.plist" and process.executable like "/opt/chef/embedded/bin/ruby") and
  not (process.executable in ("/usr/bin/sed", "/bin/bash") and file.name like ".!*!*.plist")
```



### Persistence via a Windows Installer

Branch count: 14  
Document count: 14  
Index: geneve-ut-0889

```python
any where host.os.type == "windows" and
  (process.name : "msiexec.exe" or Effective_process.name : "msiexec.exe") and
  (
    (
      event.category == "file" and event.action == "creation" and
      file.path : (
        "?:\\Windows\\System32\\Tasks\\*",
        "?:\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\*",
        "?:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*"
      ) and
      not file.path : (
        "?:\\Windows\\System32\\Tasks\\Adobe Acrobat Update Task",
        "?:\\Windows\\System32\\Tasks\\HP\\Sure Click\\Sure Click ?.?.??.????",
        "?:\\Windows\\System32\\Tasks\\HP\\Sure Click\\Sure Click UI ?.?.??.????",
        "?:\\Windows\\System32\\Tasks\\HP\\Sure Click\\Upgrade Repair ?.?.??.????",
        "?:\\Windows\\System32\\Tasks\\IntelSURQC-Upgrade-86621605-2a0b-4128-8ffc-15514c247132",
        "?:\\Windows\\System32\\Tasks\\IntelSURQC-Upgrade-86621605-2a0b-4128-8ffc-15514c247132-Logon"
      )
    ) or
    (
      event.category == "registry" and event.action == "modification" and registry.data.strings != null and
      registry.path : (
        "H*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
        "H*\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
        "H*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
        "H*\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*"
      ) and
      not registry.data.strings : (
        "C:\\Program Files (x86)\\Common Files\\Acronis\\TibMounter\\tib_mounter_monitor.exe",
        "C:\\Program Files (x86)\\Common Files\\Java\\Java Update\\jusched.exe",
        "C:\\Program Files\\Citrix\\Secure Access Client\\CtxsDPS.exe --clean-user-installs",
        "C:\\Program Files\\OpenVPN\\bin\\openvpn-gui.exe",
        "C:\\Program Files\\Veeam\\Endpoint Backup\\Veeam.EndPoint.Tray.exe -NoControlPanel -CheckNumberOfRunningAgents",
        "\"C:\\Program Files (x86)\\Cisco\\Cisco Secure Client\\UI\\csc_ui.exe\" -minimized",
        "\"C:\\Program Files (x86)\\Citrix\\ICA Client\\concentr.exe\" /startup",
        "\"C:\\Program Files (x86)\\Citrix\\ICA Client\\Receiver\\AnalyticsSrv.exe\" /Startup",
        "\"C:\\Program Files (x86)\\Citrix\\ICA Client\\redirector.exe\" /startup",
        "\"C:\\Program Files (x86)\\EPSON Software\\Download Navigator\\EPSDNMON.EXE\"",
        "\"C:\\Program Files (x86)\\Jabra\\Direct6\\jabra-direct.exe\" /minimized",
        "\"C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmware-tray.exe\"",
        "\"C:\\Program Files\\ESET\\ESET Security\\ecmds.exe\" /run /hide /proxy",
        "\"C:\\Program Files\\iTunes\\iTunesHelper.exe\"",
        "\"C:\\Program Files\\KeePassXC\\KeePassXC.exe\"",
        "\"C:\\Program Files\\Palo Alto Networks\\GlobalProtect\\PanGPA.exe\"",
        "\"C:\\Program Files\\PDF24\\pdf24.exe\"",
        "\"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe\" -n vmusr",
        "\"C:\\PROGRA~2\\Citrix\\DEVICE~1\\Bin64\\DTCLIE~1.EXE\"",
        "\"%ProgramFiles%\\Teams Installer\\Teams.exe\" --checkInstall --source=default"
      )
    )
  )
```



### Pluggable Authentication Module (PAM) Creation in Unusual Directory

Branch count: 1  
Document count: 1  
Index: geneve-ut-0891

```python
file where host.os.type == "linux" and event.type == "creation" and file.name like "pam_*.so" and not file.path like (
  "/lib/security/*",
  "/lib64/security/*",
  "/lib/x86_64-linux-gnu/security/*",
  "/usr/lib/security/*",
  "/usr/lib64/security/*",
  "/usr/lib/x86_64-linux-gnu/security/*"
) and not (
  process.name in ("dockerd", "containerd", "steam", "buildkitd", "unsquashfs", "pacman", "executor") or
  file.path like (
    "/build/rootImage/nix/store/*", "/home/*/.local/share/containers/*", "/nix/store/*", "/var/lib/containerd/*",
    "/var/snap/*", "/usr/share/nix/nix/store/*", "/tmp/cura/squashfs-root/*", "/home/*/docker/*", "/tmp/containerd*",
    "/var/lib/rancher/*/agent/containerd/*", "/var/lib/lxc/*", "/var/lib/containers/storage/*", "/var/lib/checkpoint*",
    "/var/lib/docker/overlay2/*", "/srv/docker/*", "/podman/storage/*", "/opt/jail/driver-jail*", "/build/tmp/work/iot*",
    "/tmp/containers-root/*", "/cce-14/*", "/cce-usr/*", "/var/tmp/portage/*", "/media/*", "/data/var/lib/docker/overlay2/*",
    "/home/*/.cache/bazel/*", "/home/*/.cache/umu/*/SteamLinuxRuntime*"
  )
)
```



### Pluggable Authentication Module (PAM) Source Download

Branch count: 6  
Document count: 6  
Index: geneve-ut-0892

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "ProcessRollup2") and
process.name in ("curl", "wget") and
process.args like~ "https://github.com/linux-pam/linux-pam/releases/download/v*/Linux-PAM-*.tar.xz"
```



### Pluggable Authentication Module (PAM) Version Discovery

Branch count: 12  
Document count: 12  
Index: geneve-ut-0893

```python
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and ?process.parent.name != null and
  (
    (process.name in ("dpkg", "dpkg-query") and process.args == "libpam-modules") or
    (process.name == "rpm" and process.args == "pam")
  ) and
not (
  ?process.parent.name in ("dcservice", "inspectorssmplugin") or
  ?process.working_directory in ("/var/ossec", "/opt/msp-agent") or
  ?process.parent.executable in (
    "/opt/CyberCNSAgent/cybercnsagent_linux", "/usr/local/manageengine/uems_agent/bin/dcpatchscan",
    "/usr/local/manageengine/uems_agent/bin/dcconfig", "/usr/share/vicarius/topiad",
    "/etc/rc.d/init.d/sshd-chroot"
  )
)
```



### Polkit Policy Creation

Branch count: 48  
Document count: 48  
Index: geneve-ut-0896

```python
file where host.os.type == "linux" and event.type == "creation" and process.executable != null and
file.extension in ("rules", "pkla", "policy") and file.path like~ (

  // Rule files
  "/etc/polkit-1/rules.d/*", "/usr/share/polkit-1/rules.d/*",

  // pkla files
  "/etc/polkit-1/localauthority/*", "/var/lib/polkit-1/localauthority/*",

  // Action files
  "/usr/share/polkit-1/actions/*",

  // Misc. legacy paths
  "/lib/polkit-1/rules.d/*", "/lib64/polkit-1/rules.d/*", "/var/lib/polkit-1/rules.d/*"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/bin/crio", "/usr/sbin/crond",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/kaniko/kaniko-executor",
    "/usr/local/bin/dockerd", "/usr/bin/podman", "/bin/install", "/proc/self/exe", "/usr/lib/systemd/systemd",
    "/usr/sbin/sshd", "/usr/bin/gitlab-runner", "/opt/gitlab/embedded/bin/ruby", "/usr/sbin/gdm", "/usr/bin/install",
    "/usr/local/manageengine/uems_agent/bin/dcregister", "/usr/local/bin/pacman", "./usr/bin/podman",
    "/kaniko/executor", "/opt/kaniko/executor", "/usr/bin/buildah", "/usr/lib/cargo/bin/coreutils/install"
  ) or
  process.executable like (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*",
    "/var/lib/containers/storage/overlay/*/dockerd", "/var/lib/docker/overlay2/*/dockerd"
  ) or
  (process.name like "python*" and file.name like ".ansible_tmp*.rules")
)
```



### Polkit Version Discovery

Branch count: 24  
Document count: 24  
Index: geneve-ut-0897

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "process_started", "executed") and (
  (process.name == "dnf" and process.args == "dnf" and process.args == "info" and process.args == "polkit") or
  (process.name == "rpm" and process.args == "polkit") or
  (process.name == "apt" and process.args == "show" and process.args == "policykit-1") or
  (process.name == "pkaction" and process.args == "--version")
) and
not (
  ?process.working_directory in ("/opt/msp-agent", "/opt/CyberCNSAgent") or
  ?process.parent.executable like ("/usr/local/cpanel/3rdparty/perl/*/bin/perl", "/usr/share/vicarius/topiad")
)
```



### Port Forwarding Rule Addition

Branch count: 1  
Document count: 1  
Index: geneve-ut-0898

```python
registry where host.os.type == "windows" and event.type == "change" and 
  registry.path : "*\\SYSTEM\\*ControlSet*\\Services\\PortProxy\\v4tov4\\*" and registry.data.strings != null
```



### Possible Okta DoS Attack

Branch count: 4  
Document count: 4  
Index: geneve-ut-0900

```python
event.dataset:okta.system and event.action:(application.integration.rate_limit_exceeded or system.org.rate_limit.warning or system.org.rate_limit.violation or core.concurrency.org.limit.violation)
```



### Potential Admin Group Account Addition

Branch count: 16  
Document count: 16  
Index: geneve-ut-0905

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.name in ("dscl", "dseditgroup") and process.args like~ ("/Groups/admin", "admin") and process.args like ("-a", "-append") and
 not process.Ext.effective_parent.executable like ("/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon",
                                                   "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfManagementService.app/Contents/MacOS/JamfManagementService",
                                                   "/opt/jc/bin/jumpcloud-agent",
                                                   "/Library/Addigy/go-agent")
```



### Potential Application Shimming via Sdbinst

Branch count: 2  
Document count: 2  
Index: geneve-ut-0907

```python
process where host.os.type == "windows" and event.type == "start" and process.name : "sdbinst.exe" and
  process.args : "?*" and
  not (process.args : "-m" and process.args : "-bg") and
  not process.args : (
    "-mm",
    "?:\\Program Files\\WindowsApps\\Microsoft.ApplicationCompatibilityEnhancements_*\\sdb\\sysMergeInboxStoreApp.sdb",
    "\"?:\\Program Files\\WindowsApps\\Microsoft.ApplicationCompatibilityEnhancements_*\\sdb\\sysMergeInboxStoreApp.sdb\"",
    "?:\\Program Files\\WindowsApps\\Microsoft.ApplicationCompatibilityEnhancements_*\\sdb\\msiMergeInboxStoreApp.sdb",
    "\"?:\\Program Files\\WindowsApps\\Microsoft.ApplicationCompatibilityEnhancements_*\\sdb\\msiMergeInboxStoreApp.sdb\"",
    "?:\\Program Files (x86)\\Citrix\\ICA Client\\CitrixWorkspaceLegacySWDA.sdb",
    "Citrix Workspace",
    "C:\\Program Files\\IIS Express\\iisexpressshim.sdb",
    "C:\\Program Files (x86)\\IIS Express\\iisexpressshim.sdb"
  )
```



### Potential CVE-2025-32463 Nsswitch File Creation

Branch count: 8  
Document count: 8  
Index: geneve-ut-0911

```python
file where host.os.type == "linux" and event.type == "creation" and file.path like "/*/etc/nsswitch.conf" and
process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
not file.path like (
  "/var/tmp/mkinitramfs_*", "/tmp/tmp.*/mkinitramfs_*", "/var/tmp/dracut.*", "/tmp/user/0/mkinitramfs_*",
  "/var/lib/aws-replication-agent/.tmp/mkinitramfs_*"
)
```



### Potential CVE-2025-32463 Sudo Chroot Execution Attempt

Branch count: 24  
Document count: 24  
Index: geneve-ut-0912

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "executed", "process_started", "ProcessRollup2") and
process.name == "sudo" and process.args like ("-R", "--chroot*") and
// To enforce the -R and --chroot arguments to be for sudo specifically, while wildcarding potential full sudo paths
process.command_line like ("*sudo -R*", "*sudo --chroot*")
```



### Potential CVE-2025-33053 Exploitation

Branch count: 6  
Document count: 6  
Index: geneve-ut-0913

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.executable : "C:\\Program Files\\Internet Explorer\\iediagcmd.exe" and
  process.name : ("route.exe", "netsh.exe", "ipconfig.exe", "dxdiag.exe", "conhost.exe", "makecab.exe") and
  process.executable != null and
  not process.executable : ("C:\\Windows\\System32\\route.exe",
                            "C:\\Windows\\System32\\netsh.exe",
                            "C:\\Windows\\System32\\ipconfig.exe",
                            "C:\\Windows\\System32\\dxdiag.exe",
                            "C:\\Windows\\System32\\conhost.exe",
                            "C:\\Windows\\System32\\makecab.exe")
```



### Potential CVE-2025-41244 vmtoolsd LPE Exploitation Attempt

Branch count: 54  
Document count: 54  
Index: geneve-ut-0914

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "executed", "process_started", "ProcessRollup2") and
(
  (
    process.parent.name == "vmtoolsd"
  ) or
  (
    process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
    ?process.parent.args like ("/*/open-vm-tools/serviceDiscovery/scripts/get-versions.sh")
  )
) and not (
  process.executable == null or
  ?process.parent.args == "--version" or
  process.args like (
    "/etc/vmware-tools/resume-vm-default",
    "/etc/vmware-tools/suspend-vm-default",
    "/sbin/shutdown",
    "/sbin/shutdown*",
    "/etc/vmware-tools/poweroff-vm-default",
    "/etc/vmware-tools/poweroff-vm-default",
    "/bin/touch",
    "/tmp/vmware-administrator_*",
    "/tmp/vmware-root_*",
    "/etc/vmware-tools/scripts/vmware/network",
    "/etc/vmware-tools/poweron-vm-default"
  ) or
  process.executable == "/usr/sbin/unix_chkpwd" or
  ?process.working_directory like ("/var/opt/ds_agent", "/tmp/vmware-root_*/tmpvmware*") or
  process.command_line like ("*/usr/bin/lsb_release*", "*/bin/touch*", "*/tmp/vmware-root_*")
)
```



### Potential Chroot Container Escape via Mount

Branch count: 72  
Document count: 144  
Index: geneve-ut-0915

```python
sequence by host.id, process.parent.entity_id with maxspan=5m
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "ProcessRollup2") and
   process.name == "mount" and process.args : "/dev/sd*" and process.args_count >= 3 and
   process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")]
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "ProcessRollup2") and
   process.name == "chroot"]
```



### Potential Cluster Enumeration via jq Detected via Defend for Containers

Branch count: 1  
Document count: 1  
Index: geneve-ut-0916

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name == "jq" and
process.interactive == true and container.id like "?*"
```



### Potential Code Execution via Postgresql

Branch count: 8  
Document count: 8  
Index: geneve-ut-0917

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "fork", "fork_event") and user.name == "postgres" and (
  (process.parent.args : "*sh" and process.parent.args : "echo*") or
  (process.args : "*sh" and process.args : "echo*")
) and not (
  process.parent.name == "puppet" or
  process.command_line like (
    "*BECOME-SUCCESS-*", "bash -c while true; do sleep 1;*", "df -l", "sleep 1", "who", "head -v -n *", "tail -v -n *",
    "/bin/sh -c echo BECOME-SUCCESS*", "/usr/bin/python3 /var/tmp/ansible-tmp*", "*chpasswd*"
  ) or
  process.parent.command_line like ("*BECOME-SUCCESS-*", "-bash -c echo $HOME", "su - postgres -c echo $HOME") or
  process.parent.executable in ("/usr/bin/watch", "/bin/diskmgr", "/usr/bin/diskmgr")
)
```



### Potential Command and Control via Internet Explorer

Branch count: 2  
Document count: 6  
Index: geneve-ut-0919

```python
sequence by host.id, user.name with maxspan = 5s
  [library where host.os.type == "windows" and dll.name : "IEProxy.dll" and process.name : ("rundll32.exe", "regsvr32.exe")]
  [process where host.os.type == "windows" and event.type == "start" and process.parent.name : "iexplore.exe" and process.parent.args : "-Embedding"]
  /* IE started via COM in normal conditions makes few connections, mainly to Microsoft and OCSP related domains, add FPs here */
  [network where host.os.type == "windows" and network.protocol == "dns" and process.name : "iexplore.exe" and
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
Index: geneve-ut-0921

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



### Potential Credential Access via DuplicateHandle in LSASS

Branch count: 1  
Document count: 1  
Index: geneve-ut-0923

```python
process where host.os.type == "windows" and event.code == "10" and

 /* LSASS requesting DuplicateHandle access right to another process */
 process.name : "lsass.exe" and winlog.event_data.GrantedAccess == "0x40" and

 /* call is coming from an unknown executable region */
 winlog.event_data.CallTrace : "*UNKNOWN*"
```



### Potential Credential Access via LSASS Memory Dump

Branch count: 2  
Document count: 2  
Index: geneve-ut-0924

```python
process where host.os.type == "windows" and event.code == "10" and
  winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe" and

   /* DLLs exporting MiniDumpWriteDump API to create an lsass mdmp*/
  winlog.event_data.CallTrace : ("*dbghelp*", "*dbgcore*") and

   /* case of lsass crashing */
  not process.executable : (
        "?:\\Windows\\System32\\WerFault.exe",
        "?:\\Windows\\SysWOW64\\WerFault.exe",
        "?:\\Windows\\System32\\WerFaultSecure.exe"
      )
```



### Potential Credential Access via Memory Dump File Creation

Branch count: 4  
Document count: 4  
Index: geneve-ut-0925

```python
file where host.os.type == "windows" and event.type == "creation" and

  /* MDMP header */
  file.Ext.header_bytes : "4d444d50*" and file.size >= 30000 and
  not

  (
    (
      process.name : "System" or
      process.executable : (
        "?:\\Windows\\System32\\WerFault.exe",
        "?:\\Windows\\SysWOW64\\WerFault.exe",
        "?:\\Windows\\System32\\Wermgr.exe",
        "?:\\Windows\\SysWOW64\\Wermgr.exe",
        "?:\\Windows\\System32\\WerFaultSecure.exe",
        "?:\\Windows\\SysWOW64\\WerFaultSecure.exe",
        "?:\\Windows\\System32\\WUDFHost.exe",
        "C:\\Windows\\System32\\rdrleakdiag.exe",
        "?:\\Windows\\System32\\Taskmgr.exe",
        "?:\\Windows\\SysWOW64\\Taskmgr.exe",
        "?:\\Program Files\\*.exe",
        "?:\\Program Files (x86)\\*.exe",
        "?:\\Windows\\SystemApps\\*.exe",
        "?:\\Users\\*\\AppData\\Roaming\\Zoom\\bin\\zCrashReport64.exe",
        "?:\\Windows\\CCM\\ccmdump.exe",
        "?:\\$WINDOWS.~BT\\Sources\\SetupHost.exe"
      ) and process.code_signature.trusted == true
    ) or
    (
      file.path : (
        "?:\\ProgramData\\Microsoft\\Windows\\WER\\*",
        "?:\\ProgramData\\Microsoft\\WDF\\*",
        "?:\\ProgramData\\Alteryx\\ErrorLogs\\*",
        "?:\\ProgramData\\Goodix\\*",
        "?:\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\CrashDumps\\*",
        "?:\\Users\\*\\AppData\\Roaming\\Zoom\\logs\\zoomcrash*",
        "?:\\Users\\*\\AppData\\*\\Crashpad\\*",
        "?:\\Users\\*\\AppData\\*\\crashpaddb\\*",
        "?:\\Users\\*\\AppData\\*\\HungReports\\*",
        "?:\\Users\\*\\AppData\\*\\CrashDumps\\*",
        "?:\\Users\\*\\AppData\\*\\NativeCrashReporting\\*",
        "?:\\Program Files (x86)\\*\\Crashpad\\*",
        "?:\\Program Files\\*\\Crashpad\\*"
      ) and (process.code_signature.trusted == true or process.executable == null)
    )
  )
```



### Potential Credential Access via Renamed COM+ Services DLL

Branch count: 2  
Document count: 4  
Index: geneve-ut-0926

```python
sequence by process.entity_id with maxspan=1m
 [process where host.os.type == "windows" and event.category == "process" and
    process.name : "rundll32.exe"]
 [process where host.os.type == "windows" and event.category == "process" and event.dataset : "windows.sysmon_operational" and event.code == "7" and
   (file.pe.original_file_name : "COMSVCS.DLL" or file.pe.imphash : "EADBCCBB324829ACB5F2BBE87E5549A8") and
    /* renamed COMSVCS */
    not file.name : "COMSVCS.DLL"]
```



### Potential Credential Access via Trusted Developer Utility

Branch count: 16  
Document count: 32  
Index: geneve-ut-0927

```python
sequence by process.entity_id
 [process where host.os.type == "windows" and event.type == "start" and (process.name : "MSBuild.exe" or process.pe.original_file_name == "MSBuild.exe")]
 [any where host.os.type == "windows" and (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
  (?dll.name : ("vaultcli.dll", "SAMLib.DLL") or file.name : ("vaultcli.dll", "SAMLib.DLL"))]
```



### Potential Data Exfiltration Through Wget

Branch count: 12  
Document count: 12  
Index: geneve-ut-0937

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "wget" and process.args like ("--post-file=*", "--body-file=*")
```



### Potential Data Splitting Detected

Branch count: 36  
Document count: 36  
Index: geneve-ut-0938

```python
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  (
    (process.name == "dd" and process.args like "bs=*" and process.args like "if=*") or
    (
      process.name in ("split", "rsplit") and
      (
        (process.args == "-b" or process.args like "--bytes*") or
        (process.args == "-C" or process.args like "--line-bytes*")
      )
    )
  ) and
  not (
    process.parent.name in ("apport", "overlayroot", "nessus-agent-module") or
    process.args like (
      "if=/tmp/nvim*", "if=/boot/*", "if=/dev/random", "if=/dev/urandom", "/dev/mapper/*",
      "if=*.iso", "of=/dev/stdout", "if=/dev/zero", "if=/dev/sda", "/proc/sys/kernel/*"
    ) or
    ?process.parent.args in ("/etc/init.d/apport", "/usr/bin/spectre-meltdown-checker")
  )
```



### Potential Defense Evasion via CMSTP.exe

Branch count: 1  
Document count: 1  
Index: geneve-ut-0939

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "cmstp.exe" and process.args == "/s"
```



### Potential Defense Evasion via Doas

Branch count: 1  
Document count: 1  
Index: geneve-ut-0940

```python
file where host.os.type == "linux" and event.type != "deletion" and file.path == "/etc/doas.conf"
```



### Potential Defense Evasion via PRoot

Branch count: 4  
Document count: 4  
Index: geneve-ut-0941

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.parent.name == "proot"
```



### Potential Direct Kubelet Access via Process Arguments Detected via Defend for Containers

Branch count: 1  
Document count: 1  
Index: geneve-ut-0943

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.args like "http*:10250*" and process.interactive == true and container.id like "?*"
```



### Potential Disabling of AppArmor

Branch count: 18  
Document count: 18  
Index: geneve-ut-0944

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
(
  (process.name == "systemctl" and process.args in ("disable", "stop", "kill", "mask") and process.args in ("apparmor", "apparmor.service")) or
  (process.name == "service" and process.args == "apparmor" and process.args == "stop") or
  (process.name == "chkconfig" and process.args == "apparmor" and process.args == "off") or
  (process.name == "update-rc.d" and process.args == "apparmor" and process.args in ("remove", "disable")) or
  (process.name == "ln" and process.args : "/etc/apparmor.d/*" and process.args == "/etc/apparmor.d/disable/")
) and
not ?process.parent.executable == "/opt/puppetlabs/puppet/bin/ruby"
```



### Potential Disabling of SELinux

Branch count: 6  
Document count: 6  
Index: geneve-ut-0945

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "setenforce" and process.args == "0"
```



### Potential Enumeration via Active Directory Web Service

Branch count: 2  
Document count: 4  
Index: geneve-ut-0948

```python
sequence by process.entity_id with maxspan=3m
 [library where host.os.type == "windows" and
  dll.name : ("System.DirectoryServices*.dll", "System.IdentityModel*.dll") and
  not user.id in ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
  not process.executable :
                ("?:\\windows\\system32\\dsac.exe",
                 "?:\\program files\\powershell\\?\\pwsh.exe",
                 "?:\\windows\\system32\\windowspowershell\\*.exe",
                 "?:\\windows\\syswow64\\windowspowershell\\*.exe",
                 "?:\\program files\\microsoft monitoring agent\\*.exe",
                 "?:\\windows\\adws\\microsoft.activedirectory.webservices.exe")]
 [network where host.os.type == "windows" and destination.port == 9389 and source.port >= 49152 and
  network.direction == "egress" and network.transport == "tcp" and not cidrmatch(destination.ip, "127.0.0.0/8", "::1/128")]
```



### Potential Escalation via Vulnerable MSI Repair

Branch count: 42  
Document count: 42  
Index: geneve-ut-0949

```python
process where event.type == "start" and host.os.type == "windows" and
 user.domain : ("NT AUTHORITY", "AUTORITE NT", "AUTORIDADE NT") and
 process.parent.name : ("chrome.exe", "msedge.exe", "brave.exe", "whale.exe", "browser.exe", "dragon.exe", "vivaldi.exe",
                        "opera.exe", "iexplore", "firefox.exe", "waterfox.exe", "iexplore.exe", "tor.exe", "safari.exe") and
 process.parent.command_line : "*go.microsoft.com*"
```



### Potential Etherhiding C2 via Blockchain Connection

Branch count: 90  
Document count: 180  
Index: geneve-ut-0950

```python
sequence by process.entity_id with maxspan=15s
  [network where host.os.type == "macos" and event.type == "start" and
    (process.name in ("bash", "sh", "zsh", "osascript", "node", "Cursor") or
    process.name like ("python*", "ruby*", "perl*", "tclsh*")) and
    destination.domain like ("eth-mainnet*", "ethereum*", "eth.*.com")]
  [file where host.os.type == "macos" and event.action == "modification" and file.extension in ("js", "py", "sh")]
```



### Potential Evasion via Filter Manager

Branch count: 1  
Document count: 1  
Index: geneve-ut-0951

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "fltMC.exe" and process.args : "unload" and
  not process.parent.executable : 
                   ("?:\\Program Files (x86)\\ManageEngine\\UEMS_Agent\\bin\\DCFAService64.exe", 
                    "?:\\Windows\\SysWOW64\\msiexec.exe", 
                    "?:\\Program Files\\Bitdefender\\Endpoint Security\\installer\\installer.exe", 
                    "?:\\Program Files\\Bitdefender\\Endpoint Security\\EPSecurityService.exe", 
                    "?:\\Program Files\\Bitdefender\\Bitdefender Security\\productcfg.exe", 
                    "?:\\Program Files\\Bitdefender\\Bitdefender Security\\bdservicehost.exe", 
                    "?:\\Program Files\\Bitdefender\\EndpointSetupInformation\\{*}\\Installer.exe")
```



### Potential Execution of rc.local Script

Branch count: 1  
Document count: 1  
Index: geneve-ut-0953

```python
process where host.os.type == "linux" and event.type == "info" and event.action == "already_running" and
process.parent.args == "/etc/rc.local" and process.parent.args == "start"
```



### Potential Execution via SSH Backdoor

Branch count: 8  
Document count: 16  
Index: geneve-ut-0955

```python
sequence by host.id with maxspan=1m
  [process where host.os.type == "linux" and event.action == "end" and process.name == "sshd" and process.exit_code != 0 and
   process.command_line == "/usr/sbin/sshd -D -R" and process.parent.command_line == "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"] by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name == "sshd" and process.parent.command_line == "/usr/sbin/sshd -D -R" and
   process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and process.args == "-c" and not (
     process.args like (
       "rsync*", "systemctl*", "/usr/sbin/unix_chkpwd", "/usr/bin/google_authorized_keys", "/usr/sbin/aad_certhandler*",
        "bash -c bash -s", "/usr/lib/ssh/sftp-server", "stat /etc/is_upgrade_install > /dev/null 2>&1",
        "stat /opt/qradar/ha/.*", "/usr/bin/env -i PATH=*", "/opt/gitlab/*", "clamdscan*", "wc*", "export*",
        "test*", "md5sum*", "check_mk_agent", "/usr/bin/env*", "/usr/bin/check_mk_agent", "timeout*", "/usr/sbin/haproxy*",
        "/usr/libexec/openssh/sftp-server", "command*", "find*", "cd *", "scp*", "while*", "pvesh*", "/bin/true",
        "/usr/sbin/qm mtunnel", "multipath*", "/usr/lib/openssh/sftp-server"
     ) or
     process.command_line like ("sh -c /usr/bin/env -i PATH=*", "sh -c -- /usr/bin/env -i PATH=*", "*ansible*", "*BECOME-SUCCESS*")
   )
  ] by process.parent.entity_id
```



### Potential Fake CAPTCHA Phishing Attack

Branch count: 39  
Document count: 39  
Index: geneve-ut-0958

```python
process where host.os.type == "windows" and event.type == "start" and
 process.name : ("powershell.exe", "cmd.exe", "mshta.exe") and process.parent.name : "explorer.exe" and
 process.command_line : ("*recaptcha *", "*CAPTCHA Verif*", "*complete verification*", "*Verification ID*", "*Verification Code*", "*Verification UID*",
                         "*hυmаn vаlіdаtiοn*", "*human ID*", "*Action Identificator*", "*not a robot*", "*Click OK to*", "*anti-robot test*",
                         "*Cloudflare ID*")
```



### Potential File Download via a Headless Browser

Branch count: 408  
Document count: 408  
Index: geneve-ut-0959

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("chrome.exe", "msedge.exe", "brave.exe", "browser.exe", "dragon.exe", "vivaldi.exe") and
  process.args : "--headless*" and
  process.args : ("--disable-gpu", "--dump-dom", "*http*", "data:text/html;base64,*") and
  process.parent.name :
     ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "conhost.exe", "msiexec.exe",
      "explorer.exe", "rundll32.exe", "winword.exe", "excel.exe", "onenote.exe", "hh.exe", "powerpnt.exe", "forfiles.exe",
      "pcalua.exe", "wmiprvse.exe") and
  not process.executable : (
        "?:\\inetpub\\wwwroot\\*\\ext\\modules\\html2pdf\\bin\\chrome\\*\\chrome-win64\\chrome.exe",
        "\\Device\\HarddiskVolume*\\inetpub\\wwwroot\\*\\ext\\modules\\html2pdf\\bin\\chrome\\*\\chrome-win64\\chrome.exe"
  )
```



### Potential File Transfer via Certreq

Branch count: 2  
Document count: 2  
Index: geneve-ut-0960

```python
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "CertReq.exe" or ?process.pe.original_file_name == "CertReq.exe") and process.args : "-Post"
```



### Potential File Transfer via Curl for Windows

Branch count: 66  
Document count: 66  
Index: geneve-ut-0961

```python
process where host.os.type == "windows" and event.type == "start" and
  process.executable : (
    "?:\\Windows\\System32\\curl.exe",
    "?:\\Windows\\SysWOW64\\curl.exe"
  ) and
  process.command_line : "*http*" and
  process.parent.name : (
    "cmd.exe", "powershell.exe",
    "rundll32.exe", "explorer.exe",
    "conhost.exe", "forfiles.exe",
    "wscript.exe", "cscript.exe",
    "mshta.exe", "hh.exe", "mmc.exe"
  ) and 
  not (
    ?user.id == "S-1-5-18" and
    /* Don't apply the user.id exclusion to Sysmon for compatibility */
    not event.dataset : ("windows.sysmon_operational", "windows.sysmon")
  ) and
  /* Exclude System Integrity Processes for Sysmon */
  not ?winlog.event_data.IntegrityLevel == "System"
```



### Potential Foxmail Exploitation

Branch count: 2  
Document count: 2  
Index: geneve-ut-0962

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "Foxmail.exe" and process.args : ("?:\\Users\\*\\AppData\\*", "\\\\*")
```



### Potential Hidden Local User Account Creation

Branch count: 6  
Document count: 6  
Index: geneve-ut-0967

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.name == "dscl" and process.args like~ "IsHidden" and process.args like~ "create" and 
 process.args like~ ("true", "1", "yes")
```



### Potential Hidden Process via Mount Hidepid

Branch count: 5  
Document count: 5  
Index: geneve-ut-0968

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "executed", "process_started") and
process.name == "mount" and process.args == "/proc" and process.args == "-o" and process.args : "*hidepid=2*" and
not process.parent.command_line like "/opt/cloudlinux/*"
```



### Potential Impersonation Attempt via Kubectl

Branch count: 375  
Document count: 375  
Index: geneve-ut-0969

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "executed", "process_started") and
process.name == "kubectl" and (
  process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") or
  (
    process.parent.executable like ("/tmp/*", "/var/tmp/*", "/dev/shm/*", "/root/*", "/home/*") or
    process.parent.name like (".*", "*.sh")
  )
) and process.args like~ ("--kubeconfig*", "--token*", "--as*", "--as-group*", "--as-uid*") and
not process.parent.args like ("/snap/microk8s/*/apiservice-kicker", "/snap/microk8s/*/microk8s-start.wrapper")
```



### Potential JAVA/JNDI Exploitation Attempt

Branch count: 60  
Document count: 120  
Index: geneve-ut-0972

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
                   "wget") and
    not process.command_line like~ (
      "bash -c ulimit -u",
      "bash /opt/flutter/bin/flutter*",
      "bash -c echo $$",
      "/bin/bash /opt/python3/bin/jira*",
      "/bin/sh -c env LC_ALL=C /usr/sbin/lpc status*"
    )] by process.parent.pid
```



### Potential Kerberos Attack via Bifrost

Branch count: 16  
Document count: 16  
Index: geneve-ut-0973

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.args like~ "-action" and
 (
  process.args like~ ("-kerberoast", "askhash", "asktgs", "asktgt", "s4u") or
  (process.args like~ "-ticket" and process.args like~ "ptt") or
  (process.args like~ "dump" and process.args in~ ("tickets", "keytab"))
 )
```



### Potential Kerberos Coercion via DNS-Based SPN Spoofing

Branch count: 2  
Document count: 2  
Index: geneve-ut-0974

```python
host.os.type:"windows" and
(
  (event.code:4662 and winlog.event_data.AdditionalInfo: *UWhRC*BAAAA*MicrosoftDNS*) or 
  (event.code:5137 and winlog.event_data.ObjectDN: *UWhRC*BAAAA*MicrosoftDNS*)
)
```



### Potential Kerberos SPN Spoofing via Suspicious DNS Query

Branch count: 1  
Document count: 1  
Index: geneve-ut-0976

```python
network where host.os.type == "windows" and dns.question.name : "*UWhRC*BAAAA*"
```



### Potential Kubeletctl Execution Detected via Defend for Containers

Branch count: 2  
Document count: 2  
Index: geneve-ut-0978

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  (process.name == "kubeletctl" or process.args like "*kubeletctl*") or
  (process.args in ("-s", "--server") and process.args in ("run", "portForward", "scan", "attach", "exec", "pods", "runningpods", "cri", "pid2pod"))
) and
process.interactive == true and container.id like "?*"
```



### Potential LSA Authentication Package Abuse

Branch count: 2  
Document count: 2  
Index: geneve-ut-0979

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
      "HKLM\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Authentication Packages",
      "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Authentication Packages"
  ) and
  /* exclude SYSTEM SID - look for changes by non-SYSTEM user */
  not user.id : "S-1-5-18"
```



### Potential LSASS Clone Creation via PssCaptureSnapShot

Branch count: 1  
Document count: 1  
Index: geneve-ut-0980

```python
process where host.os.type == "windows" and event.code:"4688" and
  process.executable : "?:\\Windows\\System32\\lsass.exe" and
  process.parent.executable : "?:\\Windows\\System32\\lsass.exe"
```



### Potential Lateral Tool Transfer via SMB Share

Branch count: 24  
Document count: 48  
Index: geneve-ut-0982

```python
sequence by host.id with maxspan=30s
  [network where host.os.type == "windows" and event.type == "start" and process.pid == 4 and destination.port == 445 and
   network.direction : ("incoming", "ingress") and
   network.transport == "tcp" and source.ip != "127.0.0.1" and source.ip != "::1"
  ] by process.entity_id
  /* add more executable extensions here if they are not noisy in your environment */
  [file where host.os.type == "windows" and event.type in ("creation", "change") and process.pid == 4 and 
   (file.Ext.header_bytes : "4d5a*" or file.extension : ("exe", "scr", "pif", "com", "dll"))] by process.entity_id
```



### Potential Linux Credential Dumping via Proc Filesystem

Branch count: 27  
Document count: 54  
Index: geneve-ut-0984

```python
sequence by host.id, process.parent.name with maxspan=1m
  [process where host.os.type == "linux" and process.name == "ps" and event.action in ("exec", "start", "exec_event")
   and process.args in ("-eo", "pid", "command")]
  [process where host.os.type == "linux" and process.name == "strings" and event.action in ("exec", "start", "exec_event")
   and process.args : "/tmp/*"]
```



### Potential Linux Credential Dumping via Unshadow

Branch count: 4  
Document count: 4  
Index: geneve-ut-0985

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.name == "unshadow" and process.args_count >= 3
```



### Potential Linux Hack Tool Launched

Branch count: 252  
Document count: 252  
Index: geneve-ut-0986

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name in~ (
  // exploitation frameworks
  "crackmapexec", "msfconsole", "msfvenom", "sliver-client", "sliver-server", "havoc",
  // network scanners (nmap left out to reduce noise)
  "zenmap", "nuclei", "netdiscover", "legion",
  // web enumeration
  "gobuster", "dirbuster", "dirb", "wfuzz", "ffuf", "whatweb", "eyewitness",
  // web vulnerability scanning
  "wpscan", "joomscan", "droopescan", "nikto",
  // exploitation tools
  "sqlmap", "commix", "yersinia",
  // cracking and brute forcing
  "john", "hashcat", "hydra", "ncrack", "cewl", "fcrackzip", "rainbowcrack",
  // host and network
  "linenum.sh", "linpeas.sh", "pspy32", "pspy32s", "pspy64", "pspy64s", "binwalk", "evil-winrm",
  "linux-exploit-suggester-2.pl", "linux-exploit-suggester.sh", "panix.sh"
)
```



### Potential Linux Tunneling and/or Port Forwarding via SSH Option

Branch count: 72  
Document count: 72  
Index: geneve-ut-0991

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.name in ("ssh", "sshd") and process.args == "-o" and
process.command_line like~ (
  "*ProxyCommand*", "*LocalForward*", "*RemoteForward*", "*DynamicForward*", "*Tunnel*", "*GatewayPorts*",
  "*ExitOnForwardFailure*", "*ProxyCommand*", "*ProxyJump*"
) and 
not (
  ?process.parent.args == "/usr/bin/pvedaemon" or
  ?process.parent.command_line in ("pvedaemon", "pve-ha-lrm") or
  ?process.working_directory like "*ansible*" or
  process.command_line like "*ansible*"
)
```



### Potential Local NTLM Relay via HTTP

Branch count: 6  
Document count: 6  
Index: geneve-ut-0992

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "rundll32.exe" and

  /* Rundll32 WbeDav Client  */
  process.args : ("?:\\Windows\\System32\\davclnt.dll,DavSetCookie", "?:\\Windows\\SysWOW64\\davclnt.dll,DavSetCookie") and

  /* Access to named pipe via http */
  process.args : ("http*/print/pipe/*", "http*/pipe/spoolss", "http*/pipe/srvsvc")
```



### Potential Masquerading as Business App Installer

Branch count: 54  
Document count: 54  
Index: geneve-ut-0997

```python
process where host.os.type == "windows" and 
  event.type == "start" and process.executable : "?:\\Users\\*\\Downloads\\*" and
  not process.code_signature.status like ("errorCode_endpoint*", "errorUntrustedRoot", "errorChaining") and process.hash.sha256 != null and 
  (
    /* Slack */
    (process.name : "*slack*.exe" and not
      (process.code_signature.subject_name in (
        "Slack Technologies, Inc.",
        "Slack Technologies, LLC"
       ) and process.code_signature.trusted == true)
    ) or

    /* WebEx */
    (process.name : "*webex*.exe" and not
      (process.code_signature.subject_name in ("Cisco WebEx LLC", "Cisco Systems, Inc.") and process.code_signature.trusted == true)
    ) or

    /* Teams */
    (process.name : "teams*.exe" and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Discord */
    (process.name : "*discord*.exe" and not
      (process.code_signature.subject_name == "Discord Inc." and process.code_signature.trusted == true)
    ) or

    /* WhatsApp */
    (process.name : "*whatsapp*.exe" and not
      (process.code_signature.subject_name in (
        "WhatsApp LLC",
        "WhatsApp, Inc",
        "24803D75-212C-471A-BC57-9EF86AB91435",
        /* WhatsApp Installer - MS Store */
        "Microsoft Corporation"
       ) and process.code_signature.trusted == true)
    ) or

    /* Zoom */
    (process.name : ("*zoom*installer*.exe", "*zoom*setup*.exe", "zoom.exe")  and not
      (process.code_signature.subject_name in (
        "Zoom Video Communications, Inc.", "Zoom Communications, Inc."
       ) and process.code_signature.trusted == true)
    ) or

    /* Outlook */
    (process.name : "*outlook*.exe" and not
      (
        (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true) or
        (
          process.name: "MSOutlookHelp-PST-Viewer.exe" and process.code_signature.subject_name == "Aryson Technologies Pvt. Ltd" and
          process.code_signature.trusted == true
        )
      )
    ) or

    /* Thunderbird */
    (process.name : "*thunderbird*.exe" and not
      (process.code_signature.subject_name == "Mozilla Corporation" and process.code_signature.trusted == true)
    ) or

    /* Grammarly */
    (process.name : "*grammarly*.exe" and not
      (process.code_signature.subject_name == "Grammarly, Inc." and process.code_signature.trusted == true)
    ) or

    /* Dropbox */
    (process.name : "*dropbox*.exe" and not
      (process.code_signature.subject_name == "Dropbox, Inc" and process.code_signature.trusted == true)
    ) or

    /* Tableau */
    (process.name : "*tableau*.exe" and not
      (process.code_signature.subject_name == "Tableau Software LLC" and process.code_signature.trusted == true)
    ) or

    /* Google Drive */
    (process.name : "*googledrive*.exe" and not
      (process.code_signature.subject_name == "Google LLC" and process.code_signature.trusted == true)
    ) or

    /* MSOffice */
    (process.name : "*office*setup*.exe" and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Okta */
    (process.name : "*okta*.exe" and not
      (process.code_signature.subject_name == "Okta, Inc." and process.code_signature.trusted == true)
    ) or

    /* OneDrive */
    (process.name : "*onedrive*.exe" and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Chrome */
    (process.name : "*chrome*.exe" and not
      (process.code_signature.subject_name in ("Google LLC", "Google Inc") and process.code_signature.trusted == true)
    ) or

    /* Firefox */
    (process.name : "*firefox*.exe" and not
      (process.code_signature.subject_name == "Mozilla Corporation" and process.code_signature.trusted == true)
    ) or

    /* Edge */
    (process.name : ("*microsoftedge*.exe", "*msedge*.exe") and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Brave */
    (process.name : "*brave*.exe" and not
      (process.code_signature.subject_name == "Brave Software, Inc." and process.code_signature.trusted == true)
    ) or

    /* GoogleCloud Related Tools */
    (process.name : "*GoogleCloud*.exe" and not
      (process.code_signature.subject_name == "Google LLC" and process.code_signature.trusted == true)
    ) or

    /* Github Related Tools */
    (process.name : "*github*.exe" and not
      (process.code_signature.subject_name == "GitHub, Inc." and process.code_signature.trusted == true)
    ) or

    /* Notion */
    (process.name : "*notion*.exe" and not
      (process.code_signature.subject_name == "Notion Labs, Inc." and process.code_signature.trusted == true)
    )
  )
```



### Potential Masquerading as Communication Apps

Branch count: 20  
Document count: 20  
Index: geneve-ut-0998

```python
process where host.os.type == "windows" and
  event.type == "start" and 
  not process.code_signature.status like "errorCode_endpoint*" and process.hash.sha256 != null and 
  (
    /* Slack */
    (process.name : "slack.exe" and not
      (process.code_signature.subject_name : (
        "Slack Technologies, Inc.",
        "Slack Technologies, LLC"
       ) and process.code_signature.trusted == true)
    ) or

    /* WebEx */
    (process.name : "WebexHost.exe" and not
      (process.code_signature.subject_name : ("Cisco WebEx LLC", "Cisco Systems, Inc.") and process.code_signature.trusted == true)
    ) or

    /* Teams */
    (process.name : "Teams.exe" and not
      (process.code_signature.subject_name : "Microsoft Corporation" and process.code_signature.trusted == true) and 
      process.executable != "C:\\Program Files (x86)\\Teams Installer\\Teams.exe"
    ) or

    /* Discord */
    (process.name : "Discord.exe" and not
      (process.code_signature.subject_name : "Discord Inc." and process.code_signature.trusted == true)
    ) or

    /* RocketChat */
    (process.name : "Rocket.Chat.exe" and not
      (process.code_signature.subject_name : "Rocket.Chat Technologies Corp." and process.code_signature.trusted == true) and 
      process.executable != "C:\\Program Files\\rocketchat\\Rocket.Chat.exe"
    ) or

    /* Mattermost */
    (process.name : "Mattermost.exe" and not
      (process.code_signature.subject_name : "Mattermost, Inc." and process.code_signature.trusted == true)
    ) or

    /* WhatsApp */
    (process.name : "WhatsApp.exe" and not
      (process.code_signature.subject_name : (
        "WhatsApp LLC",
        "WhatsApp, Inc",
        "24803D75-212C-471A-BC57-9EF86AB91435"
       ) and process.code_signature.trusted == true)
    ) or

    /* Zoom */
    (process.name : "Zoom.exe" and not
      (process.code_signature.subject_name : (
        "Zoom Video Communications, Inc.",
        "Zoom Communications, Inc."
       ) and process.code_signature.trusted == true)
    ) or

    /* Outlook */
    (process.name : "outlook.exe" and not
      (process.code_signature.subject_name : "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Thunderbird */
    (process.name : "thunderbird.exe" and not
      (process.code_signature.subject_name : "Mozilla Corporation" and process.code_signature.trusted == true)
    )
  )
```



### Potential Masquerading as VLC DLL

Branch count: 6  
Document count: 6  
Index: geneve-ut-1002

```python
library where host.os.type == "windows" and event.action == "load" and
  dll.name : ("libvlc.dll", "libvlccore.dll", "axvlc.dll") and
  not (
    dll.code_signature.subject_name : ("VideoLAN", "716F2E5E-A03A-486B-BC67-9B18474B9D51")
    and dll.code_signature.trusted == true
  )
```



### Potential Memory Seeking Activity

Branch count: 28  
Document count: 28  
Index: geneve-ut-1003

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and (
  (process.name == "tail" and process.args in ("-c", "--bytes")) or
  (process.name == "cmp" and process.args == "-i") or
  (process.name in ("hexdump", "xxd") and process.args == "-s") or
  (process.name == "dd" and process.args : ("skip*", "seek*"))
) and not (
  process.parent.args like ("/opt/error_monitor/error_monitor.sh", "printf*", "/sbin/dracut") or
  process.parent.name in ("acme.sh", "dracut", "leapp") or
  process.parent.executable like (
    "/bin/cagefs_enter", "/opt/nessus_agent/sbin/nessus-service", "/usr/libexec/platform-python*",
    "/usr/libexec/vdsm/vdsmd", "/usr/local/bin/docker-entrypoint.sh", "/usr/lib/module-init-tools/lsinitrd-quick",
    "/usr/bin/unmkinitramfs", "/usr/bin/lsinitramfs", "/opt/msp-agent/msp-agent-core.run",
    "/usr/local/cloudamize/bin/register.sh", "/usr/local/hestia/bin/v-log-action", "/usr/local/emps/bin/php"
  ) or
  process.parent.command_line like "sh*acme.sh*" or
  process.args like ("/var/tmp/dracut*", "/opt/bitdefender-security-tools/var/log/script_update.log") or
  ?process.working_directory like (
    "/usr/local/nutanix/ngt/python/bin", "/var/lib/waagent/*", "/opt/Tychon/Endpoint/bin",
    "/usr/local/cloudamize/bin", "/opt/sentinelone/bin"
  ) or
  process.command_line in ("tail -c 1", "tail -c 2") or
  (process.command_line == "dd ibs=18850 skip=1 count=1" and process.parent.args == "/opt/msp-agent/msp-agent-core.run")
)
```



### Potential Microsoft Office Sandbox Evasion

Branch count: 2  
Document count: 2  
Index: geneve-ut-1005

```python
file where host.os.type == "macos" and event.action in ("modification", "rename") and file.name like~ "~$*.zip"
```



### Potential Modification of Accessibility Binaries

Branch count: 16  
Document count: 16  
Index: geneve-ut-1006

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : ("Utilman.exe", "winlogon.exe") and user.name == "SYSTEM" and
 process.pe.original_file_name : "?*" and
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
    "atbroker.exe",
    "ATBroker.exe",
    "ScreenMagnifier.exe",
    "SR.exe",
    "Narrator.exe",
    "magnify.exe",
    "MAGNIFY.EXE"
    )
```



### Potential NetNTLMv1 Downgrade Attack

Branch count: 6  
Document count: 6  
Index: geneve-ut-1008

```python
registry where host.os.type == "windows" and event.action != "deletion" and
 registry.value == "LmCompatibilityLevel" and registry.data.strings in ("2", "1", "0", "0x00000002", "0x00000001", "0x00000000")
```



### Potential OpenSSH Backdoor Logging Activity

Branch count: 70  
Document count: 70  
Index: geneve-ut-1014

```python
file where host.os.type == "linux" and event.type == "creation" and process.name in ("ssh", "sshd") and
  (
    (
      file.name : (".*", "~*", "*~") and not file.name : (
        ".cache", ".viminfo", ".bash_history", ".google_authenticator", ".jelenv", ".csvignore", ".rtreport", ".git*"
      )
    ) or
    file.extension : ("in", "out", "ini", "h", "gz", "so", "sock", "sync", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9") or
    file.path :
    (
      "/tmp/*",
      "/var/tmp/*",
      "/dev/shm/*",
      "/usr/share/*",
      "/usr/include/*",
      "/usr/local/include/*",
      "/usr/share/man/*",
      "/usr/local/share/*",
      "/usr/lib/*.so.*",
      "/usr/bin/ssd",
      "/var/run/sshd/sshd.pid",
      "/var/run/nscd/ns.pid",
      "/var/run/udev/ud.pid",
      "/var/run/udevd.pid"
    )
  )
```



### Potential Outgoing RDP Connection by Unusual Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-1015

```python
network where host.os.type == "windows" and
  event.action == "connection_attempted" and destination.port == 3389 and
  destination.ip != "::1" and destination.ip != "127.0.0.1" and
  not (
    process.executable : (
      "?:\\Windows\\System32\\mstsc.exe",
      "?:\\Program Files (x86)\\mRemoteNG\\mRemoteNG.exe",
      "?:\\Program Files (x86)\\PRTG Network Monitor\\PRTG Probe.exe",
      "?:\\Program Files\\Azure Advanced Threat Protection Sensor\\*\\Microsoft.Tri.Sensor.exe",
      "?:\\Program Files (x86)\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.exe",
      "?:\\Program Files\\SentinelOne\\Sentinel Agent*\\Ranger\\SentinelRanger.exe",
      "?:\\Program Files\\Devolutions\\Remote Desktop Manager\\RemoteDesktopManager.exe",
      "?:\\Program Files (x86)\\Devolutions\\Remote Desktop Manager\\RemoteDesktopManager.exe"
    ) and process.code_signature.trusted == true
  )
```



### Potential Persistence via Atom Init Script Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-1018

```python
file where host.os.type == "macos" and event.action == "modification" and
 file.path like "/Users/*/.atom/init.coffee" and 
 not process.name like ("Atom", "xpcproxy") and 
 not user.name == "root"
```



### Potential Persistence via File Modification

Branch count: 138  
Document count: 138  
Index: geneve-ut-1019

```python
file where host.os.type == "linux" and event.dataset == "fim.event" and event.action == "updated" and
file.path : (
  // cron, anacron & at
  "/etc/cron.d/*", "/etc/cron.daily/*", "/etc/cron.hourly/*", "/etc/cron.monthly/*",
  "/etc/cron.weekly/*", "/etc/crontab", "/var/spool/cron/crontabs/*", "/etc/cron.allow",
  "/etc/cron.deny",  "/var/spool/anacron/*", "/var/spool/cron/atjobs/*",

  // systemd services & timers
  "/etc/systemd/system/*", "/usr/local/lib/systemd/system/*", "/lib/systemd/system/*",
  "/usr/lib/systemd/system/*", "/home/*/.config/systemd/user/*", "/home/*/.local/share/systemd/user/*",
  "/root/.config/systemd/user/*", "/root/.local/share/systemd/user/*",

  // LD_PRELOAD
  "/etc/ld.so.preload", "/etc/ld.so.conf.d/*", "/etc/ld.so.conf",

  // Dynamic linker
  "/lib/ld-linux*.so*", "/lib64/ld-linux*.so*", "/usr/lib/ld-linux*.so*", "/usr/lib64/ld-linux*.so*",

  // message-of-the-day (MOTD)
  "/etc/update-motd.d/*",

  // SSH
  "/home/*/.ssh/*", "/root/.ssh/*", "/etc/ssh/*",

  // system-wide shell configurations
  "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/zsh/*", "/etc/csh.cshrc",
  "/etc/csh.login", "/etc/fish/config.fish", "/etc/ksh.kshrc",

  // root and user shell configurations
  "/home/*/.profile", "/home/*/.bashrc", "/home/*/.bash_login", "/home/*/.bash_logout",
  "/root/.profile", "/root/.bashrc", "/root/.bash_login", "/root/.bash_logout",
  "/home/*/.zprofile", "/home/*/.zshrc", "/root/.zprofile", "/root/.zshrc",
  "/home/*/.cshrc", "/home/*/.login", "/home/*/.logout", "/root/.cshrc", "/root/.login", "/root/.logout",
  "/home/*/.config/fish/config.fish", "/root/.config/fish/config.fish",
  "/home/*/.kshrc", "/root/.kshrc",

  // Alias files
  "/home/*/.bash_aliases", "/root/.bash_aliases", "/home/*/.zsh_aliases", "/root/.zsh_aliases",
  "/home/*/.aws/cli/alias", "/root/.aws/cli/alias", 

  // runtime control
  "/etc/rc.common", "/etc/rc.local",

  // System V init/Upstart
  "/etc/init.d/*", "/etc/init/*",

  // passwd/sudoers/shadow
  "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/*",

  // Systemd udevd
  "/lib/udev/*", "/etc/udev/rules.d/*", "/usr/lib/udev/rules.d/*", "/run/udev/rules.d/*", "/usr/local/lib/udev/rules.d/*",

  // XDG/KDE autostart entries
  "/home/*/.config/autostart/*", "/root/.config/autostart/*", "/etc/xdg/autostart/*", "/usr/share/autostart/*",
  "/home/*/.kde/Autostart/*", "/root/.kde/Autostart/*",
  "/home/*/.kde4/Autostart/*", "/root/.kde4/Autostart/*",
  "/home/*/.kde/share/autostart/*", "/root/.kde/share/autostart/*",
  "/home/*/.kde4/share/autostart/*", "/root/.kde4/share/autostart/*",
  "/home/*/.local/share/autostart/*", "/root/.local/share/autostart/*",
  "/home/*/.config/autostart-scripts/*", "/root/.config/autostart-scripts/*",

  // LKM configuration files
  "/etc/modules", "/etc/modprobe.d/*", "/usr/lib/modprobe.d/*", "/etc/modules-load.d/*",
  "/run/modules-load.d/*", "/usr/local/lib/modules-load.d/*", "/usr/lib/modules-load.d/*",

  // PAM modules & configuration files
  "/lib/security/*", "/lib64/security/*", "/usr/lib/security/*", "/usr/lib64/security/*",
  "/lib/x86_64-linux-gnu/security/*", "/usr/lib/x86_64-linux-gnu/security/*",
  "/etc/pam.d/*", "/etc/security/pam_*", "/etc/pam.conf",

  // Polkit Rule files
  "/etc/polkit-1/rules.d/*", "/usr/share/polkit-1/rules.d/*",

  // Polkit pkla files
  "/etc/polkit-1/localauthority/*", "/var/lib/polkit-1/localauthority/*",

  // Polkit Action files
  "/usr/share/polkit-1/actions/*",

  // Polkit Legacy paths
  "/lib/polkit-1/rules.d/*", "/lib64/polkit-1/rules.d/*", "/var/lib/polkit-1/rules.d/*",

  // NetworkManager
  "/etc/NetworkManager/dispatcher.d/*",

  // D-bus Service files
  "/usr/share/dbus-1/system-services/*", "/etc/dbus-1/system.d/*",
  "/lib/dbus-1/system-services/*", "/run/dbus/system.d/*",
  "/home/*/.local/share/dbus-1/services/*", "/home/*/.dbus/session-bus/*",
  "/usr/share/dbus-1/services/*", "/etc/dbus-1/session.d/*",

  // GRUB
  "/etc/default/grub.d/*", "/etc/default/grub", "/etc/grub.d/*", "/boot/grub2/grub.cfg",
  "/boot/grub/grub.cfg", "/boot/efi/EFI/*/grub.cfg", "/etc/sysconfig/grub",

  // Dracut
  "/lib/dracut/modules.d/*", "/usr/lib/dracut/modules.d/*",

  // Misc.
  "/etc/shells"

) and not (
  file.path : (
    "/var/spool/cron/crontabs/tmp.*", "/run/udev/rules.d/*rules.*", "/home/*/.ssh/known_hosts.*", "/root/.ssh/known_hosts.*"
  ) or
  file.extension in ("dpkg-new", "dpkg-remove", "SEQ")
)
```



### Potential Persistence via Login Hook

Branch count: 1  
Document count: 1  
Index: geneve-ut-1020

```python
event.category:file and host.os.type:macos and not event.type:"deletion" and
 file.name:"com.apple.loginwindow.plist" and
 not process.name: (systemmigrationd or DesktopServicesHelper or diskmanagementd or rsync or launchd or cfprefsd or xpcproxy or ManagedClient or MCXCompositor or backupd or "iMazing Profile Editor" or storagekitd or CloneKitService)
```



### Potential Persistence via Mandatory User Profile

Branch count: 2  
Document count: 2  
Index: geneve-ut-1021

```python
file where host.os.type == "windows" and
 event.type in ("creation", "change") and user.id != "S-1-5-18" and
 file.name : "NTUSER.MAN" and file.path : "?:\\Users\\*.MAN"
```



### Potential Persistence via Periodic Tasks

Branch count: 3  
Document count: 3  
Index: geneve-ut-1022

```python
file where host.os.type == "macos" and event.action == "modification" and
 file.path like ("/private/etc/periodic/*", "/private/etc/defaults/periodic.conf", "/private/etc/periodic.conf")
```



### Potential Persistence via Time Provider Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-1023

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.path: "*\\SYSTEM\\*ControlSet*\\Services\\W32Time\\TimeProviders\\*" and
  registry.data.strings:"*.dll" and
  not
  (
    process.executable : ("?:\\Windows\\System32\\msiexec.exe", "\\Device\\HarddiskVolume*\\Windows\\System32\\msiexec.exe") and
    registry.data.strings : "?:\\Program Files\\VMware\\VMware Tools\\vmwTimeProvider\\vmwTimeProvider.dll"
  ) and
  not registry.data.strings : "C:\\Windows\\SYSTEM32\\w32time.DLL"
```



### Potential Port Monitor or Print Processor Registration Abuse

Branch count: 4  
Document count: 4  
Index: geneve-ut-1024

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
      "HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Monitors\\*",
      "HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Environments\\Windows*\\Print Processors\\*",
      "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Print\\Monitors\\*",
      "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Print\\Environments\\Windows*\\Print Processors\\*"
  ) and registry.data.strings : "*.dll" and
  /* exclude SYSTEM SID - look for changes by non-SYSTEM user */
  not user.id : "S-1-5-18"
```



### Potential PowerShell HackTool Script by Author

Branch count: 45  
Document count: 45  
Index: geneve-ut-1026

```python
host.os.type:windows and event.category:process and
  powershell.file.script_block_text : (
      "mattifestation" or "JosephBialek" or
      "harmj0y" or "ukstufus" or
      "SecureThisShit" or "Matthew Graeber" or
      "secabstraction" or "mgeeky" or
      "oddvarmoe" or "am0nsec" or
      "obscuresec" or "sixdub" or
      "darkoperator" or "funoverip" or
      "rvrsh3ll" or "kevin_robertson" or
      "dafthack" or "r4wd3r" or
      "danielhbohannon" or "OneLogicalMyth" or
      "cobbr_io" or "xorrior" or
      "PetrMedonos" or "citronneur" or
      "eladshamir" or "RastaMouse" or
      "enigma0x3" or "FuzzySec" or
      "424f424f" or "jaredhaight" or
      "fullmetalcache" or "Hubbl3" or
      "curi0usJack" or "Cx01N" or
      "itm4n" or "nurfed1" or
      "cfalta" or "Scott Sutherland" or
      "_nullbind" or "_tmenochet" or
      "jaredcatkinson" or "ChrisTruncer" or
      "monoxgas" or "TheRealWover" or
      "splinter_code"
  ) and
  not powershell.file.script_block_text : ("Get-UEFIDatabaseSigner" or "Posh-SSH")
```



### Potential PowerShell HackTool Script by Function Names

Branch count: 702  
Document count: 702  
Index: geneve-ut-1027

```python
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "Add-DomainGroupMember" or "Add-DomainObjectAcl" or
    "Add-RemoteConnection" or "Add-ServiceDacl" or
    "Add-Win32Type" or "Convert-ADName" or
    "Convert-LDAPProperty" or "ConvertFrom-LDAPLogonHours" or
    "ConvertFrom-UACValue" or "Copy-ArrayOfMemAddresses" or
    "Create-NamedPipe" or "Create-ProcessWithToken" or
    "Create-RemoteThread" or "Create-SuspendedWinLogon" or
    "Create-WinLogonProcess" or "Emit-CallThreadStub" or
    "Enable-SeAssignPrimaryTokenPrivilege" or "Enable-SeDebugPrivilege" or
    "Enum-AllTokens" or "Export-PowerViewCSV" or
    "Find-AVSignature" or "Find-AppLockerLog" or
    "Find-DomainLocalGroupMember" or "Find-DomainObjectPropertyOutlier" or
    "Find-DomainProcess" or "Find-DomainShare" or
    "Find-DomainUserEvent" or "Find-DomainUserLocation" or
    "Find-InterestingDomainAcl" or "Find-InterestingDomainShareFile" or
    "Find-InterestingFile" or "Find-LocalAdminAccess" or
    "Find-PSScriptsInPSAppLog" or "Find-PathDLLHijack" or
    "Find-ProcessDLLHijack" or "Find-RDPClientConnection" or
    "Get-AllAttributesForClass" or "Get-CachedGPPPassword" or
    "Get-DecryptedCpassword" or "Get-DecryptedSitelistPassword" or
    "Get-DelegateType" or "New-RelayEnumObject" or
    "Get-DomainDFSShare" or "Get-DomainDFSShareV1" or
    "Get-DomainDFSShareV2" or "Get-DomainDNSRecord" or
    "Get-DomainDNSZone" or "Get-DomainFileServer" or
    "Get-DomainForeignGroupMember" or "Get-DomainForeignUser" or
    "Get-DomainGPO" or "Get-DomainGPOComputerLocalGroupMapping" or
    "Get-DomainGPOLocalGroup" or "Get-DomainGPOUserLocalGroupMapping" or
    "Get-DomainGUIDMap" or "Get-DomainGroup" or
    "Get-DomainGroupMember" or "Get-DomainGroupMemberDeleted" or
    "Get-DomainManagedSecurityGroup" or "Get-DomainOU" or
    "Get-DomainObject" or "Get-DomainObjectAcl" or
    "Get-DomainObjectAttributeHistory" or "Get-DomainObjectLinkedAttributeHistory" or
    "Get-DomainPolicyData" or "Get-DomainSID" or
    "Get-DomainSPNTicket" or "Get-DomainSearcher" or
    "Get-DomainSite" or "Get-DomainSubnet" or
    "Get-DomainTrust" or "Get-DomainTrustMapping" or
    "Get-DomainUser" or "Get-DomainUserEvent" or
    "Get-Forest" or "Get-ForestDomain" or
    "Get-ForestGlobalCatalog" or "Get-ForestSchemaClass" or
    "Get-ForestTrust" or "Get-GPODelegation" or
    "Get-GPPAutologon" or "Get-GPPInnerField" or
    "Get-GPPInnerFields" or "Get-GPPPassword" or
    "Get-GptTmpl" or "Get-GroupsXML" or
    "Get-HttpStatus" or "Get-ImageNtHeaders" or
    "Get-Keystrokes" or "New-SOASerialNumberArray" or
    "Get-MemoryProcAddress" or "Get-MicrophoneAudio" or
    "Get-ModifiablePath" or "Get-ModifiableRegistryAutoRun" or
    "Get-ModifiableScheduledTaskFile" or "Get-ModifiableService" or
    "Get-ModifiableServiceFile" or "Get-Name" or
    "Get-NetComputerSiteName" or "Get-NetLocalGroup" or
    "Get-NetLocalGroupMember" or "Get-NetLoggedon" or
    "Get-NetRDPSession" or "Get-NetSession" or
    "Get-NetShare" or "Get-PEArchitecture" or
    "Get-PEBasicInfo" or "Get-PEDetailedInfo" or
    "Get-PathAcl" or "Get-PrimaryToken" or
    "Get-ProcAddress" or "Get-ProcessTokenGroup" or
    "Get-ProcessTokenPrivilege" or "Get-ProcessTokenType" or
    "Get-RegLoggedOn" or "Get-RegistryAlwaysInstallElevated" or
    "Get-RegistryAutoLogon" or "Get-RemoteProcAddress" or
    "Get-Screenshot" or "Get-ServiceDetail" or
    "Get-SiteListPassword" or "Get-SitelistField" or
    "Get-System" or "Get-SystemNamedPipe" or
    "Get-SystemToken" or "Get-ThreadToken" or
    "Get-TimedScreenshot" or "Get-TokenInformation" or
    "Get-TopPort" or "Get-UnattendedInstallFile" or
    "Get-UniqueTokens" or "Get-UnquotedService" or
    "Get-VaultCredential" or "Get-VaultElementValue" or
    "Get-VirtualProtectValue" or "Get-VolumeShadowCopy" or
    "Get-WMIProcess" or "Get-WMIRegCachedRDPConnection" or
    "Get-WMIRegLastLoggedOn" or "Get-WMIRegMountedDrive" or
    "Get-WMIRegProxy" or "Get-WebConfig" or
    "Get-Win32Constants" or "Get-Win32Functions" or
    "Get-Win32Types" or "Import-DllImports" or
    "Import-DllInRemoteProcess" or "Inject-LocalShellcode" or
    "Inject-RemoteShellcode" or "Install-ServiceBinary" or
    "Invoke-CompareAttributesForClass" or "Invoke-CreateRemoteThread" or
    "Invoke-CredentialInjection" or "Invoke-DllInjection" or
    "Invoke-EventVwrBypass" or "Invoke-ImpersonateUser" or
    "Invoke-Kerberoast" or "Invoke-MemoryFreeLibrary" or
    "Invoke-MemoryLoadLibrary" or
    "Invoke-Mimikatz" or "Invoke-NinjaCopy" or
    "Invoke-PatchDll" or "Invoke-Portscan" or
    "Invoke-PrivescAudit" or "Invoke-ReflectivePEInjection" or
    "Invoke-ReverseDnsLookup" or "Invoke-RevertToSelf" or
    "Invoke-ServiceAbuse" or "Invoke-Shellcode" or
    "Invoke-TokenManipulation" or "Invoke-UserImpersonation" or
    "Invoke-WmiCommand" or "Mount-VolumeShadowCopy" or
    "New-ADObjectAccessControlEntry" or "New-DomainGroup" or
    "New-DomainUser" or "New-DynamicParameter" or
    "New-InMemoryModule" or
    "New-ThreadedFunction" or "New-VolumeShadowCopy" or
    "Out-CompressedDll" or "Out-EncodedCommand" or
    "Out-EncryptedScript" or "Out-Minidump" or
    "PortScan-Alive" or "Portscan-Port" or
    "Remove-DomainGroupMember" or "Remove-DomainObjectAcl" or
    "Remove-RemoteConnection" or "Remove-VolumeShadowCopy" or
    "Restore-ServiceBinary" or "Set-DesktopACLToAllowEveryone" or
    "Set-DesktopACLs" or "Set-DomainObject" or
    "Set-DomainObjectOwner" or "Set-DomainUserPassword" or
    "Set-ServiceBinaryPath" or "Sub-SignedIntAsUnsigned" or
    "Test-AdminAccess" or "Test-MemoryRangeValid" or
    "Test-ServiceDaclPermission" or "Update-ExeFunctions" or
    "Update-MemoryAddresses" or "Update-MemoryProtectionFlags" or
    "Write-BytesToMemory" or "Write-HijackDll" or
    "Write-PortscanOut" or "Write-ServiceBinary" or
    "Write-UserAddMSI" or "Invoke-Privesc" or
    "func_get_proc_address" or "Invoke-BloodHound" or
    "Invoke-HostEnum" or "Get-BrowserInformation" or
    "Get-DomainAccountPolicy" or "Get-DomainAdmins" or
    "Get-AVProcesses" or "Get-AVInfo" or
    "Get-RecycleBin" or "Invoke-BruteForce" or
    "Get-PassHints" or "Invoke-SessionGopher" or
    "Get-LSASecret" or "Get-PassHashes" or
    "Invoke-WdigestDowngrade" or "Get-ChromeDump" or
    "Invoke-DomainPasswordSpray" or "Get-FoxDump" or
    "New-HoneyHash" or "Invoke-DCSync" or
    "Invoke-PowerDump" or "Invoke-SSIDExfil" or
    "Invoke-PowerShellTCP" or "Add-Exfiltration" or
    "Do-Exfiltration" or "Invoke-DropboxUpload" or
    "Invoke-ExfilDataToGitHub" or "Invoke-EgressCheck" or
    "Invoke-PostExfil" or "Create-MultipleSessions" or
    "Invoke-NetworkRelay" or "New-GPOImmediateTask" or
    "Invoke-WMIDebugger" or "Invoke-SQLOSCMD" or
    "Invoke-SMBExec" or "Invoke-PSRemoting" or
    "Invoke-ExecuteMSBuild" or "Invoke-DCOM" or
    "Invoke-InveighRelay" or "Invoke-PsExec" or
    "Find-ActiveUsersWMI" or
    "Get-SystemDrivesWMI" or "Get-ActiveNICSWMI" or
    "Remove-Persistence" or "DNS_TXT_Pwnage" or
    "Execute-OnTime" or "HTTP-Backdoor" or
    "Add-ConstrainedDelegationBackdoor" or "Add-RegBackdoor" or
    "Add-ScrnSaveBackdoor" or "Gupt-Backdoor" or
    "Invoke-ADSBackdoor" or "Add-Persistence" or
    "Invoke-ResolverBackdoor" or "Invoke-EventLogBackdoor" or
    "Invoke-DeadUserBackdoor" or "Invoke-DisableMachineAcctChange" or
    "Invoke-AccessBinary" or "Add-NetUser" or
    "Invoke-Schtasks" or "Invoke-JSRatRegsvr" or
    "Invoke-JSRatRundll" or "Invoke-PoshRatHttps" or
    "Invoke-PsGcatAgent" or "Remove-PoshRat" or
    "Install-SSP" or "Invoke-BackdoorLNK" or
    "PowerBreach" or "InstallEXE-Persistence" or
    "RemoveEXE-Persistence" or "Install-ServiceLevel-Persistence" or
    "Remove-ServiceLevel-Persistence" or "Invoke-Prompt" or
    "Invoke-PacketCapture" or "Start-WebcamRecorder" or
    "Get-USBKeyStrokes" or "Invoke-KeeThief" or
    "Get-Keystrokes" or "Invoke-NetRipper" or
    "Get-EmailItems" or "Invoke-MailSearch" or
    "Invoke-SearchGAL" or "Get-WebCredentials" or
    "Start-CaptureServer" or "Invoke-PowerShellIcmp" or
    "Invoke-PowerShellTcpOneLine" or "Invoke-PowerShellTcpOneLineBind" or
    "Invoke-PowerShellUdp" or "Invoke-PowerShellUdpOneLine" or
    "Run-EXEonRemote" or "Download-Execute-PS" or
    "Out-RundllCommand" or "Set-RemoteWMI" or
    "Set-DCShadowPermissions" or "Invoke-PowerShellWMI" or
    "Invoke-Vnc" or "Invoke-LockWorkStation" or
    "Invoke-EternalBlue" or "Invoke-ShellcodeMSIL" or
    "Invoke-MetasploitPayload" or "Invoke-DowngradeAccount" or
    "Invoke-RunAs" or "ExetoText" or
    "Disable-SecuritySettings" or "Set-MacAttribute" or
    "Invoke-MS16032" or "Invoke-BypassUACTokenManipulation" or
    "Invoke-SDCLTBypass" or "Invoke-FodHelperBypass" or
    "Invoke-EventVwrBypass" or "Invoke-EnvBypass" or
    "Get-ServiceUnquoted" or "Get-ServiceFilePermission" or
    "Get-ServicePermission" or
    "Enable-DuplicateToken" or "Invoke-PsUaCme" or
    "Invoke-Tater" or "Invoke-WScriptBypassUAC" or
    "Invoke-AllChecks" or "Find-TrustedDocuments" or
    "Invoke-Interceptor" or "Invoke-PoshRatHttp" or
    "Invoke-ExecCommandWMI" or "Invoke-KillProcessWMI" or
    "Invoke-CreateShareandExecute" or "Invoke-RemoteScriptWithOutput" or
    "Invoke-SchedJobManipulation" or "Invoke-ServiceManipulation" or
    "Invoke-PowerOptionsWMI" or "Invoke-DirectoryListing" or
    "Invoke-FileTransferOverWMI" or "Invoke-WMImplant" or
    "Invoke-WMIObfuscatedPSCommand" or "Invoke-WMIDuplicateClass" or
    "Invoke-WMIUpload" or "Invoke-WMIRemoteExtract" or "Invoke-winPEAS" or
    "Invoke-AzureHound" or "Invoke-SharpHound" or "Invoke-DownloadCradle" or
    "Invoke-AppPathBypass"
  ) and
  not powershell.file.script_block_text : (
    "sentinelbreakpoints" and "Set-PSBreakpoint"
  ) and
  not user.id : ("S-1-5-18" or "S-1-5-19")
```



### Potential Privacy Control Bypass via Localhost Secure Copy

Branch count: 4  
Document count: 4  
Index: geneve-ut-1040

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.name == "scp" and
 process.args like~ "StrictHostKeyChecking=no" and
 process.command_line like~ ("*scp *localhost:/*", "*scp *127.0.0.?:/*") and
 not process.command_line like~ "*vagrant@*127.0.0.1*"
```



### Potential Privilege Escalation through Writable Docker Socket

Branch count: 8  
Document count: 8  
Index: geneve-ut-1042

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "ProcessRollup2") and
(
  (process.name == "docker" and process.args : "run" and process.args : "-it"  and
   process.args : ("unix://*/docker.sock", "unix://*/dockershim.sock")) or
  (process.name == "socat" and process.args : ("UNIX-CONNECT:*/docker.sock", "UNIX-CONNECT:*/dockershim.sock"))
) and not user.Ext.real.id : "0" and not group.Ext.real.id : "0"
```



### Potential Privilege Escalation via CVE-2023-4911

Branch count: 1  
Document count: 5  
Index: geneve-ut-1043

```python
sequence by host.id, process.parent.entity_id, process.executable with maxspan=5s
 [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
  process.env_vars : "*GLIBC_TUNABLES=glibc.*=glibc.*=*"] with runs=5
```



### Potential Privilege Escalation via Container Misconfiguration

Branch count: 1  
Document count: 1  
Index: geneve-ut-1044

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  (process.name == "runc" and process.args == "run") or
  (process.name == "ctr" and process.args == "run" and process.args in ("--privileged", "--mount"))
) and not user.Ext.real.id == "0" and not group.Ext.real.id == "0" and
process.interactive == true and process.parent.interactive == true
```



### Potential Privilege Escalation via OverlayFS

Branch count: 3  
Document count: 6  
Index: geneve-ut-1048

```python
sequence by process.parent.entity_id, host.id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
    process.name == "unshare" and process.args : ("-r", "-rm", "m") and process.args : "*cap_setuid*"  and user.id != "0"]
  [process where host.os.type == "linux" and event.action == "uid_change" and event.type == "change" and
    user.id == "0"]
```



### Potential Privilege Escalation via PKEXEC

Branch count: 1  
Document count: 1  
Index: geneve-ut-1049

```python
file where host.os.type == "linux" and file.path : "/*GCONV_PATH*"
```



### Potential Privilege Escalation via Python cap_setuid

Branch count: 4  
Document count: 8  
Index: geneve-ut-1050

```python
sequence by host.id, process.entity_id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.args : "import os;os.set?id(0);os.system(*)" and process.args : "*python*" and user.id != "0"]
  [process where host.os.type == "linux" and event.action in ("uid_change", "gid_change") and event.type == "change" and
   (user.id == "0" or group.id == "0")]
```



### Potential Privilege Escalation via Recently Compiled Executable

Branch count: 6  
Document count: 24  
Index: geneve-ut-1051

```python
sequence by host.id with maxspan=1m
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name in ("gcc", "g++", "cc") and user.id != "0"] by process.args
  [file where host.os.type == "linux" and event.action == "creation" and event.type == "creation" and
   process.name == "ld" and user.id != "0"] by file.name
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   user.id != "0"] by process.name
  [process where host.os.type == "linux" and event.action in ("uid_change", "guid_change") and event.type == "change" and
   user.id == "0"] by process.name
```



### Potential Privilege Escalation via SUID/SGID Proxy Execution

Branch count: 64  
Document count: 64  
Index: geneve-ut-1052

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  (process.user.id == "0" and process.real_user.id != "0") or
  (process.group.id == "0" and process.real_group.id != "0")
) and process.args in (
  "/bin/su", "/usr/bin/su",
  "/usr/bin/sudo",
  "/bin/mount", "/usr/bin/mount",
  "/bin/umount", "/usr/bin/umount",
  "/usr/bin/fusermount3",
  "/bin/passwd", "/usr/bin/passwd",
  "/bin/chfn", "/usr/bin/chfn",
  "/bin/chsh", "/usr/bin/chsh",
  "/bin/gpasswd", "/usr/bin/gpasswd",
  "/bin/newgrp", "/usr/bin/newgrp",
  "/sbin/unix_chkpwd", "/usr/sbin/unix_chkpwd",
  "/usr/bin/newuidmap", "/usr/bin/newgidmap",
  "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/usr/libexec/dbus-daemon-launch-helper",
  "/usr/lib/openssh/ssh-keysign", "/usr/libexec/openssh/ssh-keysign",
  "/usr/bin/pkexec", "/usr/libexec/pkexec", "/usr/lib/polkit-1/pkexec",
  "/usr/lib/polkit-1/polkit-agent-helper-1", "/usr/libexec/polkit-agent-helper-1",
  "/usr/lib/snapd/snap-confine"
) and process.parent.args_count == 1 and
not process.parent.executable in (
  "/usr/libexec/oracle-cloud-agent/plugins/unifiedmonitoring/unifiedmonitoring", "/usr/libexec/oracle-cloud-agent/agent",
  "/usr/lib/x86_64-linux-gnu/libexec/polkit-kde-authentication-agent-1", "/usr/libexec/xfce-polkit", "/usr/bin/dolphin"
)
```



### Potential Privilege Escalation via Sudoers File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-1054

```python
event.category:process and event.type:start and process.args:(echo and *NOPASSWD*ALL*)
```



### Potential Privileged Escalation via SamAccountName Spoofing

Branch count: 1  
Document count: 1  
Index: geneve-ut-1055

```python
iam where host.os.type == "windows" and event.action == "renamed-user-account" and
  /* machine account name renamed to user like account name */
  winlog.event_data.OldTargetUserName : "*$" and not winlog.event_data.NewTargetUserName : "*$"
```



### Potential Process Injection from Malicious Document

Branch count: 18  
Document count: 18  
Index: geneve-ut-1056

```python
process where host.os.type == "windows" and event.action == "start" and
  process.parent.name : ("excel.exe", "powerpnt.exe", "winword.exe") and
  process.args_count == 1 and
  process.executable : (
    "?:\\Windows\\SysWOW64\\*.exe", "?:\\Windows\\system32\\*.exe"
  ) and
  not (process.executable : "?:\\Windows\\System32\\spool\\drivers\\x64\\*" and
       process.code_signature.trusted == true and not process.code_signature.subject_name : "Microsoft *") and
  not process.executable : (
    "?:\\Windows\\Sys*\\Taskmgr.exe",
    "?:\\Windows\\Sys*\\ctfmon.exe",
    "?:\\Windows\\System32\\notepad.exe")
```



### Potential Process Name Stomping with Prctl

Branch count: 13  
Document count: 13  
Index: geneve-ut-1058

```python
process where host.os.type == "linux" and auditd.data.syscall == "prctl" and auditd.data.a0 == "f" and
process.executable like (
  "/boot/*", "/dev/shm/*", "/etc/cron.*/*", "/etc/init.d/*", "/var/run/*", "/etc/update-motd.d/*",
  "/tmp/*", "/var/log/*", "/var/tmp/*", "/home/*", "/run/shm/*", "/run/*", "./*"
) and
not process.executable like ("/home/*/.vscode-server/*", "/tmp/VeeamAgent*", "/home/*/.xmonad/xmonad*linux*")
```



### Potential Protocol Tunneling via Chisel Client

Branch count: 27  
Document count: 54  
Index: geneve-ut-1059

```python
sequence by host.id, process.entity_id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and 
   process.args == "client" and process.args : ("R*", "*:*", "*socks*") and process.args_count >= 4 and 
   process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
   not process.name in ("velociraptor", "nbemmcmd", "redis-cli", "ipa")]
  [network where host.os.type == "linux" and event.action == "connection_attempted" and event.type == "start" and 
   destination.ip != null and destination.ip != "127.0.0.1" and destination.ip != "::1" and 
   not process.name : (
     "python*", "php*", "perl", "ruby", "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk", "java", "telnet",
     "ftp", "socat", "curl", "wget", "dpkg", "docker", "dockerd", "yum", "apt", "rpm", "dnf", "ssh", "sshd", "kubectl*",
     "clickhouse"
   )]
```



### Potential Protocol Tunneling via EarthWorm

Branch count: 6  
Document count: 6  
Index: geneve-ut-1060

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "start", "exec_event", "ProcessRollup2", "executed", "exec_event", "process_started") and
process.args : "-s" and process.args : "-d" and process.args : "rssocks"
```



### Potential REMCOS Trojan Execution

Branch count: 14  
Document count: 14  
Index: geneve-ut-1061

```python
any where host.os.type == "windows" and
(
 (event.category == "file" and event.type == "deletion" and file.path like "C:\\Users\\*\\AppData\\Local\\Temp\\TH????.tmp") or

 (event.category == "file" and file.path : "?:\\Users\\*\\AppData\\Roaming\\remcos\\logs.dat") or

 (event.category == "registry" and
  registry.value : ("Remcos", "Rmc-??????", "licence") and
  registry.path : (
      "*\\Windows\\CurrentVersion\\Run\\Remcos",
      "*\\Windows\\CurrentVersion\\Run\\Rmc-??????",
      "*\\SOFTWARE\\Remcos-*\\licence",
      "*\\Software\\Rmc-??????\\licence"
  )
 )
)
```



### Potential Remote Credential Access via Registry

Branch count: 4  
Document count: 4  
Index: geneve-ut-1064

```python
file where host.os.type == "windows" and
  event.action == "creation" and process.name : "svchost.exe" and
  file.Ext.header_bytes : "72656766*" and user.id : ("S-1-5-21-*", "S-1-12-1-*") and file.size >= 30000 and
  file.path : ("?:\\Windows\\system32\\*.tmp", "?:\\WINDOWS\\Temp\\*.tmp")
```



### Potential Remote Desktop Shadowing Activity

Branch count: 11  
Document count: 11  
Index: geneve-ut-1065

```python
/* Identifies the modification of RDP Shadow registry or
  the execution of processes indicative of active shadow RDP session */

any where host.os.type == "windows" and
(
  (event.category == "registry" and event.type == "change" and
    registry.value : "Shadow" and
    registry.path : (
      "*\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\Shadow"
    ) and
    registry.data.strings : ("1", "0x00000001", "2", "0x00000002", "3", "0x00000003", "4", "0x00000004")

  ) or
  (event.category == "process" and event.type == "start" and
     (process.name : ("RdpSaUacHelper.exe", "RdpSaProxy.exe") and process.parent.name : "svchost.exe") or
     (?process.pe.original_file_name : "mstsc.exe" and process.args : "/shadow:*")
  )
)
```



### Potential Remote Desktop Tunneling Detected

Branch count: 5  
Document count: 5  
Index: geneve-ut-1066

```python
process where host.os.type == "windows" and event.type == "start" and
  /* RDP port and usual SSH tunneling related switches in command line */
  process.args : "*:3389" and
  process.args : ("-L", "-P", "-R", "-pw", "-ssh")
```



### Potential Remote File Execution via MSIEXEC

Branch count: 48  
Document count: 144  
Index: geneve-ut-1067

```python
sequence with maxspan=1m
 [process where host.os.type == "windows" and event.action == "start" and
    process.name : "msiexec.exe" and process.args : "/V"] by process.entity_id
 [network where host.os.type == "windows" and process.name : "msiexec.exe" and
    event.action == "connection_attempted"] by process.entity_id
 [process where host.os.type == "windows" and event.action == "start" and
  process.parent.name : "msiexec.exe" and user.id : ("S-1-5-21-*", "S-1-5-12-1-*") and
  not process.executable : ("?:\\Windows\\SysWOW64\\msiexec.exe",
                            "?:\\Windows\\System32\\msiexec.exe",
                            "?:\\Windows\\System32\\srtasks.exe",
                            "?:\\Windows\\SysWOW64\\srtasks.exe",
                            "?:\\Windows\\System32\\taskkill.exe",
                            "?:\\Windows\\Installer\\MSI*.tmp",
                            "?:\\Program Files\\*.exe",
                            "?:\\Program Files (x86)\\*.exe",
                            "?:\\Windows\\System32\\ie4uinit.exe",
                            "?:\\Windows\\SysWOW64\\ie4uinit.exe",
                            "?:\\Windows\\System32\\sc.exe",
                            "?:\\Windows\\system32\\Wbem\\mofcomp.exe",
                            "?:\\Windows\\twain_32\\fjscan32\\SOP\\crtdmprc.exe",
                            "?:\\Windows\\SysWOW64\\taskkill.exe",
                            "?:\\Windows\\SysWOW64\\schtasks.exe",
                            "?:\\Windows\\system32\\schtasks.exe",
                            "?:\\Windows\\System32\\sdbinst.exe") and
  not (process.code_signature.subject_name == "Citrix Systems, Inc." and process.code_signature.trusted == true) and
  not (process.name : ("regsvr32.exe", "powershell.exe", "rundll32.exe", "wscript.exe") and
       process.Ext.token.integrity_level_name == "high" and
       process.args : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*")) and
  not (process.executable : ("?:\\Program Files\\*.exe", "?:\\Program Files (x86)\\*.exe") and process.code_signature.trusted == true) and
  not (process.name : "rundll32.exe" and process.args : "printui.dll,PrintUIEntry")
  ] by process.parent.entity_id
```



### Potential Remote Install via MsiExec

Branch count: 100  
Document count: 100  
Index: geneve-ut-1068

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "msiexec.exe" and process.args : ("-i", "/i") and process.command_line : "*http*" and
  process.args : ("/qn", "-qn", "-q", "/q", "/quiet") and
  process.parent.name : ("sihost.exe", "explorer.exe", "cmd.exe", "wscript.exe", "mshta.exe", "powershell.exe", "wmiprvse.exe", "pcalua.exe", "forfiles.exe", "conhost.exe") and
  not process.command_line : ("*--set-server=*", "*UPGRADEADD=*" , "*--url=*",
                              "*USESERVERCONFIG=*", "*RCTENTERPRISESERVER=*", "*app.ninjarmm.com*", "*zoom.us/client*",
                              "*SUPPORTSERVERSTSURI=*", "*START_URL=*", "*AUTOCONFIG=*", "*awscli.amazonaws.com*")
```



### Potential RemoteMonologue Attack

Branch count: 64  
Document count: 64  
Index: geneve-ut-1069

```python
registry where host.os.type == "windows" and event.action != "deletion" and
  registry.value == "RunAs" and registry.data.strings : "Interactive User" and

  not 
  (
    (
      process.executable : (
        "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.*\\MsMpEng.exe",
        "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
      ) and
      registry.path : "*\\SOFTWARE\\Classes\\AppID\\{1111A26D-EF95-4A45-9F55-21E52ADF9887}\\RunAs"
    ) or
    (
      process.executable : (
        "C:\\Program Files\\TeamViewer\\TeamViewer.exe",
        "C:\\Program Files (x86)\\TeamViewer\\TeamViewer.exe"
      ) and
      registry.path : "*\\SOFTWARE\\Classes\\AppID\\{850A928D-5456-4865-BBE5-42635F1EBCA1}\\RunAs"
    ) or
    (
      process.executable : "C:\\Windows\\System32\\svchost.exe" and
      registry.path : "*\\S-1-*Classes\\AppID\\{D3E34B21-9D75-101A-8C3D-00AA001A1652}\\RunAs"
    ) or
    (
      process.executable : "C:\\Windows\\System32\\SecurityHealthService.exe" and
      registry.path : (
        "*\\SOFTWARE\\Classes\\AppID\\{1D278EEF-5C38-4F2A-8C7D-D5C13B662567}\\RunAs",
        "*\\SOFTWARE\\Classes\\AppID\\{7E55A26D-EF95-4A45-9F55-21E52ADF9878}\\RunAs"
      )
    ) or
    (
      process.executable : "C:\\Windows\\System32\\SecurityHealthService.exe" and
      registry.path : (
        "*\\SOFTWARE\\Classes\\AppID\\{1D278EEF-5C38-4F2A-8C7D-D5C13B662567}\\RunAs",
        "*\\SOFTWARE\\Classes\\AppID\\{7E55A26D-EF95-4A45-9F55-21E52ADF9878}\\RunAs"
      )
    ) or
    registry.path : (
      "HKLM\\SOFTWARE\\Microsoft\\Office\\ClickToRun\\VREGISTRY_*",
      "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Office\\ClickToRun\\VREGISTRY_*"
    ) or
    (process.executable : "C:\\windows\\System32\\msiexec.exe" and ?user.id : "S-1-5-18")
  )
```



### Potential Reverse Shell

Branch count: 864  
Document count: 1728  
Index: geneve-ut-1070

```python
sequence by host.id with maxspan=5s
  [network where event.type == "start" and host.os.type == "linux" and
     event.action in ("connection_attempted", "connection_accepted") and
     process.name : ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "socat") and destination.ip != null and
     not cidrmatch(destination.ip, "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1")] by process.entity_id
  [process where event.type == "start" and host.os.type == "linux" and event.action in ("exec", "fork") and
     process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and (
       (process.args : ("-i", "-l")) or (process.parent.name == "socat" and process.parent.args : "*exec*")
   )] by process.parent.entity_id
```



### Potential Reverse Shell Activity via Terminal

Branch count: 80  
Document count: 80  
Index: geneve-ut-1071

```python
process where event.type in ("start", "process_started") and
  process.name in ("sh", "bash", "zsh", "dash", "zmodload") and
  process.args : ("*/dev/tcp/*", "*/dev/udp/*", "*zsh/net/tcp*", "*zsh/net/udp*") and

  /* noisy FPs */
  not (process.parent.name : "timeout" and process.executable : "/var/lib/docker/overlay*") and
  not process.command_line : (
    "*/dev/tcp/sirh_db/*", "*/dev/tcp/remoteiot.com/*", "*dev/tcp/elk.stag.one/*", "*dev/tcp/kafka/*",
    "*/dev/tcp/$0/$1*", "*/dev/tcp/127.*", "*/dev/udp/127.*", "*/dev/tcp/localhost/*", "*/dev/tcp/itom-vault/*") and
  not process.parent.command_line : "runc init"
```



### Potential Reverse Shell via Background Process

Branch count: 64  
Document count: 64  
Index: geneve-ut-1072

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.name in ("setsid", "nohup") and process.args : "*/dev/tcp/*0>&1*" and
process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
```



### Potential Reverse Shell via Child

Branch count: 432  
Document count: 864  
Index: geneve-ut-1073

```python
sequence by host.id, process.entity_id with maxspan=5s
  [network where event.type == "start" and host.os.type == "linux" and
     event.action in ("connection_attempted", "connection_accepted") and
     process.name : ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "socat") and destination.ip != null and
     not cidrmatch(destination.ip, "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1")]
  [process where event.type == "start" and host.os.type == "linux" and event.action == "exec" and
     process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and (
       (process.args : ("-i", "-l")) or (process.parent.name == "socat" and process.parent.args : "*exec*")
   )]
```



### Potential Reverse Shell via Java

Branch count: 288  
Document count: 576  
Index: geneve-ut-1074

```python
sequence by host.id with maxspan=5s
  [network where host.os.type == "linux" and event.action in ("connection_accepted", "connection_attempted") and
   process.executable : ("/usr/bin/java", "/bin/java", "/usr/lib/jvm/*", "/usr/java/*") and
   not (destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
     destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
     "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
     "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
     "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
     "FF00::/8"
    )
  )] by process.entity_id
  [process where host.os.type == "linux" and event.action == "exec" and
   process.parent.executable : ("/usr/bin/java", "/bin/java", "/usr/lib/jvm/*", "/usr/java/*") and
   process.parent.args : "-jar" and process.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
   and not (
     process.parent.args in (
       "/usr/lib/jenkins/jenkins.war", "/etc/remote-iot/services/remoteiot.jar", "/opt/pentaho/data-integration/launcher/launcher.jar",
       "/usr/share/java/jenkins.war", "/opt//tomcat/statistics/statistics.jar", "/usr/lib64/NetExtender.jar",
       "/var/lib/jenkins/workspace/MP-QA/tc_certified_copy*/tc_certified_copy_web_ui_test/target/surefire/surefirebooter*.jar",
       "-javaagent:/opt/opentelemetry/opentelemetry-javaagent-all.jar", "./lib/pipeline-job-executor*SNAPSHOT.jar",
       "./lib/worker-launcher-agent*SNAPSHOT.jar", "/opt/Seqrite_EndPoint_Security/wildfly/jboss-modules.jar",
       "/home/data/jenkins.war", "/pro/service-modules/deployment.jar", "/application/HES/READER/*.jar", "*-SNAPSHOT.jar",
       "READER/G1A/READER_G1A.jar", "READER_G1.jar"
     ) or
    process.command_line like~ (
      "bash -c ps -eo pid,lstart,comm*",
      "bash -c df -i /application | tail -n 1",
      "/bin/sh -xe /tmp/hudson*.sh",
      "bash -c cat /application/HES/*"
    )
   )] by process.parent.entity_id
```



### Potential SAP NetWeaver Exploitation

Branch count: 216  
Document count: 216  
Index: geneve-ut-1078

```python
process where event.type == "start" and host.os.type in ("linux", "windows") and
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
                   "wget",
                   "cmd.exe",
                   "powershell.exe",
                   "rundll32.exe",
                   "msbuild.exe",
                   "curl.exe",
                   "certutil.exe") and
   (
    process.working_directory : ("/*/sap.com*/servlet_jsp/irj/*", "*\\sap.com*\\servlet_jsp\\irj\\*") or
    process.command_line : ("*/sap.com*/servlet_jsp/irj/*", "*\\sap.com*\\servlet_jsp\\irj\\*") or
    process.parent.command_line : ("*/sap.com*/servlet_jsp/irj/*", "*\\sap.com*\\servlet_jsp\\irj\\*")
   )
```



### Potential SAP NetWeaver WebShell Creation

Branch count: 24  
Document count: 24  
Index: geneve-ut-1079

```python
file where host.os.type in ("linux", "windows") and event.action == "creation" and
 file.extension : ("jsp", "java", "class") and
 file.path : ("/*/sap.com/*/servlet_jsp/irj/root/*",
              "/*/sap.com/*/servlet_jsp/irj/work/*",
              "?:\\*\\sap.com\\*\\servlet_jsp\\irj\\root\\*",
              "?:\\*\\sap.com\\*\\servlet_jsp\\irj\\work\\*")
```



### Potential SSH Password Grabbing via strace

Branch count: 1  
Document count: 2  
Index: geneve-ut-1080

```python
sequence by host.id with maxspan=3s
  [process where host.os.type == "linux" and event.type == "end" and process.name == "sshd"]
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name == "strace"]
```



### Potential Secret Scanning via Gitleaks

Branch count: 14  
Document count: 14  
Index: geneve-ut-1082

```python
process where event.type == "start" and event.action like ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started", "Process Create*") and
process.name : ("gitleaks.exe", "gitleaks")
```



### Potential Secure File Deletion via SDelete Utility

Branch count: 1  
Document count: 1  
Index: geneve-ut-1083

```python
file where host.os.type == "windows" and event.type == "change" and file.name : "*AAA.AAA"
```



### Potential Shadow Credentials added to AD Object

Branch count: 1  
Document count: 1  
Index: geneve-ut-1084

```python
event.code:"5136" and host.os.type:"windows" and winlog.event_data.AttributeLDAPDisplayName:"msDS-KeyCredentialLink" and
  winlog.event_data.AttributeValue :B\:828* and
  not winlog.event_data.SubjectUserName: MSOL_*
```



### Potential SharpRDP Behavior

Branch count: 32  
Document count: 96  
Index: geneve-ut-1086

```python
/* Incoming RDP followed by a new RunMRU string value set to cmd, powershell, taskmgr or tsclient, followed by process execution within 1m */

sequence by host.id with maxspan=1m
  [network where host.os.type == "windows" and event.type == "start" and process.name : "svchost.exe" and destination.port == 3389 and
   network.direction : ("incoming", "ingress") and network.transport == "tcp" and
   source.ip != "127.0.0.1" and source.ip != "::1"
  ]

  [registry where host.os.type == "windows" and event.type == "change" and process.name : "explorer.exe" and
   registry.path : ("HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\*") and
   registry.data.strings : ("cmd.exe*", "powershell.exe*", "taskmgr*", "\\\\tsclient\\*.exe\\*")
  ]

  [process where host.os.type == "windows" and event.type == "start" and
   (process.parent.name : ("cmd.exe", "powershell.exe", "taskmgr.exe") or process.args : ("\\\\tsclient\\*.exe")) and
   not process.name : "conhost.exe"
   ]
```



### Potential Shell via Wildcard Injection Detected

Branch count: 648  
Document count: 1296  
Index: geneve-ut-1087

```python
sequence by host.id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "ProcessRollup2") and (
    (process.name == "tar" and process.args : "--checkpoint=*" and process.args : "--checkpoint-action=*") or
    (process.name == "rsync" and process.args : "-e*") or
    (process.name == "zip" and process.args == "--unzip-command")
   ) and not (
     process.executable like "/tmp/newroot/*" or
     process.working_directory like ("/home/*/.steam/*", "/home/*/steam/*", "/home/*/.local/share/Steam")
   )
  ] by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "start", "ProcessRollup2") and
     process.parent.name : ("tar", "rsync", "zip") and
     process.name : ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
  ] by process.parent.entity_id
```



### Potential Sudo Hijacking

Branch count: 8  
Document count: 8  
Index: geneve-ut-1091

```python
file where host.os.type == "linux" and event.action in ("creation", "rename") and
file.path in ("/usr/bin/sudo", "/bin/sudo") and not (
  process.name like ("python*", "platform-python*") or
  file.Ext.original.path in ("/usr/bin/sudo", "/bin/sudo") or
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum", "/bin/dnf", "/usr/bin/dnf",
    "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic", "/bin/pacman", "/usr/bin/pacman",
    "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk", "/usr/local/sbin/apk", "/usr/bin/apt",
    "/usr/sbin/pacman", "/usr/bin/microdnf", "/usr/local/bin/dockerd", "/usr/local/bin/podman", "/usr/local/bin/dnf",
    "/kaniko/executor", "/proc/self/exe", "/usr/bin/apt-get", "/usr/bin/apt-cache", "/usr/bin/apt-mark",
    "./usr/bin/podman", "./usr/lib/snapd/snap-update-ns", "/kaniko/kaniko-executor", "/usr/libexec/packagekitd",
    "/usr/bin/dnf5", "/usr/lib/pamac/pamac-daemon", "./usr/libexec/snapd/snap-update-ns", "/usr/bin/update-alternatives"
  ) or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/var/lib/docker/*",
    "./snap/snapd/*/usr/lib/snapd/snap-update-ns", "/opt/docker/overlay2/*/dockerd", 
    "/var/lib/containers/storage/overlay/*/dockerd"
  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*")
)
```



### Potential Sudo Privilege Escalation via CVE-2019-14287

Branch count: 6  
Document count: 6  
Index: geneve-ut-1092

```python
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
  process.name == "sudo" and process.args == "-u#-1"
```



### Potential Sudo Token Manipulation via Process Injection

Branch count: 1  
Document count: 2  
Index: geneve-ut-1093

```python
sequence by host.id, process.session_leader.entity_id with maxspan=15s
[ process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
  process.name == "gdb" and process.user.id != "0" and process.group.id != "0" ]
[ process where host.os.type == "linux" and event.action == "uid_change" and event.type == "change" and
  process.name == "sudo" and process.user.id == "0" and process.group.id == "0" ]
```



### Potential Suspicious DebugFS Root Device Access

Branch count: 1  
Document count: 1  
Index: geneve-ut-1094

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name == "debugfs" and process.args : "/dev/sd*" and not process.args == "-R" and
not user.Ext.real.id == "0" and not group.Ext.real.id == "0"
```



### Potential Suspicious File Edit

Branch count: 94  
Document count: 94  
Index: geneve-ut-1095

```python
file where host.os.type == "linux" and event.action in ("creation", "file_create_event") and file.extension == "swp" and
file.path : (
  /* common interesting files and locations */
  "/etc/.shadow.swp", "/etc/.shadow-.swp", "/etc/.shadow~.swp", "/etc/.gshadow.swp", "/etc/.gshadow-.swp",
  "/etc/.passwd.swp", "/etc/.pwd.db.swp", "/etc/.master.passwd.swp", "/etc/.spwd.db.swp", "/etc/security/.opasswd.swp",
  "/etc/.environment.swp", "/etc/.profile.swp", "/etc/sudoers.d/.*.swp", "/etc/ld.so.conf.d/.*.swp",
  "/etc/init.d/.*.swp", "/etc/.rc.local.swp", "/etc/rc*.d/.*.swp", "/dev/shm/.*.swp", "/etc/update-motd.d/.*.swp",
  "/usr/lib/update-notifier/.*.swp",

  /* service, timer, want, socket and lock files */
  "/etc/systemd/system/.*.swp", "/usr/local/lib/systemd/system/.*.swp", "/lib/systemd/system/.*.swp",
  "/usr/lib/systemd/system/.*.swp","/home/*/.config/systemd/user/.*.swp", "/run/.*.swp", "/var/run/.*.swp/",

  /* profile and shell configuration files */
  "/home/*.profile.swp", "/home/*.bash_profile.swp", "/home/*.bash_login.swp", "/home/*.bashrc.swp", "/home/*.bash_logout.swp",
  "/home/*.zshrc.swp", "/home/*.zlogin.swp", "/home/*.tcshrc.swp", "/home/*.kshrc.swp", "/home/*.config.fish.swp",
  "/root/*.profile.swp", "/root/*.bash_profile.swp", "/root/*.bash_login.swp", "/root/*.bashrc.swp", "/root/*.bash_logout.swp",
  "/root/*.zshrc.swp", "/root/*.zlogin.swp", "/root/*.tcshrc.swp", "/root/*.kshrc.swp", "/root/*.config.fish.swp"
)
```



### Potential System Tampering via File Modification

Branch count: 16  
Document count: 16  
Index: geneve-ut-1096

```python
file where host.os.type == "windows" and event.type in ("change", "deletion") and
  file.name : ("winload.exe", "winlod.efi", "ntoskrnl.exe", "bootmgr") and
  file.path : ("?:\\Windows\\*", "\\Device\\HarddiskVolume*\\Windows\\*") and
  not process.executable : (
    "?:\\Windows\\System32\\poqexec.exe",
    "?:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack_*\\tiworker.exe"
  ) and
  not file.path : (
    "?:\\Windows\\WinSxS\\Temp\\InFlight\\*",
    "?:\\Windows\\SoftwareDistribution\\Download*",
    "?:\\Windows\\WinSxS\\amd64_microsoft-windows*",
    "?:\\Windows\\SystemTemp\\*",
    "?:\\Windows\\Temp\\????????.???\\*",
    "?:\\Windows\\Temp\\*\\amd64_microsoft-windows-*"
  )
```



### Potential THC Tool Downloaded

Branch count: 48  
Document count: 48  
Index: geneve-ut-1097

```python
process where host.os.type == "linux" and event.type == "start" and
 event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
 process.name in ("curl", "wget") and process.args : (
  "https://github.com/hackerschoice/*", "https://thc.org/*", "http://nossl.segfault.net/*", "https://gsocket.io/*"
)
```



### Potential Telnet Authentication Bypass (CVE-2026-24061)

Branch count: 5  
Document count: 5  
Index: geneve-ut-1098

```python
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed") and
  process.name == "login" and process.parent.name == "telnetd" and process.args : "-*f*"
```



### Potential Unauthorized Access via Wildcard Injection Detected

Branch count: 12  
Document count: 12  
Index: geneve-ut-1101

```python
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
  process.name in ("chown", "chmod") and process.args == "-R" and process.args : "--reference=*"
```



### Potential Upgrade of Non-interactive Shell

Branch count: 4  
Document count: 4  
Index: geneve-ut-1102

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
(
  (process.name == "stty" and process.args == "raw" and process.args == "-echo" and process.args_count >= 3) or
  (
    process.name == "script" and process.args in ("-qc", "-c") and process.args == "/dev/null" and process.args_count == 4
  )
) and
not process.parent.command_line like ("linode-longview", "*bootstrap*", "*homebrew*")
```



### Potential Veeam Credential Access Command

Branch count: 6  
Document count: 6  
Index: geneve-ut-1104

```python
process where host.os.type == "windows" and event.type == "start" and
  (
    (process.name : "sqlcmd.exe" or ?process.pe.original_file_name : "sqlcmd.exe") or
    process.args : ("Invoke-Sqlcmd", "Invoke-SqlExecute", "Invoke-DbaQuery", "Invoke-SqlQuery")
  ) and
  process.args : "*[VeeamBackup].[dbo].[Credentials]*"
```



### Potential WPAD Spoofing via DNS Record Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-1105

```python
any where host.os.type == "windows" and event.code == "5137" and winlog.event_data.ObjectDN : "DC=wpad,*"
```



### Potential WSUS Abuse for Lateral Movement

Branch count: 4  
Document count: 4  
Index: geneve-ut-1106

```python
process where host.os.type == "windows" and event.type == "start" and process.parent.name : "wuauclt.exe" and
process.executable : (
    "?:\\Windows\\SoftwareDistribution\\Download\\Install\\*",
    "\\Device\\HarddiskVolume?\\Windows\\SoftwareDistribution\\Download\\Install\\*"
) and
(process.name : "psexec64.exe" or ?process.pe.original_file_name : "psexec.c")
```



### Potential Web Shell ASPX File Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-1107

```python
file where host.os.type == "windows" and event.type != "deletion" and
  file.extension : "aspx" and
  file.path : "?:\\Program Files\\Common Files\\Microsoft Shared\\Web Server Extensions\\*" and
  not process.executable: (
        "?:\\Windows\\System32\\msiexec.exe",
        "?:\\Program Files\\Common Files\\Microsoft Shared\\Web Server Extensions\\16\\BIN\\psconfigui.exe"
  )
```



### Potential notify_on_release Container Escape Detected via Defend for Containers

Branch count: 1  
Document count: 1  
Index: geneve-ut-1113

```python
file where host.os.type == "linux" and event.type == "change" and event.action == "open" and
file.name == "notify_on_release" and process.interactive == true and container.id like "*"
```



### Potential privilege escalation via CVE-2022-38028

Branch count: 4  
Document count: 4  
Index: geneve-ut-1114

```python
file where host.os.type == "windows" and event.type != "deletion" and
    file.name : "MPDW-constraints.js" and
    file.path : (
        "?:\\*\\Windows\\system32\\DriverStore\\FileRepository\\*\\MPDW-constraints.js",
        "?:\\*\\Windows\\WinSxS\\amd64_microsoft-windows-printing-printtopdf_*\\MPDW-constraints.js", 
        "\\Device\\HarddiskVolume*\\*\\Windows\\system32\\DriverStore\\FileRepository\\*\\MPDW-constraints.js",
        "\\Device\\HarddiskVolume*\\*\\Windows\\WinSxS\\amd64_microsoft-windows-printing-printtopdf_*\\MPDW-constraints.js"
    ) and
    not process.executable : (
          "?:\\$WINDOWS.~BT\\Sources\\SetupHost.exe",
          "?:\\Windows\\System32\\taskhostw.exe"
    ) and
    not file.path : (
        "?:\\$WINDOWS.~BT\\NewOS\\Windows\\WinSxS\\*\\MPDW-constraints.js",
        "\\Device\\HarddiskVolume*\\$WINDOWS.~BT\\NewOS\\Windows\\WinSxS\\*\\MPDW-constraints.js"
    )
```



### Potential release_agent Container Escape Detected via Defend for Containers

Branch count: 1  
Document count: 1  
Index: geneve-ut-1115

```python
file where host.os.type == "linux" and event.type == "change" and event.action == "open" and
file.name == "release_agent" and process.interactive == true and container.id like "*"
```



### Potentially Successful Okta MFA Bombing via Push Notifications

Branch count: 128  
Document count: 768  
Index: geneve-ut-1116

```python
sequence by okta.actor.id with maxspan=10m
  [ any
    where event.dataset == "okta.system"
      and (
        okta.event_type == "user.mfa.okta_verify.deny_push"
        or (
          okta.event_type == "user.authentication.auth_via_mfa"
          and okta.debug_context.debug_data.factor == "OKTA_VERIFY_PUSH"
          and okta.outcome.reason == "INVALID_CREDENTIALS"
        )
      )
  ] with runs=5
  [ any
    where event.dataset == "okta.system"
      and okta.event_type in (
        "user.authentication.sso",
        "user.authentication.auth_via_mfa",
        "user.authentication.verify",
        "user.session.start"
      )
      and okta.outcome.result == "SUCCESS"
  ]
```



### Potentially Suspicious Process Started via tmux or screen

Branch count: 144  
Document count: 144  
Index: geneve-ut-1117

```python
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  process.parent.name in ("screen", "tmux") and process.name like (
    "nmap", "nc", "ncat", "netcat", "socat", "nc.openbsd", "ngrok", "ping", "java", "php*", "perl", "ruby", "lua*",
    "openssl", "telnet", "wget", "curl", "id"
  )
```



### PowerShell Invoke-NinjaCopy script

Branch count: 21  
Document count: 21  
Index: geneve-ut-1118

```python
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "StealthReadFile" or
    "StealthReadFileAddr" or
    "StealthCloseFileDelegate" or
    "StealthOpenFile" or
    "StealthCloseFile" or
    "StealthReadFile" or
    "Invoke-NinjaCopy"
   )
  and not user.id : "S-1-5-18"
  and not powershell.file.script_block_text : (
    "sentinelbreakpoints" and "Set-PSBreakpoint" and "PowerSploitIndicators"
  )
```



### PowerShell Kerberos Ticket Request

Branch count: 4  
Document count: 4  
Index: geneve-ut-1120

```python
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    KerberosRequestorSecurityToken
  ) and not user.id : ("S-1-5-18" or "S-1-5-20") and
  not powershell.file.script_block_text : (
    ("sentinelbreakpoints" and ("Set-PSBreakpoint" or "Set-HookFunctionTabs")) or
    ("function global" and "\\windows\\sentinel\\4")
  )
```



### PowerShell MiniDump Script

Branch count: 3  
Document count: 3  
Index: geneve-ut-1123

```python
event.category:process and host.os.type:windows and powershell.file.script_block_text:(MiniDumpWriteDump or MiniDumpWithFullMemory or pmuDetirWpmuDiniM) and not user.id : "S-1-5-18"
```



### PowerShell PSReflect Script

Branch count: 9  
Document count: 9  
Index: geneve-ut-1125

```python
event.category:process and host.os.type:windows and
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
  ) and
  not user.id : "S-1-5-18"
```



### PowerShell Script Block Logging Disabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-1126

```python
registry where host.os.type == "windows" and event.type == "change" and
    registry.value : "EnableScriptBlockLogging" and
    registry.data.strings : ("0", "0x00000000") and
    not process.executable : (
          "?:\\Windows\\System32\\svchost.exe",
          "?:\\Windows\\System32\\DeviceEnroller.exe",
          "?:\\Windows\\system32\\omadmclient.exe",
          "?:\\Program Files (x86)\\N-able Technologies\\AutomationManagerAgent\\AutomationManager.AgentService.exe",

          /* Crowdstrike specific exclusion as it uses NT Object paths */
          "\\Device\\HarddiskVolume*\\Windows\\System32\\svchost.exe",
          "\\Device\\HarddiskVolume*\\Windows\\System32\\DeviceEnroller.exe",
          "\\Device\\HarddiskVolume*\\Windows\\system32\\omadmclient.exe",
          "\\Device\\HarddiskVolume*\\Program Files (x86)\\N-able Technologies\\AutomationManagerAgent\\AutomationManager.AgentService.exe"
    )
```



### Printer User (lp) Shell Execution

Branch count: 240  
Document count: 240  
Index: geneve-ut-1143

```python
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "ProcessRollup2", "ProcessRollup2") and user.name == "lp" and
  process.parent.name in ("cupsd", "foomatic-rip", "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
  process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and not (
    process.command_line like (
      "*/tmp/foomatic-*", "*-sDEVICE=ps2write*", "*printf*", "/bin/sh -e -c cat", "/bin/bash -c cat",
      "/bin/bash -e -c cat"
    ) or
    process.args like ("gs*", "/usr/bin/lsb_release", "/usr/lib/cups/filter/gstopdf")
  )
```



### Privilege Escalation via CAP_SETUID/SETGID Capabilities

Branch count: 4  
Document count: 8  
Index: geneve-ut-1146

```python
sequence by host.id, process.entity_id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name != null and
   (process.thread.capabilities.effective : "CAP_SET?ID" or process.thread.capabilities.permitted : "CAP_SET?ID") and
   user.id != "0" and not (
     process.parent.executable : ("/tmp/newroot/*", "/opt/carbonblack*") or
     process.parent.executable in (
       "/opt/SolarWinds/Agent/bin/Plugins/JobEngine/SolarWinds.Agent.JobEngine.Plugin", "/usr/bin/vmware-toolbox-cmd",
       "/usr/bin/dbus-daemon", "/usr/bin/update-notifier", "/usr/share/language-tools/language-options",
       "/opt/SolarWinds/Agent/*", "/usr/local/sbin/lynis.sh", "/usr/libexec/sssd/sssd_be",
       "/opt/sophos-spl/plugins/edr/bin/osqueryd.5", "/apps/dynatrace/oneagent/install/agent/lib64/oneagentos",
       "/opt/carbonblack/*/osqueryi"
     ) or
     process.executable : ("/opt/dynatrace/*", "/tmp/newroot/*", "/opt/SolarWinds/Agent/*") or
     process.executable in (
       "/bin/fgrep", "/usr/bin/sudo", "/usr/bin/pkexec", "/usr/lib/cockpit/cockpit-session", "/usr/sbin/suexec"
     ) or
     process.parent.name in ("update-notifier", "language-options", "osqueryd", "saposcol", "dbus-daemon", "osqueryi", "sdbrun") or
     process.command_line like ("sudo*BECOME-SUCCESS*", "/bin/sh*sapsysinfo.sh*", "sudo su", "sudo su -", "sudo -E -H bash -l") or
     process.name in ("sudo", "fgrep", "lsb_release", "apt-update", "dbus-daemon-launch-helper", "man") or
     process.parent.command_line like "/usr/bin/python*ansible*" or
     process.working_directory like ("/opt/Elastic/Agent/data/*", "/usr/sap/tmp") or
     process.args like ("/usr/bin/lsb_release*", "/bin/fgrep*")
   )]
  [process where host.os.type == "linux" and event.action == "uid_change" and event.type == "change" and
   (process.thread.capabilities.effective : "CAP_SET?ID" or process.thread.capabilities.permitted : "CAP_SET?ID")
   and user.id == "0"]
```



### Privilege Escalation via GDB CAP_SYS_PTRACE

Branch count: 2  
Document count: 4  
Index: geneve-ut-1147

```python
sequence by host.id, process.entry_leader.entity_id with maxspan=1m
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name == "gdb" and
   (process.thread.capabilities.effective : "CAP_SYS_PTRACE" or process.thread.capabilities.permitted : "CAP_SYS_PTRACE") and
   user.id != "0"]
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name != null and user.id == "0"]
```



### Privilege Escalation via Named Pipe Impersonation

Branch count: 4  
Document count: 4  
Index: geneve-ut-1148

```python
process where host.os.type == "windows" and event.type == "start" and
 (process.name : ("Cmd.Exe", "PowerShell.EXE") or ?process.pe.original_file_name in ("Cmd.Exe", "PowerShell.EXE")) and
 process.args : "echo" and process.args : ">" and process.args : "\\\\.\\pipe\\*"
```



### Privilege Escalation via Rogue Named Pipe Impersonation

Branch count: 1  
Document count: 1  
Index: geneve-ut-1149

```python
file where host.os.type == "windows" and
  event.provider == "Microsoft-Windows-Sysmon" and

  /* Named Pipe Creation */
  event.code == "17" and

  /* Sysmon truncates the "Pipe" keyword in normal named pipe creation events */
  file.name : "\\*\\Pipe\\*"
```



### Privilege Escalation via Root Crontab File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-1150

```python
file where host.os.type == "macos" and event.action == "modification" and
 file.path like "/private/var/at/tabs/root" and 
 not process.executable like "/usr/bin/crontab"
```



### Privilege Escalation via SUID/SGID

Branch count: 434  
Document count: 434  
Index: geneve-ut-1151

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  (process.user.id == "0" and process.real_user.id != "0") or
  (process.group.id == "0" and process.real_group.id != "0")
) and (
  process.name in (
    "aa-exec", "ab", "agetty", "alpine", "ar", "arj", "arp", "as", "ascii-xfr", "ash", "aspell",
    "atobm", "awk", "base32", "base64", "basenc", "basez", "bc", "bridge", "busctl",
    "busybox", "bzip2", "cabal", "capsh", "cat", "choom", "chown", "chroot", "clamscan", "cmp",
    "column", "comm", "cp", "cpio", "cpulimit", "csplit", "csvtool", "cupsfilter", "curl",
    "cut", "date", "dd", "debugfs", "dialog", "diff", "dig", "distcc", "dmsetup", "docker",
    "dosbox", "ed", "efax", "elvish", "emacs", "env", "eqn", "espeak", "expand", "expect", "file",
    "fish", "flock", "fmt", "fold", "gawk", "gcore", "gdb", "genie", "genisoimage", "gimp",
    "grep", "gtester", "gzip", "hd", "head", "hexdump", "highlight", "hping3", "iconv", "install",
    "ionice", "ispell", "jjs", "join", "jq", "jrunscript", "julia", "ksh", "ksshell", "kubectl",
    "ld.so", "less", "links", "logsave", "look", "lua", "make", "mawk", "minicom", "more",
    "mosquitto", "msgattrib", "msgcat", "msgconv", "msgfilter", "msgmerge", "msguniq", "multitime",
    "mv", "nasm", "nawk", "ncftp", "nft", "nice", "nl", "nm", "nmap", "node", "nohup", "ntpdate",
    "od", "openssl", "openvpn", "pandoc", "paste", "perf", "perl", "pexec", "pg", "php", "pidstat",
    "pr", "ptx", "python", "rc", "readelf", "restic", "rev", "rlwrap", "rsync", "rtorrent",
    "run-parts", "rview", "rvim", "sash", "scanmem", "sed", "setarch", "setfacl", "setlock", "shuf",
    "soelim", "softlimit", "sort", "sqlite3", "ss", "ssh-agent", "ssh-keygen", "ssh-keyscan",
    "sshpass", "start-stop-daemon", "stdbuf", "strace", "strings", "sysctl", "systemctl", "tac",
    "tail", "taskset", "tbl", "tclsh", "tee", "terraform", "tftp", "tic", "time", "timeout", "troff",
    "ul", "unexpand", "uniq", "unshare", "unsquashfs", "unzip", "update-alternatives", "uudecode",
    "uuencode", "vagrant", "varnishncsa", "view", "vigr", "vim", "vimdiff", "vipw", "w3m", "watch",
    "wc", "wget", "whiptail", "xargs", "xdotool", "xmodmap", "xmore", "xxd", "xz", "yash", "zsh",
    "zsoelim"
  ) or
  (process.name == "ip" and ((process.args == "-force" and process.args in ("-batch", "-b")) or (process.args == "exec"))) or
  (process.name == "find" and process.args in ("-exec", "-execdir")) or
  (process.name in ("bash", "csh", "dash") and process.args in ("-p", "-b"))
) and not (
  process.parent.name == "spine" or
  process.parent.executable in (
    "/usr/NX/bin/nxexec", "/opt/andrisoft/bin/WANmaintenance", "/usr/lib/vmware/bin/vmware-vmx",
    "/usr/bin/pamprivilegechange", "/usr/lib/hyper-v/bin/hv_kvp_daemon"
  ) or
  process.parent.command_line in ("runc init", "/opt/bitdefender-security-tools/bin/auctl") or
  process.args like ("/usr/bin/snmpwalk*", "/usr/bin/snmpbulkwalk*", "/usr/bin/snmpget*")
)
```



### Privilege Escalation via Windir Environment Variable

Branch count: 4  
Document count: 4  
Index: geneve-ut-1152

```python
registry where host.os.type == "windows" and event.type == "change" and
registry.value : ("windir", "systemroot") and registry.data.strings != null and
registry.path : (
    "*\\Environment\\windir",
    "*\\Environment\\systemroot"
    ) and
 not registry.data.strings : ("C:\\windows", "%SystemRoot%")
```



### Privileged Container Creation with Host Directory Mount

Branch count: 24  
Document count: 24  
Index: geneve-ut-1154

```python
process where event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "docker" and process.args == "--privileged" and process.args == "run" and
process.args == "-v" and process.args like "/:/*" and
not (
  (process.args == "aktosecurity/mirror-api-logging:k8s_ebpf" and process.args == "akto-api-security-traffic-collector") or
  (process.args like "goharbor/prepare:*" and process.args in ("/:/hostfs", "/:/hostfs/"))
)
```



### Process Activity via Compiled HTML File

Branch count: 7  
Document count: 7  
Index: geneve-ut-1157

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "hh.exe" and
 process.name : ("mshta.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cscript.exe", "wscript.exe")
```



### Process Capability Enumeration

Branch count: 3  
Document count: 3  
Index: geneve-ut-1159

```python
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "ProcessRollup2") and
  process.name == "getcap" and process.args == "-r" and process.args == "/" and
  process.args_count == 3 and user.id != "0"
```



### Process Capability Set via setcap Utility

Branch count: 3  
Document count: 3  
Index: geneve-ut-1160

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
process.name == "setcap" and not (
  process.parent.executable == null or
  process.parent.executable like (
    "/var/lib/dpkg/*", "/var/lib/docker/*", "/tmp/newroot/*", "/var/tmp/newroot/*", "/usr/bin/cmake",
    "/opt/zscaler/bin/zpa-connector"
  ) or
  process.parent.name in ("jem", "vzctl") or
  process.parent.args like "/var/lib/dpkg/info/*" or
  ?process.working_directory in ("/opt/dynatrace/oneagent", "/opt/sophos-spl/plugins/av/sbin") or
  process.parent.command_line in ("/bin/bash /entrypoint.sh telegraf", "/bin/sh /usr/local/bin/docker-entrypoint.sh server")
)
```



### Process Created with an Elevated Token

Branch count: 48  
Document count: 48  
Index: geneve-ut-1162

```python
/* This rule is only compatible with Elastic Endpoint 8.4+ */

process where host.os.type == "windows" and event.action == "start" and

 /* CreateProcessWithToken and effective parent is a privileged MS native binary used as a target for token theft */
 user.id == "S-1-5-18"  and process.parent.executable != null and

 /* Token Theft target process usually running as service are located in one of the following paths */
 process.Ext.effective_parent.executable : "?:\\Windows\\*.exe" and

/* Ignores Utility Manager in Windows running in debug mode */
 not (process.Ext.effective_parent.executable : "?:\\Windows\\System32\\Utilman.exe" and
      process.parent.executable : "?:\\Windows\\System32\\Utilman.exe" and process.parent.args : "/debug") and

/* Ignores Windows print spooler service with correlation to Access Intelligent Form */
not (process.parent.executable : ("?\\Windows\\System32\\spoolsv.exe", "C:\\Windows\\System32\\PrintIsolationHost.exe") and
     process.executable: ("?:\\Program Files\\*.exe",
                          "?:\\Program Files (x86)\\*.exe",
                          "?:\\Windows\\System32\\spool\\drivers\\*.exe",
                          "?:\\Windows\\System32\\ROUTE.EXE")) and

/* Ignores Windows error reporting executables */
 not process.executable : ("?:\\Windows\\System32\\WerFault.exe",
                           "?:\\Windows\\SysWOW64\\WerFault.exe",
                           "?:\\Windows\\System32\\WerFaultSecure.exe",
                           "?:\\Windows\\SysWOW64\\WerFaultSecure.exe",
                           "?:\\windows\\system32\\WerMgr.exe",
                           "?:\\Windows\\SoftwareDistribution\\Download\\Install\\securityhealthsetup.exe")  and

 /* Ignores Windows updates from TiWorker.exe that runs with elevated privileges */
 not (process.parent.executable : "?:\\Windows\\WinSxS\\*\\TiWorker.exe" and
      process.executable : ("?:\\Windows\\Microsoft.NET\\Framework*.exe",
                            "?:\\Windows\\WinSxS\\*.exe",
                            "?:\\Windows\\System32\\inetsrv\\iissetup.exe",
                            "?:\\Windows\\SysWOW64\\inetsrv\\iissetup.exe",
                            "?:\\Windows\\System32\\inetsrv\\aspnetca.exe",
                            "?:\\Windows\\SysWOW64\\inetsrv\\aspnetca.exe",
                            "?:\\Windows\\System32\\lodctr.exe",
                            "?:\\Windows\\SysWOW64\\lodctr.exe",
                            "?:\\Windows\\System32\\netcfg.exe",
                            "?:\\Windows\\Microsoft.NET\\Framework*\\*\\ngen.exe",
                            "?:\\Windows\\Microsoft.NET\\Framework*\\*\\aspnet_regiis.exe")) and


/* Ignores additional parent executables that run with elevated privileges */
 not process.parent.executable :
               ("?:\\Windows\\System32\\AtBroker.exe",
                "?:\\Windows\\system32\\svchost.exe",
                "?:\\Program Files (x86)\\*.exe",
                "?:\\Program Files\\*.exe",
                "?:\\Windows\\System32\\msiexec.exe",
                "?:\\Windows\\System32\\DriverStore\\*",
                "?:\\Windows\\LTSvc\\*\\Update.exe") and

/* Ignores Windows binaries with a trusted signature and specific signature name */
 not (process.code_signature.trusted == true and
      process.code_signature.subject_name :
                ("philandro Software GmbH",
                 "Freedom Scientific Inc.",
                 "TeamViewer Germany GmbH",
                 "Projector.is, Inc.",
                 "TeamViewer GmbH",
                 "Cisco WebEx LLC",
                 "Dell Inc",
                 "Sophos Ltd",
                 "Sophos Limited",
                 "Brother Industries, Ltd.",
                 "MILVUS INOVACOES EM SOFTWARE LTDA",
                 "Chocolatey Software, Inc")) and

 not (process.Ext.effective_parent.executable : "?:\\Windows\\servicing\\TrustedInstaller.exe" and
      process.executable : "C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack_*\\TiWorker.exe") and

 not process.Ext.effective_parent.executable : "?:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\ServicePortalAgent\\current\\emulator\\MmrAgent.NetFxEmulator.exe"
```



### Process Creation via Secondary Logon

Branch count: 2  
Document count: 4  
Index: geneve-ut-1163

```python
sequence by winlog.computer_name with maxspan=1m

[authentication where host.os.type == "windows" and event.action:"logged-in" and
 event.outcome == "success" and user.id : ("S-1-5-21-*", "S-1-12-1-*") and

 /* seclogon service */
 process.name == "svchost.exe" and
 winlog.event_data.LogonProcessName : "seclogo*" and source.ip == "::1" ] by winlog.event_data.TargetLogonId

[process where host.os.type == "windows" and event.type == "start"] by winlog.event_data.TargetLogonId
```



### Process Discovery Using Built-in Tools

Branch count: 11  
Document count: 11  
Index: geneve-ut-1164

```python
process where host.os.type == "windows" and event.type == "start" and process.args != null and 
  not user.id in ("S-1-5-18", "S-1-5-19", "S-1-5-20") and process.parent.executable != null and
  (
   process.name :("PsList.exe", "qprocess.exe") or

   (process.name : "powershell.exe" and process.args : ("*get-process*", "*Win32_Process*") and not process.parent.name in ("openaev-agent.exe", "cmd.exe", "Miro.exe", "Granola.exe", "Wispr Flow.exe")) or

   (process.name : "wmic.exe" and process.args : ("process", "*Win32_Process*") and not process.parent.name in ("Code.exe", "node.exe", "javaw.exe", "java.exe", "asus_framework.exe", "Evernote.exe", "RingCentral.exe", "Avaya Cloud.exe", "Arduino IDE.exe")) or

   (process.name : "tasklist.exe" and process.args_count == 1 and process.parent.args != "tasklist | findstr consent.exe") or

   (process.name : "query.exe" and process.args : ("process", "imagename*", "csv", "/fi"))
  ) and
  not process.working_directory like ("?:\\Program Files*", "D:\\*", "E:\\*") and
  not process.parent.executable like ("?:\\Program Files (x86)\\*.exe", "?:\\Program Files\\*.exe")
```



### Process Execution from an Unusual Directory

Branch count: 66  
Document count: 66  
Index: geneve-ut-1166

```python
process where host.os.type == "windows" and event.type == "start" and
  /* add suspicious execution paths here */
  process.executable : (
    "?:\\PerfLogs\\*.exe", "?:\\Users\\Public\\*.exe", "?:\\Windows\\Tasks\\*.exe",
    "?:\\Intel\\*.exe", "?:\\AMD\\Temp\\*.exe", "?:\\Windows\\AppReadiness\\*.exe",
    "?:\\Windows\\ServiceState\\*.exe", "?:\\Windows\\security\\*.exe", "?:\\Windows\\IdentityCRL\\*.exe",
    "?:\\Windows\\Branding\\*.exe", "?:\\Windows\\csc\\*.exe", "?:\\Windows\\DigitalLocker\\*.exe",
    "?:\\Windows\\en-US\\*.exe", "?:\\Windows\\wlansvc\\*.exe", "?:\\Windows\\Prefetch\\*.exe",
    "?:\\Windows\\Fonts\\*.exe", "?:\\Windows\\diagnostics\\*.exe", "?:\\Windows\\TAPI\\*.exe",
    "?:\\Windows\\INF\\*.exe", "?:\\Windows\\System32\\Speech\\*.exe", "?:\\windows\\tracing\\*.exe",
    "?:\\windows\\IME\\*.exe", "?:\\Windows\\Performance\\*.exe", "?:\\windows\\intel\\*.exe",
    "?:\\windows\\ms\\*.exe", "?:\\Windows\\dot3svc\\*.exe", "?:\\Windows\\panther\\*.exe",
    "?:\\Windows\\RemotePackages\\*.exe", "?:\\Windows\\OCR\\*.exe", "?:\\Windows\\appcompat\\*.exe",
    "?:\\Windows\\apppatch\\*.exe", "?:\\Windows\\addins\\*.exe", "?:\\Windows\\Setup\\*.exe",
    "?:\\Windows\\Help\\*.exe", "?:\\Windows\\SKB\\*.exe", "?:\\Windows\\Vss\\*.exe",
    "?:\\Windows\\Web\\*.exe", "?:\\Windows\\servicing\\*.exe", "?:\\Windows\\CbsTemp\\*.exe",
    "?:\\Windows\\Logs\\*.exe", "?:\\Windows\\WaaS\\*.exe", "?:\\Windows\\ShellExperiences\\*.exe",
    "?:\\Windows\\ShellComponents\\*.exe", "?:\\Windows\\PLA\\*.exe", "?:\\Windows\\Migration\\*.exe",
    "?:\\Windows\\debug\\*.exe", "?:\\Windows\\Cursors\\*.exe", "?:\\Windows\\Containers\\*.exe",
    "?:\\Windows\\Boot\\*.exe", "?:\\Windows\\bcastdvr\\*.exe", "?:\\Windows\\assembly\\*.exe",
    "?:\\Windows\\TextInput\\*.exe", "?:\\Windows\\security\\*.exe", "?:\\Windows\\schemas\\*.exe",
    "?:\\Windows\\SchCache\\*.exe", "?:\\Windows\\Resources\\*.exe", "?:\\Windows\\rescache\\*.exe",
    "?:\\Windows\\Provisioning\\*.exe", "?:\\Windows\\PrintDialog\\*.exe", "?:\\Windows\\PolicyDefinitions\\*.exe",
    "?:\\Windows\\media\\*.exe", "?:\\Windows\\Globalization\\*.exe", "?:\\Windows\\L2Schemas\\*.exe",
    "?:\\Windows\\LiveKernelReports\\*.exe", "?:\\Windows\\ModemLogs\\*.exe",
    "?:\\Windows\\ImmersiveControlPanel\\*.exe"
  ) and

  not process.name : (
    "SpeechUXWiz.exe", "SystemSettings.exe", "TrustedInstaller.exe",
    "PrintDialog.exe", "MpSigStub.exe", "LMS.exe", "mpam-*.exe"
  ) and
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
```



### Process Injection - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-1167

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:kernel_shellcode_event or endgame.event_subtype_full:kernel_shellcode_event)
```



### Process Injection - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-1168

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:kernel_shellcode_event or endgame.event_subtype_full:kernel_shellcode_event)
```



### Process Injection by the Microsoft Build Engine

Branch count: 1  
Document count: 1  
Index: geneve-ut-1169

```python
process where host.os.type == "windows" and
  event.provider == "Microsoft-Windows-Sysmon" and
  /* CreateRemoteThread */
  event.code == "8" and process.name: "MSBuild.exe"
```



### Process Spawned from Message-of-the-Day (MOTD)

Branch count: 171  
Document count: 171  
Index: geneve-ut-1170

```python
process where event.type == "start" and host.os.type == "linux" and event.action in ("exec", "exec_event", "start") and
process.parent.executable like "/etc/update-motd.d/*" and
(
  (
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
    (
      process.args : ("-i", "-l") or
      (process.parent.name == "socat" and process.parent.args : "*exec*")
    )
  ) or
  (
    process.name : ("nc", "ncat", "netcat", "nc.openbsd") and process.args_count >= 3 and 
    not process.args : ("-*z*", "-*l*")
  ) or
  (
    process.name : "python*" and process.args : "-c" and process.args : (
      "*import*pty*spawn*", "*import*subprocess*call*"
    )
  ) or
  (
    process.name : "perl*" and process.args : "-e" and process.args : "*socket*" and process.args : (
      "*exec*", "*system*"
    )
  ) or
  (
    process.name : "ruby*" and process.args : ("-e", "-rsocket") and process.args : (
      "*TCPSocket.new*", "*TCPSocket.open*"
    )
  ) or
  (
    process.name : "lua*" and process.args : "-e" and process.args : "*socket.tcp*" and process.args : (
      "*io.popen*", "*os.execute*"
    )
  ) or
  (process.name : "php*" and process.args : "-r" and process.args : "*fsockopen*" and process.args : "*/bin/*sh*") or 
  (process.name : ("awk", "gawk", "mawk", "nawk") and process.args : "*/inet/tcp/*") or 
  (process.name in ("openssl", "telnet")) or
  (
    process.args : (
      "./*", "/boot/*", "/dev/shm/*", "/etc/cron.*/*", "/etc/init.d/*", "/etc/update-motd.d/*", "/run/*", "/srv/*",
      "/tmp/*", "/var/tmp/*", "/var/log/*", "/opt/*"
    ) and process.args_count == 1
  )
) and 
not (
  process.parent.args == "--force" or
  process.args in ("/usr/games/lolcat", "/usr/bin/screenfetch") or
  process.parent.name == "system-crash-notification"
)
```



### Processes with Trailing Spaces

Branch count: 4  
Document count: 4  
Index: geneve-ut-1173

```python
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and
process.name : "* "
```



### Program Files Directory Masquerading

Branch count: 4  
Document count: 4  
Index: geneve-ut-1174

```python
process where host.os.type == "windows" and event.type == "start" and
  process.executable : (
    "C:\\*Program*Files*\\*.exe",
    "\\Device\\HarddiskVolume*\\*Program*Files*\\*.exe"
  ) and
  not process.executable : (
        "?:\\Program Files\\*.exe",
        "?:\\Program Files (x86)\\*.exe",
        "?:\\Users\\*.exe",
        "?:\\ProgramData\\*.exe",
        "?:\\Windows\\Downloaded Program Files\\*.exe",
        "?:\\Windows\\Temp\\.opera\\????????????\\CProgram?FilesOpera*\\*.exe",
        "?:\\Windows\\Temp\\.opera\\????????????\\CProgram?Files?(x86)Opera*\\*.exe"
  ) and
  not (
    /* Crowdstrike specific exclusion as it uses NT Object paths */
    event.dataset == "crowdstrike.fdr" and
      process.executable : (
        "\\Device\\HarddiskVolume*\\Program Files\\*.exe",
        "\\Device\\HarddiskVolume*\\Program Files (x86)\\*.exe",
        "\\Device\\HarddiskVolume*\\Users\\*.exe",
        "\\Device\\HarddiskVolume*\\ProgramData\\*.exe",
        "\\Device\\HarddiskVolume*\\Windows\\Downloaded Program Files\\*.exe",
        "\\Device\\HarddiskVolume*\\Windows\\Temp\\.opera\\????????????\\CProgram?FilesOpera*\\*.exe",
        "\\Device\\HarddiskVolume*\\Windows\\Temp\\.opera\\????????????\\CProgram?Files?(x86)Opera*\\*.exe"
      )
  )
```



### Prompt for Credentials with Osascript

Branch count: 24  
Document count: 24  
Index: geneve-ut-1175

```python
process where event.action == "exec" and host.os.type == "macos" and
 process.name == "osascript" and process.args == "-e" and process.command_line like~ ("*osascript*display*dialog*password*", "*osascript*display*dialog*passphrase*", "*osascript*display*dialog*authenticate*", "*pass*display*dialog*") and
 not (process.parent.executable == "/usr/bin/sudo" and process.command_line like~ "*Encryption Key Escrow*") and
 not (process.command_line like~ "*-e with timeout of 3600 seconds*" and user.id like "0" and process.parent.executable == "/bin/bash") and
 not process.parent.command_line like "sudo*" and
 not process.Ext.effective_parent.executable like~
                                               ("/usr/local/jamf/*",
                                                "/Library/Intune/Microsoft Intune Agent.app/Contents/MacOS/IntuneMdmDaemon",
                                                "/Library/Application Support/Mosyle/MosyleMDM.app/Contents/MacOS/MosyleMDM",
                                                "/Applications/NinjaRMMAgent/programfiles/ninjarmm-macagent",
                                                "/Applications/Karabiner-Elements.app/Contents/MacOS/Karabiner-Elements",
                                                "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon",
                                                "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfManagementService.app/Contents/MacOS/JamfManagementService")
```



### Proxy Execution via Console Window Host

Branch count: 17  
Document count: 17  
Index: geneve-ut-1176

```python
process where host.os.type == "windows" and event.type == "start" and
 process.name : "conhost.exe" and process.args : "--headless" and
  process.command_line : ("*powershell*", "*cmd *", "*cmd.exe *", "*script*", "*mshta*", "*curl *", "*curl.exe *", "*^*^*^*", "*.bat*", "*.cmd*", "*schtasks*", "*@SSL*", "*http*", "* \\\\*", "*.vbs*", "*.js*", "*mhsta*")
```



### Proxy Execution via Windows OpenSSH

Branch count: 24  
Document count: 24  
Index: geneve-ut-1177

```python
process where host.os.type == "windows" and event.type == "start" and process.name : ("ssh.exe", "sftp.exe") and
 process.command_line : ("*Command=*powershell*", "*schtasks*", "*Command=*@echo off*", "*Command=*http*", "*Command=*mshta*",  "*Command=*msiexec*",
                          "*Command=*cmd /c*", "*Command=*cmd.exe*", "*Command=\"cmd /c*", "*LocalCommand=scp*&&*", "*LocalCommand=?scp*&&*", "*Command=*script*")
```



### Proxy Shell Execution via Busybox

Branch count: 72  
Document count: 72  
Index: geneve-ut-1178

```python
process where host.os.type == "linux" and  event.type == "start" and event.action == "exec" and process.parent.name == "busybox" and
process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
process.command_line in ("bash", "bash-", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
not (
  process.args == "-c" or
  process.parent.args : (
    "crond", "/usr/sbin/crond", "/local-registrator.sh", "/var/atlassian/application-data/bamboo-agent*"
  ) or
  process.parent.command_line in (
    "sh /readonly-config/fix-split-brain.sh",
    "/bin/sh -c /health-check.sh || bash -c 'kill -s 15 $(pidof siridb-server) && (sleep 10; kill -s 9 $(pidof siridb-server))'"
  ) or
  process.command_line == "bash /etc/kafka/docker/run" or
  process.parent.command_line like (
    "/bin/sh -c apk add*", "/bin/sh -c crm-cron-enabled*", "udhcpc -n -p /run/udhcpc.*", "flock -x*"
  ) or
  process.working_directory == "/usr/share/grafana"
)
```



### ProxyChains Activity

Branch count: 6  
Document count: 6  
Index: geneve-ut-1179

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "proxychains"
```



### PsExec Network Connection

Branch count: 1  
Document count: 2  
Index: geneve-ut-1180

```python
sequence by process.entity_id
  [process where host.os.type == "windows" and process.name : "PsExec.exe" and event.type == "start" and

   /* This flag suppresses the display of the license dialog and may
      indicate that psexec executed for the first time in the machine */
   process.args : "-accepteula" and

   not process.executable : ("?:\\ProgramData\\Docusnap\\Discovery\\discovery\\plugins\\17\\Bin\\psexec.exe",
                             "?:\\Docusnap 11\\Bin\\psexec.exe",
                             "?:\\Program Files\\Docusnap X\\Bin\\psexec.exe",
                             "?:\\Program Files\\Docusnap X\\Tools\\dsDNS.exe") and
   not process.parent.executable : "?:\\Program Files (x86)\\Cynet\\Cynet Scanner\\CynetScanner.exe"]
  [network where host.os.type == "windows" and process.name : "PsExec.exe"]
```



### Python Path File (pth) Creation

Branch count: 12  
Document count: 12  
Index: geneve-ut-1181

```python
file where host.os.type == "linux" and event.action == "creation" and file.extension == "pth" and
file.path like (
  "/usr/local/lib/python*/dist-packages/*", 
  "/usr/lib/python*/dist-packages/*",
  "/usr/local/lib/python*/site-packages/*",
  "/usr/lib/python*/site-packages/*",
  "/home/*/.local/lib/python*/site-packages/*",
  "/opt/*/lib/python*/site-packages/*"
) and process.executable != null and not (
  process.executable in (
    "/usr/local/bin/pip2", "/usr/bin/restic", "/usr/bin/pacman", "/usr/bin/dockerd", "/usr/local/bin/pip3",
    "/usr/bin/pip3", "/usr/local/bin/pip", "/usr/bin/pip", "/usr/bin/podman", "/usr/local/bin/poetry",
    "/usr/bin/poetry", "/usr/bin/pamac-daemon", "/opt/venv/bin/pip", "/usr/bin/dnf", "./venv/bin/pip",
    "/usr/bin/dnf5", "/bin/dnf5", "/bin/pip", "/bin/podman", "./usr/bin/podman", "/kaniko/executor", "/dev/fd/3",
    "/opt/SolarWinds/Agent/bin/Plugins/Discovery/SolarWinds.Agent.Discovery.Plugin", "/usr/bin/crio",
    "/opt/splunk/bin/splunkd", "/opt/Tanium/TaniumClient/TaniumCX"
  ) or
  process.executable like (
    "/usr/bin/python*", "/usr/local/bin/python*", "/opt/venv/bin/python*",
    "/nix/store/*libexec/docker/dockerd", "/snap/docker/*dockerd"
  ) or
  (
    process.name like ("python*", "platform-python*", "conda", "virtualenv", "cp", "pip*", "uv") and
    file.name in ("distutils-precedence.pth", "_virtualenv.pth")
  )
)
```



### Python Site or User Customize File Creation

Branch count: 7  
Document count: 7  
Index: geneve-ut-1182

```python
file where host.os.type == "linux" and event.type == "creation" and process.executable != null and
file.path like (
  "/usr/lib/python*/sitecustomize.py",
  "/usr/local/lib/python*/sitecustomize.py",
  "/usr/lib/python*/dist-packages/sitecustomize.py",
  "/usr/local/lib/python*/dist-packages/sitecustomize.py",
  "/opt/*/lib/python*/sitecustomize.py",
  "/home/*/.local/lib/python*/site-packages/usercustomize.py",
  "/home/*/.config/python/usercustomize.py"
) and not (
  process.executable in (
    "/usr/local/bin/pip2", "/usr/bin/restic", "/usr/bin/pacman", "/usr/bin/dockerd", "/usr/local/bin/pip3",
    "/usr/bin/pip3", "/usr/local/bin/pip", "/usr/bin/pip", "/usr/bin/podman", "/usr/local/bin/poetry",
    "/usr/bin/poetry", "/usr/bin/pamac-daemon", "./venv/bin/pip", "./usr/bin/podman",
    "/opt/miniforge3/bin/mamba", "/usr/sbin/dockerd", "/opt/conda/_conda", "/kaniko/executor",
    "/usr/local/bin/dockerd", "/usr/bin/crio", "/usr/lib/systemd/systemd-executor"
  ) or
  process.executable like~ (
    "/usr/bin/python*", "/usr/local/bin/python*", "/opt/venv/bin/python*",
    "/nix/store/*libexec/docker/dockerd", "/snap/docker/*dockerd"
  )
)
```



### Quarantine Attrib Removed by Unsigned or Untrusted Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-1183

```python
file where event.action == "extended_attributes_delete" and host.os.type == "macos" and process.executable != null and
 (process.code_signature.trusted == false or process.code_signature.exists == false) and 
 not process.executable like ("/usr/bin/xattr",
                              "/System/*",
                              "/private/tmp/KSInstallAction.*/*/Install Google Software Update.app/Contents/Helpers/ksinstall",
                              "/Applications/CEWE Fotoschau.app/Contents/MacOS/FotoPlus",
                              "/Applications/.com.bomgar.scc.*/Remote Support Customer Client.app/Contents/MacOS/sdcust") and 
 not file.path like "/private/var/folders/*"
```



### RDP Enabled via Registry

Branch count: 2  
Document count: 2  
Index: geneve-ut-1186

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : "fDenyTSConnections" and
  registry.data.strings : ("0", "0x00000000") and
  not process.executable : (
        "?:\\Windows\\System32\\SystemPropertiesRemote.exe",
        "?:\\Windows\\System32\\SystemPropertiesComputerName.exe",
        "?:\\Windows\\System32\\SystemPropertiesAdvanced.exe",
        "?:\\Windows\\System32\\SystemSettingsAdminFlows.exe",
        "?:\\Windows\\WinSxS\\*\\TiWorker.exe",
        "?:\\Windows\\system32\\svchost.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\SystemPropertiesRemote.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\SystemPropertiesComputerName.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\SystemPropertiesAdvanced.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\SystemSettingsAdminFlows.exe",
        "\\Device\\HarddiskVolume*\\Windows\\WinSxS\\*\\TiWorker.exe",
        "\\Device\\HarddiskVolume*\\Windows\\system32\\svchost.exe"
  )
```



### ROT Encoded Python Script Execution

Branch count: 4  
Document count: 8  
Index: geneve-ut-1187

```python
sequence by process.entity_id with maxspan=1m
 [process where host.os.type in ("windows", "macos") and event.type == "start" and process.name : "python*"]
 [file where host.os.type in ("windows", "macos") and
  event.action != "deletion" and process.name : "python*" and file.name : "rot_??.cpython-*.pyc*"]
```



### Ransomware - Detected - Elastic Defend

Branch count: 2  
Document count: 2  
Index: geneve-ut-1191

```python
event.kind : alert and event.code : ransomware and (event.type : allowed or (event.type: denied and event.outcome: failure))
```



### Ransomware - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-1192

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:ransomware_event or endgame.event_subtype_full:ransomware_event)
```



### Ransomware - Prevented - Elastic Defend

Branch count: 1  
Document count: 1  
Index: geneve-ut-1193

```python
event.kind : alert and event.code : ransomware and event.type : denied and event.outcome : success
```



### Ransomware - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-1194

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:ransomware_event or endgame.event_subtype_full:ransomware_event)
```



### Registry Persistence via AppCert DLL

Branch count: 1  
Document count: 1  
Index: geneve-ut-1204

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : "*\\SYSTEM\\*ControlSet*\\Control\\Session Manager\\AppCertDLLs\\*"
```



### Registry Persistence via AppInit DLL

Branch count: 1  
Document count: 1  
Index: geneve-ut-1205

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : "AppInit_Dlls" and
  not process.executable : (
     "?:\\Windows\\System32\\DriverStore\\FileRepository\\*\\Display.NvContainer\\NVDisplay.Container.exe",
     "?:\\Windows\\System32\\msiexec.exe",
     "?:\\Windows\\SysWOW64\\msiexec.exe",
     "?:\\Program Files\\Commvault\\Base\\cvd.exe",
     "?:\\Program Files\\Commvault\\ContentStore*\\Base\\cvd.exe",
     "?:\\Program Files (x86)\\Commvault\\Base\\cvd.exe",
     "?:\\Program Files (x86)\\Commvault\\ContentStore*\\Base\\cvd.exe",
     "?:\\Program Files\\NVIDIA Corporation\\Display.NvContainer\\NVDisplay.Container.exe",

     /* Crowdstrike specific condition as it uses NT Object paths */
     "\\Device\\HarddiskVolume*\\Windows\\System32\\DriverStore\\FileRepository\\*\\Display.NvContainer\\NVDisplay.Container.exe",
     "\\Device\\HarddiskVolume*\\Windows\\System32\\msiexec.exe",
     "\\Device\\HarddiskVolume*\\Windows\\SysWOW64\\msiexec.exe",
     "\\Device\\HarddiskVolume*\\Program Files\\Commvault\\Base\\cvd.exe",
     "\\Device\\HarddiskVolume*\\Program Files\\Commvault\\ContentStore*\\Base\\cvd.exe",
     "\\Device\\HarddiskVolume*\\Program Files (x86)\\Commvault\\Base\\cvd.exe",
     "\\Device\\HarddiskVolume*\\Program Files (x86)\\Commvault\\ContentStore*\\Base\\cvd.exe",
     "\\Device\\HarddiskVolume*\\Program Files\\NVIDIA Corporation\\Display.NvContainer\\NVDisplay.Container.exe"
  )
  /*
    Full registry key path omitted due to data source variations:
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls"
    "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls"
  */
```



### Remote Desktop Enabled in Windows Firewall by Netsh

Branch count: 18  
Document count: 18  
Index: geneve-ut-1207

```python
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "netsh.exe" or ?process.pe.original_file_name == "netsh.exe") and
 process.args : ("localport=3389", "RemoteDesktop", "group=\"remote desktop\"") and
 process.args : ("action=allow", "enable=Yes", "enable")
```



### Remote Desktop File Opened from Suspicious Path

Branch count: 6  
Document count: 6  
Index: geneve-ut-1208

```python
process where host.os.type == "windows" and event.type == "start" and
 process.name : "mstsc.exe" and
 process.args : ("?:\\Users\\*\\Downloads\\*.rdp",
                 "?:\\Users\\*\\AppData\\Local\\Temp\\Temp?_*.rdp",
                 "?:\\Users\\*\\AppData\\Local\\Temp\\7z*.rdp",
                 "?:\\Users\\*\\AppData\\Local\\Temp\\Rar$*\\*.rdp",
                 "?:\\Users\\*\\AppData\\Local\\Temp\\BNZ.*.rdp",
                 "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\*.rdp")
```



### Remote Execution via File Shares

Branch count: 48  
Document count: 96  
Index: geneve-ut-1209

```python
sequence with maxspan=1m
  [file where host.os.type == "windows" and event.type in ("creation", "change") and 
   process.pid == 4 and (file.extension : "exe" or file.Ext.header_bytes : "4d5a*")] by host.id, file.path
  [process where host.os.type == "windows" and event.type == "start" and
    not (
      (
        process.code_signature.trusted == true and
        process.code_signature.subject_name : (
              "Veeam Software Group GmbH",
              "Elasticsearch, Inc.",
              "PDQ.com Corporation",
              "CrowdStrike, Inc.",
              "Microsoft Windows Hardware Compatibility Publisher",
              "ZOHO Corporation Private Limited",
              "BeyondTrust Corporation", 
              "CyberArk Software Ltd.", 
              "Sophos Ltd"
        )
      ) or
      (
        process.executable : (
          "?:\\Windows\\ccmsetup\\ccmsetup.exe",
          "?:\\Windows\\SoftwareDistribution\\Download\\Install\\AM_Delta*.exe",
          "?:\\Windows\\CAInvokerService.exe"
        ) and process.code_signature.trusted == true
      ) or
      (
        process.executable : "G:\\SMS_*\\srvboot.exe" and 
        process.code_signature.trusted == true and process.code_signature.subject_name : "Microsoft Corporation"
      )
    )
  ] by host.id, process.executable
```



### Remote File Copy via TeamViewer

Branch count: 22  
Document count: 22  
Index: geneve-ut-1211

```python
file where host.os.type == "windows" and event.type == "creation" and process.name : "TeamViewer.exe" and
  file.extension : ("exe", "dll", "scr", "com", "bat", "ps1", "vbs", "vbe", "js", "wsh", "hta") and
  not 
  (
    file.path : (
      "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\*.js",
      "?:\\Users\\*\\AppData\\Local\\Temp\\TeamViewer\\update.exe",
      "?:\\Users\\*\\AppData\\Local\\Temp\\?\\TeamViewer\\update.exe",
      "?:\\Users\\*\\AppData\\Local\\TeamViewer\\CustomConfigs\\???????\\TeamViewer_Resource_??.dll",
      "?:\\Users\\*\\AppData\\Local\\TeamViewer\\CustomConfigs\\???????\\TeamViewer*.exe"
    ) and process.code_signature.trusted == true
  )
```



### Remote File Download via Desktopimgdownldr Utility

Branch count: 2  
Document count: 2  
Index: geneve-ut-1213

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "desktopimgdownldr.exe" or ?process.pe.original_file_name == "desktopimgdownldr.exe") and
  process.args : "/lockscreenurl:http*"
```



### Remote File Download via MpCmdRun

Branch count: 2  
Document count: 2  
Index: geneve-ut-1214

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "MpCmdRun.exe" or ?process.pe.original_file_name == "MpCmdRun.exe") and
   process.args : "-DownloadFile" and process.args : "-url" and process.args : "-path"
```



### Remote File Download via Script Interpreter

Branch count: 8  
Document count: 16  
Index: geneve-ut-1216

```python
sequence by host.id, process.entity_id
  [network where host.os.type == "windows" and process.name : ("wscript.exe", "cscript.exe") and network.protocol != "dns" and
   network.direction : ("outgoing", "egress") and network.type == "ipv4" and destination.ip != "127.0.0.1"
  ]
  [file where host.os.type == "windows" and event.type == "creation" and file.extension : ("exe", "dll")]
```



### Remote GitHub Actions Runner Registration

Branch count: 12  
Document count: 12  
Index: geneve-ut-1217

```python
process where event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
 process.name in ("Runner.Listener", "Runner.Listener.exe") and
 process.args == "configure" and process.args == "--url" and process.args == "--token"
```



### Remote SSH Login Enabled via systemsetup Command

Branch count: 2  
Document count: 2  
Index: geneve-ut-1218

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.name == "systemsetup" and
 process.args like~ "-setremotelogin" and 
 process.args like~ "on" and
 process.parent.executable != null and
 not process.parent.executable like ("/usr/local/jamf/bin/jamf", "/usr/libexec/xpcproxy", "/usr/bin/sudo")
```



### Remote Scheduled Task Creation

Branch count: 2  
Document count: 4  
Index: geneve-ut-1219

```python
/* Task Scheduler service incoming connection followed by TaskCache registry modification  */

sequence by host.id, process.entity_id with maxspan = 1m
   [network where host.os.type == "windows" and process.name : "svchost.exe" and
   network.direction : ("incoming", "ingress") and source.port >= 49152 and destination.port >= 49152 and
   source.ip != "127.0.0.1" and source.ip != "::1" and source.ip != null
   ]
   [registry where host.os.type == "windows" and event.type == "change" and registry.value : "Actions" and
    registry.path : "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions"]
```



### Remote Scheduled Task Creation via RPC

Branch count: 1  
Document count: 1  
Index: geneve-ut-1220

```python
iam where host.os.type == "windows" and event.action == "scheduled-task-created" and
 winlog.event_data.RpcCallClientLocality : "0" and winlog.event_data.ClientProcessId : "0"
```



### Remote Windows Service Installed

Branch count: 1  
Document count: 2  
Index: geneve-ut-1222

```python
sequence by winlog.logon.id, winlog.computer_name with maxspan=1m
[authentication where host.os.type == "windows" and event.action == "logged-in" and winlog.logon.type : "Network" and
 event.outcome == "success" and source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1"]
[iam where host.os.type == "windows" and event.action == "service-installed" and
 not winlog.event_data.SubjectLogonId : "0x3e7" and
 not winlog.event_data.ServiceFileName :
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
                "?:\\Windows\\System32\\taskhostex.exe")]
```



### Remote XSL Script Execution via COM

Branch count: 16  
Document count: 32  
Index: geneve-ut-1223

```python
sequence with maxspan=1m
 [library where host.os.type == "windows" and dll.name : "msxml3.dll" and
  process.name : ("winword.exe", "excel.exe", "powerpnt.exe", "mspub.exe")] by process.entity_id
 [process where host.os.type == "windows" and event.action == "start" and
  process.parent.name : ("winword.exe", "excel.exe", "powerpnt.exe", "mspub.exe") and
  not process.executable :
        ("?:\\Windows\\System32\\WerFault.exe",
         "?:\\Windows\\SysWoW64\\WerFault.exe",
         "?:\\windows\\splwow64.exe",
         "?:\\Windows\\System32\\conhost.exe",
         "?:\\Program Files\\*.exe",
         "?:\\Program Files (x86)\\*exe")] by process.parent.entity_id
```



### Remotely Started Services via RPC

Branch count: 4  
Document count: 8  
Index: geneve-ut-1224

```python
sequence with maxspan=1s
   [network where host.os.type == "windows" and process.name : "services.exe" and
      network.direction : ("incoming", "ingress") and network.transport == "tcp" and
      source.port >= 49152 and destination.port >= 49152 and source.ip != "127.0.0.1" and source.ip != "::1"
   ] by host.id, process.entity_id
   [process where host.os.type == "windows" and 
       event.type == "start" and process.parent.name : "services.exe" and
       not (process.executable : "?:\\Windows\\System32\\msiexec.exe" and process.args : "/V") and
       not process.executable : (
                "?:\\Pella Corporation\\OSCToGPAutoService\\OSCToGPAutoSvc.exe",
                "?:\\Pella Corporation\\Pella Order Management\\GPAutoSvc.exe",
                "?:\\Pella Corporation\\Pella Order Management\\GPAutoSvc.exe",
                "?:\\Program Files (x86)\\*.exe",
                "?:\\Program Files\\*.exe",
                "?:\\Windows\\ADCR_Agent\\adcrsvc.exe",
                "?:\\Windows\\AdminArsenal\\PDQ*.exe",
                "?:\\Windows\\CAInvokerService.exe",
                "?:\\Windows\\ccmsetup\\ccmsetup.exe",
                "?:\\Windows\\eset-remote-install-service.exe",
                "?:\\Windows\\ProPatches\\Scheduler\\STSchedEx.exe",
                "?:\\Windows\\PSEXESVC.EXE",
                "?:\\Windows\\RemoteAuditService.exe",
                "?:\\Windows\\servicing\\TrustedInstaller.exe",
                "?:\\Windows\\System32\\certsrv.exe",
                "?:\\Windows\\System32\\sppsvc.exe",
                "?:\\Windows\\System32\\srmhost.exe",
                "?:\\Windows\\System32\\svchost.exe",
                "?:\\Windows\\System32\\taskhostex.exe",
                "?:\\Windows\\System32\\upfc.exe",
                "?:\\Windows\\System32\\vds.exe",
                "?:\\Windows\\System32\\VSSVC.exe",
                "?:\\Windows\\System32\\wbem\\WmiApSrv.exe",
                "?:\\Windows\\SysWOW64\\NwxExeSvc\\NwxExeSvc.exe",
                "?:\\Windows\\Veeam\\Backup\\VeeamDeploymentSvc.exe",
                "?:\\Windows\\VeeamLogShipper\\VeeamLogShipper.exe",
                "?:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe"
       )] by host.id, process.parent.entity_id
```



### Renamed Automation Script Interpreter

Branch count: 6  
Document count: 6  
Index: geneve-ut-1225

```python
process where host.os.type == "windows" and event.type == "start" and
  (
   (process.pe.original_file_name : "AutoIt*.exe" and not process.name : "AutoIt*.exe") or
   (process.pe.original_file_name == "AutoHotkey.exe" and not process.name : ("AutoHotkey*.exe", "InternalAHK.exe")) or
   (process.pe.original_file_name == "KIX32.EXE" and not process.name : "KIX*.exe" and process.executable : ("?:\\Users\\*.exe", "?:\\ProgramData\\*.exe", "\\Device\\HarddiskVolume*\\Users\\*.exe", "\\Device\\HarddiskVolume*\\ProgramData\\*.exe"))
   )
```



### Renaming of OpenSSH Binaries

Branch count: 5  
Document count: 5  
Index: geneve-ut-1227

```python
event.category:file and host.os.type:linux and event.type:change and 
process.name:(* and not (
  dnf or dnf-automatic or dpkg or yum or rpm or yum-cron or anacron or platform-python* or
  apk or ansible-admin or systemd or python* or yum or nix-daemon or nix
  )
) and 
(file.path:(/usr/bin/scp or 
              /usr/bin/sftp or 
              /usr/bin/ssh or 
              /usr/sbin/sshd) or 
file.name:libkeyutils.so) and
not (
  process.executable:(
    /usr/share/elasticsearch/* or "/usr/bin/microdnf" or "/usr/bin/dnf5" or "/usr/sbin/gdm" or
    "/usr/libexec/packagekitd" or "/usr/libexec/zypp/zypp-rpm" or "/home/sa-ansible"
  ) or
  file.Ext.original.name:"sshd.session-split"
)
```



### Root Certificate Installation

Branch count: 12  
Document count: 12  
Index: geneve-ut-1228

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
process.name in ("update-ca-trust", "update-ca-certificates") and not (
  process.parent.name like (
    "ca-certificates.postinst", "ca-certificates-*.trigger", "pacman", "pamac-daemon", "autofirma.postinst",
    "ipa-client-install", "su", "platform-python", "python*", "kesl", "execd", "systemd", "flock"
  ) or
  process.parent.args like "/var/tmp/rpm*" or
  (process.parent.name in ("sh", "bash", "zsh") and process.args == "-e") or
  process.parent.executable in (
    "/app/update-cert-trust.sh", "/opt/puppetlabs/puppet/bin/puppet", "/opt/puppetlabs/puppet/bin/ruby",
    "/start-haproxy", "/usr/bin/entrypoint.sh", "/usr/bin/crun"
  ) or
  process.parent.args like (
    "/entrypoint.sh", "/entrypoint", "./bootstrap-RHEL*", "lib/apk/exec/ca-certificates-*trigger"
  ) or
  ?process.working_directory == "/var/lib/rancher"
)
```



### Root Network Connection via GDB CAP_SYS_PTRACE

Branch count: 2  
Document count: 4  
Index: geneve-ut-1229

```python
sequence by host.id, process.entry_leader.entity_id with maxspan=30s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name == "gdb" and
   (process.thread.capabilities.effective : "CAP_SYS_PTRACE" or process.thread.capabilities.permitted : "CAP_SYS_PTRACE") and
   user.id != "0"]
  [network where host.os.type == "linux" and event.action == "connection_attempted" and event.type == "start" and
   process.name != null and user.id == "0"]
```



### Roshal Archive (RAR) or PowerShell File Downloaded from the Internet

Branch count: 48  
Document count: 48  
Index: geneve-ut-1230

```python
(event.dataset: (network_traffic.http or network_traffic.tls) or
  (event.category: (network or network_traffic) and network.protocol: http)) and
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



### SELinux Configuration Creation or Renaming

Branch count: 4  
Document count: 4  
Index: geneve-ut-1231

```python
file where host.os.type == "linux" and event.action in ("creation", "file_create_event", "rename", "file_rename_event")
and file.path : "/etc/selinux/config" and not (
  process.name in ("dockerd", "platform-python") or
  process.executable like (
    "/usr/libexec/platform-python*", "/dev/fd/3", "/usr/bin/podman", "/usr/local/cpanel/3rdparty/perl/*/bin/perl",
    "/kaniko/executor", "/usr/lib/systemd/systemd", "/usr/bin/insights-client", "/bin/podman"
  )
)
```



### SIP Provider Modification

Branch count: 32  
Document count: 32  
Index: geneve-ut-1232

```python
registry where host.os.type == "windows" and event.type == "change" and registry.value : ("Dll", "$Dll") and
  registry.path: (
    "*\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllPutSignedDataMsg\\{*}\\Dll",
    "*\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllPutSignedDataMsg\\{*}\\Dll",
    "*\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{*}\\$Dll",
    "*\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{*}\\$Dll"
    ) and
  registry.data.strings:"*.dll" and
  not (process.name : "msiexec.exe" and registry.data.strings : "mso.dll") and
  not (process.name : "regsvr32.exe" and registry.data.strings == "WINTRUST.DLL")
```



### SMTP on Port 26/TCP

Branch count: 4  
Document count: 4  
Index: geneve-ut-1235

```python
(event.dataset: (network_traffic.flow or zeek.smtp) or event.category:(network or network_traffic)) and network.transport:tcp and destination.port:26
```



### SOCKS Traffic from an Unusual Process

Branch count: 4  
Document count: 8  
Index: geneve-ut-1236

```python
sequence by source.port, source.ip, destination.ip with maxspan=1m
 [network where event.dataset == "fortinet_fortigate.log" and event.action == "signature" and network.application in ("SOCKS4", "SOCKS5")]
 [network where event.module == "endpoint" and event.action in ("disconnect_received", "connection_attempted")]
```



### SSH Authorized Key File Activity Detected via Defend for Containers

Branch count: 4  
Document count: 4  
Index: geneve-ut-1237

```python
file where host.os.type == "linux" and event.type in ("change", "creation") and
file.name in ("authorized_keys", "authorized_keys2") and
process.interactive == true and container.id like "*"
```



### SSH Authorized Keys File Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-1239

```python
file where host.os.type == "linux" and event.type == "deletion" and file.name in ("authorized_keys", "authorized_keys2") and
not (
  process.executable in (
    "/usr/bin/google_guest_agent", "/usr/bin/dockerd", "/bin/dockerd", "/usr/bin/containerd"
  ) or
  process.executable like~ "/nix/store/*" or
  file.path like~ ("*backup*", "*ansible*", "*puppet*")
)
```



### SSH Key Generated via ssh-keygen

Branch count: 6  
Document count: 6  
Index: geneve-ut-1240

```python
file where host.os.type == "linux" and event.action in ("creation", "file_create_event") and
process.executable == "/usr/bin/ssh-keygen" and file.path : ("/home/*/.ssh/*", "/root/.ssh/*", "/etc/ssh/*") and
not file.name : "known_hosts.*"
```



### SSL Certificate Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-1241

```python
file where host.os.type == "linux" and event.type == "deletion" and process.executable != null and
file.path : "/etc/ssl/certs/*" and file.extension in ("pem", "crt") and
not (
  process.name in ("dockerd", "pacman") or
  process.executable in (
    "/kaniko/executor", "/usr/sbin/update-ca-certificates", "/usr/bin/gnurm", "/usr/bin/podman",
    "/usr/local/bin/executor", "/opt/kaniko/executor", "/.envbuilder/bin/envbuilder", "/opt/kaspersky/kesl/libexec/kesl"
  )
)
```



### SUID/SGUID Enumeration Detected

Branch count: 36  
Document count: 36  
Index: geneve-ut-1243

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name == "find" and process.args : "-perm" and process.args : (
  "/6000", "-6000", "/4000", "-4000", "/2000", "-2000", "/u=s", "-u=s", "/g=s", "-g=s", "/u=s,g=s", "/g=s,u=s"
) and not (
  user.Ext.real.id == "0" or group.Ext.real.id == "0" or process.args_count >= 12 or
  (process.args : "/usr/bin/pkexec" and process.args : "-xdev" and process.args_count == 7)
)
```



### Scheduled Task Created by a Windows Script

Branch count: 60  
Document count: 120  
Index: geneve-ut-1245

```python
sequence by host.id with maxspan = 30s
  [any where host.os.type == "windows" and 
    (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
    (?dll.name : "taskschd.dll" or file.name : "taskschd.dll") and
    process.name : ("cscript.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe")]
  [registry where host.os.type == "windows" and event.type == "change" and registry.value : "Actions" and
    registry.path : (
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions",
      "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions"
  )]
```



### Scheduled Tasks AT Command Enabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-1247

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : "EnableAt" and
  registry.data.strings : ("1", "0x00000001")
```



### ScreenConnect Server Spawning Suspicious Processes

Branch count: 9  
Document count: 9  
Index: geneve-ut-1248

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "ScreenConnect.Service.exe" and
  (process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "csc.exe") or
  ?process.pe.original_file_name in ("Cmd.Exe", "PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE"))
```



### Screensaver Plist File Modified by Unexpected Process

Branch count: 27  
Document count: 27  
Index: geneve-ut-1249

```python
file where host.os.type == "macos" and event.action == "modification" and
  file.name like~ "com.apple.screensaver.*.plist" and
   file.path like (
      "/Users/*/Library/Preferences/ByHost/*",
      "/Library/Managed Preferences/*",
      "/System/Library/Preferences/*"
      ) and
  (
    process.code_signature.trusted == false or
    process.code_signature.exists == false or

    /* common script interpreters and abused native macOS bins */
    process.name like~ (
      "curl",
      "mktemp",
      "tail",
      "funzip",
      "python*",
      "osascript",
      "perl"
      )
   ) and

  /* Filter OS processes modifying screensaver plist files */
  not process.executable like (
    "/usr/sbin/cfprefsd",
    "/usr/libexec/xpcproxy",
    "/System/Library/CoreServices/ManagedClient.app/Contents/Resources/MCXCompositor",
    "/System/Library/CoreServices/ManagedClient.app/Contents/MacOS/ManagedClient"
    )
```



### Script Interpreter Connection to Non-Standard Port

Branch count: 9  
Document count: 18  
Index: geneve-ut-1251

```python
sequence by process.entity_id with maxspan=1m
  [process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and 
    (process.name like~ "python*" or process.name in ("node", "ruby")) and 
    process.args_count == 2]
  [network where host.os.type == "macos" and event.type == "start" and 
    (process.name like~ "python*" or process.name in ("node", "ruby")) and 
    destination.domain == null and 
    not destination.port in (443, 80, 53, 22, 25, 587, 465, 8080, 8089, 8200, 9200) and 
    destination.port < 49152 and
    not cidrmatch(destination.ip, "240.0.0.0/4", "233.252.0.0/24", "224.0.0.0/4", "198.19.0.0/16", 
                  "192.18.0.0/15", "192.0.0.0/24", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", 
                  "172.16.0.0/12", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", 
                  "192.168.0.0/16", "192.88.99.0/24", "100.64.0.0/10", "192.175.48.0/24", 
                  "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "::1", "FE80::/10", "FF00::/8")]
```



### SeDebugPrivilege Enabled by a Suspicious Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-1252

```python
any where host.os.type == "windows" and event.provider: "Microsoft-Windows-Security-Auditing" and
 event.action : "Token Right Adjusted Events" and

 winlog.event_data.EnabledPrivilegeList : "SeDebugPrivilege" and

 /* exclude processes with System Integrity  */
 not winlog.event_data.SubjectUserSid : ("S-1-5-18", "S-1-5-19", "S-1-5-20") and

 not winlog.event_data.ProcessName : (
        "?:\\Program Files (x86)\\*",
        "?:\\Program Files\\*",
        "?:\\Users\\*\\AppData\\Local\\Temp\\*-*\\DismHost.exe",
        "?:\\Windows\\System32\\auditpol.exe",
        "?:\\Windows\\System32\\cleanmgr.exe",
        "?:\\Windows\\System32\\lsass.exe",
        "?:\\Windows\\System32\\mmc.exe",
        "?:\\Windows\\System32\\MRT.exe",
        "?:\\Windows\\System32\\msiexec.exe",
        "?:\\Windows\\System32\\sdiagnhost.exe",
        "?:\\Windows\\System32\\ServerManager.exe",
        "?:\\Windows\\System32\\taskhostw.exe",
        "?:\\Windows\\System32\\wbem\\WmiPrvSe.exe",
        "?:\\Windows\\System32\\WerFault.exe",
        "?:\\Windows\\SysWOW64\\msiexec.exe",
        "?:\\Windows\\SysWOW64\\wbem\\WmiPrvSe.exe",
        "?:\\Windows\\SysWOW64\\WerFault.exe",
        "?:\\Windows\\WinSxS\\*"
    )
```



### Searching for Saved Credentials via VaultCmd

Branch count: 2  
Document count: 2  
Index: geneve-ut-1253

```python
process where host.os.type == "windows" and event.type == "start" and
  (?process.pe.original_file_name:"vaultcmd.exe" or process.name:"vaultcmd.exe") and
  process.args:"/list*"
```



### Security File Access via Common Utilities

Branch count: 672  
Document count: 672  
Index: geneve-ut-1254

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.name in ("cat", "less", "more", "strings", "find", "xargs") and
process.parent.executable != null and 
process.args like (
  "/etc/security/*", "/etc/pam.d/*", "/etc/login.defs", "/lib/security/*", "/lib64/security/*",
  "/usr/lib/security/*", "/usr/lib64/security/*", "/usr/lib/x86_64-linux-gnu/security/*",
  "/home/*/.aws/credentials", "/home/*/.aws/config", "/home/*/.config/gcloud/*credentials.json",
  "/home/*/.config/gcloud/configurations/config_default", "/home/*/.azure/accessTokens.json",
  "/home/*/.azure/azureProfile.json"
) and not (
  process.parent.name in ("wazuh-modulesd", "lynis") or
  process.command_line in ("cat /etc/login.defs" , "cat /home/asterisk/.aws/credentials") or
  ?process.parent.command_line in (
    "/bin/sh /usr/sbin/lynis audit system --cronjob",
    "/usr/bin/find -L /etc/security/limits.conf /etc/security/limits.d -type f -exec /usr/bin/cat {} ;",
    "/usr/bin/find /etc/security/limits.conf /etc/security/limits.d -type f -exec /usr/bin/cat {} ;"
  ) or
  ?process.parent.args in ("/opt/imperva/ragent/bin/get_sys_resources.sh", "/usr/sbin/lynis", "./terra_linux.sh") or
  process.args == "/usr/bin/coreutils" or
  (process.parent.name == "pwsh" and process.parent.command_line like "*Evaluate-STIG*") or
  ?process.parent.executable == "/usr/sap/audit_scripts/auto_audit_gral.sh"
)
```



### Security Software Discovery using WMIC

Branch count: 2  
Document count: 2  
Index: geneve-ut-1255

```python
process where host.os.type == "windows" and event.type == "start" and
(process.name : "wmic.exe" or ?process.pe.original_file_name : "wmic.exe") and
process.args : "/namespace:\\\\root\\SecurityCenter2" and process.args : "Get"
```



### Security Software Discovery via Grep

Branch count: 480  
Document count: 480  
Index: geneve-ut-1256

```python
process where event.type == "start" and
process.name : ("grep", "egrep", "pgrep") and user.id != "0" and
 not process.parent.executable : ("/Library/Application Support/*", "/opt/McAfee/agent/scripts/ma") and
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
          "elastic-endpoint*",
          "falcond*",
          "SentinelOne*",
          "CbOsxSensorService*",
          "CbDefense*",
          "WhatsYourSign*",
          "reikey*",
          "OverSight*",
          "KextViewr*",
          "Netiquette*",
          "processmonitor*",
          "filemonitor*"
          ) and
   not (
     (process.args : "Avast" and process.args : "Passwords") or
     (process.args == "osquery.conf") or 
     (process.parent.args : "/opt/McAfee/agent/scripts/ma" and process.parent.args : "checkhealth") or
     (process.command_line : (
       "grep ESET Command-line scanner, version %s -A2",
       "grep -i McAfee Web Gateway Core version:",
       "grep --color=auto ESET Command-line scanner, version %s -A2"
       )
     ) or
     (process.parent.command_line : (
       """sh -c printf "command_start_%s"*; perl -pe 's/[^ -~]/\n/g' < /opt/eset/esets/sbin/esets_scan | grep 'ESET Command-line scanner, version %s' -A2 | tail -1; printf "command_done_%s*""",
       """bash -c perl -pe 's/[^ -~]/\n/g' < /opt/eset/esets/sbin/esets_scan | grep 'ESET Command-line scanner, version %s' -A2 | tail -1"""
       )
     )
    )
```



### Sensitive Audit Policy Sub-Category Disabled

Branch count: 6  
Document count: 6  
Index: geneve-ut-1258

```python
event.code : "4719" and host.os.type : "windows" and
  winlog.event_data.AuditPolicyChangesDescription : "Success removed" and
  winlog.event_data.SubCategory : (
     "Logon" or
     "Audit Policy Change" or
     "Process Creation" or
     "Audit Other System Events" or
     "Audit Security Group Management" or
     "Audit User Account Management"
  )
```



### Sensitive File Access followed by Compression

Branch count: 33  
Document count: 66  
Index: geneve-ut-1259

```python
sequence by process.entity_id with maxspan=30s
  [file where host.os.type == "macos" and event.action == "open" and 
    not file.name in~ ("System.keychain", "login.keychain-db", "preferences.plist", "com.apple.TimeMachine.plist")]
  [file where host.os.type == "macos" and event.action == "modification" and 
    file.extension in ("zip", "gzip", "gz") and
    file.path like~ ("/Users/Shared/*", "/Library/WebServer/*", "/Users/*/Library/WebServer/*",
                     "/Library/Graphics/*", "/Users/*/Library/Graphics/*", "/Library/Fonts/*",
                     "/Users/*/Library/Fonts/*", "/private/var/root/Library/HTTPStorages/*",
                     "/tmp/*", "/var/tmp/*", "/private/tmp/*") and
    not file.path like~ ("/Library/Logs/CrashReporter/*", "/private/tmp/publish.*")]
```



### Sensitive Files Compression Inside A Container

Branch count: 60  
Document count: 60  
Index: geneve-ut-1262

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.entry_leader.entry_meta.type == "container" and process.name in ("zip", "tar", "gzip", "hdiutil", "7z") and
process.command_line like~ (
  "*/root/.ssh/*", "*/home/*/.ssh/*", "*/root/.bash_history*", "*/etc/hosts*", "*/root/.aws/*", "*/home/*/.aws/*",
  "*/root/.docker/*", "*/home/*/.docker/*", "*/etc/group*", "*/etc/passwd*", "*/etc/shadow*", "*/etc/gshadow*"
)
```



### Sensitive Keys Or Passwords Searched For Inside A Container

Branch count: 42  
Document count: 42  
Index: geneve-ut-1264

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.entry_leader.entry_meta.type == "container" and
process.name in ("grep", "egrep", "fgrep", "find", "locate", "mlocate") and
process.command_line like~ (
  "*BEGIN PRIVATE*", "*BEGIN OPENSSH PRIVATE*", "*BEGIN RSA PRIVATE*", "*BEGIN DSA PRIVATE*", "*BEGIN EC PRIVATE*",
  "*id_rsa*", "*id_dsa*"
)
```



### Sensitive Privilege SeEnableDelegationPrivilege assigned to a User

Branch count: 1  
Document count: 1  
Index: geneve-ut-1265

```python
event.code:4704 and host.os.type:"windows" and winlog.event_data.PrivilegeList:"SeEnableDelegationPrivilege"
```



### Sensitive Registry Hive Access via RegBack

Branch count: 6  
Document count: 6  
Index: geneve-ut-1266

```python
file where host.os.type == "windows" and 
 event.action == "open" and event.outcome == "success" and process.executable != null and 
 file.path :
      ("?:\\Windows\\System32\\config\\RegBack\\SAM",
       "?:\\Windows\\System32\\config\\RegBack\\SECURITY",
       "?:\\Windows\\System32\\config\\RegBack\\SYSTEM") and 
 not (
    user.id == "S-1-5-18" and process.executable : (
        "?:\\Windows\\system32\\taskhostw.exe", "?:\\Windows\\system32\\taskhost.exe"
    ))
```



### Service Account Namespace Read Detected via Defend for Containers

Branch count: 37  
Document count: 37  
Index: geneve-ut-1269

```python
any where host.os.type == "linux" and process.interactive == true and container.id like "*" and (
  (event.category == "file" and event.type == "change" and event.action == "open" and
  file.path in (
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/run/secrets/kubernetes.io/serviceaccount/namespace"
  )) or
  (event.category == "process" and event.type == "start" and event.action == "exec" and
  (
    process.name in ("cat", "head", "tail", "more", "less", "sed", "awk") or
    process.args in (
      "cat", "/bin/cat", "/usr/bin/cat", "/usr/local/bin/cat",
      "head", "/bin/head", "/usr/bin/head", "/usr/local/bin/head",
      "tail", "/bin/tail", "/usr/bin/tail", "/usr/local/bin/tail",
      "more", "/bin/more", "/usr/bin/more", "/usr/local/bin/more",
      "less", "/bin/less", "/usr/bin/less", "/usr/local/bin/less",
      "sed", "/bin/sed", "/usr/bin/sed", "/usr/local/bin/sed",
      "awk", "/bin/awk", "/usr/bin/awk", "/usr/local/bin/awk"
    )
  ) and process.args like "*/run/secrets/kubernetes.io/serviceaccount/namespace*"
    )
)
```



### Service Account Token or Certificate Read Detected via Defend for Containers

Branch count: 74  
Document count: 74  
Index: geneve-ut-1271

```python
any where host.os.type == "linux" and process.interactive == true and container.id like "*" and (
  (event.category == "file" and event.type == "change" and event.action == "open" and
  file.path in (
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "/run/secrets/kubernetes.io/serviceaccount/token",
    "/run/secrets/kubernetes.io/serviceaccount/ca.crt"
  )) or
  (event.category == "process" and event.type == "start" and event.action == "exec" and
  (
    process.name in ("cat", "head", "tail", "more", "less", "sed", "awk") or
    process.args in (
      "cat", "/bin/cat", "/usr/bin/cat", "/usr/local/bin/cat",
      "head", "/bin/head", "/usr/bin/head", "/usr/local/bin/head",
      "tail", "/bin/tail", "/usr/bin/tail", "/usr/local/bin/tail",
      "more", "/bin/more", "/usr/bin/more", "/usr/local/bin/more",
      "less", "/bin/less", "/usr/bin/less", "/usr/local/bin/less",
      "sed", "/bin/sed", "/usr/bin/sed", "/usr/local/bin/sed",
      "awk", "/bin/awk", "/usr/bin/awk", "/usr/local/bin/awk"
    )
  ) and process.args like (
    "*/run/secrets/kubernetes.io/serviceaccount/token*",
    "*/run/secrets/kubernetes.io/serviceaccount/ca.crt*"
  ))
)
```



### Service Command Lateral Movement

Branch count: 16  
Document count: 32  
Index: geneve-ut-1272

```python
sequence by process.entity_id with maxspan = 1m
  [process where host.os.type == "windows" and event.type == "start" and
     (process.name : "sc.exe" or process.pe.original_file_name : "sc.exe") and
      process.args : "\\\\*" and process.args : ("binPath=*", "binpath=*") and
      process.args : ("create", "config", "failure", "start")]
  [network where host.os.type == "windows" and process.name : "sc.exe" and destination.ip != "127.0.0.1"]
```



### Service Control Spawned via Script Interpreter

Branch count: 96  
Document count: 96  
Index: geneve-ut-1273

```python
/* This rule is not compatible with Sysmon due to user.id issues */

process where host.os.type == "windows" and event.type == "start" and
  (process.name : "sc.exe" or ?process.pe.original_file_name == "sc.exe") and
  process.parent.name : ("cmd.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe",
                         "wmic.exe", "mshta.exe","powershell.exe", "pwsh.exe") and
  process.args:("config", "create", "start", "delete", "stop", "pause") and
  /* exclude SYSTEM SID - look for service creations by non-SYSTEM user */
  not user.id : "S-1-5-18"
```



### Service DACL Modification via sc.exe

Branch count: 10  
Document count: 10  
Index: geneve-ut-1275

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "sc.exe" or ?process.pe.original_file_name : "sc.exe") and
  process.args : "sdset" and process.args : "*D;*" and
  process.args : ("*;IU*", "*;SU*", "*;BA*", "*;SY*", "*;WD*")
```



### Service Disabled via Registry Modification

Branch count: 8  
Document count: 8  
Index: geneve-ut-1276

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
    "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\Start",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\*\\Start"
  ) and registry.data.strings : ("3", "4") and
  not 
    (
      process.name : "services.exe" and user.id : "S-1-5-18"
    )
  and not registry.path : "HKLM\\SYSTEM\\ControlSet001\\Services\\MrxSmb10\\Start"
```



### Service Path Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-1277

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
    "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\ImagePath",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\*\\ImagePath"
  ) and not (
    process.executable : (
      "?:\\Program Files\\*.exe",
      "?:\\Program Files (x86)\\*.exe",
      "?:\\Windows\\System32\\services.exe",
      "?:\\Windows\\WinSxS\\*"
    )
  )
```



### Service Path Modification via sc.exe

Branch count: 1  
Document count: 1  
Index: geneve-ut-1278

```python
process where event.type == "start" and process.name : "sc.exe" and
  process.args : "*config*" and process.args : "*binPath*"
```



### Setcap setuid/setgid Capability Set

Branch count: 4  
Document count: 4  
Index: geneve-ut-1279

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and 
process.name == "setcap" and process.args : "cap_set?id+ep" and not (
  process.parent.name in ("jem", "vzctl") or
  process.args like "/usr/bin/new?idmap"
)
```



### Shadow File Modification by Unusual Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-1281

```python
file where host.os.type == "linux" and event.type == "change" and event.action == "rename" and
file.path == "/etc/shadow" and file.Ext.original.path != null and 
not (
  file.Ext.original.name in ("shadow+", "nshadow") or
  process.name in (
    "usermod", "useradd", "passwd", "chage", "systemd-sysusers", "chpasswd", "userdel", "adduser", "update-passwd", "perl"
  ) or
  process.executable like "/usr/libexec/platform-python*" or
  process.executable in (
    "/usr/bin/containerd", "/usr/bin/dnf", "/usr/bin/yum", "/bin/dnf", "./usr/bin/qemu-aarch64-static",
    "/usr/local/cpanel/whostmgr/bin/xml-api", "/usr/local/cpanel/whostmgr/bin/whostmgr5",
    "/usr/local/cpanel/bin/admin/Cpanel/security"
  )
)
```



### Shell Command-Line History Deletion Detected via Defend for Containers

Branch count: 60  
Document count: 60  
Index: geneve-ut-1283

```python
any where host.os.type == "linux" and event.category in ("file", "process") and process.interactive == true and container.id like "?*" and (
  (event.category == "file" and event.type == "deletion" and file.name in (".bash_history", ".sh_history",  ".zsh_history")) or
  (event.category == "process" and event.type == "start" and event.action == "exec" and (
    (
      (
        process.args in (
          "rm", "/bin/rm", "/usr/bin/rm", "/usr/local/bin/rm",
          "echo", "/bin/echo", "/usr/bin/echo", "/usr/local/bin/echo"
        ) or
        (process.args in ("ln", "/bin/ln", "/usr/bin/ln", "/usr/local/bin/ln") and process.args == "-sf" and process.args == "/dev/null") or
        (process.args in ("truncate", "/bin/truncate", "/usr/bin/truncate", "/usr/local/bin/truncate") and process.args == "-s0")
      ) and process.args like ("*.bash_history*", "*.sh_history*", "*.zsh_history*")
    ) or
    (process.name == "history" and process.args == "-c") or
    (process.args == "export" and process.args in ("HISTFILE=/dev/null", "HISTFILESIZE=0")) or
    (process.args == "unset" and process.args == "HISTFILE") or
    (process.args == "set" and process.args == "history" and process.args == "+o")
  )
 )
)
```



### Shell Configuration Creation

Branch count: 140  
Document count: 140  
Index: geneve-ut-1284

```python
file where host.os.type == "linux" and event.action == "creation" and file.path : (
  // system-wide configurations
  "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/bash.bash_logout", "/etc/zsh/*",
  "/etc/csh.cshrc", "/etc/csh.login", "/etc/fish/config.fish", "/etc/ksh.kshrc",
  // root and user configurations
  "/home/*/.profile", "/home/*/.bashrc", "/home/*/.bash_login", "/home/*/.bash_logout", "/home/*/.bash_profile",
  "/root/.profile", "/root/.bashrc", "/root/.bash_login", "/root/.bash_logout", "/root/.bash_profile",
  "/root/.bash_aliases", "/home/*/.bash_aliases", "/home/*/.zprofile", "/home/*/.zshrc", "/root/.zprofile",
  "/root/.zshrc", "/home/*/.cshrc", "/home/*/.login", "/home/*/.logout", "/root/.cshrc", "/root/.login",
  "/root/.logout", "/home/*/.config/fish/config.fish", "/root/.config/fish/config.fish", "/home/*/.kshrc",
  "/root/.kshrc"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/sbin/adduser", "/usr/sbin/useradd", "/usr/local/bin/dockerd",
    "/usr/sbin/gdm", "/usr/bin/unzip", "/usr/bin/gnome-shell", "/sbin/mkhomedir_helper", "/usr/sbin/sshd",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/bin/xfce4-session", "/usr/libexec/oddjob/mkhomedir", "/sbin/useradd",
    "/usr/lib/systemd/systemd", "/usr/sbin/crond", "/usr/bin/pamac-daemon", "/usr/sbin/mkhomedir_helper",
    "/opt/pbis/sbin/lwsmd", "/usr/sbin/oddjobd", "./usr/bin/podman", "/usr/bin/dnf5", "/bin/dnf5",
    "/usr/libexec/gnome-terminal-server", "/usr/bin/buildah", "/usr/lib/venv-salt-minion/bin/python.original"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable like (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*",
    "/usr/libexec/platform-python*", "./snap/snapd/*/usr/lib/snapd/snap-update-ns", "/opt/alt/python*/bin/python*"
  ) or
  process.executable == null or
  process.name in ("adclient", "mkhomedir_helper", "teleport", "mkhomedir", "adduser", "desktopDaemon", "executor", "crio") or
  (process.name == "sed" and file.name like "sed*") or
  (process.name == "perl" and file.name like "e2scrub_all.tmp*")
)
```



### Shell Execution via Apple Scripting

Branch count: 60  
Document count: 120  
Index: geneve-ut-1285

```python
sequence by host.id with maxspan=10s
 [process where host.os.type == "macos" and event.type in ("start", "process_started") and event.action == "exec" and process.name == "osascript" and process.args == "-e"] by process.entity_id
 [process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name in ("sh", "bash", "zsh") and process.args == "-c" and process.command_line : ("*curl*", "*pbpaste*", "*http*", "*chmod*", "*nscurl*")] by process.parent.entity_id
```



### Shortcut File Written or Modified on Startup Folder

Branch count: 162  
Document count: 162  
Index: geneve-ut-1286

```python
file where host.os.type == "windows" and event.type != "deletion" and file.extension == "lnk" and
  file.path : (
    "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*"
  ) and
  not (
    (process.name : "ONENOTE.EXE" and process.code_signature.status: "trusted" and file.name : "*OneNote.lnk") or
    (process.name : "OktaVerifySetup.exe" and process.code_signature.status: "trusted" and file.name : "Okta Verify.lnk") or
    (process.name : "OneLaunch.exe" and process.code_signature.status: "trusted" and file.name : "OneLaunch*.lnk") or
    (process.name : "APPServerClient.exe" and process.code_signature.status: "trusted" and file.name : "Parallels Client.lnk")
  )
```



### Signed Proxy Execution via MS Work Folders

Branch count: 1  
Document count: 1  
Index: geneve-ut-1287

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "control.exe" and process.parent.name : "WorkFolders.exe" and
  not process.executable : (
    "?:\\Windows\\System32\\control.exe",
    "?:\\Windows\\SysWOW64\\control.exe",

    /* Crowdstrike specific condition as it uses NT Object paths */
    "\\Device\\HarddiskVolume*\\Windows\\System32\\control.exe",
    "\\Device\\HarddiskVolume*\\Windows\\SysWOW64\\control.exe"
  )
```



### SoftwareUpdate Preferences Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-1290

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.name == "defaults" and
 process.args like "write" and process.args like "-bool" and process.args like~ ("com.apple.SoftwareUpdate", "/Library/Preferences/com.apple.SoftwareUpdate.plist") and not process.args like ("TRUE", "true")
```



### SolarWinds Process Disabling Services via Registry

Branch count: 14  
Document count: 14  
Index: geneve-ut-1291

```python
registry where host.os.type == "windows" and event.type == "change" and registry.value : "Start" and
  process.name : (
      "SolarWinds.BusinessLayerHost*.exe",
      "ConfigurationWizard*.exe",
      "NetflowDatabaseMaintenance*.exe",
      "NetFlowService*.exe",
      "SolarWinds.Administration*.exe",
      "SolarWinds.Collector.Service*.exe",
      "SolarwindsDiagnostics*.exe"
  ) and
  registry.path : "*\\SYSTEM\\*ControlSet*\\Services\\*\\Start" and
  registry.data.strings : ("4", "0x00000004")
```



### Startup Folder Persistence via Unsigned Process

Branch count: 12  
Document count: 24  
Index: geneve-ut-1319

```python
sequence by host.id, process.entity_id with maxspan=5s
  [process where host.os.type == "windows" and event.type == "start" and process.code_signature.trusted == false and
  /* suspicious paths can be added here  */
   process.executable : ("C:\\Users\\*.exe",
                         "C:\\ProgramData\\*.exe",
                         "C:\\Windows\\Temp\\*.exe",
                         "C:\\Windows\\Tasks\\*.exe",
                         "C:\\Intel\\*.exe",
                         "C:\\PerfLogs\\*.exe")
   ]
   [file where host.os.type == "windows" and event.type != "deletion" and user.domain != "NT AUTHORITY" and
    file.path : ("C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
                 "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*")
   ]
```



### Startup Persistence by a Suspicious Process

Branch count: 36  
Document count: 36  
Index: geneve-ut-1320

```python
file where host.os.type == "windows" and event.type != "deletion" and
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

Branch count: 40  
Document count: 40  
Index: geneve-ut-1321

```python
registry where host.os.type == "windows" and event.type == "change" and 
 registry.data.strings != null and registry.hive : ("HKEY_USERS", "HKLM") and
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
  not user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
  not registry.data.strings : ("*:\\Program Files\\*",
                               "*:\\Program Files (x86)\\*",
                               "*:\\Users\\*\\AppData\\Local\\*",
                               "* --processStart *",
                               "* --process-start-args *",
                               "ms-teamsupdate.exe -UninstallT20",
                               " ",
                               "grpconv -o", "* /burn.runonce*", "* /startup",
                               "?:\\WINDOWS\\SysWOW64\\Macromed\\Flash\\FlashUtil32_*_Plugin.exe -update plugin") and
  not process.executable : ("?:\\Windows\\System32\\msiexec.exe",
                            "?:\\Windows\\SysWOW64\\msiexec.exe",
                            "D:\\*",
                            "\\Device\\Mup*",
                            "C:\\Windows\\SysWOW64\\reg.exe",
                            "C:\\Windows\\System32\\changepk.exe",
                            "C:\\Windows\\System32\\netsh.exe",
                            "C:\\$WINDOWS.~BT\\Sources\\SetupPlatform.exe",
                            "C:\\$WINDOWS.~BT\\Sources\\SetupHost.exe",
                            "C:\\Program Files\\Cisco Spark\\CiscoCollabHost.exe",
                            "C:\\Sistemas\\Programas MP\\CCleaner\\CCleaner64.exe",
                            "C:\\Program Files (x86)\\FastTrack Software\\Admin By Request\\AdminByRequest.exe",
                            "C:\\Program Files (x86)\\Exclaimer Ltd\\Cloud Signature Update Agent\\Exclaimer.CloudSignatureAgent.exe",
                            "C:\\ProgramData\\Lenovo\\Vantage\\AddinData\\LenovoBatteryGaugeAddin\\x64\\QSHelper.exe",
                            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\*\\Installer\\setup.exe",
                            "C:\\ProgramData\\bomgar-scc-*\\bomgar-scc.exe",
                            "C:\\Windows\\SysWOW64\\Macromed\\Flash\\FlashUtil*_pepper.exe",
                            "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\*.EXE",
                            "C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\*\\AdobeARM.exe")
```



### Statistical Model Detected C2 Beaconing Activity

Branch count: 1  
Document count: 1  
Index: geneve-ut-1323

```python
beacon_stats.is_beaconing: true and
not process.name: ("WaAppAgent.exe" or "metricbeat.exe" or "packetbeat.exe" or "WindowsAzureGuestAgent.exe" or "HealthService.exe" or "Widgets.exe" or "lsass.exe" or "msedgewebview2.exe" or
                   "MsMpEng.exe" or "OUTLOOK.EXE" or "msteams.exe" or "FileSyncHelper.exe" or "SearchProtocolHost.exe" or "Creative Cloud.exe" or "ms-teams.exe" or "ms-teamsupdate.exe" or
                   "curl.exe" or "rundll32.exe" or "MsSense.exe" or "wermgr.exe" or "java" or "olk.exe" or "iexplore.exe" or "NetworkManager" or "packetbeat" or "Ssms.exe" or "NisSrv.exe" or
                   "gamingservices.exe" or "appidcertstorecheck.exe" or "POWERPNT.EXE" or "miiserver.exe" or "Grammarly.Desktop.exe" or "SnagitEditor.exe" or "CRWindowsClientService.exe" or
                   "agentbeat" or "dnf" or "yum" or "apt"
                  )
```



### Statistical Model Detected C2 Beaconing Activity with High Confidence

Branch count: 1  
Document count: 1  
Index: geneve-ut-1324

```python
beacon_stats.beaconing_score: 3
```



### Stolen Credentials Used to Login to Okta Account After MFA Reset

Branch count: 2  
Document count: 6  
Index: geneve-ut-1325

```python
sequence by user.name with maxspan=12h
    [any where host.os.type == "windows" and signal.rule.threat.tactic.name == "Credential Access"]
    [any where event.dataset == "okta.system" and okta.event_type == "user.mfa.factor.update"]
    [any where event.dataset == "okta.system" and okta.event_type: ("user.session.start", "user.authentication*")]
```



### Sublime Plugin or Application Script Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-1326

```python
file where host.os.type == "macos" and event.action == "modification" and file.extension == "py" and
  file.path like
    (
      "/Users/*/Library/Application Support/Sublime Text*/Packages/*.py",
      "/Applications/Sublime Text.app/Contents/MacOS/sublime.py"
    ) and
  not process.executable like
    (
      "/Applications/Sublime Text*.app/Contents/*",
      "/usr/local/Cellar/git/*/bin/git",
      "/Library/Developer/CommandLineTools/usr/bin/git",
      "/usr/libexec/xpcproxy",
      "/System/Library/PrivateFrameworks/DesktopServicesPriv.framework/Versions/A/Resources/DesktopServicesHelper"
    )
```



### Sudo Command Enumeration Detected

Branch count: 32  
Document count: 32  
Index: geneve-ut-1331

```python
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and process.name == "sudo" and process.args == "-l" and
  process.args_count == 2 and process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
  not process.args == "dpkg"
```



### Sudoers File Activity

Branch count: 8  
Document count: 8  
Index: geneve-ut-1332

```python
file where host.os.type in ("linux", "macos") and event.type in ("creation", "change") and
file.path like ("/etc/sudoers*", "/private/etc/sudoers*") and not (
  process.name like ("dpkg", "platform-python*", "puppet", "yum", "dnf", "python*") or
  process.executable in (
    "/opt/chef/embedded/bin/ruby", "/opt/puppetlabs/puppet/bin/ruby", "/usr/bin/dockerd",
    "/usr/bin/podman", "/opt/teleport/system/bin/teleport", "/usr/sbin/dockerd",
    "/usr/local/bin/dockerd", "/usr/local/bin/teleport", "./usr/bin/podman", "/dev/fd/5",
    "/usr/bin/rpm", "/usr/bin/microdnf", "/opt/morpheus-node/embedded/bin/chef-client",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/bin/salt-minion"
  ) or
  process.executable like ("./snap/snapd/*/usr/lib/snapd/snap-update-ns", "/opt/teleport/*/bin/teleport")
)
```



### Suricata and Elastic Defend Network Correlation

Branch count: 2  
Document count: 4  
Index: geneve-ut-1333

```python
sequence by source.port, source.ip, destination.ip with maxspan=5s
 [network where event.dataset == "suricata.eve" and event.kind == "alert" and
  event.severity != 3 and source.ip != null and destination.ip != null and
  not source.domain : ("*nessusscan*", "SCCMPS*") and
  not rule.name in ("ET INFO SMB2 NT Create AndX Request For a Powershell .ps1 File", "ET SCAN MS Terminal Server Traffic on Non-standard Port")]
 [network where event.module == "endpoint" and event.action in ("disconnect_received", "connection_attempted") and
  not process.executable in ("System", "C:\\Program Files (x86)\\Admin Arsenal\\PDQ Inventory\\PDQInventoryService.exe") and 
  not process.executable : "C:\\Windows\\AdminArsenal\\PDQInventory-Scanner\\service-*\\exec\\PDQInventoryScanner.exe"]
```



### Suspicious .NET Code Compilation

Branch count: 16  
Document count: 16  
Index: geneve-ut-1335

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("csc.exe", "vbc.exe") and
  process.parent.name : ("wscript.exe", "mshta.exe", "cscript.exe", "wmic.exe", "svchost.exe", "rundll32.exe", "cmstp.exe", "regsvr32.exe")
```



### Suspicious .NET Reflection via PowerShell

Branch count: 24  
Document count: 24  
Index: geneve-ut-1336

```python
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "[System.Reflection.Assembly]::Load" or
    "[Reflection.Assembly]::Load" or
    "Assembly.Load("
  ) and
  not powershell.file.script_block_text : (
        ("CommonWorkflowParameters" or "RelatedLinksHelpInfo") and
        "HelpDisplayStrings"
  ) and
  not (powershell.file.script_block_text :
        ("Get-SolutionFiles" or "Get-VisualStudio" or "Select-MSBuildPath") and
        file.name : "PathFunctions.ps1"
  ) and
  not powershell.file.script_block_text : (
        "Microsoft.PowerShell.Workflow.ServiceCore" and "ExtractPluginProperties([string]$pluginDir"
  ) and 

  not powershell.file.script_block_text : ("reflection.assembly]::Load('System." or "LoadWithPartialName('Microsoft." or "::Load(\"Microsoft." or "Microsoft.Build.Utilities.Core.dll") and 

  not user.id : "S-1-5-18"
```



### Suspicious /proc/maps Discovery

Branch count: 48  
Document count: 48  
Index: geneve-ut-1337

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name in ("cat", "grep", "tail", "less", "more", "egrep", "fgrep", "awk") and process.args like "/proc/*/maps" and
not (
  ?process.parent.args in ("/usr/bin/finalrd", "/sbin/chkrootkit", "./uac", "/usr/sbin/chkrootkit") or
  ?process.parent.executable in ("/usr/sbin/chkrootkit", "/sbin/chkrootkit") or
  ?process.parent.name == "uac" or
  ?process.parent.executable in ("/opt/secl/linux-ir-scripts-v3/thieves.sh", "/opt/traps/rpm-installer/setup.sh") or
  ?process.working_directory like ("/opt/traps/deb-installer", "/opt/Tanium/TaniumClient/*") or
  ?process.parent.executable like ("/home/*/sunlight/thieves.sh")
)
```



### Suspicious APT Package Manager Network Connection

Branch count: 8  
Document count: 16  
Index: geneve-ut-1339

```python
sequence by host.id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name == "apt" and process.args == "-c" and
   process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
    not process.args == "/usr/bin/apt-listbugs apt"
  ] by process.entity_id
  [network where host.os.type == "linux" and event.action == "connection_attempted" and event.type == "start" and not (
     destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
     destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
     "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
     "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
     "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
     "FF00::/8", "172.31.0.0/16"
     )
   ) and not process.executable == "/usr/bin/apt-listbugs"
  ] by process.parent.entity_id
```



### Suspicious Activity Reported by Okta User

Branch count: 1  
Document count: 1  
Index: geneve-ut-1342

```python
event.dataset:okta.system and event.action:user.account.report_suspicious_activity_by_enduser
```



### Suspicious Antimalware Scan Interface DLL

Branch count: 2  
Document count: 2  
Index: geneve-ut-1343

```python
file where host.os.type == "windows" and event.type != "deletion" and file.path != null and
  file.name : ("amsi.dll", "amsi") and 
  event.action != "A process changed a file creation time" and 
  not file.path : (
    "?:\\$SysReset\\CloudImage\\Package_for_RollupFix*\\amsi.dll",
    "?:\\Windows\\system32\\amsi.dll",
    "?:\\Windows\\Syswow64\\amsi.dll",
    "?:\\$WINDOWS.~BT\\*\\amsi.dll",
    "?:\\Windows\\CbsTemp\\*\\amsi.dll",
    "?:\\Windows\\SoftwareDistribution\\Download\\*",
    "?:\\Windows\\WinSxS\\*\\amsi.dll", 
    "?:\\Windows\\servicing\\*\\amsi.dll",
    "\\\\?\\Volume{*}\\Windows\\WinSxS\\*\\amsi.dll", 
    "\\\\?\\Volume{*}\\Windows\\system32\\amsi.dll", 
    "\\\\?\\Volume{*}\\Windows\\syswow64\\amsi.dll",

    /* Crowdstrike specific exclusion as it uses NT Object paths */
    "\\Device\\HarddiskVolume*\\Windows\\system32\\amsi.dll", 
    "\\Device\\HarddiskVolume*\\Windows\\syswow64\\amsi.dll", 
    "\\Device\\HarddiskVolume*\\Windows\\WinSxS\\*\\amsi.dll",
    "\\Device\\HarddiskVolume*\\$SysReset\\CloudImage\\Package_for_RollupFix*\\amsi.dll",
    "\\Device\\HarddiskVolume*\\$WINDOWS.~BT\\*\\amsi.dll", 
    "\\Device\\HarddiskVolume*\\Windows\\SoftwareDistribution\\Download\\*\\amsi.dll", 
    "\\Device\\HarddiskVolume*\\Windows\\CbsTemp\\*\\amsi.dll", 
    "\\Device\\HarddiskVolume*\\Windows\\servicing\\*\\amsi.dll"
  )
```



### Suspicious Apple Mail Rule Plist Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-1344

```python
file where host.os.type == "macos" and event.type != "deletion" and
  file.name == "SyncedRules.plist" and
  file.path like ("/Users/*/Library/Mail/*/MailData/SyncedRules.plist",
                  "/Users/*/Library/Mobile Documents/com.apple.mail/Data/*/MailData/SyncedRules.plist") and
  not process.executable like ("/System/Applications/Mail.app/Contents/MacOS/Mail",
                               "/Applications/Mail.app/Contents/MacOS/Mail",
                               "/System/Library/CoreServices/backupd.bundle/Contents/Resources/backupd",
                               "/usr/libexec/xpcproxy",
                               "/System/Library/Frameworks/FileProvider.framework/Support/fileproviderd",
                               "/System/Library/PrivateFrameworks/CloudDocsDaemon.framework/Versions/A/Support/bird",
                               "/sbin/launchd",
                               "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder")
```



### Suspicious Automator Workflows Execution

Branch count: 2  
Document count: 4  
Index: geneve-ut-1345

```python
sequence by host.id, process.entity_id with maxspan=15s
 [process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name == "Automator"]
 [network where host.os.type == "macos"]
```



### Suspicious Browser Child Process

Branch count: 518  
Document count: 518  
Index: geneve-ut-1346

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  process.parent.name like~ ("Google Chrome", "Google Chrome Helper*", "firefox", "Opera", "Safari", "com.apple.WebKit.WebContent", "Microsoft Edge") and
  ((process.name like~ ("sh", "bash", "dash", "ksh", "tcsh", "zsh") and process.command_line : ("*curl*", "*nscurl*", "*wget*", "*whoami*", "*pwd*")) or
  process.name like~ ("curl", "wget", "python*", "perl*", "php*", "osascript", "pwsh")) and
  process.command_line != null
```



### Suspicious Calendar File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-1347

```python
file where host.os.type == "macos" and event.action == "modification" and
  file.path like~ "/Users/*/Library/Calendars/*.calendar/Events/*.ics" and
  not process.executable like ("/System/Library/*", "/System/Applications/Calendar.app/Contents/MacOS/*", 
                               "/System/Applications/Mail.app/Contents/MacOS/Mail", "/usr/libexec/xpcproxy",
                               "/sbin/launchd", "/Applications/*")
```



### Suspicious CertUtil Commands

Branch count: 14  
Document count: 14  
Index: geneve-ut-1348

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "certutil.exe" or ?process.pe.original_file_name == "CertUtil.exe") and
  process.args : ("?decode", "?encode", "?urlcache", "?verifyctl", "?encodehex", "?decodehex", "?exportPFX")
```



### Suspicious Child Process of Adobe Acrobat Reader Update Service

Branch count: 2  
Document count: 2  
Index: geneve-ut-1350

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  process.parent.name like "com.adobe.ARMDC.SMJobBlessHelper" and
  user.name == "root" and
  not process.executable like ("/Library/PrivilegedHelperTools/com.adobe.ARMDC.SMJobBlessHelper",
                               "/usr/bin/codesign",
                               "/private/var/folders/zz/*/T/download/ARMDCHammer",
                               "/usr/sbin/pkgutil",
                               "/usr/bin/shasum",
                               "/usr/bin/perl*",
                               "/usr/sbin/spctl",
                               "/usr/sbin/installer",
                               "/usr/bin/csrutil")
```



### Suspicious Cmd Execution via WMI

Branch count: 5  
Document count: 5  
Index: geneve-ut-1351

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "WmiPrvSE.exe" and process.name : "cmd.exe" and process.args : "/c" and process.args:"/Q" and 
 process.args : "2>&1" and process.args: "1>"  and 
 process.args : ("C:\\windows\\temp\\*.txt", "\\Windows\\Temp\\*", "-encodehex", "\\\\127.0.0.1\\C$\\Windows\\Temp\\*", "\\\\127.0.0.1\\ADMIN$\\__*.*")
```



### Suspicious Content Extracted or Decompressed via Funzip

Branch count: 8  
Document count: 8  
Index: geneve-ut-1353

```python
process where host.os.type == "linux" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
((process.args == "tail" and process.args == "-c" and process.args == "funzip")) and
not process.args : "/var/log/messages" and
not ?process.parent.executable : ("/usr/bin/dracut", "/sbin/dracut", "/usr/bin/xargs") and
not (process.parent.name in ("sh", "sudo") and ?process.parent.command_line : "*nessus_su*")
```



### Suspicious CronTab Creation or Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-1354

```python
file where host.os.type == "macos" and event.type != "deletion" and process.name != null and
  file.path like "/private/var/at/tabs/*" and not process.executable == "/usr/bin/crontab"
```



### Suspicious Curl to Google App Script Endpoint

Branch count: 8  
Document count: 16  
Index: geneve-ut-1356

```python
sequence by process.entity_id with maxspan=15s
  [process where host.os.type == "macos" and event.type == "start" and process.name in ("curl", "nscurl") and
    not process.Ext.effective_parent.executable like "/Library/Kandji/Kandji Agent.app/Contents/Helpers/Kandji Library Manager.app/Contents/MacOS/kandji-library-manager"]
  [network where host.os.type == "macos" and event.type == "start" and process.name in ("curl", "nscurl") and 
    destination.domain in ("script.google.com", "script.google.com.")]
```



### Suspicious Curl to Jamf Endpoint

Branch count: 14  
Document count: 14  
Index: geneve-ut-1357

```python
process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and
  process.name in ("curl", "nscurl") and process.command_line like "*https://jamf.*" and
  ((process.parent.code_signature.exists == false or process.parent.code_signature.trusted == false) or
   process.parent.name in ("osascript", "node", "perl", "ruby") or
   process.parent.name like "python*")
```



### Suspicious DLL Loaded for Persistence or Privilege Escalation

Branch count: 83  
Document count: 83  
Index: geneve-ut-1358

```python
any where host.os.type == "windows" and 
(
  /*  Elastic Defend DLL load events */
  (event.category == "library" and 
    (
     ?dll.name : ("wlbsctrl.dll", "wbemcomn.dll", "WptsExtensions.dll", "Tsmsisrv.dll", "TSVIPSrv.dll", "Msfte.dll", "wow64log.dll", "WindowsCoreDeviceInfo.dll", "Ualapi.dll", "wlanhlp.dll", "phoneinfo.dll", "EdgeGdi.dll", "cdpsgshims.dll", "windowsperformancerecordercontrol.dll", "diagtrack_win.dll", "TPPCOIPW32.dll", "tpgenlic.dll", "thinmon.dll", "fxsst.dll", "msTracer.dll") or 

     (?dll.path : "?:\\Windows\\*\\oci.dll" and process.executable : "?:\\Windows\\*.exe")
     )
    and (?dll.code_signature.trusted == false or ?dll.code_signature.exists == false or (?dll.code_signature.trusted == true and not ?dll.code_signature.subject_name : ("Microsoft Windows", "Microsoft Corporation", "Microsoft Windows Publisher"))
      ))
   or

  /*  Sysmon DLL load events */
  ((event.category == "process" and event.action like "Image loaded*") and file.code_signature.status != "Valid" and 
  file.name : ("wlbsctrl.dll", "wbemcomn.dll", "WptsExtensions.dll", "Tsmsisrv.dll", "TSVIPSrv.dll", "Msfte.dll", "wow64log.dll", "WindowsCoreDeviceInfo.dll", "Ualapi.dll", "wlanhlp.dll", "phoneinfo.dll", "EdgeGdi.dll", "cdpsgshims.dll", "windowsperformancerecordercontrol.dll", "diagtrack_win.dll", "TPPCOIPW32.dll", "tpgenlic.dll", "thinmon.dll", "fxsst.dll", "msTracer.dll") and 
   not file.hash.sha256 in 
            ("6e837794fc282446906c36d681958f2f6212043fc117c716936920be166a700f", 
             "b14e4954e8cca060ffeb57f2458b6a3a39c7d2f27e94391cbcea5387652f21a4", 
             "c258d90acd006fa109dc6b748008edbb196d6168bc75ace0de0de54a4db46662", 
             "254e5053ac04b7623e86234077876388e0b10c3ac5c3f4e4e86292b62571bfb0")) 

) and not
  (
    ?dll.path : (
      "?:\\Windows\\System32\\wbemcomn.dll",
      "?:\\Windows\\SysWOW64\\wbemcomn.dll",
      "?:\\Windows\\System32\\windowsperformancerecordercontrol.dll",
      "?:\\Windows\\System32\\wlanhlp.dll", 
      "\\Device\\HarddiskVolume?\\Windows\\SysWOW64\\wbemcomn.dll", 
      "\\Device\\HarddiskVolume?\\Windows\\System32\\wbemcomn.dll", 
      "\\Device\\HarddiskVolume?\\Windows\\SysWOW64\\wlanhlp.dll", 
      "\\Device\\HarddiskVolume?\\Windows\\System32\\wlanhlp.dll", 
      "\\Device\\HarddiskVolume?\\Windows\\SysWOW64\\windowsperformancerecordercontrol.dll", 
      "\\Device\\HarddiskVolume?\\Windows\\System32\\windowsperformancerecordercontrol.dll", 
      "C:\\ProgramData\\docker\\windowsfilter\\*\\Files\\Windows\\System32\\windowsperformancerecordercontrol.dll", 
      "\\Device\\vmsmb\\VSMB-{*}\\os\\windows\\system32\\*.dll", 
      "C:\\Windows\\WinSxS\\amd64_microsoft-windows-wmi-core-wbemcomn-dll_*\\wbemcomn.dll", 
      "C:\\Windows\\WinSxS\\wow64_microsoft-windows-wmi-core-wbemcomn-dll_*\\wbemcomn.dll", 
      "C:\\Windows\\WinSxS\\amd64_microsoft-windows-coresystem-wpr_*\\windowsperformancerecordercontrol.dll"
    ) or

    file.path : (
      "?:\\Windows\\System32\\wbemcomn.dll",
      "?:\\Windows\\SysWOW64\\wbemcomn.dll",
      "?:\\Windows\\System32\\windowsperformancerecordercontrol.dll",
      "?:\\Windows\\System32\\wlanhlp.dll", 
      "C:\\ProgramData\\docker\\windowsfilter\\*\\Files\\Windows\\System32\\windowsperformancerecordercontrol.dll", 
      "C:\\ProgramData\\docker\\windowsfilter\\*\\Files\\Windows\\System32\\wbemcomn.dll", 
      "\\Device\\vmsmb\\VSMB-{*}\\os\\windows\\system32\\*.dll", 
      "C:\\Windows\\WinSxS\\amd64_microsoft-windows-wmi-core-wbemcomn-dll_*\\wbemcomn.dll", 
      "C:\\Windows\\WinSxS\\wow64_microsoft-windows-wmi-core-wbemcomn-dll_*\\wbemcomn.dll"
    ) or 

 ?dll.code_signature.status like "errorCode_endpoint*"
  )
```



### Suspicious Dynamic Linker Discovery via od

Branch count: 30  
Document count: 30  
Index: geneve-ut-1360

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started")
 and process.name == "od" and process.args in (
  "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/etc/ld.so.preload", "/lib64/ld-linux-x86-64.so.2",
  "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/usr/lib64/ld-linux-x86-64.so.2"
)
```



### Suspicious Emond Child Process

Branch count: 44  
Document count: 44  
Index: geneve-ut-1361

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.parent.name == "emond" and
 process.name like~ (
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

Branch count: 4  
Document count: 4  
Index: geneve-ut-1362

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("esensor.exe", "elastic-endpoint.exe") and
  process.parent.executable != null and
  process.args != null and
  /* add FPs here */
  not process.parent.executable : (
        "?:\\Program Files\\Elastic\\*",
        "?:\\Windows\\System32\\services.exe",
        "?:\\Windows\\System32\\WerFault*.exe",
        "?:\\Windows\\System32\\wermgr.exe",
        "?:\\Windows\\explorer.exe"
  ) and
  not (
    process.parent.executable : (
        "?:\\Windows\\System32\\cmd.exe",
        "?:\\Windows\\System32\\SecurityHealthHost.exe",
        "?:\\Windows\\System32\\SecurityHealth\\*\\SecurityHealthHost.exe",
        "?:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    ) and
    process.args : (
        "test", "version",
        "top", "run",
        "*help", "status",
        "upgrade", "/launch",
        "/enable", "/av"
    )
  )
```



### Suspicious Execution from Foomatic-rip or Cupsd Parent

Branch count: 352  
Document count: 352  
Index: geneve-ut-1363

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.parent.name in ("foomatic-rip", "cupsd") and process.command_line like (
  // persistence
  "*cron*", "*/etc/rc.local*", "*/dev/tcp/*", "*/etc/init.d*", "*/etc/update-motd.d*", "*/etc/sudoers*",
  "*/etc/profile*", "*autostart*", "*/etc/ssh*", "*/home/*/.ssh/*", "*/root/.ssh*", "*~/.ssh/*", "*udev*",
  "*/etc/shadow*", "*/etc/passwd*",

  // Downloads
  "*curl*", "*wget*",

  // encoding and decoding
  "*base64 *", "*base32 *", "*xxd *", "*openssl*",

  // reverse connections
  "*GS_ARGS=*", "*/dev/tcp*", "*/dev/udp/*", "*import*pty*spawn*", "*import*subprocess*call*", "*TCPSocket.new*",
  "*TCPSocket.open*", "*io.popen*", "*os.execute*", "*fsockopen*", "*disown*", "*nohup*",

  // SO loads
  "*openssl*-engine*.so*", "*cdll.LoadLibrary*.so*", "*ruby*-e**Fiddle.dlopen*.so*", "*Fiddle.dlopen*.so*",
  "*cdll.LoadLibrary*.so*",

  // misc. suspicious command lines
   "*/etc/ld.so*", "*/dev/shm/*", "*/var/tmp*", "*echo*", "*>>*", "*|*"
) and not process.args like "gs*"
```



### Suspicious Execution from INET Cache

Branch count: 12  
Document count: 12  
Index: geneve-ut-1364

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : ("explorer.exe", "winrar.exe", "7zFM.exe", "Bandizip.exe") and
  (
    process.args : "*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*" or
    process.executable : (
      "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*",

      /* Crowdstrike specific condition as it uses NT Object paths */
      "\\Device\\HarddiskVolume*\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*"
    )
  ) and
  not process.executable : (
        "?:\\Program Files\\*.exe",
        "?:\\Program Files (x86)\\*.exe",
        "?:\\Windows\\System32\\mspaint.exe",
        "?:\\Windows\\System32\\notepad.exe",

        /* Crowdstrike specific exclusion as it uses NT Object paths */
        "\\Device\\HarddiskVolume*\\Program Files\\*.exe",
        "\\Device\\HarddiskVolume*\\Program Files (x86)\\*.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\mspaint.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\notepad.exe"
  )
```



### Suspicious Execution from a Mounted Device

Branch count: 8  
Document count: 8  
Index: geneve-ut-1365

```python
process where host.os.type == "windows" and event.type == "start" and process.executable : "C:\\*" and
  (process.working_directory : "?:\\" and not process.working_directory: "C:\\") and
  process.parent.name : "explorer.exe" and
  process.name : ("rundll32.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "regsvr32.exe",
                  "cscript.exe", "wscript.exe")
```



### Suspicious Execution via Windows Subsystem for Linux

Branch count: 14  
Document count: 14  
Index: geneve-ut-1370

```python
process where host.os.type == "windows" and event.type : "start" and
  (
    (
      (process.executable : "?:\\Windows\\System32\\bash.exe" or ?process.pe.original_file_name == "Bash.exe") and
      not process.command_line : ("bash", "bash.exe")
    ) or
    process.executable : "?:\\Users\\*\\AppData\\Local\\Packages\\*\\rootfs\\usr\\bin\\bash" or
    (
      process.parent.name : "wsl.exe" and process.parent.command_line : "bash*" and not process.name : "wslhost.exe"
    ) or
    (
      process.name : "wsl.exe" and process.args : (
        "curl", "/etc/shadow", "/etc/passwd", "cat", "--system", "root", "-e", "--exec", "bash", "/mnt/c/*"
      ) and not process.args : ("wsl-bootstrap", "docker-desktop-data", "*.vscode-server*")
    )
  ) and
    not process.parent.executable : ("?:\\Program Files\\Docker\\*.exe", "?:\\Program Files (x86)\\Docker\\*.exe")
```



### Suspicious Execution with NodeJS

Branch count: 18  
Document count: 18  
Index: geneve-ut-1371

```python
process where host.os.type == "windows" and event.type == "start" and

(process.name : "node.exe" or ?process.pe.original_file_name == "node.exe" or ?process.code_signature.subject_name : "OpenJS Foundation") and

(
  (process.executable : ("?:\\Users\\*\\AppData\\*\\node.exe", "\\Device\\HarddiskVolume?\\\\Users\\*\\AppData\\*\\node.exe") and process.args : "*.js") or

  (process.args : "-r" and process.parent.name : "powershell.exe") or

   process.command_line : ("*eval(*", "*atob(*", "*require*child_process*")
)
```



### Suspicious Explorer Child Process

Branch count: 14  
Document count: 14  
Index: geneve-ut-1372

```python
process where host.os.type == "windows" and event.type == "start" and
  (
   process.name : ("cscript.exe", "wscript.exe", "powershell.exe", "rundll32.exe", "cmd.exe", "mshta.exe", "regsvr32.exe") or
   ?process.pe.original_file_name in ("cscript.exe", "wscript.exe", "PowerShell.EXE", "RUNDLL32.EXE", "Cmd.Exe", "MSHTA.EXE", "REGSVR32.EXE")
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



### Suspicious File Creation via Kworker

Branch count: 2  
Document count: 2  
Index: geneve-ut-1373

```python
file where host.os.type == "linux" and event.action in ("creation", "file_create_event") and
process.name : "kworker*" and not (
  process.name : "kworker*kcryptd*" or
  file.path like (
    "/var/log/*", "/var/crash/*", "/var/run/*", "/var/lib/systemd/coredump/*", "/var/spool/*",
    "/var/lib/nfs/nfsdcltrack/main.sqlite-journal", "/proc/*/cwd/core.*", "/var/run/apport.lock",
    "/var/spool/abrt/ccpp-*", "/var/lib/dynatrace/oneagent/*", "/var/lib/nfs*", "/run/user/*/.bubblewrap/*",
    "/etc/localtime/*", "/proc/*/cwd/core.*", "/tmp/sh-thd.*", "/var/lib/apport/coredump/*", "/var/tmp/abrt/ccpp*"
  )
)
```



### Suspicious File Made Executable via Chmod Inside A Container

Branch count: 84  
Document count: 84  
Index: geneve-ut-1376

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.entry_leader.entry_meta.type == "container" and process.name in ("chmod", "chown") and
process.args in ("4755", "755", "000", "777", "444", "+x") and
process.args like ("/dev/shm/*", "/tmp/*", "/var/tmp/*", "/run/*", "/var/run/*", "/mnt/*", "/media/*")
```



### Suspicious Hidden Child Process of Launchd

Branch count: 2  
Document count: 2  
Index: geneve-ut-1379

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.name like~ ".*" and process.parent.name == "launchd"
```



### Suspicious Image Load (taskschd.dll) from MS Office

Branch count: 30  
Document count: 30  
Index: geneve-ut-1380

```python
any where host.os.type == "windows" and
 (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
  process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE", "MSACCESS.EXE") and
  (?dll.name : "taskschd.dll" or file.name : "taskschd.dll")
```



### Suspicious ImagePath Service Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-1381

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : "ImagePath" and
  registry.path : "*\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath" and
  /* add suspicious registry ImagePath values here */
  registry.data.strings : ("%COMSPEC%*", "*\\.\\pipe\\*")
```



### Suspicious Installer Package Spawns Network Event

Branch count: 16  
Document count: 32  
Index: geneve-ut-1382

```python
sequence by host.id, process.entity_id with maxspan=15s
[process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and process.parent.name like~ ("installer", "package_script_service") and ((process.name in ("bash", "sh", "zsh") and process.args == "-c") or (process.name like~ ("python*", "osascript", "tclsh*", "curl", "nscurl")))]
[network where host.os.type == "macos" and event.type == "start"]
```



### Suspicious Interactive Process Execution Detected via Defend for Containers

Branch count: 8  
Document count: 8  
Index: geneve-ut-1384

```python
process where event.type == "start" and event.action == "exec" and process.interactive == true and
process.executable like (
  "/tmp/*", "/dev/shm/*", "/var/tmp/*", "/run/*", "/var/run/*", "/mnt/*", "/media/*", "/boot/*"
) and container.id like "?*"
```



### Suspicious Interpreter Execution Detected via Defend for Containers

Branch count: 405  
Document count: 405  
Index: geneve-ut-1385

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.interactive == true and
process.parent.executable != null and (
  (
    process.executable like ("/bin/perl*", "/usr/bin/perl*", "/usr/local/bin/perl*") and
    process.args == "-e" and process.args like~ (
      "*system(*", "*exec(*", "*IO.popen(*", "*Open3.popen3(*", "*spawn(*", "*eval(*",
      "*load(*IO::*", "*load(*Marshal*", "*load(*Fiddle*", "*load(*Zlib*", "*load(*Base64*",
      "*zlib.inflate(*", "*zlib.deflate(*", "*zlib.decompress(*", "*zlib.uncompress(*", "*zlib.compress(*",
      "*Marshal.load(*", "*Fiddle.dlopen(*", "*Fiddle::Function.new(*", "*base64*", "*zlib*", 
      "*net/http*", "*socket.new*", "*open-uri*", "*pack(*"
    )
  ) or
  process.executable like ("/bin/php*", "/usr/bin/php*", "/usr/local/bin/php*") and
  process.args == "-r" and process.args like~ (
    "*exec(*", "*system(*", "*shell_exec(*", "*passthru(*", "*proc_open(*", "*pcntl_exec(*", "*popen(*", 
    "*eval(*", "*assert(*", "*create_function(*", "*preg_replace(*e*", "*include(*", "*require(*",
    "*base64_decode(*", "*gzinflate(*", "*gzuncompress(*", "*str_rot13(*", "*urldecode(*", "*chr(*", 
    "*ord(*", "*strrev(*", "*strtr(*", "*pack(*", "*unpack(*", "*curl_exec(*", "*curl_multi_exec(*",
    "*file_get_contents(*", "*fopen(*", "*fsockopen(*", "*pfsockopen(*", "*stream_socket_client(*",
    "*socket_create(*", "*socket_connect(*", "*socket_write(*", "*socket_read(*", "*mail(*",
    "*move_uploaded_file(*"
  ) or
  process.executable like ("/bin/lua*", "/usr/bin/lua*", "/usr/local/bin/lua*") and
  process.args == "-e" and process.args like~ (
    "*os.execute(*", "*io.popen(*", "*load(*", "*loadstring(*", "*require(*", "*dofile(*",
    "*package.loadlib(*", "*base64.decode(*", "*base64.encode(*", "*zlib.inflate(*",
    "*zlib.deflate(*", "*zlib.decompress(*", "*zlib.compress(*", "*socket.bind(*",
    "*socket.connect(*", "*socket.receive(*", "*socket.send(*", "*socket.tcp(*",
    "*socket.udp(*", "*socket.listen(*", "*socket.accept(*", "*net.http.request(*",
    "*net.http.get(*", "*net.http.post(*", "*http.request(*", "*http.get(*", "*http.post(*"
  ) or
  process.executable like ("/bin/python*", "/usr/bin/python*", "/usr/local/bin/python*") and
  process.args == "-c" and process.args like~ (
    "*exec(*base64*", "*exec(*decode(*", "*exec(*marshal*", "*exec(*pickle*", "*eval(*exec(*",
    "*eval(*", "*subprocess.popen(*", "*subprocess.run(*", "*pickle.loads(*", "*marshal.loads(*",
    "*binascii*", "*os.system(*", "*os.popen(*", "*pty.*", "*dup2*", "*fileno()*", "*connect(*",
    "*bind(*", "*execve(*", "*base64*", "*base32*", "*base16*", "*base85*", "*decode(*",
    "*zlib.*", "*[::-1]*", "*socket.socket(*", "*socket.connect(*", "*socket.bind(*"
  ) or
  process.executable like ("/bin/ruby*", "/usr/bin/ruby*", "/usr/local/bin/ruby*") and
  process.args like "-e*" and process.args like~ (
    "*system(*", "*exec(*", "*IO.popen(*", "*Open3.popen3(*", "*spawn(*", "*eval(*", "*load(*",
    "*Marshal.load(*", "*Fiddle.dlopen(*", "*Fiddle::Function.new(*", "*base64*", "*zlib*", 
    "*net/http*", "*socket*", "*open-uri*", "*pack(*", "*unpack(*"
  )
) and container.id like "?*"
```



### Suspicious Kerberos Authentication Ticket Request

Branch count: 4  
Document count: 8  
Index: geneve-ut-1387

```python
sequence by source.port, source.ip with maxspan=3s
 [network where host.os.type == "windows" and destination.port == 88 and
  process.executable != null and process.pid != 4 and 
  not process.executable : 
              ("?:\\Windows\\system32\\lsass.exe", 
               "\\device\\harddiskvolume*\\windows\\system32\\lsass.exe", 
               "\\device\\harddiskvolume*\\windows\\system32\\svchost.exe") and
  not (process.executable : ("C:\\Windows\\System32\\svchost.exe", 
                             "C:\\Program Files\\VMware\\VMware View\\Server\\bin\\ws_TomcatService.exe", 
                             "F:\\IGEL\\RemoteManager\\*\\bin\\tomcat10.exe") and user.id in ("S-1-5-20", "S-1-5-18")) and   
  source.ip != "127.0.0.1" and destination.ip != "::1" and destination.ip != "127.0.0.1"]
 [authentication where host.os.type == "windows" and event.code in ("4768", "4769")]
```



### Suspicious Kworker UID Elevation

Branch count: 1  
Document count: 1  
Index: geneve-ut-1389

```python
process where host.os.type == "linux" and event.action == "session_id_change" and process.name : "kworker*" and
user.id == "0"
```



### Suspicious LSASS Access via MalSecLogon

Branch count: 1  
Document count: 1  
Index: geneve-ut-1390

```python
process where host.os.type == "windows" and event.code == "10" and
  winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe" and

   /* seclogon service accessing lsass */
  winlog.event_data.CallTrace : "*seclogon.dll*" and process.name : "svchost.exe" and

   /* PROCESS_CREATE_PROCESS & PROCESS_DUP_HANDLE & PROCESS_QUERY_INFORMATION */
  winlog.event_data.GrantedAccess == "0x14c0"
```



### Suspicious Lsass Process Access

Branch count: 1  
Document count: 1  
Index: geneve-ut-1391

```python
process where host.os.type == "windows" and event.code == "10" and
  winlog.event_data.TargetImage : "?:\\WINDOWS\\system32\\lsass.exe" and
  not winlog.event_data.GrantedAccess :
                ("0x1000", "0x1400", "0x101400", "0x101000", "0x101001", "0x100000", "0x100040", "0x3200", "0x40", "0x3200") and
  not process.name : ("procexp64.exe", "procmon.exe", "procexp.exe", "Microsoft.Identity.AadConnect.Health.AadSync.Host.ex") and
  not process.executable : (
        "?:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*",
        "?:\\ProgramData\\WebEx\\webex\\*",
        "?:\\Program Files (x86)\\*",
        "?:\\Program Files\\*",
        "?:\\Windows\\CCM\\CcmExec.exe",
        "?:\\Windows\\LTSvc\\LTSVC.exe",
        "?:\\Windows\\Sysmon.exe",
        "?:\\Windows\\Sysmon64.exe",
        "C:\\Windows\\CynetMS.exe",
        "?:\\Windows\\system32\\csrss.exe",
        "?:\\Windows\\System32\\lsm.exe",
        "?:\\Windows\\system32\\MRT.exe",
        "?:\\Windows\\System32\\msiexec.exe",
        "?:\\Windows\\system32\\wbem\\wmiprvse.exe",
        "?:\\Windows\\system32\\wininit.exe",
        "?:\\Windows\\SystemTemp\\GUM*.tmp\\GoogleUpdate.exe",
        "?:\\Windows\\sysWOW64\\wbem\\wmiprvse.exe",
        "C:\\oracle\\64\\02\\instantclient_19_13\\sqlplus.exe",
        "C:\\oracle\\64\\02\\instantclient_19_13\\sqlldr.exe",
        "d:\\oracle\\product\\19\\dbhome1\\bin\\ORACLE.EXE",
        "C:\\wamp\\bin\\apache\\apache*\\bin\\httpd.exe",
        "C:\\Windows\\system32\\netstat.exe",
        "C:\\PROGRA~1\\INFORM~1\\apps\\jdk\\*\\jre\\bin\\java.exe",
        "C:\\PROGRA~2\\CyberCNSAgentV2\\osqueryi.exe",
        "C:\\Utilityw2k19\\packetbeat\\packetbeat.exe",
        "C:\\ProgramData\\Cisco\\Cisco AnyConnect Secure Mobility Client\\Temp\\CloudUpdate\\vpndownloader.exe",
        "C:\\ProgramData\\Cisco\\Cisco Secure Client\\Temp\\CloudUpdate\\vpndownloader.exe"
  ) and
  not winlog.event_data.CallTrace : ("*mpengine.dll*", "*appresolver.dll*", "*sysmain.dll*")
```



### Suspicious MS Outlook Child Process

Branch count: 52  
Document count: 52  
Index: geneve-ut-1393

```python
process where host.os.type == "windows" and event.type == "start" and
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

Branch count: 8  
Document count: 8  
Index: geneve-ut-1394

```python
file where host.os.type == "windows" and event.type != "deletion" and
  file.name : ("wscript.exe.log",
               "cscript.exe.log",
               "mshta.exe.log",
               "wmic.exe.log",
               "svchost.exe.log",
               "dllhost.exe.log",
               "cmstp.exe.log",
               "regsvr32.exe.log")
```



### Suspicious Memory grep Activity

Branch count: 72  
Document count: 72  
Index: geneve-ut-1395

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name in ("grep", "egrep", "fgrep", "rgrep") and process.args in ("[stack]", "[vdso]", "[heap]")
```



### Suspicious Microsoft Antimalware Service Execution

Branch count: 2  
Document count: 2  
Index: geneve-ut-1396

```python
process where host.os.type == "windows" and event.type == "start" and
(
  (process.pe.original_file_name == "MsMpEng.exe" and not process.name : "MsMpEng.exe") or
  (
    process.name : "MsMpEng.exe" and
    not process.executable : (
            "?:\\ProgramData\\Microsoft\\Windows Defender\\*.exe",
            "?:\\Program Files\\Windows Defender\\*.exe",
            "?:\\Program Files (x86)\\Windows Defender\\*.exe",
            "?:\\Program Files\\Microsoft Security Client\\*.exe",
            "?:\\Program Files (x86)\\Microsoft Security Client\\*.exe",

            /* Crowdstrike specific exclusion as it uses NT Object paths */
            "\\Device\\HarddiskVolume*\\ProgramData\\Microsoft\\Windows Defender\\*.exe",
            "\\Device\\HarddiskVolume*\\Program Files\\Windows Defender\\*.exe",
            "\\Device\\HarddiskVolume*\\Program Files (x86)\\Windows Defender\\*.exe",
            "\\Device\\HarddiskVolume*\\Program Files\\Microsoft Security Client\\*.exe",
            "\\Device\\HarddiskVolume*\\Program Files (x86)\\Microsoft Security Client\\*.exe"
    )
  )
)
```



### Suspicious Microsoft HTML Application Child Process

Branch count: 12  
Document count: 12  
Index: geneve-ut-1398

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "mshta.exe" and
 (
  process.name : ("cmd.exe", "powershell.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "msiexec.exe", "schtasks.exe", "reg.exe", "wscript.exe", "rundll32.exe") or
  process.executable : ("C:\\Users\\*\\*.exe", "\\Device\\HarddiskVolume*\\Users\\*\\*.exe")
  )
```



### Suspicious Mining Process Creation Event

Branch count: 14  
Document count: 14  
Index: geneve-ut-1399

```python
file where host.os.type == "linux" and event.type == "creation" and event.action in ("creation", "file_create_event") and (
  (
    file.name like~ (
      "moneroocean_miner.service", "c3pool_miner.service", "pnsd.service", "apache4.service", "pastebin.service", "xvf.service"
    )
  ) or
  (
    process.executable like "/usr/local/share/aliyun-assist/*/aliyun-service" and file.name like~ "aliyun.service"
  )
)
```



### Suspicious Module Loaded by LSASS

Branch count: 4  
Document count: 4  
Index: geneve-ut-1401

```python
any where event.category in ("library", "driver") and host.os.type == "windows" and
  process.executable : "?:\\Windows\\System32\\lsass.exe" and
  not (dll.code_signature.subject_name :
               ("Microsoft Windows",
                "Microsoft Corporation",
                "Microsoft Windows Publisher",
                "Microsoft Windows Software Compatibility Publisher",
                "Microsoft Windows Hardware Compatibility Publisher",
                "McAfee, Inc.",
                "SecMaker AB",
                "HID Global Corporation",
                "HID Global",
                "Apple Inc.",
                "Citrix Systems, Inc.",
                "Dell Inc",
                "Hewlett-Packard Company",
                "Symantec Corporation",
                "National Instruments Corporation",
                "DigitalPersona, Inc.",
                "Novell, Inc.",
                "gemalto",
                "EasyAntiCheat Oy",
                "Entrust Datacard Corporation",
                "AuriStor, Inc.",
                "LogMeIn, Inc.",
                "VMware, Inc.",
                "Istituto Poligrafico e Zecca dello Stato S.p.A.",
                "Nubeva Technologies Ltd",
                "Micro Focus (US), Inc.",
                "Yubico AB",
                "GEMALTO SA",
                "Secure Endpoints, Inc.",
                "Sophos Ltd",
                "Morphisec Information Security 2014 Ltd",
                "Entrust, Inc.",
                "Nubeva Technologies Ltd",
                "Micro Focus (US), Inc.",
                "F5 Networks Inc",
                "Bit4id",
                "Thales DIS CPL USA, Inc.",
                "Micro Focus International plc",
                "HYPR Corp",
                "Intel(R) Software Development Products",
                "PGP Corporation",
                "Parallels International GmbH",
                "FrontRange Solutions Deutschland GmbH",
                "SecureLink, Inc.",
                "Tidexa OU",
                "Amazon Web Services, Inc.",
                "SentryBay Limited",
                "Audinate Pty Ltd",
                "CyberArk Software Ltd.",
                "McAfeeSysPrep",
                "NVIDIA Corporation PE Sign v2016",
                "Trend Micro, Inc.",
                "Fortinet Technologies (Canada) Inc.",
                "Carbon Black, Inc.") and
       dll.code_signature.status : ("trusted", "errorExpired", "errorCode_endpoint*", "errorChaining")) and

     not dll.hash.sha256 :
                ("811a03a5d7c03802676d2613d741be690b3461022ea925eb6b2651a5be740a4c",
                 "1181542d9cfd63fb00c76242567446513e6773ea37db6211545629ba2ecf26a1",
                 "ed6e735aa6233ed262f50f67585949712f1622751035db256811b4088c214ce3",
                 "26be2e4383728eebe191c0ab19706188f0e9592add2e0bf86b37442083ae5e12",
                 "9367e78b84ef30cf38ab27776605f2645e52e3f6e93369c674972b668a444faa",
                 "d46cc934765c5ecd53867070f540e8d6f7701e834831c51c2b0552aba871921b",
                 "0f77a3826d7a5cd0533990be0269d951a88a5c277bc47cff94553330b715ec61",
                 "4aca034d3d85a9e9127b5d7a10882c2ef4c3e0daa3329ae2ac1d0797398695fb",
                 "86031e69914d9d33c34c2f4ac4ae523cef855254d411f88ac26684265c981d95")
```



### Suspicious Network Connection via systemd

Branch count: 34  
Document count: 68  
Index: geneve-ut-1404

```python
sequence by host.id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name == "systemd" and (
     process.name in (
       "openssl", "nc", "ncat", "netcat", "nc.openbsd", "nc.traditional", "socat", "busybox", "mkfifo",
       "nohup", "setsid", "xterm", "telnet"
     ) or
    (process.name : "python*" and process.args : "-c" and process.args : (
     "*import*pty*spawn*", "*import*subprocess*call*"
    )) or
    (process.name : "perl*" and process.args : "-e" and process.args : "*socket*" and process.args : (
     "*exec*", "*system*"
    )) or
    (process.name : "ruby*" and process.args : ("-e", "-rsocket") and process.args : (
     "*TCPSocket.new*", "*TCPSocket.open*"
     )) or
    (process.name : "lua*" and process.args : "-e" and process.args : "*socket.tcp*" and process.args : (
     "*io.popen*", "*os.execute*"
    )) or
    (process.name : "php*" and process.args : "-r" and process.args : "*fsockopen*" and process.args : "*/bin/*sh*") or 
    (process.name == "node" and process.args == "-e" and process.args : "*spawn*sh*" and process.args : "*connect*") or
    (process.name : ("awk", "gawk", "mawk", "nawk") and process.args : "*/inet/tcp/*") or
    (process.name in ("rvim", "vim", "vimdiff", "rview", "view") and process.args == "-c" and process.args : "*socket*")
  ) and
   not (
     process.args in ("/usr/bin/pg_ctlcluster", "/usr/bin/pveproxy", "/usr/sbin/pveum", "/usr/bin/pveupdate") or
     process.executable like (
       "/usr/local/cpanel/*/bin/perl", "/opt/puppetlabs/puppet/bin/ruby", "/opt/unified-monitoring-agent/embedded/bin/ruby"
     ) or
     process.command_line in (
       "/usr/bin/perl /usr/sbin/pveum realm sync planet",
       "/usr/bin/perl -T /usr/bin/pveproxy start", "/usr/bin/perl /usr/bin/pveupdate"
     )
   )
  ] by process.entity_id
  [network where host.os.type == "linux" and event.action == "connection_attempted" and event.type == "start" and
   not process.executable == "/tmp/newroot/bin/curl"] by process.parent.entity_id
```



### Suspicious Outbound Network Connection via Unsigned Binary

Branch count: 2  
Document count: 4  
Index: geneve-ut-1407

```python
sequence by process.entity_id with maxspan=1m
  [process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and 
    (process.code_signature.trusted == false or process.code_signature.exists == false) and
    process.args_count == 1 and
    not process.executable like "/opt/homebrew/*"]
  [network where host.os.type == "macos" and event.type == "start" and 
    destination.domain == null and 
    not destination.port in (443, 80, 53, 22, 25, 587, 993, 465, 8080, 8200, 9200) and 
    destination.port < 49152 and
    not cidrmatch(destination.ip, "0.0.0.0", "240.0.0.0/4", "233.252.0.0/24", "224.0.0.0/4", 
                  "198.19.0.0/16", "192.18.0.0/15", "192.0.0.0/24", "10.0.0.0/8", "127.0.0.0/8", 
                  "169.254.0.0/16", "172.16.0.0/12", "192.0.2.0/24", "192.31.196.0/24", 
                  "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "100.64.0.0/10", 
                  "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
                  "::1", "FE80::/10", "FF00::/8")]
```



### Suspicious Outlook Child Process

Branch count: 4  
Document count: 4  
Index: geneve-ut-1408

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "outlook.exe" and
  not (
    (
      process.executable : (
        "?:\\Program Files\\*",
        "?:\\Program Files (x86)\\*",
        "?:\\Windows\\System32\\WerFault.exe",
        "?:\\Windows\\SysWOW64\\WerFault.exe",
        "?:\\Windows\\system32\\wermgr.exe",
        "?:\\Users\\*\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
        "?:\\Users\\*\\AppData\\Local\\Temp\\NewOutlookInstall\\NewOutlookInstaller.exe",
        "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
        "?:\\Users\\*\\AppData\\Local\\Island\\Island\\Application\\Island.exe",
        "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
        "?:\\Users\\*\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe",
        "?:\\Windows\\System32\\IME\\SHARED\\IMEWDBLD.EXE",
        "?:\\Windows\\System32\\spool\\drivers\\x64\\*",
        "?:\\Windows\\System32\\prevhost.exe",
        "?:\\Windows\\System32\\dwwin.exe",
        "?:\\Windows\\System32\\mspaint.exe",
        "?:\\Windows\\SysWOW64\\mspaint.exe",
        "?:\\Windows\\System32\\notepad.exe",
        "?:\\Windows\\SysWOW64\\notepad.exe",
        "?:\\Windows\\System32\\smartscreen.exe",
        "?:\\Windows\\explorer.exe",
        "?:\\Windows\\splwow64.exe"
      ) and process.code_signature.trusted == true  
    ) or
    (
      process.name : "rundll32.exe" and
      process.args : "*hpmsn???.dll,MonitorPrintJobStatus*"
    )
  )
```



### Suspicious PDF Reader Child Process

Branch count: 212  
Document count: 212  
Index: geneve-ut-1409

```python
process where host.os.type == "windows" and event.type == "start" and
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



### Suspicious Passwd File Event Action

Branch count: 1  
Document count: 2  
Index: geneve-ut-1410

```python
sequence by host.id, process.parent.pid with maxspan=1m
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name == "openssl" and process.args == "passwd" and user.id != "0"]
  [file where host.os.type == "linux" and file.path == "/etc/passwd" and process.parent.pid != 1 and
   not auditd.data.a2 == "80000" and event.outcome == "success" and user.id != "0"]
```



### Suspicious Path Mounted

Branch count: 6  
Document count: 6  
Index: geneve-ut-1412

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name == "mount" and 
process.args like ("/tmp/*", "/var/tmp/*", "/dev/shm/*", "/home/*", "/root/*", "/mount") and process.parent.executable != null and
not (
  process.parent.executable like (
    "/bin/*", "/usr/bin/*", "/usr/local/bin/*", "/sbin/*", "/usr/sbin/*", "/usr/local/sbin/*", "/usr/libexec/*",
    "/usr/local/nutanix/ngt/*/python"
  ) or
  process.parent.executable in (
    "/usr/lib/uptrack/ksplice-apply", "/usr/lib/Acronis/BackupAndRecovery/mms",
    "/usr/lib/Acronis/BackupAndRecovery/service_process-bin", "/usr/lib/systemd/systemd", "/etc/grub.d/10_linux_zfs",
    "./tools/image-summary", "/nfsplugin", "/usr/share/ksplice/ksplice-apply", "/lib/systemd/systemd"
  ) or
  process.parent.name == "snapd"
)
```



### Suspicious Portable Executable Encoded in Powershell Script

Branch count: 1  
Document count: 1  
Index: geneve-ut-1413

```python
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    TVqQAAMAAAAEAAAA
  ) and not user.id : "S-1-5-18"
```



### Suspicious Print Spooler File Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-1416

```python
file where host.os.type == "windows" and event.type == "deletion" and
  file.extension : "dll" and file.path : "?:\\Windows\\System32\\spool\\drivers\\x64\\3\\*.dll" and
  not process.name : ("spoolsv.exe", "dllhost.exe", "explorer.exe")
```



### Suspicious Print Spooler Point and Print DLL

Branch count: 1  
Document count: 2  
Index: geneve-ut-1417

```python
sequence by host.id with maxspan=30s
[registry where host.os.type == "windows" and
   registry.value : "SpoolDirectory" and
   registry.path : "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\SpoolDirectory" and
   registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4"]
[registry where host.os.type == "windows" and
   registry.value : "Module" and
   registry.path : "*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\CopyFiles\\Payload\\Module" and
   registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4\\*"]
```



### Suspicious Print Spooler SPL File Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-1418

```python
file where host.os.type == "windows" and event.type != "deletion" and
  file.extension : "spl" and
  file.path : "?:\\Windows\\System32\\spool\\PRINTERS\\*" and
  not process.name : ("spoolsv.exe",
                      "printfilterpipelinesvc.exe",
                      "PrintIsolationHost.exe",
                      "splwow64.exe",
                      "msiexec.exe",
                      "poqexec.exe",
                      "System") and
  not user.id : "S-1-5-18" and
  not process.executable :
            ("?:\\Windows\\System32\\mmc.exe",
             "\\Device\\Mup\\*.exe",
             "?:\\Windows\\System32\\svchost.exe",
             "?:\\Windows\\System32\\mmc.exe",
             "?:\\Windows\\System32\\printui.exe",
             "?:\\Windows\\System32\\mstsc.exe",
             "?:\\Windows\\System32\\spool\\*.exe",
             "?:\\Program Files\\*.exe",
             "?:\\Program Files (x86)\\*.exe",
             "?:\\PROGRA~1\\*.exe",
             "?:\\PROGRA~2\\*.exe",
             "?:\\Windows\\System32\\rundll32.exe")
```



### Suspicious Process Execution via Renamed PsExec Executable

Branch count: 1  
Document count: 1  
Index: geneve-ut-1423

```python
process where host.os.type == "windows" and event.type == "start" and
  process.pe.original_file_name : "psexesvc.exe" and not process.name : "PSEXESVC.exe"
```



### Suspicious RDP ActiveX Client Loaded

Branch count: 48  
Document count: 48  
Index: geneve-ut-1424

```python
any where host.os.type == "windows" and
 (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
 (?dll.name : "mstscax.dll" or file.name : "mstscax.dll") and
   /* depending on noise in your env add here extra paths  */
  process.executable : (
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
  not process.executable : (
    "?:\\Windows\\System32\\mstsc.exe",
    "?:\\Windows\\SysWOW64\\mstsc.exe",
    "?:\\Windows\\System32\\vmconnect.exe",
    "?:\\Windows\\System32\\WindowsSandboxClient.exe",
    "?:\\Windows\\System32\\hvsirdpclient.exe"
  )
```



### Suspicious Remote Registry Access via SeBackupPrivilege

Branch count: 1  
Document count: 2  
Index: geneve-ut-1426

```python
sequence by winlog.computer_name, winlog.event_data.SubjectLogonId with maxspan=1m
 [iam where host.os.type == "windows" and event.action == "logged-in-special" and
  winlog.event_data.PrivilegeList : "SeBackupPrivilege" and

  /* excluding accounts with existing privileged access */
  not winlog.event_data.PrivilegeList : "SeDebugPrivilege"]
 [any where host.os.type == "windows" and event.code == "5145" and winlog.event_data.RelativeTargetName : "winreg"]
```



### Suspicious Renaming of ESXI Files

Branch count: 10  
Document count: 10  
Index: geneve-ut-1427

```python
file where host.os.type == "linux" and event.action == "rename" and (
  file.Ext.original.name : ("*.vmdk", "*.vmx", "*.vmxf", "*.vmsd", "*.vmsn", "*.vswp", "*.vmss", "*.nvram", "*.vmem") or
  (file.name == "index.html" and file.Ext.original.path like "/usr/lib/vmware/*")
)
and not (
  file.name : ("*.vmdk", "*.vmx", "*.vmxf", "*.vmsd", "*.vmsn", "*.vswp", "*.vmss", "*.nvram", "*.vmem") or
  process.executable like (
    "/usr/sbin/gdm", "/usr/share/dotnet/dotnet", "/usr/bin/dotnet", "/usr/sbin/apache2",
    "/var/lib/docker/overlay2/*/usr/bin/dotnet", "/usr/lib/3cxpbx/3cxSystemService"
  )
)
```



### Suspicious ScreenConnect Client Child Process

Branch count: 152  
Document count: 152  
Index: geneve-ut-1429

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name :
                ("ScreenConnect.ClientService.exe",
                 "ScreenConnect.WindowsClient.exe",
                 "ScreenConnect.WindowsBackstageShell.exe",
                 "ScreenConnect.WindowsFileManager.exe") and
  (
   (process.name : "powershell.exe" and
    process.args : ("-enc", "-ec", "-e", "*downloadstring*", "*Reflection.Assembly*", "*http*")) or
   (process.name : "cmd.exe" and process.args : "/c") or
   (process.name : "net.exe" and process.args : "/add") or
   (process.name : "schtasks.exe" and process.args : ("/create", "-create")) or
   (process.name : "sc.exe" and process.args : "create") or
   (process.name : "rundll32.exe" and not process.args : "url.dll,FileProtocolHandler") or
   (process.name : "msiexec.exe" and process.args : ("/i", "-i") and
    process.args : ("/q", "/quiet", "/qn", "-q", "-quiet", "-qn", "-Q+")) or
   process.name : ("mshta.exe", "certutil.exe", "bistadmin.exe", "certreq.exe", "wscript.exe", "cscript.exe", "curl.exe",
                   "ssh.exe", "scp.exe", "wevtutil.exe", "wget.exe", "wmic.exe")
   )
```



### Suspicious Script Object Execution

Branch count: 12  
Document count: 12  
Index: geneve-ut-1430

```python
any where host.os.type == "windows" and
 (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
 (?dll.name : "scrobj.dll" or ?file.name : "scrobj.dll") and
 process.executable : ("?:\\Windows\\System32\\*.exe", "?:\\Windows\\SysWOW64\\*.exe") and
 not process.executable : (
       "?:\\Windows\\System32\\cscript.exe",
       "?:\\Windows\\SysWOW64\\cscript.exe",
       "?:\\Windows\\system32\\msiexec.exe",
       "?:\\Windows\\SysWOW64\\msiexec.exe",
       "?:\\Windows\\System32\\smartscreen.exe",
       "?:\\Windows\\system32\\taskhostw.exe",
       "?:\\windows\\system32\\inetsrv\\w3wp.exe",
       "?:\\windows\\SysWOW64\\inetsrv\\w3wp.exe",
       "?:\\Windows\\system32\\wscript.exe",
       "?:\\Windows\\SysWOW64\\wscript.exe",
       "?:\\Windows\\System32\\mshta.exe",
       "?:\\Windows\\system32\\mobsync.exe",
       "?:\\Windows\\SysWOW64\\mobsync.exe",
       "?:\\Windows\\System32\\cmd.exe",
       "?:\\Windows\\SysWOW64\\cmd.exe",
       "?:\\Windows\\System32\\OpenWith.exe",
       "?:\\Windows\\System32\\wbem\\WMIADAP.exe",
       "?:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
```



### Suspicious SeIncreaseBasePriorityPrivilege Use

Branch count: 1  
Document count: 1  
Index: geneve-ut-1431

```python
event.category:iam and host.os.type:"windows" and event.code:"4674" and
winlog.event_data.PrivilegeList:"SeIncreaseBasePriorityPrivilege" and event.outcome:"success" and
winlog.event_data.AccessMask:"512" and not winlog.event_data.SubjectUserSid:("S-1-5-18" or "S-1-5-19" or "S-1-5-20")
```



### Suspicious SolarWinds Child Process

Branch count: 4  
Document count: 4  
Index: geneve-ut-1433

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name: ("SolarWinds.BusinessLayerHost.exe", "SolarWinds.BusinessLayerHostx64.exe") and
 not (
    process.name : (
        "APMServiceControl*.exe",
        "ExportToPDFCmd*.Exe",
        "SolarWinds.Credentials.Orion.WebApi*.exe",
        "SolarWinds.Orion.Topology.Calculator*.exe",
        "Database-Maint.exe",
        "SolarWinds.Orion.ApiPoller.Service.exe",
        "WerFault.exe",
        "WerMgr.exe",
        "SolarWinds.BusinessLayerHost.exe",
        "SolarWinds.BusinessLayerHostx64.exe",
        "SolarWinds.Topology.Calculator.exe",
        "SolarWinds.Topology.Calculatorx64.exe",
        "SolarWinds.APM.RealTimeProcessPoller.exe") and
    process.code_signature.trusted == true
 ) and
 not process.executable : ("?:\\Windows\\SysWOW64\\ARP.EXE", "?:\\Windows\\SysWOW64\\lodctr.exe", "?:\\Windows\\SysWOW64\\unlodctr.exe")
```



### Suspicious SolarWinds Web Help Desk Java Module Load or Child Process

Branch count: 12  
Document count: 12  
Index: geneve-ut-1434

```python
any where host.os.type == "windows" and
(
 (event.category == "library" and
  process.executable : ("C:\\Program Files\\WebHelpDesk\\*\\java.exe", "C:\\Program Files (x86)\\WebHelpDesk\\*\\java.exe") and
  (dll.path : "\\Device\\Mup\\*" or dll.code_signature.trusted == false or ?dll.code_signature.exists == false)) or

 (event.category == "process" and process.name : ("cmd.exe", "powershell.exe", "rundll32.exe") and
  process.parent.executable : ("C:\\Program Files\\WebHelpDesk\\*\\java*.exe", "C:\\Program Files (x86)\\WebHelpDesk\\*\\java*.exe"))
)
```



### Suspicious Startup Shell Folder Modification

Branch count: 32  
Document count: 32  
Index: geneve-ut-1435

```python
registry where host.os.type == "windows" and event.type == "change" and
 registry.value : ("Common Startup", "Startup") and
 registry.path : (
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "HKCU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKCU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup"
     ) and
  registry.data.strings != null and
  /* Normal Startup Folder Paths */
  not registry.data.strings : (
           "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "%%USERPROFILE%%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
           "\\\\*"
           )
```



### Suspicious StartupItem Plist Creation

Branch count: 4  
Document count: 4  
Index: geneve-ut-1436

```python
file where host.os.type == "macos" and event.type != "deletion" and 
  file.name == "StartupParameters.plist" and 
  file.path like ("/System/Library/StartupItems/*/StartupParameters.plist", 
  "/Library/StartupItems/*/StartupParameters.plist") and
  not (process.code_signature.signing_id == "com.apple.shove" and process.code_signature.trusted == true)
```



### Suspicious Symbolic Link Created

Branch count: 918  
Document count: 918  
Index: geneve-ut-1437

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name == "ln" and process.args in ("-s", "-sf") and
  (
    /* suspicious files */
    (process.args in ("/etc/shadow", "/etc/shadow-", "/etc/shadow~", "/etc/gshadow", "/etc/gshadow-") or
    (process.working_directory == "/etc" and process.args in ("shadow", "shadow-", "shadow~", "gshadow", "gshadow-"))) or

    /* suspicious bins */
    (process.args in ("/bin/bash", "/bin/dash", "/bin/sh", "/bin/tcsh", "/bin/csh", "/bin/zsh", "/bin/ksh", "/bin/fish") or
    (process.working_directory == "/bin" and process.args : ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish"))) or
    (process.args in ("/usr/bin/bash", "/usr/bin/dash", "/usr/bin/sh", "/usr/bin/tcsh", "/usr/bin/csh", "/usr/bin/zsh", "/usr/bin/ksh", "/usr/bin/fish") or
    (process.working_directory == "/usr/bin" and process.args in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish"))) or

    /* suspicious locations */
    (process.args : ("/etc/cron.d/*", "/etc/cron.daily/*", "/etc/cron.hourly/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*")) or
    (process.args : ("/home/*/.ssh/*", "/root/.ssh/*","/etc/sudoers.d/*", "/dev/shm/*"))
  ) and
  process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
  not user.Ext.real.id == "0" and not group.Ext.real.id == "0"
```



### Suspicious Termination of ESXI Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-1441

```python
process where host.os.type == "linux" and event.type == "end" and process.name in ("vmware-vmx", "vmx")
and process.parent.name == "kill"
```



### Suspicious Troubleshooting Pack Cabinet Execution

Branch count: 160  
Document count: 160  
Index: geneve-ut-1442

```python
process where host.os.type == "windows" and event.action == "start" and
  (process.name : "msdt.exe" or ?process.pe.original_file_name == "msdt.exe") and process.args : "/cab" and
  process.parent.name : (
    "firefox.exe", "chrome.exe", "msedge.exe", "explorer.exe", "brave.exe", "whale.exe", "browser.exe",
    "dragon.exe", "vivaldi.exe", "opera.exe", "iexplore", "firefox.exe", "waterfox.exe", "iexplore.exe",
    "winrar.exe", "winrar.exe", "7zFM.exe", "outlook.exe", "winword.exe", "excel.exe"
  ) and
  process.args : (
    "?:\\Users\\*",
    "\\\\*",
    "http*",
    "ftp://*"
  )
```



### Suspicious Utility Launched via ProxyChains

Branch count: 204  
Document count: 204  
Index: geneve-ut-1444

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "proxychains" and process.args : (
  "ssh", "sshd", "sshuttle", "socat", "iodine", "iodined", "dnscat", "hans", "hans-ubuntu", "ptunnel-ng",
  "ssf", "3proxy", "ngrok", "gost", "pivotnacci", "chisel*", "nmap", "ping", "python*", "php*", "perl", "ruby",
  "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk", "java", "telnet", "ftp", "curl", "wget"
)
```



### Suspicious WMI Event Subscription Created

Branch count: 4  
Document count: 4  
Index: geneve-ut-1445

```python
any where host.os.type == "windows" and
 (
   (event.dataset == "windows.sysmon_operational" and event.code == "21" and
    ?winlog.event_data.Operation : "Created" and ?winlog.event_data.Consumer : ("*subscription:CommandLineEventConsumer*", "*subscription:ActiveScriptEventConsumer*")) or

   (event.dataset == "endpoint.events.api" and event.provider == "Microsoft-Windows-WMI-Activity" and ?process.Ext.api.name == "IWbemServices::PutInstance" and
    ?process.Ext.api.parameters.consumer_type in ("ActiveScriptEventConsumer", "CommandLineEventConsumer"))
 )
```



### Suspicious WMI Image Load from MS Office

Branch count: 30  
Document count: 30  
Index: geneve-ut-1446

```python
any where host.os.type == "windows" and
 (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
  process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE", "MSACCESS.EXE") and
  (?dll.name : "wmiutils.dll" or file.name : "wmiutils.dll")
```



### Suspicious WMIC XSL Script Execution

Branch count: 48  
Document count: 96  
Index: geneve-ut-1447

```python
sequence by process.entity_id with maxspan = 2m
[process where host.os.type == "windows" and event.type == "start" and
   (process.name : "WMIC.exe" or process.pe.original_file_name : "wmic.exe") and
   process.args : ("format*:*", "/format*:*", "*-format*:*") and
   not process.command_line : ("* /format:table *", "* /format:table")]
[any where host.os.type == "windows" and (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
 (?dll.name : ("jscript.dll", "vbscript.dll") or file.name : ("jscript.dll", "vbscript.dll"))]
```



### Suspicious Web Browser Sensitive File Access

Branch count: 18  
Document count: 18  
Index: geneve-ut-1448

```python
file where event.action == "open" and host.os.type == "macos" and process.executable != null and
 file.name like~ ("cookies.sqlite",
                  "key?.db",
                  "logins.json",
                  "Cookies",
                  "Cookies.binarycookies",
                  "Login Data") and
 ((process.code_signature.trusted == false or process.code_signature.exists == false) or process.name == "osascript") and
 not process.code_signature.signing_id == "org.mozilla.firefox" and
 not Effective_process.executable like "/Library/Elastic/Endpoint/elastic-endpoint.app/Contents/MacOS/elastic-endpoint"
```



### Suspicious WerFault Child Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-1449

```python
process where host.os.type == "windows" and event.type == "start" and

  process.parent.name : "WerFault.exe" and

  /* args -s and -t used to execute a process via SilentProcessExit mechanism */
  (process.parent.args : "-s" and process.parent.args : "-t" and process.parent.args : "-c") and

  not process.executable : ("?:\\Windows\\SysWOW64\\Initcrypt.exe", "?:\\Program Files (x86)\\Heimdal\\Heimdal.Guard.exe")
```



### Suspicious Windows Powershell Arguments

Branch count: 231  
Document count: 231  
Index: geneve-ut-1451

```python
process where host.os.type == "windows" and event.type == "start" and
 process.name : "powershell.exe" and

  not (
    ?user.id == "S-1-5-18" and
    /* Don't apply the user.id exclusion to Sysmon for compatibility */
    not event.dataset : ("windows.sysmon_operational", "windows.sysmon")
  ) and

  (
    process.command_line : (
          "*^*^*^*^*^*^*^*^*^*",
          "*`*`*`*`*",
          "*+*+*+*+*+*+*",
          "*[char[]](*)*-join*",
          "*Base64String*",
          "*[*Convert]*",
          "*.Compression.*",
          "*-join($*",
          "*.replace*",
          "*MemoryStream*",
          "*WriteAllBytes*",
          "* -enc *",
          "* -ec *",
          "* /e *",
          "* /enc *",
          "* /ec *",
          "*WebClient*",
          "*DownloadFile*",
          "*DownloadString*",
          "* iex*",
          "* iwr*",
          "* aQB3AHIAIABpA*",
          "*Reflection.Assembly*",
          "*Assembly.GetType*",
          "*$env:temp\\*start*",
          "*powercat*",
          "*nslookup -q=txt*",
          "*$host.UI.PromptForCredential*",
          "*Net.Sockets.TCPClient*",
          "*curl *;Start*",
          "powershell.exe \"<#*",
          "*ssh -p *",
          "*http*|iex*",
          "*@SSL\\DavWWWRoot\\*.ps1*",
          "*.lnk*.Seek(0x*",
          "*[string]::join(*",
          "*[Array]::Reverse($*",
          "* hidden $(gc *",
          "*=wscri& set*",
          "*http'+'s://*",
          "*.content|i''Ex*",
          "*//:sptth*",
          "*//:ptth*",
          "*h''t''t''p*",
          "*'tp'':''/'*",
          "*$env:T\"E\"MP*",
          "*;cmd /c $?",
          "*s''t''a''r*",
          "*$*=Get-Content*AppData*.SubString(*$*",
          "*=cat *AppData*.substring(*);*$*",
          "*-join'';*|powershell*",
          "*.Content;sleep *|powershell*",
          "*h\''t\''tp:\''*",
          "*-e aQB3AHIAIABp*",
          "*iwr *https*).Content*",
          "*$env:computername*http*",
          "*;InVoKe-ExpRESsIoN $COntent.CONTENt;*",
          "*WebClient*example.com*",
          "*=iwr $*;iex $*",
          "*ServerXmlHttp*IEX*",
          "*XmlDocument*IEX*"
    ) or

    (process.args : "-c" and process.args : "&{'*") or

    (process.args : "-Outfile" and process.args : "Start*") or

    (process.args : "-bxor" and process.args : "0x*") or

    process.args : "$*$*;set-alias" or

    process.args == "-e" or

    // ATHPowerShellCommandLineParameter
    process.args : ("-EncodedCommandParamVariation", "-UseEncodedArguments", "-CommandParamVariation") or

    (
      process.parent.name : ("explorer.exe", "cmd.exe") and
      process.command_line : ("*-encodedCommand*", "*Invoke-webrequest*", "*WebClient*", "*Reflection.Assembly*"))
    )
```



### Suspicious Zoom Child Process

Branch count: 4  
Document count: 4  
Index: geneve-ut-1452

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "Zoom.exe" and process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe")
```



### Suspicious pbpaste High Volume Activity

Branch count: 1  
Document count: 5  
Index: geneve-ut-1454

```python
sequence by host.hostname, host.id with maxspan=1m
[process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and process.name: "pbpaste"] with runs = 5
```



### Suspicious which Enumeration

Branch count: 3  
Document count: 3  
Index: geneve-ut-1456

```python
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start") and
  process.name == "which" and process.args_count >= 10 and not (
    process.parent.name == "jem" or
    process.parent.executable like ("/vz/root/*", "/var/lib/docker/*") or
    process.args == "--tty-only"
  )

/* potential tuning if rule would turn out to be noisy
and process.args in ("nmap", "nc", "ncat", "netcat", nc.traditional", "gcc", "g++", "socat") and
process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
*/
```



### Symbolic Link to Shadow Copy Created

Branch count: 8  
Document count: 8  
Index: geneve-ut-1458

```python
process where host.os.type == "windows" and event.type == "start" and
 (
    (?process.pe.original_file_name in ("Cmd.Exe","PowerShell.EXE")) or
    (process.name : ("cmd.exe", "powershell.exe"))
 ) and

 /* Create Symbolic Link to Shadow Copies */
 process.args : ("*mklink*", "*SymbolicLink*") and process.command_line : ("*HarddiskVolumeShadowCopy*")
```



### System Binary Moved or Copied

Branch count: 24  
Document count: 24  
Index: geneve-ut-1459

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and process.name in ("cp", "mv") and
file.Ext.original.path : (
  "/bin/*", "/usr/bin/*", "/usr/local/bin/*", "/sbin/*", "/usr/sbin/*", "/usr/local/sbin/*"
) and not (
  file.Ext.original.path : (
    "/bin/*.tmp", "/usr/bin/*.tmp", "/usr/local/bin/*.tmp", "/sbin/*.tmp", "/usr/sbin/*.tmp", "/usr/local/sbin/*.tmp"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : ("/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/tmp/newroot/*")
)
```



### System Binary Path File Permission Modification

Branch count: 54  
Document count: 54  
Index: geneve-ut-1460

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name == "chmod" and
process.args like (
  "/bin/*", "/usr/bin/*", "/sbin/*", "/usr/sbin/*", "/usr/local/sbin/*", "/lib/*", "/usr/lib/*", "/lib64/*", "/usr/lib64/*"
) and
process.args in ("4755", "755", "000", "777", "444", "+x") and not (
  process.args in (
    "/bin/chmod", "/usr/bin/chmod", "/usr/local/bin/chmod", "/usr/bin/restic", "/usr/local/bin/ack-tool", "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/local/bin/deploy-entrypoint.sh", "/usr/local/bin/mc", "/usr/local/bin/start.sh", "/usr/local/sbin/MySQLBackups/mysql_backup.sh",
    "/usr/bin/coreutils", "/usr/bin/docker-compose", "/usr/bin/cri-dockerd", "/usr/sbin/mkfs.ext5", "/usr/bin/cyclonedx", "/usr/bin/distro",
    "/usr/bin/telegraf", "/usr/bin/jq", "/usr/bin/google-chrome", "/usr/sbin/login_duo"
  ) or
  process.args like "/usr/lib/omnissa/*" or
  process.parent.executable like (
    "/tmp/newroot/*", "/var/lib/dpkg/*", "/usr/libexec/postfix/post-install", "/kaniko/executor", "./install_viewagent.sh", "/bin/make" 
  ) or
  process.parent.args like (
    "/var/lib/dpkg/*", "/usr/lib/postfix/bin/post-install", "/usr/lib/postfix/sbin/post-install", "/usr/libexec/postfix/post-install",
    "./install_viewagent.sh", "/usr/lib/omnissa/*", "/var/tmp/rpm-tmp.*"
  ) or
  process.parent.name in ("udevadm", "systemd", "entrypoint", "sudo", "dart") or
  process.parent.command_line == "runc init"
)
```



### System File Ownership Change

Branch count: 3  
Document count: 3  
Index: geneve-ut-1462

```python
process where host.os.type == "windows" and event.type == "start" and
  (
   (process.name : "icacls.exe" and process.args : "/reset") or
   (process.name : "takeown.exe" and process.args : "/f") or
   (process.name : "icacls.exe" and process.args : "/grant" and process.args : "Everyone:F")
   ) and
   process.command_line : "*.exe *C:\\Windows\\*"
```



### System Hosts File Access

Branch count: 32  
Document count: 32  
Index: geneve-ut-1463

```python
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and
process.name in ("vi", "nano", "cat", "more", "less", "vim", "vim.basic", "emacs") and process.args == "/etc/hosts" and
not ?process.working_directory in ("/opt/SolarWinds/Agent/bin/Plugins/SCM", "/opt/cohesityagent/software/crux/bin")
```



### System Information Discovery via Windows Command Shell

Branch count: 2  
Document count: 2  
Index: geneve-ut-1464

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "cmd.exe" and process.args : "/c" and process.args : ("set", "dir") and
  not process.parent.executable : (
    "?:\\Program Files\\*",
    "?:\\Program Files (x86)\\*",
    "?:\\PROGRA~1\\*",
    "?:\\TeamCity\\jre\\bin\\java.exe"
  ) and
  not process.args : (
    "*\\db\\rabbit@*", "*/db/rabbit@*",
    "*rabbitmq/db/*", "*RabbitMQ\\db*"
  ) and
  not process.parent.args : "*C:\\Program Files (x86)\\Tanium\\Tanium Client\\TPython\\TPython.bat*"
```



### System Information Discovery via dmidecode from Parent Shell

Branch count: 24  
Document count: 24  
Index: geneve-ut-1465

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
process.name == "dmidecode" and process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
process.parent.args == "-c"
```



### System Log File Deletion

Branch count: 24  
Document count: 24  
Index: geneve-ut-1466

```python
file where host.os.type == "linux" and event.type == "deletion" and file.path in (
  "/var/run/utmp", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog", "/var/log/faillog",
  "/var/log/syslog", "/var/log/messages", "/var/log/secure", "/var/log/auth.log", "/var/log/boot.log",
  "/var/log/kern.log", "/var/log/dmesg"
) and not (
  process.name in ("gzip", "executor", "dockerd") or
  (process.executable in ("/usr/bin/podman", "/dev/fd/3") and file.name == "lastlog")
)
```



### System Path File Creation and Execution Detected via Defend for Containers

Branch count: 54  
Document count: 54  
Index: geneve-ut-1469

```python
file where host.os.type == "linux" and event.type == "creation" and process.interactive == true and
file.path like (
  "/etc/*", "/root/*", "/bin/*", "/usr/bin/*", "/usr/local/bin/*", "/entrypoint*"
) and (
  process.name like ("wget", "curl") or
  (process.name == "busybox" and process.args == "wget") or
  process.executable like ("/tmp/*", "/dev/shm/*", "/var/tmp/*", "/run/*", "/var/run/*", "/mnt/*")
) and container.id like "?*"
```



### System Service Discovery through built-in Windows Utilities

Branch count: 14  
Document count: 14  
Index: geneve-ut-1471

```python
process where host.os.type == "windows" and event.type == "start" and process.parent.executable != null and
  (
  ((process.name: "net.exe" or process.pe.original_file_name == "net.exe" or (process.name : "net1.exe" and 
    not process.parent.name : "net.exe")) and process.args : ("start", "use") and process.args_count == 2 and
    not process.parent.args : ("*.bat", "*netlogon*", "\\\\*")) or
  ((process.name: "sc.exe" or process.pe.original_file_name == "sc.exe") and process.args: ("query", "q*") and not process.parent.args : "*.bat") or
  ((process.name: "tasklist.exe" or process.pe.original_file_name == "tasklist.exe") and process.args: "/svc" and not process.command_line : "*\\Windows\\TEMP\\nessus_task_list*") or
  (process.name : "psservice.exe" or process.pe.original_file_name == "psservice.exe")
  ) and
  not user.id in ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
  not process.parent.executable in
                       ("C:\\Program Files\\AzureConnectedMachineAgent\\himds.exe",
                        "C:\\Program Files\\AzureConnectedMachineAgent\\azcmagent.exe",
                        "C:\\Program Files\\Varian\\DICOMServices\\VMS.DICOMServices.ServiceFW.GenericControlledServiceHost.exe",
                        "C:\\Senior\\HCM\\jdk-11.0.2\\bin\\java.exe",
                        "D:\\biomerieux\\programs\\ServiceMonitor\\bin\\MylaServiceMonitor.exe",
                        "C:\\ViewPowerPro\\openJDK\\bin\\javaw.exe",
                        "C:\\ServiceNow MID Server mid-server-autosports-prod\\agent\\jre\\bin\\java.exe") and
  not process.command_line in ("sc  queryex SCardSvr",
                               "sc  query \"Axway_Integrator\" ",
                               "sc  query \"Delta enteliVAULT PostgreSQL\" ",
                               "sc  query \"WERMA-WIN-Connector\" ",
                               "sc  query _EWSSynchronizationServer_JDE ",
                               "sc query SchneiderUPSMySQL")
```



### System Shells via Services

Branch count: 4  
Document count: 4  
Index: geneve-ut-1472

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "services.exe" and
  process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe") and

  /* Third party FP's */
  not process.args : "NVDisplay.ContainerLocalSystem"
```



### System Time Discovery

Branch count: 4  
Document count: 4  
Index: geneve-ut-1473

```python
process where host.os.type == "windows" and event.type == "start" and
(
 (
    (process.name: "net.exe" or (process.name : "net1.exe" and not process.parent.name : "net.exe")) and 
    process.args : "time" and not process.args : "/set"
 ) or 
 (process.name: "w32tm.exe" and process.args: "/tz") or 
 (process.name: "tzutil.exe" and process.args: "/g")
) and not user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20")
```



### System V Init Script Created

Branch count: 128  
Document count: 128  
Index: geneve-ut-1474

```python
file where host.os.type == "linux" and event.action in ("creation", "file_create_event", "rename", "file_rename_event")
and file.path like "/etc/init.d/*" and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client", "./envbuilder/bin/envbuilder",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/usr/bin/pamac-daemon", "/opt/puppetlabs/puppet/bin/ruby",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "./usr/bin/podman", "/usr/lib/systemd/systemd",
    "/usr/bin/buildah", "/dev/.buildkit_qemu_emulator", "/usr/lib/nvidia/post-install", "/usr/bin/dnf5", "/usr/sbin/yum-cron"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove", "dpkg-new") or
  ?file.Ext.original.name like "*.dpkg-new" or
  file.path like ("/etc/init.d/*beat*", "/etc/init.d/elastic-agent*") or
  process.executable like (
    "/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*", "/var/lib/docker/overlay2/*/dockerd ",
    "/var/lib/containers/storage/overlay/*/dockerd"
  ) or
  process.name in ("docker-init", "jumpcloud-agent", "crio") or
  process.executable == null or
  process.name in ("executor", "univention-config-registry", "install", "dockerd-entrypoint.sh", "platform-python*", "ssm-agent-worker") or
  (process.name == "ln" and file.path : "/etc/init.d/rc*.d/*") or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") or
  (process.name == "cp" and file.path == "/etc/init.d/unified-monitoring-agent") or
  (process.name == "./vmware-install.pl" and file.path == "/etc/init.d/vmware-tools")
)
```



### System and Network Configuration Check

Branch count: 10  
Document count: 10  
Index: geneve-ut-1475

```python
file where host.os.type == "macos" and event.action == "open" and 
  file.path like "/Library/Preferences/SystemConfiguration/preferences.plist" and
  (process.name like~ ("python*", "osascript", "perl", "ruby", "node") or 
   process.executable like ("/Users/Shared/*", "/tmp/*", "/private/tmp/*", "/var/tmp/*", "/private/var/tmp/*")) and
  not Effective_process.executable like "/Applications/Docker.app/Contents/MacOS/Docker"
```



### SystemKey Access via Command Line

Branch count: 4  
Document count: 4  
Index: geneve-ut-1476

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  process.args in ("/private/var/db/SystemKey", "/var/db/SystemKey") and
  not process.Ext.effective_parent.executable like "/Library/Elastic/Endpoint/elastic-endpoint.app/Contents/MacOS/elastic-endpoint"
```



### Systemd Generator Created

Branch count: 18  
Document count: 18  
Index: geneve-ut-1477

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and file.path : (
"/run/systemd/system-generators/*", "/etc/systemd/system-generators/*",
"/usr/local/lib/systemd/system-generators/*", "/lib/systemd/system-generators/*",
"/usr/lib/systemd/system-generators/*", "/etc/systemd/user-generators/*",
"/usr/local/lib/systemd/user-generators/*", "/usr/lib/systemd/user-generators/*",
"/lib/systemd/user-generators/*"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client", "/usr/sbin/sshd",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/libexec/platform-python",
    "./usr/bin/podman", "/usr/lib/dracut/dracut-install", "/usr/bin/dnf5", "/usr/libexec/packagekitd", "/usr/sbin/dnf",
    "/kaniko/executor", "/dev/fd/3", "/usr/local/bin/defender", "./usr/bin/qemu-aarch64-static", "/usr/sbin/yum"
  ) or
  process.executable like (
    "/snap/docker/*/bin/dockerd", "/var/lib/docker/overlay2/*/dockerd", "/var/lib/containers/storage/overlay/*/dockerd"
  ) or
  process.name like~ ("ssm-agent-worker", "crio", "docker-init", "systemd", "pacman", "python*", "platform-python*") or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable == null
)
```



### Systemd Service Created

Branch count: 80  
Document count: 80  
Index: geneve-ut-1478

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and file.path : (
  "/etc/systemd/system/*", "/etc/systemd/user/*", "/usr/local/lib/systemd/system/*",
  "/lib/systemd/system/*", "/usr/lib/systemd/system/*", "/usr/lib/systemd/user/*",
  "/home/*/.config/systemd/user/*", "/home/*/.local/share/systemd/user/*",
  "/root/.config/systemd/user/*", "/root/.local/share/systemd/user/*"
) and file.extension == "service" and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/bin/crio", "/usr/sbin/crond",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/kaniko/kaniko-executor",
    "/usr/local/bin/dockerd", "/usr/bin/podman", "/bin/install", "/proc/self/exe", "/usr/lib/systemd/systemd",
    "/usr/sbin/sshd", "/usr/bin/gitlab-runner", "/opt/gitlab/embedded/bin/ruby", "/usr/sbin/gdm", "/usr/bin/install",
    "/usr/local/manageengine/uems_agent/bin/dcregister", "/usr/local/bin/defender", "./usr/bin/podman",
    "/etc/checkpoint/common/install.sh", "/usr/bin/dnf5", "/usr/lib/dracut/dracut-install", "/usr/bin/buildah",
    "/opt/msp-agent/msp-agent-core", "/opt/sysmon/sysmon", "/opt/datadog-agent/embedded/bin/installer", "/usr/bin/tdnf",
    "/opt/teleport/system/bin/teleport-update", "/opt/gitlab/embedded/bin/cinc-client", "/usr/libexec/snapd/snapd",
    "/usr/sbin/yum-cron", "/sbin/yum-cron", "/opt/splunkforwarder/bin/splunk"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*",
    "/usr/share/elastic-agent/data/*/components/endpoint-security",  "/opt/Elastic/Agent/data/*/components/endpoint-security",
    "/opt/TrendMicro/EndpointBasecamp/*", "/var/lib/docker/overlay2/*dockerd", "/var/lib/containers/storage/overlay/*/dockerd",
    "/var/opt/kaspersky/kesl/*/opt/kaspersky/kesl/libexec/launcher"

  ) or
  process.executable == null or
  process.name like (
    "ssm-agent-worker", "python*", "platform-python*", "dnf_install", "cloudflared", "lxc-pve-prestart-hook",
    "convert-usrmerge", "elastic-agent", "google_metadata_script_runner", "update-alternatives", "gitlab-runner",
    "install", "crio", "apt-get", "package-cleanup", "dcservice", "dcregister", "jumpcloud-agent", "executor",
    "pacman", "convert2rhel", "packagekitd"
  ) or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```



### Systemd Shell Execution During Boot

Branch count: 7  
Document count: 7  
Index: geneve-ut-1480

```python
process where host.os.type == "linux" and event.type == "info" and event.action == "already_running" and
process.parent.name == "systemd" and process.name in ("bash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
process.parent.command_line == "/sbin/init" and process.args_count >= 2
```



### Systemd Timer Created

Branch count: 80  
Document count: 80  
Index: geneve-ut-1481

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and file.path : (
  "/etc/systemd/system/*", "/etc/systemd/user/*", "/usr/local/lib/systemd/system/*",
  "/lib/systemd/system/*", "/usr/lib/systemd/system/*", "/usr/lib/systemd/user/*",
  "/home/*/.config/systemd/user/*", "/home/*/.local/share/systemd/user/*",
  "/root/.config/systemd/user/*", "/root/.local/share/systemd/user/*"
) and file.extension == "timer" and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/usr/bin/pamac-daemon", "./usr/bin/podman",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/bin/crio", "/usr/sbin/crond",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/kaniko/kaniko-executor",
    "/usr/local/bin/dockerd", "/usr/bin/podman", "/bin/install", "/proc/self/exe", "/kaniko/executor",
    "/etc/checkpoint/common/install.sh", "/usr/bin/dnf5", "/usr/libexec/packagekitd", "/usr/sbin/dnf",
    "/opt/kaniko/executor", "/usr/bin/env", "/usr/local/bin/teleport-update", "/usr/bin/buildah",
    "/usr/lib/systemd/systemd", "/usr/local/bin/defender"
  ) or
  process.name like (
    "python*", "crio", "apt-get", "install", "snapd", "cloudflared", "sshd", "convert-usrmerge", "docker-init",
    "google_metadata_script_runner", "ssm-agent-worker", "pacman", "convert2rhel", "platform-python*"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable like (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*",
    "/var/lib/docker/overlay2/*/dockerd", "/home/*/bin/dockerd", "/var/lib/containers/storage/overlay/*/dockerd"
  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```



### Systemd-udevd Rule File Creation

Branch count: 10  
Document count: 10  
Index: geneve-ut-1482

```python
file where host.os.type == "linux" and event.action == "creation" and
process.executable != null and file.extension == "rules" and
file.path like (
  "/lib/udev/*", "/etc/udev/rules.d/*", "/usr/lib/udev/rules.d/*", "/run/udev/rules.d/*", "/usr/local/lib/udev/rules.d/*"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe",  "/usr/bin/pamac-daemon", "./usr/bin/podman",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/libexec/netplan/generate",
    "/lib/systemd/system-generators/netplan", "/lib/systemd/systemd", "/usr/bin/containerd", "/usr/sbin/sshd",
    "/kaniko/executor", "/usr/local/bin/defender", "/usr/bin/dnf5", "/opt/kaniko/executor", "/lib/netplan/generate"
  ) or
  file.Ext.original.extension == "dpkg-new" or
  process.executable like (
    "/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*", "/usr/lib/*", "/usr/libexec/*",
     "/var/lib/docker/overlay2/*/dockerd", "/var/lib/containers/storage/overlay*/dockerd"
  ) or
  process.name in (
    "systemd", "netplan", "apt-get", "vmware-config-tools.pl", "systemd-hwdb", "ssm-agent-worker", "crio", "cloud-init", "convert2rhel" 
  ) or
  process.name like ("python*", "perl*") or
  (process.name == "sed" and file.name : "sed*")
)
```



### TCC Bypass via Mounted APFS Snapshot Access

Branch count: 2  
Document count: 2  
Index: geneve-ut-1483

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name == "mount_apfs" and
 process.args like~ "/System/Volumes/Data" and process.args like~ "noowners"
```



### Tampering of Shell Command-Line History

Branch count: 180  
Document count: 180  
Index: geneve-ut-1486

```python
process where event.action in ("exec", "exec_event", "executed", "process_started") and event.type == "start" and
(
  (
    (process.args : ("rm", "echo") or
    (process.args : "ln" and process.args : "-sf" and process.args : "/dev/null") or
    (process.args : "truncate" and process.args : "-s0")
  )
    and process.args : (
      ".bash_history", "/root/.bash_history", "/home/*/.bash_history","/Users/.bash_history", "/Users/*/.bash_history",
      ".zsh_history", "/root/.zsh_history", "/home/*/.zsh_history", "/Users/.zsh_history", "/Users/*/.zsh_history"
    )
  ) or
  (process.args : "history" and process.args : "-c") or
  (process.args : "export" and process.args : ("HISTFILE=/dev/null", "HISTFILESIZE=0")) or
  (process.args : "unset" and process.args : "HISTFILE") or
  (process.args : "set" and process.args : "history" and process.args : "+o")
) and not (
  process.executable like (
    "/usr/bin/timeout", "/usr/bin/kubectl", "/usr/bin/psql", "/usr/lib/postgresql/*/bin/psql", "/usr/bin/bazel", "/usr/bin/git",  "/usr/bin/jq", "/bin/grep"
  ) or
  process.command_line == "stat -c %s history"
)
```



### Tampering with RUNNER_TRACKING_ID in GitHub Actions Runners

Branch count: 4  
Document count: 4  
Index: geneve-ut-1487

```python
process where host.os.type in ("linux", "macos") and event.type == "start" and event.action == "exec" and
process.parent.name in ("Runner.Worker", "Runner.Listener") and process.env_vars like~ "RUNNER_TRACKING_ID*" and
not process.env_vars like~ "RUNNER_TRACKING_ID=github_*"
```



### Telnet Authentication Bypass via User Environment Variable

Branch count: 4  
Document count: 8  
Index: geneve-ut-1488

```python
sequence by host.id with maxspan=1s
 [process where host.os.type == "linux" and event.type == "start" and event.action in ("process_started", "executed") and process.name == "telnetd"] by process.pid
 [process where host.os.type == "linux" and event.type == "start" and event.action in ("process_started", "executed") and process.name == "login" and process.args : "-*f*"] by process.parent.pid
```



### Temporarily Scheduled Task Creation

Branch count: 1  
Document count: 2  
Index: geneve-ut-1489

```python
sequence by winlog.computer_name, winlog.event_data.TaskName with maxspan=5m
   [iam where host.os.type == "windows" and event.action == "scheduled-task-created" and not user.name : "*$"]
   [iam where host.os.type == "windows" and event.action == "scheduled-task-deleted" and not user.name : "*$"]
```



### Third-party Backup Files Deleted via Unexpected Process

Branch count: 30  
Document count: 30  
Index: geneve-ut-1490

```python
file where host.os.type == "windows" and event.type == "deletion" and
  (
    /* Veeam Related Backup Files */
    (
      file.extension : ("VBK", "VIB", "VBM") and
      not (
        process.executable : ("?:\\Windows\\*", "?:\\Program Files\\*", "?:\\Program Files (x86)\\*") and
        (process.code_signature.trusted == true and process.code_signature.subject_name : ("Veeam Software Group GmbH", "Veeam Software AG"))
      )
    ) or
    /* Veritas Backup Exec Related Backup File */
    (
      file.extension : "BKF" and
        not process.executable : (
          "?:\\Program Files\\Veritas\\Backup Exec\\*",
          "?:\\Program Files (x86)\\Veritas\\Backup Exec\\*"
        )
    )
  ) and
  not (
    process.name : ("MSExchangeMailboxAssistants.exe", "Microsoft.PowerBI.EnterpriseGateway.exe") and
      (process.code_signature.subject_name : "Microsoft Corporation" and process.code_signature.trusted == true)
  ) and
  not file.path : (
    "?:\\ProgramData\\Trend Micro\\*",
    "?:\\Program Files (x86)\\Trend Micro\\*",
    "?:\\$RECYCLE.BIN\\*"
  )
```



### Timestomping using Touch Command

Branch count: 8  
Document count: 8  
Index: geneve-ut-1496

```python
process where event.type == "start" and event.action == "exec" and process.name == "touch" and
process.parent.executable != null and process.args like (
  "-t*", "-d*", "-a*", "-m*", "-r*", "--date=*", "--reference=*", "--time=*"
) and not (
  process.parent.executable in (
    "/usr/local/bin/manage_omnimesh_logs", "/pro/bin/sys/install/packageUtils.sh", "/bin/dracut",
    "/usr/libexec/postfix/aliasesdb", "pwsh-preview", "/usr/bin/dracut", "/usr/share/initramfs-tools/hooks/amd64_microcode",
    "/usr/local/bin/start-mailserver.sh", "/usr/bin/ssm-agent-worker", "/bin/ssm-agent-worker", "/usr/local/cpanel/scripts/restartsrv_bind"
  ) or
  process.parent.executable like ("/opt/sw/tomcat/rc_scripts/*", "/tmp/newroot/var/lib/docker/overlay2/*", "/snap/*", "/opt/zeek/*") or
  process.parent.name in (
    "xargs", "find", "sudo", "make", "pmlogger_check", "pmlogger_daily", "pmlogger_janitor", "autoupdate", "pmlogctl",
    "spyglass", "desktop-launch", "pmiectl", "systemd"
  ) or
  process.parent.args like (
    "/home/*/scripts/auto_download_process.py", "/home/*/scripts/perl_python_eagu1p.py", "/var/lib/dpkg/info/*",
    "bazel-out/k8-dbg/bin/dependencies/thirdparty/libjansson_foreign_cc/build_script.sh", "/usr/lib/portage/python*/ebuild.sh",
    "/var/tmp/rpm-tmp.*", "/usr/lib/pcp/bin/pmlogger_janitor", "/usr/libexec/pcp/bin/pmlogger_janitor",
    "/usr/libexec/pcp/bin/pmlogger_daily", "/usr/lib/pcp/bin/pmlogger_daily", "/opt/oracle.ExaWatcher/GetExaWatcherResults.sh"
  ) or
  process.args in (
    "/usr/bin/coreutils", "--no-create", "/etc/opt/lumu/lumud.conf", "/opt/vuso*", "/opt/diff", "/etc/aliases.db", "/opt/cursor/cursor"
  ) or
  process.args like (
    "--checkpoint=*", "/root/.config/envman/*", "/var/tmp/dracut*", "/var/tmp/portage*", "/snap/*", "/var/tmp/pmlogger_*/stamp", "/opt/ubki/*.jar",
    "/usr/lib/go-*/bin/go", "/usr/lib/dracut/dracut-functions.sh", "/tmp/KSInstallAction.*/m/.patch/*"
  ) or
  process.command_line in ("/bin/touch -a /tmp/au_status", "touch -d 2 seconds ago /etc/postfix/main.cf") or
  process.parent.command_line == "runc init" or
  process.working_directory in ("/opt/libexec", "/opt/local/src/connectxx/build/src/mdp")
)
```



### Tool Installation Detected via Defend for Containers

Branch count: 325  
Document count: 325  
Index: geneve-ut-1498

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.interactive == true and (
  (process.name in ("apt", "apt-get", "dnf", "microdnf", "yum", "zypper", "tdnf") and process.args == "install") or
  (process.name == "apk" and process.args == "add") or
  (process.name == "pacman" and process.args like "-*S*") or
  (process.name in ("rpm", "dpkg") and process.args in ("-i", "--install"))
) and process.args like (
  "curl", "wget", "socat", "busybox", "openssl", "torsocks",
  "netcat", "netcat-openbsd", "netcat-traditional", "ncat", "tor",
  "python*", "perl", "node", "nodejs", "ruby", "lua", "bash", "sh",
  "dash", "zsh", "fish", "tcsh", "csh", "ksh"
) and container.id like "?*"
```



### Trap Signals Execution

Branch count: 4  
Document count: 4  
Index: geneve-ut-1499

```python
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and
process.name == "trap" and process.args : "SIG*"
```



### UAC Bypass Attempt via Elevated COM Internet Explorer Add-On Installer

Branch count: 1  
Document count: 1  
Index: geneve-ut-1500

```python
process where host.os.type == "windows" and event.type == "start" and
 process.executable : "C:\\*\\AppData\\*\\Temp\\IDC*.tmp\\*.exe" and
 process.parent.name : "ieinstal.exe" and process.parent.args : "-Embedding"

 /* uncomment once in winlogbeat */
 /* and not (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true) */
```



### UAC Bypass Attempt via Privileged IFileOperation COM Interface

Branch count: 6  
Document count: 6  
Index: geneve-ut-1501

```python
file where host.os.type == "windows" and event.type : "change" and process.name : "dllhost.exe" and
  /* Known modules names side loaded into process running with high or system integrity level for UAC Bypass, update here for new modules */
  file.name : ("wow64log.dll", "comctl32.dll", "DismCore.dll", "OskSupport.dll", "duser.dll", "Accessibility.ni.dll") and
  /* has no impact on rule logic just to avoid OS install related FPs */
  not file.path : ("C:\\Windows\\SoftwareDistribution\\*", "C:\\Windows\\WinSxS\\*")
```



### UAC Bypass Attempt via Windows Directory Masquerading

Branch count: 2  
Document count: 2  
Index: geneve-ut-1502

```python
process where host.os.type == "windows" and event.type == "start" and
  process.args : ("C:\\Windows \\system32\\*.exe", "C:\\Windows \\SysWOW64\\*.exe")
```



### UAC Bypass Attempt with IEditionUpgradeManager Elevated COM Interface

Branch count: 1  
Document count: 1  
Index: geneve-ut-1503

```python
process where host.os.type == "windows" and event.type == "start" and process.name : "Clipup.exe" and
  not process.executable : "C:\\Windows\\System32\\ClipUp.exe" and process.parent.name : "dllhost.exe" and
  /* CLSID of the Elevated COM Interface IEditionUpgradeManager */
  process.parent.args : "/Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}"
```



### UAC Bypass via DiskCleanup Scheduled Task Hijack

Branch count: 1  
Document count: 1  
Index: geneve-ut-1504

```python
process where host.os.type == "windows" and event.type == "start" and
 process.args : "/autoclean" and process.args : "/d" and process.executable != null and
 not process.executable : (
        "C:\\Windows\\System32\\cleanmgr.exe",
        "C:\\Windows\\SysWOW64\\cleanmgr.exe",
        "C:\\Windows\\System32\\taskhostw.exe",

        /* Crowdstrike specific exclusion as it uses NT Object paths */
        "\\Device\\HarddiskVolume*\\Windows\\System32\\cleanmgr.exe",
        "\\Device\\HarddiskVolume*\\Windows\\SysWOW64\\cleanmgr.exe",
        "\\Device\\HarddiskVolume*\\Windows\\System32\\taskhostw.exe"
)
```



### UAC Bypass via ICMLuaUtil Elevated COM Interface

Branch count: 2  
Document count: 2  
Index: geneve-ut-1505

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name == "dllhost.exe" and
 process.parent.args in ("/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}", "/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}") and
 process.pe.original_file_name != "WerFault.exe"
```



### UAC Bypass via Windows Firewall Snap-In Hijack

Branch count: 1  
Document count: 1  
Index: geneve-ut-1506

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name == "mmc.exe" and
 /* process.Ext.token.integrity_level_name == "high" can be added in future for tuning */
 /* args of the Windows Firewall SnapIn */
  process.parent.args == "WF.msc" and process.name != "WerFault.exe"
```



### Unauthorized Access to an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-1508

```python
event.dataset:okta.system and event.action:app.generic.unauth_app_access_attempt
```



### Uncommon Destination Port Connection by Web Server

Branch count: 45  
Document count: 45  
Index: geneve-ut-1510

```python
network where host.os.type == "linux" and event.type == "start" and event.action == "connection_attempted" and (
  process.name like (
    "apache", "nginx", "apache2", "httpd", "lighttpd", "caddy", "mongrel_rails", "gunicorn",
    "uwsgi", "openresty", "cherokee", "h2o", "resin", "puma", "unicorn", "traefik", "tornado", "hypercorn",
    "daphne", "twistd", "yaws", "webfsd", "httpd.worker", "flask", "rails", "mongrel", "php-fpm*", "php-cgi",
    "php-fcgi", "php-cgi.cagefs", "catalina.sh", "hiawatha", "lswsctrl"
  ) or
  user.name in ("apache", "www-data", "httpd", "nginx", "lighttpd", "tomcat", "tomcat8", "tomcat9") or
  user.id in ("33", "498", "48") or
  (process.name == "java" and process.working_directory like "/u0?/*")
) and
network.direction == "egress" and destination.ip != null and
not destination.port in (80, 443, 8080, 8443, 8000, 8888, 3128, 3306, 5432, 8220, 8082) and
not cidrmatch(destination.ip, "127.0.0.0/8", "::1","FE80::/10", "FF00::/8", "10.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32",
"192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24",
"224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")
```



### Unexpected Child Process of macOS Screensaver Engine

Branch count: 1  
Document count: 1  
Index: geneve-ut-1512

```python
process where host.os.type == "macos" and event.type == "start" and process.parent.name == "ScreenSaverEngine"
```



### Unix Socket Connection

Branch count: 68  
Document count: 68  
Index: geneve-ut-1513

```python
process where host.os.type == "linux" and event.type == "start" and
 event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
 (
  (process.name in ("nc", "ncat", "netcat", "nc.openbsd") and
   process.args == "-U" and process.args : ("/usr/local/*", "/run/*", "/var/run/*")) or
  (process.name == "socat" and
   process.args == "-" and process.args : ("UNIX-CLIENT:/usr/local/*", "UNIX-CLIENT:/run/*", "UNIX-CLIENT:/var/run/*")) or
  (process.name == "curl" and process.args : ("--unix-socket", "--abstract-unix-socket"))
) and
not (
  process.args == "/var/run/libvirt/libvirt-sock" or
  process.parent.name in ("bundle", "ruby", "haproxystatus.sh") or
  process.parent.command_line == "sh /docker-entrypoint autoheal" or
  process.command_line like "*runtime.autoheal*" or
  process.parent.executable == "/app/letsencrypt_service" or
  process.parent.args in ("/usr/libexec/netdata/plugins.d/cgroup-name.sh", "/healthcheck") or
  ?process.working_directory == "/app"
)
```



### Unsigned BITS Service Client Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-1515

```python
library where dll.name : "Bitsproxy.dll" and process.executable != null and
not process.code_signature.trusted == true and
not process.code_signature.status : ("errorExpired", "errorCode_endpoint*")
```



### Untrusted DLL Loaded by Azure AD Sync Service

Branch count: 2  
Document count: 2  
Index: geneve-ut-1520

```python
any where host.os.type == "windows" and process.name : "AzureADConnectAuthenticationAgentService.exe" and
(
 (event.category == "library" and event.action == "load") or
 (event.category == "process" and event.action : "Image loaded*")
) and

not (?dll.code_signature.trusted == true or file.code_signature.status == "Valid") and not

  (
   /* Elastic defend DLL path */
   ?dll.path :
         ("?:\\Windows\\assembly\\NativeImages*",
          "?:\\Windows\\Microsoft.NET\\*",
          "?:\\Windows\\WinSxS\\*",
          "?:\\Windows\\System32\\DriverStore\\FileRepository\\*") or

   /* Sysmon DLL path is mapped to file.path */
   file.path :
         ("?:\\Windows\\assembly\\NativeImages*",
          "?:\\Windows\\Microsoft.NET\\*",
          "?:\\Windows\\WinSxS\\*",
          "?:\\Windows\\System32\\DriverStore\\FileRepository\\*")
  )
```



### Untrusted Driver Loaded

Branch count: 2  
Document count: 2  
Index: geneve-ut-1521

```python
driver where host.os.type == "windows" and process.pid == 4 and
  (dll.code_signature.trusted == false or dll.code_signature.exists == false) and
  not dll.code_signature.status : ("errorExpired", "errorRevoked", "errorCode_endpoint:*")
```



### Unusual Child Process from a System Virtual Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-1526

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.pid == 4 and process.executable : "?*" and
  not process.executable : ("Registry", "MemCompression", "?:\\Windows\\System32\\smss.exe", "HotPatch")
```



### Unusual Child Process of dns.exe

Branch count: 1  
Document count: 1  
Index: geneve-ut-1527

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "dns.exe" and
  not process.executable : (
    "?:\\Windows\\System32\\conhost.exe",

    /* Crowdstrike specific exclusion as it uses NT Object paths */
    "\\Device\\HarddiskVolume*\\Windows\\System32\\conhost.exe",
    "\\Device\\HarddiskVolume*\\Program Files\\ReasonLabs\\*"
  ) and
  not ?process.parent.executable : "?:\\Program Files\\ReasonLabs\\DNS\\ui\\DNS.exe"
```



### Unusual D-Bus Daemon Child Process

Branch count: 12  
Document count: 12  
Index: geneve-ut-1536

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
process.parent.name == "dbus-daemon" and process.args_count > 1 and not (
  process.parent.args == "--session" or
  process.args in ("/usr/lib/software-properties/software-properties-dbus", "/usr/share/backintime/qt/serviceHelper.py") or
  process.name in ("dbus-daemon-launch-helper", "gnome-keyring-daemon", "abrt-dbus", "aptd", "usb-creator-helper") or
  process.executable like (
    "/usr/lib/*", "/usr/local/lib/*", "/usr/libexec/*", "/tmp/newroot/*", "/usr/sbin/setroubleshootd",
    "/usr/share/setroubleshoot/SetroubleshootPrivileged.py",
    "/var/lib/awx/.local/share/containers/storage/overlay/*/SetroubleshootPrivileged.py",
    "/home/*/.local/share/containers/storage/overlay/*/SetroubleshootPrivileged.py",
    "/bin/rpm", "/run/user/*/.bubblewrap/newroot/usr/libexec/rhsmd", "/opt/CrowdStrike/sandbox/usr/libexec/rhsmd",
    "/run/user/*/.bubblewrap/*/setroubleshootd"
  ) or
  (
    process.name like "python*" and
    process.args in (
      "/usr/share/usb-creator/usb-creator-helper", "/usr/sbin/aptd", "/usr/sbin/aptk", "/usr/bin/hp-pkservice",
      "/usr/libexec/language-selector/ls-dbus-backend"
    )
  ) or
  (process.name == "perl" and process.args like "/usr/share/system-tools-backends-*.pl") or
  ?process.working_directory like "/run/user/*/.bubblewrap/newroot/var/lib/gdm/"
)
```



### Unusual DPKG Execution

Branch count: 1  
Document count: 1  
Index: geneve-ut-1538

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.executable : "/var/lib/dpkg/info/*" and process.session_leader.name != null and
process.group_leader.name != null and not (
  process.parent.name in ("dpkg", "dpkg-reconfigure", "frontend") or
  process.session_leader.name == "dpkg" or
  process.group_leader.name == "dpkg" or
  process.parent.executable in ("/usr/share/debconf/frontend", "/usr/bin/unattended-upgrade")
)
```



### Unusual Executable File Creation by a System Critical Process

Branch count: 18  
Document count: 18  
Index: geneve-ut-1542

```python
file where host.os.type == "windows" and event.type != "deletion" and
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

Branch count: 168  
Document count: 168  
Index: geneve-ut-1546

```python
file where host.os.type == "windows" and event.type == "creation" and
   process.name : ("cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe", "node.exe", "python*.exe") and
   file.extension in~ (
    "pdf", "dll", "exe", "dat", "com", "bat", "cmd", "sys", "vbs", "ps1", "hta", "txt", "vbe", "js",
    "wsh", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "rtf", "gif", "jpg", "png", "bmp", "img", "iso"
  ) and
  file.path : "C:\\*:*" and
  not file.name :("*:$DATA", "*PG$Secure", "*Zone.Identifier", "*com.apple.lastuseddate#PS", "*com.apple.provenance")
```



### Unusual Instance Metadata Service (IMDS) API Request

Branch count: 141  
Document count: 282  
Index: geneve-ut-1558

```python
sequence by host.id, process.parent.entity_id with maxspan=3s
[
    process
    where host.os.type == "linux"
        and event.type == "start"
        and event.action == "exec"
        and process.parent.executable != null

        // common tooling / suspicious names (keep broad)
        and (
            process.name : (
                "curl", "wget", "python*", "perl*", "php*", "ruby*", "lua*", "telnet", "pwsh",
                "openssl", "nc", "ncat", "netcat", "awk", "gawk", "mawk", "nawk", "socat", "node",
                "bash", "sh"
            )
            or
            // suspicious execution locations (dropped binaries / temp execution)
            process.executable : (
                "./*", "/tmp/*", "/var/tmp/*", "/var/www/*", "/dev/shm/*", "/etc/init.d/*", "/etc/rc*.d/*",
                "/etc/cron*", "/etc/update-motd.d/*", "/boot/*", "/srv/*", "/run/*", "/etc/rc.local"
            )
            or
            // threat-relevant IMDS / metadata endpoints (inclusion list)
            process.command_line : (
                "*169.254.169.254/latest/api/token*",
                "*169.254.169.254/latest/meta-data/iam/security-credentials*",
                "*169.254.169.254/latest/meta-data/local-ipv4*",
                "*169.254.169.254/latest/meta-data/local-hostname*",
                "*169.254.169.254/latest/meta-data/public-ipv4*",
                "*169.254.169.254/latest/user-data*",
                "*169.254.169.254/latest/dynamic/instance-identity/document*",
                "*169.254.169.254/latest/meta-data/instance-id*",
                "*169.254.169.254/latest/meta-data/public-keys*",
                "*computeMetadata/v1/instance/service-accounts/*/token*",
                "*/metadata/identity/oauth2/token*",
                "*169.254.169.254/opc/v*/instance*",
                "*169.254.169.254/opc/v*/vnics*"
            )
        )

        // global working-dir / executable / parent exclusions for known benign agents
        and not process.working_directory : (
            "/opt/rapid7*",
            "/opt/nessus*",
            "/snap/amazon-ssm-agent*",
            "/var/snap/amazon-ssm-agent/*",
            "/var/log/amazon/ssm/*",
            "/srv/snp/docker/overlay2*",
            "/opt/nessus_agent/var/nessus/*"
        )

        and not process.executable : (
            "/opt/rumble/bin/rumble-agent*",
            "/opt/aws/inspector/bin/inspectorssmplugin",
            "/snap/oracle-cloud-agent/*",
            "/lusr/libexec/oracle-cloud-agent/*"
        )

        and not process.parent.executable : (
            "/usr/bin/setup-policy-routes",
            "/usr/share/ec2-instance-connect/*",
            "/var/lib/amazon/ssm/*",
            "/etc/update-motd.d/30-banner",
            "/usr/sbin/dhclient-script",
            "/usr/local/bin/uwsgi",
            "/usr/lib/skylight/al-extras",
            "/usr/bin/cloud-init",
            "/usr/sbin/waagent",
            "/usr/bin/google_osconfig_agent",
            "/usr/bin/docker",
            "/usr/bin/containerd-shim",
            "/usr/bin/runc"
        )

        and not process.entry_leader.executable : (
            "/usr/local/qualys/cloud-agent/bin/qualys-cloud-agent",
            "/opt/Elastic/Agent/data/elastic-agent-*/elastic-agent",
            "/opt/nessus_agent/sbin/nessus-service"
        )

        // carve-out: safe /usr/bin/curl usage (suppress noisy, legitimate agent patterns)
        and not (
            process.executable == "/usr/bin/curl"
            and (
                // AWS IMDSv2 token PUT that includes ttl header
                (process.command_line : "*-X PUT*169.254.169.254/latest/api/token*" and process.command_line : "*X-aws-ec2-metadata-token-ttl-seconds*")
                or
                // Any IMDSv2 GET that includes token header for any /latest/* path
                process.command_line : "*-H X-aws-ec2-metadata-token:*169.254.169.254/latest/*"
                or
                // Common amazon tooling UA
                process.command_line : "*-A amazon-ec2-net-utils/*"
                or
                // Azure metadata legitimate header
                process.command_line : "*-H Metadata:true*169.254.169.254/metadata/*"
                or
                // Oracle IMDS legitimate header
                process.command_line : "*-H Authorization:*Oracle*169.254.169.254/opc/*"
            )
        )
]
[
    network where host.os.type == "linux"
        and event.action == "connection_attempted"
        and destination.ip == "169.254.169.254"
]
```



### Unusual Kill Signal

Branch count: 39  
Document count: 39  
Index: geneve-ut-1561

```python
process where host.os.type == "linux" and event.action == "killed-pid" and auditd.data.syscall == "kill" and
auditd.data.a1 in (
  "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f", "30",
  "31", "32", "33", "34", "35", "36", "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f", "40",
  "41", "42", "43", "44", "45", "46", "47"
)
```



### Unusual Library Load via Python

Branch count: 1  
Document count: 1  
Index: geneve-ut-1563

```python
library where host.os.type == "macos" and event.action == "load" and
  dll.path like "/Users/*" and
  process.name like "python*" and
  not dll.name like ("*.so", "*.dylib", "Python", "*.*_extension", "*.dylib.*") and
  not dll.path like ("*/site-packages/*/Qt*/lib/Qt*.framework/Versions/*/Qt*",
                     "/Users/*/.pyenv/versions/*/lib/python*/site-packages/*")
```



### Unusual Network Connection via DllHost

Branch count: 1  
Document count: 2  
Index: geneve-ut-1579

```python
sequence by host.id, process.entity_id with maxspan=1m
  [process where host.os.type == "windows" and event.type == "start" and process.name : "dllhost.exe" and process.args_count == 1]
  [network where host.os.type == "windows" and process.name : "dllhost.exe" and
   not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
    "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
    "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
    "FF00::/8")]
```



### Unusual Parent-Child Relationship

Branch count: 32  
Document count: 32  
Index: geneve-ut-1583

```python
process where host.os.type == "windows" and event.type == "start" and
process.parent.name != null and
 (
   /* suspicious parent processes */
   (process.name:"autochk.exe" and not process.parent.name:"smss.exe") or
   (process.name:("fontdrvhost.exe", "dwm.exe") and not process.parent.name:("wininit.exe", "winlogon.exe", "dwm.exe")) or
   (process.name:("consent.exe", "RuntimeBroker.exe", "TiWorker.exe") and not process.parent.name:("svchost.exe", "Workplace Container Helper.exe")) or
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
   (process.name:"svchost.exe" and not process.parent.name:("MsMpEng.exe", "services.exe", "svchost.exe")) or
   (process.name:"spoolsv.exe" and not process.parent.name:("services.exe", "Workplace Starter.exe")) or
   (process.name:"taskhost.exe" and not process.parent.name:("services.exe", "svchost.exe", "ngentask.exe")) or
   (process.name:"taskhostw.exe" and not process.parent.name:("services.exe", "svchost.exe")) or
   (process.name:"userinit.exe" and not process.parent.name:("dwm.exe", "winlogon.exe", "KUsrInit.exe")) or
   (process.name:("wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe") and not process.parent.name:"svchost.exe") or
   /* suspicious child processes */
   (process.parent.name:("SearchProtocolHost.exe", "taskhost.exe", "csrss.exe") and not process.name:("werfault.exe", "wermgr.exe", "WerFaultSecure.exe", "conhost.exe", "ngentask.exe")) or
   (process.parent.name:"autochk.exe" and not process.name:("chkdsk.exe", "doskey.exe", "WerFault.exe")) or
   (process.parent.name:"smss.exe" and not process.name:("autochk.exe", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "setupcl.exe", "WerFault.exe", "wpbbin.exe", "PvsVmBoot.exe", "SophosNA.exe", "omnissa-ic-nga.exe", "icarus_rvrt.exe", "poqexec.exe")) or
   (process.parent.name:"wermgr.exe" and not process.name:("WerFaultSecure.exe", "wermgr.exe", "WerFault.exe")) or
   (process.parent.name:"conhost.exe" and not process.name:("mscorsvw.exe", "wermgr.exe", "WerFault.exe", "WerFaultSecure.exe"))
  )
```



### Unusual Persistence via Services Registry

Branch count: 24  
Document count: 24  
Index: geneve-ut-1584

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.data.strings != null and registry.value : ("ServiceDLL", "ImagePath") and
  registry.path : (
      "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ServiceDLL",
      "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath",
      "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet*\\Services\\*\\ServiceDLL",
      "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath",
      "MACHINE\\SYSTEM\\ControlSet*\\Services\\*\\ServiceDLL",
      "MACHINE\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath"
  ) and not registry.data.strings : (
      "?:\\windows\\system32\\Drivers\\*.sys",
      "\\SystemRoot\\System32\\drivers\\*.sys",
      "\\??\\?:\\Windows\\system32\\Drivers\\*.SYS",
      "\\??\\?:\\Windows\\syswow64\\*.sys",
      "system32\\DRIVERS\\USBSTOR", 
      "system32\\drivers\\*.sys", 
      "C:\\WindowsAzure\\GuestAgent*.exe", 
      "\"C:\\Program Files\\Common Files\\McAfee\\*", 
      "C:\\Program Files (x86)\\VERITAS\\VxPBX\\bin\\pbx_exchange.exe", 
      "\"C:\\Program Files (x86)\\VERITAS\\VxPBX\\bin\\pbx_exchange.exe\"",
      "\"C:\\ProgramData\\McAfee\\Agent\\Current\\*") and
  not (process.name : "procexp??.exe" and registry.data.strings : "?:\\*\\procexp*.sys") and
  not process.executable : (
      "?:\\Program Files\\*.exe",
      "?:\\Program Files (x86)\\*.exe",
      "?:\\Windows\\System32\\svchost.exe",
      "?:\\Windows\\winsxs\\*\\TiWorker.exe",
      "?:\\Windows\\System32\\drvinst.exe",
      "?:\\Windows\\System32\\services.exe",
      "?:\\Windows\\System32\\msiexec.exe",
      "?:\\Windows\\System32\\regsvr32.exe",
      "?:\\Windows\\System32\\WaaSMedicAgent.exe", 
      "?:\\Windows\\UUS\\amd64\\WaaSMedicAgent.exe"
  )
```



### Unusual Print Spooler Child Process

Branch count: 32  
Document count: 32  
Index: geneve-ut-1587

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "spoolsv.exe" and process.command_line != null and
 (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System") and

 /* exclusions for FP control below */
 not process.name : ("splwow64.exe", "PDFCreator.exe", "acrodist.exe", "spoolsv.exe", "msiexec.exe", "route.exe", "WerFault.exe") and
 not process.command_line : "*\\WINDOWS\\system32\\spool\\DRIVERS*" and
 not (process.name : "net.exe" and process.command_line : ("*stop*", "*start*")) and
 not (process.name : ("cmd.exe", "powershell.exe") and process.command_line : ("*.spl*", "*\\program files*", "*route add*")) and
 not (process.name : "netsh.exe" and process.command_line : ("*add portopening*", "*rule name*")) and
 not (process.name : "regsvr32.exe" and process.command_line : "*PrintConfig.dll*") and
 not process.executable : (
    "?:\\Program Files (x86)\\CutePDF Writer\\CPWriter2.exe",
    "?:\\Program Files (x86)\\GPLGS\\gswin32c.exe",
    "?:\\Program Files (x86)\\Acro Software\\CutePDF Writer\\CPWSave.exe",
    "?:\\Program Files (x86)\\Acro Software\\CutePDF Writer\\CPWriter2.exe",
    "?:\\Program Files (x86)\\CutePDF Writer\\CPWSave.exe",
    "?:\\Program Files (x86)\\TSplus\\UniversalPrinter\\CPWriter2.exe",
    "?:\\Program Files\\Seagull\\Printer Drivers\\Packages\\*\\DriverEnvironmentSetup.exe",
    "?:\\Windows\\system32\\CNAB4RPD.EXE",

    /* Crowdstrike specific condition as it uses NT Object paths */
    "\\Device\\HarddiskVolume*\\Program Files (x86)\\CutePDF Writer\\CPWriter2.exe",
    "\\Device\\HarddiskVolume*\\Program Files (x86)\\GPLGS\\gswin32c.exe",
    "\\Device\\HarddiskVolume*\\Program Files (x86)\\Acro Software\\CutePDF Writer\\CPWSave.exe",
    "\\Device\\HarddiskVolume*\\Program Files (x86)\\Acro Software\\CutePDF Writer\\CPWriter2.exe",
    "\\Device\\HarddiskVolume*\\Program Files (x86)\\CutePDF Writer\\CPWSave.exe",
    "\\Device\\HarddiskVolume*\\Program Files (x86)\\TSplus\\UniversalPrinter\\CPWriter2.exe",
    "\\Device\\HarddiskVolume*\\Program Files\\Seagull\\Printer Drivers\\Packages\\*\\DriverEnvironmentSetup.exe",
    "\\Device\\HarddiskVolume*\\Windows\\system32\\CNAB4RPD.EXE"
 )
```



### Unusual Process Execution on WBEM Path

Branch count: 2  
Document count: 2  
Index: geneve-ut-1591

```python
process where host.os.type == "windows" and event.type == "start" and
  process.executable : ("?:\\Windows\\System32\\wbem\\*", "?:\\Windows\\SysWow64\\wbem\\*") and
  not process.name : (
    "mofcomp.exe",
    "scrcons.exe",
    "unsecapp.exe",
    "wbemtest.exe",
    "winmgmt.exe",
    "wmiadap.exe",
    "wmiapsrv.exe",
    "wmic.exe",
    "wmiprvse.exe"
  )
```



### Unusual Process Extension

Branch count: 256  
Document count: 256  
Index: geneve-ut-1592

```python
process where host.os.type == "windows" and event.type == "start" and
  process.executable : "?*" and 
  not process.name : ("*.exe", "*.com", "*.scr", "*.tmp", "*.dat") and
  not process.executable : 
    (
      "MemCompression",
      "Registry",
      "vmmem",
      "vmmemWSL",
      "?:\\Program Files\\Dell\\SupportAssistAgent\\*.p5x",
      "?:\\Program Files\\Docker\\Docker\\com.docker.service",
      "?:\\Users\\*\\AppData\\Local\\Intel\\AGS\\Libs\\AGSRunner.bin",
      "\\Device\\Mup\\*\\Software Management\\Select.Html.dep",
      "?:\\DJJApplications\\MedicalRecords\\bin\\Select.Html.dep",
      "?:\\ProgramData\\Software Management\\Select.Html.dep",
      "?:\\Program Files (x86)\\EnCase Applications\\Examiner Service\\EnCase64\\enhkey.dll",
      "?:\\Program Files (x86)\\Panda Security\\WAC\\PSNAEInj64.dll",
      "?:\\Program Files (x86)\\Johnson Controls\\LicenseActivator\\crp32002.ngn"
    ) and
  not (
    (process.name : "C9632CF058AE4321B6B0B5EA39B710FE" and process.code_signature.subject_name == "Dell Inc") or
    (process.name : "*.upd" and process.code_signature.subject_name == "Bloomberg LP") or
    (process.name: "FD552E21-686E-413C-931D-3B82A9D29F3B" and process.code_signature.subject_name: "Adobe Inc.") or
    (process.name: "3B91051C-AE82-43C9-BCEF-0309CD2DD9EB" and process.code_signature.subject_name: "McAfee, LLC") or
    (process.name: "soffice.bin" and process.code_signature.subject_name: "The Document Foundation") or
    (process.name: ("VeeamVixProxy_*", "{????????-????-????-????-????????????}") and process.code_signature.subject_name: "Veeam Software Group GmbH") or
    (process.name: "1cv8p64.bin" and process.code_signature.subject_name: "LLC 1C-Soft") or
    (process.name: "AGSRunner.bin" and process.code_signature.subject_name: "Intel Corporation")
  )
```



### Unusual Process For MSSQL Service Accounts

Branch count: 198  
Document count: 198  
Index: geneve-ut-1593

```python
process where event.type == "start" and host.os.type == "windows" and
  user.name : (
    "SQLSERVERAGENT", "SQLAGENT$*",
    "MSSQLSERVER", "MSSQL$*",
    "MSSQLServerOLAPService",
    "ReportServer*", "MsDtsServer150",
    "MSSQLFDLauncher*",
    "SQLServer2005SQLBrowserUser$*",
    "SQLWriter", "winmgmt"
  ) and user.domain : "NT SERVICE" and
  not (
    (
      process.name : (
        "sqlceip.exe", "sqlservr.exe", "sqlagent.exe",
        "msmdsrv.exe", "ReportingServicesService.exe",
        "MsDtsSrvr.exe", "sqlbrowser.exe", "DTExec.exe",
        "SQLPS.exe", "fdhost.exe", "fdlauncher.exe",
        "SqlDumper.exe", "sqlsqm.exe", "DatabaseMail.exe",
        "ISServerExec.exe", "Microsoft.ReportingServices.Portal.WebHost.exe",
        "bcp.exe", "SQLCMD.exe", "DatabaseMail.exe"
      ) or
      process.executable : (
        "?:\\Windows\\System32\\wermgr.exe",
        "?:\\Windows\\System32\\conhost.exe",
        "?:\\Windows\\System32\\WerFault.exe"
      )
    ) and
    (
      process.code_signature.subject_name : ("Microsoft Corporation", "Microsoft Windows") and
      process.code_signature.trusted == true
    )
  ) and
  not (
    (process.name : "cmd.exe" and process.parent.name : "sqlservr.exe") or
    (process.name : "cmd.exe" and process.parent.name : "forfiles.exe" and process.command_line : "/c echo *")
  )
```



### Unusual Process Network Connection

Branch count: 144  
Document count: 288  
Index: geneve-ut-1597

```python
sequence by process.entity_id
  [process where host.os.type == "windows" and (process.name : "Microsoft.Workflow.Compiler.exe" or
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
  [network where host.os.type == "windows" and (process.name : "Microsoft.Workflow.Compiler.exe" or
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

Branch count: 4  
Document count: 4  
Index: geneve-ut-1631

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : ("net.exe", "net1.exe") and not process.parent.name : "net.exe") and
  (process.args : "user" and process.args : ("/ad", "/add"))
```



### User Added to Privileged Group in Active Directory

Branch count: 20  
Document count: 20  
Index: geneve-ut-1632

```python
iam where host.os.type == "windows" and event.action == "added-member-to-group" and
(
    group.id : "S-1-5-21*" and
    (
        group.name : (
            "Admin*",
            "Domain Admins",
            "Enterprise Admins",
            "Backup Admins",
            "Schema Admins",
            "DnsAdmins",
            "Exchange Organization Administrators",
            "Print Operators",
            "Server Operators",
            "Account Operators"
        )
    ) or
    (
        group.id : (
            "S-1-5-21-*-544",
            "S-1-5-21-*-512",
            "S-1-5-21-*-519",
            "S-1-5-21-*-551",
            "S-1-5-21-*-518",
            "S-1-5-21-*-1101",
            "S-1-5-21-*-1102",
            "S-1-5-21-*-550",
            "S-1-5-21-*-549",
            "S-1-5-21-*-548"
        )
    )
)
```



### User Added to the Admin Group

Branch count: 1  
Document count: 1  
Index: geneve-ut-1633

```python
configuration where host.os.type == "macos" and event.type == "change" and
  event.action == "od_group_add" and group.name:"admin"
```



### User account exposed to Kerberoasting

Branch count: 1  
Document count: 1  
Index: geneve-ut-1635

```python
event.code:5136 and host.os.type:"windows" and winlog.event_data.OperationType:"%%14674" and
  winlog.event_data.ObjectClass:"user" and
  winlog.event_data.AttributeLDAPDisplayName:"servicePrincipalName"
```



### User or Group Creation/Modification

Branch count: 6  
Document count: 6  
Index: geneve-ut-1636

```python
iam where host.os.type == "linux" and event.type in ("creation", "change") and auditd.result == "success" and
event.action in ("changed-password", "added-user-account", "added-group-account-to") and process.name != null
```



### VNC (Virtual Network Computing) from the Internet

Branch count: 9  
Document count: 9  
Index: geneve-ut-1637

```python
(event.dataset: network_traffic.flow or (event.category: (network or network_traffic))) and
  network.transport:tcp and destination.port >= 5800 and destination.port <= 5810 and
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

Branch count: 9  
Document count: 9  
Index: geneve-ut-1638

```python
(event.dataset: network_traffic.flow  or (event.category: (network or network_traffic))) and
  network.transport:tcp and destination.port >= 5800 and destination.port <= 5810 and
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



### Veeam Backup Library Loaded by Unusual Process

Branch count: 10  
Document count: 10  
Index: geneve-ut-1639

```python
library where host.os.type == "windows" and event.action == "load" and
  (dll.name : "Veeam.Backup.Common.dll" or dll.pe.original_file_name : "Veeam.Backup.Common.dll") and
  (
    process.code_signature.trusted == false or
    process.code_signature.exists == false or
    process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
  )
```



### Virtual Machine Fingerprinting

Branch count: 25  
Document count: 25  
Index: geneve-ut-1640

```python
process where host.os.type == "linux" and event.type == "start" and 
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "process_started") and
process.args in (
  "/sys/class/dmi/id/bios_version", "/sys/class/dmi/id/product_name", "/sys/class/dmi/id/chassis_vendor",
  "/proc/scsi/scsi", "/proc/ide/hd0/model"
) and not (
  user.name == "root" or
  ?process.parent.name in ("LinkManager.exe", "saposcol", "svc_snow_discovery") or
  ?process.working_directory == "/home/qualys" or
  ?process.parent.executable in (
    "/usr/sara/sbin/sys2prometheus", "/usr/sara/sbin/sys2ganglia", "/usr/libexec/valgrind/memcheck-amd64-linux",
    "/var/lib/cfengine3/modules/init_node", "/opt/emby-server/system/EmbyServer"
  )
)
```



### Virtual Machine Fingerprinting via Grep

Branch count: 6  
Document count: 6  
Index: geneve-ut-1641

```python
process where event.type == "start" and
 process.name in ("grep", "egrep") and user.id != "0" and
 process.args : ("parallels*", "vmware*", "virtualbox*") and process.args : "Manufacturer*" and
 not process.parent.executable in ("/Applications/Docker.app/Contents/MacOS/Docker", "/usr/libexec/kcare/virt-what")
```



### Virtual Private Network Connection Attempt

Branch count: 6  
Document count: 6  
Index: geneve-ut-1642

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  (
    (process.name == "networksetup" and process.args like~ "-connectpppoeservice") or
    (process.name == "scutil" and process.args like~ "--nc" and process.args like~ "start") or
    (process.name == "osascript" and process.command_line : "osascript*set VPN to service*")
  )
```



### Volume Shadow Copy Deleted or Resized via VssAdmin

Branch count: 4  
Document count: 4  
Index: geneve-ut-1643

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "vssadmin.exe" or ?process.pe.original_file_name == "VSSADMIN.EXE") and
  process.args : ("delete", "resize") and process.args : "shadows*"
```



### Volume Shadow Copy Deletion via PowerShell

Branch count: 60  
Document count: 60  
Index: geneve-ut-1644

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and
  process.args : ("*Get-WmiObject*", "*gwmi*", "*Get-CimInstance*", "*gcim*") and
  process.args : ("*Win32_ShadowCopy*") and
  process.args : ("*.Delete()*", "*Remove-WmiObject*", "*rwmi*", "*Remove-CimInstance*", "*rcim*")
```



### Volume Shadow Copy Deletion via WMIC

Branch count: 2  
Document count: 2  
Index: geneve-ut-1645

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "WMIC.exe" or ?process.pe.original_file_name == "wmic.exe") and
  process.args : "delete" and process.args : "shadowcopy"
```



### WDAC Policy File by an Unusual Process

Branch count: 8  
Document count: 8  
Index: geneve-ut-1646

```python
file where host.os.type == "windows" and event.action != "deletion" and
  file.extension : ("p7b", "cip") and
  file.path : (
    "?:\\Windows\\System32\\CodeIntegrity\\*.p7b",
    "?:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip",
    "\\Device\\HarddiskVolume*\\Windows\\System32\\CodeIntegrity\\*.p7b",
    "\\Device\\HarddiskVolume*\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip"
  ) and
  not process.executable : (
    "C:\\Windows\\System32\\poqexec.exe",
    "\\Device\\HarddiskVolume*\\Windows\\System32\\poqexec.exe"
  )
```



### WMI Incoming Lateral Movement

Branch count: 24  
Document count: 48  
Index: geneve-ut-1647

```python
sequence by host.id with maxspan = 20s

 /* Accepted Incoming RPC connection by Winmgmt service */

  [network where host.os.type == "windows" and process.name : "svchost.exe" and network.direction : ("incoming", "ingress") and
   source.ip != "127.0.0.1" and source.ip != "::1" and destination.port == 135]

  /* Excluding Common FPs Nessus and SCCM */

  [process where host.os.type == "windows" and event.type == "start" and process.parent.name : "WmiPrvSE.exe" and
   not (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System") and
   not (
         user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
         /* Don't apply the user.id exclusion to Sysmon for compatibility */
         not event.dataset : ("windows.sysmon_operational", "windows.sysmon")
   ) and
   not process.executable :
               ("?:\\Program Files\\HPWBEM\\Tools\\hpsum_swdiscovery.exe",
                "?:\\Windows\\CCM\\Ccm32BitLauncher.exe",
                "?:\\Windows\\System32\\wbem\\mofcomp.exe",
                "?:\\Windows\\Microsoft.NET\\Framework*\\csc.exe",
                "?:\\Windows\\System32\\powercfg.exe") and
   not (process.executable : "?:\\Windows\\System32\\msiexec.exe" and process.args : "REBOOT=ReallySuppress") and
   not (process.executable : "?:\\Windows\\System32\\inetsrv\\appcmd.exe" and process.args : "uninstall")
   ]
```



### WMI WBEMTEST Utility Execution

Branch count: 1  
Document count: 1  
Index: geneve-ut-1648

```python
process where host.os.type == "windows" and event.type == "start" and process.name : "wbemtest.exe"
```



### WMIC Remote Command

Branch count: 3  
Document count: 3  
Index: geneve-ut-1649

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "WMIC.exe" and
  process.args : "*node:*" and
  process.args : ("call", "set", "get") and
  not process.args : ("*/node:localhost*", "*/node:\"127.0.0.1\"*", "/node:127.0.0.1")
```



### WPS Office Exploitation via DLL Hijack

Branch count: 6  
Document count: 6  
Index: geneve-ut-1650

```python
any where host.os.type == "windows" and process.name : "promecefpluginhost.exe" and
(
 (event.category == "library" and
  ?dll.path :
     ("?:\\Users\\*\\AppData\\Local\\Temp\\wps\\INetCache\\*",
      "\\Device\\Mup\\**", "\\\\*")) or

  ((event.category == "process" and event.action : "Image loaded*") and
  ?file.path :
     ("?:\\Users\\*\\AppData\\Local\\Temp\\wps\\INetCache\\*",
      "\\Device\\Mup\\**", "\\\\*"))
)
```



### WRITEDAC Access on Active Directory Object

Branch count: 2  
Document count: 2  
Index: geneve-ut-1651

```python
host.os.type: "windows" and event.action : ("Directory Service Access" or "object-operation-performed") and
  event.code : "4662" and winlog.event_data.AccessMask:"0x40000"
```



### Web Application Suspicious Activity: POST Request Declined

Branch count: 1  
Document count: 1  
Index: geneve-ut-1652

```python
http.response.status_code:403 and http.request.method:post
```



### Web Application Suspicious Activity: Unauthorized Method

Branch count: 1  
Document count: 1  
Index: geneve-ut-1653

```python
http.response.status_code:405
```



### Web Application Suspicious Activity: sqlmap User Agent

Branch count: 1  
Document count: 1  
Index: geneve-ut-1654

```python
user_agent.original:"sqlmap/1.3.11#stable (http://sqlmap.org)"
```



### Web Server Potential SQL Injection Request

Branch count: 61  
Document count: 61  
Index: geneve-ut-1660

```python
any where url.original like~ (
  "*%20order%20by%*", "*dbms_pipe.receive_message%28chr%*", "*waitfor%20delay%20*", "*%28select%20*from%20pg_sleep%285*", "*%28select%28sleep%285*", "*%3bselect%20pg_sleep%285*",
  "*select%20concat%28concat*", "*xp_cmdshell*", "*select*case*when*", "*and*extractvalue*select*", "*from*information_schema.tables*", "*boolean*mode*having*", "*extractvalue*concat*",
  "*case*when*sleep*", "*select*sleep*", "*dbms_lock.sleep*", "*and*sleep*", "*like*sleep*", "*csleep*", "*pgsleep*", "*char*char*char*", "*union*select*", "*concat*select*",
  "*select*else*drop*", "*having*like*", "*case*else*end*", "*if*sleep*", "*where*and*select*", "*or*1=1*", "*\"1\"=\"1\"*", "*or*'a'='a*", "*into*outfile*", "*pga_sleep*",
  "*into%20outfile*", "*into*dumpfile*", "*load_file%28*", "*load%5ffile%28*", "*cast%28*", "*convert%28*", "*cast%28%*", "*convert%28%*", "*@@version*", "*@@version_comment*",
  "*version%28*", "*user%28*", "*current_user%28*", "*database%28*", "*schema_name%28*", "*information_schema.columns*", "*information_schema.columns*", "*table_schema*",
  "*column_name*", "*dbms_pipe*", "*dbms_lock%2e*sleep*", "*dbms_lock.sleep*", "*sp_executesql*", "*sp_executesql*", "*load%20data*", "*information_schema*",  "*pg_slp*",
  "*information_schema.tables*"
)
```



### Web Server Spawned via Python

Branch count: 40  
Document count: 40  
Index: geneve-ut-1662

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
(
  (process.name like "python*" and process.args in ("http.server", "SimpleHTTPServer")) or
  (
    process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
    process.command_line like~ "*python* -m http.server*"
  )
) and
not process.parent.executable == "/usr/lib/systemd/systemd"
```



### WebProxy Settings Modification

Branch count: 48  
Document count: 48  
Index: geneve-ut-1665

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and event.action == "exec" and
 process.name == "networksetup" and process.args like~ ("-setwebproxy", "-setsecurewebproxy", "-setautoproxyurl") and
 (process.parent.name like~ ("osascript", "bash", "sh", "zsh", "Terminal", "Python*") or (process.parent.code_signature.exists == false or process.parent.code_signature.trusted == false))
```



### WebServer Access Logs Deleted

Branch count: 5  
Document count: 5  
Index: geneve-ut-1666

```python
file where event.type == "deletion" and
  file.path : ("C:\\inetpub\\logs\\LogFiles\\*.log",
               "/var/log/apache*/access.log",
               "/etc/httpd/logs/access_log",
               "/var/log/httpd/access_log",
               "/var/www/*/logs/access.log")
```



### Werfault ReflectDebugger Persistence

Branch count: 1  
Document count: 1  
Index: geneve-ut-1667

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : "ReflectDebugger"

  /*
    Full registry key path omitted due to data source variations:
    HKLM\\Software\\Microsoft\\Windows\\Windows Error Reporting\\Hangs\\ReflectDebugger
  */
```



### Whoami Process Activity

Branch count: 61  
Document count: 61  
Index: geneve-ut-1668

```python
process where host.os.type == "windows" and event.type == "start" and process.name : "whoami.exe" and
(
  (
    /* scoped for whoami execution under system privileges */
    (
      (
        user.domain : ("NT *", "* NT", "IIS APPPOOL") and
        user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-82-*") and
        not ?winlog.event_data.SubjectUserName : "*$" and

        /* Sysmon will always populate user.id as S-1-5-18, leading to FPs */
        not event.dataset : ("windows.sysmon_operational", "windows.sysmon")
      ) or
      (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System")
    ) and
    not (
      process.parent.name : "cmd.exe" and
      process.parent.args : (
          "chcp 437>nul 2>&1 & C:\\WINDOWS\\System32\\whoami.exe  /groups",
          "chcp 437>nul 2>&1 & %systemroot%\\system32\\whoami /user",
          "C:\\WINDOWS\\System32\\whoami.exe /groups",
          "*WINDOWS\\system32\\config\\systemprofile*"
      )
    ) and
    not (process.parent.executable : "C:\\Windows\\system32\\inetsrv\\appcmd.exe" and process.parent.args : "LIST") and
    not process.parent.executable : (
        "C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe",
        "C:\\Program Files\\Cohesity\\cohesity_windows_agent_service.exe"
    )
  ) or
  process.parent.name : ("wsmprovhost.exe", "w3wp.exe", "wmiprvse.exe", "rundll32.exe", "regsvr32.exe")
)
```



### Windows Account or Group Discovery

Branch count: 36  
Document count: 36  
Index: geneve-ut-1669

```python
process where host.os.type == "windows" and event.type == "start" and
(
  (
   (
    (process.name : "net.exe" or process.pe.original_file_name == "net.exe") or
    (
     (process.name : "net1.exe" or process.pe.original_file_name == "net1.exe") and
     not process.parent.name : "net.exe"
    )
   ) and process.args : ("accounts", "group", "user", "localgroup") and not process.args : "/add"
  ) or
  (process.name:("dsquery.exe", "dsget.exe") and process.args:("*members*", "user")) or
  (process.name:"dsquery.exe" and process.args:"*filter*") or
  process.name:("quser.exe", "qwinsta.exe", "PsGetSID.exe", "PsLoggedOn.exe", "LogonSessions.exe", "whoami.exe") or
  (
    process.name: "cmd.exe" and
    (
      process.args : "echo" and process.args : (
        "%username%", "%userdomain%", "%userdnsdomain%",
        "%userdomain_roamingprofile%", "%userprofile%",
        "%homepath%", "%localappdata%", "%appdata%"
      ) or
      process.args : "set"
    )
  )
) and not process.parent.args: "C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Content\\DetectionScripts\\*.ps1"
and not process.parent.name : "LTSVC.exe" and not user.id : "S-1-5-18"
```



### Windows Defender Disabled via Registry Modification

Branch count: 24  
Document count: 24  
Index: geneve-ut-1671

```python
registry where host.os.type == "windows" and event.type == "change" and
  (
    (
      registry.path: (
        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware"
      ) and
      registry.data.strings: ("1", "0x00000001")
   ) or
   (
      registry.path: (
        "HKLM\\System\\*ControlSet*\\Services\\WinDefend\\Start",
        "\\REGISTRY\\MACHINE\\System\\*ControlSet*\\Services\\WinDefend\\Start"
      ) and
      registry.data.strings in ("3", "4", "0x00000003", "0x00000004")
   )
  ) and

  not
    (
      process.executable : (
          "?:\\WINDOWS\\system32\\services.exe",
          "?:\\Windows\\System32\\svchost.exe",
          "?:\\Program Files (x86)\\Trend Micro\\Security Agent\\NTRmv.exe"
      ) and user.id : "S-1-5-18"
    )
```



### Windows Defender Exclusions Added via PowerShell

Branch count: 12  
Document count: 12  
Index: geneve-ut-1672

```python
process where host.os.type == "windows" and event.type == "start" and
 (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or ?process.pe.original_file_name in ("PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE")) and
  process.args : ("*Add-MpPreference*", "*Set-MpPreference*") and
  process.args : ("*-Exclusion*")
```



### Windows Event Logs Cleared

Branch count: 2  
Document count: 2  
Index: geneve-ut-1673

```python
host.os.type:windows and event.action:("audit-log-cleared" or "Log clear") and
  not winlog.provider_name:"AD FS Auditing"
```



### Windows Firewall Disabled via PowerShell

Branch count: 24  
Document count: 24  
Index: geneve-ut-1674

```python
process where host.os.type == "windows" and event.type == "start" and
  (
    process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or
    ?process.pe.original_file_name in ("PowerShell.EXE", "pwsh.dll", "powershell_ise.EXE")
  ) and
  process.args : "*Set-NetFirewallProfile*" and
  process.args : "*-Enabled*" and process.args : "*False*" and
  process.args : ("*-All*", "*Public*", "*Domain*", "*Private*")
```



### Windows Installer with Suspicious Properties

Branch count: 10  
Document count: 20  
Index: geneve-ut-1675

```python
sequence with maxspan=1m
  [registry where host.os.type == "windows" and event.type == "change" and process.name : "msiexec.exe" and
   (
    (registry.value : "InstallSource" and
     registry.data.strings : ("?:\\Users\\*\\Temp\\Temp?_*.zip\\*",
                             "?:\\Users\\*\\*.7z\\*",
                             "?:\\Users\\*\\*.rar\\*")) or

    (registry.value : ("DisplayName", "ProductName") and registry.data.strings : "SetupTest")
    )]
  [process where host.os.type == "windows" and event.action == "start" and
    process.parent.name : "msiexec.exe" and
    not process.name : "msiexec.exe" and
    not (process.executable : ("?:\\Program Files (x86)\\*.exe", "?:\\Program Files\\*.exe") and process.code_signature.trusted == true)]
```



### Windows Network Enumeration

Branch count: 8  
Document count: 8  
Index: geneve-ut-1676

```python
process where host.os.type == "windows" and event.type == "start" and
  ((process.name : "net.exe" or process.pe.original_file_name == "net.exe") or
   ((process.name : "net1.exe" or process.pe.original_file_name == "net1.exe") and
       not process.parent.name : "net.exe")) and
  (process.args : "view" or (process.args : "time" and process.args : "\\\\*")) and
  not process.command_line : "net  view \\\\localhost "


  /* expand when ancestry is available
  and not descendant of [process where event.type == "start" and process.name : "cmd.exe" and
                           ((process.parent.name : "userinit.exe") or
                            (process.parent.name : "gpscript.exe") or
                            (process.parent.name : "explorer.exe" and
                               process.args : "C:\\*\\Start Menu\\Programs\\Startup\\*.bat*"))]
  */
```



### Windows Registry File Creation in SMB Share

Branch count: 2  
Document count: 2  
Index: geneve-ut-1677

```python
file where host.os.type == "windows" and event.type == "creation" and
 /* regf file header */
 file.Ext.header_bytes : "72656766*" and file.size >= 30000 and
 process.pid == 4 and user.id : ("S-1-5-21*", "S-1-12-1-*") and
 not file.path : (
    "?:\\*\\UPM_Profile\\NTUSER.DAT",
    "?:\\*\\UPM_Profile\\NTUSER.DAT.LASTGOODLOAD",
    "?:\\*\\UPM_Profile\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat*",
    "?:\\Windows\\Netwrix\\Temp\\????????.???.offreg",
    "?:\\*\\AppData\\Local\\Packages\\Microsoft.*\\Settings\\settings.dat*"
 )
```



### Windows Sandbox with Sensitive Configuration

Branch count: 8  
Document count: 8  
Index: geneve-ut-1678

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("wsb.exe", "WindowsSandboxClient.exe") and
  process.command_line : ("*<Networking>Enable</Networking>*",
                          "*<HostFolder>C:\\*<ReadOnly>false*",
                          "*<LogonCommand>*",
                          "*<NetworkingEnabled>true*")
```



### Windows Script Execution from Archive

Branch count: 15  
Document count: 15  
Index: geneve-ut-1680

```python
process where host.os.type == "windows" and event.type == "start" and process.name : "wscript.exe" and
 process.parent.name : ("explorer.exe", "winrar.exe", "7zFM.exe") and
 process.args :
        ("?:\\Users\\*\\AppData\\Local\\Temp\\7z*\\*",
         "?:\\Users\\*\\AppData\\Local\\Temp\\*.zip.*\\*",
         "?:\\Users\\*\\AppData\\Local\\Temp\\Rar$*\\*",
         "?:\\Users\\*\\AppData\\Local\\Temp\\Temp?_*\\*",
         "?:\\Users\\*\\AppData\\Local\\Temp\\BNZ.*")
```



### Windows Script Interpreter Executing Process via WMI

Branch count: 216  
Document count: 432  
Index: geneve-ut-1681

```python
sequence by host.id with maxspan = 5s
    [any where host.os.type == "windows" and
     (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
     (?dll.name : "wmiutils.dll" or file.name : "wmiutils.dll") and process.name : ("wscript.exe", "cscript.exe")]
    [process where host.os.type == "windows" and event.type == "start" and
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



### Windows Server Update Service Spawning Suspicious Processes

Branch count: 12  
Document count: 12  
Index: geneve-ut-1682

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "rundll32.exe", "curl.exe") and
  (
   (process.parent.name : "w3wp.exe" and process.parent.args : "WsusPool") or
   process.parent.name : "WsusService.exe"
   )
```



### Windows Subsystem for Linux Distribution Installed

Branch count: 1  
Document count: 1  
Index: geneve-ut-1684

```python
registry where host.os.type == "windows" and event.type == "change" and registry.value : "PackageFamilyName" and
 registry.path : "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss\\*\\PackageFamilyName"
```



### Windows Subsystem for Linux Enabled via Dism Utility

Branch count: 2  
Document count: 2  
Index: geneve-ut-1685

```python
process where host.os.type == "windows" and event.type : "start" and
 (process.name : "Dism.exe" or ?process.pe.original_file_name == "DISM.EXE") and 
 process.command_line : "*Microsoft-Windows-Subsystem-Linux*"
```



### Windows System Information Discovery

Branch count: 4  
Document count: 4  
Index: geneve-ut-1686

```python
process where host.os.type == "windows" and event.type == "start" and
(
  (
    process.name : "cmd.exe" and process.args : "ver*" and not
    process.parent.executable : (
        "?:\\Users\\*\\AppData\\Local\\Keybase\\upd.exe",
        "?:\\Users\\*\\python*.exe"
    )
  ) or 
  process.name : ("systeminfo.exe", "hostname.exe") or 
  (process.name : "wmic.exe" and process.args : "os" and process.args : "get")
) and not
process.parent.executable : (
    "?:\\Program Files\\*",
    "?:\\Program Files (x86)\\*",
    "?:\\ProgramData\\*"
) and not user.id : "S-1-5-18"
```



### Windows System Network Connections Discovery

Branch count: 18  
Document count: 18  
Index: geneve-ut-1687

```python
process where event.type == "start" and
(
  process.name : "netstat.exe" or
  (
   (
    (process.name : "net.exe" or process.pe.original_file_name == "net.exe") or
    (
     (process.name : "net1.exe" or process.pe.original_file_name == "net1.exe") and
     not process.parent.name : "net.exe"
    )
   ) and process.args : ("use", "user", "session", "config") and not process.args: ("/persistent:*", "/delete", "\\\\*")
  ) or
  (process.name : "nbtstat.exe" and process.args : "-s*")
) and not user.id : "S-1-5-18"
```



### Wireless Credential Dumping using Netsh Command

Branch count: 2  
Document count: 2  
Index: geneve-ut-1688

```python
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "netsh.exe" or ?process.pe.original_file_name == "netsh.exe") and
  process.args : "wlan" and process.args : "key*clear"
```



### Yum Package Manager Plugin File Creation

Branch count: 16  
Document count: 16  
Index: geneve-ut-1689

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and
file.path : ("/usr/lib/yum-plugins/*", "/etc/yum/pluginconf.d/*") and not (
  process.executable in (
    "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf", "/usr/bin/microdnf", "/bin/rpm",
    "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum", "/bin/dnf", "/usr/bin/dnf",
    "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet", "/bin/puppet",
    "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client", "/bin/autossl_check",
    "/usr/bin/autossl_check", "/proc/self/exe", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd",
    "/usr/libexec/netplan/generate", "./usr/bin/podman"
  ) or
  process.name in ("yumBackend.py", "crio", "dockerd") or
  file.extension in ("swp", "swpx", "swx") or
  file.Ext.original.name like ".ansible*" or
  file.name like ".ansible_tmp*" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/*", "/usr/libexec/*",
    "/etc/kernel/*"

  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*")
)
```



### Yum/DNF Plugin Status Discovery

Branch count: 36  
Document count: 36  
Index: geneve-ut-1690

```python
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name == "grep" and process.args : "plugins*" and process.args like (
  "/etc/yum.conf", "/usr/lib/yum-plugins/*", "/etc/yum/pluginconf.d/*",
  "/usr/lib/python*/site-packages/dnf-plugins/*", "/etc/dnf/plugins/*", "/etc/dnf/dnf.conf"
) and
not ?process.parent.executable == "/usr/lib/venv-salt-minion/bin/python.original"
```



### Zoom Meeting with no Passcode

Branch count: 1  
Document count: 1  
Index: geneve-ut-1691

```python
event.type:creation and event.module:zoom and event.dataset:zoom.webhook and
  event.action:meeting.created and not zoom.meeting.password:*
```



### rc.local/rc.common File Creation

Branch count: 8  
Document count: 8  
Index: geneve-ut-1693

```python
file where host.os.type == "linux" and event.action == "creation" and
file.path in ("/etc/rc.local", "/etc/rc.common") and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/libexec/platform-python"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  process.executable == null or
  process.name in ("ssm-agent-worker", "convert2rhel", "platform-python*") or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```
