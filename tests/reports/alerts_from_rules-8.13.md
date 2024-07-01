# Alerts generation from detection rules

This report captures the detection rules signals generation coverage. Here you can
learn what rules are supported and what not and why.

Curious about the inner workings? Read [here](signals_generation.md).

Rules version: 8.13.11

## Table of contents
   1. [Unsuccessful rules with signals (7)](#unsuccessful-rules-with-signals-7)
   1. [Rules with no signals (3)](#rules-with-no-signals-3)
   1. [Rules with too few signals (10)](#rules-with-too-few-signals-10)
   1. [Rules with the correct signals (826)](#rules-with-the-correct-signals-826)

## Unsuccessful rules with signals (7)

### File Creation, Execution and Self-Deletion in Suspicious Directory

Branch count: 4608  
Document count: 13824  
Index: geneve-ut-294

```python
sequence by host.id, user.id with maxspan=1m
  [file where host.os.type == "linux" and event.action == "creation" and 
   process.name in ("curl", "wget", "fetch", "ftp", "sftp", "scp", "rsync", "ld") and 
   file.path : ("/dev/shm/*", "/run/shm/*", "/tmp/*", "/var/tmp/*",
     "/run/*", "/var/run/*", "/var/www/*", "/proc/*/fd/*")] by file.name
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and 
   process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")] by process.name
  [file where host.os.type == "linux" and event.action == "deletion" and not process.name in ("rm", "ld") and 
   file.path : ("/dev/shm/*", "/run/shm/*", "/tmp/*", "/var/tmp/*",
     "/run/*", "/var/run/*", "/var/www/*", "/proc/*/fd/*")] by file.name
```



### Potential External Linux SSH Brute Force Detected

Branch count: 1024  
Document count: 10240  
Index: geneve-ut-631

```python
sequence by host.id, source.ip, user.name with maxspan=15s
  [ authentication where host.os.type == "linux" and 
   event.action in ("ssh_login", "user_login") and event.outcome == "failure" and
   not cidrmatch(source.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", 
       "::1", "FE80::/10", "FF00::/8") ] with runs = 10
```



### Potential Internal Linux SSH Brute Force Detected

Branch count: 1024  
Document count: 10240  
Index: geneve-ut-636

```python
sequence by host.id, source.ip, user.name with maxspan=15s
  [ authentication where host.os.type == "linux" and 
   event.action in ("ssh_login", "user_login") and event.outcome == "failure" and
   cidrmatch(source.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", 
       "::1", "FE80::/10", "FF00::/8") ] with runs = 10
```



### Potential Privilege Escalation via Service ImagePath Modification

Branch count: 1794  
Document count: 1794  
Index: geneve-ut-695

```python
registry where host.os.type == "windows" and event.type == "change" and process.executable != null and 
  event.action == "modification" and registry.value == "ImagePath" and
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



### Potential Successful SSH Brute Force Attack

Branch count: 2048  
Document count: 22528  
Index: geneve-ut-729

```python
sequence by host.id, source.ip, user.name with maxspan=15s
  [authentication where host.os.type == "linux" and event.action  in ("ssh_login", "user_login") and
   event.outcome == "failure" and source.ip != null and source.ip != "0.0.0.0" and source.ip != "::" ] with runs=10

  [authentication where host.os.type == "linux" and event.action  in ("ssh_login", "user_login") and
   event.outcome == "success" and source.ip != null and source.ip != "0.0.0.0" and source.ip != "::" ]
```



### Suspicious Execution via Scheduled Task

Branch count: 4608  
Document count: 4608  
Index: geneve-ut-928

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

     not (process.name : "cmd.exe" and process.args : "?:\\*.bat" and process.working_directory : "?:\\Windows\\System32\\") and
     not (process.name : "cscript.exe" and process.args : "?:\\Windows\\system32\\calluxxprovider.vbs") and
     not (process.name : "powershell.exe" and process.args : ("-File", "-PSConsoleFile") and user.id : "S-1-5-18") and
     not (process.name : "msiexec.exe" and user.id : "S-1-5-18")
```



### Suspicious Symbolic Link Created

Branch count: 1836  
Document count: 1836  
Index: geneve-ut-982

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
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



## Rules with no signals (3)

### Linux Group Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-440

```python
iam where host.os.type == "linux" and (event.type == "group" and event.type == "creation") and
process.name in ("groupadd", "addgroup") and group.name != null
```



### Linux User Account Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-444

```python
iam where host.os.type == "linux" and (event.type == "user" and event.type == "creation") and
process.name in ("useradd", "adduser") and user.name != null
```



### Potential Network Share Discovery

Branch count: 4  
Document count: 8  
Index: geneve-ut-665

```python
sequence by user.name, source.port, source.ip with maxspan=15s 
 [file where event.action == "network-share-object-access-checked" and 
  winlog.event_data.ShareName in ("\\\\*\\ADMIN$", "\\\\*\\C$") and 
  source.ip != null and source.ip != "0.0.0.0" and source.ip != "::1" and source.ip != "::" and source.ip != "127.0.0.1"]
 [file where event.action == "network-share-object-access-checked" and 
  winlog.event_data.ShareName in ("\\\\*\\ADMIN$", "\\\\*\\C$") and 
  source.ip != null and source.ip != "0.0.0.0" and source.ip != "::1" and source.ip != "::" and source.ip != "127.0.0.1"]
```



## Rules with too few signals (10)

### File Creation, Execution and Self-Deletion in Suspicious Directory

Branch count: 4608  
Document count: 13824  
Index: geneve-ut-294  
Failure message(s):  
  got 1000 signals, expected 4608  

```python
sequence by host.id, user.id with maxspan=1m
  [file where host.os.type == "linux" and event.action == "creation" and 
   process.name in ("curl", "wget", "fetch", "ftp", "sftp", "scp", "rsync", "ld") and 
   file.path : ("/dev/shm/*", "/run/shm/*", "/tmp/*", "/var/tmp/*",
     "/run/*", "/var/run/*", "/var/www/*", "/proc/*/fd/*")] by file.name
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and 
   process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")] by process.name
  [file where host.os.type == "linux" and event.action == "deletion" and not process.name in ("rm", "ld") and 
   file.path : ("/dev/shm/*", "/run/shm/*", "/tmp/*", "/var/tmp/*",
     "/run/*", "/var/run/*", "/var/www/*", "/proc/*/fd/*")] by file.name
```



### Potential External Linux SSH Brute Force Detected

Branch count: 1024  
Document count: 10240  
Index: geneve-ut-631  
Failure message(s):  
  got 1000 signals, expected 1024  

```python
sequence by host.id, source.ip, user.name with maxspan=15s
  [ authentication where host.os.type == "linux" and 
   event.action in ("ssh_login", "user_login") and event.outcome == "failure" and
   not cidrmatch(source.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", 
       "::1", "FE80::/10", "FF00::/8") ] with runs = 10
```



### Potential Internal Linux SSH Brute Force Detected

Branch count: 1024  
Document count: 10240  
Index: geneve-ut-636  
Failure message(s):  
  got 1000 signals, expected 1024  

```python
sequence by host.id, source.ip, user.name with maxspan=15s
  [ authentication where host.os.type == "linux" and 
   event.action in ("ssh_login", "user_login") and event.outcome == "failure" and
   cidrmatch(source.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", 
       "::1", "FE80::/10", "FF00::/8") ] with runs = 10
```



### Potential Privilege Escalation via Enlightenment

Branch count: 6  
Document count: 12  
Index: geneve-ut-688  
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
Index: geneve-ut-695  
Failure message(s):  
  got 1000 signals, expected 1794  

```python
registry where host.os.type == "windows" and event.type == "change" and process.executable != null and 
  event.action == "modification" and registry.value == "ImagePath" and
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



### Potential Successful SSH Brute Force Attack

Branch count: 2048  
Document count: 22528  
Index: geneve-ut-729  
Failure message(s):  
  got 1000 signals, expected 2048  

```python
sequence by host.id, source.ip, user.name with maxspan=15s
  [authentication where host.os.type == "linux" and event.action  in ("ssh_login", "user_login") and
   event.outcome == "failure" and source.ip != null and source.ip != "0.0.0.0" and source.ip != "::" ] with runs=10

  [authentication where host.os.type == "linux" and event.action  in ("ssh_login", "user_login") and
   event.outcome == "success" and source.ip != null and source.ip != "0.0.0.0" and source.ip != "::" ]
```



### Privilege Escalation via CAP_CHOWN/CAP_FOWNER Capabilities

Branch count: 32  
Document count: 64  
Index: geneve-ut-771  
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



### Suspicious Execution via Scheduled Task

Branch count: 4608  
Document count: 4608  
Index: geneve-ut-928  
Failure message(s):  
  got 1000 signals, expected 4608  

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

     not (process.name : "cmd.exe" and process.args : "?:\\*.bat" and process.working_directory : "?:\\Windows\\System32\\") and
     not (process.name : "cscript.exe" and process.args : "?:\\Windows\\system32\\calluxxprovider.vbs") and
     not (process.name : "powershell.exe" and process.args : ("-File", "-PSConsoleFile") and user.id : "S-1-5-18") and
     not (process.name : "msiexec.exe" and user.id : "S-1-5-18")
```



### Suspicious Network Connection via systemd

Branch count: 11  
Document count: 22  
Index: geneve-ut-958  
Failure message(s):  
  got 8 signals, expected 11  

```python
sequence by host.id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name == "systemd" and process.name in (
     "python*", "php*", "perl", "ruby", "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk"
   )
  ] by process.entity_id
  [network where host.os.type == "linux" and event.action == "connection_attempted" and event.type == "start"
  ] by process.parent.entity_id
```



### Suspicious Symbolic Link Created

Branch count: 1836  
Document count: 1836  
Index: geneve-ut-982  
Failure message(s):  
  got 1000 signals, expected 1836  

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
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



## Rules with the correct signals (826)

### A scheduled task was created

Branch count: 1  
Document count: 1  
Index: geneve-ut-000

```python
iam where event.action == "scheduled-task-created" and

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



### A scheduled task was updated

Branch count: 1  
Document count: 1  
Index: geneve-ut-001

```python
iam where event.action == "scheduled-task-updated" and

 /* excluding tasks created by the computer account */
 not user.name : "*$" and 
 not winlog.event_data.TaskName : "*Microsoft*" and 
 not winlog.event_data.TaskName :
          ("\\User_Feed_Synchronization-*",
           "\\OneDrive Reporting Task-S-1-5-21*",
           "\\OneDrive Reporting Task-S-1-12-1-*",
           "\\Hewlett-Packard\\HP Web Products Detection",
           "\\Hewlett-Packard\\HPDeviceCheck", 
           "\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateAssistant", 
           "\\IpamDnsProvisioning",  
           "\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateAssistantAllUsersRun", 
           "\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateAssistantCalendarRun", 
           "\\Microsoft\\Windows\\UpdateOrchestrator\\UpdateAssistantWakeupRun", 
           "\\Microsoft\\Windows\\.NET Framework\\.NET Framework NGEN v*", 
           "\\Microsoft\\VisualStudio\\Updates\\BackgroundDownload") and 
  not winlog.event_data.SubjectUserSid :  ("S-1-5-18", "S-1-5-19", "S-1-5-20")
```



### APT Package Manager Configuration File Creation

Branch count: 8  
Document count: 8  
Index: geneve-ut-002

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
    "/usr/local/bin/apt-get", "/usr/bin/apt-get"
  ) or
  file.path :("/etc/apt/apt.conf.d/*.tmp*") or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/*", "/usr/libexec/*",
    "/etc/kernel/*"
  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```



### AWS CloudTrail Log Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-006

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:CreateTrail and event.outcome:success
```



### AWS CloudTrail Log Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-007

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:DeleteTrail and event.outcome:success
```



### AWS CloudTrail Log Suspended

Branch count: 1  
Document count: 1  
Index: geneve-ut-008

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:StopLogging and event.outcome:success
```



### AWS CloudTrail Log Updated

Branch count: 1  
Document count: 1  
Index: geneve-ut-009

```python
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:UpdateTrail and event.outcome:success
```



### AWS CloudWatch Alarm Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-010

```python
event.dataset:aws.cloudtrail and event.provider:monitoring.amazonaws.com and event.action:DeleteAlarms and event.outcome:success
```



### AWS CloudWatch Log Group Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-011

```python
event.dataset:aws.cloudtrail and event.provider:logs.amazonaws.com and event.action:DeleteLogGroup and event.outcome:success
```



### AWS CloudWatch Log Stream Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-012

```python
event.dataset:aws.cloudtrail and event.provider:logs.amazonaws.com and event.action:DeleteLogStream and event.outcome:success
```



### AWS Config Resource Deletion

Branch count: 9  
Document count: 9  
Index: geneve-ut-013

```python
event.dataset:aws.cloudtrail and event.provider:config.amazonaws.com and
    event.action:(DeleteConfigRule or DeleteOrganizationConfigRule or DeleteConfigurationAggregator or
    DeleteConfigurationRecorder or DeleteConformancePack or DeleteOrganizationConformancePack or
    DeleteDeliveryChannel or DeleteRemediationConfiguration or DeleteRetentionConfiguration)
```



### AWS Configuration Recorder Stopped

Branch count: 1  
Document count: 1  
Index: geneve-ut-014

```python
event.dataset:aws.cloudtrail and event.provider:config.amazonaws.com and event.action:StopConfigurationRecorder and event.outcome:success
```



### AWS Credentials Searched For Inside A Container

Branch count: 84  
Document count: 84  
Index: geneve-ut-015

```python
process where event.module == "cloud_defend" and     
  event.type == "start" and

/*account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg*/
(process.name : ("grep", "egrep", "fgrep", "find", "locate", "mlocate") or process.args : ("grep", "egrep", "fgrep", "find", "locate", "mlocate")) and 
process.args : ("*aws_access_key_id*", "*aws_secret_access_key*", "*aws_session_token*", "*accesskeyid*", "*secretaccesskey*", "*access_key*", "*.aws/credentials*")
```



### AWS Deletion of RDS Instance or Cluster

Branch count: 3  
Document count: 3  
Index: geneve-ut-016

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(DeleteDBCluster or DeleteGlobalCluster or DeleteDBInstance)
and event.outcome:success
```



### AWS EC2 Encryption Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-019

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:DisableEbsEncryptionByDefault and event.outcome:success
```



### AWS EC2 Full Network Packet Capture Detected

Branch count: 4  
Document count: 4  
Index: geneve-ut-020

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and
event.action:(CreateTrafficMirrorFilter or CreateTrafficMirrorFilterRule or CreateTrafficMirrorSession or CreateTrafficMirrorTarget) and
event.outcome:success
```



### AWS EC2 Instance Connect SSH Public Key Uploaded

Branch count: 2  
Document count: 2  
Index: geneve-ut-021

```python
event.dataset: aws.cloudtrail
    and event.provider: ec2-instance-connect.amazonaws.com
    and event.action: (SendSSHPublicKey or SendSerialConsoleSSHPublicKey)
    and event.outcome: success
```



### AWS EC2 Network Access Control List Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-022

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(CreateNetworkAcl or CreateNetworkAclEntry) and event.outcome:success
```



### AWS EC2 Network Access Control List Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-023

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(DeleteNetworkAcl or DeleteNetworkAclEntry) and event.outcome:success
```



### AWS EC2 Snapshot Activity

Branch count: 1  
Document count: 1  
Index: geneve-ut-024

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:ModifySnapshotAttribute
```



### AWS EC2 VM Export Failure

Branch count: 1  
Document count: 1  
Index: geneve-ut-025

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:CreateInstanceExportTask and event.outcome:failure
```



### AWS EFS File System or Mount Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-026

```python
event.dataset:aws.cloudtrail and event.provider:elasticfilesystem.amazonaws.com and
event.action:(DeleteMountTarget or DeleteFileSystem) and event.outcome:success
```



### AWS ElastiCache Security Group Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-027

```python
event.dataset:aws.cloudtrail and event.provider:elasticache.amazonaws.com and event.action:"Create Cache Security Group" and
event.outcome:success
```



### AWS ElastiCache Security Group Modified or Deleted

Branch count: 5  
Document count: 5  
Index: geneve-ut-028

```python
event.dataset:aws.cloudtrail and event.provider:elasticache.amazonaws.com and event.action:("Delete Cache Security Group" or
"Authorize Cache Security Group Ingress" or  "Revoke Cache Security Group Ingress" or "AuthorizeCacheSecurityGroupEgress" or
"RevokeCacheSecurityGroupEgress") and event.outcome:success
```



### AWS EventBridge Rule Disabled or Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-029

```python
event.dataset:aws.cloudtrail and event.provider:eventbridge.amazonaws.com and event.action:(DeleteRule or DisableRule) and
event.outcome:success
```



### AWS Execution via System Manager

Branch count: 1  
Document count: 1  
Index: geneve-ut-030

```python
event.dataset:aws.cloudtrail and event.provider:ssm.amazonaws.com and event.action:SendCommand and event.outcome:success
```



### AWS GuardDuty Detector Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-031

```python
event.dataset:aws.cloudtrail and event.provider:guardduty.amazonaws.com and event.action:DeleteDetector and event.outcome:success
```



### AWS IAM Assume Role Policy Update

Branch count: 1  
Document count: 1  
Index: geneve-ut-035

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:UpdateAssumeRolePolicy and event.outcome:success
```



### AWS IAM Deactivation of MFA Device

Branch count: 2  
Document count: 2  
Index: geneve-ut-037

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:(DeactivateMFADevice or DeleteVirtualMFADevice) and event.outcome:success
```



### AWS IAM Group Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-038

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:CreateGroup and event.outcome:success
```



### AWS IAM Group Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-039

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:DeleteGroup and event.outcome:success
```



### AWS IAM Login Profile Added to User

Branch count: 1  
Document count: 1  
Index: geneve-ut-040

```python
event.dataset: aws.cloudtrail and event.provider: "iam.amazonaws.com"
    and event.action: "CreateLoginProfile" and event.outcome: success
```



### AWS IAM Password Recovery Requested

Branch count: 1  
Document count: 1  
Index: geneve-ut-041

```python
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:PasswordRecoveryRequested and event.outcome:success
```



### AWS IAM Roles Anywhere Profile Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-042

```python
event.dataset:aws.cloudtrail
    and event.provider: rolesanywhere.amazonaws.com
    and event.action: CreateProfile
    and event.outcome: success
```



### AWS IAM Roles Anywhere Trust Anchor Created with External CA

Branch count: 1  
Document count: 1  
Index: geneve-ut-043

```python
event.dataset: aws.cloudtrail
    and event.provider: rolesanywhere.amazonaws.com
    and event.action: CreateTrustAnchor
    and event.outcome: success
    and not aws.cloudtrail.request_parameters: *sourceType=AWS_ACM_PCA*
```



### AWS IAM User Addition to Group

Branch count: 1  
Document count: 1  
Index: geneve-ut-044

```python
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:AddUserToGroup and event.outcome:success
```



### AWS KMS Customer Managed Key Disabled or Scheduled for Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-046

```python
event.dataset:aws.cloudtrail and event.provider:kms.amazonaws.com and event.action:("DisableKey" or "ScheduleKeyDeletion") and event.outcome:success
```



### AWS Lambda Function Created or Updated

Branch count: 2  
Document count: 2  
Index: geneve-ut-047

```python
event.dataset: "aws.cloudtrail"
    and event.provider: "lambda.amazonaws.com"
    and event.outcome: "success"
    and event.action: (CreateFunction* or UpdateFunctionCode*)
```



### AWS Lambda Layer Added to Existing Function

Branch count: 2  
Document count: 2  
Index: geneve-ut-049

```python
event.dataset: aws.cloudtrail
    and event.provider: lambda.amazonaws.com
    and event.outcome: success
    and event.action: (PublishLayerVersion* or UpdateFunctionConfiguration)
```



### AWS Management Console Root Login

Branch count: 1  
Document count: 1  
Index: geneve-ut-051

```python
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:ConsoleLogin and aws.cloudtrail.user_identity.type:Root and event.outcome:success
```



### AWS RDS Cluster Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-052

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(CreateDBCluster or CreateGlobalCluster) and event.outcome:success
```



### AWS RDS DB Snapshot Created

Branch count: 2  
Document count: 2  
Index: geneve-ut-053

```python
event.dataset: "aws.cloudtrail" and event.provider: "rds.amazonaws.com" 
    and event.action: ("CreateDBSnapshot" or "CreateDBClusterSnapshot") and event.outcome: "success"
```



### AWS RDS Instance Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-054

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:CreateDBInstance and event.outcome:success
```



### AWS RDS Instance/Cluster Stoppage

Branch count: 2  
Document count: 2  
Index: geneve-ut-055

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:(StopDBCluster or StopDBInstance) and event.outcome:success
```



### AWS RDS Security Group Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-056

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:CreateDBSecurityGroup and event.outcome:success
```



### AWS RDS Security Group Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-057

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:DeleteDBSecurityGroup and event.outcome:success
```



### AWS RDS Snapshot Export

Branch count: 1  
Document count: 1  
Index: geneve-ut-058

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:StartExportTask and event.outcome:success
```



### AWS RDS Snapshot Restored

Branch count: 1  
Document count: 1  
Index: geneve-ut-059

```python
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:RestoreDBInstanceFromDBSnapshot and
event.outcome:success
```



### AWS Redshift Cluster Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-060

```python
event.dataset:aws.cloudtrail and event.provider:redshift.amazonaws.com and event.action:CreateCluster and event.outcome:success
```



### AWS Root Login Without MFA

Branch count: 1  
Document count: 1  
Index: geneve-ut-061

```python
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:ConsoleLogin and
  aws.cloudtrail.user_identity.type:Root and
  aws.cloudtrail.console_login.additional_eventdata.mfa_used:false and
  event.outcome:success
```



### AWS Route 53 Domain Transfer Lock Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-062

```python
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:DisableDomainTransferLock and event.outcome:success
```



### AWS Route 53 Domain Transferred to Another Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-063

```python
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:TransferDomainToAnotherAwsAccount and event.outcome:success
```



### AWS Route Table Created

Branch count: 2  
Document count: 2  
Index: geneve-ut-064

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(CreateRoute or CreateRouteTable) and
event.outcome:success
```



### AWS Route Table Modified or Deleted

Branch count: 5  
Document count: 5  
Index: geneve-ut-065

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(ReplaceRoute or ReplaceRouteTableAssociation or
DeleteRouteTable or DeleteRoute or DisassociateRouteTable) and event.outcome:success
```



### AWS Route53 private hosted zone associated with a VPC

Branch count: 1  
Document count: 1  
Index: geneve-ut-066

```python
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:AssociateVPCWithHostedZone and
event.outcome:success
```



### AWS S3 Bucket Configuration Deletion

Branch count: 5  
Document count: 5  
Index: geneve-ut-067

```python
event.dataset:aws.cloudtrail and event.provider:s3.amazonaws.com and
  event.action:(DeleteBucketPolicy or DeleteBucketReplication or DeleteBucketCors or
                DeleteBucketEncryption or DeleteBucketLifecycle)
  and event.outcome:success
```



### AWS SAML Activity

Branch count: 4  
Document count: 4  
Index: geneve-ut-071

```python
event.dataset:aws.cloudtrail and event.provider:(iam.amazonaws.com or sts.amazonaws.com) and event.action:(Assumerolewithsaml or
UpdateSAMLProvider) and event.outcome:success
```



### AWS STS GetSessionToken Abuse

Branch count: 1  
Document count: 1  
Index: geneve-ut-073

```python
event.dataset:aws.cloudtrail and event.provider:sts.amazonaws.com and event.action:GetSessionToken and
aws.cloudtrail.user_identity.type:IAMUser and event.outcome:success
```



### AWS Security Group Configuration Change Detection

Branch count: 6  
Document count: 6  
Index: geneve-ut-074

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(AuthorizeSecurityGroupEgress or
CreateSecurityGroup or ModifyInstanceAttribute or ModifySecurityGroupRules or RevokeSecurityGroupEgress or
RevokeSecurityGroupIngress) and event.outcome:success
```



### AWS Security Token Service (STS) AssumeRole Usage

Branch count: 1  
Document count: 1  
Index: geneve-ut-075

```python
event.dataset:aws.cloudtrail and event.provider:sts.amazonaws.com and event.action:AssumeRole and
aws.cloudtrail.user_identity.session_context.session_issuer.type:Role and event.outcome:success
```



### AWS VPC Flow Logs Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-077

```python
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:DeleteFlowLogs and event.outcome:success
```



### AWS WAF Access Control List Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-078

```python
event.dataset:aws.cloudtrail and event.action:DeleteWebACL and event.outcome:success
```



### AWS WAF Rule or Rule Group Deletion

Branch count: 6  
Document count: 6  
Index: geneve-ut-079

```python
event.dataset:aws.cloudtrail and event.provider:(waf.amazonaws.com or waf-regional.amazonaws.com or wafv2.amazonaws.com) and event.action:(DeleteRule or DeleteRuleGroup) and event.outcome:success
```



### Accepted Default Telnet Port Connection

Branch count: 3  
Document count: 3  
Index: geneve-ut-082

```python
(event.dataset:network_traffic.flow or event.category:(network or network_traffic))
    and event.type:connection and not event.action:(
        flow_dropped or denied or deny or
        flow_terminated or timeout or Reject or network_flow)
    and destination.port:23
```



### Access to Keychain Credentials Directories

Branch count: 12  
Document count: 12  
Index: geneve-ut-083

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
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
    not process.executable : ("/opt/jc/bin/jumpcloud-agent", "/usr/bin/basename") and
    not process.Ext.effective_parent.executable : ("/opt/rapid7/ir_agent/ir_agent",
                                                   "/Library/Elastic/Endpoint/elastic-endpoint.app/Contents/MacOS/elastic-endpoint",
                                                   "/Applications/QualysCloudAgent.app/Contents/MacOS/qualys-cloud-agent",
                                                   "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon",
                                                   "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfManagementService.app/Contents/MacOS/JamfManagementService",
                                                   "/usr/local/jamf/bin/jamf",
                                                   "/Applications/Microsoft Defender.app/Contents/MacOS/wdavdaemon")
```



### Access to a Sensitive LDAP Attribute

Branch count: 4  
Document count: 4  
Index: geneve-ut-084

```python
any where event.action == "Directory Service Access" and event.code == "4662" and

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
Index: geneve-ut-085

```python
process where host.os.type == "windows" and event.type == "start" and process.args : ("*.ost", "*.pst") and
  not process.name : "outlook.exe" and
  not (
        process.name : "rundll32.exe" and
        process.args : "*davclnt.dll,DavSetCookie*"
  )
```



### Account Discovery Command via SYSTEM Account

Branch count: 4  
Document count: 4  
Index: geneve-ut-087

```python
process where host.os.type == "windows" and event.type == "start" and
  (?process.Ext.token.integrity_level_name : "System" or
  ?winlog.event_data.IntegrityLevel : "System") and
  (
    process.name : "whoami.exe" or
    (
      process.name : "net1.exe" and not process.parent.name : "net.exe" and not process.args : ("start", "stop", "/active:*")
    )
  )
```



### Account Password Reset Remotely

Branch count: 9  
Document count: 18  
Index: geneve-ut-088

```python
sequence by winlog.computer_name with maxspan=1m
  [authentication where event.action == "logged-in" and
    /* event 4624 need to be logged */
    winlog.logon.type : "Network" and event.outcome == "success" and source.ip != null and
    source.ip != "127.0.0.1" and source.ip != "::1" and
    not winlog.event_data.TargetUserName : ("svc*", "PIM_*", "_*_", "*-*-*", "*$")] by winlog.event_data.TargetLogonId
   /* event 4724 need to be logged */
  [iam where event.action == "reset-password" and
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



### Account or Group Discovery via Built-In Tools

Branch count: 48  
Document count: 48  
Index: geneve-ut-089

```python
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and ( 
  (process.name in ("groups", "id")) or 
  (process.name == "dscl" and process.args : ("/Active Directory/*", "/Users*", "/Groups*")) or
  (process.name == "dscacheutil" and process.args in ("user", "group")) or
  (process.args in ("/etc/passwd", "/etc/master.passwd", "/etc/sudoers")) or
  (process.name == "getent" and process.args in ("passwd", "group"))
)
```



### Active Directory Group Modification by SYSTEM

Branch count: 1  
Document count: 1  
Index: geneve-ut-090

```python
iam where winlog.api == "wineventlog" and event.code == "4728" and
winlog.event_data.SubjectUserSid : "S-1-5-18" and

/* DOMAIN_USERS and local groups */
not group.id : "S-1-5-21-*-513"
```



### AdFind Command Activity

Branch count: 36  
Document count: 36  
Index: geneve-ut-091

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "AdFind.exe" or ?process.pe.original_file_name == "AdFind.exe") and
  process.args : ("objectcategory=computer", "(objectcategory=computer)",
                  "objectcategory=person", "(objectcategory=person)",
                  "objectcategory=subnet", "(objectcategory=subnet)",
                  "objectcategory=group", "(objectcategory=group)",
                  "objectcategory=organizationalunit", "(objectcategory=organizationalunit)",
                  "objectcategory=attributeschema", "(objectcategory=attributeschema)",
                  "domainlist", "dcmodes", "adinfo", "dclist", "computers_pwnotreqd", "trustdmp")
```



### Adding Hidden File Attribute via Attrib

Branch count: 4  
Document count: 4  
Index: geneve-ut-092

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "attrib.exe" or ?process.pe.original_file_name == "ATTRIB.EXE") and process.args : "+h" and
  not (process.parent.name: "cmd.exe" and process.command_line: "attrib  +R +H +S +A *.cui")
```



### AdminSDHolder Backdoor

Branch count: 1  
Document count: 1  
Index: geneve-ut-093

```python
event.action:"Directory Service Changes" and event.code:5136 and
  winlog.event_data.ObjectDN:CN=AdminSDHolder,CN=System*
```



### Administrator Privileges Assigned to an Okta Group

Branch count: 1  
Document count: 1  
Index: geneve-ut-095

```python
event.dataset:okta.system and event.action:group.privilege.grant
```



### Administrator Role Assigned to an Okta User

Branch count: 1  
Document count: 1  
Index: geneve-ut-096

```python
event.dataset:okta.system and event.action:user.account.privilege.grant
```



### Adobe Hijack Persistence

Branch count: 2  
Document count: 2  
Index: geneve-ut-097

```python
file where host.os.type == "windows" and event.type == "creation" and
  file.path : ("?:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe",
               "?:\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\AcroCEF\\RdrCEF.exe") and
  not process.name : "msiexec.exe"
```



### Adversary Behavior - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-098

```python
event.kind:alert and event.module:endgame and (event.action:behavior_protection_event or endgame.event_subtype_full:behavior_protection_event)
```



### Agent Spoofing - Mismatched Agent ID

Branch count: 2  
Document count: 2  
Index: geneve-ut-099

```python
event.agent_id_status:(agent_id_mismatch or mismatch)
```



### Apple Script Execution followed by Network Connection

Branch count: 1  
Document count: 2  
Index: geneve-ut-106

```python
sequence by host.id, process.entity_id with maxspan=30s
 [process where host.os.type == "macos" and event.type == "start" and process.name == "osascript"]
 [network where host.os.type == "macos" and event.type != "end" and process.name == "osascript" and destination.ip != "::1" and
  not cidrmatch(destination.ip,
    "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32",
    "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24",
    "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10", "FF00::/8")]
```



### Apple Scripting Execution with Administrator Privileges

Branch count: 2  
Document count: 2  
Index: geneve-ut-107

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name : "osascript" and
  process.command_line : "osascript*with administrator privileges" and
  not process.parent.name : "Electron" and
  not process.Ext.effective_parent.executable : ("/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
                                                 "/Applications/OpenVPN Connect/Uninstall OpenVPN Connect.app/Contents/MacOS/uninstaller")
```



### Application Added to Google Workspace Domain

Branch count: 1  
Document count: 1  
Index: geneve-ut-108

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:ADD_APPLICATION
```



### Application Removed from Blocklist in Google Workspace

Branch count: 1  
Document count: 1  
Index: geneve-ut-109

```python
event.dataset:"google_workspace.admin" and event.category:"iam" and event.type:"change"  and
  event.action:"CHANGE_APPLICATION_SETTING" and
  google_workspace.admin.application.name:"Google Workspace Marketplace" and
  google_workspace.admin.old_value: *allowed*false* and google_workspace.admin.new_value: *allowed*true*
```



### At Job Created or Modified

Branch count: 8  
Document count: 8  
Index: geneve-ut-111

```python
file where host.os.type == "linux" and
event.action in ("rename", "creation") and file.path : "/var/spool/cron/atjobs/*" and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/local/bin/dockerd"
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
Index: geneve-ut-112

```python
process where host.os.type == "windows" and event.type == "start" and process.name : "at.exe" and process.args : "\\\\*"
```



### Attempt to Clear Kernel Ring Buffer

Branch count: 4  
Document count: 4  
Index: geneve-ut-113

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name == "dmesg" and process.args == "-c"
```



### Attempt to Create Okta API Token

Branch count: 1  
Document count: 1  
Index: geneve-ut-114

```python
event.dataset:okta.system and event.action:system.api_token.create
```



### Attempt to Deactivate an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-115

```python
event.dataset:okta.system and event.action:application.lifecycle.deactivate
```



### Attempt to Deactivate an Okta Network Zone

Branch count: 1  
Document count: 1  
Index: geneve-ut-116

```python
event.dataset:okta.system and event.action:zone.deactivate
```



### Attempt to Deactivate an Okta Policy

Branch count: 1  
Document count: 1  
Index: geneve-ut-117

```python
event.dataset:okta.system and event.action:policy.lifecycle.deactivate
```



### Attempt to Deactivate an Okta Policy Rule

Branch count: 1  
Document count: 1  
Index: geneve-ut-118

```python
event.dataset:okta.system and event.action:policy.rule.deactivate
```



### Attempt to Delete an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-119

```python
event.dataset:okta.system and event.action:application.lifecycle.delete
```



### Attempt to Delete an Okta Network Zone

Branch count: 1  
Document count: 1  
Index: geneve-ut-120

```python
event.dataset:okta.system and event.action:zone.delete
```



### Attempt to Delete an Okta Policy

Branch count: 1  
Document count: 1  
Index: geneve-ut-121

```python
event.dataset:okta.system and event.action:policy.lifecycle.delete
```



### Attempt to Delete an Okta Policy Rule

Branch count: 1  
Document count: 1  
Index: geneve-ut-122

```python
event.dataset:okta.system and event.action:policy.rule.delete
```



### Attempt to Disable Gatekeeper

Branch count: 2  
Document count: 2  
Index: geneve-ut-123

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and
  process.args:(spctl and "--master-disable")
```



### Attempt to Disable IPTables or Firewall

Branch count: 34  
Document count: 34  
Index: geneve-ut-124

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
 (
   /* disable FW */
   (
     (process.name == "ufw" and process.args == "disable") or
     (process.name == "iptables" and process.args == "-F" and process.args_count == 2)
   ) or

   /* stop FW service */
   (
     ((process.name == "service" and process.args == "stop") or
       (process.name == "chkconfig" and process.args == "off") or
       (process.name == "systemctl" and process.args in ("disable", "stop", "kill"))) and
    process.args in ("firewalld", "ip6tables", "iptables")
    )
  )
```



### Attempt to Disable Syslog Service

Branch count: 30  
Document count: 30  
Index: geneve-ut-125

```python
process where host.os.type == "linux" and event.action in ("exec", "exec_event") and
 ( (process.name == "service" and process.args == "stop") or
   (process.name == "chkconfig" and process.args == "off") or
   (process.name == "systemctl" and process.args in ("disable", "stop", "kill"))
 ) and process.args in ("syslog", "rsyslog", "syslog-ng")
```



### Attempt to Enable the Root Account

Branch count: 2  
Document count: 2  
Index: geneve-ut-126

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:dsenableroot and not process.args:"-d"
```



### Attempt to Install Kali Linux via WSL

Branch count: 7  
Document count: 7  
Index: geneve-ut-127

```python
process where host.os.type == "windows" and event.type == "start" and
(
 (process.name : "wsl.exe" and process.args : ("-d", "--distribution", "-i", "--install") and process.args : "kali*") or 
 process.executable : 
        ("?:\\Users\\*\\AppData\\Local\\packages\\kalilinux*", 
         "?:\\Users\\*\\AppData\\Local\\Microsoft\\WindowsApps\\kali.exe",
         "?:\\Program Files*\\WindowsApps\\KaliLinux.*\\kali.exe")
 )
```



### Attempt to Install Root Certificate

Branch count: 2  
Document count: 2  
Index: geneve-ut-128

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and
  process.name:security and process.args:"add-trusted-cert" and
  not process.parent.executable:("/Library/Bitdefender/AVP/product/bin/BDCoreIssues" or "/Applications/Bitdefender/SecurityNetworkInstallerApp.app/Contents/MacOS/SecurityNetworkInstallerApp"
)
```



### Attempt to Modify an Okta Application

Branch count: 1  
Document count: 1  
Index: geneve-ut-129

```python
event.dataset:okta.system and event.action:application.lifecycle.update
```



### Attempt to Modify an Okta Network Zone

Branch count: 3  
Document count: 3  
Index: geneve-ut-130

```python
event.dataset:okta.system and event.action:(zone.update or network_zone.rule.disabled or zone.remove_blacklist)
```



### Attempt to Modify an Okta Policy

Branch count: 1  
Document count: 1  
Index: geneve-ut-131

```python
event.dataset:okta.system and event.action:policy.lifecycle.update
```



### Attempt to Modify an Okta Policy Rule

Branch count: 1  
Document count: 1  
Index: geneve-ut-132

```python
event.dataset:okta.system and event.action:policy.rule.update
```



### Attempt to Mount SMB Share via Command Line

Branch count: 8  
Document count: 8  
Index: geneve-ut-133

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  (
    process.name : "mount_smbfs" or
    (process.name : "open" and process.args : "smb://*") or
    (process.name : "mount" and process.args : "smbfs") or
    (process.name : "osascript" and process.command_line : "osascript*mount volume*smb://*")
  ) and
  not process.parent.executable : "/Applications/Google Drive.app/Contents/MacOS/Google Drive"
```



### Attempt to Reset MFA Factors for an Okta User Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-134

```python
event.dataset:okta.system and event.action:user.mfa.factor.reset_all
```



### Attempt to Revoke Okta API Token

Branch count: 1  
Document count: 1  
Index: geneve-ut-136

```python
event.dataset:okta.system and event.action:system.api_token.revoke
```



### Attempt to Unload Elastic Endpoint Security Kernel Extension

Branch count: 4  
Document count: 4  
Index: geneve-ut-137

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:kextunload and process.args:("/System/Library/Extensions/EndpointSecurity.kext" or "EndpointSecurity.kext")
```



### Attempted Bypass of Okta MFA

Branch count: 1  
Document count: 1  
Index: geneve-ut-138

```python
event.dataset:okta.system and event.action:user.mfa.attempt_bypass
```



### Attempted Private Key Access

Branch count: 3  
Document count: 3  
Index: geneve-ut-139

```python
process where host.os.type == "windows" and event.type == "start" and
  process.args : ("*.pem *", "*.pem", "*.id_rsa*") and
  not process.args: ("--tls-cert", "--ssl-cert") and
  not process.executable : (
    "?:\\ProgramData\\Logishrd\\LogiOptions\\Software\\*\\LogiLuUpdater.exe",
    "?:\\Program Files\\Elastic\\Agent\\data\\*\\osqueryd.exe",
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

Branch count: 2  
Document count: 2  
Index: geneve-ut-143

```python
event.category:file and host.os.type:macos and not event.type:deletion and
  file.path:(/Library/Security/SecurityAgentPlugins/* and
  not (/Library/Security/SecurityAgentPlugins/KandjiPassport.bundle/* or /Library/Security/SecurityAgentPlugins/TeamViewerAuthPlugin.bundle/*)) and
  not (process.name:shove and process.code_signature.trusted:true)
```



### Azure AD Global Administrator Role Assigned

Branch count: 1  
Document count: 1  
Index: geneve-ut-144

```python
event.dataset:azure.auditlogs and azure.auditlogs.properties.category:RoleManagement and
azure.auditlogs.operation_name:"Add member to role" and
azure.auditlogs.properties.target_resources.0.modified_properties.1.new_value:"\"Global Administrator\""
```



### Azure Active Directory High Risk Sign-in

Branch count: 4  
Document count: 4  
Index: geneve-ut-145

```python
event.dataset:azure.signinlogs and
  (azure.signinlogs.properties.risk_level_during_signin:high or azure.signinlogs.properties.risk_level_aggregated:high) and
  event.outcome:(success or Success)
```



### Azure Active Directory High Risk User Sign-in Heuristic

Branch count: 4  
Document count: 4  
Index: geneve-ut-146

```python
event.dataset:azure.signinlogs and
  azure.signinlogs.properties.risk_state:("confirmedCompromised" or "atRisk") and event.outcome:(success or Success)
```



### Azure Active Directory PowerShell Sign-in

Branch count: 2  
Document count: 2  
Index: geneve-ut-147

```python
event.dataset:azure.signinlogs and
  azure.signinlogs.properties.app_display_name:"Azure Active Directory PowerShell" and
  azure.signinlogs.properties.token_issuer_type:AzureAD and event.outcome:(success or Success)
```



### Azure Alert Suppression Rule Created or Modified

Branch count: 1  
Document count: 1  
Index: geneve-ut-148

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.SECURITY/ALERTSSUPPRESSIONRULES/WRITE" and
event.outcome: "success"
```



### Azure Application Credential Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-149

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Update application - Certificates and secrets management" and event.outcome:(success or Success)
```



### Azure Automation Account Created

Branch count: 2  
Document count: 2  
Index: geneve-ut-150

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WRITE" and event.outcome:(Success or success)
```



### Azure Automation Runbook Created or Modified

Branch count: 6  
Document count: 6  
Index: geneve-ut-151

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
Index: geneve-ut-152

```python
event.dataset:azure.activitylogs and
    azure.activitylogs.operation_name:"MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE" and
    event.outcome:(Success or success)
```



### Azure Automation Webhook Created

Branch count: 4  
Document count: 4  
Index: geneve-ut-153

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
Index: geneve-ut-154

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE" and event.outcome:(Success or success)
```



### Azure Blob Permissions Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-155

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:(
     "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/BLOBS/MANAGEOWNERSHIP/ACTION" or
     "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/BLOBS/MODIFYPERMISSIONS/ACTION") and
  event.outcome:(Success or success)
```



### Azure Command Execution on Virtual Machine

Branch count: 2  
Document count: 2  
Index: geneve-ut-156

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION" and event.outcome:(Success or success)
```



### Azure Conditional Access Policy Modified

Branch count: 4  
Document count: 4  
Index: geneve-ut-157

```python
event.dataset:(azure.activitylogs or azure.auditlogs) and
event.action:"Update conditional access policy" and event.outcome:(Success or success)
```



### Azure Diagnostic Settings Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-158

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE" and event.outcome:(Success or success)
```



### Azure Event Hub Authorization Rule Created or Updated

Branch count: 2  
Document count: 2  
Index: geneve-ut-159

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.EVENTHUB/NAMESPACES/AUTHORIZATIONRULES/WRITE" and event.outcome:(Success or success)
```



### Azure Event Hub Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-160

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE" and event.outcome:(Success or success)
```



### Azure External Guest User Invitation

Branch count: 2  
Document count: 2  
Index: geneve-ut-161

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Invite external user" and azure.auditlogs.properties.target_resources.*.display_name:guest and event.outcome:(Success or success)
```



### Azure Firewall Policy Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-162

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE" and event.outcome:(Success or success)
```



### Azure Frontdoor Web Application Firewall (WAF) Policy Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-163

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/FRONTDOORWEBAPPLICATIONFIREWALLPOLICIES/DELETE" and event.outcome:(Success or success)
```



### Azure Full Network Packet Capture Detected

Branch count: 6  
Document count: 6  
Index: geneve-ut-164

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:
    (
        MICROSOFT.NETWORK/*/STARTPACKETCAPTURE/ACTION or
        MICROSOFT.NETWORK/*/VPNCONNECTIONS/STARTPACKETCAPTURE/ACTION or
        MICROSOFT.NETWORK/*/PACKETCAPTURES/WRITE
    ) and
event.outcome:(Success or success)
```



### Azure Global Administrator Role Addition to PIM User

Branch count: 4  
Document count: 4  
Index: geneve-ut-165

```python
event.dataset:azure.auditlogs and azure.auditlogs.properties.category:RoleManagement and
    azure.auditlogs.operation_name:("Add eligible member to role in PIM completed (permanent)" or
                                    "Add member to role in PIM completed (timebound)") and
    azure.auditlogs.properties.target_resources.*.display_name:"Global Administrator" and
    event.outcome:(Success or success)
```



### Azure Key Vault Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-166

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KEYVAULT/VAULTS/WRITE" and event.outcome:(Success or success)
```



### Azure Kubernetes Events Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-167

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EVENTS.K8S.IO/EVENTS/DELETE" and
event.outcome:(Success or success)
```



### Azure Kubernetes Pods Deleted

Branch count: 2  
Document count: 2  
Index: geneve-ut-168

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE" and
event.outcome:(Success or success)
```



### Azure Kubernetes Rolebindings Created

Branch count: 4  
Document count: 4  
Index: geneve-ut-169

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:
	("MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLEBINDINGS/WRITE" or
	 "MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLEBINDINGS/WRITE") and
event.outcome:(Success or success)
```



### Azure Network Watcher Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-170

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE" and event.outcome:(Success or success)
```



### Azure Privilege Identity Management Role Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-171

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Update role setting in PIM" and event.outcome:(Success or success)
```



### Azure Resource Group Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-172

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE" and event.outcome:(Success or success)
```



### Azure Service Principal Addition

Branch count: 2  
Document count: 2  
Index: geneve-ut-173

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add service principal" and event.outcome:(success or Success)
```



### Azure Service Principal Credentials Added

Branch count: 2  
Document count: 2  
Index: geneve-ut-174

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add service principal credentials" and event.outcome:(success or Success)
```



### Azure Storage Account Key Regenerated

Branch count: 2  
Document count: 2  
Index: geneve-ut-175

```python
event.dataset:azure.activitylogs and azure.activitylogs.operation_name:"MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION" and event.outcome:(Success or success)
```



### Azure Virtual Network Device Modified or Deleted

Branch count: 22  
Document count: 22  
Index: geneve-ut-176

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
Index: geneve-ut-177

```python
process where host.os.type == "linux" and event.type != "end" and process.executable == "/usr/sbin/tc" and
process.args == "filter" and process.args == "add" and process.args == "bpf" and
not process.parent.executable == "/usr/sbin/libvirtd"
```



### Base16 or Base32 Encoding/Decoding Activity

Branch count: 16  
Document count: 16  
Index: geneve-ut-178

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name in ("base16", "base32", "base32plain", "base32hex") and
not process.args in ("--help", "--version")
```



### Bash Shell Profile Modification

Branch count: 9  
Document count: 9  
Index: geneve-ut-179

```python
event.category:file and event.type:change and
  process.name:(* and not (sudo or vim or zsh or env or nano or bash or Terminal or xpcproxy or login or cat or cp or
  launchctl or java or dnf or tailwatchd or ldconfig or yum or semodule or cpanellogd or dockerd or authselect or chmod or
  dnf-automatic or git or dpkg or platform-python)) and
  not process.executable:(/Applications/* or /private/var/folders/* or /usr/local/* or /opt/saltstack/salt/bin/*) and
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



### Binary Content Copy via Cmd.exe

Branch count: 3  
Document count: 3  
Index: geneve-ut-180

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "cmd.exe" and (
    (process.args : "type" and process.args : (">", ">>")) or
    (process.args : "copy" and process.args : "/b"))
```



### Binary Executed from Shared Memory Directory

Branch count: 8  
Document count: 8  
Index: geneve-ut-181

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
user.id == "0" and process.executable : ("/dev/shm/*", "/run/shm/*", "/var/run/*", "/var/lock/*") and
not process.executable : ("/var/run/docker/*", "/var/run/utsns/*", "/var/run/s6/*", "/var/run/cloudera-scm-agent/*", 
"/var/run/argo/argoexec") and not process.parent.command_line : "/usr/bin/runc init"
```



### Bitsadmin Activity

Branch count: 13  
Document count: 13  
Index: geneve-ut-182

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
Index: geneve-ut-183

```python
file where host.os.type == "windows" and event.action : "creation" and 
(
  /* Firefox-Based Browsers */
  (
    file.name : "*.xpi" and
    file.path : "?:\\Users\\*\\AppData\\Roaming\\*\\Profiles\\*\\Extensions\\*.xpi" and
    not 
    (
      process.name : "firefox.exe" and
      file.name : ("langpack-*@firefox.mozilla.org.xpi", "*@dictionaries.addons.mozilla.org.xpi")
    )
  ) or
  /* Chromium-Based Browsers */
  (
    file.name : "*.crx" and
    file.path : "?:\\Users\\*\\AppData\\Local\\*\\*\\User Data\\Webstore Downloads\\*"
  )
)
```



### Bypass UAC via Event Viewer

Branch count: 1  
Document count: 1  
Index: geneve-ut-184

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "eventvwr.exe" and
  not process.executable :
            ("?:\\Windows\\SysWOW64\\mmc.exe",
             "?:\\Windows\\System32\\mmc.exe",
             "?:\\Windows\\SysWOW64\\WerFault.exe",
             "?:\\Windows\\System32\\WerFault.exe")
```



### Chkconfig Service Add

Branch count: 4  
Document count: 4  
Index: geneve-ut-186

```python
process where host.os.type == "linux" and event.action in ("exec", "exec_event") and
( 
  (process.executable : "/usr/sbin/chkconfig" and process.args : "--add") or
  (process.args : "*chkconfig" and process.args : "--add")
) and 
not process.parent.name in ("rpm", "qualys-scan-util", "qualys-cloud-agent", "update-alternatives") and
not process.parent.args : ("/var/tmp/rpm*", "/var/lib/waagent/*")
```



### Clearing Windows Console History

Branch count: 24  
Document count: 24  
Index: geneve-ut-187

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or ?process.pe.original_file_name == "PowerShell.EXE") and
     (process.args : "*Clear-History*" or
     (process.args : ("*Remove-Item*", "rm") and process.args : ("*ConsoleHost_history.txt*", "*(Get-PSReadlineOption).HistorySavePath*")) or
     (process.args : "*Set-PSReadlineOption*" and process.args : "*SaveNothing*"))
```



### Clearing Windows Event Logs

Branch count: 9  
Document count: 9  
Index: geneve-ut-188

```python
process where host.os.type == "windows" and event.type == "start" and
(
  (
    (process.name : "wevtutil.exe" or ?process.pe.original_file_name == "wevtutil.exe") and
    process.args : ("/e:false", "cl", "clear-log")
  ) or
  (
    process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and
    process.args : "Clear-EventLog"
  )
)
```



### Code Signing Policy Modification Through Built-in tools

Branch count: 16  
Document count: 16  
Index: geneve-ut-190

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name: "bcdedit.exe" or ?process.pe.original_file_name == "bcdedit.exe") and process.args: ("-set", "/set") and 
  process.args: ("TESTSIGNING", "nointegritychecks", "loadoptions", "DISABLE_INTEGRITY_CHECKS")
```



### Code Signing Policy Modification Through Registry

Branch count: 24  
Document count: 24  
Index: geneve-ut-191

```python
registry where host.os.type == "windows" and event.type : ("creation", "change") and
(
  registry.path : (
    "HKEY_USERS\\*\\Software\\Policies\\Microsoft\\Windows NT\\Driver Signing\\BehaviorOnFailedVerify",
    "HKU\\*\\Software\\Policies\\Microsoft\\Windows NT\\Driver Signing\\BehaviorOnFailedVerify",
    "\\REGISTRY\\USER\\*\\Software\\Policies\\Microsoft\\Windows NT\\Driver Signing\\BehaviorOnFailedVerify"
  ) and
  registry.value: "BehaviorOnFailedVerify" and
  registry.data.strings : ("0", "0x00000000", "1", "0x00000001")
)
```



### Command Execution via SolarWinds Process

Branch count: 12  
Document count: 12  
Index: geneve-ut-192

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
Index: geneve-ut-193

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
Index: geneve-ut-194

```python
process where host.os.type == "windows" and event.type == "start" and
 process.name : ("cmd.exe", "powershell.exe") and
  process.parent.name : "rundll32.exe" and process.parent.command_line != null and
  /* common FPs can be added here */
  not process.parent.args : ("C:\\Windows\\System32\\SHELL32.dll,RunAsNewUser_RunDLL",
                             "C:\\WINDOWS\\*.tmp,zzzzInvokeManagedCustomActionOutOfProc")
```



### Component Object Model Hijacking

Branch count: 54  
Document count: 54  
Index: geneve-ut-195

```python
registry where host.os.type == "windows" and
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
        "HKEY_USERS\\*\\ScriptletURL*"
      )  
    )
  ) and 

      not  (
            process.code_signature.trusted == true and
            process.code_signature.subject_name in 
                         ("Island Technology Inc.", "Google LLC", "Grammarly, Inc.", "Dropbox, Inc", "REFINITIV US LLC", "HP Inc.",
                          "Citrix Systems, Inc.", "Adobe Inc.", "Veeam Software Group GmbH", "Zhuhai Kingsoft Office Software Co., Ltd.",
                          "Oracle America, Inc.")
        ) and 

  /* excludes Microsoft signed noisy processes */
  not
  (
    process.name : ("OneDrive.exe", "OneDriveSetup.exe", "FileSyncConfig.exe", "Teams.exe", "MicrosoftEdgeUpdate.exe", "msrdcw.exe", "MicrosoftEdgeUpdateComRegisterShell64.exe") and
    process.code_signature.trusted == true and process.code_signature.subject_name in ("Microsoft Windows", "Microsoft Corporation")
  ) and

  not process.executable : 
                  ("?:\\Program Files (x86)\\*.exe", 
                   "?:\\Program Files\\*.exe",
                   "?:\\Windows\\System32\\svchost.exe", 
                   "?:\\Windows\\System32\\msiexec.exe", 
                   "?:\\Windows\\SysWOW64\\regsvr32.exe",
                   "?:\\Windows\\System32\\regsvr32.exe",
                   "?:\\Windows\\System32\\DriverStore\\FileRepository\\*.exe", 
                   "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe")
```



### Compression DLL Loaded by Unusual Process

Branch count: 12  
Document count: 12  
Index: geneve-ut-196

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
Index: geneve-ut-198

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

Branch count: 1  
Document count: 2  
Index: geneve-ut-200

```python
sequence by process.entity_id
  [process where host.os.type == "linux" and process.name == "telnet" and event.type == "start"]
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

Branch count: 1  
Document count: 2  
Index: geneve-ut-201

```python
sequence by process.entity_id
  [process where host.os.type == "linux" and process.name == "telnet" and event.type == "start"]
  [network where host.os.type == "linux" and process.name == "telnet" and cidrmatch(
     destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
     "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
     "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
     "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
     "FF00::/8"
    )
  ]
```



### Container Management Utility Run Inside A Container

Branch count: 9  
Document count: 9  
Index: geneve-ut-202

```python
process where container.id: "*" and event.type== "start" 
  and process.name: ("dockerd", "docker", "kubelet", "kube-proxy", "kubectl", "containerd", "runc", "systemd", "crictl")
```



### Container Workload Protection

Branch count: 1  
Document count: 1  
Index: geneve-ut-203

```python
event.kind:alert and event.module:cloud_defend
```



### Control Panel Process with Unusual Arguments

Branch count: 24  
Document count: 24  
Index: geneve-ut-204

```python
process where host.os.type == "windows" and event.type == "start" and
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
Index: geneve-ut-206

```python
file where host.os.type == "macos" and event.type != "deletion" and
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
Index: geneve-ut-207

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name : "osascript" and
 process.command_line : "osascript*login item*hidden:true*"
```



### Creation of Hidden Shared Object File

Branch count: 1  
Document count: 1  
Index: geneve-ut-208

```python
file where host.os.type == "linux" and event.type == "creation" and file.extension == "so" and file.name : ".*.so" and
not process.name == "dockerd"
```



### Creation of Kernel Module

Branch count: 2  
Document count: 2  
Index: geneve-ut-209

```python
file where host.os.type == "linux" and event.type in ("change", "creation") and file.path : "/lib/modules/*" and
file.extension == "ko" and not process.name : (
  "dpkg", "systemd", "falcon-sensor*", "dnf", "yum", "rpm", "cp"
)
```



### Creation of SettingContent-ms Files

Branch count: 1  
Document count: 1  
Index: geneve-ut-210

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
Index: geneve-ut-211

```python
any where host.os.type == "windows" and event.action == "Directory Service Changes" and
    event.code == "5137" and winlog.event_data.ObjectClass == "dnsNode" and
    not winlog.event_data.SubjectUserName : "*$"
```



### Creation of a Hidden Local User Account

Branch count: 2  
Document count: 2  
Index: geneve-ut-212

```python
registry where host.os.type == "windows" and registry.path : (
    "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\*$\\",
    "\\REGISTRY\\MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\*$\\"
)
```



### Creation or Modification of Domain Backup DPAPI private key

Branch count: 2  
Document count: 2  
Index: geneve-ut-213

```python
file where host.os.type == "windows" and event.type != "deletion" and file.name : ("ntds_capi_*.pfx", "ntds_capi_*.pvk")
```



### Creation or Modification of Root Certificate

Branch count: 16  
Document count: 16  
Index: geneve-ut-215

```python
registry where host.os.type == "windows" and event.type in ("creation", "change") and
  registry.path :
    (
      "HKLM\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "HKLM\\Software\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "HKLM\\Software\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "HKLM\\Software\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "\\REGISTRY\\MACHINE\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "\\REGISTRY\\MACHINE\\Software\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob",
      "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\*\\Blob",
      "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates\\*\\Blob"
    ) and
  not process.executable : (
          "?:\\ProgramData\\Lenovo\\Vantage\\Addins\\LenovoHardwareScanAddin\\*\\LdeApi.Server.exe",
          "?:\\ProgramData\\Logishrd\\LogiOptionsPlus\\Plugins\\64\\certmgr.exe",
          "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
          "?:\\ProgramData\\Quest\\KACE\\modules\\clientidentifier\\clientidentifier.exe",
          "?:\\Program Files (x86)\\*.exe",
          "?:\\Program Files\\*.exe",
          "?:\\Windows\\CCM\\CcmExec.exe",
          "?:\\Windows\\ccmsetup\\cache\\ccmsetup.exe",
          "?:\\Windows\\Cluster\\clussvc.exe",
          "?:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe",
          "?:\\Windows\\Lenovo\\ImController\\PluginHost86\\Lenovo.Modern.ImController.PluginHost.Device.exe",
          "?:\\Windows\\Lenovo\\ImController\\Service\\Lenovo.Modern.ImController.exe",
          "?:\\Windows\\Sysmon.exe",
          "?:\\Windows\\Sysmon64.exe",
          "?:\\Windows\\System32\\*.exe",
          "?:\\Windows\\SysWOW64\\*.exe",
          "?:\\Windows\\UUS\\amd64\\MoUsoCoreWorker.exe",
          "?:\\Windows\\WinSxS\\*.exe"
  )
```



### Creation or Modification of a new GPO Scheduled Task or Service

Branch count: 2  
Document count: 2  
Index: geneve-ut-216

```python
file where host.os.type == "windows" and event.type != "deletion" and
  file.path : ("?:\\Windows\\SYSVOL\\domain\\Policies\\*\\MACHINE\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
               "?:\\Windows\\SYSVOL\\domain\\Policies\\*\\MACHINE\\Preferences\\Services\\Services.xml") and
  not process.name : "dfsrs.exe"
```



### Credential Acquisition via Registry Hive Dumping

Branch count: 8  
Document count: 8  
Index: geneve-ut-217

```python
process where host.os.type == "windows" and event.type == "start" and
 (?process.pe.original_file_name == "reg.exe" or process.name : "reg.exe") and
 process.args : ("save", "export") and
 process.args : ("hklm\\sam", "hklm\\security")
```



### Credential Dumping - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-218

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:cred_theft_event or endgame.event_subtype_full:cred_theft_event)
```



### Credential Dumping - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-219

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:cred_theft_event or endgame.event_subtype_full:cred_theft_event)
```



### Credential Manipulation - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-220

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:token_manipulation_event or endgame.event_subtype_full:token_manipulation_event)
```



### Credential Manipulation - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-221

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:token_manipulation_event or endgame.event_subtype_full:token_manipulation_event)
```



### Cron Job Created or Modified

Branch count: 80  
Document count: 80  
Index: geneve-ut-222

```python
file where host.os.type == "linux" and
event.action in ("rename", "creation") and file.path : (
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
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/local/bin/dockerd"
  ) or
  file.path : "/var/spool/cron/crontabs/tmp.*" or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : ("/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*") or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```



### CyberArk Privileged Access Security Error

Branch count: 1  
Document count: 1  
Index: geneve-ut-223

```python
event.dataset:cyberarkpas.audit and event.type:error
```



### CyberArk Privileged Access Security Recommended Monitor

Branch count: 20  
Document count: 20  
Index: geneve-ut-224

```python
event.dataset:cyberarkpas.audit and
  event.code:(4 or 22 or 24 or 31 or 38 or 57 or 60 or 130 or 295 or 300 or 302 or
              308 or 319 or 344 or 346 or 359 or 361 or 378 or 380 or 411) and
  not event.type:error
```



### DNF Package Manager Plugin File Creation

Branch count: 16  
Document count: 16  
Index: geneve-ut-225

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and
file.path : ("/usr/lib/python*/site-packages/dnf-plugins/*", "/etc/dnf/plugins/*") and not (
  process.executable in (
    "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf", "/usr/bin/microdnf", "/bin/rpm",
    "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum", "/bin/dnf", "/usr/bin/dnf",
    "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet", "/bin/puppet",
    "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client", "/bin/autossl_check",
    "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd",
    "/usr/libexec/netplan/generate"
  ) or
  file.extension in ("swp", "swpx", "swx") or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/*", "/usr/libexec/*",
    "/etc/kernel/*"
  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```



### DNS Global Query Block List Modified or Disabled

Branch count: 3  
Document count: 3  
Index: geneve-ut-226

```python
registry where host.os.type == "windows" and event.type : "change" and
(
  (registry.value : "EnableGlobalQueryBlockList" and registry.data.strings : ("0", "0x00000000")) or
  (registry.value : "GlobalQueryBlockList" and not registry.data.strings : "wpad")
)
```



### DNS-over-HTTPS Enabled via Registry

Branch count: 4  
Document count: 4  
Index: geneve-ut-228

```python
registry where host.os.type == "windows" and event.type in ("creation", "change") and
  (registry.path : "*\\SOFTWARE\\Policies\\Microsoft\\Edge\\BuiltInDnsClientEnabled" and
  registry.data.strings : "1") or
  (registry.path : "*\\SOFTWARE\\Google\\Chrome\\DnsOverHttpsMode" and
  registry.data.strings : "secure") or
  (registry.path : "*\\SOFTWARE\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS" and
  registry.data.strings : "1")
```



### Default Cobalt Strike Team Server Certificate

Branch count: 9  
Document count: 9  
Index: geneve-ut-229

```python
(event.dataset: network_traffic.tls or event.category: (network or network_traffic))
  and (tls.server.hash.md5:950098276A495286EB2A2556FBAB6D83
  or tls.server.hash.sha1:6ECE5ECE4192683D2D84E25B0BA7E04F9CB7EB7C
  or tls.server.hash.sha256:87F2085C32B6A2CC709B365F55873E207A9CAA10BFFECF2FD16D3CF9D94D390C)
```



### Delete Volume USN Journal with Fsutil

Branch count: 2  
Document count: 2  
Index: geneve-ut-231

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "fsutil.exe" or ?process.pe.original_file_name == "fsutil.exe") and
  process.args : "deletejournal" and process.args : "usn"
```



### Deleting Backup Catalogs with Wbadmin

Branch count: 2  
Document count: 2  
Index: geneve-ut-232

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "wbadmin.exe" or ?process.pe.original_file_name == "WBADMIN.EXE") and
  process.args : "catalog" and process.args : "delete"
```



### Disable Windows Event and Security Logs Using Built-in Tools

Branch count: 12  
Document count: 12  
Index: geneve-ut-234

```python
process where host.os.type == "windows" and event.type == "start" and
(
  ((process.name:"logman.exe" or ?process.pe.original_file_name == "Logman.exe") and
      process.args : "EventLog-*" and process.args : ("stop", "delete")) or

  ((process.name : ("pwsh.exe", "powershell.exe", "powershell_ise.exe") or ?process.pe.original_file_name in
      ("pwsh.exe", "powershell.exe", "powershell_ise.exe")) and
	process.args : "Set-Service" and process.args: "EventLog" and process.args : "Disabled")  or

  ((process.name:"auditpol.exe" or ?process.pe.original_file_name == "AUDITPOL.EXE") and process.args : "/success:disable")
)
```



### Disable Windows Firewall Rules via Netsh

Branch count: 2  
Document count: 2  
Index: geneve-ut-235

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "netsh.exe" and
  (
    (process.args : "disable" and process.args : "firewall" and process.args : "set") or
    (process.args : "advfirewall" and process.args : "off" and process.args : "state")
  )
```



### Disabling User Account Control via Registry Modification

Branch count: 12  
Document count: 12  
Index: geneve-ut-236

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.path :
    (
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop",
      "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
      "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin",
      "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop"
    ) and
  registry.data.strings : ("0", "0x00000000")
```



### Disabling Windows Defender Security Settings via PowerShell

Branch count: 24  
Document count: 24  
Index: geneve-ut-237

```python
process where host.os.type == "windows" and event.type == "start" and
  (
    process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or
    ?process.pe.original_file_name in ("powershell.exe", "pwsh.dll", "powershell_ise.exe")
  ) and
  process.args : "Set-MpPreference" and process.args : ("-Disable*", "Disabled", "NeverSend", "-Exclusion*")
```



### Discovery of Domain Groups

Branch count: 12  
Document count: 12  
Index: geneve-ut-238

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and (
  process.name in ("ldapsearch", "dscacheutil") or (process.name == "dscl" and process.args : "*-list*")
)
```



### Domain Added to Google Workspace Trusted Domains

Branch count: 1  
Document count: 1  
Index: geneve-ut-240

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:ADD_TRUSTED_DOMAINS
```



### Dumping Account Hashes via Built-In Commands

Branch count: 4  
Document count: 4  
Index: geneve-ut-243

```python
event.category:process and host.os.type:macos and event.type:start and
 process.name:(defaults or mkpassdb) and process.args:(ShadowHashData or "-dump")
```



### Dumping of Keychain Content via Security Command

Branch count: 2  
Document count: 2  
Index: geneve-ut-244

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.args : "dump-keychain" and process.args : "-d"
```



### Dynamic Linker Copy

Branch count: 10  
Document count: 20  
Index: geneve-ut-245

```python
sequence by process.entity_id with maxspan=1m
[process where host.os.type == "linux" and event.type == "start" and process.name in ("cp", "rsync") and
   process.args in (
     "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/etc/ld.so.preload", "/lib64/ld-linux-x86-64.so.2",
     "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/usr/lib64/ld-linux-x86-64.so.2"
    )]
[file where host.os.type == "linux" and event.action == "creation" and file.extension == "so"]
```



### ESXI Discovery via Find

Branch count: 12  
Document count: 12  
Index: geneve-ut-247

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name == "find" and process.args : ("/etc/vmware/*", "/usr/lib/vmware/*", "/vmfs/*")
```



### ESXI Discovery via Grep

Branch count: 108  
Document count: 108  
Index: geneve-ut-248

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name in ("grep", "egrep", "pgrep") and process.args in (
  "vmdk", "vmx", "vmxf", "vmsd", "vmsn", "vswp", "vmss", "nvram", "vmem"
)
```



### ESXI Timestomping using Touch Command

Branch count: 12  
Document count: 12  
Index: geneve-ut-249

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name == "touch" and process.args == "-r" and
process.args : ("/etc/vmware/*", "/usr/lib/vmware/*", "/vmfs/*")
```



### EggShell Backdoor Execution

Branch count: 2  
Document count: 2  
Index: geneve-ut-250

```python
event.category:process and event.type:(process_started or start) and process.name:espl and process.args:eyJkZWJ1ZyI6*
```



### Elastic Agent Service Terminated

Branch count: 201  
Document count: 201  
Index: geneve-ut-251

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
  /* pkill , killall used to stop Elastic Agent on Linux */
  ( event.type == "end" and process.name : ("pkill", "killall") and process.args: "elastic-agent")
  or
  /* Unload Elastic Agent extension on MacOS */
  (process.name : "kextunload" and
    process.args : "com.apple.iokit.EndpointSecurity" and
    event.action : "end"))
```



### Emond Rules Creation or Modification

Branch count: 3  
Document count: 3  
Index: geneve-ut-252

```python
file where host.os.type == "macos" and event.type != "deletion" and
 file.path : ("/private/etc/emond.d/rules/*.plist", "/etc/emon.d/rules/*.plist", "/private/var/db/emondClients/*")
```



### Enable Host Network Discovery via Netsh

Branch count: 2  
Document count: 2  
Index: geneve-ut-253

```python
process where host.os.type == "windows" and event.type == "start" and
process.name : "netsh.exe" and
process.args : ("firewall", "advfirewall") and process.args : "group=Network Discovery" and process.args : "enable=Yes"
```



### Encoded Executable Stored in the Registry

Branch count: 1  
Document count: 1  
Index: geneve-ut-254

```python
registry where host.os.type == "windows" and
/* update here with encoding combinations */
 registry.data.strings : "TVqQAAMAAAAEAAAA*"
```



### Encrypting Files with WinRar or 7z

Branch count: 14  
Document count: 14  
Index: geneve-ut-255

```python
process where host.os.type == "windows" and event.type == "start" and
(
  (
    (
      process.name:"rar.exe" or ?process.code_signature.subject_name == "win.rar GmbH" or
      ?process.pe.original_file_name == "Command line RAR"
    ) and
    process.args == "a" and process.args : ("-hp*", "-p*", "/hp*", "/p*")
  ) or
  (
    ?process.pe.original_file_name in ("7z.exe", "7za.exe") and
    process.args == "a" and process.args : "-p*"
  )
) and
  not process.parent.executable : (
        "C:\\Program Files\\*.exe",
        "C:\\Program Files (x86)\\*.exe",
        "?:\\ManageEngine\\*\\jre\\bin\\java.exe",
        "?:\\Nox\\bin\\Nox.exe"
      )
```



### Endpoint Security

Branch count: 1  
Document count: 1  
Index: geneve-ut-256

```python
event.kind:alert and event.module:(endpoint and not endgame)
```



### Enumerating Domain Trusts via DSQUERY.EXE

Branch count: 2  
Document count: 2  
Index: geneve-ut-257

```python
process where host.os.type == "windows" and event.type == "start" and
    (process.name : "dsquery.exe" or ?process.pe.original_file_name: "dsquery.exe") and 
    process.args : "*objectClass=trustedDomain*"
```



### Enumerating Domain Trusts via NLTEST.EXE

Branch count: 7  
Document count: 7  
Index: geneve-ut-258

```python
process where host.os.type == "windows" and event.type == "start" and
    process.name : "nltest.exe" and process.args : (
        "/DCLIST:*", "/DCNAME:*", "/DSGET*",
        "/LSAQUERYFTI:*", "/PARENTDOMAIN",
        "/DOMAIN_TRUSTS", "/BDC_QUERY:*"
        ) and 
not process.parent.name : "PDQInventoryScanner.exe" and 
not user.id in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
```



### Enumeration of Administrator Accounts

Branch count: 64  
Document count: 64  
Index: geneve-ut-260

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
Index: geneve-ut-264

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  (
    process.name : ("ldapsearch", "dsmemberutil") or
    (process.name : "dscl" and
      process.args : ("read", "-read", "list", "-list", "ls", "search", "-search") and
      process.args : ("/Active Directory/*", "/Users*", "/Groups*"))
	) and
  ((process.Ext.effective_parent.executable : ("/Volumes/*", "/Applications/*") or process.parent.executable : ("/Volumes/*", "/Applications/*")) or
   (process.Ext.effective_parent.name : ".*" or process.parent.name : ".*")) and
  not process.Ext.effective_parent.executable : ("/Applications/QualysCloudAgent.app/Contents/MacOS/qualys-cloud-agent",
                                                 "/Applications/Kaspersky Anti-Virus For Mac.app/Contents/MacOS/kavd.app/Contents/MacOS/kavd",
                                                 "/Applications/ESET Endpoint Security.app/Contents/MacOS/esets_ctl",
                                                 "/Applications/NordVPN.app/Contents/MacOS/NordVPN",
                                                 "/Applications/Xcode.app/Contents/MacOS/Xcode",
                                                 "/Applications/ESET Endpoint Security.app/Contents/Helpers/Uninstaller.app/Contents/MacOS/Uninstaller",
                                                 "/Applications/Parallels Desktop.app/Contents/MacOS/prl_client_app",
                                                 "/Applications/Zscaler/Zscaler.app/Contents/MacOS/Zscaler",
                                                 "/Applications/com.avast.av.uninstaller.app/Contents/MacOS/com.avast.av.uninstaller",
                                                 "/Applications/NoMAD.app/Contents/MacOS/NoMAD",
                                                 "/Applications/ESET Management Agent.app/Contents/MacOS/ERAAgent")
```



### Exchange Mailbox Export via PowerShell

Branch count: 1  
Document count: 1  
Index: geneve-ut-265

```python
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : "New-MailboxExportRequest"
```



### Executable Bit Set for Potential Persistence Script

Branch count: 360  
Document count: 360  
Index: geneve-ut-266

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
process.args : (
  // Misc.
  "/etc/rc.local", "/etc/rc.common", "/etc/init.d/*", "/etc/update-motd.d/*", "/etc/apt/apt.conf.d/*", "/etc/cron*",
  "/etc/init/*",

  // XDG
  "/etc/xdg/autostart/*", "/home/*/.config/autostart/*", "/root/.config/autostart/*",
  "/home/*/.local/share/autostart/*", "/root/.local/share/autostart/*", "/home/*/.config/autostart-scripts/*",
  "/root/.config/autostart-scripts/*", "/etc/xdg/autostart/*", "/usr/share/autostart/*",

  // udev
  "/lib/udev/*", "/etc/udev/rules.d/*", "/usr/lib/udev/rules.d/*", "/run/udev/rules.d/*"

) and (
  (process.name == "chmod" and process.args : ("+x*", "1*", "3*", "5*", "7*")) or
  (process.name == "install" and process.args : "-m*" and process.args : ("7*", "5*", "3*", "1*"))
) and not process.parent.executable : "/var/lib/dpkg/*"
```



### Executable File with Unusual Extension

Branch count: 64  
Document count: 64  
Index: geneve-ut-268

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

Branch count: 4  
Document count: 4  
Index: geneve-ut-269

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
process.name : ("kworker*", "kthread*") and process.executable != null
```



### Execution from a Removable Media with Network Connection

Branch count: 4  
Document count: 8  
Index: geneve-ut-271

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
Index: geneve-ut-272

```python
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "xwizard.exe" or ?process.pe.original_file_name : "xwizard.exe") and
 (
   (process.args : "RunWizard" and process.args : "{*}") or
   (process.executable != null and
     not process.executable : ("C:\\Windows\\SysWOW64\\xwizard.exe", "C:\\Windows\\System32\\xwizard.exe")
   )
 )
```



### Execution of File Written or Modified by Microsoft Office

Branch count: 24  
Document count: 48  
Index: geneve-ut-273

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
   not (process.name : "NewOutlookInstaller.exe" and process.code_signature.subject_name : "Microsoft Corporation" and process.code_signature.trusted == true)
  ] by host.id, process.executable
```



### Execution of File Written or Modified by PDF Reader

Branch count: 4  
Document count: 8  
Index: geneve-ut-274

```python
sequence with maxspan=2h
  [file where host.os.type == "windows" and event.type != "deletion" and file.extension : "exe" and
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
  [process where host.os.type == "windows" and event.type == "start"] by host.id, process.executable
```



### Execution of Persistent Suspicious Program

Branch count: 54  
Document count: 162  
Index: geneve-ut-275

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
Index: geneve-ut-277

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and process.args:("-e" and const*require*child_process*)
```



### Execution via MSSQL xp_cmdshell Stored Procedure

Branch count: 7  
Document count: 7  
Index: geneve-ut-279

```python
process where host.os.type == "windows" and event.type == "start" and process.parent.name : "sqlservr.exe" and 
  (
   (process.name : "cmd.exe" and 
    not process.args : ("\\\\*", "diskfree", "rmdir", "mkdir", "dir", "del", "rename", "bcp", "*XMLNAMESPACES*", 
                        "?:\\MSSQL\\Backup\\Jobs\\sql_agent_backup_job.ps1", "K:\\MSSQL\\Backup\\msdb", "K:\\MSSQL\\Backup\\Logins")) or 

   (process.name : "vpnbridge.exe" or ?process.pe.original_file_name : "vpnbridge.exe") or 

   (process.name : "certutil.exe" or ?process.pe.original_file_name == "CertUtil.exe") or 

   (process.name : "bitsadmin.exe" or ?process.pe.original_file_name == "bitsadmin.exe")
  )
```



### Execution via Microsoft DotNet ClickOnce Host

Branch count: 2  
Document count: 4  
Index: geneve-ut-280

```python
sequence by user.id with maxspan=5s
 [process where host.os.type == "windows" and event.action == "start" and
  process.name : "rundll32.exe" and process.command_line : ("*dfshim*ShOpenVerbApplication*", "*dfshim*#*")]
 [network where host.os.type == "windows" and process.name : "dfsvc.exe"]
```



### Execution via TSClient Mountpoint

Branch count: 1  
Document count: 1  
Index: geneve-ut-281

```python
process where host.os.type == "windows" and event.type == "start" and process.executable : "\\Device\\Mup\\tsclient\\*.exe"
```



### Execution via Windows Subsystem for Linux

Branch count: 2  
Document count: 2  
Index: geneve-ut-282

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
        "?:\\Windows\\Sys*\\wslconfig.exe"
  )
```



### Execution via local SxS Shared Module

Branch count: 1  
Document count: 1  
Index: geneve-ut-283

```python
file where host.os.type == "windows" and file.extension : "dll" and file.path : "C:\\*\\*.exe.local\\*.dll"
```



### Execution with Explicit Credentials via Scripting

Branch count: 24  
Document count: 24  
Index: geneve-ut-284

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:"security_authtrampoline" and
 process.parent.name:(osascript or com.apple.automator.runner or sh or bash or dash or zsh or python* or Python or perl* or php* or ruby or pwsh)
```



### Expired or Revoked Driver Loaded

Branch count: 2  
Document count: 2  
Index: geneve-ut-285

```python
driver where host.os.type == "windows" and process.pid == 4 and
  dll.code_signature.status : ("errorExpired", "errorRevoked")
```



### Exploit - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-286

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:exploit_event or endgame.event_subtype_full:exploit_event)
```



### Exploit - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-287

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:exploit_event or endgame.event_subtype_full:exploit_event)
```



### Exporting Exchange Mailbox via PowerShell

Branch count: 6  
Document count: 6  
Index: geneve-ut-288

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and
  process.command_line : ("*MailboxExportRequest*", "*-Mailbox*-ContentFilter*")
```



### External Alerts

Branch count: 1  
Document count: 1  
Index: geneve-ut-289

```python
event.kind:alert and not event.module:(endgame or endpoint or cloud_defend)
```



### File Creation Time Changed

Branch count: 1  
Document count: 1  
Index: geneve-ut-293

```python
file where host.os.type == "windows" and event.code : "2" and

 /* Requires Sysmon EventID 2 - File creation time change */
 event.action : "File creation time changed*" and 

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



### File Deletion via Shred

Branch count: 4  
Document count: 4  
Index: geneve-ut-295

```python
process where host.os.type == "linux" and event.type == "start" and process.name == "shred" and process.args in (
  "-u", "--remove", "-z", "--zero"
) and not process.parent.name == "logrotate"
```



### File Made Executable via Chmod Inside A Container

Branch count: 20  
Document count: 20  
Index: geneve-ut-296

```python
file where container.id: "*" and event.type in ("change", "creation") and

/*account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg*/
(process.name : "chmod" or process.args : "chmod") and 
process.args : ("*x*", "777", "755", "754", "700") and not process.args: "-x"
```



### File Staged in Root Folder of Recycle Bin

Branch count: 1  
Document count: 1  
Index: geneve-ut-298

```python
file where host.os.type == "windows" and event.type == "creation" and
  file.path : "?:\\$RECYCLE.BIN\\*" and
  not file.path : "?:\\$RECYCLE.BIN\\*\\*" and
  not file.name : "desktop.ini"
```



### File System Debugger Launched Inside a Privileged Container

Branch count: 1  
Document count: 1  
Index: geneve-ut-299

```python
process where event.module == "cloud_defend" and     
  event.type == "start" and process.name == "debugfs" and 
  process.args : "/dev/sd*" and not process.args == "-R" and
  container.security_context.privileged == true
```



### File Transfer or Listener Established via Netcat

Branch count: 375  
Document count: 750  
Index: geneve-ut-300

```python
sequence by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and
      process.name:("nc","ncat","netcat","netcat.openbsd","netcat.traditional") and (
          /* bind shell to echo for command execution */
          (process.args:("-l","-p") and process.args:("-c","echo","$*"))
          /* bind shell to specific port */
          or process.args:("-l","-p","-lp")
          /* reverse shell to command-line interpreter used for command execution */
          or (process.args:("-e") and process.args:("/bin/bash","/bin/sh"))
          /* file transfer via stdout */
          or process.args:(">","<")
          /* file transfer via pipe */
          or (process.args:("|") and process.args:("nc","ncat"))
      )]
  [network where host.os.type == "linux" and (process.name == "nc" or process.name == "ncat" or process.name == "netcat" or
                  process.name == "netcat.openbsd" or process.name == "netcat.traditional")]
```



### File and Directory Permissions Modification

Branch count: 16  
Document count: 16  
Index: geneve-ut-301

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

Branch count: 2  
Document count: 2  
Index: geneve-ut-302

```python
process where host.os.type == "linux" and event.type == "start" and user.id == "0" and
  process.executable : "/usr/bin/chattr" and process.args : ("-*i*", "+*i*") and
  not process.parent.executable: ("/lib/systemd/systemd", "/usr/local/uems_agent/bin/*", "/usr/lib/systemd/systemd") and
  not process.parent.name in ("systemd", "cf-agent", "ntpdate", "xargs", "px", "preinst", "auth")
```



### File or Directory Deletion Command

Branch count: 11  
Document count: 11  
Index: geneve-ut-303

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



### Finder Sync Plugin Registered and Enabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-305

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name : "pluginkit" and
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
  ) and
  not process.parent.executable : ("/Library/Application Support/IDriveforMac/IDriveHelperTools/FinderPluginApp.app/Contents/MacOS/FinderPluginApp",
                                   "/Applications/Google Drive.app/Contents/MacOS/Google Drive") and
  not process.Ext.effective_parent.executable : ("/Applications/Google Drive.app/Contents/MacOS/Google Drive",
                                                 "/usr/local/jamf/bin/jamf",
                                                 "/Applications/Nextcloud.app/Contents/MacOS/Nextcloud",
                                                 "/Library/Application Support/Checkpoint/Endpoint Security/AMFinderExtensions.app/Contents/MacOS/AMFinderExtensions",
                                                 "/Applications/pCloud Drive.app/Contents/MacOS/pCloud Drive")
```



### Forwarded Google Workspace Security Alert

Branch count: 1  
Document count: 1  
Index: geneve-ut-323

```python
event.dataset: google_workspace.alert
```



### Full User-Mode Dumps Enabled System-Wide

Branch count: 8  
Document count: 8  
Index: geneve-ut-324

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
Index: geneve-ut-325

```python
event.dataset:gcp.audit and event.action:(*.compute.firewalls.insert or google.appengine.*.Firewall.Create*Rule)
```



### GCP Firewall Rule Deletion

Branch count: 2  
Document count: 2  
Index: geneve-ut-326

```python
event.dataset:gcp.audit and event.action:(*.compute.firewalls.delete or google.appengine.*.Firewall.Delete*Rule)
```



### GCP Firewall Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-327

```python
event.dataset:gcp.audit and event.action:(*.compute.firewalls.patch or google.appengine.*.Firewall.Update*Rule)
```



### GCP IAM Custom Role Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-328

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.CreateRole and event.outcome:success
```



### GCP IAM Role Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-329

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DeleteRole and event.outcome:success
```



### GCP IAM Service Account Key Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-330

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DeleteServiceAccountKey and event.outcome:success
```



### GCP Logging Bucket Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-331

```python
event.dataset:gcp.audit and event.action:google.logging.v*.ConfigServiceV*.DeleteBucket and event.outcome:success
```



### GCP Logging Sink Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-332

```python
event.dataset:gcp.audit and event.action:google.logging.v*.ConfigServiceV*.DeleteSink and event.outcome:success
```



### GCP Logging Sink Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-333

```python
event.dataset:gcp.audit and event.action:google.logging.v*.ConfigServiceV*.UpdateSink and event.outcome:success
```



### GCP Pub/Sub Subscription Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-334

```python
event.dataset:gcp.audit and event.action:google.pubsub.v*.Subscriber.CreateSubscription and event.outcome:success
```



### GCP Pub/Sub Subscription Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-335

```python
event.dataset:gcp.audit and event.action:google.pubsub.v*.Subscriber.DeleteSubscription and event.outcome:success
```



### GCP Pub/Sub Topic Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-336

```python
event.dataset:gcp.audit and event.action:google.pubsub.v*.Publisher.CreateTopic and event.outcome:success
```



### GCP Pub/Sub Topic Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-337

```python
event.dataset:gcp.audit and event.action:google.pubsub.v*.Publisher.DeleteTopic and event.outcome:success
```



### GCP Service Account Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-338

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.CreateServiceAccount and event.outcome:success
```



### GCP Service Account Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-339

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DeleteServiceAccount and event.outcome:success
```



### GCP Service Account Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-340

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DisableServiceAccount and event.outcome:success
```



### GCP Service Account Key Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-341

```python
event.dataset:gcp.audit and event.action:google.iam.admin.v*.CreateServiceAccountKey and event.outcome:success
```



### GCP Storage Bucket Configuration Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-342

```python
event.dataset:gcp.audit and event.action:"storage.buckets.update" and event.outcome:success
```



### GCP Storage Bucket Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-343

```python
event.dataset:gcp.audit and event.action:"storage.buckets.delete"
```



### GCP Storage Bucket Permissions Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-344

```python
event.dataset:gcp.audit and event.action:"storage.setIamPermissions" and event.outcome:success
```



### GCP Virtual Private Cloud Network Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-345

```python
event.dataset:gcp.audit and event.action:v*.compute.networks.delete and event.outcome:success
```



### GCP Virtual Private Cloud Route Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-346

```python
event.dataset:gcp.audit and event.action:(v*.compute.routes.insert or "beta.compute.routes.insert")
```



### GCP Virtual Private Cloud Route Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-347

```python
event.dataset:gcp.audit and event.action:v*.compute.routes.delete and event.outcome:success
```



### Git Hook Child Process

Branch count: 575  
Document count: 575  
Index: geneve-ut-348

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.name in (
  "applypatch-msg", "commit-msg", "fsmonitor-watchman", "post-update", "post-checkout", "post-commit",
  "pre-applypatch", "pre-commit", "pre-merge-commit", "prepare-commit-msg", "pre-push", "pre-rebase", "pre-receive",
  "push-to-checkout", "update", "post-receive", "pre-auto-gc", "post-rewrite", "sendemail-validate", "p4-pre-submit",
  "post-index-change", "post-merge", "post-applypatch"
) and (
  process.name in ("nohup", "setsid", "disown", "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") or 
  process.name : ("php*", "perl*", "ruby*", "lua*") or 
  process.executable : (
    "/boot/*", "/dev/shm/*", "/etc/cron.*/*", "/etc/init.d/*", "/etc/update-motd.d/*",
    "/run/*", "/srv/*", "/tmp/*", "/var/tmp/*", "/var/log/*"
  )
) and not process.name in ("git", "dirname")
```



### Git Hook Created or Modified

Branch count: 4  
Document count: 4  
Index: geneve-ut-349

```python
file where host.os.type == "linux" and event.type == "creation" and file.path : "*.git/hooks/*" and
file.extension == null and process.executable != null and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/usr/bin/pamac-daemon", "/bin/pamac-daemon",
    "/usr/local/bin/dockerd", "/sbin/dockerd"
  ) or
  process.executable : ("/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*") or
  process.name in ("git", "dirname") or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```



### GitHub App Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-350

```python
configuration where event.dataset == "github.audit" and github.category == "integration_installation" and event.type == "deletion"
```



### GitHub Owner Role Granted To User

Branch count: 1  
Document count: 1  
Index: geneve-ut-351

```python
iam where event.dataset == "github.audit" and event.action == "org.update_member" and github.permission == "admin"
```



### GitHub PAT Access Revoked

Branch count: 1  
Document count: 1  
Index: geneve-ut-352

```python
configuration where event.dataset == "github.audit" and event.action == "personal_access_token.access_revoked"
```



### GitHub Protected Branch Settings Changed

Branch count: 1  
Document count: 1  
Index: geneve-ut-353

```python
configuration where event.dataset == "github.audit" 
  and github.category == "protected_branch" and event.type == "change"
```



### GitHub Repo Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-354

```python
configuration where event.dataset == "github.audit" and event.action == "repo.create"
```



### GitHub Repository Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-355

```python
configuration where event.module == "github" and event.action == "repo.destroy"
```



### GitHub User Blocked From Organization

Branch count: 1  
Document count: 1  
Index: geneve-ut-357

```python
configuration where event.dataset == "github.audit" and event.action == "org.block_user"
```



### Google Drive Ownership Transferred via Google Workspace

Branch count: 1  
Document count: 1  
Index: geneve-ut-358

```python
event.dataset:"google_workspace.admin" and event.action:"CREATE_DATA_TRANSFER_REQUEST"
  and event.category:"iam" and google_workspace.admin.application.name:Drive*
```



### Google Workspace 2SV Policy Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-359

```python
event.dataset:"google_workspace.login" and event.action:"2sv_disable"
```



### Google Workspace API Access Granted via Domain-Wide Delegation of Authority

Branch count: 1  
Document count: 1  
Index: geneve-ut-360

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:AUTHORIZE_API_CLIENT_ACCESS
```



### Google Workspace Admin Role Assigned to a User

Branch count: 1  
Document count: 1  
Index: geneve-ut-361

```python
event.dataset:"google_workspace.admin" and event.category:"iam" and event.action:"ASSIGN_ROLE"
  and google_workspace.event.type:"DELEGATED_ADMIN_SETTINGS" and google_workspace.admin.role.name : *_ADMIN_ROLE
```



### Google Workspace Admin Role Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-362

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:DELETE_ROLE
```



### Google Workspace Bitlocker Setting Disabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-363

```python
event.dataset:"google_workspace.admin" and event.action:"CHANGE_APPLICATION_SETTING" and event.category:(iam or configuration)
    and google_workspace.admin.new_value:"Disabled" and google_workspace.admin.setting.name:BitLocker*
```



### Google Workspace Custom Admin Role Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-364

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:CREATE_ROLE
```



### Google Workspace Custom Gmail Route Created or Modified

Branch count: 4  
Document count: 4  
Index: geneve-ut-365

```python
event.dataset:"google_workspace.admin" and event.action:("CREATE_GMAIL_SETTING" or "CHANGE_GMAIL_SETTING")
  and google_workspace.event.type:"EMAIL_SETTINGS" and google_workspace.admin.setting.name:("EMAIL_ROUTE" or "MESSAGE_SECURITY_RULE")
```



### Google Workspace Drive Encryption Key(s) Accessed from Anonymous User

Branch count: 105  
Document count: 105  
Index: geneve-ut-366

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
Index: geneve-ut-367

```python
event.dataset:google_workspace.admin and event.provider:admin
  and event.category:iam and event.action:ENFORCE_STRONG_AUTHENTICATION
  and google_workspace.admin.new_value:false
```



### Google Workspace Object Copied from External Drive and Access Granted to Custom Application

Branch count: 4  
Document count: 8  
Index: geneve-ut-368

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
Index: geneve-ut-369

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



### Google Workspace Restrictions for Google Marketplace Modified to Allow Any App

Branch count: 2  
Document count: 2  
Index: geneve-ut-370

```python
event.dataset:"google_workspace.admin" and event.action:"CHANGE_APPLICATION_SETTING" and event.category:(iam or configuration)
    and google_workspace.event.type:"APPLICATION_SETTINGS" and google_workspace.admin.application.name:"Google Workspace Marketplace"
        and google_workspace.admin.setting.name:"Apps Access Setting Allowlist access"  and google_workspace.admin.new_value:"ALLOW_ALL"
```



### Google Workspace Role Modified

Branch count: 2  
Document count: 2  
Index: geneve-ut-371

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:(ADD_PRIVILEGE or UPDATE_ROLE)
```



### Google Workspace Suspended User Account Renewed

Branch count: 1  
Document count: 1  
Index: geneve-ut-372

```python
event.dataset:google_workspace.admin and event.category:iam and event.action:UNSUSPEND_USER
```



### Google Workspace User Organizational Unit Changed

Branch count: 1  
Document count: 1  
Index: geneve-ut-373

```python
event.dataset:"google_workspace.admin" and event.type:change and event.category:iam
    and google_workspace.event.type:"USER_SETTINGS" and event.action:"MOVE_USER_TO_ORG_UNIT"
```



### Group Policy Discovery via Microsoft GPResult Utility

Branch count: 8  
Document count: 8  
Index: geneve-ut-375

```python
process where host.os.type == "windows" and event.type == "start" and
(process.name: "gpresult.exe" or ?process.pe.original_file_name == "gprslt.exe") and process.args: ("/z", "/v", "/r", "/x")
```



### Hidden Files and Directories via Hidden Flag

Branch count: 1  
Document count: 1  
Index: geneve-ut-377

```python
file where event.type == "creation" and process.name == "chflags"
```



### Host Files System Changes via Windows Subsystem for Linux

Branch count: 1  
Document count: 2  
Index: geneve-ut-386

```python
sequence by process.entity_id with maxspan=5m
 [process where host.os.type == "windows" and event.type == "start" and
  process.name : "dllhost.exe" and 
   /* Plan9FileSystem CLSID - WSL Host File System Worker */
  process.command_line : "*{DFB65C4C-B34F-435D-AFE9-A86218684AA8}*"]
 [file where host.os.type == "windows" and process.name : "dllhost.exe" and not file.path : "?:\\Users\\*\\Downloads\\*"]
```



### Hosts File Modified

Branch count: 12  
Document count: 12  
Index: geneve-ut-387

```python
any where

  /* file events for creation; file change events are not captured by some of the included sources for linux and so may
     miss this, which is the purpose of the process + command line args logic below */
  (
   event.category == "file" and event.type in ("change", "creation") and
     file.path : ("/private/etc/hosts", "/etc/hosts", "?:\\Windows\\System32\\drivers\\etc\\hosts") and 
     not process.name in ("dockerd", "rootlesskit", "podman", "crio")
  )
  or

  /* process events for change targeting linux only */
  (
   event.category == "process" and event.type in ("start") and
     process.name in ("nano", "vim", "vi", "emacs", "echo", "sed") and
     process.args : ("/etc/hosts") and 
     not process.parent.name in ("dhclient-script", "google_set_hostname")
  )
```



### Hping Process Activity

Branch count: 12  
Document count: 12  
Index: geneve-ut-388

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name in ("hping", "hping2", "hping3")
```



### IIS HTTP Logging Disabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-389

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "appcmd.exe" or ?process.pe.original_file_name == "appcmd.exe") and
  process.args : "/dontLog*:*True" and
  not process.parent.name : "iissetup.exe"
```



### IPSEC NAT Traversal Port Activity

Branch count: 3  
Document count: 3  
Index: geneve-ut-390

```python
(event.dataset: network_traffic.flow or (event.category: (network or network_traffic))) and network.transport:udp and destination.port:4500
```



### ImageLoad via Windows Update Auto Update Client

Branch count: 8  
Document count: 8  
Index: geneve-ut-393

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
Index: geneve-ut-395

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
Index: geneve-ut-396

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
Index: geneve-ut-397

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
Index: geneve-ut-398

```python
sequence by host.id with maxspan = 30s
   [network where host.os.type == "windows" and network.direction : ("incoming", "ingress") and destination.port in (5985, 5986) and
    network.protocol == "http" and source.ip != "127.0.0.1" and source.ip != "::1"]
   [process where host.os.type == "windows" and 
    event.type == "start" and process.parent.name : "wsmprovhost.exe" and not process.executable : "?:\\Windows\\System32\\conhost.exe"]
```



### Incoming Execution via WinRM Remote Shell

Branch count: 4  
Document count: 8  
Index: geneve-ut-399

```python
sequence by host.id with maxspan=30s
   [network where host.os.type == "windows" and process.pid == 4 and network.direction : ("incoming", "ingress") and
    destination.port in (5985, 5986) and network.protocol == "http" and source.ip != "127.0.0.1" and source.ip != "::1"]
   [process where host.os.type == "windows" and 
    event.type == "start" and process.parent.name : "winrshost.exe" and not process.executable : "?:\\Windows\\System32\\conhost.exe"]
```



### Indirect Command Execution via Forfiles/Pcalua

Branch count: 2  
Document count: 2  
Index: geneve-ut-400

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : ("pcalua.exe", "forfiles.exe")
```



### Insecure AWS EC2 VPC Security Group Ingress Rule Added

Branch count: 14  
Document count: 14  
Index: geneve-ut-402

```python
event.dataset: "aws.cloudtrail"
    and event.provider: ec2.amazonaws.com
    and event.action: AuthorizeSecurityGroupIngress
    and event.outcome: success
    and aws.cloudtrail.flattened.request_parameters.cidrIp: ("0.0.0.0/0" or "::/0")
    and aws.cloudtrail.flattened.request_parameters.fromPort: (
        21 or 22 or 23 or 445 or 3389 or 5985 or 5986)
```



### InstallUtil Activity

Branch count: 1  
Document count: 1  
Index: geneve-ut-403

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "installutil.exe" and not user.id : "S-1-5-18"
```



### InstallUtil Process Making Network Connections

Branch count: 2  
Document count: 4  
Index: geneve-ut-404

```python
/* the benefit of doing this as an eql sequence vs kql is this will limit to alerting only on the first network connection */

sequence by process.entity_id
  [process where host.os.type == "windows" and event.type == "start" and process.name : "installutil.exe"]
  [network where host.os.type == "windows" and process.name : "installutil.exe" and network.direction : ("outgoing", "egress")]
```



### Installation of Custom Shim Databases

Branch count: 2  
Document count: 2  
Index: geneve-ut-405

```python
registry where host.os.type == "windows" and event.type in ("creation", "change") and
    registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\*.sdb" and 
    not process.executable : 
                       ("?:\\Program Files (x86)\\DesktopCentral_Agent\\swrepository\\1\\swuploads\\SAP-SLC\\SAPSetupSLC02_14-80001954\\Setup\\NwSapSetup.exe", 
                        "?:\\$WINDOWS.~BT\\Sources\\SetupPlatform.exe", 
                         "?:\\Program Files (x86)\\SAP\\SAPsetup\\setup\\NwSapSetup.exe", 
                         "?:\\Program Files (x86)\\SAP\\SapSetup\\OnRebootSvc\\NWSAPSetupOnRebootInstSvc.exe", 
                         "?:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Security for Windows Server\\kavfs.exe")
```



### Installation of Security Support Provider

Branch count: 4  
Document count: 4  
Index: geneve-ut-406

```python
registry where host.os.type == "windows" and
   registry.path : (
      "HKLM\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Security Packages*",
      "HKLM\\SYSTEM\\*ControlSet*\\Control\\Lsa\\OSConfig\\Security Packages*",
      "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Security Packages*",
      "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Lsa\\OSConfig\\Security Packages*"
   ) and
   not process.executable : ("C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\SysWOW64\\msiexec.exe")
```



### Interactive Exec Command Launched Against A Running Container

Branch count: 1  
Document count: 1  
Index: geneve-ut-407

```python
process where container.id : "*" and event.type== "start" and 

/* use of kubectl exec to enter a container */
process.entry_leader.entry_meta.type : "container" and 

/* process is the inital process run in a container */
process.entry_leader.same_as_process== true and

/* interactive process */
process.interactive == true
```



### Interactive Terminal Spawned via Perl

Branch count: 6  
Document count: 6  
Index: geneve-ut-409

```python
event.category:process and host.os.type:linux and event.type:(start or process_started) and process.name:perl and
  process.args:("exec \"/bin/sh\";" or "exec \"/bin/dash\";" or "exec \"/bin/bash\";")
```



### Interactive Terminal Spawned via Python

Branch count: 36  
Document count: 36  
Index: geneve-ut-410

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
(
  (process.parent.name : "python*" and process.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh",
   "fish") and process.parent.args_count >= 3 and process.parent.args : "*pty.spawn*" and process.parent.args : "-c") or
  (process.parent.name : "python*" and process.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh",
   "fish") and process.args : "*sh" and process.args_count == 1 and process.parent.args_count == 1)
)
```



### KRBTGT Delegation Backdoor

Branch count: 1  
Document count: 1  
Index: geneve-ut-411

```python
event.action:modified-user-account and event.code:4738 and
  winlog.event_data.AllowedToDelegateTo:*krbtgt*
```



### Kerberos Cached Credentials Dumping

Branch count: 2  
Document count: 2  
Index: geneve-ut-412

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and
  process.name:kcc and
  process.args:copy_cred_cache
```



### Kerberos Traffic from Unusual Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-414

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
Index: geneve-ut-415

```python
driver where host.os.type == "linux" and event.action == "loaded-kernel-module" and
auditd.data.syscall in ("init_module", "finit_module")
```



### Kernel Driver Load by non-root User

Branch count: 2  
Document count: 2  
Index: geneve-ut-416

```python
driver where host.os.type == "linux" and event.action == "loaded-kernel-module" and
auditd.data.syscall in ("init_module", "finit_module") and user.id != "0"
```



### Kernel Load or Unload via Kexec Detected

Branch count: 24  
Document count: 24  
Index: geneve-ut-417

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name == "kexec" and process.args in ("--exec", "-e", "--load", "-l", "--unload", "-u")
```



### Kernel Module Load via insmod

Branch count: 1  
Document count: 1  
Index: geneve-ut-418

```python
process where host.os.type == "linux" and event.type == "start" and process.name == "insmod" and process.args : "*.ko"
```



### Kernel Module Removal

Branch count: 22  
Document count: 22  
Index: geneve-ut-419

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
process.name == "rmmod" or (process.name == "modprobe" and process.args in ("--remove", "-r")) and 
process.parent.name in ("sudo", "bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
```



### Keychain Password Retrieval via Command Line

Branch count: 28  
Document count: 28  
Index: geneve-ut-420

```python
process where host.os.type == "macos" and event.action == "exec" and
 process.name : "security" and
 process.args : ("-wa", "-ga") and process.args : ("find-generic-password", "find-internet-password") and
 process.command_line : ("*Chrome*", "*Chromium*", "*Opera*", "*Safari*", "*Brave*", "*Microsoft Edge*", "*Firefox*") and
 not process.parent.executable : "/Applications/Keeper Password Manager.app/Contents/Frameworks/Keeper Password Manager Helper*/Contents/MacOS/Keeper Password Manager Helper*"
```



### Kirbi File Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-421

```python
file where host.os.type == "windows" and event.type == "creation" and file.extension : "kirbi"
```



### Kubernetes Anonymous Request Authorized

Branch count: 3  
Document count: 3  
Index: geneve-ut-422

```python
event.dataset:kubernetes.audit_logs
  and kubernetes.audit.annotations.authorization_k8s_io/decision:allow
  and kubernetes.audit.user.username:("system:anonymous" or "system:unauthenticated" or not *)
  and not kubernetes.audit.requestURI:(/healthz* or /livez* or /readyz*)
```



### Kubernetes Denied Service Account Request

Branch count: 1  
Document count: 1  
Index: geneve-ut-424

```python
event.dataset: "kubernetes.audit_logs"
  and kubernetes.audit.user.username: system\:serviceaccount\:*
  and kubernetes.audit.annotations.authorization_k8s_io/decision: "forbid"
```



### Kubernetes Exposed Service Created With Type NodePort

Branch count: 3  
Document count: 3  
Index: geneve-ut-425

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
Index: geneve-ut-426

```python
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.objectRef.resource:"pods"
  and kubernetes.audit.verb:("create" or "update" or "patch")
  and kubernetes.audit.requestObject.spec.hostIPC:true
  and not kubernetes.audit.requestObject.spec.containers.image: ("docker.elastic.co/beats/elastic-agent:8.4.0")
```



### Kubernetes Pod Created With HostNetwork

Branch count: 3  
Document count: 3  
Index: geneve-ut-427

```python
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.objectRef.resource:"pods"
  and kubernetes.audit.verb:("create" or "update" or "patch")
  and kubernetes.audit.requestObject.spec.hostNetwork:true
  and not kubernetes.audit.requestObject.spec.containers.image: ("docker.elastic.co/beats/elastic-agent:8.4.0")
```



### Kubernetes Pod Created With HostPID

Branch count: 3  
Document count: 3  
Index: geneve-ut-428

```python
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.objectRef.resource:"pods"
  and kubernetes.audit.verb:("create" or "update" or "patch")
  and kubernetes.audit.requestObject.spec.hostPID:true
  and not kubernetes.audit.requestObject.spec.containers.image: ("docker.elastic.co/beats/elastic-agent:8.4.0")
```



### Kubernetes Pod created with a Sensitive hostPath Volume

Branch count: 48  
Document count: 48  
Index: geneve-ut-429

```python
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.objectRef.resource:"pods"
  and kubernetes.audit.verb:("create" or "update" or "patch")
  and kubernetes.audit.requestObject.spec.volumes.hostPath.path:
  ("/" or
  "/proc" or
  "/root" or
  "/var" or
  "/var/run" or
  "/var/run/docker.sock" or
  "/var/run/crio/crio.sock" or
  "/var/run/cri-dockerd.sock" or
  "/var/lib/kubelet" or
  "/var/lib/kubelet/pki" or
  "/var/lib/docker/overlay2" or
  "/etc" or
  "/etc/kubernetes" or
  "/etc/kubernetes/manifests" or
  "/etc/kubernetes/pki" or
  "/home/admin")
  and not kubernetes.audit.requestObject.spec.containers.image: ("docker.elastic.co/beats/elastic-agent:8.4.0")
```



### Kubernetes Privileged Pod Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-430

```python
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.objectRef.resource:pods
  and kubernetes.audit.verb:create
  and kubernetes.audit.requestObject.spec.containers.securityContext.privileged:true
  and not kubernetes.audit.requestObject.spec.containers.image: ("docker.elastic.co/beats/elastic-agent:8.4.0")
```



### Kubernetes Suspicious Assignment of Controller Service Account

Branch count: 1  
Document count: 1  
Index: geneve-ut-431

```python
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.verb : "create"
  and kubernetes.audit.objectRef.resource : "pods"
  and kubernetes.audit.objectRef.namespace : "kube-system"
  and kubernetes.audit.requestObject.spec.serviceAccountName:*controller
```



### Kubernetes Suspicious Self-Subject Review

Branch count: 8  
Document count: 8  
Index: geneve-ut-432

```python
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.verb:"create"
  and kubernetes.audit.objectRef.resource:("selfsubjectaccessreviews" or "selfsubjectrulesreviews")
  and (kubernetes.audit.user.username:(system\:serviceaccount\:* or system\:node\:*)
  or kubernetes.audit.impersonatedUser.username:(system\:serviceaccount\:* or system\:node\:*))
```



### Kubernetes User Exec into Pod

Branch count: 1  
Document count: 1  
Index: geneve-ut-433

```python
event.dataset : "kubernetes.audit_logs"
  and kubernetes.audit.annotations.authorization_k8s_io/decision:"allow"
  and kubernetes.audit.verb:"create"
  and kubernetes.audit.objectRef.resource:"pods"
  and kubernetes.audit.objectRef.subresource:"exec"
```



### LSASS Memory Dump Creation

Branch count: 20  
Document count: 20  
Index: geneve-ut-434

```python
file where host.os.type == "windows" and event.action != "deletion" and
  file.name : ("lsass*.dmp", "dumpert.dmp", "Andrew.dmp", "SQLDmpr*.mdmp", "Coredump.dmp") and

  not (
        process.executable : (
          "?:\\Program Files\\Microsoft SQL Server\\*\\Shared\\SqlDumper.exe",
          "?:\\Windows\\System32\\dllhost.exe"
        ) and
        file.path : (
          "?:\\*\\Reporting Services\\Logfiles\\SQLDmpr*.mdmp",
          "?:\\Program Files\\Microsoft SQL Server\\*\\Shared\\ErrorDumps\\SQLDmpr*.mdmp",
          "?:\\Program Files\\Microsoft SQL Server\\*\\MSSQL\\LOG\\SQLDmpr*.mdmp"
        )
      ) and

  not (
        process.executable : "?:\\Windows\\system32\\WerFault.exe" and
        file.path : (
          "?:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\CrashDumps\\lsass.exe.*.dmp",
          "?:\\Windows\\System32\\%LOCALAPPDATA%\\CrashDumps\\lsass.exe.*.dmp"
        )
  )
```



### LSASS Memory Dump Handle Access

Branch count: 18  
Document count: 18  
Index: geneve-ut-435

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
        "?:\\Windows\\explorer.exe",
        "?:\\Windows\\System32\\poqexec.exe")
```



### LSASS Process Access via Windows API

Branch count: 4  
Document count: 4  
Index: geneve-ut-436

```python
api where host.os.type == "windows" and 
  process.Ext.api.name in ("OpenProcess", "OpenThread") and Target.process.name : "lsass.exe" and 
  not 
  (
    process.executable : (
        "?:\\ProgramData\\GetSupportService*\\Updates\\Update_*.exe",
        "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
        "?:\\Program Files (x86)\\Asiainfo Security\\OfficeScan Client\\NTRTScan.exe",
        "?:\\Program Files (x86)\\Blackpoint\\SnapAgent\\SnapAgent.exe",
        "?:\\Program Files (x86)\\eScan\\reload.exe",
        "?:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe",
        "?:\\Program Files (x86)\\Kaspersky Lab\\*\\avp.exe",
        "?:\\Program Files (x86)\\N-able Technologies\\Reactive\\bin\\NableReactiveManagement.exe",
        "?:\\Program Files (x86)\\N-able Technologies\\Windows Agent\\bin\\agent.exe",
        "?:\\Program Files (x86)\\Trend Micro\\*\\CCSF\\TmCCSF.exe",
        "?:\\Program Files*\\Windows Defender\\MsMpEng.exe",
        "?:\\Program Files\\Bitdefender\\Endpoint Security\\EPSecurityService.exe",
        "?:\\Program Files\\Cisco\\AMP\\*\\sfc.exe",
        "?:\\Program Files\\Common Files\\McAfee\\AVSolution\\mcshield.exe",
        "?:\\Program Files\\EA\\AC\\EAAntiCheat.GameService.exe",
        "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\metricbeat.exe",
        "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\osqueryd.exe",
        "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\packetbeat.exe",
        "?:\\Program Files\\ESET\\ESET Security\\ekrn.exe",
        "?:\\Program Files\\Fortinet\\FortiClient\\FortiProxy.exe",
        "?:\\Program Files\\Huntress\\HuntressAgent.exe",
        "?:\\Program Files\\LogicMonitor\\Agent\\bin\\sbshutdown.exe",
        "?:\\Program Files\\Microsoft Security Client\\MsMpEng.exe",
        "?:\\Program Files\\Qualys\\QualysAgent\\QualysAgent.exe",
        "?:\\Program Files\\TDAgent\\ossec-agent\\ossec-agent.exe",
        "?:\\Program Files\\Topaz OFD\\Warsaw\\core.exe",
        "?:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
        "?:\\Windows\\AdminArsenal\\PDQDeployRunner\\*\\exec\\Sysmon64.exe",
        "?:\\Windows\\Sysmon.exe",
        "?:\\Windows\\Sysmon64.exe",
        "?:\\Windows\\System32\\csrss.exe",
        "?:\\Windows\\System32\\MRT.exe",
        "?:\\Windows\\System32\\msiexec.exe",
        "?:\\Windows\\System32\\RtkAudUService64.exe",
        "?:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
        "?:\\Windows\\SysWOW64\\wbem\\WmiPrvSE.exe"
    ) and not ?process.code_signature.trusted == false
  )
```



### Lateral Movement via Startup Folder

Branch count: 8  
Document count: 8  
Index: geneve-ut-437

```python
file where host.os.type == "windows" and event.type in ("creation", "change") and

 /* via RDP TSClient mounted share or SMB */
  (process.name : "mstsc.exe" or process.pid == 4) and

   file.path : ("?:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
                "?:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")
```



### Launch Agent Creation or Modification and Immediate Loading

Branch count: 6  
Document count: 12  
Index: geneve-ut-438

```python
sequence by host.id with maxspan=1m
 [file where host.os.type == "macos" and event.type != "deletion" and
  file.path : ("/System/Library/LaunchAgents/*", "/Library/LaunchAgents/*", "/Users/*/Library/LaunchAgents/*")
 ]
 [process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name == "launchctl" and process.args == "load"]
```



### LaunchDaemon Creation or Modification and Immediate Loading

Branch count: 4  
Document count: 8  
Index: geneve-ut-439

```python
sequence by host.id with maxspan=1m
 [file where host.os.type == "macos" and event.type != "deletion" and file.path : ("/System/Library/LaunchDaemons/*", "/Library/LaunchDaemons/*")]
 [process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name == "launchctl" and process.args == "load"]
```



### Linux Process Hooking via GDB

Branch count: 8  
Document count: 8  
Index: geneve-ut-441

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name == "gdb" and process.args in ("--pid", "-p") and 
/* Covered by d4ff2f53-c802-4d2e-9fb9-9ecc08356c3f */
process.args != "1"
```



### Linux Restricted Shell Breakout via Linux Binary(s)

Branch count: 609  
Document count: 609  
Index: geneve-ut-442

```python
process where host.os.type == "linux" and event.type == "start" and
(
  /* launching shell from capsh */
  (process.name == "capsh" and process.args == "--") or

  /* launching shells from unusual parents or parent+arg combos */
  (process.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and (
    (process.parent.name : "*awk" and process.parent.args : "BEGIN {system(*)}") or
    (process.parent.name == "git" and process.parent.args : ("*PAGER*", "!*sh", "exec *sh") or 
     process.args : ("*PAGER*", "!*sh", "exec *sh") and not process.name == "ssh" ) or
    (process.parent.name : ("byebug", "ftp", "strace", "zip", "tar") and 
    (
      process.parent.args : "BEGIN {system(*)}" or
      (process.parent.args : ("*PAGER*", "!*sh", "exec *sh") or process.args : ("*PAGER*", "!*sh", "exec *sh")) or
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
   process.parent.args == "runc") and not process.parent.args in ("ls-remote", "push", "fetch") and not process.parent.name == "mkinitramfs") or
  (process.name == "env" and process.args_count == 2 and process.args : "*sh") or
  (process.parent.name in ("vi", "vim") and process.parent.args == "-c" and process.parent.args : ":!*sh") or
  (process.parent.name in ("c89", "c99", "gcc") and process.parent.args : "*sh,-s" and process.parent.args == "-wrapper") or
  (process.parent.name == "expect" and process.parent.args == "-c" and process.parent.args : "spawn *sh;interact") or
  (process.parent.name == "mysql" and process.parent.args == "-e" and process.parent.args : "\\!*sh") or
  (process.parent.name == "ssh" and process.parent.args == "-o" and process.parent.args : "ProxyCommand=;*sh 0<&2 1>&2")
)
```



### Linux System Information Discovery

Branch count: 64  
Document count: 64  
Index: geneve-ut-443

```python
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and (
  process.name: "uname" or (
  process.name: ("cat", "more", "less") and process.args: ("*issue*", "*version*", "*profile*", "*services*", "*cpuinfo*")
  )
)
```



### Linux User Added to Privileged Group

Branch count: 240  
Document count: 240  
Index: geneve-ut-445

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.args in (
  "root", "admin", "wheel", "staff", "sudo","disk", "video", "shadow", "lxc", "lxd"
) and
(
  process.name in ("usermod", "adduser") or
  process.name == "gpasswd" and 
  process.args in ("-a", "--add", "-M", "--members") 
)
```



### Local Account TokenFilter Policy Disabled

Branch count: 6  
Document count: 6  
Index: geneve-ut-447

```python
registry where host.os.type == "windows" and registry.path : (
  "HKLM\\*\\LocalAccountTokenFilterPolicy",
  "\\REGISTRY\\MACHINE\\*\\LocalAccountTokenFilterPolicy",
  "MACHINE\\*\\LocalAccountTokenFilterPolicy") and
  registry.data.strings : ("1", "0x00000001")
```



### Local Scheduled Task Creation

Branch count: 600  
Document count: 1200  
Index: geneve-ut-448

```python
sequence with maxspan=1m
  [process where host.os.type == "windows" and event.type != "end" and
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



### MFA Disabled for Google Workspace Organization

Branch count: 2  
Document count: 2  
Index: geneve-ut-450

```python
event.dataset:google_workspace.admin and event.provider:admin and event.category:iam and event.action:(ENFORCE_STRONG_AUTHENTICATION or ALLOW_STRONG_AUTHENTICATION) and google_workspace.admin.new_value:false
```



### MS Office Macro Security Registry Modifications

Branch count: 96  
Document count: 96  
Index: geneve-ut-451

```python
registry where host.os.type == "windows" and event.type == "change" and
    registry.path : (
        "HKU\\S-1-5-21-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\AccessVBOM",
        "HKU\\S-1-5-21-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\VbaWarnings",
        "HKU\\S-1-12-1-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\AccessVBOM",
        "HKU\\S-1-12-1-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\VbaWarnings",
        "\\REGISTRY\\USER\\S-1-5-21-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\AccessVBOM",
        "\\REGISTRY\\USER\\S-1-5-21-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\VbaWarnings",
        "\\REGISTRY\\USER\\S-1-12-1-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\AccessVBOM",
        "\\REGISTRY\\USER\\S-1-12-1-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\VbaWarnings"
        ) and
    registry.data.strings : ("0x00000001", "1") and
    process.name : ("cscript.exe", "wscript.exe", "mshta.exe", "mshta.exe", "winword.exe", "excel.exe")
```



### MacOS Installer Package Spawns Network Event

Branch count: 84  
Document count: 168  
Index: geneve-ut-452

```python
sequence by host.id with maxspan=15s
[process where host.os.type == "macos" and event.type == "start" and event.action == "exec" and process.parent.name : ("installer", "package_script_service") and process.name : ("bash", "sh", "zsh", "python", "osascript", "tclsh*")] by process.entity_id
[network where host.os.type == "macos" and event.type == "start" and process.name : ("curl", "osascript", "wget", "python", "java", "ruby", "node")] by process.parent.entity_id
```



### Machine Learning Detected DGA activity using a known SUNBURST DNS domain

Branch count: 1  
Document count: 1  
Index: geneve-ut-453

```python
ml_is_dga.malicious_prediction:1 and dns.question.registered_domain:avsvmcloud.com
```



### Machine Learning Detected a DNS Request Predicted to be a DGA Domain

Branch count: 1  
Document count: 1  
Index: geneve-ut-454

```python
ml_is_dga.malicious_prediction:1 and not dns.question.registered_domain:avsvmcloud.com
```



### Machine Learning Detected a Suspicious Windows Event Predicted to be Malicious Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-456

```python
process where (problemchild.prediction == 1 or blocklist_label == 1) and not process.args : ("*C:\\WINDOWS\\temp\\nessus_*.txt*", "*C:\\WINDOWS\\temp\\nessus_*.tmp*")
```



### Malware - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-458

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:file_classification_event or endgame.event_subtype_full:file_classification_event)
```



### Malware - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-459

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:file_classification_event or endgame.event_subtype_full:file_classification_event)
```



### Member Removed From GitHub Organization

Branch count: 1  
Document count: 1  
Index: geneve-ut-461

```python
configuration where event.dataset == "github.audit" and event.action == "org.remove_member"
```



### Message-of-the-Day (MOTD) File Creation

Branch count: 8  
Document count: 8  
Index: geneve-ut-463

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and
file.path : "/etc/update-motd.d/*" and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```



### Microsoft 365 Exchange Anti-Phish Policy Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-464

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-AntiPhishPolicy" and event.outcome:success
```



### Microsoft 365 Exchange Anti-Phish Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-465

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-AntiPhishRule" or "Disable-AntiPhishRule") and event.outcome:success
```



### Microsoft 365 Exchange DKIM Signing Configuration Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-466

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Set-DkimSigningConfig" and o365.audit.Parameters.Enabled:False and event.outcome:success
```



### Microsoft 365 Exchange DLP Policy Removed

Branch count: 1  
Document count: 1  
Index: geneve-ut-467

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-DlpPolicy" and event.outcome:success
```



### Microsoft 365 Exchange Malware Filter Policy Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-468

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Remove-MalwareFilterPolicy" and event.outcome:success
```



### Microsoft 365 Exchange Malware Filter Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-469

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-MalwareFilterRule" or "Disable-MalwareFilterRule") and event.outcome:success
```



### Microsoft 365 Exchange Management Group Role Assignment

Branch count: 1  
Document count: 1  
Index: geneve-ut-470

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"New-ManagementRoleAssignment" and event.outcome:success
```



### Microsoft 365 Exchange Safe Attachment Rule Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-471

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Disable-SafeAttachmentRule" and event.outcome:success
```



### Microsoft 365 Exchange Safe Link Policy Disabled

Branch count: 1  
Document count: 1  
Index: geneve-ut-472

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"Disable-SafeLinksRule" and event.outcome:success
```



### Microsoft 365 Exchange Transport Rule Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-473

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:"New-TransportRule" and event.outcome:success
```



### Microsoft 365 Exchange Transport Rule Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-474

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Remove-TransportRule" or "Disable-TransportRule") and event.outcome:success
```



### Microsoft 365 Global Administrator Role Assigned

Branch count: 1  
Document count: 1  
Index: geneve-ut-475

```python
event.dataset:o365.audit and event.code:"AzureActiveDirectory" and event.action:"Add member to role." and
o365.audit.ModifiedProperties.Role_DisplayName.NewValue:"Global Administrator"
```



### Microsoft 365 Inbox Forwarding Rule Created

Branch count: 6  
Document count: 6  
Index: geneve-ut-476

```python
event.dataset:o365.audit and event.provider:Exchange and
event.category:web and event.action:("New-InboxRule" or "Set-InboxRule") and
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
Index: geneve-ut-477

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"Potential ransomware activity" and event.outcome:success
```



### Microsoft 365 Teams Custom Application Interaction Allowed

Branch count: 1  
Document count: 1  
Index: geneve-ut-478

```python
event.dataset:o365.audit and event.provider:MicrosoftTeams and
event.category:web and event.action:TeamsTenantSettingChanged and
o365.audit.Name:"Allow sideloading and interaction of custom apps" and
o365.audit.NewValue:True and event.outcome:success
```



### Microsoft 365 Teams External Access Enabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-479

```python
event.dataset:o365.audit and event.provider:(SkypeForBusiness or MicrosoftTeams) and
event.category:web and event.action:"Set-CsTenantFederationConfiguration" and
o365.audit.Parameters.AllowFederatedUsers:True and event.outcome:success
```



### Microsoft 365 Teams Guest Access Enabled

Branch count: 2  
Document count: 2  
Index: geneve-ut-480

```python
event.dataset:o365.audit and event.provider:(SkypeForBusiness or MicrosoftTeams) and
event.category:web and event.action:"Set-CsTeamsClientConfiguration" and
o365.audit.Parameters.AllowGuestUser:True and event.outcome:success
```



### Microsoft 365 Unusual Volume of File Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-481

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"Unusual volume of file deletion" and event.outcome:success
```



### Microsoft 365 User Restricted from Sending Email

Branch count: 1  
Document count: 1  
Index: geneve-ut-482

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"User restricted from sending email" and event.outcome:success
```



### Microsoft Build Engine Started by a System Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-485

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "MSBuild.exe" and
  process.parent.name : ("explorer.exe", "wmiprvse.exe")
```



### Microsoft Build Engine Started by an Office Application

Branch count: 8  
Document count: 8  
Index: geneve-ut-486

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
Index: geneve-ut-487

```python
process where host.os.type == "windows" and event.type == "start" and
  process.pe.original_file_name == "MSBuild.exe" and
  not process.name : "MSBuild.exe"
```



### Microsoft Exchange Server UM Spawning Suspicious Processes

Branch count: 2  
Document count: 2  
Index: geneve-ut-488

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : ("UMService.exe", "UMWorkerProcess.exe") and
    not process.executable :
              ("?:\\Windows\\System32\\werfault.exe",
               "?:\\Windows\\System32\\wermgr.exe",
               "?:\\Program Files\\Microsoft\\Exchange Server\\V??\\Bin\\UMWorkerProcess.exe",
               "?:\\Program Files\\Microsoft\\Exchange Server\\Bin\\UMWorkerProcess.exe",
               "D:\\Exchange 2016\\Bin\\UMWorkerProcess.exe",
               "E:\\ExchangeServer\\Bin\\UMWorkerProcess.exe",
               "D:\\Exchange\\Bin\\UMWorkerProcess.exe",
               "D:\\Exchange Server\\Bin\\UMWorkerProcess.exe",
               "E:\\Exchange Server\\V15\\Bin\\UMWorkerProcess.exe")
```



### Microsoft Exchange Server UM Writing Suspicious Files

Branch count: 48  
Document count: 48  
Index: geneve-ut-489

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
Index: geneve-ut-490

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
Index: geneve-ut-491

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "w3wp.exe" and process.parent.args : "MSExchange*AppPool" and
  (process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe") or
  ?process.pe.original_file_name in ("cmd.exe", "powershell.exe", "pwsh.dll", "powershell_ise.exe"))
```



### Microsoft IIS Connection Strings Decryption

Branch count: 2  
Document count: 2  
Index: geneve-ut-492

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "aspnet_regiis.exe" or ?process.pe.original_file_name == "aspnet_regiis.exe") and
  process.args : "connectionStrings" and process.args : "-pdf"
```



### Microsoft IIS Service Account Password Dumped

Branch count: 2  
Document count: 2  
Index: geneve-ut-493

```python
process where host.os.type == "windows" and event.type == "start" and
   (process.name : "appcmd.exe" or ?process.pe.original_file_name == "appcmd.exe") and
   process.args : "/list" and process.args : "/text*password"
```



### Microsoft Management Console File from Unusual Path

Branch count: 1  
Document count: 1  
Index: geneve-ut-494

```python
process where host.os.type == "windows" and event.type == "start" and
  process.executable : "?:\\Windows\\System32\\mmc.exe" and process.args : "*.msc" and
  not process.args : ("?:\\Windows\\System32\\*.msc", "?:\\Windows\\SysWOW64\\*.msc", "?:\\Program files\\*.msc", "?:\\Program Files (x86)\\*.msc")
```



### Microsoft Windows Defender Tampering

Branch count: 30  
Document count: 30  
Index: geneve-ut-495

```python
registry where host.os.type == "windows" and event.type in ("creation", "change") and
 process.executable != null and 
  not process.executable :
              ("?:\\Windows\\system32\\svchost.exe", 
               "?:\\Windows\\CCM\\CcmExec.exe", 
               "?:\\Windows\\System32\\DeviceEnroller.exe", 
               "?:\\Program Files (x86)\\Trend Micro\\Security Agent\\tmuninst.exe") and 
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
Index: geneve-ut-496

```python
file where host.os.type == "windows" and file.name : "mimilsa.log" and process.name : "lsass.exe"
```



### Modification of AmsiEnable Registry Key

Branch count: 12  
Document count: 12  
Index: geneve-ut-497

```python
registry where host.os.type == "windows" and event.type in ("creation", "change") and
  registry.path : (
    "HKEY_USERS\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable",
    "HKU\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable",
    "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable"
  ) and
  registry.data.strings: ("0", "0x00000000")
```



### Modification of Boot Configuration

Branch count: 4  
Document count: 4  
Index: geneve-ut-498

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "bcdedit.exe" or ?process.pe.original_file_name == "bcdedit.exe") and
    (
      (process.args : "/set" and process.args : "bootstatuspolicy" and process.args : "ignoreallfailures") or
      (process.args : "no" and process.args : "recoveryenabled")
    )
```



### Modification of Dynamic Linker Preload Shared Object Inside A Container

Branch count: 1  
Document count: 1  
Index: geneve-ut-500

```python
file where event.module== "cloud_defend" and event.type != "deletion" and file.path== "/etc/ld.so.preload"
```



### Modification of Environment Variable via Unsigned or Untrusted Parent

Branch count: 2  
Document count: 2  
Index: geneve-ut-501

```python
event.category:process and host.os.type:macos and event.type:start and 
  process.name:launchctl and 
  (process.parent.code_signature.exists : false or process.parent.code_signature.trusted : false) and
  process.args:(setenv and not (ANT_HOME or 
                                DBUS_LAUNCHD_SESSION_BUS_SOCKET or 
                                EDEN_ENV or 
                                LG_WEBOS_TV_SDK_HOME or 
                                RUNTIME_JAVA_HOME or 
                                WEBOS_CLI_TV or 
                                JAVA*_HOME) and 
                not *.vmoptions) and 
  not process.parent.executable:("/Applications/IntelliJ IDEA CE.app/Contents/jbr/Contents/Home/lib/jspawnhelper" or 
                                  /Applications/NoMachine.app/Contents/Frameworks/bin/nxserver.bin or 
                                  /Applications/NoMachine.app/Contents/Frameworks/bin/nxserver.bin or 
                                  /usr/local/bin/kr)
```



### Modification of OpenSSH Binaries

Branch count: 5  
Document count: 5  
Index: geneve-ut-502

```python
event.category:file and host.os.type:linux and event.type:change and 
  process.name:(* and not (dnf or dnf-automatic or dpkg or yum or rpm or yum-cron or anacron or platform-python)) and 
  (file.path:(/usr/bin/scp or 
                /usr/bin/sftp or 
                /usr/bin/ssh or 
                /usr/sbin/sshd) or 
  file.name:libkeyutils.so) and
  not process.executable:/usr/share/elasticsearch/*
```



### Modification of Safari Settings via Defaults Command

Branch count: 1  
Document count: 1  
Index: geneve-ut-503

```python
event.category:process and host.os.type:macos and event.type:start and
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



### Modification of WDigest Security Provider

Branch count: 16  
Document count: 16  
Index: geneve-ut-505

```python
registry where host.os.type == "windows" and event.type : ("creation", "change") and
    registry.path : (
        "HKLM\\SYSTEM\\*ControlSet*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential",
        "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\SecurityProviders\\WDigest\\UseLogonCredential"
    ) and registry.data.strings : ("1", "0x00000001") and
    not (process.executable : "?:\\Windows\\System32\\svchost.exe" and user.id : "S-1-5-18")
```



### Modification of the msPKIAccountCredentials

Branch count: 1  
Document count: 1  
Index: geneve-ut-506

```python
event.action:"Directory Service Changes" and event.code:"5136" and
  winlog.event_data.AttributeLDAPDisplayName:"msPKIAccountCredentials" and winlog.event_data.OperationType:"%%14674" and
  not winlog.event_data.SubjectUserSid : "S-1-5-18"
```



### Modification or Removal of an Okta Application Sign-On Policy

Branch count: 2  
Document count: 2  
Index: geneve-ut-507

```python
event.dataset:okta.system and event.action:(application.policy.sign_on.update or application.policy.sign_on.rule.delete)
```



### Mofcomp Activity

Branch count: 2  
Document count: 2  
Index: geneve-ut-508

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



### Mount Launched Inside a Privileged Container

Branch count: 2  
Document count: 2  
Index: geneve-ut-509

```python
process where event.module == "cloud_defend" and  event.type== "start" and 
(process.name== "mount" or process.args== "mount") and container.security_context.privileged == true
```



### Mounting Hidden or WebDav Remote Shares

Branch count: 12  
Document count: 12  
Index: geneve-ut-510

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

Branch count: 1  
Document count: 2  
Index: geneve-ut-511

```python
sequence by process.entity_id
  [process where host.os.type == "windows" and process.name : "MSBuild.exe" and event.type == "start"]
  [network where host.os.type == "windows" and process.name : "MSBuild.exe" and
     not cidrmatch(destination.ip, "127.0.0.1", "::1") and
     not dns.question.name : "localhost"]
```



### Mshta Making Network Connections

Branch count: 1  
Document count: 2  
Index: geneve-ut-512

```python
sequence by process.entity_id with maxspan=10m
  [process where host.os.type == "windows" and event.type == "start" and process.name : "mshta.exe" and
     not process.parent.name : "Microsoft.ConfigurationManagement.exe" and
     not (process.parent.executable : "C:\\Amazon\\Amazon Assistant\\amazonAssistantService.exe" or
          process.parent.executable : "C:\\TeamViewer\\TeamViewer.exe") and
     not process.args : "ADSelfService_Enroll.hta"]
  [network where host.os.type == "windows" and process.name : "mshta.exe"]
```



### Multi-Factor Authentication Disabled for an Azure User

Branch count: 2  
Document count: 2  
Index: geneve-ut-513

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Disable Strong Authentication" and event.outcome:(Success or success)
```



### Multiple Logon Failure Followed by Logon Success

Branch count: 1  
Document count: 6  
Index: geneve-ut-516

```python
sequence by winlog.computer_name, source.ip with maxspan=5s
  [authentication where event.action == "logon-failed" and
    /* event 4625 need to be logged */
    winlog.logon.type : "Network" and user.id != null and 
    source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1" and 
    not winlog.event_data.TargetUserSid : "S-1-0-0" and not user.id : "S-1-0-0" and 
    not user.name : ("ANONYMOUS LOGON", "-", "*$") and not user.domain == "NT AUTHORITY" and

    /* noisy failure status codes often associated to authentication misconfiguration */
    not winlog.event_data.Status : ("0xC000015B", "0XC000005E", "0XC0000133", "0XC0000192")] with runs=5
  [authentication where event.action == "logged-in" and
    /* event 4624 need to be logged */
    winlog.logon.type : "Network" and
    source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1" and
    not user.name : ("ANONYMOUS LOGON", "-", "*$") and not user.domain == "NT AUTHORITY"]
```



### Multiple Logon Failure from the same Source Address

Branch count: 1  
Document count: 10  
Index: geneve-ut-517

```python
sequence by winlog.computer_name, source.ip with maxspan=10s
  [authentication where event.action == "logon-failed" and
    /* event 4625 need to be logged */
    winlog.logon.type : "Network" and
    source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1" and
    not user.name : ("ANONYMOUS LOGON", "-", "*$") and not user.domain == "NT AUTHORITY" and

    /*
    noisy failure status codes often associated to authentication misconfiguration :
     0xC000015B - The user has not been granted the requested logon type (also called the logon right) at this machine.
     0XC000005E	- There are currently no logon servers available to service the logon request.
     0XC0000133	- Clocks between DC and other computer too far out of sync.
     0XC0000192	An attempt was made to logon, but the Netlogon service was not started.
    */
    not winlog.event_data.Status : ("0xC000015B", "0XC000005E", "0XC0000133", "0XC0000192")] with runs=10
```



### Multiple Vault Web Credentials Read

Branch count: 1  
Document count: 2  
Index: geneve-ut-523

```python
sequence by winlog.computer_name, winlog.process.pid with maxspan=1s

 /* 2 consecutive vault reads from same pid for web creds */

 [any where event.code : "5382" and
  (winlog.event_data.SchemaFriendlyName : "Windows Web Password Credential" and winlog.event_data.Resource : "http*") and
  not winlog.event_data.SubjectLogonId : "0x3e7" and 
  not winlog.event_data.Resource : "http://localhost/"]

 [any where event.code : "5382" and
  (winlog.event_data.SchemaFriendlyName : "Windows Web Password Credential" and winlog.event_data.Resource : "http*") and
  not winlog.event_data.SubjectLogonId : "0x3e7" and 
  not winlog.event_data.Resource : "http://localhost/"]
```



### NTDS Dump via Wbadmin

Branch count: 2  
Document count: 2  
Index: geneve-ut-525

```python
process where host.os.type == "windows" and event.type == "start" and
    (process.name : "wbadmin.exe" or ?process.pe.original_file_name : "wbadmin.exe") and 
     process.args : "recovery" and process.command_line : "*ntds.dit*"
```



### NTDS or SAM Database File Copied

Branch count: 210  
Document count: 210  
Index: geneve-ut-526

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

Branch count: 2  
Document count: 2  
Index: geneve-ut-527

```python
process where host.os.type == "linux" and event.type == "start" and event.action : ("exec", "exec_event") and
process.executable: "/usr/bin/unshare" and
not process.parent.executable: ("/usr/bin/udevadm", "*/lib/systemd/systemd-udevd", "/usr/bin/unshare") and
not process.args == "/usr/bin/snap" and not process.parent.name in ("zz-proxmox-boot", "java")
```



### Netcat Listener Established Inside A Container

Branch count: 560  
Document count: 560  
Index: geneve-ut-528

```python
process where container.id: "*" and event.type== "start" 
and event.action in ("fork", "exec") and 
(
process.name:("nc","ncat","netcat","netcat.openbsd","netcat.traditional") or
/*account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg*/
process.args: ("nc","ncat","netcat","netcat.openbsd","netcat.traditional")
) and (
          /* bind shell to echo for command execution */
          (process.args:("-*l*", "--listen", "-*p*", "--source-port") and process.args:("-c", "--sh-exec", "-e", "--exec", "echo","$*"))
          /* bind shell to specific port */
          or process.args:("-*l*", "--listen", "-*p*", "--source-port")
          )
```



### Netcat Listener Established via rlwrap

Branch count: 10  
Document count: 10  
Index: geneve-ut-529

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and 
process.name == "rlwrap" and process.args in ("nc", "ncat", "netcat", "nc.openbsd", "socat") and
process.args : "*l*" and process.args_count >= 4
```



### Netsh Helper DLL

Branch count: 2  
Document count: 2  
Index: geneve-ut-530

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
    "HKLM\\Software\\Microsoft\\netsh\\*",
    "\\REGISTRY\\MACHINE\\Software\\Microsoft\\netsh\\*"
  )
```



### Network Activity Detected via cat

Branch count: 16  
Document count: 32  
Index: geneve-ut-532

```python
sequence by host.id, process.entity_id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name == "cat" and process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")]
  [network where host.os.type == "linux" and event.action in ("connection_attempted", "disconnect_received") and
   process.name == "cat" and not (destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
     destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
     "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
     "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
     "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
     "FF00::/8"
     )
   )]
```



### Network Connection Initiated by SSHD Child Process

Branch count: 1  
Document count: 2  
Index: geneve-ut-533

```python
sequence by host.id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.executable == "/usr/sbin/sshd"] by process.entity_id
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



### Network Connection via Certutil

Branch count: 1  
Document count: 1  
Index: geneve-ut-535

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
Index: geneve-ut-536

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
Index: geneve-ut-537

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

Branch count: 3  
Document count: 12  
Index: geneve-ut-538

```python
sequence by host.id with maxspan=1m
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and 
   process.name in ("gcc", "g++", "cc")] by process.args
  [file where host.os.type == "linux" and event.action == "creation" and process.name == "ld"] by file.name
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec"] by process.name
  [network where host.os.type == "linux" and event.action == "connection_attempted" and destination.ip != null and 
   not cidrmatch(destination.ip, "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1")] by process.name
```



### Network Connection via Registration Utility

Branch count: 18  
Document count: 36  
Index: geneve-ut-539

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
Index: geneve-ut-540

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
Index: geneve-ut-541

```python
sequence by host.id, process.entity_id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
     (process.parent.executable == "/usr/bin/xfce4-session") or
     (process.executable == "/bin/sh" and process.args == "-e" and process.args == "-u" and
      process.args == "-c" and process.args : "export GIO_LAUNCHED_DESKTOP_FILE_PID=$$;*")
   )
  ]
  [network where host.os.type == "linux" and event.type == "start" and event.action == "connection_attempted"]
```



### Network Logon Provider Registry Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-542

```python
registry where host.os.type == "windows" and registry.data.strings : "?*" and
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

Branch count: 2  
Document count: 2  
Index: geneve-ut-545

```python
registry where host.os.type == "windows" and event.action != "deletion" and
  registry.path :
       ("HKLM\\SYSTEM\\ControlSet*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication", 
        "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication" ) and
  registry.data.strings : "0"
```



### New ActiveSyncAllowedDeviceID Added via PowerShell

Branch count: 3  
Document count: 3  
Index: geneve-ut-546

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and process.args : "Set-CASMailbox*ActiveSyncAllowedDeviceIDs*"
```



### New GitHub App Installed

Branch count: 1  
Document count: 1  
Index: geneve-ut-547

```python
configuration where event.dataset == "github.audit" and event.action == "integration_installation.create"
```



### New GitHub Owner Added

Branch count: 1  
Document count: 1  
Index: geneve-ut-548

```python
iam where event.dataset == "github.audit" and event.action == "org.add_member" and github.permission == "admin"
```



### New Okta Authentication Behavior Detected

Branch count: 1  
Document count: 1  
Index: geneve-ut-549

```python
event.dataset:okta.system and okta.debug_context.debug_data.risk_behaviors:*
```



### New Okta Identity Provider (IdP) Added by Admin

Branch count: 1  
Document count: 1  
Index: geneve-ut-550

```python
event.dataset: "okta.system" and event.action: "system.idp.lifecycle.create" and okta.outcome.result: "SUCCESS"
```



### New User Added To GitHub Organization

Branch count: 1  
Document count: 1  
Index: geneve-ut-551

```python
configuration where event.dataset == "github.audit" and event.action == "org.add_member"
```



### New or Modified Federation Domain

Branch count: 6  
Document count: 6  
Index: geneve-ut-552

```python
event.dataset:o365.audit and event.provider:Exchange and event.category:web and event.action:("Set-AcceptedDomain" or
"Set-MsolDomainFederationSettings" or "Add-FederatedDomain" or "New-AcceptedDomain" or "Remove-AcceptedDomain" or "Remove-FederatedDomain") and
event.outcome:success
```



### Nping Process Activity

Branch count: 4  
Document count: 4  
Index: geneve-ut-553

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name == "nping"
```



### O365 Email Reported by User as Malware or Phish

Branch count: 1  
Document count: 1  
Index: geneve-ut-555

```python
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.action:AlertTriggered and rule.name:"Email reported by user as malware or phish"
```



### O365 Exchange Suspicious Mailbox Right Delegation

Branch count: 3  
Document count: 3  
Index: geneve-ut-557

```python
event.dataset:o365.audit and event.provider:Exchange and event.action:Add-MailboxPermission and
o365.audit.Parameters.AccessRights:(FullAccess or SendAs or SendOnBehalf) and event.outcome:success and
not user.id : "NT AUTHORITY\SYSTEM (Microsoft.Exchange.Servicehost)"
```



### O365 Mailbox Audit Logging Bypass

Branch count: 1  
Document count: 1  
Index: geneve-ut-558

```python
event.dataset:o365.audit and event.provider:Exchange and event.action:Set-MailboxAuditBypassAssociation and event.outcome:success
```



### Office Test Registry Persistence

Branch count: 1  
Document count: 1  
Index: geneve-ut-559

```python
registry where host.os.type == "windows" and event.action != "deletion" and
    registry.path : "*\\Software\\Microsoft\\Office Test\\Special\\Perf\\*"
```



### Okta FastPass Phishing Detection

Branch count: 1  
Document count: 1  
Index: geneve-ut-561

```python
event.dataset:okta.system and event.category:authentication and
  okta.event_type:user.authentication.auth_via_mfa and event.outcome:failure and okta.outcome.reason:"FastPass declined phishing attempt"
```



### Okta Sign-In Events via Third-Party IdP

Branch count: 10  
Document count: 10  
Index: geneve-ut-562

```python
event.dataset:okta.system and okta.debug_context.debug_data.request_uri:/oauth2/v1/authorize/callback and
    (not okta.authentication_context.issuer.id:Okta and event.action:(user.authentication.auth_via_IDP
        or user.authentication.auth_via_inbound_SAML
        or user.authentication.auth_via_mfa
        or user.authentication.auth_via_social)
        or event.action:user.session.start) or
    (event.action:user.authentication.auth_via_IDP and okta.outcome.result:FAILURE
        and okta.outcome.reason:("A SAML assert with the same ID has already been processed by Okta for a previous request"
            or "Unable to match transformed username"
            or "Unable to resolve IdP endpoint"
            or "Unable to validate SAML Response"
            or "Unable to validate incoming SAML Assertion"))
```



### Okta ThreatInsight Threat Suspected Promotion

Branch count: 2  
Document count: 2  
Index: geneve-ut-563

```python
event.dataset:okta.system and (event.action:security.threat.detected or okta.debug_context.debug_data.threat_suspected: true)
```



### Okta User Session Impersonation

Branch count: 1  
Document count: 1  
Index: geneve-ut-564

```python
event.dataset:okta.system and event.action:user.session.impersonation.initiate
```



### OneDrive Malware File Upload

Branch count: 1  
Document count: 1  
Index: geneve-ut-566

```python
event.dataset:o365.audit and event.provider:OneDrive and event.code:SharePointFileOperation and event.action:FileMalwareDetected
```



### Outbound Scheduled Task Activity via PowerShell

Branch count: 36  
Document count: 72  
Index: geneve-ut-567

```python
sequence by host.id, process.entity_id with maxspan = 5s
 [any where host.os.type == "windows" and (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
  (?dll.name : "taskschd.dll" or file.name : "taskschd.dll") and process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe")]
 [network where host.os.type == "windows" and process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and destination.port == 135 and not destination.address in ("127.0.0.1", "::1")]
```



### Peripheral Device Discovery

Branch count: 2  
Document count: 2  
Index: geneve-ut-569

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "fsutil.exe" or ?process.pe.original_file_name == "fsutil.exe") and
  process.args : "fsinfo" and process.args : "drives"
```



### Permission Theft - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-570

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:token_protection_event or endgame.event_subtype_full:token_protection_event)
```



### Permission Theft - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-571

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:token_protection_event or endgame.event_subtype_full:token_protection_event)
```



### Persistence via BITS Job Notify Cmdline

Branch count: 1  
Document count: 1  
Index: geneve-ut-572

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
Index: geneve-ut-573

```python
event.category:file and host.os.type:macos and not event.type:deletion and
  file.path:/Library/DirectoryServices/PlugIns/*.dsplug
```



### Persistence via Docker Shortcut Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-574

```python
event.category:file and host.os.type:macos and event.action:modification and
 file.path:/Users/*/Library/Preferences/com.apple.dock.plist and
 not process.name:(xpcproxy or cfprefsd or plutil or jamf or PlistBuddy or InstallerRemotePluginService) and
 not process.executable:(/Library/Addigy/download-cache/* or "/Library/Kandji/Kandji Agent.app/Contents/MacOS/kandji-library-manager")
```



### Persistence via Folder Action Script

Branch count: 11  
Document count: 11  
Index: geneve-ut-575

```python
process where host.os.type == "macos" and event.type : "start" and process.name in ("osascript", "python", "tcl", "node", "perl", "ruby", "php", "bash", "csh", "zsh", "sh") and
  process.parent.name == "com.apple.foundation.UserScriptService" and not process.args : ("/Users/*/Library/Application Support/iTerm2/Scripts/AutoLaunch/*.scpt", "/Users/*/Library/Application Scripts/com.microsoft.*/FoxitUtils.applescript")
```



### Persistence via Hidden Run Key Detected

Branch count: 12  
Document count: 12  
Index: geneve-ut-576

```python
/* Registry Path ends with backslash */
registry where host.os.type == "windows" and /* length(registry.data.strings) > 0 and */
 registry.path : ("HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\",
                  "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\",
                  "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\",
                  "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "\\REGISTRY\\MACHINE\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                  "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\",
                  "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\")
```



### Persistence via KDE AutoStart Script or Desktop File Modification

Branch count: 32  
Document count: 32  
Index: geneve-ut-577

```python
file where host.os.type == "linux" and event.type != "deletion" and
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
    not process.name in ("yum", "dpkg", "install", "dnf", "teams", "yum-cron", "dnf-automatic", "docker", "dockerd", 
    "rpm", "pacman", "podman", "nautilus", "remmina", "cinnamon-settings.py")
```



### Persistence via Login or Logout Hook

Branch count: 2  
Document count: 2  
Index: geneve-ut-578

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

Branch count: 18  
Document count: 18  
Index: geneve-ut-579

```python
file where host.os.type == "windows" and event.type != "deletion" and
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
Index: geneve-ut-580

```python
file where host.os.type == "windows" and event.type != "deletion" and
 file.path : "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Outlook\\VbaProject.OTM"
```



### Persistence via PowerShell profile

Branch count: 6  
Document count: 6  
Index: geneve-ut-581

```python
file where host.os.type == "windows" and event.type != "deletion" and
  file.path : ("?:\\Users\\*\\Documents\\WindowsPowerShell\\*",
               "?:\\Users\\*\\Documents\\PowerShell\\*",
               "?:\\Windows\\System32\\WindowsPowerShell\\*") and
  file.name : ("profile.ps1", "Microsoft.Powershell_profile.ps1")
```



### Persistence via Scheduled Job Creation

Branch count: 4  
Document count: 4  
Index: geneve-ut-582

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



### Persistence via TelemetryController Scheduled Task Hijack

Branch count: 1  
Document count: 1  
Index: geneve-ut-583

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
Index: geneve-ut-584

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
Index: geneve-ut-585

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "wmic.exe" or ?process.pe.original_file_name == "wmic.exe") and
  process.args : "create" and
  process.args : ("ActiveScriptEventConsumer", "CommandLineEventConsumer")
```



### Persistence via WMI Standard Registry Provider

Branch count: 48  
Document count: 48  
Index: geneve-ut-586

```python
registry where host.os.type == "windows" and
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



### Port Forwarding Rule Addition

Branch count: 3  
Document count: 3  
Index: geneve-ut-588

```python
registry where host.os.type == "windows" and registry.path : (
  "HKLM\\SYSTEM\\*ControlSet*\\Services\\PortProxy\\v4tov4\\*",
  "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\PortProxy\\v4tov4\\*",
  "MACHINE\\SYSTEM\\*ControlSet*\\Services\\PortProxy\\v4tov4\\*"
)
```



### Possible Consent Grant Attack via Azure-Registered Application

Branch count: 18  
Document count: 18  
Index: geneve-ut-589

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
Index: geneve-ut-591

```python
event.dataset:okta.system and event.action:(application.integration.rate_limit_exceeded or system.org.rate_limit.warning or system.org.rate_limit.violation or core.concurrency.org.limit.violation)
```



### Potential Admin Group Account Addition

Branch count: 16  
Document count: 16  
Index: geneve-ut-595

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:(dscl or dseditgroup) and process.args:(("/Groups/admin" or admin) and ("-a" or "-append")) and
 not process.Ext.effective_parent.executable : ("/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon" or
                                                "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfManagementService.app/Contents/MacOS/JamfManagementService" or
                                                "/opt/jc/bin/jumpcloud-agent" or
                                                "/Library/Addigy/go-agent")
```



### Potential Application Shimming via Sdbinst

Branch count: 2  
Document count: 2  
Index: geneve-ut-597

```python
process where host.os.type == "windows" and event.type == "start" and process.name : "sdbinst.exe" and
  process.args : "?*" and
  not (process.args : "-m" and process.args : "-bg") and
  not process.args : "-mm"
```



### Potential Chroot Container Escape via Mount

Branch count: 8  
Document count: 16  
Index: geneve-ut-599

```python
sequence by host.id, process.parent.entity_id with maxspan=5m
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name == "mount" and process.args : "/dev/sd*" and process.args_count >= 3 and
   process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")]
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name == "chroot"]
```



### Potential Code Execution via Postgresql

Branch count: 8  
Document count: 8  
Index: geneve-ut-600

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "fork", "fork_event") and 
user.name == "postgres" and (
  (process.parent.args : "*sh" and process.parent.args : "echo*") or 
  (process.args : "*sh" and process.args : "echo*")
) and not process.parent.name : "puppet"
```



### Potential Command and Control via Internet Explorer

Branch count: 2  
Document count: 6  
Index: geneve-ut-601

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



### Potential Container Escape via Modified notify_on_release File

Branch count: 1  
Document count: 1  
Index: geneve-ut-602

```python
file where event.module == "cloud_defend" and event.action == "open" and 
event.type == "change" and file.name : "notify_on_release"
```



### Potential Container Escape via Modified release_agent File

Branch count: 1  
Document count: 1  
Index: geneve-ut-603

```python
file where event.module == "cloud_defend" and event.action == "open" and 
event.type == "change" and file.name : "release_agent"
```



### Potential Cookies Theft via Browser Debugging

Branch count: 63  
Document count: 63  
Index: geneve-ut-604

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

Branch count: 12  
Document count: 12  
Index: geneve-ut-605

```python
any where event.action : ("Directory Service Access", "object-operation-performed") and
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
    not winlog.event_data.SubjectUserName : (
          "*$", "MSOL_*", "OpenDNS_Connector", "adconnect", "SyncADConnect",
          "SyncADConnectCM", "aadsync", "svcAzureADSync", "-"
        )

    /* The Umbrella AD Connector uses the OpenDNS_Connector account to perform replication */
```



### Potential Credential Access via DuplicateHandle in LSASS

Branch count: 1  
Document count: 1  
Index: geneve-ut-606

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
Index: geneve-ut-607

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
Index: geneve-ut-608

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
        "?:\\Windows\\CCM\\ccmdump.exe"
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
        "?:\\Users\\*\\AppData\\*\\NativeCrashReporting\\*"
      ) and (process.code_signature.trusted == true or process.executable == null)
    )
  )
```



### Potential Credential Access via Renamed COM+ Services DLL

Branch count: 2  
Document count: 4  
Index: geneve-ut-609

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
Index: geneve-ut-610

```python
sequence by process.entity_id
 [process where host.os.type == "windows" and event.type == "start" and (process.name : "MSBuild.exe" or process.pe.original_file_name == "MSBuild.exe")]
 [any where host.os.type == "windows" and (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
  (?dll.name : ("vaultcli.dll", "SAMLib.DLL") or file.name : ("vaultcli.dll", "SAMLib.DLL"))]
```



### Potential Cross Site Scripting (XSS)

Branch count: 13  
Document count: 13  
Index: geneve-ut-612

```python
any where processor.name == "transaction" and
url.fragment : ("<iframe*", "*prompt(*)*", "<script*>", "<svg*>", "*onerror=*", "*javascript*alert*", "*eval*(*)*", "*onclick=*",
"*alert(document.cookie)*", "*alert(document.domain)*","*onresize=*","*onload=*","*onmouseover=*")
```



### Potential DLL Side-Loading via Microsoft Antimalware Service Executable

Branch count: 2  
Document count: 2  
Index: geneve-ut-614

```python
process where host.os.type == "windows" and event.type == "start" and
(
  (process.pe.original_file_name == "MsMpEng.exe" and not process.name : "MsMpEng.exe") or
  (process.name : "MsMpEng.exe" and not
        process.executable : ("?:\\ProgramData\\Microsoft\\Windows Defender\\*.exe",
                              "?:\\Program Files\\Windows Defender\\*.exe",
                              "?:\\Program Files (x86)\\Windows Defender\\*.exe",
                              "?:\\Program Files\\Microsoft Security Client\\*.exe",
                              "?:\\Program Files (x86)\\Microsoft Security Client\\*.exe"))
)
```



### Potential DLL Side-Loading via Trusted Microsoft Programs

Branch count: 4  
Document count: 4  
Index: geneve-ut-615

```python
process where host.os.type == "windows" and event.type == "start" and
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



### Potential Defense Evasion via CMSTP.exe

Branch count: 1  
Document count: 1  
Index: geneve-ut-621

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "cmstp.exe" and process.args == "/s"
```



### Potential Defense Evasion via PRoot

Branch count: 2  
Document count: 2  
Index: geneve-ut-622

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
process.parent.name == "proot"
```



### Potential Disabling of AppArmor

Branch count: 8  
Document count: 8  
Index: geneve-ut-623

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and (
  (process.name == "systemctl" and process.args == "disable" and process.args == "apparmor") or
  (process.name == "ln" and process.args : "/etc/apparmor.d/*" and process.args == "/etc/apparmor.d/disable/")
)
```



### Potential Disabling of SELinux

Branch count: 4  
Document count: 4  
Index: geneve-ut-624

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name == "setenforce" and process.args == "0"
```



### Potential Enumeration via Active Directory Web Service

Branch count: 2  
Document count: 4  
Index: geneve-ut-625

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



### Potential Evasion via Filter Manager

Branch count: 6  
Document count: 6  
Index: geneve-ut-626

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "fltMC.exe" and process.args : "unload" and
  not
  (
    (
      process.executable : "?:\\Program Files (x86)\\ManageEngine\\UEMS_Agent\\bin\\DCFAService64.exe" and
      process.args : ("DFMFilter", "DRMFilter")
    ) or
    (
      process.executable : "?:\\Windows\\SysWOW64\\msiexec.exe" and
      process.args : ("BrFilter_*", "BrCow_*") and
      user.id : "S-1-5-18"
    )
  )
```



### Potential Execution of rc.local Script

Branch count: 1  
Document count: 1  
Index: geneve-ut-628

```python
process where host.os.type == "linux" and event.type == "info" and event.action == "already_running" and 
process.parent.args == "/etc/rc.local" and process.parent.args == "start"
```



### Potential Execution via XZBackdoor

Branch count: 1  
Document count: 4  
Index: geneve-ut-629

```python
sequence by host.id, user.id with maxspan=1s
 [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name == "sshd" and
    process.args == "-D" and process.args == "-R"] by process.pid, process.entity_id
 [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.parent.name == "sshd" and 
  process.executable != "/usr/sbin/sshd"] by process.parent.pid, process.parent.entity_id
 [process where host.os.type == "linux" and event.action == "end" and process.name == "sshd" and process.exit_code != 0] by process.pid, process.entity_id
 [network where host.os.type == "linux" and event.type == "end" and event.action == "disconnect_received" and process.name == "sshd"] by process.pid, process.entity_id
```



### Potential File Download via a Headless Browser

Branch count: 204  
Document count: 204  
Index: geneve-ut-632

```python
process where host.os.type == "windows" and event.type == "start" and
 process.name : ("chrome.exe", "msedge.exe", "brave.exe", "browser.exe", "dragon.exe", "vivaldi.exe") and
  (process.args : "--headless*" or process.args : "data:text/html;base64,*") and
  process.parent.name :
     ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "conhost.exe", "msiexec.exe",
      "explorer.exe", "rundll32.exe", "winword.exe", "excel.exe", "onenote.exe", "hh.exe", "powerpnt.exe", "forfiles.exe",
      "pcalua.exe", "wmiprvse.exe")
```



### Potential File Transfer via Certreq

Branch count: 2  
Document count: 2  
Index: geneve-ut-633

```python
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "CertReq.exe" or ?process.pe.original_file_name == "CertReq.exe") and process.args : "-Post"
```



### Potential Hidden Local User Account Creation

Branch count: 6  
Document count: 6  
Index: geneve-ut-634

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:dscl and process.args:(IsHidden and create and (true or 1 or yes))
```



### Potential Hidden Process via Mount Hidepid

Branch count: 4  
Document count: 4  
Index: geneve-ut-635

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name == "mount" and process.args == "/proc" and process.args == "-o" and
process.args : "*hidepid=2*"
```



### Potential JAVA/JNDI Exploitation Attempt

Branch count: 60  
Document count: 120  
Index: geneve-ut-638

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
Index: geneve-ut-639

```python
event.category:process and host.os.type:macos and event.type:start and
 process.args:("-action" and ("-kerberoast" or askhash or asktgs or asktgt or s4u or ("-ticket" and ptt) or (dump and (tickets or keytab))))
```



### Potential LSA Authentication Package Abuse

Branch count: 2  
Document count: 2  
Index: geneve-ut-640

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
Index: geneve-ut-641

```python
process where host.os.type == "windows" and event.code:"4688" and
  process.executable : "?:\\Windows\\System32\\lsass.exe" and
  process.parent.executable : "?:\\Windows\\System32\\lsass.exe"
```



### Potential Lateral Tool Transfer via SMB Share

Branch count: 24  
Document count: 48  
Index: geneve-ut-643

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



### Potential Linux Backdoor User Account Creation

Branch count: 4  
Document count: 4  
Index: geneve-ut-644

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name == "usermod" and process.args : "-u" and process.args : "0" and process.args : "-o"
```



### Potential Linux Credential Dumping via Proc Filesystem

Branch count: 3  
Document count: 6  
Index: geneve-ut-645

```python
sequence by host.id, process.parent.name with maxspan=1m
  [process where host.os.type == "linux" and process.name == "ps" and event.action == "exec"
   and process.args in ("-eo", "pid", "command")]
  [process where host.os.type == "linux" and process.name == "strings" and event.action == "exec"
   and process.args : "/tmp/*"]
```



### Potential Linux Credential Dumping via Unshadow

Branch count: 2  
Document count: 2  
Index: geneve-ut-646

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
process.name == "unshadow" and process.args_count >= 3
```



### Potential Linux Hack Tool Launched

Branch count: 156  
Document count: 156  
Index: geneve-ut-647

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name in (
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
  "linenum.sh", "linpeas.sh", "pspy32", "pspy32s", "pspy64", "pspy64s", "binwalk", "evil-winrm"
)
```



### Potential Linux Local Account Brute Force Detected

Branch count: 1  
Document count: 10  
Index: geneve-ut-648

```python
sequence by host.id, process.parent.executable, user.id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name == "su" and 
   not process.parent.name in (
     "bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "clickhouse-server", "ma", "gitlab-runner",
     "updatedb.findutils", "cron"
   )
  ] with runs=10
```



### Potential Linux SSH X11 Forwarding

Branch count: 72  
Document count: 72  
Index: geneve-ut-650

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
process.name in ("ssh", "sshd") and process.args in ("-X", "-Y") and process.args_count >= 3 and 
process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
```



### Potential Linux Tunneling and/or Port Forwarding

Branch count: 458  
Document count: 458  
Index: geneve-ut-651

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and (
  (
    // gost & pivotnacci - spawned without process.parent.name
    (process.name == "gost" and process.args : ("-L*", "-C*", "-R*")) or (process.name == "pivotnacci")) or (
    // ssh
    (process.name in ("ssh", "sshd") and (process.args in ("-R", "-L", "-D", "-w") and process.args_count >= 4 and 
     not process.args : "chmod")) or
    // sshuttle
    (process.name == "sshuttle" and process.args in ("-r", "--remote", "-l", "--listen") and process.args_count >= 4) or
    // socat
    (process.name == "socat" and process.args : ("TCP4-LISTEN:*", "SOCKS*") and process.args_count >= 3) or
    // chisel
    (process.name : "chisel*" and process.args in ("client", "server")) or
    // iodine(d), dnscat, hans, ptunnel-ng, ssf, 3proxy & ngrok 
    (process.name in ("iodine", "iodined", "dnscat", "hans", "hans-ubuntu", "ptunnel-ng", "ssf", "3proxy", "ngrok"))
  ) and process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
)
```



### Potential Local NTLM Relay via HTTP

Branch count: 6  
Document count: 6  
Index: geneve-ut-652

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
Index: geneve-ut-654

```python
process where host.os.type == "windows" and
  event.type == "start" and process.executable : "?:\\Users\\*\\Downloads\\*" and
  not process.code_signature.status : ("errorCode_endpoint*", "errorUntrustedRoot", "errorChaining") and
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
        "24803D75-212C-471A-BC57-9EF86AB91435"
       ) and process.code_signature.trusted == true)
    ) or

    /* Zoom */
    (process.name : ("*zoom*installer*.exe", "*zoom*setup*.exe", "zoom.exe")  and not
      (process.code_signature.subject_name == "Zoom Video Communications, Inc." and process.code_signature.trusted == true)
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
Index: geneve-ut-655

```python
process where host.os.type == "windows" and
  event.type == "start" and
  (
    /* Slack */
    (process.name : "slack.exe" and not
      (process.code_signature.subject_name in (
        "Slack Technologies, Inc.",
        "Slack Technologies, LLC"
       ) and process.code_signature.trusted == true)
    ) or

    /* WebEx */
    (process.name : "WebexHost.exe" and not
      (process.code_signature.subject_name in ("Cisco WebEx LLC", "Cisco Systems, Inc.") and process.code_signature.trusted == true)
    ) or

    /* Teams */
    (process.name : "Teams.exe" and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Discord */
    (process.name : "Discord.exe" and not
      (process.code_signature.subject_name == "Discord Inc." and process.code_signature.trusted == true)
    ) or

    /* RocketChat */
    (process.name : "Rocket.Chat.exe" and not
      (process.code_signature.subject_name == "Rocket.Chat Technologies Corp." and process.code_signature.trusted == true)
    ) or

    /* Mattermost */
    (process.name : "Mattermost.exe" and not
      (process.code_signature.subject_name == "Mattermost, Inc." and process.code_signature.trusted == true)
    ) or

    /* WhatsApp */
    (process.name : "WhatsApp.exe" and not
      (process.code_signature.subject_name in (
        "WhatsApp LLC",
        "WhatsApp, Inc",
        "24803D75-212C-471A-BC57-9EF86AB91435"
       ) and process.code_signature.trusted == true)
    ) or

    /* Zoom */
    (process.name : "Zoom.exe" and not
      (process.code_signature.subject_name == "Zoom Video Communications, Inc." and process.code_signature.trusted == true)
    ) or

    /* Outlook */
    (process.name : "outlook.exe" and not
      (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true)
    ) or

    /* Thunderbird */
    (process.name : "thunderbird.exe" and not
      (process.code_signature.subject_name == "Mozilla Corporation" and process.code_signature.trusted == true)
    )
  )
```



### Potential Masquerading as VLC DLL

Branch count: 6  
Document count: 6  
Index: geneve-ut-658

```python
library where host.os.type == "windows" and event.action == "load" and
  dll.name : ("libvlc.dll", "libvlccore.dll", "axvlc.dll") and
  not (
    dll.code_signature.subject_name : ("VideoLAN", "716F2E5E-A03A-486B-BC67-9B18474B9D51")
    and dll.code_signature.trusted == true
  )
```



### Potential Memory Seeking Activity

Branch count: 12  
Document count: 12  
Index: geneve-ut-659

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and (
  (process.name == "tail" and process.args == "-c") or
  (process.name == "cmp" and process.args == "-i") or
  (process.name in ("hexdump", "xxd") and process.args == "-s") or
  (process.name == "dd" and process.args : ("skip*", "seek*"))
)
```



### Potential Microsoft Office Sandbox Evasion

Branch count: 1  
Document count: 1  
Index: geneve-ut-661

```python
event.category:file and host.os.type:(macos and macos) and not event.type:deletion and file.name:~$*.zip
```



### Potential Modification of Accessibility Binaries

Branch count: 16  
Document count: 16  
Index: geneve-ut-662

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



### Potential Non-Standard Port HTTP/HTTPS connection

Branch count: 8  
Document count: 8  
Index: geneve-ut-667

```python
network where process.name : ("http", "https") and destination.port not in (80, 443) and event.action in (
  "connection_attempted", "ipv4_connection_attempt_event", "connection_accepted", "ipv4_connection_accept_event"
) and destination.ip != "127.0.0.1"
```



### Potential Non-Standard Port SSH connection

Branch count: 2  
Document count: 4  
Index: geneve-ut-668

```python
sequence by process.entity_id with maxspan=1m
  [process where event.action == "exec" and process.name:"ssh" and not process.parent.name in (
   "rsync", "pyznap", "git", "ansible-playbook", "scp", "pgbackrest", "git-lfs", "expect", "Sourcetree", "ssh-copy-id",
   "run"
   )
  ]
  [network where process.name:"ssh" and event.action in ("connection_attempted", "connection_accepted") and 
   destination.port != 22 and destination.ip != "127.0.0.1" and network.transport: "tcp"
  ]
```



### Potential OpenSSH Backdoor Logging Activity

Branch count: 84  
Document count: 84  
Index: geneve-ut-670

```python
file where host.os.type == "linux" and event.type == "change" and process.executable : ("/usr/sbin/sshd", "/usr/bin/ssh") and
  (
    (file.name : (".*", "~*", "*~") and not file.name : (".cache", ".viminfo", ".bash_history", ".google_authenticator",
      ".jelenv", ".csvignore", ".rtreport")) or
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



### Potential Outgoing RDP Connection by Unusual Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-671

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
Index: geneve-ut-674

```python
event.category:file and host.os.type:macos and not event.type:"deletion" and
 file.path:/Users/*/.atom/init.coffee and not process.name:(Atom or xpcproxy) and not user.name:root
```



### Potential Persistence via File Modification

Branch count: 83  
Document count: 83  
Index: geneve-ut-675

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

  // runtime control
  "/etc/rc.common", "/etc/rc.local",

  // init daemon
  "/etc/init.d/*",

  // passwd/sudoers/shadow
  "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/*",

  // Systemd udevd
  "/lib/udev/*", "/etc/udev/rules.d/*", "/usr/lib/udev/rules.d/*", "/run/udev/rules.d/*",

  // XDG/KDE autostart entries
  "/home/*/.config/autostart/*", "/root/.config/autostart/*", "/etc/xdg/autostart/*", "/usr/share/autostart/*",
  "/home/*/.kde/Autostart/*", "/root/.kde/Autostart/*",
  "/home/*/.kde4/Autostart/*", "/root/.kde4/Autostart/*",
  "/home/*/.kde/share/autostart/*", "/root/.kde/share/autostart/*",
  "/home/*/.kde4/share/autostart/*", "/root/.kde4/share/autostart/*",
  "/home/*/.local/share/autostart/*", "/root/.local/share/autostart/*",
  "/home/*/.config/autostart-scripts/*", "/root/.config/autostart-scripts/*"
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
Index: geneve-ut-676

```python
event.category:file and host.os.type:macos and not event.type:"deletion" and
 file.name:"com.apple.loginwindow.plist" and
 not process.name: (systemmigrationd or DesktopServicesHelper or diskmanagementd or rsync or launchd or cfprefsd or xpcproxy or ManagedClient or MCXCompositor or backupd or "iMazing Profile Editor" or storagekitd or CloneKitService)
```



### Potential Persistence via Periodic Tasks

Branch count: 3  
Document count: 3  
Index: geneve-ut-677

```python
event.category:file and host.os.type:macos and not event.type:"deletion" and
 file.path:(/private/etc/periodic/* or /private/etc/defaults/periodic.conf or /private/etc/periodic.conf)
```



### Potential Persistence via Time Provider Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-678

```python
registry where host.os.type == "windows" and event.type:"change" and
  registry.path: (
    "HKLM\\SYSTEM\\*ControlSet*\\Services\\W32Time\\TimeProviders\\*",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\W32Time\\TimeProviders\\*"
  ) and
  registry.data.strings:"*.dll" and
  not
  (
    process.executable : "?:\\Windows\\System32\\msiexec.exe" and
    registry.data.strings : "?:\\Program Files\\VMware\\VMware Tools\\vmwTimeProvider\\vmwTimeProvider.dll"
  )
```



### Potential Port Monitor or Print Processor Registration Abuse

Branch count: 8  
Document count: 8  
Index: geneve-ut-679

```python
registry where host.os.type == "windows" and event.type in ("creation", "change") and
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

Branch count: 46  
Document count: 46  
Index: geneve-ut-680

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
      "Boe Prox" or "jaredcatkinson" or
      "ChrisTruncer" or "monoxgas" or
      "TheRealWover" or "splinter_code"
  )
```



### Potential PowerShell HackTool Script by Function Names

Branch count: 696  
Document count: 696  
Index: geneve-ut-681

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
    "Invoke-SSHCommand" or "Find-ActiveUsersWMI" or
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
    "Invoke-WMIUpload" or "Invoke-WMIRemoteExtract" or "Invoke-winPEAS"
  ) and
  not powershell.file.script_block_text : (
    "sentinelbreakpoints" and "Set-PSBreakpoint"
  ) and
  not user.id : ("S-1-5-18" or "S-1-5-19")
```



### Potential Privacy Control Bypass via Localhost Secure Copy

Branch count: 4  
Document count: 4  
Index: geneve-ut-683

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
 process.name:"scp" and
 process.args:"StrictHostKeyChecking=no" and
 process.command_line:("scp *localhost:/*", "scp *127.0.0.1:/*") and
 not process.args:"vagrant@*127.0.0.1*"
```



### Potential Privacy Control Bypass via TCCDB Modification

Branch count: 2  
Document count: 2  
Index: geneve-ut-684

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name : "sqlite*" and
 process.args : "/*/Application Support/com.apple.TCC/TCC.db" and
 not process.parent.executable : "/Library/Bitdefender/AVP/product/bin/*"
```



### Potential Privilege Escalation through Writable Docker Socket

Branch count: 4  
Document count: 4  
Index: geneve-ut-685

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and 
(
  (process.name == "docker" and process.args : "run" and process.args : "-it"  and 
   process.args : ("unix://*/docker.sock", "unix://*/dockershim.sock")) or 
  (process.name == "socat" and process.args : ("UNIX-CONNECT:*/docker.sock", "UNIX-CONNECT:*/dockershim.sock"))
) and not user.Ext.real.id : "0" and not group.Ext.real.id : "0"
```



### Potential Privilege Escalation via CVE-2023-4911

Branch count: 1  
Document count: 5  
Index: geneve-ut-686

```python
sequence by host.id, process.parent.entity_id, process.executable with maxspan=5s
 [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and 
  process.env_vars : "*GLIBC_TUNABLES=glibc.*=glibc.*=*"] with runs=5
```



### Potential Privilege Escalation via Container Misconfiguration

Branch count: 1  
Document count: 1  
Index: geneve-ut-687

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
Index: geneve-ut-691

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
Index: geneve-ut-692

```python
file where host.os.type == "linux" and file.path : "/*GCONV_PATH*"
```



### Potential Privilege Escalation via Python cap_setuid

Branch count: 4  
Document count: 8  
Index: geneve-ut-693

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
Index: geneve-ut-694

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



### Potential Privilege Escalation via Sudoers File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-696

```python
event.category:process and event.type:start and process.args:(echo and *NOPASSWD*ALL*)
```



### Potential Privileged Escalation via SamAccountName Spoofing

Branch count: 1  
Document count: 1  
Index: geneve-ut-698

```python
iam where event.action == "renamed-user-account" and
  /* machine account name renamed to user like account name */
  winlog.event_data.OldTargetUserName : "*$" and not winlog.event_data.NewTargetUserName : "*$"
```



### Potential Process Injection from Malicious Document

Branch count: 18  
Document count: 18  
Index: geneve-ut-699

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



### Potential Protocol Tunneling via Chisel Client

Branch count: 36  
Document count: 72  
Index: geneve-ut-701

```python
sequence by host.id, process.entity_id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and 
   process.args == "client" and process.args : ("R*", "*:*", "*socks*", "*.*") and process.args_count >= 4 and 
   process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")]
  [network where host.os.type == "linux" and event.action == "connection_attempted" and event.type == "start" and 
   destination.ip != null and destination.ip != "127.0.0.1" and destination.ip != "::1" and 
   not process.name : (
     "python*", "php*", "perl", "ruby", "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk", "java", "telnet",
     "ftp", "socat", "curl", "wget", "dpkg", "docker", "dockerd", "yum", "apt", "rpm", "dnf", "ssh", "sshd")]
```



### Potential Protocol Tunneling via EarthWorm

Branch count: 1  
Document count: 1  
Index: geneve-ut-703

```python
process where host.os.type == "linux" and event.type == "start" and
 process.args : "-s" and process.args : "-d" and process.args : "rssocks"
```



### Potential Remote Credential Access via Registry

Branch count: 4  
Document count: 4  
Index: geneve-ut-708

```python
file where host.os.type == "windows" and
  event.action == "creation" and process.name : "svchost.exe" and
  file.Ext.header_bytes : "72656766*" and user.id : ("S-1-5-21-*", "S-1-12-1-*") and file.size >= 30000 and
  file.path : ("?:\\Windows\\system32\\*.tmp", "?:\\WINDOWS\\Temp\\*.tmp")
```



### Potential Remote Desktop Shadowing Activity

Branch count: 5  
Document count: 5  
Index: geneve-ut-709

```python
/* Identifies the modification of RDP Shadow registry or
  the execution of processes indicative of active shadow RDP session */

any where host.os.type == "windows" and
(
  (event.category == "registry" and
     registry.path : (
      "HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\Shadow",
      "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\Shadow"
    )
  ) or
  (event.category == "process" and event.type == "start" and
     (process.name : ("RdpSaUacHelper.exe", "RdpSaProxy.exe") and process.parent.name : "svchost.exe") or
     (process.pe.original_file_name : "mstsc.exe" and process.args : "/shadow:*")
  )
)
```



### Potential Remote Desktop Tunneling Detected

Branch count: 5  
Document count: 5  
Index: geneve-ut-710

```python
process where host.os.type == "windows" and event.type == "start" and
  /* RDP port and usual SSH tunneling related switches in command line */
  process.args : "*:3389" and
  process.args : ("-L", "-P", "-R", "-pw", "-ssh")
```



### Potential Remote File Execution via MSIEXEC

Branch count: 48  
Document count: 144  
Index: geneve-ut-711

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



### Potential Reverse Shell

Branch count: 864  
Document count: 1728  
Index: geneve-ut-712

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
Index: geneve-ut-713

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

Branch count: 32  
Document count: 32  
Index: geneve-ut-714

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and 
process.name in ("setsid", "nohup") and process.args : "*/dev/tcp/*0>&1*" and 
process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
```



### Potential Reverse Shell via Child

Branch count: 432  
Document count: 864  
Index: geneve-ut-715

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
Index: geneve-ut-716

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
   and not process.parent.args in (
     "/usr/share/java/jenkins.war", "/etc/remote-iot/services/remoteiot.jar",
     "/usr/lib64/NetExtender.jar", "/usr/lib/jenkins/jenkins.war"
   )] by process.parent.entity_id
```



### Potential SSH-IT SSH Worm Downloaded

Branch count: 40  
Document count: 40  
Index: geneve-ut-720

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name in ("curl", "wget") and process.args : (
  "https://thc.org/ssh-it/x", "http://nossl.segfault.net/ssh-it-deploy.sh", "https://gsocket.io/x",
  "https://thc.org/ssh-it/bs", "http://nossl.segfault.net/bs"
)
```



### Potential Secure File Deletion via SDelete Utility

Branch count: 1  
Document count: 1  
Index: geneve-ut-722

```python
file where host.os.type == "windows" and event.type == "change" and file.name : "*AAA.AAA"
```



### Potential Shadow Credentials added to AD Object

Branch count: 1  
Document count: 1  
Index: geneve-ut-723

```python
event.action:"Directory Service Changes" and event.code:"5136" and
 winlog.event_data.AttributeLDAPDisplayName:"msDS-KeyCredentialLink" and winlog.event_data.AttributeValue :B\:828* and
 not winlog.event_data.SubjectUserName: MSOL_*
```



### Potential SharpRDP Behavior

Branch count: 32  
Document count: 96  
Index: geneve-ut-725

```python
/* Incoming RDP followed by a new RunMRU string value set to cmd, powershell, taskmgr or tsclient, followed by process execution within 1m */

sequence by host.id with maxspan=1m
  [network where host.os.type == "windows" and event.type == "start" and process.name : "svchost.exe" and destination.port == 3389 and
   network.direction : ("incoming", "ingress") and network.transport == "tcp" and
   source.ip != "127.0.0.1" and source.ip != "::1"
  ]

  [registry where host.os.type == "windows" and process.name : "explorer.exe" and
   registry.path : ("HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\*") and
   registry.data.strings : ("cmd.exe*", "powershell.exe*", "taskmgr*", "\\\\tsclient\\*.exe\\*")
  ]

  [process where host.os.type == "windows" and event.type == "start" and
   (process.parent.name : ("cmd.exe", "powershell.exe", "taskmgr.exe") or process.args : ("\\\\tsclient\\*.exe")) and
   not process.name : "conhost.exe"
   ]
```



### Potential Shell via Wildcard Injection Detected

Branch count: 72  
Document count: 144  
Index: geneve-ut-726

```python
sequence by host.id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
    (process.name == "tar" and process.args : "--checkpoint=*" and process.args : "--checkpoint-action=*") or
    (process.name == "rsync" and process.args : "-e*") or
    (process.name == "zip" and process.args == "--unzip-command") )]  by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and 
     process.parent.name : ("tar", "rsync", "zip") and 
     process.name : ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")] by process.parent.entity_id
```



### Potential Sudo Hijacking

Branch count: 8  
Document count: 8  
Index: geneve-ut-730

```python
file where host.os.type == "linux" and event.action in ("creation", "rename") and
file.path in ("/usr/bin/sudo", "/bin/sudo") and not (
  file.Ext.original.path in ("/usr/bin/sudo", "/bin/sudo") or
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum", "/bin/dnf", "/usr/bin/dnf",
    "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic", "/bin/pacman", "/usr/bin/pacman",
    "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk", "/usr/local/sbin/apk", "/usr/bin/apt",
    "/usr/sbin/pacman", "/usr/bin/microdnf", "/usr/local/bin/dockerd", "/usr/local/bin/podman", "/usr/local/bin/dnf",
    "/kaniko/executor", "/proc/self/exe", "/usr/bin/apt-get", "/usr/bin/apt-cache", "/usr/bin/apt-mark"
  ) or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/var/lib/docker/*"
  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*")
)
```



### Potential Sudo Privilege Escalation via CVE-2019-14287

Branch count: 4  
Document count: 4  
Index: geneve-ut-731

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name == "sudo" and process.args == "-u#-1"
```



### Potential Sudo Token Manipulation via Process Injection

Branch count: 1  
Document count: 2  
Index: geneve-ut-732

```python
sequence by host.id, process.session_leader.entity_id with maxspan=15s
[ process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and 
  process.name == "gdb" and process.user.id != "0" and process.group.id != "0" ]
[ process where host.os.type == "linux" and event.action == "uid_change" and event.type == "change" and 
  process.name == "sudo" and process.user.id == "0" and process.group.id == "0" ]
```



### Potential Suspicious DebugFS Root Device Access

Branch count: 2  
Document count: 2  
Index: geneve-ut-734

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and 
process.name == "debugfs" and process.args : "/dev/sd*" and not process.args == "-R" and 
not user.Ext.real.id == "0" and not group.Ext.real.id == "0"
```



### Potential Suspicious File Edit

Branch count: 94  
Document count: 94  
Index: geneve-ut-735

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



### Potential Unauthorized Access via Wildcard Injection Detected

Branch count: 8  
Document count: 8  
Index: geneve-ut-736

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name in ("chown", "chmod") and process.args == "-R" and process.args : "--reference=*"
```



### Potential Upgrade of Non-interactive Shell

Branch count: 2  
Document count: 2  
Index: geneve-ut-737

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and (
  (process.name == "stty" and process.args == "raw" and process.args == "-echo" and process.args_count >= 3) or
  (process.name == "script" and process.args in ("-qc", "-c") and process.args == "/dev/null" and 
   process.args_count == 4)
)
```



### Potential Veeam Credential Access Command

Branch count: 6  
Document count: 6  
Index: geneve-ut-738

```python
process where host.os.type == "windows" and event.type == "start" and
  (
    (process.name : "sqlcmd.exe" or process.pe.original_file_name : "sqlcmd.exe") or
    process.args : ("Invoke-Sqlcmd", "Invoke-SqlExecute", "Invoke-DbaQuery", "Invoke-SqlQuery")
  ) and
  process.args : "*[VeeamBackup].[dbo].[Credentials]*"
```



### Potential WPAD Spoofing via DNS Record Creation

Branch count: 1  
Document count: 1  
Index: geneve-ut-739

```python
any where host.os.type == "windows" and event.action == "Directory Service Changes" and
    event.code == "5137" and winlog.event_data.ObjectDN : "DC=wpad,*"
```



### Potential Windows Error Manager Masquerading

Branch count: 8  
Document count: 16  
Index: geneve-ut-741

```python
sequence by host.id, process.entity_id with maxspan = 5s
  [process where host.os.type == "windows" and event.type:"start" and process.name : ("wermgr.exe", "WerFault.exe") and process.args_count == 1]
  [network where host.os.type == "windows" and process.name : ("wermgr.exe", "WerFault.exe") and network.protocol != "dns" and
    network.direction : ("outgoing", "egress") and destination.ip !="::1" and destination.ip !="127.0.0.1"
  ]
```



### Potential privilege escalation via CVE-2022-38028

Branch count: 2  
Document count: 2  
Index: geneve-ut-745

```python
file where host.os.type == "windows" and
           file.path : ("?:\\*\\Windows\\system32\\DriVerStoRe\\FiLeRePoSiToRy\\*\\MPDW-constraints.js",
                        "?:\\*\\Windows\\WinSxS\\amd64_microsoft-windows-printing-printtopdf_*\\MPDW-constraints.js")
```



### Potentially Successful MFA Bombing via Push Notifications

Branch count: 4  
Document count: 16  
Index: geneve-ut-746

```python
sequence by okta.actor.id with maxspan=10m
  [authentication where event.dataset == "okta.system" and event.module == "okta"
    and event.action == "user.mfa.okta_verify.deny_push"] with runs=3
  [authentication where event.dataset == "okta.system" and event.module == "okta"
    and (event.action : (
      "user.authentication.sso",
      "user.authentication.auth_via_mfa",
      "user.authentication.verify",
      "user.session.start") and okta.outcome.result == "SUCCESS")]
```



### Potentially Suspicious Process Started via tmux or screen

Branch count: 80  
Document count: 80  
Index: geneve-ut-747

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and 
process.parent.name in ("screen", "tmux") and process.name : (
  "nmap", "nc", "ncat", "netcat", "socat", "nc.openbsd", "ngrok", "ping", "java", "python*", "php*", "perl", "ruby",
  "lua*", "openssl", "telnet", "awk", "wget", "curl", "id"
  )
```



### PowerShell Invoke-NinjaCopy script

Branch count: 21  
Document count: 21  
Index: geneve-ut-748

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
Index: geneve-ut-750

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



### PowerShell Mailbox Collection Script

Branch count: 5  
Document count: 5  
Index: geneve-ut-752

```python
event.category:process and host.os.type:windows and
  (
   powershell.file.script_block_text : (
      "Microsoft.Office.Interop.Outlook" or
      "Interop.Outlook.olDefaultFolders" or
      "::olFolderInBox"
   ) or
   powershell.file.script_block_text : (
      "Microsoft.Exchange.WebServices.Data.Folder" or
      "Microsoft.Exchange.WebServices.Data.FileAttachment"
   )
  ) and not user.id : "S-1-5-18"
```



### PowerShell MiniDump Script

Branch count: 3  
Document count: 3  
Index: geneve-ut-753

```python
event.category:process and host.os.type:windows and powershell.file.script_block_text:(MiniDumpWriteDump or MiniDumpWithFullMemory or pmuDetirWpmuDiniM) and not user.id : "S-1-5-18"
```



### PowerShell PSReflect Script

Branch count: 9  
Document count: 9  
Index: geneve-ut-754

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

Branch count: 4  
Document count: 4  
Index: geneve-ut-755

```python
registry where host.os.type == "windows" and event.type == "change" and
    registry.path : (
        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging"
    ) and registry.data.strings : ("0", "0x00000000")
```



### PowerShell Suspicious Discovery Related Windows API Functions

Branch count: 24  
Document count: 24  
Index: geneve-ut-766

```python
event.category:process and host.os.type:windows and
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
    QueryServiceObjectSecurity or
    GetComputerNameEx or
    NetWkstaGetInfo or
    GetUserNameEx or
    NetUserEnum or
    NetUserGetInfo or
    NetGroupEnum or
    NetGroupGetInfo or
    NetGroupGetUsers or
    NetWkstaTransportEnum or
    NetServerGetInfo or
    LsaEnumerateTrustedDomains  or
    NetScheduleJobEnum or
    NetUserModalsGet
  )
```



### Privilege Escalation via CAP_SETUID/SETGID Capabilities

Branch count: 4  
Document count: 8  
Index: geneve-ut-772

```python
sequence by host.id, process.entity_id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name != null and
   (process.thread.capabilities.effective : "CAP_SET?ID" or process.thread.capabilities.permitted : "CAP_SET?ID") and 
   user.id != "0"]
  [process where host.os.type == "linux" and event.action == "uid_change" and event.type == "change" and 
   (process.thread.capabilities.effective : "CAP_SET?ID" or process.thread.capabilities.permitted : "CAP_SET?ID")
   and user.id == "0"]
```



### Privilege Escalation via GDB CAP_SYS_PTRACE

Branch count: 2  
Document count: 4  
Index: geneve-ut-773

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
Index: geneve-ut-774

```python
process where host.os.type == "windows" and event.type == "start" and
 (process.name : ("Cmd.Exe", "PowerShell.EXE") or ?process.pe.original_file_name in ("Cmd.Exe", "PowerShell.EXE")) and
 process.args : "echo" and process.args : ">" and process.args : "\\\\.\\pipe\\*"
```



### Privilege Escalation via Rogue Named Pipe Impersonation

Branch count: 1  
Document count: 1  
Index: geneve-ut-775

```python
file where host.os.type == "windows" and event.action : "Pipe Created*" and
 /* normal sysmon named pipe creation events truncate the pipe keyword */
  file.name : "\\*\\Pipe\\*"
```



### Privilege Escalation via Root Crontab File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-776

```python
event.category:file and host.os.type:macos and not event.type:deletion and
 file.path:/private/var/at/tabs/root and not process.executable:/usr/bin/crontab
```



### Privilege Escalation via SUID/SGID

Branch count: 426  
Document count: 426  
Index: geneve-ut-777

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  (process.user.id == "0" and process.real_user.id != "0") or 
  (process.group.id == "0" and process.real_group.id != "0")
) and (
  process.name in (
    "aa-exec", "ab", "agetty", "alpine", "ar", "arj", "arp", "as", "ascii-xfr", "ash", "aspell",
    "atobm", "awk", "base32", "base64", "basenc", "basez", "bash", "bc", "bridge", "busctl",
    "busybox", "bzip2", "cabal", "capsh", "cat", "choom", "chown", "chroot", "clamscan", "cmp",
    "column", "comm", "cp", "cpio", "cpulimit", "csh", "csplit", "csvtool", "cupsfilter", "curl",
    "cut", "dash", "date", "dd", "debugfs", "dialog", "diff", "dig", "distcc", "dmsetup", "docker",
    "dosbox", "ed", "efax", "elvish", "emacs", "env", "eqn", "espeak", "expand", "expect", "file",
    "find", "fish", "flock", "fmt", "fold", "gawk", "gcore", "gdb", "genie", "genisoimage", "gimp",
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
  process.name == "ip" and (
    (process.args == "-force" and process.args in ("-batch", "-b")) or (process.args == "exec")
  )
)
```



### Privilege Escalation via Windir Environment Variable

Branch count: 6  
Document count: 6  
Index: geneve-ut-778

```python
registry where host.os.type == "windows" and registry.path : (
    "HKEY_USERS\\*\\Environment\\windir",
    "HKEY_USERS\\*\\Environment\\systemroot",
    "HKU\\*\\Environment\\windir",
    "HKU\\*\\Environment\\systemroot",
    "\\REGISTRY\\USER\\*\\Environment\\windir",
    "\\REGISTRY\\USER\\*\\Environment\\systemroot"
    ) and
 not registry.data.strings : ("C:\\windows", "%SystemRoot%")
```



### Privileged Account Brute Force

Branch count: 1  
Document count: 5  
Index: geneve-ut-779

```python
sequence by winlog.computer_name, source.ip with maxspan=10s
  [authentication where event.action == "logon-failed" and winlog.logon.type : "Network" and
    source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1" and user.name : "*admin*" and

    /* noisy failure status codes often associated to authentication misconfiguration */
    not winlog.event_data.Status : ("0xC000015B", "0XC000005E", "0XC0000133", "0XC0000192")] with runs=5
```



### Process Activity via Compiled HTML File

Branch count: 7  
Document count: 7  
Index: geneve-ut-781

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "hh.exe" and
 process.name : ("mshta.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cscript.exe", "wscript.exe")
```



### Process Capability Enumeration

Branch count: 2  
Document count: 2  
Index: geneve-ut-782

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
process.name == "getcap" and process.args == "-r" and process.args == "/" and process.args_count == 3 and
user.id != "0"
```



### Process Capability Set via setcap Utility

Branch count: 2  
Document count: 2  
Index: geneve-ut-783

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
process.name == "setcap" and not (
  process.parent.executable == null or
  process.parent.executable : ("/var/lib/dpkg/*", "/var/lib/docker/*", "/tmp/newroot/*", "/var/tmp/newroot/*") or 
  process.parent.name in ("jem", "vzctl")
)
```



### Process Created with an Elevated Token

Branch count: 96  
Document count: 96  
Index: geneve-ut-785

```python
/* This rule is only compatible with Elastic Endpoint 8.4+ */

process where host.os.type == "windows" and event.action == "start" and

 /* CreateProcessWithToken and effective parent is a privileged MS native binary used as a target for token theft */
 user.id : "S-1-5-18"  and

 /* Token Theft target process usually running as service are located in one of the following paths */
 process.Ext.effective_parent.executable :
                ("?:\\Windows\\*.exe",
                 "?:\\Program Files\\*.exe",
                 "?:\\Program Files (x86)\\*.exe",
                 "?:\\ProgramData\\*") and

/* Ignores Utility Manager in Windows running in debug mode */
 not (process.Ext.effective_parent.executable : "?:\\Windows\\System32\\Utilman.exe" and
      process.parent.executable : "?:\\Windows\\System32\\Utilman.exe" and process.parent.args : "/debug") and

/* Ignores Windows print spooler service with correlation to Access Intelligent Form */
not (process.parent.executable : "?\\Windows\\System32\\spoolsv.exe" and
     process.executable: "?:\\Program Files*\\Access\\Intelligent Form\\*\\LaunchCreate.exe") and 

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
                "?:\\Windows\\System32\\DriverStore\\*") and

/* Ignores Windows binaries with a trusted signature and specific signature name */
 not (process.code_signature.trusted == true and
      process.code_signature.subject_name : 
                ("philandro Software GmbH", 
                 "Freedom Scientific Inc.", 
                 "TeamViewer Germany GmbH", 
                 "Projector.is, Inc.", 
                 "TeamViewer GmbH", 
                 "Cisco WebEx LLC", 
                 "Dell Inc"))
```



### Process Creation via Secondary Logon

Branch count: 2  
Document count: 4  
Index: geneve-ut-786

```python
sequence by winlog.computer_name with maxspan=1m

[authentication where event.action:"logged-in" and
 event.outcome == "success" and user.id : ("S-1-5-21-*", "S-1-12-1-*") and

 /* seclogon service */
 process.name == "svchost.exe" and
 winlog.event_data.LogonProcessName : "seclogo*" and source.ip == "::1" ] by winlog.event_data.TargetLogonId

[process where event.type == "start"] by winlog.event_data.TargetLogonId
```



### Process Discovery Using Built-in Tools

Branch count: 8  
Document count: 8  
Index: geneve-ut-787

```python
process where host.os.type == "windows" and event.type == "start" and
  (
    process.name :("PsList.exe", "qprocess.exe") or 
   (process.name : "powershell.exe" and process.args : ("*get-process*", "*Win32_Process*")) or 
   (process.name : "wmic.exe" and process.args : ("process", "*Win32_Process*")) or
   (process.name : "tasklist.exe" and not process.args : ("pid eq*")) or
   (process.name : "query.exe" and process.args : "process")
  ) and not user.id : "S-1-5-18"
```



### Process Discovery via Built-In Applications

Branch count: 8  
Document count: 8  
Index: geneve-ut-788

```python
process where event.type == "start" and event.action in ("exec", "exec_event") and process.name in (
  "ps", "pstree", "htop", "pgrep"
) and 
not process.parent.name in ("amazon-ssm-agent", "snap")
```



### Process Execution from an Unusual Directory

Branch count: 66  
Document count: 66  
Index: geneve-ut-789

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
 /* uncomment once in winlogbeat */
 /* and not (process.code_signature.subject_name == "Microsoft Corporation" and process.code_signature.trusted == true) */
```



### Process Injection - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-790

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:kernel_shellcode_event or endgame.event_subtype_full:kernel_shellcode_event)
```



### Process Injection - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-791

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:kernel_shellcode_event or endgame.event_subtype_full:kernel_shellcode_event)
```



### Process Injection by the Microsoft Build Engine

Branch count: 1  
Document count: 1  
Index: geneve-ut-792

```python
process.name:MSBuild.exe and host.os.type:windows and event.action:"CreateRemoteThread detected (rule: CreateRemoteThread)"
```



### Process Spawned from Message-of-the-Day (MOTD)

Branch count: 114  
Document count: 114  
Index: geneve-ut-793

```python
process where event.type == "start" and host.os.type == "linux" and event.action : ("exec", "exec_event") and
  process.parent.executable : "/etc/update-motd.d/*" and (
  (process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and (
    (process.args : ("-i", "-l")) or (process.parent.name == "socat" and process.parent.args : "*exec*"))) or
  (process.name : ("nc", "ncat", "netcat", "nc.openbsd") and process.args_count >= 3 and 
    not process.args : ("-*z*", "-*l*")) or
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
  (process.name : ("awk", "gawk", "mawk", "nawk") and process.args : "*/inet/tcp/*") or 
  (process.name in ("openssl", "telnet")) or
  (process.args : (
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



### Process Termination followed by Deletion

Branch count: 3  
Document count: 6  
Index: geneve-ut-795

```python
sequence by host.id with maxspan=5s
   [process where host.os.type == "windows" and event.type == "end" and
    process.code_signature.trusted != true and
    not process.executable : ("C:\\Windows\\SoftwareDistribution\\*.exe", "C:\\Windows\\WinSxS\\*.exe")
   ] by process.executable
   [file where host.os.type == "windows" and event.type == "deletion" and file.extension : ("exe", "scr", "com") and
    not process.executable :
             ("?:\\Program Files\\*.exe",
              "?:\\Program Files (x86)\\*.exe",
              "?:\\Windows\\System32\\svchost.exe",
              "?:\\Windows\\System32\\drvinst.exe") and
    not file.path : (
          "?:\\Program Files\\*.exe",
          "?:\\Program Files (x86)\\*.exe",
          "?:\\Windows\\Temp\\*\\DismHost.exe",
          "?:\\$WINDOWS.~BT\\Work\\*\\DismHost.exe",
          "?:\\$WinREAgent\\Scratch\\*\\DismHost.exe",
          "?:\\Windows\\tenable_mw_scan_*.exe",
          "?:\\Users\\*\\AppData\\Local\\Temp\\LogiUI\\Pak\\uninstall.exe"
    )
   ] by file.path
```



### Processes with Trailing Spaces

Branch count: 4  
Document count: 4  
Index: geneve-ut-796

```python
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and
process.name : "* "
```



### Program Files Directory Masquerading

Branch count: 1  
Document count: 1  
Index: geneve-ut-797

```python
process where host.os.type == "windows" and event.type == "start" and
  process.executable : "C:\\*Program*Files*\\*.exe" and
  not process.executable : (
        "?:\\Program Files\\*.exe",
        "?:\\Program Files (x86)\\*.exe",
        "?:\\Users\\*.exe",
        "?:\\ProgramData\\*.exe",
        "?:\\Windows\\Downloaded Program Files\\*.exe",
        "?:\\Windows\\Temp\\.opera\\????????????\\CProgram?FilesOpera*\\*.exe",
        "?:\\Windows\\Temp\\.opera\\????????????\\CProgram?Files?(x86)Opera*\\*.exe"
  )
```



### Prompt for Credentials with OSASCRIPT

Branch count: 12  
Document count: 12  
Index: geneve-ut-798

```python
process where event.action == "exec" and host.os.type == "macos" and
 process.name : "osascript" and process.args : "-e" and process.command_line : ("*osascript*display*dialog*password*", "*osascript*display*dialog*passphrase*") and
 not (process.parent.executable : "/usr/bin/sudo" and process.command_line : "*Encryption Key Escrow*") and
 not (process.command_line : "*-e with timeout of 3600 seconds*" and user.id == "0" and process.parent.executable : "/bin/bash") and
 not process.Ext.effective_parent.executable : ("/usr/local/jamf/*", 
                                                "/Applications/Karabiner-Elements.app/Contents/MacOS/Karabiner-Elements",
                                                "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                                                "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon",
                                                "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfManagementService.app/Contents/MacOS/JamfManagementService")
```



### ProxyChains Activity

Branch count: 4  
Document count: 4  
Index: geneve-ut-799

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name == "proxychains"
```



### PsExec Network Connection

Branch count: 1  
Document count: 2  
Index: geneve-ut-800

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



### Quarantine Attrib Removed by Unsigned or Untrusted Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-801

```python
file where event.action == "extended_attributes_delete" and host.os.type == "macos" and process.executable != null and
(process.code_signature.trusted == false or process.code_signature.exists == false) and not
process.executable : ("/usr/bin/xattr", 
                      "/System/*", 
                      "/private/tmp/KSInstallAction.*/*/Install Google Software Update.app/Contents/Helpers/ksinstall",
                      "/Applications/CEWE Fotoschau.app/Contents/MacOS/FotoPlus",
                      "/Applications/.com.bomgar.scc.*/Remote Support Customer Client.app/Contents/MacOS/sdcust") and not
file.path : "/private/var/folders/*"
```



### RDP Enabled via Registry

Branch count: 4  
Document count: 4  
Index: geneve-ut-804

```python
registry where host.os.type == "windows" and 
 event.type in ("creation", "change") and
  registry.path : "HKLM\\SYSTEM\\*ControlSet*\\Control\\Terminal Server\\fDenyTSConnections" and
  registry.data.strings : ("0", "0x00000000") and
  not process.executable : ("?:\\Windows\\System32\\SystemPropertiesRemote.exe", 
                            "?:\\Windows\\System32\\SystemPropertiesComputerName.exe", 
                            "?:\\Windows\\System32\\SystemPropertiesAdvanced.exe", 
                            "?:\\Windows\\System32\\SystemSettingsAdminFlows.exe", 
                            "?:\\Windows\\WinSxS\\*\\TiWorker.exe", 
                            "?:\\Windows\\system32\\svchost.exe")
```



### Ransomware - Detected - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-807

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:ransomware_event or endgame.event_subtype_full:ransomware_event)
```



### Ransomware - Prevented - Elastic Endgame

Branch count: 2  
Document count: 2  
Index: geneve-ut-808

```python
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:ransomware_event or endgame.event_subtype_full:ransomware_event)
```



### Registry Persistence via AppCert DLL

Branch count: 3  
Document count: 3  
Index: geneve-ut-814

```python
registry where host.os.type == "windows" and
/* uncomment once stable length(bytes_written_string) > 0 and */
  registry.path : (
    "HKLM\\SYSTEM\\*ControlSet*\\Control\\Session Manager\\AppCertDLLs\\*",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Session Manager\\AppCertDLLs\\*",
    "MACHINE\\SYSTEM\\*ControlSet*\\Control\\Session Manager\\AppCertDLLs\\*"
  )
```



### Registry Persistence via AppInit DLL

Branch count: 4  
Document count: 4  
Index: geneve-ut-815

```python
registry where host.os.type == "windows" and
  registry.path : (
     "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls",
     "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls",
     "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls",
     "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_Dlls"
  ) and
  not process.executable : (
     "?:\\Windows\\System32\\DriverStore\\FileRepository\\*\\Display.NvContainer\\NVDisplay.Container.exe",
     "?:\\Windows\\System32\\msiexec.exe",
     "?:\\Windows\\SysWOW64\\msiexec.exe",
     "?:\\Program Files\\Commvault\\Base\\cvd.exe",
     "?:\\Program Files\\Commvault\\ContentStore*\\Base\\cvd.exe",
     "?:\\Program Files (x86)\\Commvault\\Base\\cvd.exe",
     "?:\\Program Files (x86)\\Commvault\\ContentStore*\\Base\\cvd.exe",
     "?:\\Program Files\\NVIDIA Corporation\\Display.NvContainer\\NVDisplay.Container.exe"
  )
```



### Remote Desktop Enabled in Windows Firewall by Netsh

Branch count: 18  
Document count: 18  
Index: geneve-ut-817

```python
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "netsh.exe" or ?process.pe.original_file_name == "netsh.exe") and
 process.args : ("localport=3389", "RemoteDesktop", "group=\"remote desktop\"") and
 process.args : ("action=allow", "enable=Yes", "enable")
```



### Remote Execution via File Shares

Branch count: 36  
Document count: 72  
Index: geneve-ut-818

```python
sequence with maxspan=1m
  [file where host.os.type == "windows" and event.type in ("creation", "change") and 
   process.pid == 4 and (file.extension : "exe" or file.Ext.header_bytes : "4d5a*")] by host.id, file.path
  [process where host.os.type == "windows" and event.type == "start" and
    not (
      /* Veeam related processes */
      (
        process.name : (
          "VeeamGuestHelper.exe", "VeeamGuestIndexer.exe", "VeeamAgent.exe", "VeeamLogShipper.exe", "Veeam.VSS.Sharepoint2010.exe"
        ) and process.code_signature.trusted == true and process.code_signature.subject_name : "Veeam Software Group GmbH"
      ) or
      /* PDQ related processes */
      (
        process.name : (
          "PDQInventoryScanner.exe", "PDQInventoryMonitor.exe", "PDQInventory-Scanner-?.exe", "PDQInventoryWakeCommand-?.exe"
        ) and process.code_signature.trusted == true and process.code_signature.subject_name : "PDQ.com Corporation"
      )
    )
  ] by host.id, process.executable
```



### Remote File Copy to a Hidden Share

Branch count: 13  
Document count: 13  
Index: geneve-ut-819

```python
process where host.os.type == "windows" and event.type == "start" and
  (
    process.name : ("cmd.exe", "powershell.exe", "xcopy.exe") and
    process.args : ("copy*", "move*", "cp", "mv") or
    process.name : "robocopy.exe"
  ) and process.args : "*\\\\*\\*$*"
```



### Remote File Copy via TeamViewer

Branch count: 22  
Document count: 22  
Index: geneve-ut-820

```python
file where host.os.type == "windows" and event.type == "creation" and process.name : "TeamViewer.exe" and
  file.extension : ("exe", "dll", "scr", "com", "bat", "ps1", "vbs", "vbe", "js", "wsh", "hta") and
  not 
  (
    file.path : (
      "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\*.js",
      "?:\\Users\\*\\AppData\\Local\\Temp\\TeamViewer\\update.exe",
      "?:\\Users\\*\\AppData\\Local\\Temp\\?\\TeamViewer\\update.exe"
    ) and process.code_signature.trusted == true
  )
```



### Remote File Download via Desktopimgdownldr Utility

Branch count: 2  
Document count: 2  
Index: geneve-ut-821

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "desktopimgdownldr.exe" or ?process.pe.original_file_name == "desktopimgdownldr.exe") and
  process.args : "/lockscreenurl:http*"
```



### Remote File Download via MpCmdRun

Branch count: 2  
Document count: 2  
Index: geneve-ut-822

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "MpCmdRun.exe" or ?process.pe.original_file_name == "MpCmdRun.exe") and
   process.args : "-DownloadFile" and process.args : "-url" and process.args : "-path"
```



### Remote File Download via PowerShell

Branch count: 12  
Document count: 24  
Index: geneve-ut-823

```python
sequence by process.entity_id with maxspan=30s

[network where host.os.type == "windows" and
  process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and network.protocol == "dns" and
   not dns.question.name : (
          "localhost", "*.microsoft.com", "*.azureedge.net", "*.powershellgallery.com",
          "*.windowsupdate.com", "metadata.google.internal", "dist.nuget.org",
          "artifacts.elastic.co", "*.digicert.com", "packages.chocolatey.org",
          "outlook.office365.com"
       ) and not user.id : "S-1-5-18"]
[file where host.os.type == "windows" and event.type == "creation" and
  process.name : "powershell.exe" and file.extension : ("exe", "dll", "ps1", "bat") and
  not file.name : "__PSScriptPolicy*.ps1"]
```



### Remote File Download via Script Interpreter

Branch count: 8  
Document count: 16  
Index: geneve-ut-824

```python
sequence by host.id, process.entity_id
  [network where host.os.type == "windows" and process.name : ("wscript.exe", "cscript.exe") and network.protocol != "dns" and
   network.direction : ("outgoing", "egress") and network.type == "ipv4" and destination.ip != "127.0.0.1"
  ]
  [file where host.os.type == "windows" and event.type == "creation" and file.extension : ("exe", "dll")]
```



### Remote SSH Login Enabled via systemsetup Command

Branch count: 2  
Document count: 2  
Index: geneve-ut-825

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:systemsetup and
 process.args:("-setremotelogin" and on) and
 not process.parent.executable : /usr/local/jamf/bin/jamf
```



### Remote Scheduled Task Creation

Branch count: 2  
Document count: 4  
Index: geneve-ut-826

```python
/* Task Scheduler service incoming connection followed by TaskCache registry modification  */

sequence by host.id, process.entity_id with maxspan = 1m
   [network where host.os.type == "windows" and process.name : "svchost.exe" and
   network.direction : ("incoming", "ingress") and source.port >= 49152 and destination.port >= 49152 and
   source.ip != "127.0.0.1" and source.ip != "::1"
   ]
   [registry where host.os.type == "windows" and registry.path : "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions"]
```



### Remote Scheduled Task Creation via RPC

Branch count: 1  
Document count: 1  
Index: geneve-ut-827

```python
iam where event.action == "scheduled-task-created" and 
 winlog.event_data.RpcCallClientLocality : "0" and winlog.event_data.ClientProcessId : "0"
```



### Remote Windows Service Installed

Branch count: 1  
Document count: 2  
Index: geneve-ut-829

```python
sequence by winlog.logon.id, winlog.computer_name with maxspan=1m
[authentication where event.action == "logged-in" and winlog.logon.type : "Network" and
event.outcome=="success" and source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1"]
[iam where event.action == "service-installed" and
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
Index: geneve-ut-830

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
Index: geneve-ut-831

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



### Renamed AutoIt Scripts Interpreter

Branch count: 1  
Document count: 1  
Index: geneve-ut-832

```python
process where host.os.type == "windows" and event.type == "start" and
  process.pe.original_file_name : "AutoIt*.exe" and not process.name : "AutoIt*.exe"
```



### Root Network Connection via GDB CAP_SYS_PTRACE

Branch count: 2  
Document count: 4  
Index: geneve-ut-834

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
Index: geneve-ut-835

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



### Route53 Resolver Query Log Configuration Deleted

Branch count: 1  
Document count: 1  
Index: geneve-ut-836

```python
event.dataset:aws.cloudtrail and event.provider: route53resolver.amazonaws.com
    and event.action: DeleteResolverQueryLogConfig and event.outcome: success
```



### SIP Provider Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-837

```python
registry where host.os.type == "windows" and event.type:"change" and
  registry.path: (
    "*\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllPutSignedDataMsg\\{*}\\Dll",
    "*\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllPutSignedDataMsg\\{*}\\Dll",
    "*\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{*}\\$Dll",
    "*\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{*}\\$Dll"
    ) and
  registry.data.strings:"*.dll"
```



### SMTP on Port 26/TCP

Branch count: 4  
Document count: 4  
Index: geneve-ut-839

```python
(event.dataset: (network_traffic.flow or zeek.smtp) or event.category:(network or network_traffic)) and network.transport:tcp and destination.port:26
```



### SSH Authorized Keys File Modified Inside a Container

Branch count: 6  
Document count: 6  
Index: geneve-ut-841

```python
file where container.id:"*" and
  event.type in ("change", "creation") and file.name: ("authorized_keys", "authorized_keys2", "sshd_config")
```



### SSH Connection Established Inside A Running Container

Branch count: 2  
Document count: 2  
Index: geneve-ut-842

```python
process where container.id: "*" and event.type == "start" and 

/* use of sshd to enter a container*/
process.entry_leader.entry_meta.type: "sshd"  and 

/* process is the initial process run in a container or start of a new session*/
(process.entry_leader.same_as_process== true or process.session_leader.same_as_process== true) and 

/* interactive process*/
process.interactive== true
```



### SSH Key Generated via ssh-keygen

Branch count: 6  
Document count: 6  
Index: geneve-ut-843

```python
file where host.os.type == "linux" and event.action in ("creation", "file_create_event") and
process.executable == "/usr/bin/ssh-keygen" and file.path : ("/home/*/.ssh/*", "/root/.ssh/*", "/etc/ssh/*") and
not file.name : "known_hosts.*"
```



### SSH Process Launched From Inside A Container

Branch count: 6  
Document count: 6  
Index: geneve-ut-844

```python
process where container.id: "*" and event.type== "start" and
event.action in ("fork", "exec") and event.action != "end" and 
process.name: ("sshd", "ssh", "autossh")
```



### SUID/SGUID Enumeration Detected

Branch count: 36  
Document count: 36  
Index: geneve-ut-847

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
Index: geneve-ut-849

```python
sequence by host.id with maxspan = 30s
  [any where host.os.type == "windows" and 
    (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
    (?dll.name : "taskschd.dll" or file.name : "taskschd.dll") and
    process.name : ("cscript.exe", "wscript.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe")]
  [registry where host.os.type == "windows" and registry.path : (
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\*\\Actions")]
```



### Scheduled Tasks AT Command Enabled

Branch count: 4  
Document count: 4  
Index: geneve-ut-851

```python
registry where host.os.type == "windows" and
  registry.path : (
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Configuration\\EnableAt",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Configuration\\EnableAt"
  ) and registry.data.strings : ("1", "0x00000001")
```



### ScreenConnect Server Spawning Suspicious Processes

Branch count: 9  
Document count: 9  
Index: geneve-ut-852

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "ScreenConnect.Service.exe" and
  (process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "csc.exe") or
  ?process.pe.original_file_name in ("cmd.exe", "powershell.exe", "pwsh.dll", "powershell_ise.exe"))
```



### Screensaver Plist File Modified by Unexpected Process

Branch count: 27  
Document count: 27  
Index: geneve-ut-853

```python
file where host.os.type == "macos" and event.type != "deletion" and
  file.name: "com.apple.screensaver.*.plist" and
   file.path : (
      "/Users/*/Library/Preferences/ByHost/*",
      "/Library/Managed Preferences/*",
      "/System/Library/Preferences/*"
      ) and
  (
    process.code_signature.trusted == false or
    process.code_signature.exists == false or

    /* common script interpreters and abused native macOS bins */
    process.name : (
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
  not process.executable : (
    "/usr/sbin/cfprefsd",
    "/usr/libexec/xpcproxy",
    "/System/Library/CoreServices/ManagedClient.app/Contents/Resources/MCXCompositor",
    "/System/Library/CoreServices/ManagedClient.app/Contents/MacOS/ManagedClient"
    )
```



### SeDebugPrivilege Enabled by a Suspicious Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-854

```python
any where host.os.type == "windows" and event.provider: "Microsoft-Windows-Security-Auditing" and
 event.action : "Token Right Adjusted Events" and

 winlog.event_data.EnabledPrivilegeList : "SeDebugPrivilege" and

 /* exclude processes with System Integrity  */
 not winlog.event_data.SubjectUserSid : ("S-1-5-18", "S-1-5-19", "S-1-5-20") and

 not winlog.event_data.ProcessName :
         ("?:\\Windows\\System32\\msiexec.exe",
          "?:\\Windows\\SysWOW64\\msiexec.exe",
          "?:\\Windows\\System32\\lsass.exe",
          "?:\\Windows\\WinSxS\\*",
          "?:\\Program Files\\*",
          "?:\\Program Files (x86)\\*",
          "?:\\Windows\\System32\\MRT.exe",
          "?:\\Windows\\System32\\cleanmgr.exe",
          "?:\\Windows\\System32\\taskhostw.exe",
          "?:\\Windows\\System32\\mmc.exe",
          "?:\\Users\\*\\AppData\\Local\\Temp\\*-*\\DismHost.exe",
          "?:\\Windows\\System32\\auditpol.exe",
          "?:\\Windows\\System32\\wbem\\WmiPrvSe.exe",
          "?:\\Windows\\SysWOW64\\wbem\\WmiPrvSe.exe")
```



### Searching for Saved Credentials via VaultCmd

Branch count: 2  
Document count: 2  
Index: geneve-ut-855

```python
process where host.os.type == "windows" and event.type == "start" and
  (?process.pe.original_file_name:"vaultcmd.exe" or process.name:"vaultcmd.exe") and
  process.args:"/list*"
```



### Security Software Discovery using WMIC

Branch count: 2  
Document count: 2  
Index: geneve-ut-856

```python
process where host.os.type == "windows" and event.type == "start" and
(process.name : "wmic.exe" or ?process.pe.original_file_name : "wmic.exe") and
process.args : "/namespace:\\\\root\\SecurityCenter2" and process.args : "Get"
```



### Security Software Discovery via Grep

Branch count: 116  
Document count: 116  
Index: geneve-ut-857

```python
process where event.type == "start" and
process.name : "grep" and user.id != "0" and
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
          "elastic-endpoint*"
          ) and
   not (
     (process.args : "Avast" and process.args : "Passwords") or
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



### Sensitive Files Compression Inside A Container

Branch count: 270  
Document count: 270  
Index: geneve-ut-860

```python
process where container.id: "*" and event.type== "start" and 

/*account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg*/  
(process.name: ("zip", "tar", "gzip", "hdiutil", "7z") or process.args: ("zip", "tar", "gzip", "hdiutil", "7z"))
and process.args: ( 
"/root/.ssh/id_rsa", 
"/root/.ssh/id_rsa.pub", 
"/root/.ssh/id_ed25519", 
"/root/.ssh/id_ed25519.pub", 
"/root/.ssh/authorized_keys", 
"/root/.ssh/authorized_keys2", 
"/root/.ssh/known_hosts", 
"/root/.bash_history", 
"/etc/hosts", 
"/home/*/.ssh/id_rsa", 
"/home/*/.ssh/id_rsa.pub", 
"/home/*/.ssh/id_ed25519",
"/home/*/.ssh/id_ed25519.pub",
"/home/*/.ssh/authorized_keys",
"/home/*/.ssh/authorized_keys2",
"/home/*/.ssh/known_hosts",
"/home/*/.bash_history",
"/root/.aws/credentials",
"/root/.aws/config",
"/home/*/.aws/credentials",
"/home/*/.aws/config",
"/root/.docker/config.json",
"/home/*/.docker/config.json",
"/etc/group",
"/etc/passwd",
"/etc/shadow",
"/etc/gshadow")
```



### Sensitive Keys Or Passwords Searched For Inside A Container

Branch count: 60  
Document count: 60  
Index: geneve-ut-861

```python
process where container.id: "*" and event.type== "start" and
((
/*account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg*/  
  (process.name in ("grep", "egrep", "fgrep") or process.args in ("grep", "egrep", "fgrep")) 
    and process.args : ("*BEGIN PRIVATE*", "*BEGIN OPENSSH PRIVATE*", "*BEGIN RSA PRIVATE*", 
"*BEGIN DSA PRIVATE*", "*BEGIN EC PRIVATE*", "*pass*", "*ssh*", "*user*")
) 
or 
(
/*account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg*/
  (process.name in ("find", "locate", "mlocate") or process.args in ("find", "locate", "mlocate")) 
    and process.args : ("*id_rsa*", "*id_dsa*")
))
```



### Sensitive Privilege SeEnableDelegationPrivilege assigned to a User

Branch count: 1  
Document count: 1  
Index: geneve-ut-862

```python
event.action:"Authorization Policy Change" and event.code:4704 and
  winlog.event_data.PrivilegeList:"SeEnableDelegationPrivilege"
```



### Service Command Lateral Movement

Branch count: 16  
Document count: 32  
Index: geneve-ut-863

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
Index: geneve-ut-864

```python
/* This rule is not compatible with Sysmon due to user.id issues */

process where host.os.type == "windows" and event.type == "start" and
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
Index: geneve-ut-865

```python
sequence by winlog.computer_name with maxspan=5m
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



### Service Disabled via Registry Modification

Branch count: 8  
Document count: 8  
Index: geneve-ut-866

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
Index: geneve-ut-867

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
Index: geneve-ut-868

```python
process where event.type == "start" and process.name : "sc.exe" and
  process.args : "*config*" and process.args : "*binPath*"
```



### Setcap setuid/setgid Capability Set

Branch count: 2  
Document count: 2  
Index: geneve-ut-869

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and 
process.name == "setcap" and process.args : "cap_set?id+ep" and not process.parent.name in ("jem", "vzctl")
```



### SharePoint Malware File Upload

Branch count: 1  
Document count: 1  
Index: geneve-ut-870

```python
event.dataset:o365.audit and event.provider:SharePoint and event.code:SharePointFileOperation and event.action:FileMalwareDetected
```



### Shell Configuration Creation or Modification

Branch count: 240  
Document count: 240  
Index: geneve-ut-872

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and file.path : (
  // system-wide configurations
  "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/zsh/*",
  "/etc/csh.cshrc", "/etc/csh.login", "/etc/fish/config.fish", "/etc/ksh.kshrc",
  // root and user configurations
  "/home/*/.profile", "/home/*/.bashrc", "/home/*/.bash_login", "/home/*/.bash_logout",
  "/root/.profile", "/root/.bashrc", "/root/.bash_login", "/root/.bash_logout",
  "/home/*/.zprofile", "/home/*/.zshrc", "/root/.zprofile", "/root/.zshrc",
  "/home/*/.cshrc", "/home/*/.login", "/home/*/.logout", "/root/.cshrc", "/root/.login", "/root/.logout",
  "/home/*/.config/fish/config.fish", "/root/.config/fish/config.fish",
  "/home/*/.kshrc", "/root/.kshrc"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/sbin/adduser", "/usr/sbin/useradd", "/usr/local/bin/dockerd"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```



### Shell Execution via Apple Scripting

Branch count: 72  
Document count: 144  
Index: geneve-ut-873

```python
sequence by host.id with maxspan=5s
 [process where host.os.type == "macos" and event.type in ("start", "process_started", "info") and process.name == "osascript" and process.args : "-e"] by process.entity_id
 [process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name : ("sh", "bash", "zsh") and process.args == "-c" and process.args : ("*curl*", "*pbcopy*", "*http*", "*chmod*")] by process.parent.entity_id
```



### Shortcut File Written or Modified on Startup Folder

Branch count: 162  
Document count: 162  
Index: geneve-ut-874

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
Index: geneve-ut-875

```python
process where host.os.type == "windows" and event.type == "start"
    and process.name : "control.exe" and process.parent.name : "WorkFolders.exe"
    and not process.executable : ("?:\\Windows\\System32\\control.exe", "?:\\Windows\\SysWOW64\\control.exe")
```



### SoftwareUpdate Preferences Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-876

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:defaults and
 process.args:(write and "-bool" and (com.apple.SoftwareUpdate or /Library/Preferences/com.apple.SoftwareUpdate.plist) and not (TRUE or true))
```



### SolarWinds Process Disabling Services via Registry

Branch count: 28  
Document count: 28  
Index: geneve-ut-877

```python
registry where host.os.type == "windows" and registry.path : (
    "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\Start",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\*\\Start"
  ) and
  registry.data.strings : ("4", "0x00000004") and
  process.name : (
      "SolarWinds.BusinessLayerHost*.exe",
      "ConfigurationWizard*.exe",
      "NetflowDatabaseMaintenance*.exe",
      "NetFlowService*.exe",
      "SolarWinds.Administration*.exe",
      "SolarWinds.Collector.Service*.exe",
      "SolarwindsDiagnostics*.exe")
```



### Startup Folder Persistence via Unsigned Process

Branch count: 12  
Document count: 24  
Index: geneve-ut-891

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
Index: geneve-ut-892

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



### Statistical Model Detected C2 Beaconing Activity

Branch count: 1  
Document count: 1  
Index: geneve-ut-895

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
Index: geneve-ut-896

```python
beacon_stats.beaconing_score: 3
```



### Stolen Credentials Used to Login to Okta Account After MFA Reset

Branch count: 2  
Document count: 6  
Index: geneve-ut-897

```python
sequence by user.name with maxspan=12h
    [any where host.os.type == "windows" and signal.rule.threat.tactic.name == "Credential Access"]
    [any where event.dataset == "okta.system" and okta.event_type == "user.mfa.factor.update"]
    [any where event.dataset == "okta.system" and okta.event_type: ("user.session.start", "user.authentication*")]
```



### Sublime Plugin or Application Script Modification

Branch count: 4  
Document count: 4  
Index: geneve-ut-898

```python
file where host.os.type == "macos" and event.type in ("change", "creation") and file.extension : "py" and
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



### Sudo Command Enumeration Detected

Branch count: 8  
Document count: 8  
Index: geneve-ut-899

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and 
process.name == "sudo" and process.args == "-l" and process.args_count == 2 and
process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and 
not group.Ext.real.id : "0" and not user.Ext.real.id : "0" and not process.args == "dpkg"
```



### Suspicious .NET Code Compilation

Branch count: 16  
Document count: 16  
Index: geneve-ut-902

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("csc.exe", "vbc.exe") and
  process.parent.name : ("wscript.exe", "mshta.exe", "cscript.exe", "wmic.exe", "svchost.exe", "rundll32.exe", "cmstp.exe", "regsvr32.exe")
```



### Suspicious .NET Reflection via PowerShell

Branch count: 8  
Document count: 8  
Index: geneve-ut-903

```python
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "[System.Reflection.Assembly]::Load" or
    "[Reflection.Assembly]::Load"
  ) and
  not powershell.file.script_block_text : (
        ("CommonWorkflowParameters" or "RelatedLinksHelpInfo") and
        "HelpDisplayStrings"
  ) and
  not (powershell.file.script_block_text :
        ("Get-SolutionFiles" or "Get-VisualStudio" or "Select-MSBuildPath") and
        file.name : "PathFunctions.ps1"
  ) and
  not user.id : "S-1-5-18"
```



### Suspicious /proc/maps Discovery

Branch count: 16  
Document count: 16  
Index: geneve-ut-904

```python
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name in ("cat", "grep") and process.args : "/proc/*/maps" and process.entry_leader.name in (
  "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish"
)
```



### Suspicious APT Package Manager Execution

Branch count: 152  
Document count: 304  
Index: geneve-ut-905

```python
sequence by host.id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name == "apt" and process.args == "-c" and process.name in (
     "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish"
   )
  ] by process.entity_id
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name : (
     "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "python*", "php*",
     "perl", "ruby", "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk"
   )
  ] by process.parent.entity_id
```



### Suspicious APT Package Manager Network Connection

Branch count: 8  
Document count: 16  
Index: geneve-ut-906

```python
sequence by host.id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name == "apt" and process.args == "-c" and process.name in (
     "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish"
    )
  ] by process.entity_id
  [network where host.os.type == "linux" and event.action == "connection_attempted" and event.type == "start"
  ] by process.parent.entity_id
```



### Suspicious Activity Reported by Okta User

Branch count: 1  
Document count: 1  
Index: geneve-ut-908

```python
event.dataset:okta.system and event.action:user.account.report_suspicious_activity_by_enduser
```



### Suspicious Antimalware Scan Interface DLL

Branch count: 2  
Document count: 2  
Index: geneve-ut-909

```python
file where host.os.type == "windows" and event.type != "deletion" and file.path != null and
 file.name : ("amsi.dll", "amsi") and not file.path : ("?:\\Windows\\system32\\amsi.dll", "?:\\Windows\\Syswow64\\amsi.dll", "?:\\$WINDOWS.~BT\\NewOS\\Windows\\WinSXS\\*", "?:\\$WINDOWS.~BT\\NewOS\\Windows\\servicing\\LCU\\*", "?:\\$WINDOWS.~BT\\Work\\*\\*", "?:\\Windows\\SoftwareDistribution\\Download\\*")
```



### Suspicious Automator Workflows Execution

Branch count: 2  
Document count: 4  
Index: geneve-ut-910

```python
sequence by host.id with maxspan=30s
 [process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name == "automator"]
 [network where host.os.type == "macos" and process.name:"com.apple.automator.runner"]
```



### Suspicious Browser Child Process

Branch count: 182  
Document count: 182  
Index: geneve-ut-911

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  process.parent.name : ("Google Chrome", "Google Chrome Helper*", "firefox", "Opera", "Safari", "com.apple.WebKit.WebContent", "Microsoft Edge") and
  process.name : ("sh", "bash", "dash", "ksh", "tcsh", "zsh", "curl", "wget", "python*", "perl*", "php*", "osascript", "pwsh") and
  process.command_line != null and
  not process.command_line : "*/Library/Application Support/Microsoft/MAU*/Microsoft AutoUpdate.app/Contents/MacOS/msupdate*" and
  not process.args :
    (
      "hw.model",
      "IOPlatformExpertDevice",
      "/Volumes/Google Chrome/Google Chrome.app/Contents/Frameworks/*/Resources/install.sh",
      "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/*/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)",
      "/Applications/Firefox.app/Contents/MacOS/plugin-container.app/Contents/MacOS/plugin-container",
      "--defaults-torrc",
      "*Chrome.app",
      "Framework.framework/Versions/*/Resources/keystone_promote_preflight.sh",
      "/Users/*/Library/Application Support/Google/Chrome/recovery/*/ChromeRecovery",
      "$DISPLAY",
      "*GIO_LAUNCHED_DESKTOP_FILE_PID=$$*",
      "/opt/homebrew/*",
      "/usr/local/*brew*"
    )
```



### Suspicious Calendar File Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-912

```python
event.category:file and host.os.type:macos and event.action:modification and
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
Index: geneve-ut-913

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "certutil.exe" or ?process.pe.original_file_name == "CertUtil.exe") and
  process.args : ("?decode", "?encode", "?urlcache", "?verifyctl", "?encodehex", "?decodehex", "?exportPFX")
```



### Suspicious Child Process of Adobe Acrobat Reader Update Service

Branch count: 2  
Document count: 2  
Index: geneve-ut-914

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and
  process.parent.name:com.adobe.ARMDC.SMJobBlessHelper and
  user.name:root and
  not process.executable: (/Library/PrivilegedHelperTools/com.adobe.ARMDC.SMJobBlessHelper or
                           /usr/bin/codesign or
                           /private/var/folders/zz/*/T/download/ARMDCHammer or
                           /usr/sbin/pkgutil or
                           /usr/bin/shasum or
                           /usr/bin/perl* or
                           /usr/sbin/spctl or
                           /usr/sbin/installer or
                           /usr/bin/csrutil)
```



### Suspicious Cmd Execution via WMI

Branch count: 2  
Document count: 2  
Index: geneve-ut-915

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "WmiPrvSE.exe" and process.name : "cmd.exe" and
 process.args : "\\\\127.0.0.1\\*" and process.args : ("2>&1", "1>")
```



### Suspicious Communication App Child Process

Branch count: 60  
Document count: 60  
Index: geneve-ut-916

```python
process where host.os.type == "windows" and event.type == "start" and
  (
    /* Slack */
    (process.parent.name : "slack.exe" and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Island\\Island\\Application\\Island.exe",
            "?:\\Users\\*\\AppData\\Roaming\\Zoom\\bin*\\Zoom.exe",
            "?:\\Windows\\System32\\rundll32.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
            "?:\\Windows\\System32\\notepad.exe",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Windows\\SysWOW64\\WerFault.exe",
            "?:\\Users\\*\\AppData\\Local\\Programs\\Opera\\opera.exe"
          ) and process.code_signature.trusted == true  
        ) or
        (
          process.code_signature.subject_name : (
            "Slack Technologies, Inc.",
            "Slack Technologies, LLC"
          ) and process.code_signature.trusted == true
        ) or
        (
          (process.name : "powershell.exe" and process.command_line : "powershell.exe -c Invoke-WebRequest -Uri https://slackb.com/*") or
          (process.name : "cmd.exe" and process.command_line : "C:\\WINDOWS\\system32\\cmd.exe /d /s /c \"%windir%\\System32\\rundll32.exe User32.dll,SetFocus 0\"")
        )
      )
    ) or

    /* WebEx */
    (process.parent.name : ("CiscoCollabHost.exe", "WebexHost.exe") and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
            "?:\\Users\\*\\AppData\\Local\\Programs\\Opera\\opera.exe"
          ) and process.code_signature.trusted == true  
        ) or
        (
          process.code_signature.subject_name : (
            "Cisco Systems, Inc.",
            "Cisco WebEx LLC",
            "Cisco Systems Inc."
          ) and process.code_signature.trusted == true
        )
      )
    ) or

    /* Teams */
    (process.parent.name : "Teams.exe" and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Windows\\SysWOW64\\WerFault.exe",
            "?:\\Windows\\BrowserCore\\BrowserCore.exe",
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe"
          ) and process.code_signature.trusted == true  
        ) or
        (
          process.code_signature.subject_name : (
            "Microsoft Corporation",
            "Microsoft 3rd Party Application Component"
          ) and process.code_signature.trusted == true
        ) or
        (
          (process.name : "taskkill.exe" and process.args : "Teams.exe")
        )
      )
    ) or

    /* Discord */
    (process.parent.name : "Discord.exe" and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Windows\\System32\\reg.exe",
            "?:\\Windows\\SysWOW64\\reg.exe",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Windows\\SysWOW64\\WerFault.exe"
          ) and process.code_signature.trusted == true  
        ) or
        (
          process.code_signature.subject_name : (
            "Discord Inc."
          ) and process.code_signature.trusted == true
        ) or
        (
          process.name : "cmd.exe" and 
          (
            process.command_line : (
              "C:\\WINDOWS\\system32\\cmd.exe /d /s /c \"chcp\"",
              "C:\\WINDOWS\\system32\\cmd.exe /q /d /s /c \"C:\\Program^ Files\\NVIDIA^ Corporation\\NVSMI\\nvidia-smi.exe\""
            ) or
            process.args : (
              "C:\\WINDOWS/System32/nvidia-smi.exe",
              "C:\\WINDOWS\\System32\\nvidia-smi.exe",
              "C:\\Windows\\System32\\DriverStore\\FileRepository/*/nvidia-smi.exe*"
            )
          )
        )
      )
    ) or

    /* WhatsApp */
    (process.parent.name : "Whatsapp.exe" and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Windows\\System32\\reg.exe",
            "?:\\Windows\\SysWOW64\\reg.exe"
          ) and process.code_signature.trusted == true  
        ) or
        (
          process.code_signature.subject_name : (
            "WhatsApp LLC",
            "WhatsApp, Inc",
            "24803D75-212C-471A-BC57-9EF86AB91435"
          ) and process.code_signature.trusted == true
        ) or
        (
          (process.name : "cmd.exe" and process.command_line : "C:\\Windows\\system32\\cmd.exe /d /s /c \"C:\\Windows\\system32\\wbem\\wmic.exe*")
        )
      )
    ) or

    /* Zoom */
    (process.parent.name : "Zoom.exe" and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Island\\Island\\Application\\Island.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
            "?:\\Windows\\System32\\WerFault.exe"
          ) and process.code_signature.trusted == true  
        ) or
        (
          process.code_signature.subject_name : (
            "Zoom Video Communications, Inc."
          ) and process.code_signature.trusted == true
        )
      )
    ) or

    /* Outlook */
    (process.parent.name : "outlook.exe" and not
      (
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
    ) or

    /* Thunderbird */
    (process.parent.name : "thunderbird.exe" and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Windows\\splwow64.exe"
          ) and process.code_signature.trusted == true  
        ) or
        (
          process.code_signature.subject_name : (
            "Mozilla Corporation"
          ) and process.code_signature.trusted == true
        )
      )
    )
  )
```



### Suspicious Content Extracted or Decompressed via Funzip

Branch count: 4  
Document count: 4  
Index: geneve-ut-917

```python
process where host.os.type == "linux" and event.action in ("exec", "exec_event") and
((process.args == "tail" and process.args == "-c" and process.args == "funzip")) and
not process.args : "/var/log/messages" and 
not process.parent.executable : ("/usr/bin/dracut", "/sbin/dracut", "/usr/bin/xargs") and
not (process.parent.name in ("sh", "sudo") and process.parent.command_line : "*nessus_su*")
```



### Suspicious CronTab Creation or Modification

Branch count: 1  
Document count: 1  
Index: geneve-ut-918

```python
file where host.os.type == "macos" and event.type != "deletion" and process.name != null and
  file.path : "/private/var/at/tabs/*" and not process.executable == "/usr/bin/crontab"
```



### Suspicious DLL Loaded for Persistence or Privilege Escalation

Branch count: 189  
Document count: 189  
Index: geneve-ut-919

```python
any where host.os.type == "windows" and
 (event.category : ("driver", "library") or (event.category == "process" and event.action : "Image loaded*")) and
 (
  /* compatible with Elastic Endpoint Library Events */
  (?dll.name : ("wlbsctrl.dll", "wbemcomn.dll", "WptsExtensions.dll", "Tsmsisrv.dll", "TSVIPSrv.dll", "Msfte.dll",
               "wow64log.dll", "WindowsCoreDeviceInfo.dll", "Ualapi.dll", "wlanhlp.dll", "phoneinfo.dll", "EdgeGdi.dll",
               "cdpsgshims.dll", "windowsperformancerecordercontrol.dll", "diagtrack_win.dll", "oci.dll", "TPPCOIPW32.dll", 
               "tpgenlic.dll", "thinmon.dll", "fxsst.dll", "msTracer.dll")
   and (?dll.code_signature.trusted != true or ?dll.code_signature.exists != true)) or

  /* compatible with Sysmon EventID 7 - Image Load */
  (file.name : ("wlbsctrl.dll", "wbemcomn.dll", "WptsExtensions.dll", "Tsmsisrv.dll", "TSVIPSrv.dll", "Msfte.dll",
               "wow64log.dll", "WindowsCoreDeviceInfo.dll", "Ualapi.dll", "wlanhlp.dll", "phoneinfo.dll", "EdgeGdi.dll",
               "cdpsgshims.dll", "windowsperformancerecordercontrol.dll", "diagtrack_win.dll", "oci.dll", "TPPCOIPW32.dll", 
               "tpgenlic.dll", "thinmon.dll", "fxsst.dll", "msTracer.dll") and 
   not file.path : ("?:\\Windows\\System32\\wbemcomn.dll", "?:\\Windows\\SysWOW64\\wbemcomn.dll") and 
   not file.hash.sha256 : 
            ("6e837794fc282446906c36d681958f2f6212043fc117c716936920be166a700f", 
             "b14e4954e8cca060ffeb57f2458b6a3a39c7d2f27e94391cbcea5387652f21a4", 
             "c258d90acd006fa109dc6b748008edbb196d6168bc75ace0de0de54a4db46662") and 
   not file.code_signature.status == "Valid")
  )
```



### Suspicious Dynamic Linker Discovery via od

Branch count: 20  
Document count: 20  
Index: geneve-ut-921

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name == "od" and process.args in (
  "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/etc/ld.so.preload", "/lib64/ld-linux-x86-64.so.2",
  "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/usr/lib64/ld-linux-x86-64.so.2"
)
```



### Suspicious Emond Child Process

Branch count: 44  
Document count: 44  
Index: geneve-ut-922

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
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

Branch count: 4  
Document count: 4  
Index: geneve-ut-923

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("esensor.exe", "elastic-endpoint.exe") and
  process.parent.executable != null and
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
        "?:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    ) and
    process.args : (
        "test", "version",
        "top", "run",
        "*help", "status",
        "upgrade", "/launch",
        "/enable"
    )
  )
```



### Suspicious Execution from INET Cache

Branch count: 8  
Document count: 8  
Index: geneve-ut-924

```python
process where host.os.type == "windows" and event.type == "start" and  
 process.parent.name : ("explorer.exe", "winrar.exe", "7zFM.exe", "Bandizip.exe") and
  (process.args : "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*" or
   process.executable : "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*")
```



### Suspicious Execution from a Mounted Device

Branch count: 8  
Document count: 8  
Index: geneve-ut-925

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
Index: geneve-ut-929

```python
process where host.os.type == "windows" and event.type : "start" and
  (
    (
      (process.executable : "?:\\Windows\\System32\\bash.exe" or ?process.pe.original_file_name == "Bash.exe") and 
      not process.command_line : ("bash", "bash.exe")
    ) or 
    process.executable : "?:\\Users\\*\\AppData\\Local\\Packages\\*\\rootfs\\usr\\bin\\bash" or 
    (
      process.parent.name : "wsl.exe" and ?process.parent.command_line : "bash*" and not process.name : "wslhost.exe"
    ) or 
    (
      process.name : "wsl.exe" and process.args : (
        "curl", "/etc/shadow", "/etc/passwd", "cat", "--system", "root", "-e", "--exec", "bash", "/mnt/c/*"
      ) and not process.args : ("wsl-bootstrap", "docker-desktop-data", "*.vscode-server*")
    )
  ) and 
    not process.parent.executable : ("?:\\Program Files\\Docker\\*.exe", "?:\\Program Files (x86)\\Docker\\*.exe")
```



### Suspicious Explorer Child Process

Branch count: 14  
Document count: 14  
Index: geneve-ut-930

```python
process where host.os.type == "windows" and event.type == "start" and
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



### Suspicious File Creation via Kworker

Branch count: 2  
Document count: 2  
Index: geneve-ut-933

```python
file where host.os.type == "linux" and event.action in ("creation", "file_create_event") and
  process.name : "kworker*" and not (
    (process.name : "kworker*kcryptd*") or
    (file.path : ("/var/log/*", "/var/crash/*", "/var/run/*", "/var/lib/systemd/coredump/*", "/var/spool/*"))
  )
```



### Suspicious Hidden Child Process of Launchd

Branch count: 2  
Document count: 2  
Index: geneve-ut-937

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:.* and process.parent.executable:/sbin/launchd
```



### Suspicious Image Load (taskschd.dll) from MS Office

Branch count: 30  
Document count: 30  
Index: geneve-ut-938

```python
any where host.os.type == "windows" and
 (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
  process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE", "MSACCESS.EXE") and
  (?dll.name : "taskschd.dll" or file.name : "taskschd.dll")
```



### Suspicious ImagePath Service Creation

Branch count: 4  
Document count: 4  
Index: geneve-ut-939

```python
registry where host.os.type == "windows" and registry.path : (
    "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath",
    "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath"
    ) and
 /* add suspicious registry ImagePath values here */
    registry.data.strings : ("%COMSPEC%*", "*\\.\\pipe\\*")
```



### Suspicious Interactive Shell Spawned From Inside A Container

Branch count: 6  
Document count: 6  
Index: geneve-ut-941

```python
process where container.id: "*" and
event.type== "start" and 

/*D4C consolidates closely spawned event.actions, this excludes end actions to only capture ongoing processes*/
event.action in ("fork", "exec") and event.action != "end"
 and process.entry_leader.same_as_process== false and
(
(process.executable: "*/*sh" and process.args: ("-i", "-it")) or
process.args: "*/*sh"
)
```



### Suspicious Kworker UID Elevation

Branch count: 1  
Document count: 1  
Index: geneve-ut-944

```python
process where host.os.type == "linux" and event.action == "session_id_change" and process.name : "kworker*" and
user.id == "0"
```



### Suspicious LSASS Access via MalSecLogon

Branch count: 1  
Document count: 1  
Index: geneve-ut-945

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
Index: geneve-ut-946

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
        "?:\\Windows\\system32\\csrss.exe",
        "?:\\Windows\\System32\\lsm.exe",
        "?:\\Windows\\system32\\MRT.exe",
        "?:\\Windows\\System32\\msiexec.exe",
        "?:\\Windows\\system32\\wbem\\wmiprvse.exe",
        "?:\\Windows\\system32\\wininit.exe",
        "?:\\Windows\\SystemTemp\\GUM*.tmp\\GoogleUpdate.exe",
        "?:\\Windows\\sysWOW64\\wbem\\wmiprvse.exe"
  ) and
  not winlog.event_data.CallTrace : ("*mpengine.dll*", "*appresolver.dll*", "*sysmain.dll*")
```



### Suspicious MS Outlook Child Process

Branch count: 52  
Document count: 52  
Index: geneve-ut-948

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
Index: geneve-ut-949

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

Branch count: 24  
Document count: 24  
Index: geneve-ut-950

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
process.name in ("grep", "egrep", "fgrep", "rgrep") and process.args in ("[stack]", "[vdso]", "[heap]")
```



### Suspicious Mining Process Creation Event

Branch count: 14  
Document count: 14  
Index: geneve-ut-953

```python
file where host.os.type == "linux" and event.type == "creation" and event.action : ("creation", "file_create_event") and 
file.name : ("aliyun.service", "moneroocean_miner.service", "c3pool_miner.service", "pnsd.service", "apache4.service", "pastebin.service", "xvf.service")
```



### Suspicious Module Loaded by LSASS

Branch count: 2  
Document count: 2  
Index: geneve-ut-955

```python
library where host.os.type == "windows" and process.executable : "?:\\Windows\\System32\\lsass.exe" and
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



### Suspicious Network Connection via Sudo Binary

Branch count: 2  
Document count: 2  
Index: geneve-ut-957

```python
network where host.os.type == "linux" and event.type == "start" and
event.action in ("connection_attempted", "ipv4_connection_attempt_event") and process.name == "sudo"
```



### Suspicious Network Tool Launched Inside A Container

Branch count: 28  
Document count: 28  
Index: geneve-ut-959

```python
process where container.id: "*" and event.type== "start" and 
(
(process.name: ("nc", "ncat", "nmap", "dig", "nslookup", "tcpdump", "tshark", "ngrep", "telnet", "mitmproxy", "socat", "zmap", "masscan", "zgrab")) or 
/*account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg*/
(process.args: ("nc", "ncat", "nmap", "dig", "nslookup", "tcpdump", "tshark", "ngrep", "telnet", "mitmproxy", "socat", "zmap", "masscan", "zgrab"))
)
```



### Suspicious PDF Reader Child Process

Branch count: 212  
Document count: 212  
Index: geneve-ut-960

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
Index: geneve-ut-961

```python
sequence by host.id, process.parent.pid with maxspan=1m
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name == "openssl" and process.args == "passwd" and user.id != "0"]
  [file where host.os.type == "linux" and file.path == "/etc/passwd" and process.parent.pid != 1 and
   not auditd.data.a2 == "80000" and event.outcome == "success" and user.id != "0"]
```



### Suspicious Portable Executable Encoded in Powershell Script

Branch count: 1  
Document count: 1  
Index: geneve-ut-962

```python
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    TVqQAAMAAAAEAAAA
  ) and not user.id : "S-1-5-18"
```



### Suspicious Print Spooler File Deletion

Branch count: 1  
Document count: 1  
Index: geneve-ut-965

```python
file where host.os.type == "windows" and event.type : "deletion" and
 not process.name : ("spoolsv.exe", "dllhost.exe", "explorer.exe") and
 file.path : "?:\\Windows\\System32\\spool\\drivers\\x64\\3\\*.dll"
```



### Suspicious Print Spooler Point and Print DLL

Branch count: 4  
Document count: 8  
Index: geneve-ut-966

```python
sequence by host.id with maxspan=30s
[registry where host.os.type == "windows" and
 registry.path : (
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\SpoolDirectory",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\SpoolDirectory"
    ) and
 registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4"]
[registry where host.os.type == "windows" and
 registry.path : (
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\CopyFiles\\Payload\\Module",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\CopyFiles\\Payload\\Module"
    ) and
 registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4\\*"]
```



### Suspicious Print Spooler SPL File Created

Branch count: 1  
Document count: 1  
Index: geneve-ut-967

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



### Suspicious PrintSpooler Service Executable File Creation

Branch count: 2  
Document count: 2  
Index: geneve-ut-968

```python
file where host.os.type == "windows" and event.type == "creation" and
  process.name : "spoolsv.exe" and file.extension : "dll" and
  file.path : ("?:\\Windows\\System32\\*", "?:\\Windows\\SysWOW64\\*") and
  not file.path : (
    "?:\\WINDOWS\\SysWOW64\\PrintConfig.dll",
    "?:\\WINDOWS\\system32\\x5lrs.dll",
    "?:\\WINDOWS\\sysWOW64\\x5lrs.dll",
    "?:\\WINDOWS\\system32\\PrintConfig.dll",
    "?:\\WINDOWS\\system32\\spool\\DRIVERS\\x64\\*.dll",
    "?:\\WINDOWS\\system32\\spool\\DRIVERS\\W32X86\\*.dll",
    "?:\\WINDOWS\\system32\\spool\\PRTPROCS\\x64\\*.dll",
    "?:\\WINDOWS\\system32\\spool\\{????????-????-????-????-????????????}\\*.dll"
  )
```



### Suspicious Process Execution via Renamed PsExec Executable

Branch count: 1  
Document count: 1  
Index: geneve-ut-972

```python
process where host.os.type == "windows" and event.type == "start" and
  process.pe.original_file_name : "psexesvc.exe" and not process.name : "PSEXESVC.exe"
```



### Suspicious RDP ActiveX Client Loaded

Branch count: 48  
Document count: 48  
Index: geneve-ut-973

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
Index: geneve-ut-974

```python
sequence by winlog.computer_name, winlog.event_data.SubjectLogonId with maxspan=1m
 [iam where event.action == "logged-in-special"  and
  winlog.event_data.PrivilegeList : "SeBackupPrivilege" and

  /* excluding accounts with existing privileged access */
  not winlog.event_data.PrivilegeList : "SeDebugPrivilege"]
 [any where event.action == "Detailed File Share" and winlog.event_data.RelativeTargetName : "winreg"]
```



### Suspicious Renaming of ESXI Files

Branch count: 9  
Document count: 9  
Index: geneve-ut-975

```python
file where host.os.type == "linux" and event.action == "rename" and
file.Ext.original.name : ("*.vmdk", "*.vmx", "*.vmxf", "*.vmsd", "*.vmsn", "*.vswp", "*.vmss", "*.nvram", "*.vmem")
and not file.name : ("*.vmdk", "*.vmx", "*.vmxf", "*.vmsd", "*.vmsn", "*.vswp", "*.vmss", "*.nvram", "*.vmem")
```



### Suspicious Renaming of ESXI index.html File

Branch count: 1  
Document count: 1  
Index: geneve-ut-976

```python
file where host.os.type == "linux" and event.action == "rename" and file.name : "index.html" and
file.Ext.original.path : "/usr/lib/vmware/*"
```



### Suspicious ScreenConnect Client Child Process

Branch count: 152  
Document count: 152  
Index: geneve-ut-977

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

Branch count: 8  
Document count: 8  
Index: geneve-ut-978

```python
any where host.os.type == "windows" and 
 (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and 
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



### Suspicious SolarWinds Child Process

Branch count: 4  
Document count: 4  
Index: geneve-ut-980

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



### Suspicious Startup Shell Folder Modification

Branch count: 10  
Document count: 10  
Index: geneve-ut-981

```python
registry where host.os.type == "windows" and
 registry.path : (
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "HKU\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup",
     "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Startup",
     "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup",
     "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Startup",
     "\\REGISTRY\\USER\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup"
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



### Suspicious Termination of ESXI Process

Branch count: 2  
Document count: 2  
Index: geneve-ut-985

```python
process where host.os.type == "linux" and event.type == "end" and process.name in ("vmware-vmx", "vmx")
and process.parent.name == "kill"
```



### Suspicious Troubleshooting Pack Cabinet Execution

Branch count: 160  
Document count: 160  
Index: geneve-ut-986

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

Branch count: 136  
Document count: 136  
Index: geneve-ut-987

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and process.name == "proxychains" and process.args : (
  "ssh", "sshd", "sshuttle", "socat", "iodine", "iodined", "dnscat", "hans", "hans-ubuntu", "ptunnel-ng",
  "ssf", "3proxy", "ngrok", "gost", "pivotnacci", "chisel*", "nmap", "ping", "python*", "php*", "perl", "ruby",
  "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk", "java", "telnet", "ftp", "curl", "wget"
)
```



### Suspicious WMI Event Subscription Created

Branch count: 2  
Document count: 2  
Index: geneve-ut-988

```python
any where event.dataset == "windows.sysmon_operational" and event.code == "21" and
    winlog.event_data.Operation : "Created" and winlog.event_data.Consumer : ("*subscription:CommandLineEventConsumer*", "*subscription:ActiveScriptEventConsumer*")
```



### Suspicious WMI Image Load from MS Office

Branch count: 30  
Document count: 30  
Index: geneve-ut-989

```python
any where host.os.type == "windows" and
 (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
  process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE", "MSACCESS.EXE") and
  (?dll.name : "wmiutils.dll" or file.name : "wmiutils.dll")
```



### Suspicious WMIC XSL Script Execution

Branch count: 48  
Document count: 96  
Index: geneve-ut-990

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
Index: geneve-ut-991

```python
file where event.action == "open" and host.os.type == "macos" and process.executable != null and
 file.name : ("cookies.sqlite", 
              "key?.db", 
              "logins.json", 
              "Cookies", 
              "Cookies.binarycookies", 
              "Login Data") and 
 ((process.code_signature.trusted == false or process.code_signature.exists == false) or process.name : "osascript") and 
 not process.code_signature.signing_id : "org.mozilla.firefox" and
 not process.Ext.effective_parent.executable : "/Library/Elastic/Endpoint/elastic-endpoint.app/Contents/MacOS/elastic-endpoint"
```



### Suspicious WerFault Child Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-992

```python
process where host.os.type == "windows" and event.type == "start" and

  process.parent.name : "WerFault.exe" and

  /* args -s and -t used to execute a process via SilentProcessExit mechanism */
  (process.parent.args : "-s" and process.parent.args : "-t" and process.parent.args : "-c") and

  not process.executable : ("?:\\Windows\\SysWOW64\\Initcrypt.exe", "?:\\Program Files (x86)\\Heimdal\\Heimdal.Guard.exe")
```



### Suspicious Zoom Child Process

Branch count: 4  
Document count: 4  
Index: geneve-ut-996

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "Zoom.exe" and process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe")
```



### Suspicious which Enumeration

Branch count: 2  
Document count: 2  
Index: geneve-ut-999

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and 
process.name == "which" and process.args_count >= 10 and not process.parent.name == "jem" and 
not process.args == "--tty-only"

/* potential tuning if rule would turn out to be noisy
and process.args in ("nmap", "nc", "ncat", "netcat", nc.traditional", "gcc", "g++", "socat") and 
process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
*/
```



### Symbolic Link to Shadow Copy Created

Branch count: 8  
Document count: 8  
Index: geneve-ut-1001

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
Index: geneve-ut-1002

```python
file where host.os.type == "linux" and event.type == "change" and event.action == "rename" and
file.Ext.original.path : (
  "/bin/*", "/usr/bin/*", "/usr/local/bin/*", "/sbin/*", "/usr/sbin/*", "/usr/local/sbin/*"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/libexec/netplan/generate",
    "/usr/bin/update-alternatives", "/bin/update-alternatives", "/usr/sbin/update-alternatives",
    "/sbin/update-alternatives", "/usr/bin/pip3", "/bin/pip3", "/usr/local/bin/pip3", "/usr/local/bin/node",
    "/bin/node", "/usr/bin/node", "/sbin/apk", "/usr/sbin/apk", "/usr/local/sbin/apk", "/usr/bin/pip", "/bin/pip",
    "/usr/local/bin/pip"
  ) or
  file.Ext.original.path : (
    "/bin/*.tmp", "/usr/bin/*.tmp", "/usr/local/bin/*.tmp", "/sbin/*.tmp", "/usr/sbin/*.tmp", "/usr/local/sbin/*.tmp"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : ("/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*") or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```



### System Hosts File Access

Branch count: 20  
Document count: 20  
Index: geneve-ut-1003

```python
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and
process.name in ("vi", "nano", "cat", "more", "less") and process.args == "/etc/hosts"
```



### System Information Discovery via Windows Command Shell

Branch count: 2  
Document count: 2  
Index: geneve-ut-1004

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "cmd.exe" and process.args : "/c" and process.args : ("set", "dir") and
  not process.parent.executable : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*", "?:\\PROGRA~1\\*")
```



### System Log File Deletion

Branch count: 11  
Document count: 11  
Index: geneve-ut-1005

```python
file where host.os.type == "linux" and event.type == "deletion" and
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
    "/var/log/auth.log",
    "/var/log/boot.log",
    "/var/log/kern.log"
    ) and
    not process.name in ("gzip", "executor", "dockerd")
```



### System Network Connections Discovery

Branch count: 16  
Document count: 16  
Index: geneve-ut-1006

```python
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and
process.name in ("netstat", "lsof", "who", "w")
```



### System Owner/User Discovery Linux

Branch count: 20  
Document count: 20  
Index: geneve-ut-1007

```python
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and 
process.name : ("whoami", "w", "who", "users", "id")
```



### System Service Discovery through built-in Windows Utilities

Branch count: 14  
Document count: 14  
Index: geneve-ut-1008

```python
process where host.os.type == "windows" and event.type == "start" and
  (
  ((process.name: "net.exe" or process.pe.original_file_name == "net.exe" or (process.name : "net1.exe" and 
    not process.parent.name : "net.exe")) and process.args : ("start", "use") and process.args_count == 2) or
  ((process.name: "sc.exe" or process.pe.original_file_name == "sc.exe") and process.args: ("query", "q*")) or
  ((process.name: "tasklist.exe" or process.pe.original_file_name == "tasklist.exe") and process.args: "/svc") or
  (process.name : "psservice.exe" or process.pe.original_file_name == "psservice.exe")
  ) and not user.id : "S-1-5-18"
```



### System Shells via Services

Branch count: 4  
Document count: 4  
Index: geneve-ut-1009

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
Index: geneve-ut-1010

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

Branch count: 16  
Document count: 16  
Index: geneve-ut-1011

```python
file where host.os.type == "linux" and event.action in ("creation", "file_create_event", "rename", "file_rename_event")
and file.path : "/etc/init.d/*" and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```



### SystemKey Access via Command Line

Branch count: 4  
Document count: 4  
Index: geneve-ut-1012

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and
  process.args:("/private/var/db/SystemKey" or "/var/db/SystemKey") and
  not process.Ext.effective_parent.executable : "/Library/Elastic/Endpoint/elastic-endpoint.app/Contents/MacOS/elastic-endpoint"
```



### Systemd Generator Created

Branch count: 18  
Document count: 18  
Index: geneve-ut-1013

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
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable == null
)
```



### Systemd Service Created

Branch count: 80  
Document count: 80  
Index: geneve-ut-1014

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
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```



### Systemd Timer Created

Branch count: 80  
Document count: 80  
Index: geneve-ut-1016

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
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```



### Systemd-udevd Rule File Creation

Branch count: 32  
Document count: 32  
Index: geneve-ut-1017

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and 
process.executable != null and 
file.path : (
  "/lib/udev/*", "/etc/udev/rules.d/*", "/usr/lib/udev/rules.d/*", "/run/udev/rules.d/*"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/libexec/netplan/generate"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*", "/usr/lib/*", "/usr/libexec/*"
  ) or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```



### TCC Bypass via Mounted APFS Snapshot Access

Branch count: 2  
Document count: 2  
Index: geneve-ut-1018

```python
event.category:process and host.os.type:macos and event.type:(start or process_started) and process.name:mount_apfs and
  process.args:(/System/Volumes/Data and noowners)
```



### Tampering of Shell Command-Line History

Branch count: 180  
Document count: 180  
Index: geneve-ut-1021

```python
process where event.action in ("exec", "exec_event", "executed", "process_started") and event.type == "start" and
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



### Temporarily Scheduled Task Creation

Branch count: 1  
Document count: 2  
Index: geneve-ut-1022

```python
sequence by winlog.computer_name, winlog.event_data.TaskName with maxspan=5m
   [iam where event.action == "scheduled-task-created" and not user.name : "*$"]
   [iam where event.action == "scheduled-task-deleted" and not user.name : "*$"]
```



### Third-party Backup Files Deleted via Unexpected Process

Branch count: 30  
Document count: 30  
Index: geneve-ut-1023

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

Branch count: 4  
Document count: 4  
Index: geneve-ut-1028

```python
process where event.type == "start" and
 process.name : "touch" and user.id != "0" and
 process.args : ("-r", "-t", "-a*","-m*") and
 not process.args : (
   "/usr/lib/go-*/bin/go", "/usr/lib/dracut/dracut-functions.sh", "/tmp/KSInstallAction.*/m/.patch/*"
) and not process.parent.name in ("pmlogger_daily", "pmlogger_janitor", "systemd")
```



### Trap Signals Execution

Branch count: 4  
Document count: 4  
Index: geneve-ut-1029

```python
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and
process.name == "trap" and process.args : "SIG*"
```



### UAC Bypass Attempt via Elevated COM Internet Explorer Add-On Installer

Branch count: 1  
Document count: 1  
Index: geneve-ut-1030

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
Index: geneve-ut-1031

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
Index: geneve-ut-1032

```python
process where host.os.type == "windows" and event.type == "start" and
  process.args : ("C:\\Windows \\system32\\*.exe", "C:\\Windows \\SysWOW64\\*.exe")
```



### UAC Bypass Attempt with IEditionUpgradeManager Elevated COM Interface

Branch count: 1  
Document count: 1  
Index: geneve-ut-1033

```python
process where host.os.type == "windows" and event.type == "start" and process.name : "Clipup.exe" and
  not process.executable : "C:\\Windows\\System32\\ClipUp.exe" and process.parent.name : "dllhost.exe" and
  /* CLSID of the Elevated COM Interface IEditionUpgradeManager */
  process.parent.args : "/Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}"
```



### UAC Bypass via DiskCleanup Scheduled Task Hijack

Branch count: 1  
Document count: 1  
Index: geneve-ut-1034

```python
process where host.os.type == "windows" and event.type == "start" and
 process.args : "/autoclean" and process.args : "/d" and process.executable != null and 
 not process.executable : ("C:\\Windows\\System32\\cleanmgr.exe",
                           "C:\\Windows\\SysWOW64\\cleanmgr.exe",
                           "C:\\Windows\\System32\\taskhostw.exe")
```



### UAC Bypass via ICMLuaUtil Elevated COM Interface

Branch count: 2  
Document count: 2  
Index: geneve-ut-1035

```python
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name == "dllhost.exe" and
 process.parent.args in ("/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}", "/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}") and
 process.pe.original_file_name != "WerFault.exe"
```



### UAC Bypass via Windows Firewall Snap-In Hijack

Branch count: 1  
Document count: 1  
Index: geneve-ut-1036

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
Index: geneve-ut-1038

```python
event.dataset:okta.system and event.action:app.generic.unauth_app_access_attempt
```



### Unexpected Child Process of macOS Screensaver Engine

Branch count: 1  
Document count: 1  
Index: geneve-ut-1040

```python
process where host.os.type == "macos" and event.type == "start" and process.parent.name == "ScreenSaverEngine"
```



### Unix Socket Connection

Branch count: 60  
Document count: 60  
Index: geneve-ut-1041

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and (
  (process.name in ("nc", "ncat", "netcat", "nc.openbsd") and 
   process.args == "-U" and process.args : ("/usr/local/*", "/run/*", "/var/run/*")) or
  (process.name == "socat" and 
   process.args == "-" and process.args : ("UNIX-CLIENT:/usr/local/*", "UNIX-CLIENT:/run/*", "UNIX-CLIENT:/var/run/*"))
)
```



### Unsigned BITS Service Client Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-1043

```python
library where dll.name : "Bitsproxy.dll" and process.executable != null and
not process.code_signature.trusted == true and
not process.code_signature.status : ("errorExpired", "errorCode_endpoint*")
```



### Untrusted Driver Loaded

Branch count: 1  
Document count: 1  
Index: geneve-ut-1048

```python
driver where host.os.type == "windows" and process.pid == 4 and
  dll.code_signature.trusted != true and 
  not dll.code_signature.status : ("errorExpired", "errorRevoked", "errorCode_endpoint:*")
```



### Unusual Child Process from a System Virtual Process

Branch count: 1  
Document count: 1  
Index: geneve-ut-1050

```python
process where host.os.type == "windows" and event.type == "start" and
  process.parent.pid == 4 and process.executable : "?*" and
  not process.executable : ("Registry", "MemCompression", "?:\\Windows\\System32\\smss.exe")
```



### Unusual Child Process of dns.exe

Branch count: 1  
Document count: 1  
Index: geneve-ut-1051

```python
process where host.os.type == "windows" and event.type == "start" and process.parent.name : "dns.exe" and
  not process.name : "conhost.exe"
```



### Unusual Child Processes of RunDLL32

Branch count: 2  
Document count: 4  
Index: geneve-ut-1052

```python
sequence with maxspan=1h
  [process where host.os.type == "windows" and event.type == "start" and
     (process.name : "rundll32.exe" or process.pe.original_file_name == "RUNDLL32.EXE") and
      process.args_count == 1
  ] by process.entity_id
  [process where host.os.type == "windows" and event.type == "start" and process.parent.name : "rundll32.exe"
  ] by process.parent.entity_id
```



### Unusual Executable File Creation by a System Critical Process

Branch count: 18  
Document count: 18  
Index: geneve-ut-1059

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

Branch count: 29  
Document count: 29  
Index: geneve-ut-1061

```python
file where host.os.type == "windows" and event.type == "creation" and

  file.path : "C:\\*:*" and
  not file.path : 
          ("C:\\*:zone.identifier*",
           "C:\\users\\*\\appdata\\roaming\\microsoft\\teams\\old_weblogs_*:$DATA") and

  not process.executable :
          ("?:\\windows\\System32\\svchost.exe",
           "?:\\Windows\\System32\\inetsrv\\w3wp.exe",
           "?:\\Windows\\explorer.exe",
           "?:\\Windows\\System32\\sihost.exe",
           "?:\\Windows\\System32\\PickerHost.exe",
           "?:\\Windows\\System32\\SearchProtocolHost.exe",
           "?:\\Program Files (x86)\\Dropbox\\Client\\Dropbox.exe",
           "?:\\Program Files\\Rivet Networks\\SmartByte\\SmartByteNetworkService.exe",
           "?:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
           "?:\\Program Files\\ExpressConnect\\ExpressConnectNetworkService.exe",
           "?:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
           "?:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
           "?:\\Program Files\\Mozilla Firefox\\firefox.exe",
           "?:\\Program Files(x86)\\Microsoft Office\\root\\*\\EXCEL.EXE",
           "?:\\Program Files\\Microsoft Office\\root\\*\\EXCEL.EXE",
           "?:\\Program Files (x86)\\Microsoft Office\\root\\*\\OUTLOOK.EXE",
           "?:\\Program Files\\Microsoft Office\\root\\*\\OUTLOOK.EXE",
           "?:\\Program Files (x86)\\Microsoft Office\\root\\*\\POWERPNT.EXE",
           "?:\\Program Files\\Microsoft Office\\root\\*\\POWERPNT.EXE",
           "?:\\Program Files (x86)\\Microsoft Office\\root\\*\\WINWORD.EXE",
           "?:\\Program Files\\Microsoft Office\\root\\*\\WINWORD.EXE") and

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

Branch count: 6  
Document count: 6  
Index: geneve-ut-1062

```python
file where host.os.type == "windows" and process.name : "dns.exe" and event.type in ("creation", "deletion", "change") and
  not file.name : "dns.log" and not
  (file.extension : ("old", "temp", "bak", "dns", "arpa") and file.path : "C:\\Windows\\System32\\dns\\*")
```



### Unusual Network Activity from a Windows System Binary

Branch count: 400  
Document count: 800  
Index: geneve-ut-1076

```python
sequence by process.entity_id with maxspan=5m
  [process where host.os.type == "windows" and event.type == "start" and

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
      (
        process.name : "msbuild.exe" and
          destination.ip != "127.0.0.1"
      ) or
      process.name : "msdt.exe" or
      process.name : "mshta.exe" or
      (
        process.name : "msiexec.exe" and not
        dns.question.name : (
           "ocsp.digicert.com", "ocsp.verisign.com", "ocsp.comodoca.com", "ocsp.entrust.net", "ocsp.usertrust.com",
           "ocsp.godaddy.com", "ocsp.camerfirma.com", "ocsp.globalsign.com", "ocsp.sectigo.com", "*.local"
        ) and
        /* Localhost, DigiCert and Comodo CA IP addresses */
        not cidrmatch(destination.ip, "127.0.0.1", "192.229.211.108/32", "192.229.221.95/32",
                      "152.195.38.76/32", "104.18.14.101/32")
      ) or
      process.name : "msxsl.exe" or
      process.name : "odbcconf.exe" or
      process.name : "rcsi.exe" or
      process.name : "regsvr32.exe" or
      process.name : "xwizard.exe")]
```



### Unusual Network Connection via DllHost

Branch count: 1  
Document count: 2  
Index: geneve-ut-1077

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



### Unusual Network Connection via RunDLL32

Branch count: 1  
Document count: 2  
Index: geneve-ut-1078

```python
sequence by host.id, process.entity_id with maxspan=1m
  [process where host.os.type == "windows" and event.type == "start" and process.name : "rundll32.exe" and process.args_count == 1]
  [network where host.os.type == "windows" and process.name : "rundll32.exe" and
   not cidrmatch(destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1",
       "FE80::/10", "FF00::/8")]
```



### Unusual Parent-Child Relationship

Branch count: 32  
Document count: 32  
Index: geneve-ut-1081

```python
process where host.os.type == "windows" and event.type == "start" and
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
   (process.name:"svchost.exe" and not process.parent.name:("MsMpEng.exe", "services.exe", "svchost.exe")) or
   (process.name:"spoolsv.exe" and not process.parent.name:"services.exe") or
   (process.name:"taskhost.exe" and not process.parent.name:("services.exe", "svchost.exe", "ngentask.exe")) or
   (process.name:"taskhostw.exe" and not process.parent.name:("services.exe", "svchost.exe")) or
   (process.name:"userinit.exe" and not process.parent.name:("dwm.exe", "winlogon.exe")) or
   (process.name:("wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe") and not process.parent.name:"svchost.exe") or
   /* suspicious child processes */
   (process.parent.name:("SearchProtocolHost.exe", "taskhost.exe", "csrss.exe") and not process.name:("werfault.exe", "wermgr.exe", "WerFaultSecure.exe", "conhost.exe")) or
   (process.parent.name:"autochk.exe" and not process.name:("chkdsk.exe", "doskey.exe", "WerFault.exe")) or
   (process.parent.name:"smss.exe" and not process.name:("autochk.exe", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "setupcl.exe", "WerFault.exe")) or
   (process.parent.name:"wermgr.exe" and not process.name:("WerFaultSecure.exe", "wermgr.exe", "WerFault.exe")) or
   (process.parent.name:"conhost.exe" and not process.name:("mscorsvw.exe", "wermgr.exe", "WerFault.exe", "WerFaultSecure.exe"))
  )
```



### Unusual Persistence via Services Registry

Branch count: 8  
Document count: 8  
Index: geneve-ut-1082

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
      "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ServiceDLL",
      "HKLM\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath",
      "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet*\\Services\\*\\ServiceDLL",
      "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet*\\Services\\*\\ImagePath"
  ) and not registry.data.strings : (
      "?:\\windows\\system32\\Drivers\\*.sys",
      "\\SystemRoot\\System32\\drivers\\*.sys",
      "\\??\\?:\\Windows\\system32\\Drivers\\*.SYS",
      "system32\\DRIVERS\\USBSTOR") and
  not (process.name : "procexp??.exe" and registry.data.strings : "?:\\*\\procexp*.sys") and
  not process.executable : (
      "?:\\Program Files\\*.exe",
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
Index: geneve-ut-1083

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
    "?:\\Program Files (x86)\\GPLGS\\gswin32c.exe"
 )
```



### Unusual Process Execution Path - Alternate Data Stream

Branch count: 1  
Document count: 1  
Index: geneve-ut-1084

```python
process where host.os.type == "windows" and event.type == "start" and
  process.args : "?:\\*:*" and process.args_count == 1
```



### Unusual Process Execution on WBEM Path

Branch count: 2  
Document count: 2  
Index: geneve-ut-1085

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
Index: geneve-ut-1086

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
Index: geneve-ut-1087

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
Index: geneve-ut-1090

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



### Unusual User Privilege Enumeration via id

Branch count: 1  
Document count: 20  
Index: geneve-ut-1102

```python
sequence by host.id, process.parent.entity_id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and 
   process.name == "id" and process.args_count == 2 and 
   not (process.parent.name == "rpm" or process.parent.args : "/var/tmp/rpm-tmp*")] with runs=20
```



### User Account Creation

Branch count: 4  
Document count: 4  
Index: geneve-ut-1113

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("net.exe", "net1.exe") and
  not process.parent.name : "net.exe" and
  (process.args : "user" and process.args : ("/ad", "/add"))
```



### User Added as Owner for Azure Application

Branch count: 2  
Document count: 2  
Index: geneve-ut-1114

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add owner to application" and event.outcome:(Success or success)
```



### User Added as Owner for Azure Service Principal

Branch count: 2  
Document count: 2  
Index: geneve-ut-1115

```python
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Add owner to service principal" and event.outcome:(Success or success)
```



### User Added to Privileged Group

Branch count: 22  
Document count: 22  
Index: geneve-ut-1116

```python
iam where winlog.api == "wineventlog" and event.action == "added-member-to-group" and
(
    (
        group.name : (
            "Admin*",
            "Local Administrators",
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
            "S-1-5-32-544",
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



### User account exposed to Kerberoasting

Branch count: 1  
Document count: 1  
Index: geneve-ut-1117

```python
event.action:"Directory Service Changes" and event.code:5136 and
  winlog.event_data.OperationType:"%%14674" and
  winlog.event_data.ObjectClass:"user" and
  winlog.event_data.AttributeLDAPDisplayName:"servicePrincipalName"
```



### User or Group Creation/Modification

Branch count: 6  
Document count: 6  
Index: geneve-ut-1118

```python
iam where host.os.type == "linux" and event.type in ("creation", "change") and auditd.result == "success" and 
event.action in ("changed-password", "added-user-account", "added-group-account-to")
```



### VNC (Virtual Network Computing) from the Internet

Branch count: 9  
Document count: 9  
Index: geneve-ut-1119

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
Index: geneve-ut-1120

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
Index: geneve-ut-1121

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

Branch count: 10  
Document count: 10  
Index: geneve-ut-1122

```python
event.category:process and host.os.type:linux and event.type:(start or process_started) and
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
Index: geneve-ut-1123

```python
process where event.type == "start" and
 process.name in ("grep", "egrep") and user.id != "0" and
 process.args : ("parallels*", "vmware*", "virtualbox*") and process.args : "Manufacturer*" and
 not process.parent.executable in ("/Applications/Docker.app/Contents/MacOS/Docker", "/usr/libexec/kcare/virt-what")
```



### Virtual Private Network Connection Attempt

Branch count: 6  
Document count: 6  
Index: geneve-ut-1124

```python
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  (
    (process.name : "networksetup" and process.args : "-connectpppoeservice") or
    (process.name : "scutil" and process.args : "--nc" and process.args : "start") or
    (process.name : "osascript" and process.command_line : "osascript*set VPN to service*")
  )
```



### Volume Shadow Copy Deleted or Resized via VssAdmin

Branch count: 4  
Document count: 4  
Index: geneve-ut-1125

```python
process where host.os.type == "windows" and event.type == "start"
  and (process.name : "vssadmin.exe" or ?process.pe.original_file_name == "VSSADMIN.EXE") and
  process.args in ("delete", "resize") and process.args : "shadows*"
```



### Volume Shadow Copy Deletion via PowerShell

Branch count: 60  
Document count: 60  
Index: geneve-ut-1126

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
Index: geneve-ut-1127

```python
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "WMIC.exe" or ?process.pe.original_file_name == "wmic.exe") and
  process.args : "delete" and process.args : "shadowcopy"
```



### WMI Incoming Lateral Movement

Branch count: 8  
Document count: 16  
Index: geneve-ut-1128

```python
sequence by host.id with maxspan = 2s

 /* Accepted Incoming RPC connection by Winmgmt service */

  [network where host.os.type == "windows" and process.name : "svchost.exe" and network.direction : ("incoming", "ingress") and
   source.ip != "127.0.0.1" and source.ip != "::1" and source.port >= 49152 and destination.port >= 49152
  ]

  /* Excluding Common FPs Nessus and SCCM */

  [process where host.os.type == "windows" and event.type == "start" and process.parent.name : "WmiPrvSE.exe" and
   not (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System") and
   not user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
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
Index: geneve-ut-1129

```python
process where host.os.type == "windows" and event.type == "start" and process.name : "wbemtest.exe"
```



### WMIC Remote Command

Branch count: 3  
Document count: 3  
Index: geneve-ut-1130

```python
process where host.os.type == "windows" and event.type == "start" and
  process.name : "WMIC.exe" and
  process.args : "*node:*" and
  process.args : ("call", "set", "get") and
  not process.args : ("*/node:localhost*", "*/node:\"127.0.0.1\"*", "/node:127.0.0.1")
```



### WRITEDAC Access on Active Directory Object

Branch count: 2  
Document count: 2  
Index: geneve-ut-1131

```python
host.os.type: "windows" and event.action : ("Directory Service Access" or "object-operation-performed") and
  event.code : "4662" and winlog.event_data.AccessMask:"0x40000"
```



### Web Application Suspicious Activity: POST Request Declined

Branch count: 1  
Document count: 1  
Index: geneve-ut-1132

```python
http.response.status_code:403 and http.request.method:post
```



### Web Application Suspicious Activity: Unauthorized Method

Branch count: 1  
Document count: 1  
Index: geneve-ut-1133

```python
http.response.status_code:405
```



### Web Application Suspicious Activity: sqlmap User Agent

Branch count: 1  
Document count: 1  
Index: geneve-ut-1134

```python
user_agent.original:"sqlmap/1.3.11#stable (http://sqlmap.org)"
```



### WebProxy Settings Modification

Branch count: 3  
Document count: 3  
Index: geneve-ut-1136

```python
event.category:process and host.os.type:macos and event.type:start and
 process.name : networksetup and process.args : (("-setwebproxy" or "-setsecurewebproxy" or "-setautoproxyurl") and not (Bluetooth or off)) and
 not process.parent.executable : ("/Library/PrivilegedHelperTools/com.80pct.FreedomHelper" or
                                  "/Applications/Fiddler Everywhere.app/Contents/Resources/app/out/WebServer/Fiddler.WebUi" or
                                  "/usr/libexec/xpcproxy") and
 not process.Ext.effective_parent.executable : ("/Applications/Proxyman.app/Contents/MacOS/Proxyman" or "/Applications/Incoggo.app/Contents/MacOS/Incoggo.app")
```



### WebServer Access Logs Deleted

Branch count: 5  
Document count: 5  
Index: geneve-ut-1137

```python
file where event.type == "deletion" and
  file.path : ("C:\\inetpub\\logs\\LogFiles\\*.log",
               "/var/log/apache*/access.log",
               "/etc/httpd/logs/access_log",
               "/var/log/httpd/access_log",
               "/var/www/*/logs/access.log")
```



### Werfault ReflectDebugger Persistence

Branch count: 2  
Document count: 2  
Index: geneve-ut-1138

```python
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
    "HKLM\\Software\\Microsoft\\Windows\\Windows Error Reporting\\Hangs\\ReflectDebugger",
    "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\Windows Error Reporting\\Hangs\\ReflectDebugger"
  )
```



### Whoami Process Activity

Branch count: 53  
Document count: 53  
Index: geneve-ut-1139

```python
process where host.os.type == "windows" and event.type == "start" and process.name : "whoami.exe" and
(
  (
    /* scoped for whoami execution under system privileges */
    (
      user.domain : ("NT *", "* NT", "IIS APPPOOL") and
      user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-82-*") and
      not ?winlog.event_data.SubjectUserName : "*$"
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
Index: geneve-ut-1140

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

Branch count: 48  
Document count: 48  
Index: geneve-ut-1142

```python
registry where host.os.type == "windows" and event.type in ("creation", "change") and
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
Index: geneve-ut-1143

```python
process where host.os.type == "windows" and event.type == "start" and
 (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or ?process.pe.original_file_name in ("powershell.exe", "pwsh.dll", "powershell_ise.exe")) and
  process.args : ("*Add-MpPreference*", "*Set-MpPreference*") and
  process.args : ("*-Exclusion*")
```



### Windows Event Logs Cleared

Branch count: 2  
Document count: 2  
Index: geneve-ut-1144

```python
event.action:("audit-log-cleared" or "Log clear") and winlog.api:"wineventlog" and
  not winlog.provider_name:"AD FS Auditing"
```



### Windows Firewall Disabled via PowerShell

Branch count: 16  
Document count: 16  
Index: geneve-ut-1145

```python
process where host.os.type == "windows" and event.action == "start" and
  (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or ?process.pe.original_file_name == "PowerShell.EXE") and
   process.args : "*Set-NetFirewallProfile*" and
  (process.args : "*-Enabled*" and process.args : "*False*") and
  (process.args : "*-All*" or process.args : ("*Public*", "*Domain*", "*Private*"))
```



### Windows Installer with Suspicious Properties

Branch count: 10  
Document count: 20  
Index: geneve-ut-1146

```python
sequence with maxspan=1m
  [registry where host.os.type == "windows" and process.name : "msiexec.exe" and
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
Index: geneve-ut-1147

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
Index: geneve-ut-1148

```python
file where host.os.type == "windows" and event.type == "creation" and
 /* regf file header */
 file.Ext.header_bytes : "72656766*" and file.size >= 30000 and
 process.pid == 4 and user.id : ("S-1-5-21*", "S-1-12-1-*") and
 not file.path : (
    "?:\\*\\UPM_Profile\\NTUSER.DAT",
    "?:\\*\\UPM_Profile\\NTUSER.DAT.LASTGOOD.LOAD",
    "?:\\Windows\\Netwrix\\Temp\\????????.???.offreg",
    "?:\\*\\AppData\\Local\\Packages\\Microsoft.*\\Settings\\settings.dat*"
 )
```



### Windows Script Interpreter Executing Process via WMI

Branch count: 216  
Document count: 432  
Index: geneve-ut-1150

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



### Windows Service Installed via an Unusual Client

Branch count: 2  
Document count: 2  
Index: geneve-ut-1151

```python
configuration where host.os.type == "windows" and
  event.action == "service-installed" and
  (winlog.event_data.ClientProcessId == "0" or winlog.event_data.ParentProcessId == "0") and
  not winlog.event_data.ServiceFileName : (
    "?:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe",
    "?:\\Windows\\VeeamLogShipper\\VeeamLogShipper.exe",
    "%SystemRoot%\\system32\\Drivers\\Crowdstrike\\*-CsInstallerService.exe",
    "\"%windir%\\AdminArsenal\\PDQInventory-Scanner\\service-1\\PDQInventory-Scanner-1.exe\" "
  )
```



### Windows Subsystem for Linux Distribution Installed

Branch count: 2  
Document count: 2  
Index: geneve-ut-1152

```python
registry where host.os.type == "windows" and
 registry.path : 
       ("HK*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss\\*\\PackageFamilyName",
        "\\REGISTRY\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss\\*\\PackageFamilyName")
```



### Windows Subsystem for Linux Enabled via Dism Utility

Branch count: 2  
Document count: 2  
Index: geneve-ut-1153

```python
process where host.os.type == "windows" and event.type : "start" and
 (process.name : "Dism.exe" or ?process.pe.original_file_name == "DISM.EXE") and 
 process.command_line : "*Microsoft-Windows-Subsystem-Linux*"
```



### Windows System Information Discovery

Branch count: 4  
Document count: 4  
Index: geneve-ut-1154

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
Index: geneve-ut-1155

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
Index: geneve-ut-1156

```python
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "netsh.exe" or ?process.pe.original_file_name == "netsh.exe") and
  process.args : "wlan" and process.args : "key*clear"
```



### Yum Package Manager Plugin File Creation

Branch count: 16  
Document count: 16  
Index: geneve-ut-1157

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and
file.path : ("/usr/lib/yum-plugins/*", "/etc/yum/pluginconf.d/*") and not (
  process.executable in (
    "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf", "/usr/bin/microdnf", "/bin/rpm",
    "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum", "/bin/dnf", "/usr/bin/dnf",
    "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet", "/bin/puppet",
    "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client", "/bin/autossl_check",
    "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd",
    "/usr/libexec/netplan/generate"
  ) or
  process.name == "yumBackend.py" or
  file.extension in ("swp", "swpx", "swx") or
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

Branch count: 12  
Document count: 12  
Index: geneve-ut-1158

```python
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
process.name == "grep" and process.args : "plugins*" and process.args : (
  "/etc/yum.conf", "/usr/lib/yum-plugins/*", "/etc/yum/pluginconf.d/*",
  "/usr/lib/python*/site-packages/dnf-plugins/*", "/etc/dnf/plugins/*", "/etc/dnf/dnf.conf"
)
```



### Zoom Meeting with no Passcode

Branch count: 1  
Document count: 1  
Index: geneve-ut-1159

```python
event.type:creation and event.module:zoom and event.dataset:zoom.webhook and
  event.action:meeting.created and not zoom.meeting.password:*
```



### rc.local/rc.common File Creation

Branch count: 16  
Document count: 16  
Index: geneve-ut-1160

```python
file where host.os.type == "linux" and event.action in ("rename", "creation") and
file.path in ("/etc/rc.local", "/etc/rc.common") and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*") 
)
```
