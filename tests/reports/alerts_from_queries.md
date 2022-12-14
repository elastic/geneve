# Alerts generation from test queries

This report captures the unit test queries signals generation coverage.
Here you can learn what queries are supported.

## Table of contents
   1. [Rules with the correct signals (53)](#rules-with-the-correct-signals-53)

## Rules with the correct signals (53)

### Rule 000

Branch count: 1  
Document count: 1  
Index: geneve-ut-000

```python
any where true
```

```python
[{'@timestamp': 0}]
```



### Rule 001

Branch count: 1  
Document count: 1  
Index: geneve-ut-001

```python
any where not false
```

```python
[{'@timestamp': 0}]
```



### Rule 002

Branch count: 1  
Document count: 1  
Index: geneve-ut-002

```python
any where not (true and false)
```

```python
[{'@timestamp': 0}]
```



### Rule 003

Branch count: 1  
Document count: 1  
Index: geneve-ut-003

```python
any where not (false or false)
```

```python
[{'@timestamp': 0}]
```



### Rule 004

Branch count: 1  
Document count: 1  
Index: geneve-ut-004

```python
network where source.port > 512 and source.port < 1024
```

```python
[{'event': {'category': ['network']}, 'source': {'port': 971}, '@timestamp': 0}]
```



### Rule 005

Branch count: 1  
Document count: 1  
Index: geneve-ut-005

```python
network where not (source.port < 512 or source.port > 1024)
```

```python
[{'event': {'category': ['network']}, 'source': {'port': 999}, '@timestamp': 0}]
```



### Rule 006

Branch count: 1  
Document count: 1  
Index: geneve-ut-006

```python
network where destination.port not in (80, 443)
```

```python
[{'destination': {'port': 65449}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 007

Branch count: 1  
Document count: 1  
Index: geneve-ut-007

```python
network where not destination.port in (80, 443)
```

```python
[{'destination': {'port': 65449}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 008

Branch count: 1  
Document count: 1  
Index: geneve-ut-008

```python
network where destination.port == 22 and destination.port in (80, 443) or destination.port == 25
```

```python
[{'destination': {'port': 25}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 009

Branch count: 1  
Document count: 1  
Index: geneve-ut-009

```python
process where process.name == "regsvr32.exe"
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'regsvr32.exe'}, '@timestamp': 0}]
```



### Rule 010

Branch count: 1  
Document count: 1  
Index: geneve-ut-010

```python
process where process.name != "regsvr32.exe"
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'ZFy'}, '@timestamp': 0}]
```



### Rule 011

Branch count: 1  
Document count: 1  
Index: geneve-ut-011

```python
process where process.pid != 0
```

```python
[{'event': {'category': ['process']}, 'process': {'pid': 4289255490}, '@timestamp': 0}]
```



### Rule 012

Branch count: 1  
Document count: 1  
Index: geneve-ut-012

```python
process where process.pid >= 0
```

```python
[{'event': {'category': ['process']}, 'process': {'pid': 4289255490}, '@timestamp': 0}]
```



### Rule 013

Branch count: 1  
Document count: 1  
Index: geneve-ut-013

```python
process where process.pid > 0
```

```python
[{'event': {'category': ['process']}, 'process': {'pid': 4289255490}, '@timestamp': 0}]
```



### Rule 014

Branch count: 1  
Document count: 1  
Index: geneve-ut-014

```python
process where process.code_signature.exists == true
```

```python
[{'process': {'code_signature': {'exists': True}}, 'event': {'category': ['process']}, '@timestamp': 0}]
```



### Rule 015

Branch count: 1  
Document count: 1  
Index: geneve-ut-015

```python
process where process.code_signature.exists != true
```

```python
[{'process': {'code_signature': {'exists': False}}, 'event': {'category': ['process']}, '@timestamp': 0}]
```



### Rule 016

Branch count: 1  
Document count: 1  
Index: geneve-ut-016

```python
any where network.protocol == "some protocol"
```

```python
[{'network': {'protocol': 'some protocol'}, '@timestamp': 0}]
```



### Rule 017

Branch count: 1  
Document count: 1  
Index: geneve-ut-017

```python
any where process.pid == null
```

```python
[{'@timestamp': 0}]
```



### Rule 018

Branch count: 1  
Document count: 1  
Index: geneve-ut-018

```python
any where not process.pid != null
```

```python
[{'@timestamp': 0}]
```



### Rule 019

Branch count: 1  
Document count: 1  
Index: geneve-ut-019

```python
any where process.pid != null
```

```python
[{'process': {'pid': 4289255490}, '@timestamp': 0}]
```



### Rule 020

Branch count: 1  
Document count: 1  
Index: geneve-ut-020

```python
any where not process.pid == null
```

```python
[{'process': {'pid': 4289255490}, '@timestamp': 0}]
```



### Rule 021

Branch count: 1  
Document count: 1  
Index: geneve-ut-021

```python
process where process.name == "regsvr32.exe" and process.parent.name == "cmd.exe"
```

```python
[{'process': {'parent': {'name': 'cmd.exe'}, 'name': 'regsvr32.exe'}, 'event': {'category': ['process']}, '@timestamp': 0}]
```



### Rule 022

Branch count: 1  
Document count: 1  
Index: geneve-ut-022

```python
process where process.name : ("*.EXE", "*.DLL")
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'XIUtkNI.EXE'}, '@timestamp': 0}]
```



### Rule 023

Branch count: 1  
Document count: 1  
Index: geneve-ut-023

```python
process where process.args != null
```

```python
[{'event': {'category': ['process']}, 'process': {'args': ['ZFy']}, '@timestamp': 0}]
```



### Rule 024

Branch count: 1  
Document count: 1  
Index: geneve-ut-024

```python
process where process.args : "-f" and process.args == "-r"
```

```python
[{'event': {'category': ['process']}, 'process': {'args': ['-f', '-r']}, '@timestamp': 0}]
```



### Rule 025

Branch count: 1  
Document count: 1  
Index: geneve-ut-025

```python
network where destination.ip == "127.0.0.1"
```

```python
[{'destination': {'ip': '127.0.0.1'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 026

Branch count: 1  
Document count: 1  
Index: geneve-ut-026

```python
network where cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
```

```python
[{'destination': {'ip': '192.168.214.62'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 027

Branch count: 1  
Document count: 1  
Index: geneve-ut-027

```python
network where not cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
```

```python
[{'destination': {'ip': '107.31.65.130'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 028

Branch count: 1  
Document count: 1  
Index: geneve-ut-028

```python
network where destination.ip != null
```

```python
[{'destination': {'ip': '107.31.65.130'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 029

Branch count: 1  
Document count: 1  
Index: geneve-ut-029

```python
network where destination.ip == "::1"
```

```python
[{'destination': {'ip': '::1'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 030

Branch count: 1  
Document count: 1  
Index: geneve-ut-030

```python
network where destination.ip == "822e::/16"
```

```python
[{'destination': {'ip': '822e:c14a:e6ea:94e4:e5ac:b58c:1b43:3a53'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 031

Branch count: 1  
Document count: 1  
Index: geneve-ut-031

```python
event.category:network and destination.ip:"822e::/16"
```

```python
[{'destination': {'ip': '822e:c14a:e6ea:94e4:e5ac:b58c:1b43:3a53'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 032

Branch count: 1  
Document count: 1  
Index: geneve-ut-032

```python
network where host.ip != null
```

```python
[{'event': {'category': ['network']}, 'host': {'ip': ['107.31.65.130']}, '@timestamp': 0}]
```



### Rule 033

Branch count: 1  
Document count: 1  
Index: geneve-ut-033

```python
event.category:network and host.ip:"822e::/96"
```

```python
[{'event': {'category': ['network']}, 'host': {'ip': ['822e::e6ea:94e4']}, '@timestamp': 0}]
```



### Rule 034

Branch count: 2  
Document count: 2  
Index: geneve-ut-034

```python
network where not (source.port > 512 and source.port < 1024)
```

```python
[{'event': {'category': ['network']}, 'source': {'port': 488}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'source': {'port': 28447}, '@timestamp': 1}]
```



### Rule 035

Branch count: 2  
Document count: 2  
Index: geneve-ut-035

```python
network where source.port > 512 or source.port < 1024
```

```python
[{'event': {'category': ['network']}, 'source': {'port': 59173}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'source': {'port': 628}, '@timestamp': 1}]
```



### Rule 036

Branch count: 2  
Document count: 2  
Index: geneve-ut-036

```python
network where source.port < 2000 and (source.port > 512 or source.port > 1024)
```

```python
[{'event': {'category': ['network']}, 'source': {'port': 1768}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'source': {'port': 1915}, '@timestamp': 1}]
```



### Rule 037

Branch count: 2  
Document count: 2  
Index: geneve-ut-037

```python
network where (source.port > 512 or source.port > 1024) and source.port < 2000
```

```python
[{'event': {'category': ['network']}, 'source': {'port': 1768}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'source': {'port': 1915}, '@timestamp': 1}]
```



### Rule 038

Branch count: 4  
Document count: 4  
Index: geneve-ut-038

```python
network where (source.port > 1024 or source.port < 2000) and (source.port < 4000 or source.port > 512)
```

```python
[{'event': {'category': ['network']}, 'source': {'port': 3536}, '@timestamp': 0},
 {'event': {'category': ['network']}, 'source': {'port': 58008}, '@timestamp': 1},
 {'event': {'category': ['network']}, 'source': {'port': 975}, '@timestamp': 2},
 {'event': {'category': ['network']}, 'source': {'port': 1369}, '@timestamp': 3}]
```



### Rule 039

Branch count: 2  
Document count: 2  
Index: geneve-ut-039

```python
network where destination.port in (80, 443)
```

```python
[{'destination': {'port': 80}, 'event': {'category': ['network']}, '@timestamp': 0},
 {'destination': {'port': 443}, 'event': {'category': ['network']}, '@timestamp': 1}]
```



### Rule 040

Branch count: 2  
Document count: 2  
Index: geneve-ut-040

```python
process where process.name == "regsvr32.exe" or process.parent.name == "cmd.exe"
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'regsvr32.exe'}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, '@timestamp': 1}]
```



### Rule 041

Branch count: 3  
Document count: 3  
Index: geneve-ut-041

```python
process where process.name == "regsvr32.exe" or process.name == "cmd.exe" or process.name == "powershell.exe"
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'regsvr32.exe'}, '@timestamp': 0},
 {'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, '@timestamp': 1},
 {'event': {'category': ['process']}, 'process': {'name': 'powershell.exe'}, '@timestamp': 2}]
```



### Rule 042

Branch count: 3  
Document count: 3  
Index: geneve-ut-042

```python
process where process.name in ("regsvr32.exe", "cmd.exe", "powershell.exe")
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'regsvr32.exe'}, '@timestamp': 0},
 {'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, '@timestamp': 1},
 {'event': {'category': ['process']}, 'process': {'name': 'powershell.exe'}, '@timestamp': 2}]
```



### Rule 043

Branch count: 3  
Document count: 3  
Index: geneve-ut-043

```python
process where process.name in ("regsvr32.exe", "cmd.exe") or process.name == "powershell.exe"
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'regsvr32.exe'}, '@timestamp': 0},
 {'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, '@timestamp': 1},
 {'event': {'category': ['process']}, 'process': {'name': 'powershell.exe'}, '@timestamp': 2}]
```



### Rule 044

Branch count: 2  
Document count: 2  
Index: geneve-ut-044

```python
process where event.type in ("start", "process_started") and process.args : "dump-keychain" and process.args : "-d"
```

```python
[{'event': {'type': ['start'], 'category': ['process']}, 'process': {'args': ['dump-keychain', '-d']}, '@timestamp': 0},
 {'event': {'type': ['process_started'], 'category': ['process']}, 'process': {'args': ['dump-keychain', '-d']}, '@timestamp': 1}]
```



### Rule 045

Branch count: 2  
Document count: 2  
Index: geneve-ut-045

```python
event.type:(start or process_started) and (process.args:"dump-keychain" and process.args:"-d")
```

```python
[{'event': {'type': ['start']}, 'process': {'args': ['dump-keychain', '-d']}, '@timestamp': 0},
 {'event': {'type': ['process_started']}, 'process': {'args': ['dump-keychain', '-d']}, '@timestamp': 1}]
```



### Rule 046

Branch count: 1  
Document count: 2  
Index: geneve-ut-046

```python
sequence
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe"]
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, '@timestamp': 1}]
```



### Rule 047

Branch count: 1  
Document count: 2  
Index: geneve-ut-047

```python
sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe"]
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, 'user': {'id': 'ZFy'}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, 'user': {'id': 'ZFy'}, '@timestamp': 1}]
```



### Rule 048

Branch count: 1  
Document count: 2  
Index: geneve-ut-048

```python
sequence
        [process where process.name : "cmd.exe"] by user.id
        [process where process.parent.name : "cmd.exe"] by user.name
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, 'user': {'id': 'ZFy'}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, 'user': {'name': 'ZFy'}, '@timestamp': 1}]
```



### Rule 049

Branch count: 2  
Document count: 4  
Index: geneve-ut-049

```python
sequence
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe" or process.name : "powershell.exe"]
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, '@timestamp': 1},
 {'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, '@timestamp': 2},
 {'event': {'category': ['process']}, 'process': {'name': 'powershell.exe'}, '@timestamp': 3}]
```



### Rule 050

Branch count: 2  
Document count: 4  
Index: geneve-ut-050

```python
sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe" or process.name : "powershell.exe"]
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, 'user': {'id': 'ZFy'}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, 'user': {'id': 'ZFy'}, '@timestamp': 1},
 {'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, 'user': {'id': 'XIU'}, '@timestamp': 2},
 {'event': {'category': ['process']}, 'process': {'name': 'powershell.exe'}, 'user': {'id': 'XIU'}, '@timestamp': 3}]
```



### Rule 051

Branch count: 4  
Document count: 8  
Index: geneve-ut-051

```python
sequence
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.name
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.parent.name
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}, 'name': 'cmd.exe'}, 'event': {'category': ['process']}, '@timestamp': 1},
 {'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, '@timestamp': 2},
 {'process': {'parent': {'name': 'cmd.exe'}, 'name': 'powershell.exe'}, 'event': {'category': ['process']}, '@timestamp': 3},
 {'event': {'category': ['process']}, 'process': {'name': 'powershell.exe'}, '@timestamp': 4},
 {'process': {'parent': {'name': 'powershell.exe'}, 'name': 'cmd.exe'}, 'event': {'category': ['process']}, '@timestamp': 5},
 {'event': {'category': ['process']}, 'process': {'name': 'powershell.exe'}, '@timestamp': 6},
 {'process': {'parent': {'name': 'powershell.exe'}, 'name': 'powershell.exe'}, 'event': {'category': ['process']}, '@timestamp': 7}]
```



### Rule 052

Branch count: 4  
Document count: 8  
Index: geneve-ut-052

```python
sequence by user.id
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.name
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.parent.name
```

```python
[{'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, 'user': {'id': 'ZFy'}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}, 'name': 'cmd.exe'}, 'event': {'category': ['process']}, 'user': {'id': 'ZFy'}, '@timestamp': 1},
 {'event': {'category': ['process']}, 'process': {'name': 'cmd.exe'}, 'user': {'id': 'XIU'}, '@timestamp': 2},
 {'process': {'parent': {'name': 'cmd.exe'}, 'name': 'powershell.exe'}, 'event': {'category': ['process']}, 'user': {'id': 'XIU'}, '@timestamp': 3},
 {'event': {'category': ['process']}, 'process': {'name': 'powershell.exe'}, 'user': {'id': 'tkN'}, '@timestamp': 4},
 {'process': {'parent': {'name': 'powershell.exe'}, 'name': 'cmd.exe'}, 'event': {'category': ['process']}, 'user': {'id': 'tkN'}, '@timestamp': 5},
 {'event': {'category': ['process']}, 'process': {'name': 'powershell.exe'}, 'user': {'id': 'Ioi'}, '@timestamp': 6},
 {'process': {'parent': {'name': 'powershell.exe'}, 'name': 'powershell.exe'}, 'event': {'category': ['process']}, 'user': {'id': 'Ioi'}, '@timestamp': 7}]
```
