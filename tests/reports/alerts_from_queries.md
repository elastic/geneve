# Alerts generation from test queries

This report captures the unit test queries signals generation coverage.
Here you can learn what queries are supported.

## Table of contents
   1. [Rules with the correct signals (57)](#rules-with-the-correct-signals-57)

## Rules with the correct signals (57)

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
[{'source': {'port': 971}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 005

Branch count: 1  
Document count: 1  
Index: geneve-ut-005

```python
network where not (source.port < 512 or source.port > 1024)
```

```python
[{'source': {'port': 999}, 'event': {'category': ['network']}, '@timestamp': 0}]
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
[{'process': {'name': 'regsvr32.exe'}, 'event': {'category': ['process']}, '@timestamp': 0}]
```



### Rule 010

Branch count: 1  
Document count: 1  
Index: geneve-ut-010

```python
process where process.name != "regsvr32.exe"
```

```python
[{'process': {'name': 'TvCfUyyFjS'}, 'event': {'category': ['process']}, '@timestamp': 0}]
```



### Rule 011

Branch count: 1  
Document count: 1  
Index: geneve-ut-011

```python
process where process.pid != 0
```

```python
[{'process': {'pid': 4289255490}, 'event': {'category': ['process']}, '@timestamp': 0}]
```



### Rule 012

Branch count: 1  
Document count: 1  
Index: geneve-ut-012

```python
process where process.pid >= 0
```

```python
[{'process': {'pid': 4289255490}, 'event': {'category': ['process']}, '@timestamp': 0}]
```



### Rule 013

Branch count: 1  
Document count: 1  
Index: geneve-ut-013

```python
process where process.pid > 0
```

```python
[{'process': {'pid': 4289255490}, 'event': {'category': ['process']}, '@timestamp': 0}]
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
[{'process': {'name': 'regsvr32.exe', 'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, '@timestamp': 0}]
```



### Rule 022

Branch count: 1  
Document count: 1  
Index: geneve-ut-022

```python
process where process.args != null
```

```python
[{'process': {'args': ['TvCfUyyFjS']}, 'event': {'category': ['process']}, '@timestamp': 0}]
```



### Rule 023

Branch count: 1  
Document count: 1  
Index: geneve-ut-023

```python
process where process.args : "-f" and process.args == "-r"
```

```python
[{'process': {'args': ['-f', '-r']}, 'event': {'category': ['process']}, '@timestamp': 0}]
```



### Rule 024

Branch count: 1  
Document count: 1  
Index: geneve-ut-024

```python
network where destination.ip == "127.0.0.1"
```

```python
[{'destination': {'ip': '127.0.0.1'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 025

Branch count: 1  
Document count: 1  
Index: geneve-ut-025

```python
network where cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
```

```python
[{'destination': {'ip': '192.168.214.62'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 026

Branch count: 1  
Document count: 1  
Index: geneve-ut-026

```python
network where not cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
```

```python
[{'destination': {'ip': '107.31.65.130'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 027

Branch count: 1  
Document count: 1  
Index: geneve-ut-027

```python
network where destination.ip != null
```

```python
[{'destination': {'ip': '107.31.65.130'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 028

Branch count: 1  
Document count: 1  
Index: geneve-ut-028

```python
network where destination.ip == "::1"
```

```python
[{'destination': {'ip': '::1'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 029

Branch count: 1  
Document count: 1  
Index: geneve-ut-029

```python
network where destination.ip == "822e::/16"
```

```python
[{'destination': {'ip': '822e:c14a:e6ea:94e4:e5ac:b58c:1b43:3a53'}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 030

Branch count: 1  
Document count: 1  
Index: geneve-ut-030

```python
event.category:network and destination.ip:"822e::/16"
```

```python
[{'event': {'category': ['network']}, 'destination': {'ip': '822e:3686:aa79:ec58:8d14:2981:f18d:f2a6'}, '@timestamp': 0}]
```



### Rule 031

Branch count: 1  
Document count: 1  
Index: geneve-ut-031

```python
network where host.ip != null
```

```python
[{'host': {'ip': ['107.31.65.130']}, 'event': {'category': ['network']}, '@timestamp': 0}]
```



### Rule 032

Branch count: 1  
Document count: 1  
Index: geneve-ut-032

```python
event.category:network and host.ip:"822e::/96"
```

```python
[{'event': {'category': ['network']}, 'host': {'ip': ['822e::aa79:ec58']}, '@timestamp': 0}]
```



### Rule 033

Branch count: 1  
Document count: 1  
Index: geneve-ut-033

```python
event.category:process and not process.args : (TRUE or true)
```

```python
[{'event': {'category': ['process']}, 'process': {'args': ['XIUtkNI']}, '@timestamp': 0}]
```



### Rule 034

Branch count: 2  
Document count: 2  
Index: geneve-ut-034

```python
network where not (source.port > 512 and source.port < 1024)
```

```python
[{'source': {'port': 488}, 'event': {'category': ['network']}, '@timestamp': 0},
 {'source': {'port': 44665}, 'event': {'category': ['network']}, '@timestamp': 80}]
```



### Rule 035

Branch count: 2  
Document count: 2  
Index: geneve-ut-035

```python
network where source.port > 512 or source.port < 1024
```

```python
[{'source': {'port': 59173}, 'event': {'category': ['network']}, '@timestamp': 0},
 {'source': {'port': 967}, 'event': {'category': ['network']}, '@timestamp': 63}]
```



### Rule 036

Branch count: 2  
Document count: 2  
Index: geneve-ut-036

```python
network where source.port < 2000 and (source.port > 512 or source.port > 1024)
```

```python
[{'source': {'port': 1768}, 'event': {'category': ['network']}, '@timestamp': 0},
 {'source': {'port': 1991}, 'event': {'category': ['network']}, '@timestamp': 63}]
```



### Rule 037

Branch count: 2  
Document count: 2  
Index: geneve-ut-037

```python
network where (source.port > 512 or source.port > 1024) and source.port < 2000
```

```python
[{'source': {'port': 1768}, 'event': {'category': ['network']}, '@timestamp': 0},
 {'source': {'port': 1991}, 'event': {'category': ['network']}, '@timestamp': 63}]
```



### Rule 038

Branch count: 4  
Document count: 4  
Index: geneve-ut-038

```python
network where (source.port > 1024 or source.port < 2000) and (source.port < 4000 or source.port > 512)
```

```python
[{'source': {'port': 3536}, 'event': {'category': ['network']}, '@timestamp': 0},
 {'source': {'port': 62862}, 'event': {'category': ['network']}, '@timestamp': 63},
 {'source': {'port': 981}, 'event': {'category': ['network']}, '@timestamp': 121},
 {'source': {'port': 1749}, 'event': {'category': ['network']}, '@timestamp': 190}]
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
 {'destination': {'port': 443}, 'event': {'category': ['network']}, '@timestamp': 63}]
```



### Rule 040

Branch count: 2  
Document count: 2  
Index: geneve-ut-040

```python
process where process.name : ("*.EXE", "*.DLL")
```

```python
[{'process': {'name': 'XIUtkNI.EXE'}, 'event': {'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'ILOoOHmx.DLL'}, 'event': {'category': ['process']}, '@timestamp': 30}]
```



### Rule 041

Branch count: 2  
Document count: 2  
Index: geneve-ut-041

```python
process where process.name == "regsvr32.exe" or process.parent.name == "cmd.exe"
```

```python
[{'process': {'name': 'regsvr32.exe'}, 'event': {'category': ['process']}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, '@timestamp': 80}]
```



### Rule 042

Branch count: 3  
Document count: 3  
Index: geneve-ut-042

```python
process where process.name == "regsvr32.exe" or process.name == "cmd.exe" or process.name == "powershell.exe"
```

```python
[{'process': {'name': 'regsvr32.exe'}, 'event': {'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, '@timestamp': 80},
 {'process': {'name': 'powershell.exe'}, 'event': {'category': ['process']}, '@timestamp': 151}]
```



### Rule 043

Branch count: 3  
Document count: 3  
Index: geneve-ut-043

```python
process where process.name in ("regsvr32.exe", "cmd.exe", "powershell.exe")
```

```python
[{'process': {'name': 'regsvr32.exe'}, 'event': {'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, '@timestamp': 80},
 {'process': {'name': 'powershell.exe'}, 'event': {'category': ['process']}, '@timestamp': 151}]
```



### Rule 044

Branch count: 3  
Document count: 3  
Index: geneve-ut-044

```python
process where process.name in ("regsvr32.exe", "cmd.exe") or process.name == "powershell.exe"
```

```python
[{'process': {'name': 'regsvr32.exe'}, 'event': {'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, '@timestamp': 80},
 {'process': {'name': 'powershell.exe'}, 'event': {'category': ['process']}, '@timestamp': 151}]
```



### Rule 045

Branch count: 2  
Document count: 2  
Index: geneve-ut-045

```python
process where event.type in ("start", "process_started") and process.args : "dump-keychain" and process.args : "-d"
```

```python
[{'event': {'category': ['process'], 'type': ['start']}, 'process': {'args': ['dump-keychain', '-d']}, '@timestamp': 0},
 {'event': {'category': ['process'], 'type': ['process_started']}, 'process': {'args': ['dump-keychain', '-d']}, '@timestamp': 58}]
```



### Rule 046

Branch count: 2  
Document count: 2  
Index: geneve-ut-046

```python
event.type:(start or process_started) and (process.args:"dump-keychain" and process.args:"-d")
```

```python
[{'event': {'type': ['start']}, 'process': {'args': ['dump-keychain', '-d']}, '@timestamp': 0},
 {'event': {'type': ['process_started']}, 'process': {'args': ['dump-keychain', '-d']}, '@timestamp': 58}]
```



### Rule 047

Branch count: 4  
Document count: 4  
Index: geneve-ut-047

```python
event.category:process and process.args:a and process.args:(b1 or b2) and process.args:(c1 or c2)
```

```python
[{'event': {'category': ['process']}, 'process': {'args': ['a', 'b1', 'c1']}, '@timestamp': 0},
 {'event': {'category': ['process']}, 'process': {'args': ['a', 'b1', 'c2']}, '@timestamp': 71},
 {'event': {'category': ['process']}, 'process': {'args': ['a', 'b2', 'c1']}, '@timestamp': 101},
 {'event': {'category': ['process']}, 'process': {'args': ['a', 'b2', 'c2']}, '@timestamp': 185}]
```



### Rule 048

Branch count: 4  
Document count: 4  
Index: geneve-ut-048

```python
process where process.args : "a" and process.args : ("b1", "b2") and process.args : ("c1", "c2")
```

```python
[{'process': {'args': ['a', 'b1', 'c1']}, 'event': {'category': ['process']}, '@timestamp': 0},
 {'process': {'args': ['a', 'b1', 'c2']}, 'event': {'category': ['process']}, '@timestamp': 71},
 {'process': {'args': ['a', 'b2', 'c1']}, 'event': {'category': ['process']}, '@timestamp': 101},
 {'process': {'args': ['a', 'b2', 'c2']}, 'event': {'category': ['process']}, '@timestamp': 185}]
```



### Rule 049

Branch count: 1  
Document count: 2  
Index: geneve-ut-049

```python
sequence
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe"]
```

```python
[{'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, '@timestamp': 80}]
```



### Rule 050

Branch count: 1  
Document count: 2  
Index: geneve-ut-050

```python
sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe"]
```

```python
[{'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, 'user': {'id': 'TvCfUyyFjS'}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, 'user': {'id': 'TvCfUyyFjS'}, '@timestamp': 94}]
```



### Rule 051

Branch count: 1  
Document count: 2  
Index: geneve-ut-051

```python
sequence
        [process where process.name : "cmd.exe"] by user.id
        [process where process.parent.name : "cmd.exe"] by user.name
```

```python
[{'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, 'user': {'id': 'TvCfUyyFjS'}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, 'user': {'name': 'TvCfUyyFjS'}, '@timestamp': 94}]
```



### Rule 052

Branch count: 1  
Document count: 2  
Index: geneve-ut-052

```python
sequence
        [process where process.name : "*.exe"] by process.name
        [process where process.name : "*.dll"] by process.parent.name
```

```python
[{'process': {'name': 'XIUtkNI.exe'}, 'event': {'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'ILOoOHmx.dll', 'parent': {'name': 'XIUtkNI.exe'}}, 'event': {'category': ['process']}, '@timestamp': 30}]
```



### Rule 053

Branch count: 2  
Document count: 4  
Index: geneve-ut-053

```python
sequence
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe" or process.name : "powershell.exe"]
```

```python
[{'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, '@timestamp': 80},
 {'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, '@timestamp': 151},
 {'process': {'name': 'powershell.exe'}, 'event': {'category': ['process']}, '@timestamp': 238}]
```



### Rule 054

Branch count: 2  
Document count: 4  
Index: geneve-ut-054

```python
sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe" or process.name : "powershell.exe"]
```

```python
[{'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, 'user': {'id': 'TvCfUyyFjS'}, '@timestamp': 0},
 {'process': {'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, 'user': {'id': 'TvCfUyyFjS'}, '@timestamp': 94},
 {'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, 'user': {'id': 'HmxBnLeO'}, '@timestamp': 178},
 {'process': {'name': 'powershell.exe'}, 'event': {'category': ['process']}, 'user': {'id': 'HmxBnLeO'}, '@timestamp': 204}]
```



### Rule 055

Branch count: 4  
Document count: 8  
Index: geneve-ut-055

```python
sequence
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.name
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.parent.name
```

```python
[{'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, '@timestamp': 0},
 {'process': {'name': 'cmd.exe', 'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, '@timestamp': 80},
 {'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, '@timestamp': 151},
 {'process': {'name': 'powershell.exe', 'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, '@timestamp': 238},
 {'process': {'name': 'powershell.exe'}, 'event': {'category': ['process']}, '@timestamp': 268},
 {'process': {'name': 'cmd.exe', 'parent': {'name': 'powershell.exe'}}, 'event': {'category': ['process']}, '@timestamp': 362},
 {'process': {'name': 'powershell.exe'}, 'event': {'category': ['process']}, '@timestamp': 446},
 {'process': {'name': 'powershell.exe', 'parent': {'name': 'powershell.exe'}}, 'event': {'category': ['process']}, '@timestamp': 487}]
```



### Rule 056

Branch count: 4  
Document count: 8  
Index: geneve-ut-056

```python
sequence by user.id
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.name
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.parent.name
```

```python
[{'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, 'user': {'id': 'TvCfUyyFjS'}, '@timestamp': 0},
 {'process': {'name': 'cmd.exe', 'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, 'user': {'id': 'TvCfUyyFjS'}, '@timestamp': 94},
 {'process': {'name': 'cmd.exe'}, 'event': {'category': ['process']}, 'user': {'id': 'HmxBnLeO'}, '@timestamp': 178},
 {'process': {'name': 'powershell.exe', 'parent': {'name': 'cmd.exe'}}, 'event': {'category': ['process']}, 'user': {'id': 'HmxBnLeO'}, '@timestamp': 204},
 {'process': {'name': 'powershell.exe'}, 'event': {'category': ['process']}, 'user': {'id': 'ymEEwVPYMG'}, '@timestamp': 221},
 {'process': {'name': 'cmd.exe', 'parent': {'name': 'powershell.exe'}}, 'event': {'category': ['process']}, 'user': {'id': 'ymEEwVPYMG'}, '@timestamp': 244},
 {'process': {'name': 'powershell.exe'}, 'event': {'category': ['process']}, 'user': {'id': 'PZRgUv'}, '@timestamp': 327},
 {'process': {'name': 'powershell.exe', 'parent': {'name': 'powershell.exe'}}, 'event': {'category': ['process']}, 'user': {'id': 'PZRgUv'}, '@timestamp': 358}]
```
