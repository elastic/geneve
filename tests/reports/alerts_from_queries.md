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



### Rule 001

Branch count: 1  
Document count: 1  
Index: geneve-ut-001

```python
any where not false
```



### Rule 002

Branch count: 1  
Document count: 1  
Index: geneve-ut-002

```python
any where not (true and false)
```



### Rule 003

Branch count: 1  
Document count: 1  
Index: geneve-ut-003

```python
any where not (false or false)
```



### Rule 004

Branch count: 1  
Document count: 1  
Index: geneve-ut-004

```python
network where source.port > 512 and source.port < 1024
```



### Rule 005

Branch count: 1  
Document count: 1  
Index: geneve-ut-005

```python
network where not (source.port < 512 or source.port > 1024)
```



### Rule 006

Branch count: 1  
Document count: 1  
Index: geneve-ut-006

```python
network where destination.port not in (80, 443)
```



### Rule 007

Branch count: 1  
Document count: 1  
Index: geneve-ut-007

```python
network where not destination.port in (80, 443)
```



### Rule 008

Branch count: 1  
Document count: 1  
Index: geneve-ut-008

```python
network where destination.port == 22 and destination.port in (80, 443) or destination.port == 25
```



### Rule 009

Branch count: 1  
Document count: 1  
Index: geneve-ut-009

```python
process where process.name == "regsvr32.exe"
```



### Rule 010

Branch count: 1  
Document count: 1  
Index: geneve-ut-010

```python
process where process.name != "regsvr32.exe"
```



### Rule 011

Branch count: 1  
Document count: 1  
Index: geneve-ut-011

```python
process where process.pid != 0
```



### Rule 012

Branch count: 1  
Document count: 1  
Index: geneve-ut-012

```python
process where process.pid >= 0
```



### Rule 013

Branch count: 1  
Document count: 1  
Index: geneve-ut-013

```python
process where process.pid > 0
```



### Rule 014

Branch count: 1  
Document count: 1  
Index: geneve-ut-014

```python
process where process.code_signature.exists == true
```



### Rule 015

Branch count: 1  
Document count: 1  
Index: geneve-ut-015

```python
process where process.code_signature.exists != true
```



### Rule 016

Branch count: 1  
Document count: 1  
Index: geneve-ut-016

```python
any where network.protocol == "some protocol"
```



### Rule 017

Branch count: 1  
Document count: 1  
Index: geneve-ut-017

```python
any where process.pid == null
```



### Rule 018

Branch count: 1  
Document count: 1  
Index: geneve-ut-018

```python
any where not process.pid != null
```



### Rule 019

Branch count: 1  
Document count: 1  
Index: geneve-ut-019

```python
any where process.pid != null
```



### Rule 020

Branch count: 1  
Document count: 1  
Index: geneve-ut-020

```python
any where not process.pid == null
```



### Rule 021

Branch count: 1  
Document count: 1  
Index: geneve-ut-021

```python
process where process.name == "regsvr32.exe" and process.parent.name == "cmd.exe"
```



### Rule 022

Branch count: 1  
Document count: 1  
Index: geneve-ut-022

```python
process where process.args != null
```



### Rule 023

Branch count: 1  
Document count: 1  
Index: geneve-ut-023

```python
process where process.args : "-f" and process.args == "-r"
```



### Rule 024

Branch count: 1  
Document count: 1  
Index: geneve-ut-024

```python
network where destination.ip == "127.0.0.1"
```



### Rule 025

Branch count: 1  
Document count: 1  
Index: geneve-ut-025

```python
network where cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
```



### Rule 026

Branch count: 1  
Document count: 1  
Index: geneve-ut-026

```python
network where not cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
```



### Rule 027

Branch count: 1  
Document count: 1  
Index: geneve-ut-027

```python
network where destination.ip != null
```



### Rule 028

Branch count: 1  
Document count: 1  
Index: geneve-ut-028

```python
network where destination.ip == "::1"
```



### Rule 029

Branch count: 1  
Document count: 1  
Index: geneve-ut-029

```python
network where destination.ip == "822e::/16"
```



### Rule 030

Branch count: 1  
Document count: 1  
Index: geneve-ut-030

```python
event.category:network and destination.ip:"822e::/16"
```



### Rule 031

Branch count: 1  
Document count: 1  
Index: geneve-ut-031

```python
network where host.ip != null
```



### Rule 032

Branch count: 1  
Document count: 1  
Index: geneve-ut-032

```python
event.category:network and host.ip:"822e::/96"
```



### Rule 033

Branch count: 1  
Document count: 1  
Index: geneve-ut-033

```python
event.category:process and not process.args : (TRUE or true)
```



### Rule 034

Branch count: 2  
Document count: 2  
Index: geneve-ut-034

```python
network where not (source.port > 512 and source.port < 1024)
```



### Rule 035

Branch count: 2  
Document count: 2  
Index: geneve-ut-035

```python
network where source.port > 512 or source.port < 1024
```



### Rule 036

Branch count: 2  
Document count: 2  
Index: geneve-ut-036

```python
network where source.port < 2000 and (source.port > 512 or source.port > 1024)
```



### Rule 037

Branch count: 2  
Document count: 2  
Index: geneve-ut-037

```python
network where (source.port > 512 or source.port > 1024) and source.port < 2000
```



### Rule 038

Branch count: 4  
Document count: 4  
Index: geneve-ut-038

```python
network where (source.port > 1024 or source.port < 2000) and (source.port < 4000 or source.port > 512)
```



### Rule 039

Branch count: 2  
Document count: 2  
Index: geneve-ut-039

```python
network where destination.port in (80, 443)
```



### Rule 040

Branch count: 2  
Document count: 2  
Index: geneve-ut-040

```python
process where process.name : ("*.EXE", "*.DLL")
```



### Rule 041

Branch count: 2  
Document count: 2  
Index: geneve-ut-041

```python
process where process.name == "regsvr32.exe" or process.parent.name == "cmd.exe"
```



### Rule 042

Branch count: 3  
Document count: 3  
Index: geneve-ut-042

```python
process where process.name == "regsvr32.exe" or process.name == "cmd.exe" or process.name == "powershell.exe"
```



### Rule 043

Branch count: 3  
Document count: 3  
Index: geneve-ut-043

```python
process where process.name in ("regsvr32.exe", "cmd.exe", "powershell.exe")
```



### Rule 044

Branch count: 3  
Document count: 3  
Index: geneve-ut-044

```python
process where process.name in ("regsvr32.exe", "cmd.exe") or process.name == "powershell.exe"
```



### Rule 045

Branch count: 2  
Document count: 2  
Index: geneve-ut-045

```python
process where event.type in ("start", "process_started") and process.args : "dump-keychain" and process.args : "-d"
```



### Rule 046

Branch count: 2  
Document count: 2  
Index: geneve-ut-046

```python
event.type:(start or process_started) and (process.args:"dump-keychain" and process.args:"-d")
```



### Rule 047

Branch count: 4  
Document count: 4  
Index: geneve-ut-047

```python
event.category:process and process.args:a and process.args:(b1 or b2) and process.args:(c1 or c2)
```



### Rule 048

Branch count: 4  
Document count: 4  
Index: geneve-ut-048

```python
process where process.args : "a" and process.args : ("b1", "b2") and process.args : ("c1", "c2")
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



### Rule 050

Branch count: 1  
Document count: 2  
Index: geneve-ut-050

```python
sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe"]
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



### Rule 052

Branch count: 1  
Document count: 2  
Index: geneve-ut-052

```python
sequence
        [process where process.name : "*.exe"] by process.name
        [process where process.name : "*.dll"] by process.parent.name
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



### Rule 054

Branch count: 2  
Document count: 4  
Index: geneve-ut-054

```python
sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe" or process.name : "powershell.exe"]
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



### Rule 056

Branch count: 4  
Document count: 8  
Index: geneve-ut-056

```python
sequence by user.id
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.name
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.parent.name
```
