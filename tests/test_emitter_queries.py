# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Test emitter with querie."""

import os
import unittest

import tests.utils as tu
from geneve.events_emitter import SourceEvents, guess_from_query

from . import jupyter

event_docs_mappings = {
    """process where process.name == "regsvr32.exe"
    """: {
        "properties": {
            "@timestamp": {"type": "date"},
            "event": {"properties": {"category": {"type": "keyword"}}},
            "process": {"properties": {"name": {"type": "keyword"}}},
        },
    },
    """network where source.ip == "::1" or destination.ip == "::1"
    """: {
        "properties": {
            "@timestamp": {"type": "date"},
            "event": {"properties": {"category": {"type": "keyword"}}},
            "destination": {"properties": {"ip": {"type": "ip"}}},
            "source": {"properties": {"ip": {"type": "ip"}}},
        },
    },
    """process where process.code_signature.exists == false and process.pid > 1024
    """: {
        "properties": {
            "@timestamp": {"type": "date"},
            "event": {"properties": {"category": {"type": "keyword"}}},
            "process": {
                "properties": {
                    "code_signature": {"properties": {"exists": {"type": "boolean"}}},
                    "pid": {"type": "long"},
                }
            },  # noqa: E501
        },
    },
    """azure.auditlogs.properties.target_resources.*.display_name:guest and azure.activitylogs.level:*
    """: {
        "dynamic_templates": [
            {
                "azure.auditlogs.properties.target_resources.*.display_name": {
                    "path_match": "azure.auditlogs.properties.target_resources.*.display_name",
                    "mapping": {
                        "type": "keyword",
                    },
                },
            }
        ],
        "properties": {
            "@timestamp": {"type": "date"},
            "azure": {
                "properties": {
                    "activitylogs": {
                        "properties": {
                            "level": {"type": "long"},
                        },
                    },
                },
            },
        },
    },
}

mono_branch_mono_doc = {
    """any where true
    """: [
        [{}],
    ],
    """any where not false
    """: [
        [{}],
    ],
    """any where not (true and false)
    """: [
        [{}],
    ],
    """any where not (false or false)
    """: [
        [{}],
    ],
    """network where source.port > 512 and source.port < 1024
    """: [
        [{"event": {"category": ["network"]}, "source": {"port": 794}}],
    ],
    """network where not (source.port < 512 or source.port > 1024)
    """: [
        [{"event": {"category": ["network"]}, "source": {"port": 1021}}],
    ],
    """network where destination.port not in (80, 443)
    """: [
        [{"event": {"category": ["network"]}, "destination": {"port": 7564}}],
    ],
    """network where not destination.port in (80, 443)
    """: [
        [{"event": {"category": ["network"]}, "destination": {"port": 246}}],
    ],
    """network where destination.port == 22 and destination.port in (80, 443) or destination.port == 25
    """: [
        [{"event": {"category": ["network"]}, "destination": {"port": 25}}],
    ],
    """process where process.name == "regsvr32.exe"
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}}],
    ],
    """process where process.name != "regsvr32.exe"
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "CFMpmDwut"}}],
    ],
    """process where process.pid != 0
    """: [
        [{"event": {"category": ["process"]}, "process": {"pid": 3009213395}}],
    ],
    """process where process.pid >= 0
    """: [
        [{"event": {"category": ["process"]}, "process": {"pid": 1706296503}}],
    ],
    """process where process.pid > 0
    """: [
        [{"event": {"category": ["process"]}, "process": {"pid": 2505219495}}],
    ],
    """process where process.code_signature.exists == true
    """: [
        [{"event": {"category": ["process"]}, "process": {"code_signature": {"exists": True}}}],
    ],
    """process where process.code_signature.exists != true
    """: [
        [{"event": {"category": ["process"]}, "process": {"code_signature": {"exists": False}}}],
    ],
    """any where network.protocol == "some protocol"
    """: [
        [{"network": {"protocol": "some protocol"}}],
    ],
    """any where process.pid == null
    """: [
        [{}],
    ],
    """any where not process.pid != null
    """: [
        [{}],
    ],
    """any where process.pid != null
    """: [
        [{"process": {"pid": 102799507}}],
    ],
    """any where not process.pid == null
    """: [
        [{"process": {"pid": 2584819203}}],
    ],
    """process where process.name == "regsvr32.exe" and process.parent.name == "cmd.exe"
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe", "parent": {"name": "cmd.exe"}}}],
    ],
    """process where process.args != null
    """: [
        [{"event": {"category": ["process"]}, "process": {"args": ["oGyCAQpaw"]}}],
    ],
    """process where process.args : "-f" and process.args == "-r"
    """: [
        [{"event": {"category": ["process"]}, "process": {"args": ["-f", "-r"]}}],
    ],
    """network where destination.ip == "127.0.0.1"
    """: [
        [{"event": {"category": ["network"]}, "destination": {"ip": "127.0.0.1"}}],
    ],
    """network where cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
    """: [
        [{"event": {"category": ["network"]}, "destination": {"ip": "10.77.153.19"}}],
    ],
    """network where not cidrMatch(destination.ip, "10.0.0.0/8", "192.168.0.0/16")
    """: [
        [{"event": {"category": ["network"]}, "destination": {"ip": "0.225.250.37"}}],
    ],
    """network where destination.ip != null
    """: [
        [{"event": {"category": ["network"]}, "destination": {"ip": "143.174.17.137"}}],
    ],
    """network where destination.ip == "::1"
    """: [
        [{"event": {"category": ["network"]}, "destination": {"ip": "::1"}}],
    ],
    """network where destination.ip == "822e::/16"
    """: [
        [{"event": {"category": ["network"]}, "destination": {"ip": "822e:f740:dcc5:503a:946f:261:2c07:f7a5"}}],
    ],
    """event.category:network and destination.ip:"822e::/16"
    """: [
        [{"event": {"category": ["network"]}, "destination": {"ip": "822e:f0be:74f0:33be:4671:6fb9:4832:99ba"}}],
    ],
    """network where host.ip != null
    """: [
        [{"event": {"category": ["network"]}, "host": {"ip": ["238.136.72.63"]}}],
    ],
    """event.category:network and host.ip:"822e::/96"
    """: [
        [{"event": {"category": ["network"]}, "host": {"ip": ["822e::680b:a785"]}}],
    ],
    """event.category:process and not process.args : (TRUE or true)
    """: [
        [{"event": {"category": ["process"]}, "process": {"args": ["IjvkBbQFwv"]}}],
    ],
}

multi_branch_mono_doc = {
    """network where not (source.port > 512 and source.port < 1024)
    """: [
        [{"event": {"category": ["network"]}, "source": {"port": 182}}],
        [{"event": {"category": ["network"]}, "source": {"port": 11985}}],
    ],
    """network where source.port > 512 or source.port < 1024
    """: [
        [{"event": {"category": ["network"]}, "source": {"port": 44925}}],
        [{"event": {"category": ["network"]}, "source": {"port": 398}}],
    ],
    """network where source.port < 2000 and (source.port > 512 or source.port > 1024)
    """: [
        [{"event": {"category": ["network"]}, "source": {"port": 1334}}],
        [{"event": {"category": ["network"]}, "source": {"port": 1645}}],
    ],
    """network where (source.port > 512 or source.port > 1024) and source.port < 2000
    """: [
        [{"event": {"category": ["network"]}, "source": {"port": 575}}],
        [{"event": {"category": ["network"]}, "source": {"port": 1635}}],
    ],
    """network where (source.port > 1024 or source.port < 2000) and (source.port < 4000 or source.port > 512)
    """: [
        [{"event": {"category": ["network"]}, "source": {"port": 1970}}],
        [{"event": {"category": ["network"]}, "source": {"port": 31485}}],
        [{"event": {"category": ["network"]}, "source": {"port": 1825}}],
        [{"event": {"category": ["network"]}, "source": {"port": 756}}],
    ],
    """network where destination.port in (80, 443)
    """: [
        [{"event": {"category": ["network"]}, "destination": {"port": 80}}],
        [{"event": {"category": ["network"]}, "destination": {"port": 443}}],
    ],
    """process where process.name : ("*.EXE", "*.DLL")
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "LeneQZk.EXE"}}],
        [{"event": {"category": ["process"]}, "process": {"name": "xfWH.DLL"}}],
    ],
    """process where process.name == "regsvr32.exe" or process.parent.name == "cmd.exe"
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}}],
    ],
    """process where process.name == "regsvr32.exe" or process.name == "cmd.exe" or process.name == "powershell.exe"
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}}],
    ],
    """process where process.name in ("regsvr32.exe", "cmd.exe", "powershell.exe")
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}}],
    ],
    """process where process.name in ("regsvr32.exe", "cmd.exe") or process.name == "powershell.exe"
    """: [
        [{"event": {"category": ["process"]}, "process": {"name": "regsvr32.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}}],
        [{"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}}],
    ],
    """process where event.type in ("start", "process_started") and process.args : "dump-keychain" and process.args : "-d"
    """: [
        [{"event": {"category": ["process"], "type": ["start"]}, "process": {"args": ["dump-keychain", "-d"]}}],
        [
            {
                "event": {"category": ["process"], "type": ["process_started"]},
                "process": {"args": ["dump-keychain", "-d"]},
            }
        ],  # noqa: E501
    ],
    """event.type:(start or process_started) and (process.args:"dump-keychain" and process.args:"-d")
    """: [
        [{"event": {"type": ["start"]}, "process": {"args": ["dump-keychain", "-d"]}}],
        [{"event": {"type": ["process_started"]}, "process": {"args": ["dump-keychain", "-d"]}}],
    ],
    """event.category:process and process.args:a and process.args:(b1 or b2) and process.args:(c1 or c2)
    """: [
        [{"event": {"category": ["process"]}, "process": {"args": ["a", "b1", "c1"]}}],
        [{"event": {"category": ["process"]}, "process": {"args": ["a", "b1", "c2"]}}],
        [{"event": {"category": ["process"]}, "process": {"args": ["a", "b2", "c1"]}}],
        [{"event": {"category": ["process"]}, "process": {"args": ["a", "b2", "c2"]}}],
    ],
    """process where process.args : "a" and process.args : ("b1", "b2") and process.args : ("c1", "c2")
    """: [
        [{"event": {"category": ["process"]}, "process": {"args": ["a", "b1", "c1"]}}],
        [{"event": {"category": ["process"]}, "process": {"args": ["a", "b1", "c2"]}}],
        [{"event": {"category": ["process"]}, "process": {"args": ["a", "b2", "c1"]}}],
        [{"event": {"category": ["process"]}, "process": {"args": ["a", "b2", "c2"]}}],
    ],
}

mono_branch_multi_doc = {
    """sequence
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe"]
    """: [
        [
            {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
            {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}},
        ]
    ],
    """sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe"]
    """: [
        [
            {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "LDgZ"}},
            {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"id": "LDgZ"}},
        ]
    ],
    """sequence
        [process where process.name : "cmd.exe"] by user.id
        [process where process.parent.name : "cmd.exe"] by user.name
    """: [
        [
            {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "Kv"}},
            {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"name": "Kv"}},
        ]
    ],
    """sequence
        [process where process.name : "*.exe"] by process.name
        [process where process.name : "*.dll"] by process.parent.name
    """: [
        [
            {"event": {"category": ["process"]}, "process": {"name": "QfHxGuOAe.exe"}},
            {"event": {"category": ["process"]}, "process": {"name": "pEGA.dll", "parent": {"name": "QfHxGuOAe.exe"}}},
        ]
    ],
    """sequence
        [process where process.name : "*.exe"] with runs=2
        [process where process.pid < 10] with runs=2
    """: [
        [
            {"event": {"category": ["process"]}, "process": {"name": "GDkziCQDEu.exe"}},
            {"event": {"category": ["process"]}, "process": {"name": "enLIHTLSCD.exe"}},
            {"event": {"category": ["process"]}, "process": {"pid": 4}},
            {"event": {"category": ["process"]}, "process": {"pid": 8}},
        ]
    ],
}

multi_branch_multi_doc = {
    """sequence
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe" or process.name : "powershell.exe"]
    """: [
        [
            {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
            {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}},
        ],
        [
            {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
            {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
        ],
    ],
    """sequence by user.id
        [process where process.name : "cmd.exe"]
        [process where process.parent.name : "cmd.exe" or process.name : "powershell.exe"]
    """: [
        [
            {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "lYLed"}},
            {"event": {"category": ["process"]}, "process": {"parent": {"name": "cmd.exe"}}, "user": {"id": "lYLed"}},
        ],
        [
            {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "nIMUeJSFeX"}},
            {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}, "user": {"id": "nIMUeJSFeX"}},
        ],
    ],
    """sequence
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.name
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.parent.name
    """: [
        [
            {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
            {"event": {"category": ["process"]}, "process": {"name": "cmd.exe", "parent": {"name": "cmd.exe"}}},
        ],
        [
            {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}},
            {"event": {"category": ["process"]}, "process": {"name": "powershell.exe", "parent": {"name": "cmd.exe"}}},
        ],
        [
            {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
            {"event": {"category": ["process"]}, "process": {"name": "cmd.exe", "parent": {"name": "powershell.exe"}}},
        ],
        [
            {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
            {
                "event": {"category": ["process"]},
                "process": {"name": "powershell.exe", "parent": {"name": "powershell.exe"}},
            },  # noqa: E501
        ],
    ],
    """sequence by user.id
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.name
        [process where process.name in ("cmd.exe", "powershell.exe")] by process.parent.name
    """: [
        [
            {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "v"}},
            {
                "event": {"category": ["process"]},
                "process": {"name": "cmd.exe", "parent": {"name": "cmd.exe"}},
                "user": {"id": "v"},
            },  # noqa: E501
        ],
        [
            {"event": {"category": ["process"]}, "process": {"name": "cmd.exe"}, "user": {"id": "wmg"}},
            {
                "event": {"category": ["process"]},
                "process": {"name": "powershell.exe", "parent": {"name": "cmd.exe"}},
                "user": {"id": "wmg"},
            },  # noqa: E501
        ],
        [
            {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}, "user": {"id": "dMOeSIvI"}},
            {
                "event": {"category": ["process"]},
                "process": {"name": "cmd.exe", "parent": {"name": "powershell.exe"}},
                "user": {"id": "dMOeSIvI"},
            },  # noqa: E501
        ],
        [
            {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}, "user": {"id": "oI"}},
            {
                "event": {"category": ["process"]},
                "process": {"name": "powershell.exe", "parent": {"name": "powershell.exe"}},
                "user": {"id": "oI"},
            },  # noqa: E501
        ],
    ],
}

exceptions = {
    """any where false
    """: "Root without branches",
    """any where not true
    """: "Root without branches",
    """any where not (true and true)
    """: "Root without branches",
    """any where not (true or false)
    """: "Root without branches",
    """any where process.pid == null and process.pid != null
    """: "Unsolvable constraints: process.pid (cannot be non-null)",
    """any where process.pid > 0 and process.pid == null
    """: "Unsolvable constraints: process.pid (cannot be null)",
    """any where process.name != null and process.name == null
    """: "Unsolvable constraints: process.name (cannot be null)",
    """any where process.name == "cmd.exe" and process.name == null
    """: "Unsolvable constraints: process.name (cannot be null)",
    """process where process.pid == 0
    """: "Unsolvable constraints: process.pid (out of boundary, 1 <= 0 <= 4294967295)",
    """process where process.pid <= 0
    """: "Unsolvable constraints: process.pid (empty solution space, 1 <= x <= 0)",
    """process where process.pid < 0
    """: "Unsolvable constraints: process.pid (empty solution space, 1 <= x <= -1)",
    """any where network.protocol == "http" and network.protocol == "https"
    """: "Unsolvable constraints: network.protocol (not in Strings({'http'}): ('https'))",
    """network where destination.port == 22 and destination.port in (80, 443)
    """: "Root without branches",
    """network where not (source.port > 512 or source.port < 1024)
    """: "Unsolvable constraints: source.port (empty solution space, 1024 <= x <= 512)",
    """sequence by process.name
        [process where process.name : "cmd.exe"]
        [process where process.name : "powershell.exe"]
    """: "Unsolvable constraints: process.name (not in Strings({'cmd.exe'}): ('powershell.exe'))",
    """sequence
        [process where process.name : "cmd.exe"] by process.name
        [process where process.parent.name : "powershell.exe"] by process.parent.name
    """: "Unsolvable constraints: process.name (not in Strings({'cmd.exe'}): ('powershell.exe'))",
    """sequence by process.name
        [process where process.name == null]
        [process where process.name : "powershell.exe"]
    """: "Unsolvable constraints: process.name (cannot be non-null)",
    """sequence
        [process where process.name in ("cmd.exe", "powershell.exe")] with runs=10000
    """: "Root with too many branches (limit: 10000)",
}

cardinality = [
    (
        """process where process.pid > 0 and process.pid < 100 and _cardinality(process.pid, 0)""",
        1,
        [
            [{"event": {"category": ["process"]}, "process": {"pid": 35}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 30}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 95}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 23}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 86}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 26}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 92}}],
        ],
    ),
    (
        """process where process.pid > 0 and process.pid < 100 and _cardinality(process.pid, 1)""",
        1,
        [
            [{"event": {"category": ["process"]}, "process": {"pid": 38}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 38}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 38}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 38}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 38}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 38}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 38}}],
        ],
    ),
    (
        """process where process.pid > 0 and process.pid < 100 and _cardinality(process.pid, 2)""",
        1,
        [
            [{"event": {"category": ["process"]}, "process": {"pid": 87}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 19}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 19}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 87}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 87}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 87}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 19}}],
            [{"event": {"category": ["process"]}, "process": {"pid": 87}}],
        ],
    ),
    (
        """network where source.ip == "10.0.0.0/24" and _cardinality(source.ip, 2)""",
        1,
        [
            [{"event": {"category": ["network"]}, "source": {"ip": "10.0.0.214"}}],
            [{"event": {"category": ["network"]}, "source": {"ip": "10.0.0.231"}}],
            [{"event": {"category": ["network"]}, "source": {"ip": "10.0.0.231"}}],
            [{"event": {"category": ["network"]}, "source": {"ip": "10.0.0.231"}}],
            [{"event": {"category": ["network"]}, "source": {"ip": "10.0.0.231"}}],
            [{"event": {"category": ["network"]}, "source": {"ip": "10.0.0.214"}}],
            [{"event": {"category": ["network"]}, "source": {"ip": "10.0.0.214"}}],
        ],
    ),
    (
        """network where destination.ip == "1::/112" and _cardinality(destination.ip, 3)""",
        1,
        [
            [{"event": {"category": ["network"]}, "destination": {"ip": "1::f09b"}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "1::179c"}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "1::8ad5"}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "1::179c"}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "1::f09b"}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "1::f09b"}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "1::f09b"}}],
        ],
    ),
    (
        """process where _cardinality(process.name, 3)""",
        1,
        [
            [{"event": {"category": ["process"]}, "process": {"name": "mAfTYLRtkYY"}}],
            [{"event": {"category": ["process"]}, "process": {"name": "eDDub"}}],
            [{"event": {"category": ["process"]}, "process": {"name": "KArreqRoHjY"}}],
            [{"event": {"category": ["process"]}, "process": {"name": "mAfTYLRtkYY"}}],
            [{"event": {"category": ["process"]}, "process": {"name": "eDDub"}}],
            [{"event": {"category": ["process"]}, "process": {"name": "eDDub"}}],
            [{"event": {"category": ["process"]}, "process": {"name": "eDDub"}}],
        ],
    ),
    (
        """network where destination.port in (22, 443) and _cardinality(destination.ip, 1)""",
        2,
        [
            [{"event": {"category": ["network"]}, "destination": {"ip": "54.133.127.168", "port": 22}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "54.133.127.168", "port": 443}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "54.133.127.168", "port": 22}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "54.133.127.168", "port": 443}}],
        ],
    ),
    (
        """network where destination.port in (22, 443) and _cardinality(destination.ip, 2)""",
        2,
        [
            [{"event": {"category": ["network"]}, "destination": {"ip": "208.66.119.21", "port": 22}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "238.46.28.79", "port": 443}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "208.66.119.21", "port": 22}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "238.46.28.79", "port": 443}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "208.66.119.21", "port": 22}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "208.66.119.21", "port": 443}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "238.46.28.79", "port": 22}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "238.46.28.79", "port": 443}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "238.46.28.79", "port": 22}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "238.46.28.79", "port": 443}}],
        ],
    ),
    (
        """network where destination.port in (22, 443) and _cardinality(destination.ip, 3)""",
        2,
        [
            [{"event": {"category": ["network"]}, "destination": {"ip": "245.152.197.251", "port": 22}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "38.70.19.31", "port": 443}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "189.178.87.67", "port": 22}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "38.70.19.31", "port": 443}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "245.152.197.251", "port": 22}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "189.178.87.67", "port": 443}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "38.70.19.31", "port": 22}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "245.152.197.251", "port": 443}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "245.152.197.251", "port": 22}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "189.178.87.67", "port": 443}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "38.70.19.31", "port": 22}}],
            [{"event": {"category": ["network"]}, "destination": {"ip": "245.152.197.251", "port": 443}}],
        ],
    ),
]


class TestQueries(tu.QueryTestCase, tu.SeededTestCase, unittest.TestCase):
    maxDiff = None
    nb = jupyter.Notebook()
    nb.cells.append(
        jupyter.Markdown(
            """
        # Documents generation from test queries

        This Jupyter Notebook captures the unit test results of documents generation from queries.
        Here you can learn what kind of queries the emitter handles and the documents it generates.

        To edit an input cell, just click in its gray area. To execute it, press `Ctrl+Enter`.

        Curious about the inner workings? Read [here](../../docs/events_generation.md).
        Need help in using a Jupyter Notebook?
        Read [here](https://jupyter-notebook.readthedocs.io/en/stable/notebook.html#structure-of-a-notebook-document).
    """
        )
    )

    @classmethod
    @nb.chapter("## Preliminaries")
    def setUpClass(cls, cells):
        super(TestQueries, cls).setUpClass()
        cells += [
            jupyter.Markdown(
                """
                This is an auxiliary cell, it prepares the environment for the rest of this notebook.
            """
            ),
            jupyter.Code(
                """
                import os; os.chdir('../..')  # use the repo's root as base for local modules import
                from geneve.events_emitter import SourceEvents
                from geneve.utils import load_schema

                # load the ECS schema
                SourceEvents.schema = load_schema('./etc/ecs-8.2.0.tar.gz', 'generated/ecs/ecs_flat.yml')

                def emit(query, timestamp=False, complete=True, count=1):
                    try:
                        events = SourceEvents.from_query(query).emit(timestamp=timestamp, complete=complete, count=count)
                        if complete:
                            return [[event.doc for event in branch] for branch in events]
                        else:
                            return [event.doc for event in events]
                    except Exception as e:
                        print(e)
            """
            ),
            jupyter.Markdown(
                """
                ## How to read the test results

                If you opened this as freshly generated, the output cells content comes from the unit tests run and
                you can read it as a plain test report. Such content is generated in a controlled environment and is
                meant not to change between unit tests runs.
                The notebook itself does not run in such controlled environment therefore executing these cells, even
                if unmodified, will likely lead to different results each time.

                On the other hand, you can experiment and modify the queries in the input cells, check the results
                and, why not?, report any interesting finding. You can also add and remove cells at will.
            """
            ),
        ]

    def test_len(self):
        se = SourceEvents(self.schema)
        se.stack_version = self.stack_version

        self.assertEqual(len(se), 0)
        self.assertEqual(bool(se), False)

        se.add_query("process where process.name != null")
        self.assertEqual(len(se), 1)
        self.assertEqual(bool(se), True)

        se.add_query("process where process.pid != null")
        self.assertEqual(len(se), 2)

        se.add_query("process where process.args != null")
        self.assertEqual(len(se), 3)

    def test_mappings(self):
        for query, mappings in event_docs_mappings.items():
            with self.subTest(query):
                se = SourceEvents(self.schema)
                se.stack_version = self.stack_version

                root = se.add_query(query)
                self.assertEqual(mappings, se.mappings(root))
                self.assertEqual(mappings, se.mappings())

    @nb.chapter("## Mono-branch mono-document")
    def test_mono_branch_mono_doc(self, cells):
        cells.append(
            jupyter.Markdown(
                """
            What follows are queries that shall trigger a signal with just a single source event,
            therefore at most one document is generated for each execution.
        """
            )
        )
        for i, (query, docs) in enumerate(mono_branch_mono_doc.items()):
            with self.subTest(query, i=i):
                self.assertEqual(len(docs), 1)
                self.assertEqual(len(docs[0]), 1)
                self.assertQuery(query, docs)
            cells.append(self.query_cell(query, docs))

    @nb.chapter("## Multi-branch mono-document")
    def test_multi_branch_mono_doc(self, cells):
        cells.append(
            jupyter.Markdown(
                """
            Following queries have one or more disjunctive operators (eg. _or_) which split the query
            in multiple _branches_. Each branch shall generate a single source event.
        """
            )
        )
        for i, (query, docs) in enumerate(multi_branch_mono_doc.items()):
            with self.subTest(query, i=i):
                self.assertGreater(len(docs), 1)
                for branch in docs:
                    self.assertEqual(len(branch), 1)
                self.assertQuery(query, docs)
            cells.append(self.query_cell(query, docs))

    @nb.chapter("## Mono-branch multi-document")
    def test_mono_branch_multi_doc(self, cells):
        cells.append(
            jupyter.Markdown(
                """
            Following queries instead require multiple related source events, it's not analyzed only each
            event content but also the relation with each others. Therefore a senquence of documents is generated
            each time and all the documents in the sequence are required for one signal to be generated.
        """
            )
        )
        for i, (query, docs) in enumerate(mono_branch_multi_doc.items()):
            with self.subTest(query, i=i):
                self.assertEqual(len(docs), 1)
                self.assertGreater(len(docs[0]), 1)
                self.assertQuery(query, docs)
            cells.append(self.query_cell(query, docs))

    @nb.chapter("## Multi-branch multi-document")
    def test_multi_branch_multi_doc(self, cells):
        cells.append(
            jupyter.Markdown(
                """
            Same as above but one or more queries in the sequence have a disjunction (eg. _or_ operator) therefore
            multiple sequences shall be generated.
        """
            )
        )
        for i, (query, docs) in enumerate(multi_branch_multi_doc.items()):
            with self.subTest(query, i=i):
                self.assertGreater(len(docs), 1)
                for branch in docs:
                    self.assertGreater(len(branch), 1)
                self.assertQuery(query, docs)
            cells.append(self.query_cell(query, docs))

    @nb.chapter("## Error conditions")
    def test_exceptions(self, cells):
        cells.append(
            jupyter.Markdown(
                """
            Not all the queries make sense, no documents can be generated for those that cannot logically be ever
            matched. In such cases an error is reported, as the following cells show.

            Here you can challenge the generation engine first hand and check that all the due errors are reported
            and make sense to you.
        """
            )
        )
        for i, (query, msg) in enumerate(exceptions.items()):
            with self.subTest(query, i=i):
                with self.assertRaises(ValueError, msg=msg) as cm:
                    self.assertQuery(query, None)
                self.assertEqual(msg, str(cm.exception))
                cells.append(self.query_cell(query, str(cm.exception), output_type="stream"))

    @nb.chapter("## Cardinality")
    def test_cardinality(self, cells):
        cells.append(
            jupyter.Markdown(
                """
            Cardinality constraints set an upper bound to the number of different values generated for a given field.
        """
            )
        )
        for i, (query, branches, docs) in enumerate(cardinality):
            with self.subTest(query, i=i):
                self.assertQuery(query, docs, int(len(docs) / branches))
                cells.append(self.query_cell(query, docs, len(docs)))

    @nb.chapter("## Any oddities?")
    def test_unchanged(self, cells):
        cells.append(
            jupyter.Markdown(
                """
            Did you find anything odd reviewing the report or playing with the documents emitter?
            We are interested to know, feel free to [create an issue](https://github.com/elastic/geneve/issues/new).
        """
            )
        )
        tu.assertReportUnchanged(self, self.nb, "documents_from_queries.ipynb")


@unittest.skipIf(os.getenv("TEST_SIGNALS_QUERIES", "0").lower() in ("0", "false", "no", ""), "Slow online test")
class TestSignalsQueries(tu.SignalsTestCase, tu.OnlineTestCase, tu.SeededTestCase, unittest.TestCase):
    maxDiff = None
    nb = jupyter.Notebook()
    nb.cells.append(
        jupyter.Markdown(
            """
        # Alerts generation from test queries

        This report captures the unit test queries signals generation coverage.
        Here you can learn what queries are supported.
    """
        )
    )

    def parse_from_queries(self, queries):
        rules = []
        asts = []
        for i, query in enumerate(queries):
            guess = guess_from_query(query)
            index_name = "{:s}-{:03d}".format(self.index_template, i)
            rules.append(
                {
                    "rule_id": "test_{:03d}".format(i),
                    "risk_score": 17,
                    "description": "Test rule {:03d}".format(i),
                    "name": "Geneve: Rule {:03d}".format(i),
                    "index": [index_name],
                    "interval": "90s",
                    "from": "now-2h",
                    "severity": "low",
                    "type": guess.type,
                    "query": query,
                    "language": guess.language,
                    "tags": self.test_tags,
                    "max_signals": 200,
                    "enabled": True,
                    ".test_private": {},  # private test data, not sent to Kibana
                }
            )
            asts.append(guess.ast)
        return rules, asts

    def test_queries(self):
        mf_ext = f"_{self.multiplying_factor}x" if self.multiplying_factor > 1 else ""
        queries = tuple(mono_branch_mono_doc) + tuple(multi_branch_mono_doc) + tuple(mono_branch_multi_doc) + tuple(multi_branch_multi_doc)
        rules, asts = self.parse_from_queries(queries)
        pending = self.load_rules_and_docs(rules, asts)
        try:
            self.check_signals(rules, pending)
        except AssertionError:
            tu.assertReportUnchanged(self, self.nb, f"alerts_from_queries{mf_ext}.md")
            raise
        tu.assertReportUnchanged(self, self.nb, f"alerts_from_queries{mf_ext}.md")
