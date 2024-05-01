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

"""Constraints solver for ip fields."""

import ipaddress

from ..constraints import ConflictError
from ..utils import random
from . import Field, solver


def match_nets(values, nets):
    if not isinstance(values, list):
        values = [values]
    return any(v in net for v in values for net in nets)


@solver.type("ip")
class IPField(Field):
    valid_constraints = ["==", "!=", "in", "not in"]

    def __init__(self, field, constraints, field_constraints, schema):
        super().__init__(field, constraints, field_constraints, schema)

        self.include_nets = set()
        self.exclude_nets = set()
        self.exclude_addrs = set()

        for k, v, *_ in constraints + field_constraints:
            if k == "==":
                v = str(v)
                try:
                    v = ipaddress.ip_address(v)
                except ValueError:
                    pass
                else:
                    if self.is_array:
                        self.value.extend(v if isinstance(v, list) else [v])
                    elif self.value is None or self.value == v:
                        self.value = v
                    else:
                        raise ConflictError(f"is already {self.value}, cannot set to {v}", field, k)
                    continue
                try:
                    self.include_nets.add(ipaddress.ip_network(v))
                except ValueError:
                    raise ValueError(f"Not an IP address or network: {v}")
            elif k == "!=":
                v = str(v)
                try:
                    self.exclude_addrs.add(ipaddress.ip_address(v))
                    continue
                except ValueError:
                    pass
                try:
                    self.exclude_nets.add(ipaddress.ip_network(v))
                except ValueError:
                    raise ValueError(f"Not an IP address or network: {v}")
            elif k == "in":
                values = [v] if isinstance(v, str) else v
                for v in values:
                    try:
                        self.include_nets.add(ipaddress.ip_network(str(v)))
                    except ValueError:
                        raise ValueError(f"Not an IP network: {str(v)}")
            elif k == "not in":
                values = [v] if isinstance(v, str) else v
                for v in values:
                    try:
                        self.exclude_nets.add(ipaddress.ip_network(str(v)))
                    except ValueError:
                        raise ValueError(f"Not an IP network: {str(v)}")

        if self.include_nets & self.exclude_nets:
            intersecting_nets = ", ".join(str(net) for net in sorted(self.include_nets & self.exclude_nets))
            raise ConflictError(f"net(s) both included and excluded: {intersecting_nets}", field)
        if (
            self.value is not None
            and self.exclude_addrs
            and set(self.value if isinstance(self.value, list) else [self.value]) & self.exclude_addrs
        ):
            if len(self.exclude_addrs) == 1:
                raise ConflictError(f"cannot be {self.exclude_addrs.pop()}", field)
            else:
                self.exclude_addrs = ", ".join(str(v) for v in sorted(self.exclude_addrs))
                raise ConflictError(f"cannot be any of ({self.exclude_addrs})", field)
        if self.value is not None and self.exclude_nets and match_nets(self.value, self.exclude_nets):
            if len(self.exclude_nets) == 1:
                raise ConflictError(f"cannot be in net {self.exclude_nets.pop()}", field)
            else:
                self.exclude_nets = ", ".join(str(v) for v in sorted(self.exclude_nets))
                raise ConflictError(f"cannot be in any of nets ({self.exclude_nets})", field)
        self.ip_versions = sorted(ip.version for ip in self.include_nets | self.exclude_nets | self.exclude_addrs) or [4]
        self.include_nets = sorted(self.include_nets, key=lambda x: (x.version, x))

    def solve(self, left_attempts, environment):
        value = self.value
        history_addrs = self.get_history(environment)
        exclude_addrs = self.exclude_addrs | set(history_addrs)
        while left_attempts and (
            value in (None, [])
            or set(value if self.is_array else [value]) & exclude_addrs  # noqa: W503
            or match_nets(value, self.exclude_nets)
        ):  # noqa: W503
            if self.include_nets:
                net = random.choice(self.include_nets)
                v = net[random.randrange(net.num_addresses)]
            else:
                bits = 128 if random.choice(self.ip_versions) == 6 else 32
                v = ipaddress.ip_address(random.randrange(1, 2**bits))
            value = [v] if self.is_array else v
            left_attempts -= 1
        value = [v.compressed for v in value] if self.is_array else value.compressed
        return {"value": value, "left_attempts": left_attempts}
