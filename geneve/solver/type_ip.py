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
from . import solver


def match_nets(values, nets):
    if type(values) != list:
        values = [values]
    return any(v in net for v in values for net in nets)


@solver("ip", "==", "!=", "in", "not in")
def solve_ip_field(field, value, constraints, left_attempts, environment):
    include_nets = set()
    exclude_nets = set()
    exclude_addrs = set()

    for k, v, *_ in constraints:
        if k == "==":
            v = str(v)
            try:
                v = ipaddress.ip_address(v)
            except ValueError:
                pass
            else:
                if type(value) == list:
                    value.extend(v if type(v) == list else [v])
                elif value is None or value == v:
                    value = v
                else:
                    raise ConflictError(f"is already {value}, cannot set to {v}", field, k)
                continue
            try:
                include_nets.add(ipaddress.ip_network(v))
            except ValueError:
                raise ValueError(f"Not an IP address or network: {v}")
        elif k == "!=":
            v = str(v)
            try:
                exclude_addrs.add(ipaddress.ip_address(v))
                continue
            except ValueError:
                pass
            try:
                exclude_nets.add(ipaddress.ip_network(v))
            except ValueError:
                raise ValueError(f"Not an IP address or network: {v}")
        elif k == "in":
            values = [v] if type(v) == str else v
            for v in values:
                try:
                    include_nets.add(ipaddress.ip_network(str(v)))
                except ValueError:
                    raise ValueError(f"Not an IP network: {str(v)}")
        elif k == "not in":
            values = [v] if type(v) == str else v
            for v in values:
                try:
                    exclude_nets.add(ipaddress.ip_network(str(v)))
                except ValueError:
                    raise ValueError(f"Not an IP network: {str(v)}")

    if include_nets & exclude_nets:
        intersecting_nets = ", ".join(str(net) for net in sorted(include_nets & exclude_nets))
        raise ConflictError(f"net(s) both included and excluded: {intersecting_nets}", field)
    if value is not None and exclude_addrs and set(value if type(value) == list else [value]) & exclude_addrs:
        if len(exclude_addrs) == 1:
            raise ConflictError(f"cannot be {exclude_addrs.pop()}", field)
        else:
            exclude_addrs = ", ".join(str(v) for v in sorted(exclude_addrs))
            raise ConflictError(f"cannot be any of ({exclude_addrs})", field)
    if value is not None and exclude_nets and match_nets(value, exclude_nets):
        if len(exclude_nets) == 1:
            raise ConflictError(f"cannot be in net {exclude_nets.pop()}", field)
        else:
            exclude_nets = ", ".join(str(v) for v in sorted(exclude_nets))
            raise ConflictError(f"cannot be in any of nets ({exclude_nets})", field)
    ip_versions = sorted(ip.version for ip in include_nets | exclude_nets | exclude_addrs) or [4]
    include_nets = sorted(include_nets, key=lambda x: (x.version, x))
    while left_attempts and (
        value in (None, [])
        or set(value if type(value) == list else [value]) & exclude_addrs  # noqa: W503
        or match_nets(value, exclude_nets)
    ):  # noqa: W503
        if include_nets:
            net = random.choice(include_nets)
            v = net[random.randrange(net.num_addresses)]
        else:
            bits = 128 if random.choice(ip_versions) == 6 else 32
            v = ipaddress.ip_address(random.randrange(1, 2**bits))
        value = [v] if type(value) == list else v
        left_attempts -= 1
    value = [v.compressed for v in value] if type(value) == list else value.compressed
    return {"value": value, "left_attempts": left_attempts}
