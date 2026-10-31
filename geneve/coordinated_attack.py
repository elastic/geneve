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

"""Coordinated attacks and the backpacks that carry their shared entities (starter).

A coordinated attack tells a story with a few roles (a workstation, a file server,
a clerk, an operator's address...) played across its member queries. Each
member binds some of its fields to role attributes: the same workstation is
``host.id`` in the rules it runs, ``source.ip`` in the rule of the server it
reaches. A backpack holds the value of every role attribute for one attack
instance. Its content is a pure function of (attack, coordination seed,
instance id, schema), so unrelated emitters derive the same backpack without
talking to each other.

Backpacks go down to the solvers: ``SourceEvents.emit(..., backpack=view)``,
where ``view`` is the field-to-value mapping that the backpack gives to one
member, makes every field solver that finds its field in the view use the
pre-assigned value instead of generating one. The value is checked against
the other constraints of the field like any other `==` constraint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from random import Random
from typing import Mapping

from .events_emitter import SourceEvents
from .solver import Entity
from .utils import random

__all__ = (
    "ROLE_KINDS",
    "AttackBackpack",
    "AttackEmitter",
    "AttackLedger",
    "CoordinatedAttack",
    "Member",
    "fill_backpack",
    "schedule",
)

# role kind -> attribute -> canonical ECS field, which gives the attribute its type and constraints
ROLE_KINDS = {
    "host": {"id": "host.id", "name": "host.name", "ip": "host.ip"},
    "user": {"id": "user.id", "name": "user.name"},
    "ip": {"ip": "source.ip"},
}


@dataclass(frozen=True)
class Member:
    """One query of the story and how it sees the roles: field -> ``role.attr``.

    `after` names the member this one follows, `within` how long after it at
    most. A member without `after` happens at the start of the attack.
    """

    query: str
    bindings: Mapping[str, str] = field(default_factory=dict)
    name: str | None = None
    after: str | None = None
    within: timedelta | None = None

    def __post_init__(self):
        if self.name is None:
            object.__setattr__(self, "name", self.query.strip())
        if (self.after is None) != (self.within is None):
            raise ValueError(f"member '{self.name}': `after` and `within` go together")
        if self.within is not None and self.within <= timedelta(0):
            raise ValueError(f"member '{self.name}': `within` must be positive")


@dataclass(frozen=True)
class CoordinatedAttack:
    """Declarative story: roles (name -> kind) and the members that play them."""

    name: str
    roles: Mapping[str, str]
    members: tuple[Member, ...]

    def __post_init__(self):
        for role, kind in self.roles.items():
            if kind not in ROLE_KINDS:
                raise ValueError(f"role '{role}': unknown kind '{kind}'")
        seen = set()
        for member in self.members:
            if member.name in seen:
                raise ValueError(f"member '{member.name}': duplicate name")
            if member.after is not None and member.after not in seen:
                raise ValueError(f"member '{member.name}': `after` must name an earlier member, not '{member.after}'")
            seen.add(member.name)
            for binding in member.bindings.values():
                self.canonical_field(binding)

    def member(self, name):
        for member in self.members:
            if member.name == name:
                return member
        raise KeyError(name)

    def canonical_field(self, binding):
        """ECS field that gives a ``role.attr`` binding its type."""
        role, _, attr = binding.partition(".")
        if role not in self.roles:
            raise ValueError(f"binding '{binding}': unknown role '{role}'")
        attrs = ROLE_KINDS[self.roles[role]]
        if attr not in attrs:
            raise ValueError(f"binding '{binding}': {self.roles[role]} has no attribute '{attr}'")
        return attrs[attr]

    def bindings(self):
        """All the ``role.attr`` the members refer to."""
        return sorted({binding for member in self.members for binding in member.bindings.values()})


@dataclass(frozen=True)
class AttackBackpack:
    """Values of the role attributes of one attack instance, keyed by ``role.attr``."""

    attack: str
    instance_id: str
    values: Mapping[str, object]

    def view(self, member: Member) -> Mapping[str, object]:
        """What a member sees of the backpack: its bound fields with their values."""
        return {fld: self.values[binding] for fld, binding in member.bindings.items()}


def derive_seed() -> int:
    """Reproducible seed drawn from the shared generator without consuming it.

    The draw is made on a private copy of the shared state: the shared
    generator is only read, never seeded, advanced or restored. As a
    consequence the same shared state always yields the same seed.
    """
    snapshot = Random()
    snapshot.setstate(random.getstate())
    return snapshot.getrandbits(64)


def fill_backpack(
    attack: CoordinatedAttack,
    *,
    coordination_seed: str | int | None = None,
    instance_id: str,
    schema: Mapping | None = None,
    stack_version=None,
) -> AttackBackpack:
    """Pre-generate the backpack of an attack instance.

    Every ``role.attr`` the members refer to gets a value from the regular
    field solver of its canonical field, so it has the type and the ECS bounds
    that the schema gives to that field. Same inputs always yield the same
    backpack, from private random generators: the shared one is left untouched
    and the call is safe to run concurrently with any other user of it.

    Without a `coordination_seed` one is derived from the current state of the
    shared generator (see `derive_seed`), so whoever controls that state, for
    example the test harness, controls the backpack. Emitters that must agree
    on a backpack have either to pass the same `coordination_seed` or to share
    that state.
    """
    if coordination_seed is None:
        coordination_seed = derive_seed()
    schema = {} if schema is None else schema
    values = {}
    for binding in attack.bindings():
        canonical = attack.canonical_field(binding)
        solver = Entity("", {canonical: []}, schema, stack_version).fields[canonical]
        seed = f"{coordination_seed}\0{instance_id}\0{attack.name}\0{binding}"
        # a private generator per attribute: nothing shared is seeded, consumed or locked
        values[binding] = solver(None, {"random": Random(seed)})["value"]
    return AttackBackpack(attack=attack.name, instance_id=instance_id, values=values)


def schedule(
    attack: CoordinatedAttack,
    *,
    coordination_seed: str | int | None = None,
    instance_id: str,
) -> Mapping[str, timedelta]:
    """Offset of every member from the start of an attack instance.

    A member that follows another happens after it, within the window the
    story gives, at an offset drawn from a private generator seeded like the
    backpack. Emitters that agree on the backpack agree on the timeline too,
    whichever members each of them emits.
    """
    if coordination_seed is None:
        coordination_seed = derive_seed()
    offsets = {}
    for member in attack.members:
        if member.after is None:
            offsets[member.name] = timedelta(0)
        else:
            seed = f"{coordination_seed}\0{instance_id}\0{attack.name}\0{member.name}\0after"
            # in (0, within]: never at the same instant as the member it follows
            offsets[member.name] = offsets[member.after] + member.within * (1 - Random(seed).random())
    return offsets


@dataclass(frozen=True)
class LedgerEntry:
    member: str
    timestamp: datetime
    documents: int


@dataclass(frozen=True)
class AttackLedger:
    """Ground truth of one emission: what was emitted for an attack instance, and when.

    Each member emitted is meant to trigger one alert, so `expected_alerts` is
    the count to check the detections against. Emitters that emit different
    members of the same instance each produce their own ledger, the ground
    truth of the instance is the union.
    """

    attack: str
    instance_id: str
    start: datetime
    members: tuple[LedgerEntry, ...]

    @property
    def expected_alerts(self):
        return len(self.members)


class AttackEmitter:
    """Prepare the members of a coordinated attack once, then emit instances of it."""

    def __init__(self, attack: CoordinatedAttack, *, schema=None, source_events: SourceEvents | None = None):
        self.attack = attack
        self.source_events = source_events or SourceEvents(schema)
        self.roots = {m.name: self.source_events.add_query(m.query, glue=m.bindings) for m in attack.members}

    def emit(self, *, instance_id: str, start: datetime, coordination_seed: str | int | None = None, members=None):
        """Emit one instance of the attack, or only the `members` named, from `start`.

        Returns the events and the ledger. Which members this emitter plays
        does not change what the others see: backpack and timeline are the
        same for every emitter of the instance.
        """
        if coordination_seed is None:
            coordination_seed = derive_seed()
        se = self.source_events
        backpack = fill_backpack(
            self.attack, coordination_seed=coordination_seed, instance_id=instance_id, schema=se.schema, stack_version=se.stack_version
        )
        offsets = schedule(self.attack, coordination_seed=coordination_seed, instance_id=instance_id)
        events = []
        entries = []
        for member in self.attack.members:
            if members is not None and member.name not in members:
                continue
            timestamp = start + offsets[member.name]
            emitted = list(se.emit(self.roots[member.name], timestamp=timestamp, backpack=backpack.view(member)))
            events.extend(emitted)
            entries.append(LedgerEntry(member.name, timestamp, len(emitted)))
        return events, AttackLedger(self.attack.name, instance_id, start, tuple(entries))
