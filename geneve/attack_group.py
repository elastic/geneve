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

"""Attack groups and the backpacks that carry their shared entities (starter).

An attack group names member queries and the entity fields that must align
across their documents. A backpack holds the values of those fields for one
attack instance. Its content is a pure function of (group, coordination seed,
instance id, schema), so unrelated emitters derive the same backpack without
talking to each other.

Backpacks go down to the solvers: ``SourceEvents.emit(..., backpack=...)``
makes every field solver that finds its field in the backpack use the
pre-assigned value instead of generating one. The value is checked against
the other constraints of the field like any other `==` constraint.
"""

from __future__ import annotations

from dataclasses import dataclass
from random import Random
from typing import Mapping

from .solver import Entity
from .utils import random

__all__ = (
    "AttackBackpack",
    "AttackGroup",
    "fill_backpack",
)


@dataclass(frozen=True)
class AttackGroup:
    """Declarative story: member queries plus shared entity field paths."""

    name: str
    members: tuple[str, ...]
    entities: tuple[str, ...]


@dataclass(frozen=True)
class AttackBackpack:
    """Pre-generated values of the shared entities of one attack instance."""

    group: str
    instance_id: str
    values: Mapping[str, object]


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
    group: AttackGroup,
    *,
    coordination_seed: str | int | None = None,
    instance_id: str,
    schema: Mapping | None = None,
    stack_version=None,
) -> AttackBackpack:
    """Pre-generate the backpack of an attack instance.

    Values come from the regular field solvers, so they have the type and the
    ECS bounds that the schema gives to each entity field. Same inputs always
    yield the same backpack, from private random generators: the shared one is
    left untouched and the call is safe to run concurrently with any other user
    of it.

    Without a `coordination_seed` one is derived from the current state of the
    shared generator (see `derive_seed`), so whoever controls that state, for
    example the test harness, controls the backpack. Emitters that must agree
    on a backpack have either to pass the same `coordination_seed` or to share
    that state.
    """
    if coordination_seed is None:
        coordination_seed = derive_seed()
    entities = Entity("", {field: [] for field in group.entities}, {} if schema is None else schema, stack_version)
    values = {}
    for field, field_solver in entities.fields.items():
        seed = f"{coordination_seed}\0{instance_id}\0{group.name}\0{field}"
        # a private generator per field: nothing shared is seeded, consumed or locked
        values[field] = field_solver(None, {"random": Random(seed)})["value"]
    return AttackBackpack(group=group.name, instance_id=instance_id, values=values)
