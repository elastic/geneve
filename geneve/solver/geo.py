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

"""Geo group constraints solver."""

import random

from faker import Faker

from geneve.solver import solver

# https://faker.readthedocs.io/en/master/index.html#seeding-the-generator
faker = Faker()
faker.seed_instance(random.random())


@solver("source.geo.")
@solver("destination.geo.")
def resolve_geo_group(group, fields, schema, env):
    lol = faker.location_on_land()
    yield f"{group}.location.lat", float(lol[0])
    yield f"{group}.location.lon", float(lol[1])
    yield f"{group}.city_name", lol[2]
    yield f"{group}.country_iso_code", lol[3]
    yield f"{group}.timezone", lol[4]
