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

from faker import Faker

from geneve.solver import Entity, solver

faker = Faker()


@solver.group("source.geo")
@solver.group("destination.geo")
class GeoEntity(Entity):
    def solve(self, doc, join_doc, env):
        lol = faker.location_on_land()
        geo = {
            "location.lat": float(lol[0]),
            "location.lon": float(lol[1]),
            "city_name": lol[2],
            "country_iso_code": lol[3],
            "timezone": lol[4],
        }
        self.emit_group(doc, geo)
