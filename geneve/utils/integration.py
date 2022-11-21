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

"""Helper class for Agent integrations."""

import functools
import os
from glob import glob
from pathlib import Path

from ruamel.yaml import YAML

from . import deep_merge, dirs, es, resource
from .epr import EPR

epr = EPR()


class DataStream:
    def __init__(self, data_stream_dir):
        self.name = data_stream_dir.name
        self.__fields = {}

        with open(data_stream_dir / "fields" / "fields.yml", encoding="utf-8") as f:
            yaml = YAML(typ="safe")
            fields = yaml.load(f)

        def add_field(name, field):
            f = {
                "type": field["type"],
            }
            for property in ("normalize", "path", "required"):
                if field.get(property, None):
                    f[property] = field[property]
            self.__fields[name] = f

        for field in fields:
            if field["type"] == "group":
                for child in field["fields"]:
                    add_field(field["name"] + "." + child["name"], child)
            else:
                add_field(field["name"], field)

    def __str__(self):
        return f"name: {self.name}, fields:\n  " + "\n  ".join(str((k, self.__fields[k])) for k in sorted(self.__fields))

    def mappings(self):
        return es.mappings(self.__fields, self.__fields)


class Integration:
    cachedir = dirs.cache

    def __init__(self, package, version):
        self.__data_streams = {}

        uri = self.cachedir / f"{package}-{version}.zip"
        if not uri.exists():
            res = epr.get_package(package, version)
            uri = f"{epr.url}/{res['download']}"

        with resource(uri, cachedir=self.cachedir) as resource_dir:
            with open(next(Path(resource_dir).glob("*/manifest.yml")), encoding="utf-8") as f:
                yaml = YAML(typ="safe")
                manifest = yaml.load(f)

            if manifest["type"] != "integration":
                raise ValueError(f"Not an integration: {manifest['name']} (type={manifest['type']})")

            self.package = manifest["name"]
            self.version = manifest["version"]

            for d in Path(resource_dir).glob("*/data_stream/*"):
                data_stream = DataStream(d)
                self.__data_streams[data_stream.name] = data_stream

    def __str__(self):
        return f"{self.package}/{self.version}"

    def mappings(self):
        mappings = {}
        for data_stream in self.__data_streams.values():
            deep_merge(mappings, data_stream.mappings())
        return mappings


@functools.lru_cache
def get_integration_package(package):
    if package.find("/") == -1:
        version = None
    else:
        package, version = package.split("/")

    if not package:
        raise ValueError(f"Missing integration name: {package}")
    if not version:
        res = epr.search_package(package)
        if len(res) == 0:
            raise ValueError(f"Unknown integration package: {package}")
        version = res[0]["version"]

    return Integration(package, version)
