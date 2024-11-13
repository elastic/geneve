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

"""Implement the Elastic stack base"""

from datetime import datetime
from pathlib import Path

from elasticsearch import AuthenticationException, Elasticsearch

from ..utils import str_to_bool
from ..utils.kibana import Kibana
from ..utils.shelllib import shell_expand

driver_name = "elastic"


def _read_credentials_json(fp):
    import json

    for res in json.load(fp).get("resources", []):
        if "credentials" in res:
            return (res["credentials"]["username"], res["credentials"]["password"])


def _read_credentials_csv(fp):
    import csv

    reader = csv.reader(fp)
    # read the first row
    row = next(reader)
    # if it contains headers, read the next
    if row[0].strip().lower() == "username" and row[1].strip().lower() == "password":
        row = next(reader)
    # username and password are expected in the first two columns
    return tuple(column.strip() for column in row[:2])


_credentials_readers = {
    "json": _read_credentials_json,
    "csv": _read_credentials_csv,
}


def _read_credentials(filename):
    with open(filename) as fp:
        return _credentials_readers[filename.suffix[1:]](fp)


class ElasticStack:
    def __init__(self, config):
        self.id = config.get("id")
        self.name = config["name"]
        self.es_args = config["elasticsearch"]
        self.kb_args = config.get("kibana")
        self.es = None
        self.kb = None

        # ensure that all the expected environment variables are in place
        _ = shell_expand(self.es_args)
        _ = shell_expand(self.kb_args)

    def connect(self):
        es_args = shell_expand(self.es_args)
        kb_args = shell_expand(self.kb_args) or {}
        basic_auth = None

        # drop empty vars
        for var in ("api_key", "ca_certs", "verify_certs"):
            if not es_args.get(var):
                es_args.pop(var, None)
            if not kb_args.get(var):
                kb_args.pop(var, None)

        if es_args.get("basic_auth") == ["", ""]:
            es_args.pop("basic_auth", None)
        if kb_args.get("basic_auth") == ["", ""]:
            kb_args.pop("basic_auth", None)

        if "verify_certs" in es_args:
            es_args["verify_certs"] = str_to_bool(es_args["verify_certs"])
        if "verify_certs" in kb_args:
            kb_args["verify_certs"] = str_to_bool(kb_args["verify_certs"])

        try:
            es = Elasticsearch(**es_args)
            es.info()
        except AuthenticationException:
            es = None
            if "basic_auth" not in es_args:
                for filename in (f for ext in _credentials_readers for f in Path(".").glob(f"credentials-*.{ext}")):
                    basic_auth = _read_credentials(filename)
                    try:
                        es = Elasticsearch(**es_args, basic_auth=basic_auth)
                        es.info()
                        break
                    except AuthenticationException:
                        es = None
            if not es:
                raise ValueError("No valid credentials found")

        if not kb_args:
            kb_args["cloud_id"] = es_args.get("cloud_id")
            kb_args["verify_certs"] = es_args.get("verify_certs")
            kb_args["ca_certs"] = es_args.get("ca_certs")
            kb_args["basic_auth"] = basic_auth or es_args.get("basic_auth")

        while True:
            try:
                kb = Kibana(**kb_args)
                kb.status()
                break
            except Kibana.exceptions.SSLError:
                if kb_args.get("ca_certs") == es_args.get("ca_certs"):
                    raise
                kb_args["ca_certs"] = es_args.get("ca_certs")
            except Kibana.exceptions.HTTPError as e:
                if e.response.status_code != 401:  # Unauthorized
                    raise
                if kb_args.get("basic_auth") == (basic_auth or es_args.get("basic_auth")):
                    raise
                kb_args["basic_auth"] = basic_auth or es_args.get("basic_auth")

        self.es = es
        self.kb = kb

    def info(self):
        def normalize_date(d):
            if not d:
                return "0000-00-00 00:00:00"
            if (dot := d.find(".")) != -1:
                d = d[:dot]
            return datetime.fromisoformat(d).strftime("%Y-%m-%d %H:%M%:%S")

        es_info = self.es.info()
        es_version = es_info["version"].get("number")
        es_build_date = normalize_date(es_info["version"].get("build_date"))
        es_build_hash = es_info["version"].get("build_hash", "00000000")[:8]
        es_build_flavor = es_info["version"].get("build_flavor")

        kb_info = self.kb.status()
        kb_version = kb_info["version"].get("number")
        kb_build_date = normalize_date(kb_info["version"].get("build_date"))
        kb_build_hash = kb_info["version"].get("build_hash", "00000000")[:8]

        return [
            f"ES: {es_version} {es_build_date} {es_build_hash} ({es_build_flavor})",
            f"KB: {kb_version} {kb_build_date} {kb_build_hash}",
        ]

    def update_config(self, config):
        if not config:
            config["name"] = self.name
            config["elasticsearch"] = self.es_args
            if self.kb_args:
                config["kibana"] = self.kb_args
            if self.id:
                config["id"] = self.id
            return True
        return (
            config.get("driver", driver_name) == driver_name
            and config.get("id") == self.id
            and config["name"] == self.name
            and config["elasticsearch"] == self.es_args
            and config.get("kibana") == self.kb_args
        )

    def __str__(self):
        id = f" ({self.id[:6]})" if self.id else ""
        return f"{self.name}{id}"


def probe():
    return []


def load_from_config(config):
    return ElasticStack(config) if config.get("driver", driver_name) == driver_name else None
