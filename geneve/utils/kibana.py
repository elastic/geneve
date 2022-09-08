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

"""Helper class for Kibana REST API."""

import json
import uuid

import requests


class Kibana:
    """Minimal Kibana REST API Python client

    To be replaced by the official one (https://github.com/elastic/geneve/issues/55)
    """

    exceptions = requests.exceptions

    def __init__(self, url=None, cloud_id=None, basic_auth=None, ca_certs=None):
        if not (url or cloud_id):
            raise ValueError("Either `url` or `cloud_id` must be defined")

        self.url = url
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json", "kbn-xsrf": str(uuid.uuid4())})

        if basic_auth is not None:
            self.session.auth = requests.auth.HTTPBasicAuth(*basic_auth)
        if ca_certs is not None:
            self.session.verify = ca_certs

        if cloud_id:
            import base64

            cluster_name, cloud_info = cloud_id.split(":")
            domain, es_uuid, kibana_uuid = base64.b64decode(cloud_info.encode("utf-8")).decode("utf-8").split("$")

            if domain.endswith(":443"):
                domain = domain[:-4]

            url_from_cloud = f"https://{kibana_uuid}.{domain}:9243"
            if self.url and self.url != url_from_cloud:
                raise ValueError(f"url provided ({self.url}) does not match url derived from cloud_id {url_from_cloud}")
            self.url = url_from_cloud

    def close(self):
        self.session.close()

    def task_manager_health(self):
        url = f"{self.url}/api/task_manager/_health"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def ping(self):
        try:
            self.task_manager_health()
            return True
        except requests.exceptions.ConnectionError:
            return False

    def status(self):
        url = f"{self.url}/api/status"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def create_siem_index(self):
        url = f"{self.url}/api/detection_engine/index"
        res = self.session.post(url)
        res.raise_for_status()
        return res.json()

    def get_siem_index(self):
        url = f"{self.url}/api/detection_engine/index"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()

    def create_detection_engine_rule(self, rule):
        url = f"{self.url}/api/detection_engine/rules"
        res = self.session.post(url, data=json.dumps(rule))
        res.raise_for_status()
        return res.json()

    def delete_detection_engine_rule(self, rule):
        url = f"{self.url}/api/detection_engine/rules?id={rule['id']}"
        res = self.session.delete(url)
        res.raise_for_status()
        return res.json()

    def find_detection_engine_rules(self):
        url = f"{self.url}/api/detection_engine/rules/_find?per_page=1000"
        res = self.session.get(url)
        res.raise_for_status()
        return {rule["id"]: rule for rule in res.json()["data"]}

    def create_detection_engine_rules(self, rules):
        url = f"{self.url}/api/detection_engine/rules/_bulk_create"
        res = self.session.post(url, data=json.dumps(rules))
        res.raise_for_status()
        return {rule["id"]: rule for rule in res.json()}

    def delete_detection_engine_rules(self, rules=None):
        if rules is None:
            rules = self.find_detection_engine_rules()
        rules = [{"id": rule} for rule in rules]
        url = f"{self.url}/api/detection_engine/rules/_bulk_delete"
        res = self.session.delete(url, data=json.dumps(rules))
        res.raise_for_status()
        return res.json()

    def find_detection_engine_rules_statuses(self, rules=None):
        if rules is None:
            rules = self.find_detection_engine_rules()
        rules = {"ids": list(rules)}
        url = f"{self.url}/api/detection_engine/rules/_find_statuses?per_page=1000"
        res = self.session.post(url, data=json.dumps(rules))
        res.raise_for_status()
        return res.json()

    def search_detection_engine_signals(self, body):
        url = f"{self.url}/api/detection_engine/signals/search"
        res = self.session.post(url, data=json.dumps(body))
        res.raise_for_status()
        return res.json()
