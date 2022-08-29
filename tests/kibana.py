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

import requests


class Kibana:
    exceptions = requests.exceptions

    def __init__(self, url, http_auth=None):
        self.url = url
        self.session = requests.Session()
        self.session.headers.update({"kbn-xsrf": "true"})
        if http_auth is not None:
            self.session.auth = requests.auth.HTTPBasicAuth(*http_auth)

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
