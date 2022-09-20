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

"""Discover stacks in the cloud using `ecctl`"""

import json
import subprocess

from .prober_elastic import ElasticStack


def cloud_id_from_resources(resources):
    for res in resources:
        if "cloud_id" in res:
            return res["cloud_id"]


class ElasticCloudControlStack(ElasticStack):
    def __init__(self, id, name, resources, **kwargs):
        config = {
            "id": id,
            "name": name,
            "elasticsearch": {
                "cloud_id": cloud_id_from_resources(resources),
            },
        }
        super().__init__(config)


def probe():
    try:
        p = subprocess.run(["ecctl", "deployment", "list", "--output=json"], capture_output=True, check=True)
        deployments = json.loads(p.stdout)["deployments"]
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []

    return [ElasticCloudControlStack(**d) for d in deployments]


def load_from_config(config):
    pass
