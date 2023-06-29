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

"""Helper class for the Elastic Package Registry REST API.

See https://github.com/elastic/package-registry
"""

from urllib.parse import quote


class EPR:
    def __init__(self, url=None):
        import requests

        self.url = url or "https://epr.elastic.co"
        self.session = requests.Session()

    def close(self):
        self.session.close()

    def search_package(self, name, **conditions):
        conditions = "&".join(f"{quote(str(k))}={quote(str(v))}" for k, v in conditions.items())
        url = f"{self.url}/search?package={quote(name)}&{conditions}"
        res = self.session.get(url)
        res.raise_for_status()
        return res.json()
