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

"""Functions for a simple configuration file handling

# Rules of the house

To keep the code simple the following conditions apply:

* load() is cached, the configuration is read only once. This means that there
  is one global configuation held in the load's cache.

* in the (unlucky) need of changing the configuration, changes are
  shared among all the users as long as the access path starts from what
  load() returns. Holding a reference to part of the configuration may
  lead to inconsistent views of it.

  Essentially, if you need to read some config value, always start from
  invoking loads().

* before loading the configuration, set the configuration file path with
  `config.set_path(...)`
"""

from functools import lru_cache
from pathlib import Path


def set_path(path):
    """Set the configuraton file path and force load() to reload the configuration"""

    global _path
    _path = Path(path) if path else path
    load.cache_clear()


@lru_cache
def load():
    """Load the configuration from file"""

    if _path is None:
        raise ValueError(f"Read 'Rules of the house' at {__file__}")
    if not _path.expanduser().exists():
        return {}

    from ruamel.yaml import YAML

    with open(_path.expanduser()) as f:
        yaml = YAML()
        return yaml.load(f) or {}


def save():
    """Save the configuration to file"""

    config = load()
    if config:
        from ruamel.yaml import YAML

        _path.expanduser().parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(_path.expanduser(), "w") as f:
            yaml = YAML()
            yaml.dump(config, f)


# use set_path() to change this
_path = None
