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

"""Functions to discover, lookup, load and save stack configurations."""

from functools import lru_cache


def configurations():
    """Return a list of all the configured stacks"""

    from ..config import load

    config = load()
    if "stacks" not in config or not config["stacks"]:
        config["stacks"] = []
    return config["stacks"]


@lru_cache
def _probers():
    """Return a list of all the stack probers found in the module directory"""

    import sys
    from importlib import util
    from pathlib import Path

    modules = []
    for path in Path(__file__).parent.glob("prober_*.py"):
        module_name = f"{__package__}.{path.stem}"
        try:
            module = sys.modules[module_name]
        except KeyError:
            spec = util.spec_from_file_location(module_name, path)
            module = util.module_from_spec(spec)
            spec.loader.exec_module(module)
            sys.modules[module_name] = module
        modules.append(module)
    return modules


def discover():
    """Return a list of all the discovered stacks that are not already in the configuration"""

    return sorted(
        (stack for prober in _probers() for stack in prober.probe() if not any(stack.update_config(config) for config in configurations())),
        key=lambda x: x.name,
    )


def load_from_config(config):
    """Given a stack configuration, return the stack instance"""

    for prober in _probers():
        stack = prober.load_from_config(config)
        if stack:
            return stack
    raise ValueError(f"Unknown driver: {config['driver']}")


def lookup(stack_ref):
    """Return the stack referred by stack_ref

    If stack_ref is a number, the stack is searched among the configured ones
    If it's a single letter, it's searched among the discovered ones
    If it's a string, its name is searched in the configured stacks first, then in the discovered ones
    """

    import string

    if isinstance(stack_ref, int) and stack_ref >= 0:
        return load_from_config(configurations()[stack_ref])
    if isinstance(stack_ref, str) and len(stack_ref) == 1:
        pos = string.ascii_letters.find(stack_ref)
        if pos >= 0:
            return discover()[pos]
    if isinstance(stack_ref, str) and len(stack_ref) > 1:
        for config in configurations():
            if config["name"] == stack_ref:
                return load_from_config(config)
        for stack in discover():
            if stack.name == stack_ref:
                return stack
    raise ValueError(f"Invalid stack reference: {stack_ref}")


def set_default(stack):
    """Return False if the stack was already the default, otherwise True"""

    stack_configs = configurations()
    for nr, config in enumerate(stack_configs):
        if stack.update_config(config):
            if nr:
                del stack_configs[nr]
                stack_configs.insert(0, config)
            return nr != 0
    config = {}
    stack.update_config(config)
    stack_configs.insert(0, config)
    return True
