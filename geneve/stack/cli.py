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

"""Implement the `stack` cli subcommand"""

import click

from .. import cli
from . import configurations, discover, load_from_config, lookup, set_default


def _print_stack(ref, stack, verbose):
    if verbose:
        try:
            stack.connect()
            click.echo(f"  {ref}. {stack} - {', '.join(stack.info())}")
        except Exception as e:
            click.echo(f"  {ref}. {stack} - error: {e}")
    else:
        click.echo(f"  {ref}. {stack}")


def show_configured_stacks(verbose):
    from .. import config

    if not configurations():
        click.echo("No stacks configured.")
        return False

    click.echo(f"Configured stacks ({config._path}):")
    for ref, stack_config in enumerate(configurations()):
        try:
            stack = load_from_config(stack_config)
        except Exception as e:
            click.echo(f"  {ref}. error: {e}")
        else:
            _print_stack(ref, stack, verbose)
    return True


def show_discovered_stacks(verbose):
    import string

    new = "new " if configurations() else ""
    discovered_stacks = discover()

    click.echo("")
    if discovered_stacks:
        click.echo(f"Discovered {new}stacks:")
        for ref, stack in enumerate(discovered_stacks):
            _print_stack(string.ascii_letters[ref], stack, verbose)
    else:
        click.echo(f"No {new}stacks discovered.")


def validate_stack_ref(ctx, param, value):
    if value is None:
        return None
    try:
        value = int(value)
    except:
        pass
    try:
        return lookup(value)
    except Exception as e:
        raise click.BadParameter(str(e))


@cli.main.command()
@click.option("-d", "--discover", is_flag=True, help="Discover stacks you have access to")
@click.option("-v", "--verbose", is_flag=True, help="Increase output verbosity")
@click.argument("stack", required=False, callback=validate_stack_ref)
def stack(discover, verbose, stack=None):
    """Manage the stack for ingesting the generated data

    STACK is one among those shown by `stack -d`"""

    from .. import config

    if stack is not None:
        if set_default(stack):
            click.echo(f"New default stack: {stack}\n")
            config.save()
        else:
            click.echo("No config change needed\n")

    configured = show_configured_stacks(verbose)
    if discover or not configured:
        show_discovered_stacks(verbose)
