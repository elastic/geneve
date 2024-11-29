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

"""Resource functions."""

import shutil
import sys
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse

from .dirs import tempdir


def download(uri, destdir, *, basedir=None, cachedir=None, cachefile=None, validate=None):
    uri_parts = urlparse(str(uri))
    if uri_parts.scheme.startswith("http"):
        if cachedir and cachefile:
            local_file = cachedir / cachefile
        else:
            local_file = Path(cachedir or destdir) / Path(uri_parts.path).name
        if local_file.exists() and validate and not validate(local_file):
            local_file.unlink()
        if not local_file.exists():
            local_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with open(local_file, "wb") as f:
                import requests

                f.write(requests.get(uri).content)
    elif uri_parts.scheme == "file":
        local_file = Path(basedir or Path.cwd()) / (uri_parts.netloc + uri_parts.path)
    elif uri_parts.scheme == "":
        local_file = Path(basedir or Path.cwd()) / uri_parts.path
    else:
        raise ValueError(f"uri scheme not supported: {uri_parts.scheme}")
    return local_file


@contextmanager
def resource(uri, basedir=None, cachedir=None, cachefile=None, validate=None):

    with tempdir() as tmpdir:
        local_file = download(uri, tmpdir, basedir=basedir, cachedir=cachedir, cachefile=cachefile, validate=validate)

        if local_file.is_dir():
            tmpdir = local_file
        else:
            kwargs = {}
            if sys.version_info >= (3, 12) and ".tar" in local_file.suffixes:
                kwargs = {"filter": "data"}
            try:
                shutil.unpack_archive(local_file, tmpdir, **kwargs)
            except shutil.ReadError:
                tmpdir = local_file
            else:
                if local_file.parent == tmpdir:
                    local_file.unlink()
                inner_entries = tmpdir.glob("*")
                new_tmpdir = next(inner_entries)
                try:
                    # check if there are other directories or files
                    _ = next(inner_entries)
                except StopIteration:
                    # lone entry, probably a directory, let's use it as base
                    tmpdir = new_tmpdir

        yield tmpdir


def _gz_compress(base_name, base_dir, **kwargs):
    import gzip

    if Path(base_dir).is_dir():
        raise ValueError("cannot compress dirs with gzip")
    with open(base_dir, "rb") as f_in:
        with gzip.open(base_name + ".gz", "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)


def _bz2_compress(base_name, base_dir, **kwargs):
    import bz2

    if Path(base_dir).is_dir():
        raise ValueError("cannot compress dirs with bzip2")
    with open(base_dir, "rb") as f_in:
        with bz2.open(base_name + ".bz2", "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)


def _xz_compress(base_name, base_dir, **kwargs):
    import lzma

    if Path(base_dir).is_dir():
        raise ValueError("cannot compress dirs with lzma")
    with open(base_dir, "rb") as f_in:
        with lzma.open(base_name + ".xz", "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)


shutil.register_archive_format("gz", _gz_compress, description="compress a file with gzip")
shutil.register_archive_format("bz2", _bz2_compress, description="compress a file with bzip2")
shutil.register_archive_format("xz", _xz_compress, description="compress a file with xz")


def _gz_uncompress(archive_name, dest_dir, **kwargs):
    import gzip

    dest_name = Path(dest_dir) / Path(archive_name).stem
    with gzip.open(archive_name, "rb") as f_in:
        with open(dest_name, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)


def _bz2_uncompress(archive_name, dest_dir, **kwargs):
    import bz2

    dest_name = Path(dest_dir) / Path(archive_name).stem
    with bz2.open(archive_name, "rb") as f_in:
        with open(dest_name, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)


def _xz_uncompress(archive_name, dest_dir, **kwargs):
    import lzma

    dest_name = Path(dest_dir) / Path(archive_name).stem
    with lzma.open(archive_name, "rb") as f_in:
        with open(dest_name, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)


shutil.register_unpack_format("gz", [".gz"], _gz_uncompress, description="decompress a file with gzip")
shutil.register_unpack_format("bz2", [".bz2"], _bz2_uncompress, description="decompress a file with bzip2")
shutil.register_unpack_format("xz", [".xz"], _xz_uncompress, description="decompress a file with xz")
