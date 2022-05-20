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

from itertools import islice

from . import version
from .events_emitter import SourceEvents

from flask import Flask, request, jsonify
app = Flask("geneve")


@app.route("/api/v1/version", methods=["GET"])
def get_version():
    ret = {
        "version": version
    }
    return jsonify(ret)


@app.route("/api/v1/emit", methods=["GET"])
def emit():
    query = request.args.get("query")
    count = int(request.args.get("count", 1))
    se = SourceEvents.from_query(query)
    docs = [event.doc for events in islice(se, count) for event in events]
    return jsonify(docs)
