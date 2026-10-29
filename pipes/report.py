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

"""Write periodic Obvious output documents for the Geneve Pipes process."""

import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

GENERATOR_STATS = Path("/var/run/geneve-stats/generator.json")
BULK_STATS = Path("/var/run/geneve-stats/bulk.json")
READY_FILE = Path("/tmp/geneve-ready")


def read_stats(path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def report(sequence):
    generator = read_stats(GENERATOR_STATS)
    bulk = read_stats(BULK_STATS)
    status = "running" if generator.get("prepared_rules", 0) else "starting"
    document = {
        "@timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "execution_id": os.environ["OBVIOUS_EXECUTION_ID"],
        "status": status,
        "sequence": sequence,
        "configured_rules": generator.get("configured_rules", 0),
        "prepared_rules": generator.get("prepared_rules", 0),
        "skipped_rules": generator.get("skipped_rules", 0),
        "trigger_attempts": generator.get("trigger_attempts", 0),
        "generated_documents": generator.get("generated_documents", 0),
        "generation_failures": generator.get("generation_failures", 0),
        "bulk_batches": bulk.get("batches", 0),
        "bulk_created": bulk.get("created", 0),
        "bulk_failed": bulk.get("failed", 0),
    }
    request = urllib.request.Request(
        f"{os.environ['OBVIOUS_ES_URL'].rstrip('/')}/{os.environ['OBVIOUS_OUTPUT_INDEX']}/_doc?refresh=wait_for",
        data=json.dumps(document).encode(),
        headers={
            "Authorization": f"ApiKey {os.environ['OBVIOUS_ES_API_KEY']}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15):
            pass
    except urllib.error.URLError as error:
        print(f"cannot write Geneve tool output: {error}", flush=True)
    if status == "running":
        READY_FILE.touch()


def main():
    sequence = 0
    while True:
        sequence += 1
        report(sequence)
        time.sleep(5)


if __name__ == "__main__":
    main()
