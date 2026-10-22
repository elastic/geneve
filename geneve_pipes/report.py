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
        "execution_id": os.environ["GENEVE_EXECUTION_ID"],
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
