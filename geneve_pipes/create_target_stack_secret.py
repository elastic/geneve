"""Create the per-execution target-stack Secret from a local credential file."""

import argparse
import base64
import json
import subprocess
from pathlib import Path


def encoded(value):
    return base64.b64encode(value.encode()).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("execution_id", help="Obvious execution ID")
    parser.add_argument("--credentials", required=True, type=Path, help="local target-stack credential JSON")
    args = parser.parse_args()

    credentials = json.loads(args.credentials.read_text())
    api_key = credentials["credentials"]["api_key"]
    if not api_key:
        raise ValueError("credentials file has no API key")

    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "geneve-target-stack",
            "namespace": f"obvious-exec-{args.execution_id}",
        },
        "type": "Opaque",
        "data": {
            "GENEVE_TARGET_ES_URL": encoded(credentials["elasticsearch"]["url"]),
            "GENEVE_TARGET_KIBANA_URL": encoded(credentials["kibana"]["url"]),
            "GENEVE_TARGET_ES_API_KEY": encoded(api_key),
        },
    }
    subprocess.run(["kubectl", "apply", "-f", "-"], input=json.dumps(manifest).encode(), check=True)


if __name__ == "__main__":
    main()
