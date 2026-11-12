import argparse
import json
import sys
import urllib.request
from pathlib import Path

import yaml

SOURCE_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml"
OUTPUT = Path(__file__).resolve().parent.parent / "data" / "atomic" / "atomics.json"


def load(source):
    if source.startswith("http://") or source.startswith("https://"):
        print(f"Downloading {source}")
        with urllib.request.urlopen(source, timeout=180) as response:
            return yaml.safe_load(response.read().decode("utf-8"))
    print(f"Reading {source}")
    return yaml.safe_load(Path(source).read_text(encoding="utf-8"))


def build(index):
    out = {}
    for techniques in (index or {}).values():
        if not isinstance(techniques, dict):
            continue
        for tid, body in techniques.items():
            tests = []
            for test in (body or {}).get("atomic_tests") or []:
                tests.append({
                    "name": test.get("name", ""),
                    "guid": test.get("auto_generated_guid", ""),
                    "platforms": test.get("supported_platforms", []),
                    "executor": (test.get("executor") or {}).get("name", ""),
                })
            if tests:
                seen = {t["guid"] for t in out.get(tid, [])}
                out.setdefault(tid, []).extend(t for t in tests if t["guid"] not in seen)
    return dict(sorted(out.items()))


def main():
    parser = argparse.ArgumentParser(description="Build the compact Atomic Red Team index used by Sigma Forge")
    parser.add_argument("--source", default=SOURCE_URL, help="URL or local path of atomics/Indexes/index.yaml")
    parser.add_argument("--output", default=str(OUTPUT))
    args = parser.parse_args()
    try:
        data = build(load(args.source))
    except Exception as exc:
        print(f"Failed to load the Atomic Red Team index: {exc}", file=sys.stderr)
        return 1
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"source": "redcanaryco/atomic-red-team", "techniques": data}, separators=(",", ":")), encoding="utf-8")
    print(f"{sum(len(v) for v in data.values())} atomic tests for {len(data)} techniques -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
