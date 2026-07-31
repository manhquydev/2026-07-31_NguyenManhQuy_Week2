#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-python3}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PYTHONPATH="$ROOT" "$PY" -m agent.normalize_week1_artifacts \
  --submission-dir "$ROOT" \
  --output "$WORK/aggregate.jsonl" \
  --manifest-output "$WORK/aggregate.manifest.json" >/dev/null

PYTHONPATH="$ROOT" "$PY" - "$WORK/aggregate.jsonl" "$WORK/aggregate.manifest.json" <<'PY'
import json
import sys
from pathlib import Path

records = [json.loads(line) for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()]
manifest = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
assert len(records) == 36
assert {tool: sum(row["tool"] == tool for row in records) for tool in ("nuclei", "trivy", "semgrep")} == {
    "nuclei": 21, "trivy": 4, "semgrep": 11,
}
assert manifest["aggregate_count"] == 36
assert all(row["provenance_kind"] == "week1-submission" for row in records)
PY

for query in "SQL Injection" "XSS"; do
  "$PY" "$ROOT/scripts/search-knowledge.py" "$query" -k 3 >/dev/null
done

echo "Week 2 checks: PASS"
