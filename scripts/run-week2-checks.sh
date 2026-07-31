#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-python3}"
PYTHONPATH="$ROOT" PYTHON="$PY" "$PY" "$ROOT/tests/test-week2-delivery.py"

echo "Week 2 checks: PASS"
