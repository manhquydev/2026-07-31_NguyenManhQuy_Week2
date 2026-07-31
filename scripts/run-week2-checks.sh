#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_INPUT="${PYTHON:-python3}"
PY_COMMAND="$(command -v -- "$PY_INPUT")" || {
  echo "Python interpreter not found: $PY_INPUT" >&2
  exit 127
}
if [[ "$PY_COMMAND" != /* ]]; then
  PY_COMMAND="$(cd "$(dirname "$PY_COMMAND")" && pwd -P)/$(basename "$PY_COMMAND")"
fi
PYTHONPATH="$ROOT" PYTHON="$PY_COMMAND" "$PY_COMMAND" "$ROOT/tests/test-week2-delivery.py"

echo "Week 2 checks: PASS"
