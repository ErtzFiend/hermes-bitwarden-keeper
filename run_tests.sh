#!/usr/bin/env bash
# Runs the bitwarden-keeper test suite against a Hermes checkout.
#
#   HERMES_SRC=/path/to/hermes-agent ./run_tests.sh
#
# Uses a disposable HERMES_HOME and a FAKE bw shim — never real vault state.
set -euo pipefail
PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HERMES_SRC="${HERMES_SRC:-/usr/local/lib/hermes-agent}"

if [[ ! -d "$HERMES_SRC/agent" ]]; then
  echo "ERROR: Hermes source not found at $HERMES_SRC (set HERMES_SRC)" >&2
  exit 2
fi
command -v python3 >/dev/null || { echo "ERROR: python3 not found" >&2; exit 2; }
HERMES_PYTHON="${HERMES_PYTHON:-python3}"
"$HERMES_PYTHON" -c "import pytest" 2>/dev/null || {
  echo "ERROR: pytest not importable by $HERMES_PYTHON (pip install pytest fastapi httpx)" >&2
  exit 2
}

echo "Running bitwarden-keeper tests (HERMES_SRC=$HERMES_SRC, fake bw shim)..."
HERMES_HOME="$(mktemp -d)" \
PYTHONPATH="$HERMES_SRC:$PLUGIN_DIR" \
PYTHONDONTWRITEBYTECODE=1 \
  "$HERMES_PYTHON" -m pytest "$PLUGIN_DIR/tests" "$@"
echo "All tests passed."
