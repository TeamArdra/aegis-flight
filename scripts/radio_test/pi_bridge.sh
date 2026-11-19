#!/bin/bash
# Parameterized bridge launcher for bench or companion testing.
# Usage: [FCPORT=/dev/ttyAMA0] [GCSPORT=/dev/ttyUSB0] [MODE=passive] [SECS=...] pi_bridge.sh LABEL MODE [extra args...]
set -euo pipefail
LABEL="${1:?usage: pi_bridge.sh LABEL MODE [extra args...]}"
MODE="${2:-passive}"
shift 2 || true
AEGIS_HOME="${AEGIS_HOME:-$PWD}"
RUN_ROOT="${AEGIS_RUN_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/aegisflight/runs}"
D="$RUN_ROOT/$LABEL"
mkdir -p "$D"
cd "$AEGIS_HOME"
export PYTHONPATH="${AEGIS_HOME}/src${PYTHONPATH:+:$PYTHONPATH}"
PYTHON_BIN="${AEGIS_PYTHON:-${AEGIS_HOME}/.venv/bin/python}"
FCPORT="${FCPORT:-/dev/ttyAMA0}"
FCBAUD="${FCBAUD:-921600}"
GCSPORT="${GCSPORT:-/dev/ttyUSB0}"
GCSBAUD="${GCSBAUD:-57600}"
STATUS_PORT="${STATUS_PORT:-8090}"
ALLOW_URL_FLAG=""
if [[ "$FCPORT" == socket://* || "$GCSPORT" == socket://* ]]; then
  ALLOW_URL_FLAG="--allow-url"
fi
SECS_ARGS=()
if [ -n "${SECS:-}" ]; then
  SECS_ARGS=(--seconds "$SECS")
fi
echo $$ > "$RUN_ROOT/bridge.pid"
exec "$PYTHON_BIN" -m aegisflight.cli.main ips-bridge \
  --fc-port "$FCPORT" --fc-baud "$FCBAUD" \
  --gcs-port "$GCSPORT" --gcs-baud "$GCSBAUD" \
  $ALLOW_URL_FLAG \
  --defense-mode "$MODE" \
  --config-dir "${AEGIS_CONFIG_DIR:-configs/ardupilot_copter}" \
  --status-port "$STATUS_PORT" \
  --db "$D/bridge.sqlite" \
  "${SECS_ARGS[@]}" "$@" > "$D/bridge.log" 2>&1
