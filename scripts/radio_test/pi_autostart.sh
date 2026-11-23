#!/bin/bash
# Start the AegisFlight companion bridge at boot safely in passive mode by default.
set -euo pipefail
AEGIS_HOME="${AEGIS_HOME:-$HOME/aegisflight}"
ENV_FILE="${AUTOSTART_ENV:-/etc/aegisflight/onboard.env}"
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi
: "${GCSPORT:?set GCSPORT (the radio serial device) in $ENV_FILE}"
for _ in $(seq 1 180); do [ -e "$GCSPORT" ] && break; sleep 1; done
LABEL="${LABEL:-boot-$(date +%Y%m%d-%H%M%S)}"
MODE="${MODE:-passive}"
# shellcheck disable=SC2086
exec "$AEGIS_HOME/scripts/radio_test/pi_bridge.sh" "$LABEL" "$MODE" ${EXTRA:-}
