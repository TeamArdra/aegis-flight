#!/bin/bash
# Start the AegisFlight bridge at boot (cron @reboot, or the systemd unit aegis-bridge.service).
# Waits for the radio to enumerate, then runs pi_bridge.sh with the settings in ~/aegis_test/autostart.env
# (exported GCSPORT GCSBAUD FCPORT SECS, MODE, EXTRA, LABEL). Start it only once per boot (cron @reboot or systemd).
set -u
ENV_FILE="${AUTOSTART_ENV:-$HOME/aegis_test/autostart.env}"
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
: "${GCSPORT:?set GCSPORT (the radio serial device) in $ENV_FILE}"
for _ in $(seq 1 180); do [ -e "$GCSPORT" ] && break; sleep 1; done   # the USB radio can enumerate a few seconds after boot
LABEL="${LABEL:-boot-$(date +%Y%m%d-%H%M%S)}"
# shellcheck disable=SC2086
exec "$HOME/aegis_test/pi_bridge.sh" "$LABEL" "${MODE:-active-ips}" ${EXTRA:-}
