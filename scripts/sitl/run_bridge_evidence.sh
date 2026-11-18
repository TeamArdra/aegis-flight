#!/usr/bin/env bash
# Issue #25 acceptance criterion 2: a passive `aegis ips-bridge` run with raw logs against a live ArduCopter SITL.
# Linux/WSL only; everything this script starts dials or binds 127.0.0.1 (SITL's serial ports dial out to
# loopback_pair.py, so SITL opens no MAVLink listener). No hardware, no attack traffic.
#
#   usage: run_bridge_evidence.sh <ardupilot_dir> <run_dir> [seconds]
#   env:   PY (python with aegisflight + pymavlink, default python3), AEGIS (default: aegis next to $PY)
#
#   SITL SERIAL1 --tcpclient--> loopback_pair 5762 <-> 5772 <--socket://-- aegis ips-bridge --socket://--> hub.py 5800
#   hub.py 5801 <-- gcs_heartbeat.py (benign GCS)
#
# The run directory gets the bridge archive (frames_down/up, decisions, actions, events.sqlite, run_manifest.json);
# side logs (SITL, relay, hub, GCS, bridge stdout) go to <run_dir>.side/.
set -euo pipefail
[ $# -ge 2 ] || { sed -n 2,14p "$0"; exit 2; }
AP=$(cd "$1" && pwd); RUN=$2; SECS=${3:-90}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
PY=${PY:-python3}; AEGIS=${AEGIS:-$(dirname "$PY")/aegis}
SIDE=$RUN.side
[ -e "$RUN" ] && { echo "refusing: $RUN exists (use a fresh run dir)" >&2; exit 2; }
mkdir -p "$SIDE"; SIDE=$(cd "$SIDE" && pwd)
WORK=$(mktemp -d)  # SITL eeprom.bin and logs; never inside the repo, so the tree stays clean
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

{
  echo "ardupilot: $(grep -m1 THISFIRMWARE "$AP/ArduCopter/version.h" | cut -d'"' -f2) @ $(git -C "$AP" rev-parse HEAD)"
  echo "aegisflight: $(git -C "$REPO" rev-parse HEAD)"
  "$PY" -c 'import sys,platform;print("python:",sys.version.split()[0],platform.platform())'
  "$PY" -m pip freeze 2>/dev/null | sed 's/^/pip: /'
} > "$SIDE/versions.txt"

"$PY" "$REPO/scripts/sitl/loopback_pair.py" 5762 5772 > "$SIDE/relay.log" 2>&1 & PIDS+=($!)
"$PY" "$REPO/scripts/ardupilot/inline_demo/hub.py" > "$SIDE/hub.log" 2>&1 & PIDS+=($!)
sleep 1
(cd "$WORK" && exec "$AP/build/sitl/bin/arducopter" --model + --speedup 1 -I0 --home 12.9716,77.5946,920,90 \
   --defaults "$AP/Tools/autotest/default_params/copter.parm" \
   --serial0 none --serial1 tcpclient:127.0.0.1:5762 --serial2 none) > "$SIDE/sitl.log" 2>&1 & PIDS+=($!)
sleep 3
"$AEGIS" ips-bridge --fc-port socket://127.0.0.1:5772 --gcs-port socket://127.0.0.1:5800 --allow-url \
  --defense-mode passive --config-dir "$REPO/configs/ardupilot_copter" --run-dir "$RUN" --seconds "$SECS" \
  > "$SIDE/bridge.log" 2>&1 & BRIDGE=$!; PIDS+=($BRIDGE)
sleep 2
"$PY" "$REPO/scripts/sitl/gcs_heartbeat.py" --url tcp:127.0.0.1:5801 --seconds $((SECS - 6)) > "$SIDE/gcs.json" 2> "$SIDE/gcs.err" \
  & GCS=$!; PIDS+=($GCS)
ss -ltnup > "$SIDE/listeners.txt" 2>&1 || true
rc=0; wait "$BRIDGE" || rc=$?
wait "$GCS" || echo "gcs_heartbeat exited non-zero (no vehicle HEARTBEAT?)" >&2
echo "bridge exit $rc"
"$AEGIS" verify-log "$RUN/events.sqlite" | tee "$SIDE/verify_log.txt"
for f in frames_down.jsonl frames_up.jsonl decisions.jsonl actions.jsonl; do
  printf '%s %s\n' "$(wc -l < "$RUN/$f")" "$f"
done | tee "$SIDE/row_counts.txt"
exit "$rc"
