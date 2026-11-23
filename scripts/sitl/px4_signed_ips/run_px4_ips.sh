#!/bin/bash
# Host-side runner: one signed inline-bridge run against PX4 SITL (instance 0, GCS UDP 18570, sysid 1). [SITL]
#   run_px4_ips.sh <label> <signing|gps> <passive|active-ips>
# PX4 runs in container px4sitl, everything else in aegis-px4 (same network namespace). Needs /h/{udp_tcp_shim,
# pilot_px4,px4_relay_attack}.py and /app (aegisflight installed) in aegis-px4, /start.sh in px4sitl.
set -u
LABEL=$1; SCEN=$2; MODE=$3
P="docker exec px4sitl"; A="docker exec aegis-px4"
$P bash -c 'for i in 0 2; do PX4_DIR=/px4 AEGIS_PX4_INSTANCE=$i AEGIS_SITL_RUN=/run_i$i bash /start.sh stop; done' >/dev/null 2>&1; sleep 3
$A sh -c 'pkill -f "[u]dp_tcp_shim"; pkill -f "[p]ilot_px4"; pkill -f "[p]x4_relay_attack"; pkill -f "[a]egisflight.cli.main onboard"; true' >/dev/null 2>&1
$P rm -rf /run_i0
$P bash -c 'PX4_DIR=/px4 AEGIS_PX4_INSTANCE=0 AEGIS_SITL_RUN=/run_i0 bash /start.sh start' >/dev/null 2>&1
ok=0; for _ in $(seq 1 90); do $P grep -aq "Startup script returned successfully" /run_i0/px4.log 2>/dev/null && { ok=1; break; }; sleep 1; done
[ $ok = 1 ] || { echo "$LABEL BOOT_FAIL"; exit 2; }
sleep 8
$A sh -c "rm -rf /h/$LABEL; mkdir -p /h/$LABEL /h/run_$LABEL; head -c32 /dev/urandom > /h/$LABEL/gcs.key; rm -f /h/READY_FOR_FAULT
cat > /h/$LABEL/onboard.yaml <<YAML
topology: inline
fc_port: socket://127.0.0.1:5762
fc_baud: 115200
gcs_port: socket://127.0.0.1:5800
gcs_baud: 115200
allow_url: true
defense_mode: $MODE
fail_closed_uplink_commands: true
semantic_firewall_enabled: true
config_dir: /app/configs/universal_flight
run_root: /h/run_$LABEL
archive_enabled: true
allow_dirty: false
db_name: events.sqlite
signing_key_file: /h/$LABEL/gcs.key
anchors_enabled: true
anchor_interval_s: 30.0
status_host: 127.0.0.1
status_port: 8090
dashboard:
  enabled: false
YAML"
if [ "$SCEN" = gps ]; then
  $A sh -c "cd /h && nohup python px4_relay_attack.py --px4-port 18570 --listen-port 18670 --onset-s 90 --duration-s 40 --attack ${ATTACK:-drift} --rate-ms ${RATE:-15} --bearing-deg 45 --frames-log /h/$LABEL/drift.frames.jsonl --stats /h/$LABEL/drift.stats.json > /h/$LABEL/relay.log 2>&1 &"
  sleep 2; SHIMPORT=18670
else SHIMPORT=18570; fi
$A sh -c "cd /h && nohup python udp_tcp_shim.py --tcp-port 5762 --px4-port $SHIMPORT --stats /h/$LABEL/shim.stats.json > /h/$LABEL/shim.log 2>&1 &"
$A sh -c "cd /h && nohup python pilot_px4.py --key /h/$LABEL/gcs.key --scenario $SCEN --out /h/$LABEL/pilot.json --ready-file /h/READY_FOR_FAULT --observe-s 110 ${MC:+--manual-control} > /h/$LABEL/pilot.log 2>&1 &"
sleep 3
$A sh -c "cd /app && nohup python -m aegisflight.cli.main onboard --config /h/$LABEL/onboard.yaml --seconds 420 > /h/$LABEL/onboard.log 2>&1 &"
for _ in $(seq 1 120); do $A grep -q "^DONE\|NO HB\|ARM REJ" /h/$LABEL/pilot.log 2>/dev/null && break; sleep 3; done
sleep 3
$A sh -c "curl -s http://127.0.0.1:8090/status > /h/$LABEL/status_final.json; pkill -f '[a]egisflight.cli.main onboard'; pkill -f '[p]x4_relay_attack'; sleep 2; pkill -f '[u]dp_tcp_shim'; true"
echo "$LABEL finished"
