#!/bin/bash
# usage: [FCPORT=5762] [SECS=900] [GCSPORT=socket://127.0.0.1:5800] [GCSBAUD=115200] pi_bridge.sh LABEL MODE [extra ips-bridge args...]
# Pi bridge for tunnel / real-radio test runs: the FC side is a socket on 127.0.0.1 (ssh -R tunnel to a SITL on the laptop);
# the GCS side is a socket (tunnelled hub) by default or a real serial radio when GCSPORT is a device path.
LABEL=$1; MODE=$2; shift 2; D=$HOME/aegis_runs/$LABEL; mkdir -p $D; cd $HOME/aegis_test
export PYTHONPATH=$HOME/aegis_test/src
echo $$ > $HOME/aegis_runs/wifi_bridge.pid
exec venv/bin/python -c "from aegisflight.cli.main import main; main()" ips-bridge --fc-port socket://127.0.0.1:${FCPORT:-5762} --fc-baud 115200 --gcs-port ${GCSPORT:-socket://127.0.0.1:5800} --gcs-baud ${GCSBAUD:-115200} --allow-url --defense-mode $MODE --config-dir configs/ardupilot_copter --status-port 8090 --db $D/bridge.sqlite --seconds ${SECS:-900} "$@" > $D/bridge.log 2>&1
