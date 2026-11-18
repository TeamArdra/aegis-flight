#!/bin/bash
# usage: run_radio_pi.sh <label> <flight_seconds> -- REAL radio pair: laptop COM3 (ground) <-> air radio on the Pi, bridge on the Pi
LABEL=$1; FS=$2; PY=/c/afvenv/Scripts/python.exe; K="${PI_KEY:?set PI_KEY}"; PIH=${PI_HOST:-${PI_HOST:-169.254.225.172}}; PI="ssh -i $K -o BatchMode=yes ardra@$PIH"
REPO="${REPO:?set REPO to the repo root}"
cd /c/afsitl
$PI '~/aegis_test/wifi_stop.sh; ~/aegis_test/stop_relay.sh'; [ -f tunnel.pid ] && kill $(cat tunnel.pid) 2>/dev/null
taskkill //IM ArduCopter.elf //F >/dev/null 2>&1
for p in 5800 5801 5802 5803 8090; do pid=$(netstat -ano | grep ":$p " | grep LISTEN | awk '{print $5}' | head -1); [ -n "$pid" ] && taskkill //PID $pid //F >/dev/null 2>&1; done
sleep 2; rm -f eeprom.bin tap_$LABEL.bin; mkdir -p hubcap_$LABEL
# provision MAVLink-2 signing into a fresh SITL (SERIAL0), then restart it on the same eeprom
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_prov_$LABEL.log 2>&1 &
sleep 6; $PY sign_setup.py sign.key 6 > signsetup_$LABEL.log 2>&1
taskkill //IM ArduCopter.elf //F >/dev/null 2>&1; sleep 2
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_$LABEL.log 2>&1 &
sleep 2; $PY holder.py > /dev/null 2>&1 &
$PY $REPO/scripts/radio_test/radio_hub.py --port COM3 --baud 115200 --capture-dir C:/afsitl/hubcap_$LABEL > hub_$LABEL.log 2>&1 &
sleep 4
ssh -i $K -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=5 -N -R 5762:127.0.0.1:5762 -L 8090:127.0.0.1:8090 ardra@$PIH &
echo $! > tunnel.pid; sleep 3
$PI "(GCSPORT=/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0 GCSBAUD=115200 SECS=900 setsid nohup ~/aegis_test/pi_bridge.sh $LABEL active-ips --signing-key-file ~/aegis_test/keys/sign.key --signing-state ~/aegis_runs/$LABEL/sign_state.json > /dev/null 2>&1 < /dev/null &); sleep 1; echo bridge started"
sleep 10
$PY texts_watch.py 400 texts_$LABEL.json > watch_$LABEL.log 2>&1 &
$PY $REPO/scripts/ardupilot/inline_demo/pi/fly_signed_radio.py $LABEL sign.key > fly_$LABEL.log 2>&1 &
until grep -q "^modechange done" fly_$LABEL.log 2>/dev/null; do sleep 3; done
sleep 3
# the replay attacker needs a capture of genuine signed uplink frames: rebuild a raw tap from the hub capture
$PY - <<PYEOF
import sys; sys.path.insert(0, "$REPO/scripts/radio_test")
from radio_hub import read_capture
open("C:/afsitl/tap_$LABEL.bin", "wb").write(b"".join(d for _t, d in read_capture("C:/afsitl/hubcap_$LABEL/uplink.cap")))
PYEOF
echo "attack at $(date +%s)" > attack_$LABEL.log
$PI 'curl -s http://127.0.0.1:8090/status' > status_pre_$LABEL.json
$PY attack_signed.py tap_$LABEL.bin wrong.key >> attack_$LABEL.log 2>&1
$PY attack_signed.py tap_$LABEL.bin wrong.key v1 >> attack_$LABEL.log 2>&1
until grep -q "^done" fly_$LABEL.log 2>/dev/null; do sleep 5; done
$PI 'curl -s http://127.0.0.1:8090/status' > status_$LABEL.json
$PY - <<PYEOF > hubstats_$LABEL.json
import socket; s=socket.create_connection(("127.0.0.1",5803)); print(s.recv(65536).decode())
PYEOF
echo finished > case_$LABEL.done
