#!/bin/bash
# usage: run_radio_pi.sh <label> <flight_seconds> -- REAL radio pair: laptop COM3 (ground) <-> air radio on the Pi, bridge on the Pi
LABEL=$1; FS=$2; PY=/c/afvenv/Scripts/python.exe; K="${PI_KEY:?set PI_KEY}"; PIH=${PI_HOST:-${PI_HOST:-169.254.225.172}}; PI="ssh -i $K -o BatchMode=yes ardra@$PIH"
REPO="${REPO:?set REPO to the repo root}"
cd /c/afsitl
$PI '~/aegis_test/wifi_stop.sh; ~/aegis_test/stop_relay.sh'; [ -f tunnel.pid ] && kill $(cat tunnel.pid) 2>/dev/null
taskkill //IM ArduCopter.elf //F >/dev/null 2>&1
for p in 5800 5801 5802 5803 8090; do pid=$(netstat -ano | grep ":$p " | grep LISTEN | awk '{print $5}' | head -1); [ -n "$pid" ] && taskkill //PID $pid //F >/dev/null 2>&1; done
sleep 2; rm -f eeprom.bin; mkdir -p hubcap_$LABEL
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_$LABEL.log 2>&1 &
sleep 2; $PY holder.py > /dev/null 2>&1 &
$PY $REPO/scripts/radio_test/radio_hub.py --port COM3 --baud 115200 --capture-dir C:/afsitl/hubcap_$LABEL > hub_$LABEL.log 2>&1 &
sleep 4
ssh -i $K -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=5 -N -R 5762:127.0.0.1:5762 -L 8090:127.0.0.1:8090 ardra@$PIH &
echo $! > tunnel.pid; sleep 3
$PI "(GCSPORT=/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0 GCSBAUD=115200 SECS=$((FS+400)) setsid nohup ~/aegis_test/pi_bridge.sh $LABEL active-ips --allow-unsigned > /dev/null 2>&1 < /dev/null &); sleep 1; echo bridge started"
$PI "(cd ~/aegis_test; mkdir -p ~/aegis_runs/$LABEL; setsid nohup venv/bin/python scripts/radio_test/pi_monitor.py --status-url http://127.0.0.1:8090 --interval 5 --out ~/aegis_runs/$LABEL/mon.jsonl --seconds $((FS+300)) --warmup 60 > ~/aegis_runs/$LABEL/mon.log 2>&1 < /dev/null &); echo monitor started"
sleep 10
$PY texts_watch.py $((FS+200)) texts_$LABEL.json > watch_$LABEL.log 2>&1 &
$PY radio_pilot.py $LABEL $FS 40 160 > radiopilot_$LABEL.log 2>&1 &
until grep -q "^airborne" radiopilot_$LABEL.log 2>/dev/null; do sleep 3; done
sleep 90; echo "== flood $(date +%s)"; $PY flood.py 10 30
$PY - <<PYEOF > hubstats_mid_$LABEL.json
import socket; s=socket.create_connection(("127.0.0.1",5803)); print(s.recv(65536).decode())
PYEOF
until grep -q "^pilot done" radiopilot_$LABEL.log 2>/dev/null; do sleep 5; done
$PI 'curl -s http://127.0.0.1:8090/status' > status_$LABEL.json
$PY - <<PYEOF > hubstats_$LABEL.json
import socket; s=socket.create_connection(("127.0.0.1",5803)); print(s.recv(65536).decode())
PYEOF
$PI "pkill -TERM -f 'pi_monito[r].py'; sleep 3; cat ~/aegis_runs/$LABEL/mon_summary.json" > monsummary_$LABEL.json 2>&1
$PI "cd ~/aegis_runs/$LABEL; python3 - <<PYEOF
import sqlite3
c=sqlite3.connect('bridge.sqlite')
for r in c.execute('select round(wall_time),attack_type,severity,round(threat_score,2),substr(evidence,1,120) from events order by id'): print(r)
PYEOF" > events_$LABEL.txt
echo finished > case_$LABEL.done
