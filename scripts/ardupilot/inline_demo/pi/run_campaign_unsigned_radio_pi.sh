#!/bin/bash
# usage: run_campaign_unsigned_radio_pi.sh (UNSIGNED link: set CAMPAIGN_UNSIGNED=1 for campaign.py) <label> <passive|advisory|active-ips> <seed>
# Randomised, overlapping attack campaign over the REAL radio pair, signed link, bridge on the Pi, SITL on the laptop.
# Needs PI_KEY (ssh key path) and REPO (repo root) in the environment.
LABEL=$1; POSTURE=$2; SEED=$3; PY=/c/afvenv/Scripts/python.exe; K="${PI_KEY:?set PI_KEY}"; PIH=${PI_HOST:-${PI_HOST:-169.254.225.172}}
PI="ssh -i $K -o BatchMode=yes ardra@$PIH"
: "${REPO:?set REPO}"
cd /c/afsitl
$PI '~/aegis_test/wifi_stop.sh; ~/aegis_test/stop_relay.sh'; [ -f tunnel.pid ] && kill $(cat tunnel.pid) 2>/dev/null
taskkill //IM ArduCopter.elf //F >/dev/null 2>&1
for p in 5800 5801 5802 5803 5806 5807 8090; do pid=$(netstat -ano | grep ":$p " | grep LISTEN | awk '{print $5}' | head -1); [ -n "$pid" ] && taskkill //PID $pid //F >/dev/null 2>&1; done
sleep 2; rm -f eeprom.bin gps_fault_$LABEL.flag gps_clear_$LABEL.flag; mkdir -p hubcap_$LABEL
# a real firmware directory with a trusted manifest on the Pi, plus a pristine copy to restore from
$PI 'rm -rf ~/aegis_fw ~/aegis_fw_orig; mkdir -p ~/aegis_fw; head -c 200000 /dev/urandom > ~/aegis_fw/autopilot.bin; head -c 20000 /dev/urandom > ~/aegis_fw/params.bin; cd ~/aegis_test; PYTHONPATH=src venv/bin/python -c "from aegisflight.cli.main import main; main()" fw-manifest ~/aegis_fw | tail -1 | cut -c1-60; cp -r ~/aegis_fw ~/aegis_fw_orig'
# unsigned link: nothing is provisioned into the SITL
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_$LABEL.log 2>&1 &
sleep 2; $PY gps_console.py $LABEL > console_$LABEL.log 2>&1 &
sleep 4
INJ_OUT=C:/afsitl/inject_$LABEL.json $PY inject_proxy.py > inj_$LABEL.log 2>&1 &
$PY $REPO/scripts/radio_test/radio_hub.py --port COM3 --baud 115200 --capture-dir C:/afsitl/hubcap_$LABEL > hub_$LABEL.log 2>&1 &
sleep 3
ssh -i $K -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=5 -N -R 5762:127.0.0.1:5806 -L 8090:127.0.0.1:8090 ardra@$PIH &
echo $! > tunnel.pid; sleep 3
$PI "(GCSPORT=/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0 GCSBAUD=115200 SECS=2400 setsid nohup ~/aegis_test/pi_bridge.sh $LABEL $POSTURE --allow-unsigned --firmware-dir /home/ardra/aegis_fw --firmware-recheck-s 5 > /dev/null 2>&1 < /dev/null &); sleep 1; echo bridge started"
$PI "(cd ~/aegis_test; mkdir -p ~/aegis_runs/$LABEL; setsid nohup venv/bin/python scripts/radio_test/pi_monitor.py --status-url http://127.0.0.1:8090 --interval 5 --out ~/aegis_runs/$LABEL/mon.jsonl --seconds 2400 --warmup 60 > ~/aegis_runs/$LABEL/mon.log 2>&1 < /dev/null &); echo monitor started"
sleep 10
$PY texts_watch.py 1700 texts_$LABEL.json > watch_$LABEL.log 2>&1 &
PI_KEY=$K REPO=$REPO CAMPAIGN_UNSIGNED=1 $PY campaign.py $LABEL $POSTURE $SEED > campaign_$LABEL.log 2>&1
$PI 'curl -s http://127.0.0.1:8090/status' > status_$LABEL.json
$PY - <<PYEOF > hubstats_$LABEL.json
import socket; s=socket.create_connection(("127.0.0.1",5803)); print(s.recv(65536).decode())
PYEOF
$PI "pkill -TERM -f 'pi_monito[r].py'; sleep 3; cat ~/aegis_runs/$LABEL/mon_summary.json" > monsummary_$LABEL.json 2>&1
$PI "cd ~/aegis_runs/$LABEL; python3 - <<PYEOF
import sqlite3
c=sqlite3.connect('bridge.sqlite')
for r in c.execute('select wall_time,attack_type,severity,round(threat_score,2),substr(evidence,1,110) from events order by id'): print(r)
PYEOF" > events_$LABEL.txt
$PI '~/aegis_test/wifi_stop.sh'
echo finished > case_$LABEL.done
