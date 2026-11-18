#!/bin/bash
# usage: run_radio_reboot_pi.sh (the Pi is rebooted by a person during the flight; the bridge starts via pi_autostart.sh / cron @reboot) (no attacks; the user unplugs the Pi radio during the flight) <label> <flight_seconds> -- REAL radio pair: laptop COM3 (ground) <-> air radio on the Pi, bridge on the Pi
LABEL=$1; FS=$2; PY=/c/afvenv/Scripts/python.exe; K="${PI_KEY:?set PI_KEY}"; PIH=${PI_HOST:-169.254.225.172}; PI="ssh -i $K -o BatchMode=yes ardra@$PIH"
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
(while true; do ssh -i $K -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=3 -o ServerAliveCountMax=2 -N -R 5762:127.0.0.1:5762 -L 8090:127.0.0.1:8090 ardra@$PIH; sleep 2; done) &
echo $! > tunnel.pid; sleep 3
$PI "(setsid nohup ~/aegis_test/pi_autostart.sh > ~/aegis_runs/autostart.log 2>&1 < /dev/null &); sleep 1; echo bridge started via pi_autostart.sh"
sleep 10
$PY texts_watch.py $((FS+200)) texts_$LABEL.json > watch_$LABEL.log 2>&1 &
$PY radio_pilot.py $LABEL $FS > radiopilot_$LABEL.log 2>&1 &
until grep -q "^airborne" radiopilot_$LABEL.log 2>/dev/null; do sleep 3; done
until grep -q "^pilot done" radiopilot_$LABEL.log 2>/dev/null; do sleep 5; done
$PI 'curl -s http://127.0.0.1:8090/status' > status_$LABEL.json
$PY - <<PYEOF > hubstats_$LABEL.json
import socket; s=socket.create_connection(("127.0.0.1",5803)); print(s.recv(65536).decode())
PYEOF
echo finished > case_$LABEL.done
