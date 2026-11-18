#!/bin/bash
# usage: run_fault_pi.sh <label> -- hard-kill + restart of the Pi bridge mid-flight, then a tunnel (link) loss
LABEL=$1; PY=/c/afvenv/Scripts/python.exe
K="${PI_KEY:?set PI_KEY to the ssh key path}"; PIH=${PI_HOST:-169.254.225.172}; PI="ssh -i $K -o BatchMode=yes ardra@$PIH"
START="(setsid nohup ~/aegis_test/pi_bridge.sh $LABEL active-ips --allow-unsigned > /dev/null 2>&1 < /dev/null &); sleep 1; echo restarted"
tunnel() { ssh -i $K -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=5 -N -R 5762:127.0.0.1:5762 -R 5800:127.0.0.1:5800 -L 8090:127.0.0.1:8090 ardra@$PIH & echo $! > tunnel.pid; }
cd /c/afsitl
$PI '~/aegis_test/wifi_stop.sh'
[ -f tunnel.pid ] && kill $(cat tunnel.pid) 2>/dev/null
taskkill //IM ArduCopter.elf //F >/dev/null 2>&1
for p in 5800 5801 5802 8104; do pid=$(netstat -ano | grep ":$p " | grep LISTEN | awk '{print $5}' | head -1); [ -n "$pid" ] && taskkill //PID $pid //F >/dev/null 2>&1; done
sleep 2; rm -f eeprom.bin
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_$LABEL.log 2>&1 &
$PY hub.py > hub_$LABEL.log 2>&1 &
sleep 2; $PY holder.py > /dev/null 2>&1 &
sleep 5; tunnel; sleep 3
$PI "(setsid nohup ~/aegis_test/pi_bridge.sh $LABEL active-ips --allow-unsigned > /dev/null 2>&1 < /dev/null &); sleep 1; echo started"
sleep 12
$PY fly2.py $LABEL > fly_$LABEL.log 2>&1 &
$PY watch_gaps.py 330 gaps_$LABEL.json > watch_$LABEL.log 2>&1 &
until grep -q "^leg done\|^t .* alt 2[0-9]" fly_$LABEL.log 2>/dev/null; do sleep 3; done
sleep 15
sleep 55
echo "== drop tunnel $(date +%s)"; kill $(cat tunnel.pid); sleep 10
echo "== restore tunnel $(date +%s)"; tunnel; sleep 5
sleep 45
$PI 'curl -s http://127.0.0.1:8090/status' > status_$LABEL.json
$PY - <<PYEOF
import json
s=json.load(open("status_$LABEL.json")); print("after: frames", s["frames"], "topology", s["topology"]["kind"], "state", s["state"])
PYEOF
echo finished > case_$LABEL.done
