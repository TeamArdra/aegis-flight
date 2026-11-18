#!/bin/bash
# usage: run_soak_pi.sh <label> <seconds>  -- long ACTIVE_IPS soak with the bridge on the Pi + resource monitor
LABEL=$1; SECS=$2; PY=/c/afvenv/Scripts/python.exe; K="${PI_KEY:?set PI_KEY}"; PIH=${PI_HOST:-169.254.225.172}; PI="ssh -i $K -o BatchMode=yes ardra@$PIH"
cd /c/afsitl
$PI '~/aegis_test/wifi_stop.sh'; [ -f tunnel.pid ] && kill $(cat tunnel.pid) 2>/dev/null
taskkill //IM ArduCopter.elf //F >/dev/null 2>&1
for p in 5800 5801 5802 8090 8104; do pid=$(netstat -ano | grep ":$p " | grep LISTEN | awk '{print $5}' | head -1); [ -n "$pid" ] && taskkill //PID $pid //F >/dev/null 2>&1; done
sleep 2; rm -f eeprom.bin
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_$LABEL.log 2>&1 &
$PY hub.py > hub_$LABEL.log 2>&1 &
sleep 2; $PY holder.py > /dev/null 2>&1 &
sleep 5
ssh -i $K -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=5 -N -R 5762:127.0.0.1:5762 -R 5800:127.0.0.1:5800 -L 8090:127.0.0.1:8090 ardra@$PIH &
echo $! > tunnel.pid; sleep 3
$PI "(SECS=$((SECS+300)) setsid nohup ~/aegis_test/pi_bridge.sh $LABEL active-ips --allow-unsigned > /dev/null 2>&1 < /dev/null &); sleep 1; echo bridge started"
sleep 10
$PI "(cd ~/aegis_test; mkdir -p ~/aegis_runs/$LABEL; setsid nohup venv/bin/python scripts/radio_test/pi_monitor.py --status-url http://127.0.0.1:8090 --interval 5 --out ~/aegis_runs/$LABEL/mon.jsonl --seconds $((SECS+120)) --warmup 120 > ~/aegis_runs/$LABEL/mon.log 2>&1 < /dev/null &); echo monitor started"
$PY soak_pilot.py $LABEL $SECS > soakpilot_$LABEL.log 2>&1
sleep 5
$PI 'curl -s http://127.0.0.1:8090/status' > status_$LABEL.json
$PI "pkill -TERM -f 'pi_monito[r].py'; sleep 3; cat ~/aegis_runs/$LABEL/mon_summary.json" > monsummary_$LABEL.json 2>&1
echo finished > case_$LABEL.done
