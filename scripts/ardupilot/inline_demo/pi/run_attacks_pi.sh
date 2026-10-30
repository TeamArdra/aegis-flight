#!/bin/bash
# usage: run_attacks_pi.sh <label> -- flood, telemetry manipulation (MITM on the FC link) and firmware tamper, bridge on the Pi (active-ips)
LABEL=$1; PY=/c/afvenv/Scripts/python.exe; K="${PI_KEY:?set PI_KEY}"; PIH=${PI_HOST:-169.254.225.172}; PI="ssh -i $K -o BatchMode=yes ardra@$PIH"
cd /c/afsitl
$PI '~/aegis_test/wifi_stop.sh'; [ -f tunnel.pid ] && kill $(cat tunnel.pid) 2>/dev/null
taskkill //IM ArduCopter.elf //F >/dev/null 2>&1
for p in 5800 5801 5802 5806 5807 8090 8104; do pid=$(netstat -ano | grep ":$p " | grep LISTEN | awk '{print $5}' | head -1); [ -n "$pid" ] && taskkill //PID $pid //F >/dev/null 2>&1; done
sleep 2; rm -f eeprom.bin
# a real firmware directory with a trusted manifest on the Pi
$PI 'rm -rf ~/aegis_fw; mkdir -p ~/aegis_fw; head -c 200000 /dev/urandom > ~/aegis_fw/autopilot.bin; head -c 20000 /dev/urandom > ~/aegis_fw/params.bin; cd ~/aegis_test; PYTHONPATH=src venv/bin/python -c "from aegisflight.cli.main import main; main()" fw-manifest ~/aegis_fw | tail -1 | cut -c1-80'
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_$LABEL.log 2>&1 &
$PY hub.py > hub_$LABEL.log 2>&1 &
sleep 2; $PY holder.py > /dev/null 2>&1 &
sleep 5
INJ_OUT=C:/afsitl/inject_$LABEL.json $PY inject_proxy.py > inj_$LABEL.log 2>&1 &
sleep 2
ssh -i $K -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=5 -N -R 5762:127.0.0.1:5806 -R 5800:127.0.0.1:5800 -L 8090:127.0.0.1:8090 ardra@$PIH &
echo $! > tunnel.pid; sleep 3
$PI "(SECS=900 setsid nohup ~/aegis_test/pi_bridge.sh $LABEL active-ips --allow-unsigned --firmware-dir /home/ardra/aegis_fw --firmware-recheck-s 5 > /dev/null 2>&1 < /dev/null &); sleep 1; echo bridge started"
sleep 10
$PY texts_watch.py 330 texts_$LABEL.json > watch_$LABEL.log 2>&1 &
$PY soak_pilot.py $LABEL 250 > soakpilot_$LABEL.log 2>&1 &
until grep -q "^airborne" soakpilot_$LABEL.log 2>/dev/null; do sleep 3; done
ev() { echo "== $1 $(date +%s)"; }
sleep 10; ev flood;        $PY flood.py 10 400
sleep 20; ev alt_bias;     echo "alt_bias 40" | $PY -c "import socket,sys;s=socket.create_connection(('127.0.0.1',5807));s.sendall(sys.stdin.read().encode());print(s.recv(10))"; sleep 15; echo off | $PY -c "import socket,sys;s=socket.create_connection(('127.0.0.1',5807));s.sendall(sys.stdin.read().encode());print(s.recv(10))"
sleep 20; ev batt_jump;    echo "batt_jump 3" | $PY -c "import socket,sys;s=socket.create_connection(('127.0.0.1',5807));s.sendall(sys.stdin.read().encode());print(s.recv(10))"; sleep 15; echo off | $PY -c "import socket,sys;s=socket.create_connection(('127.0.0.1',5807));s.sendall(sys.stdin.read().encode());print(s.recv(10))"
sleep 20; ev freeze;       echo "freeze" | $PY -c "import socket,sys;s=socket.create_connection(('127.0.0.1',5807));s.sendall(sys.stdin.read().encode());print(s.recv(10))"; sleep 15; echo off | $PY -c "import socket,sys;s=socket.create_connection(('127.0.0.1',5807));s.sendall(sys.stdin.read().encode());print(s.recv(10))"
sleep 20; ev fw_tamper;    $PI 'python3 -c "
p=\"/home/ardra/aegis_fw/autopilot.bin\"; b=bytearray(open(p,\"rb\").read()); b[5000]^=0xFF; open(p,\"wb\").write(bytes(b))"'
sleep 25
$PI 'curl -s http://127.0.0.1:8090/status' > status_$LABEL.json
$PI "cd ~/aegis_runs/$LABEL; python3 - <<PYEOF
import sqlite3
c=sqlite3.connect('bridge.sqlite')
for r in c.execute('select round(wall_time),attack_type,severity,round(threat_score,2),integrity_status,substr(evidence,1,160) from events order by id'): print(r)
PYEOF" > events_$LABEL.txt
until [ -f texts_$LABEL.json ]; do sleep 5; done
echo finished > case_$LABEL.done
