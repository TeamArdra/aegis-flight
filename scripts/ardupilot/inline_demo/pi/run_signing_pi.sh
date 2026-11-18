#!/bin/bash
# usage: run_signing_pi.sh <label> <passive|active-ips>  -- signed link, bridge on the Pi (ssh -R tunnels)
LABEL=$1; MODE=$2; PY=/c/afvenv/Scripts/python.exe; AEGIS=/c/afvenv/Scripts/aegis.exe
K="${PI_KEY:?set PI_KEY to the ssh key path}"; PI="ssh -i $K -o BatchMode=yes ardra@${PI_HOST:-169.254.225.172}"
cd /c/afsitl
$PI '~/aegis_test/wifi_stop.sh'
[ -f tunnel.pid ] && kill $(cat tunnel.pid) 2>/dev/null
taskkill //IM ArduCopter.elf //F >/dev/null 2>&1
for p in 5800 5801 5802 8104; do pid=$(netstat -ano | grep ":$p " | grep LISTEN | awk '{print $5}' | head -1); [ -n "$pid" ] && taskkill //PID $pid //F >/dev/null 2>&1; done
sleep 2; rm -f eeprom.bin tap_$LABEL.bin
# provision signing into a fresh SITL, then restart it on the same eeprom
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_prov_$LABEL.log 2>&1 &
sleep 6; $PY sign_setup.py sign.key 6 > signsetup_$LABEL.log 2>&1
taskkill //IM ArduCopter.elf //F >/dev/null 2>&1; sleep 2
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_$LABEL.log 2>&1 &
HUB_TAP=C:/afsitl/tap_$LABEL.bin $PY hub.py > hub_$LABEL.log 2>&1 &
sleep 2
$PY holder.py > /dev/null 2>&1 &
sleep 5
ssh -i $K -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=5 -N -R 5762:127.0.0.1:5762 -R 5800:127.0.0.1:5800 -L 8090:127.0.0.1:8090 ardra@${PI_HOST:-169.254.225.172} &
echo $! > tunnel.pid
sleep 3
$PI "(setsid nohup ~/aegis_test/pi_bridge.sh $LABEL $MODE --signing-key-file ~/aegis_test/keys/sign.key --signing-state ~/aegis_runs/$LABEL/sign_state.json > /dev/null 2>&1 < /dev/null &); sleep 1; echo started"
sleep 12
$AEGIS serve --port 8104 --source serial --serial-port socket://127.0.0.1:5802 --allow-url --baud 115200 --signing-key-file sign.key --db C:/afsitl/gcsids_$LABEL.sqlite > serve_$LABEL.log 2>&1 &
sleep 4
$PY fly_signed.py $LABEL sign.key > fly_$LABEL.log 2>&1 &
until grep -q "^modechange done" fly_$LABEL.log 2>/dev/null; do sleep 3; done
sleep 3
echo "attack at $(date +%s)" > attack_$LABEL.log
$PI 'curl -s http://127.0.0.1:8090/status' > status_pre_$LABEL.json
$PY attack_signed.py tap_$LABEL.bin wrong.key >> attack_$LABEL.log 2>&1
$PY attack_signed.py tap_$LABEL.bin wrong.key v1 >> attack_$LABEL.log 2>&1
until grep -q "^done" fly_$LABEL.log 2>/dev/null; do sleep 5; done
$PI 'curl -s http://127.0.0.1:8090/status' > status_$LABEL.json
curl -s http://127.0.0.1:8104/api/status > gcsstatus_$LABEL.json
echo finished > case_$LABEL.done
