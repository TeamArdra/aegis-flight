#!/bin/bash
# usage: run_mgmt_pi.sh <label>   (PI_SSH=user@host PI_KEY=<ssh key> required)
# The in-band management validation of run_mgmt.sh (variant `on`), with the bridge on a Raspberry Pi. SITL, fc_tap, the hub, the
# ground `aegis serve` and the driver stay on this machine; the Pi bridge reaches them through ssh -R tunnels (FC side via fc_tap
# on 5805, GCS side 5800) and its status port comes back with -L 8090. Needs ~/aegis_test/pi_bridge.sh and keys/{mgmt.key,ctl.token}
# on the Pi (scripts/radio_test/laptop_ctl.py deploy + scp) and mgmt.key / wrongmgmt.key / ctl.token in C:/afsitl.
LABEL=$1; PY=/c/afvenv/Scripts/python.exe; AEGIS=/c/afvenv/Scripts/aegis.exe
: "${PI_SSH:?}"; : "${PI_KEY:?}"
SD="$(cd "$(dirname "$0")" && pwd -W)"; CFG="$(cd "$SD/../../.." && pwd -W)/configs/ardupilot_copter"
PI="ssh -i $PI_KEY -o BatchMode=yes $PI_SSH"
cd /c/afsitl
$PI '~/aegis_test/wifi_stop.sh'; [ -f tunnel.pid ] && kill $(cat tunnel.pid) 2>/dev/null
taskkill //IM ArduCopter.elf //F >/dev/null 2>&1
for p in 5800 5801 5802 5803 5805 8090 8104; do pid=$(netstat -ano | grep ":$p " | grep LISTEN | awk '{print $5}' | head -1); [ -n "$pid" ] && taskkill //PID $pid //F >/dev/null 2>&1; done
sleep 2
rm -f eeprom.bin tap_$LABEL.bin mhub_$LABEL.jsonl mfc_$LABEL.json maudit_$LABEL.jsonl mdrive_$LABEL.json
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_m$LABEL.log 2>&1 &
HUB_TAP=C:/afsitl/tap_$LABEL.bin HUB_STATS=C:/afsitl/mhub_$LABEL.jsonl $PY $SD/hub_mgmt.py > hub_m$LABEL.log 2>&1 &
sleep 2
$PY holder.py > /dev/null 2>&1 &
FC_TAP_OUT=C:/afsitl/mfc_$LABEL.json $PY $SD/fc_tap.py > fctap_$LABEL.log 2>&1 &
sleep 5
ssh -i $PI_KEY -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=5 -N -R 5805:127.0.0.1:5805 -R 5800:127.0.0.1:5800 -L 8090:127.0.0.1:8090 $PI_SSH &
echo $! > tunnel.pid; sleep 3
RD='~/aegis_runs/'$LABEL
$PI "mkdir -p $RD; (FCPORT=5805 SECS=1500 setsid nohup ~/aegis_test/pi_bridge.sh $LABEL passive --allow-unsigned --mgmt-key-file ~/aegis_test/keys/mgmt.key --mgmt-state $RD/mstate.json --audit-log $RD/audit.jsonl --lock-posture-file $RD/lock.flag --control-token-file ~/aegis_test/keys/ctl.token > /dev/null 2>&1 < /dev/null &); sleep 1; echo bridge started"
$AEGIS serve --port 8104 --source serial --serial-port socket://127.0.0.1:5803 --allow-url --baud 115200 --config-dir $CFG --db C:/afsitl/mgcs_$LABEL.sqlite --mgmt-key-file C:/afsitl/mgmt.key > mserve_$LABEL.log 2>&1 &
sleep 8
$PY fly_unsigned.py $LABEL > fly_m$LABEL.log 2>&1 &
until grep -q "^modechange done" fly_m$LABEL.log 2>/dev/null; do sleep 3; done
sleep 8
$PY $SD/mgmt_drive.py $LABEL on > mdrive_$LABEL.log 2>&1
touch stop_$LABEL.flag
until grep -q "^done" fly_m$LABEL.log 2>/dev/null; do sleep 3; done
echo finished > mcase_$LABEL.done
$PI '~/aegis_test/wifi_stop.sh'; kill $(cat tunnel.pid) 2>/dev/null
