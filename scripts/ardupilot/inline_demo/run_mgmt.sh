#!/bin/bash
# usage: run_mgmt.sh <label> <on|off>
# SITL validation of the in-band management channel on an UNSIGNED flight link (the management key is separate).
#   on  = management channel enabled (keys, audit log, lock file) + driver mgmt_drive.py (tests a-e, g)
#   off = identical flight and forged-LAND attack with `--mgmt-status-interval 0 --gcs-alerts off` and no keys (test f)
# Run from anywhere; SITL files, keys and logs live in C:/afsitl (never in the repo). Create the keys once:
#   python -c "import os; open('C:/afsitl/mgmt.key','wb').write(os.urandom(32)); open('C:/afsitl/wrongmgmt.key','wb').write(os.urandom(32))"
LABEL=$1; VARIANT=$2; PY=/c/afvenv/Scripts/python.exe; AEGIS=/c/afvenv/Scripts/aegis.exe
SD="$(cd "$(dirname "$0")" && pwd -W)"; CFG="$(cd "$SD/../../.." && pwd -W)/configs/ardupilot_copter"
cd /c/afsitl
rm -f eeprom.bin tap_$LABEL.bin restart_$LABEL.flag stop_$LABEL.flag mhub_$LABEL.jsonl mfc_$LABEL.json \
  maudit_$LABEL.jsonl mstate_$LABEL.json mlock_$LABEL.flag mdrive_$LABEL.json
./ArduCopter.elf --model + --speedup 1 --home 12.9716,77.5946,920,90 > sitl_m$LABEL.log 2>&1 &
HUB_TAP=C:/afsitl/tap_$LABEL.bin HUB_STATS=C:/afsitl/mhub_$LABEL.jsonl $PY $SD/hub_mgmt.py > hub_m$LABEL.log 2>&1 &
sleep 2
$PY holder.py > /dev/null 2>&1 &
FC_TAP_OUT=C:/afsitl/mfc_$LABEL.json $PY $SD/fc_tap.py > fctap_$LABEL.log 2>&1 &
sleep 5
if [ "$VARIANT" = on ]; then
  BOPT="--mgmt-key-file C:/afsitl/mgmt.key --mgmt-state C:/afsitl/mstate_$LABEL.json --audit-log C:/afsitl/maudit_$LABEL.jsonl --lock-posture-file C:/afsitl/mlock_$LABEL.flag"
  SOPT="--mgmt-key-file C:/afsitl/mgmt.key"
else
  BOPT="--mgmt-status-interval 0 --gcs-alerts off"; SOPT=""
fi
$AEGIS ips-bridge --fc-port socket://127.0.0.1:5805 --fc-baud 115200 --gcs-port socket://127.0.0.1:5800 --gcs-baud 115200 --allow-url --allow-unsigned --defense-mode passive --config-dir $CFG --status-port 8090 --control-token-file C:/afsitl/ctl.token --db C:/afsitl/mbridge_$LABEL.sqlite --seconds 1500 $BOPT > mbridge_$LABEL.log 2>&1 &
$AEGIS serve --port 8104 --source serial --serial-port socket://127.0.0.1:5803 --allow-url --baud 115200 --config-dir $CFG --db C:/afsitl/mgcs_$LABEL.sqlite $SOPT > mserve_$LABEL.log 2>&1 &
sleep 4
$PY fly_unsigned.py $LABEL > fly_m$LABEL.log 2>&1 &
until grep -q "^modechange done" fly_m$LABEL.log 2>/dev/null; do sleep 3; done
sleep 8
$PY $SD/mgmt_drive.py $LABEL $VARIANT > mdrive_$LABEL.log 2>&1
touch stop_$LABEL.flag
until grep -q "^done" fly_m$LABEL.log 2>/dev/null; do sleep 3; done
echo finished > mcase_$LABEL.done
# stop only what this harness started (matched by command line, never by image name)
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { \$_.ProcessId -ne \$PID -and \$_.Name -notmatch 'powershell' -and \$_.CommandLine -match 'hub_mgmt\.py|holder\.py|fly_unsigned\.py|fc_tap\.py|ips-bridge|serve --port 8104|ArduCopter\.elf' } | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue }"
