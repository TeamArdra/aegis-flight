#!/bin/bash
# usage: PI_KEY=... PI_HOST=ardra2@<pi-ip> COM=COM3 run_px_campaign.sh <label> <passive|advisory|active-ips> <signed|unsigned> <seed>
# Randomised attack campaign against the REAL, DISARMED, propeller-less Pixhawk 6X, through px_fc_proxy.py + ips-bridge on the Pi
# and the LR900 radio pair. Never arms, never sends takeoff/motor commands. Writes C:/afsitl/px_campaign_<label>.json (laptop)
# and ~/aegis_runs/px_<label>/ (Pi: bridge.sqlite, bridge.log, proxy.log).
set -e
LABEL=$1; POSTURE=$2; LINK=$3; SEED=$4
: "${PI_KEY:?set PI_KEY}"; : "${PI_HOST:?set PI_HOST}"; COM=${COM:-COM3}
PY=/c/afvenv/Scripts/python.exe
SD="$(cd "$(dirname "$0")" && pwd -W)"
D="~/aegis_runs/px_$LABEL"  # quoted: ~ must stay literal here and expand on the REMOTE (Pi) shell, not this local one
PROXY_PORT=5810

# the kill logic lives in a REMOTE FILE (~/aegis_runs/kill_px.sh, deployed once below), never inlined into this ssh
# command: pkill -f matches a process's full cmdline including that of its OWN invoking shell, so a pattern naming
# itself inline self-matches and kills the session running it (see real_pixhawk README).
ssh -i "$PI_KEY" -o BatchMode=yes "$PI_HOST" "mkdir -p ~/aegis_runs && cat > ~/aegis_runs/kill_px.sh" <<'KILLSCRIPT'
#!/bin/bash
pkill -f 'px_fc_proxy\.py' 2>/dev/null
pkill -f 'aegisflight\.cli\.main' 2>/dev/null
exit 0
KILLSCRIPT
ssh -i "$PI_KEY" -o BatchMode=yes "$PI_HOST" "bash ~/aegis_runs/kill_px.sh; sleep 2; mkdir -p $D"

# one-time firmware directory with a trusted manifest, if not already set up
ssh -i "$PI_KEY" -o BatchMode=yes "$PI_HOST" '[ -f ~/aegis_fw_orig/autopilot.bin ] || (
  rm -rf ~/aegis_fw ~/aegis_fw_orig; mkdir -p ~/aegis_fw;
  head -c 200000 /dev/urandom > ~/aegis_fw/autopilot.bin;
  cd ~/aegis_test; PYTHONPATH=src venv/bin/python -c "from aegisflight.cli.main import main; main()" fw-manifest ~/aegis_fw;
  cp -r ~/aegis_fw ~/aegis_fw_orig)'

BOPT="--defense-mode $POSTURE"
if [ "$LINK" = signed ]; then
  BOPT="$BOPT --signing-key-file ~/aegis_runs/signing_key.hex"
else
  [ "$POSTURE" = active-ips ] && BOPT="$BOPT --allow-unsigned"
fi

ssh -i "$PI_KEY" -o BatchMode=yes "$PI_HOST" "cd ~/aegis_test && export PYTHONPATH=\$HOME/aegis_test/src
nohup venv/bin/python scripts/ardupilot/real_pixhawk/px_fc_proxy.py /dev/ttyACM0 $PROXY_PORT > $D/proxy.log 2>&1 &
sleep 2
nohup venv/bin/python -c 'from aegisflight.cli.main import main; main()' ips-bridge --fc-port socket://127.0.0.1:$PROXY_PORT --allow-url --gcs-port /dev/ttyUSB0 --gcs-baud 115200 $BOPT --config-dir configs/ardupilot_copter --status-port 8090 --firmware-dir ~/aegis_fw --firmware-recheck-s 5 --db $D/bridge.sqlite --seconds 600 > $D/bridge.log 2>&1 &
sleep 3; head -c 200 $D/bridge.log"
echo

KEYARGS=""
if [ "$LINK" = signed ]; then KEYARGS="--key C:/afsitl/px_campaign_signing.key --wrongkey C:/afsitl/px_campaign_wrong.key"; fi
PIHOST_IP=${PI_HOST#*@}
"$PY" "$SD/px_campaign.py" "$LABEL" "$LINK" "$SEED" "127.0.0.1:5801" "$PI_KEY" "$PI_HOST" "$PROXY_PORT" $KEYARGS

ssh -i "$PI_KEY" -o BatchMode=yes "$PI_HOST" "sleep 3; bash ~/aegis_runs/kill_px.sh; sleep 2
cd $D; python3 - <<'PYEOF'
import sqlite3
c = sqlite3.connect('bridge.sqlite')
for r in c.execute('select wall_time,attack_type,severity,round(threat_score,2),substr(evidence,1,100) from events order by id'):
    print(r)
PYEOF
tail -n 1 bridge.log" > "C:/afsitl/px_events_${LABEL}.txt" 2>&1
echo "campaign $LABEL done; events: C:/afsitl/px_events_${LABEL}.txt ; result: C:/afsitl/px_campaign_${LABEL}.json"
