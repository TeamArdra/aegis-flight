"""Laptop orchestrator: replay each scenario at 1x over the REAL radio through the REAL bridge on the Pi, in all three postures.

    laptop (COM3 radio)  <==radio==>  Pi radio port -> aegis ips-bridge -> /tmp/fcpty (stand-in FC replaying the real flight)

The laptop transmits the scenario's uplink frames (attacker + GCS) over the radio at their recorded times and counts the downlink it
receives; the Pi side logs which injected uplink frames reached the FC and polls the bridge for alerts. Evidence tier BENCH/REPLAY:
real bridge + real serial + real radio; the vehicle is a stand-in replaying recorded real-flight telemetry.
"""
from __future__ import annotations

import argparse
import json
import os
import pickle
import subprocess
import sys
import threading
import time
from pathlib import Path

import serial

HOST = os.environ.get("AEGIS_PI_HOST", "user@raspberrypi.local")          # ssh target of the companion computer
KEY = os.environ.get("AEGIS_PI_KEY", str(Path.home() / ".ssh" / "id_ed25519"))
GCS_PORT = os.environ.get("AEGIS_GCS_PORT", "COM3")                       # laptop-side telemetry radio
RADIO = "/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0"


def ssh(cmd: str, timeout: int = 60) -> str:
    p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-i", KEY, HOST, cmd], capture_output=True, text=True,
                       timeout=timeout)
    return (p.stdout or "") + (p.stderr or "")


START = r"""#!/bin/bash
# hw_start.sh SCENARIO MODE SECS RUNTAG
SC=$1; MODE=$2; SECS=$3; TAG=$4
for p in $(pgrep -f "ips-bridge|pi_replay|fake_fc"); do [ "$p" != "$$" ] && kill $p 2>/dev/null; done
sleep 0.5; rm -f /tmp/go /tmp/fcpty /tmp/result.json
[ -f /tmp/benchkey ] || head -c 32 /dev/urandom > /tmp/benchkey
cd ~/aegis-flight
nohup ~/aegis-venv/bin/python scripts/realworld/pi_replay.py /tmp/scn/$SC.pkl /tmp/fcpty /tmp/result.json > /tmp/replay.log 2>&1 &
for i in $(seq 1 50); do [ -e /tmp/fcpty ] && break; sleep 0.1; done
EXTRA=""
if [ "$MODE" = "active-ips" ]; then EXTRA="--allow-hardware-active-ips --signing-key-file /tmp/benchkey --signing-state /tmp/s_$TAG.json --signing-permissive"; fi
nohup timeout $((SECS+30)) ~/aegis-venv/bin/aegis ips-bridge --fc-port /tmp/fcpty --fc-baud 115200 --gcs-port """ + RADIO + r""" --gcs-baud 115200 \
  --defense-mode $MODE --config-dir configs/universal_flight --status-port 8765 $EXTRA > /tmp/bridge.log 2>&1 &
sleep 3; tail -1 /tmp/bridge.log | cut -c1-160
"""
STOP = r"""#!/bin/bash
for p in $(pgrep -f "ips-bridge|pi_replay|fake_fc"); do [ "$p" != "$$" ] && kill $p 2>/dev/null; done
"""


def run_one(sc_path: Path, mode: str, tag: str, ser: serial.Serial) -> dict:
    sc = pickle.load(open(sc_path, "rb"))
    frames = sc["frames"]
    dur = frames[-1][0] + 3.0
    out = ssh(f"bash /tmp/hw_start.sh {sc_path.stem} {mode} {int(dur)} {tag}", 60).strip()
    if "refus" in out or "Traceback" in out:
        return {"name": sc["name"], "mode": mode, "error": out[-300:]}
    ser.reset_input_buffer()
    up = [(t, raw) for t, raw, d in frames if d == "up"]
    stop = threading.Event()
    rx = {"frames": 0, "bytes": 0}

    def reader() -> None:

        from pymavlink.dialects.v10 import ardupilotmega as mav1  # noqa: F401
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
        from aegisflight.proxy.transport import split_frames
        while not stop.is_set():
            d = ser.read(4096)
            rx["bytes"] += len(d)
            rx["frames"] += len(split_frames(d)[0]) if d else 0

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    ssh("touch /tmp/go", 15)
    t0 = time.monotonic()
    sent_up = 0
    i = 0
    while time.monotonic() - t0 < dur:
        now = time.monotonic() - t0
        while i < len(up) and up[i][0] <= now:
            ser.write(up[i][1])
            sent_up += 1
            i += 1
        time.sleep(0.003)
    time.sleep(2.0)
    stop.set()
    th.join(timeout=2)
    raw = ssh("cat /tmp/result.json 2>/dev/null", 20)
    ssh("bash /tmp/hw_stop.sh", 20)
    try:
        res = json.loads(raw)
    except Exception:  # noqa: BLE001
        return {"name": sc["name"], "mode": mode, "error": "no result: " + raw[-200:]}
    res.update(mode_requested=mode, laptop_up_sent=sent_up, laptop_down_rx_frames=rx["frames"], laptop_down_rx_bytes=rx["bytes"])
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--modes", default="passive,advisory,active-ips")
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    scn = sorted(Path(a.scenarios).glob("*.pkl"))
    if a.only:
        scn = [s for s in scn if any(k in s.stem for k in a.only.split(","))]
    # ship scenarios + scripts + helper shells to the Pi
    root = Path(__file__).resolve().parents[2]
    subprocess.run(["scp", "-q", "-o", "BatchMode=yes", "-i", KEY, "-r", str(Path(a.scenarios)), f"{HOST}:/tmp/scn"], check=True)
    subprocess.run(["scp", "-q", "-o", "BatchMode=yes", "-i", KEY, str(root / "scripts/realworld/pi_replay.py"),
                    f"{HOST}:aegis-flight/scripts/realworld/pi_replay.py"], check=False)
    ssh("mkdir -p ~/aegis-flight/scripts/realworld")
    subprocess.run(["scp", "-q", "-o", "BatchMode=yes", "-i", KEY, str(root / "scripts/realworld/pi_replay.py"),
                    f"{HOST}:aegis-flight/scripts/realworld/pi_replay.py"], check=True)
    ssh("cat > /tmp/hw_start.sh <<'EOF'\n" + START + "\nEOF\ncat > /tmp/hw_stop.sh <<'EOF'\n" + STOP + "\nEOF")
    ser = serial.Serial(GCS_PORT, 115200, timeout=0.05)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    resf = out / "hw_results.jsonl"
    done = set()
    if resf.exists():
        for line in resf.read_text().splitlines():
            d = json.loads(line)
            done.add((d.get("name"), d.get("mode_requested")))
    modes = a.modes.split(",")
    total = len(scn) * len(modes)
    n = 0
    t_start = time.time()
    for sc in scn:
        for mode in modes:
            n += 1
            key = (sc.stem, mode)
            if key in done:
                continue
            res = run_one(sc, mode, f"{sc.stem}_{mode}", ser)
            res.setdefault("mode_requested", mode)
            res.setdefault("name", sc.stem)
            with resf.open("a") as fh:
                fh.write(json.dumps(res) + "\n")
            el = time.time() - t_start
            print(f"[{n}/{total}] {sc.stem} {mode} alerts={len(res.get('alerts', []))} inj_deliv={res.get('uplink_injected_delivered')}/"
                  f"{res.get('uplink_injected_total')} err={res.get('error')} ({el / 60:.0f} min)", flush=True)


if __name__ == "__main__":
    main()
