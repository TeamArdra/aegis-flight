"""Laptop orchestrator: command-path attacks against the REAL flight controller through the REAL bridge on the Pi and the REAL radio,
in all three postures. The Pixhawk must be on the bench with PROPS OFF (it is armed briefly in the disarm scenario).

    laptop COM3 radio  <==radio==>  Pi radio -> aegis ips-bridge -> Pixhawk (USB-CDC)

Outcome is read from what the real FC reports back over the radio (HEARTBEAT armed/mode, COMMAND_ACK, PARAM_VALUE, SYSTEM_TIME boot
counter, STATUSTEXT) plus the bridge /status counters read over ssh. Evidence tier: BENCH (real FC, no flight). Never FIELD-flight.

    python rw_hw_real_fc.py --out DIR [--only a,b] [--modes passive,advisory,active-ips]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import threading
import time
from pathlib import Path

import serial
from pymavlink.dialects.v20 import ardupilotmega as mav

HOST = os.environ.get("AEGIS_PI_HOST", "user@raspberrypi.local")          # ssh target of the companion computer
KEY = os.environ.get("AEGIS_PI_KEY", str(Path.home() / ".ssh" / "id_ed25519"))
GCS_PORT = os.environ.get("AEGIS_GCS_PORT", "COM3")                       # laptop-side telemetry radio
RADIO = "/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0"
PARAM = b"SCR_USER1"          # unused scripting user parameter: harmless to write, restored afterwards
PILOT, ROGUE = 255, 66
TGT = (1, 1)


def ssh(cmd: str, timeout: int = 60) -> str:
    p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-i", KEY, HOST, cmd], capture_output=True, text=True,
                       timeout=timeout)
    return (p.stdout or "") + (p.stderr or "")


START = r"""#!/bin/bash
# real_start.sh MODE TAG
MODE=$1; TAG=$2
for p in $(pgrep -f "ips-bridge"); do [ "$p" != "$$" ] && kill $p 2>/dev/null; done
sleep 0.5
FC=$(ls /dev/serial/by-id/* 2>/dev/null | grep -v Silicon | head -1)
[ -z "$FC" ] && { echo "NO_FC"; exit 1; }
[ -f /tmp/benchkey ] || head -c 32 /dev/urandom > /tmp/benchkey
cd ~/aegis-flight
EXTRA=""
if [ "$MODE" = "active-ips" ]; then EXTRA="--allow-hardware-active-ips --signing-key-file /tmp/benchkey --signing-state /tmp/s_$TAG.json --signing-permissive"; fi
nohup timeout 120 ~/aegis-venv/bin/aegis ips-bridge --fc-port "$FC" --fc-baud 115200 --gcs-port """ + RADIO + r""" --gcs-baud 115200 \
  --defense-mode $MODE --config-dir configs/universal_flight --status-port 8765 $EXTRA > /tmp/bridge.log 2>&1 &
sleep 3; echo "FC=$FC"; tail -1 /tmp/bridge.log | cut -c1-160
"""
STOP = r"""#!/bin/bash
for p in $(pgrep -f "ips-bridge"); do [ "$p" != "$$" ] && kill $p 2>/dev/null; done
"""
STATUS = r"""curl -s --max-time 3 http://127.0.0.1:8765/status"""


class Obs:
    """Reads the downlink the real FC sends back through the bridge and radio."""

    def __init__(self, ser: serial.Serial) -> None:
        self.ser = ser
        self.dec = mav.MAVLink(None)
        self.dec.robust_parsing = True
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.hb: list[tuple[float, int, int, int]] = []   # (t, armed, custom_mode, sysid)
        self.boot: list[tuple[float, int]] = []
        self.acks: list[tuple[float, int, int]] = []
        self.params: list[tuple[float, str, float]] = []
        self.texts: list[tuple[float, str]] = []
        self.msgs = 0
        self.th = threading.Thread(target=self.run, daemon=True)
        self.th.start()

    def run(self) -> None:
        while not self.stop.is_set():
            d = self.ser.read(4096)
            if not d:
                continue
            try:
                ms = self.dec.parse_buffer(bytearray(d)) or []
            except Exception:  # noqa: BLE001
                continue
            t = time.monotonic()
            with self.lock:
                for m in ms:
                    self.msgs += 1
                    n = m.get_type()
                    if n == "HEARTBEAT" and m.type != 6:   # not a GCS
                        self.hb.append((t, 1 if m.base_mode & 128 else 0, m.custom_mode, m.get_srcSystem()))
                    elif n == "SYSTEM_TIME":
                        self.boot.append((t, m.time_boot_ms))
                    elif n == "COMMAND_ACK":
                        self.acks.append((t, m.command, m.result))
                    elif n == "PARAM_VALUE":
                        self.params.append((t, str(m.param_id).strip("\x00"), m.param_value))
                    elif n == "STATUSTEXT":
                        self.texts.append((t, str(m.text)))

    def snap(self) -> dict:
        with self.lock:
            return {"hb": list(self.hb), "boot": list(self.boot), "acks": list(self.acks), "params": list(self.params),
                    "texts": list(self.texts), "msgs": self.msgs}


class Tx:
    def __init__(self, ser: serial.Serial) -> None:
        self.ser = ser
        self.enc = {s: mav.MAVLink(None, srcSystem=s, srcComponent=190) for s in (PILOT, ROGUE)}
        self.sent = {"pilot": 0, "attack": 0}

    def send(self, sysid: int, msg, kind: str) -> bytes:
        raw = bytes(msg.pack(self.enc[sysid]))
        self.ser.write(raw)
        self.sent[kind] += 1
        return raw


def cmd(c: int, p1=0, p2=0, p3=0, p4=0, p5=0, p6=0, p7=0):
    return mav.MAVLink_command_long_message(*TGT, c, 0, p1, p2, p3, p4, p5, p6, p7)


def attack_msg(kind: str):
    if kind == "disarm":
        return cmd(400, 0, 21196)
    if kind == "force_arm":
        return cmd(400, 1, 2989)
    if kind == "reboot":
        return cmd(246, 1)
    if kind == "set_mode":
        return cmd(176, 1, 9)                       # LAND (ArduCopter 9); disarmed board: mode change is observable
    if kind == "param_set":
        return mav.MAVLink_param_set_message(*TGT, PARAM, 777.0, 9)
    if kind == "rc_override":
        return mav.MAVLink_rc_channels_override_message(*TGT, 1000, 1000, 1000, 1000, 0, 0, 0, 0)
    if kind == "waypoint":
        return mav.MAVLink_mission_item_int_message(*TGT, 0, 3, 16, 2, 1, 0, 0, 0, 0, int(19.0e7), int(73.0e7), 100.0, 0)
    raise ValueError(kind)


SCEN = [  # name, attack kind, sysid, rate/s, window s, pilot pre-arm
    ("benign", None, None, 0, 10, False),
    ("cmd_disarm", "disarm", ROGUE, 2, 8, True),
    ("cmd_force_arm", "force_arm", ROGUE, 2, 8, False),
    ("cmd_reboot", "reboot", ROGUE, 0.5, 8, False),
    ("cmd_param_set", "param_set", ROGUE, 2, 8, False),
    ("cmd_rc_override", "rc_override", ROGUE, 5, 8, False),
    ("cmd_waypoint", "waypoint", ROGUE, 2, 8, False),
    ("gcs_replay_set_mode", "set_mode", PILOT, 2, 8, False),   # trusted sysid, unsigned: the known gap
    ("cmd_set_mode", "set_mode", ROGUE, 2, 8, False),
]


def last(snap: dict, key: str):
    return snap[key][-1] if snap[key] else None


def wait_fc(timeout: float = 60) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if "FC=" in ssh("ls /dev/serial/by-id/* 2>/dev/null | grep -v Silicon | head -1 | sed 's/^/FC=/'", 15):
            return True
        time.sleep(2)
    return False


def pump(tx: Tx, secs: float, hb_every: float = 1.0) -> None:
    t0 = time.monotonic()
    nxt = t0
    while time.monotonic() - t0 < secs:
        if time.monotonic() >= nxt:
            tx.send(PILOT, mav.MAVLink_heartbeat_message(6, 8, 0, 0, 4, 3), "pilot")
            nxt += hb_every
        time.sleep(0.05)


def run_one(sc: tuple, mode: str, ser: serial.Serial, obs: Obs, tx: Tx) -> dict:
    name, kind, sysid, rate, win, prearm = sc
    res: dict = {"scenario": name, "kind": kind, "mode": mode, "sysid": sysid, "tier": "BENCH real FC, no flight"}
    if not wait_fc():
        return res | {"error": "FC not present"}
    out = ssh(f"bash /tmp/real_start.sh {mode} {name}_{mode}", 60).strip()
    res["start"] = out[-200:]
    if "NO_FC" in out or "refus" in out or "Traceback" in out:
        return res | {"error": out[-300:]}
    ser.reset_input_buffer()
    pump(tx, 6)                                           # settle: learn baseline state
    base = obs.snap()
    res["baseline_msgs"] = base["msgs"]
    if not base["hb"]:
        ssh("bash /tmp/real_stop.sh", 20)
        return res | {"error": "no heartbeat from the FC through the bridge/radio"}
    if prearm:                                            # pilot force-arm (props off) so a disarm attack has something to undo
        tx.send(PILOT, cmd(400, 1, 2989), "pilot")
        pump(tx, 3)
    tx.send(PILOT, mav.MAVLink_param_request_read_message(*TGT, PARAM, -1), "pilot")
    pump(tx, 1.5)
    pre = obs.snap()
    res["pre"] = {"armed": last(pre, "hb")[1], "mode": last(pre, "hb")[2], "boot_ms": (last(pre, "boot") or (0, None))[1],
                  "scr_user1": next((v for _, n, v in reversed(pre["params"]) if n == "SCR_USER1"), None)}
    t_att = time.monotonic()
    if kind is not None:
        t0 = time.monotonic()
        while time.monotonic() - t0 < win:
            tx.send(sysid, attack_msg(kind), "attack" if sysid != PILOT else "attack")
            pump(tx, 1.0 / rate)
    else:
        pump(tx, win)
    tx.send(PILOT, mav.MAVLink_param_request_read_message(*TGT, PARAM, -1), "pilot")
    pump(tx, 4)
    post = obs.snap()
    hb_new = [h for h in post["hb"] if h[0] >= t_att]
    boot_new = [b for t, b in post["boot"] if t >= t_att]
    res["post"] = {"armed": hb_new[-1][1] if hb_new else None, "mode": hb_new[-1][2] if hb_new else None,
                   "any_armed_during": any(h[1] for h in hb_new), "modes_seen": sorted({h[2] for h in hb_new}),
                   "boot_ms_regressed": any(b2 < b1 for b1, b2 in zip(boot_new, boot_new[1:], strict=False)) or (
                       bool(boot_new) and res["pre"]["boot_ms"] is not None and min(boot_new) < res["pre"]["boot_ms"]),
                   "hb_after_attack": len(hb_new),
                   "scr_user1": next((v for t, n, v in reversed(post["params"]) if n == "SCR_USER1" and t >= t_att), None),
                   "acks": [(c, r) for t, c, r in post["acks"] if t >= t_att][:12],
                   "texts": [s for t, s in post["texts"] if t >= t_att][-4:]}
    # restore: disarm, restore param and mode (pilot sysid 255 passes every posture)
    tx.send(PILOT, cmd(400, 0, 21196), "pilot")
    orig = res["pre"]["scr_user1"]
    if orig is not None:
        tx.send(PILOT, mav.MAVLink_param_set_message(*TGT, PARAM, float(orig), 9), "pilot")
    tx.send(PILOT, cmd(176, 1, int(res["pre"]["mode"])), "pilot")
    pump(tx, 3)
    fin = obs.snap()
    fh = [h for h in fin["hb"] if h[0] >= t_att]
    res["final_armed"] = fh[-1][1] if fh else None
    st = ssh(STATUS, 20)
    try:
        d = json.loads(st)
        res["bridge"] = {"mode": d.get("mode"), "state": d.get("state"), "frames": d.get("frames"), "alerts": (d.get("analyser") or {}).get("alerts"),
                         "summary": ((d.get("analyser") or {}).get("summary") or "")[:160], "latency_us": d.get("latency_us")}
    except Exception:  # noqa: BLE001
        res["bridge"] = {"raw": st[-200:]}
    res["sent"] = dict(tx.sent)
    ssh("bash /tmp/real_stop.sh", 20)
    if kind == "reboot":
        time.sleep(8)
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", default="")
    ap.add_argument("--modes", default="passive,advisory,active-ips")
    a = ap.parse_args()
    ssh("cat > /tmp/real_start.sh <<'EOF'\n" + START + "\nEOF\ncat > /tmp/real_stop.sh <<'EOF'\n" + STOP + "\nEOF")
    ser = serial.Serial(GCS_PORT, 115200, timeout=0.05)
    obs, tx = Obs(ser), Tx(ser)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    f = out / "real_fc_results.jsonl"
    done = set()
    if f.exists():
        for line in f.read_text().splitlines():
            d = json.loads(line)
            done.add((d["scenario"], d["mode"]))
    scen = [s for s in SCEN if not a.only or s[0] in a.only.split(",")]
    for sc in scen:
        for mode in a.modes.split(","):
            if (sc[0], mode) in done:
                continue
            res = run_one(sc, mode, ser, obs, tx)
            with f.open("a") as fh:
                fh.write(json.dumps(res) + "\n")
            print(sc[0], mode, "armed", res.get("pre", {}).get("armed"), "->", res.get("post", {}).get("armed"),
                  "final", res.get("final_armed"), "err", res.get("error"), flush=True)
    obs.stop.set()


if __name__ == "__main__":
    main()
