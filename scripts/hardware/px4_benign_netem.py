"""Benign PX4 SITL mission with the IDS fed live from the same GCS link. [SITL], link-level only.

One process is both the ground station (heartbeat, arm, takeoff, square legs, land) on PX4's GCS
UDP port and the IDS: every frame received is written to a tlog and queued into
``LiveMavlinkSource`` -> ``IDSPipeline`` (PX4 locks its GCS link to the first sender, so a second
client cannot observe the same stream). No attack is injected and nothing is sent to the vehicle
except GCS commands. Run it in a container that shares PX4's network namespace; optionally impair
the GCS link first with ``scripts/hardware/px4_netem_on.sh`` (needs NET_ADMIN). Start a FRESH PX4
for every run.

    python scripts/hardware/px4_benign_netem.py --out /out/run1 --profile configs/universal_flight --laps 2
"""

import argparse
import json
import math
import queue
import struct
import sys
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from pymavlink import mavutil

from aegisflight.config import load_config
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.mavlink_live import LiveMavlinkSource


class QTransport:
    def __init__(self):
        self.q = queue.Queue()
        self.dropped_overflow = 0

    def start(self):
        pass

    def put(self, buf):
        self.q.put((time.monotonic_ns(), bytes(buf)))

    def poll(self):
        out = []
        try:
            while True:
                out.append(self.q.get_nowait())
        except queue.Empty:
            pass
        return out

    def close(self):
        pass


ap = argparse.ArgumentParser()
ap.add_argument("--out", required=True)
ap.add_argument("--profile", default="configs/universal_flight")
ap.add_argument("--alt", type=float, default=20.0)
ap.add_argument("--side", type=float, default=60.0)
ap.add_argument("--laps", type=int, default=3)
ap.add_argument("--no-ml", action="store_true")
ap.add_argument("--port", type=int, default=18570)
a = ap.parse_args()
out = Path(a.out)
out.parent.mkdir(parents=True, exist_ok=True)
cfg = load_config(a.profile)
model = None if a.no_ml else "models/isoforest.joblib"
pipe = IDSPipeline(cfg, model_path=model, firmware_dir=None)
tr = QTransport()
stop = threading.Event()
decisions = []
classes = Counter()
lat = []


def ids_thread():
    src = LiveMavlinkSource(tr, sample_rate_hz=10.0)
    with open(out.with_suffix(".jsonl"), "w") as jf:
        for tick in src.stream():
            if stop.is_set():
                break
            asmt = pipe.process_tick(tick)
            if asmt is None:
                continue
            lat.append(asmt.latency_ms)
            classes[asmt.attack_type.value if asmt.threat else "BENIGN"] += 1
            rec = {
                "t": round(asmt.t, 2),
                "wall": time.time(),
                "threat": bool(asmt.threat),
                "type": asmt.attack_type.value,
                "score": round(asmt.threat_score, 3),
                "lat_ms": round(asmt.latency_ms, 2),
                "n_msgs": len(tick.messages),
            }
            if asmt.threat:
                rec["explain"] = str(getattr(asmt, "explanation", ""))[:300]
            jf.write(json.dumps(rec) + "\n")
            jf.flush()
    out.with_suffix(".stats.json").write_text(
        json.dumps(src.stats if isinstance(src.stats, dict) else str(src.stats))
    )


th = threading.Thread(target=ids_thread, daemon=True)
th.start()

m = mavutil.mavlink_connection(
    f"udpout:127.0.0.1:{a.port}", source_system=255, source_component=190, dialect="common"
)
tlog = open(out.with_suffix(".tlog"), "wb")
st = {
    "hb": None,
    "pos": None,
    "ack": {},
    "last_hb": 0.0,
    "n": 0,
    "target": (1, 1),
    "mode_changes": [],
}


def pump(timeout=0.05):
    now = time.time()
    if now - st["last_hb"] >= 1.0:
        m.mav.heartbeat_send(
            mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0
        )
        st["last_hb"] = now
    while True:
        msg = m.recv_match(blocking=True, timeout=timeout)
        timeout = 0
        if msg is None:
            return
        buf = msg.get_msgbuf()
        if buf:
            tlog.write(struct.pack(">Q", int(time.time() * 1e6)) + bytes(buf))
            tr.put(buf)
            st["n"] += 1
        t = msg.get_type()
        if (
            t == "HEARTBEAT"
            and msg.get_srcComponent() == 1
            and msg.type != mavutil.mavlink.MAV_TYPE_GCS
        ):
            st["hb"] = msg
            st["target"] = (msg.get_srcSystem(), msg.get_srcComponent())
        elif t == "COMMAND_ACK":
            st["ack"][msg.command] = msg.result
        elif t == "GLOBAL_POSITION_INT":
            st["pos"] = {
                "lat": msg.lat / 1e7,
                "lon": msg.lon / 1e7,
                "alt": msg.alt / 1e3,
                "rel": msg.relative_alt / 1e3,
            }


def wait(s):
    e = time.time() + s
    while time.time() < e:
        pump()


def cmd(c, *p):
    p = tuple(p) + (0.0,) * (7 - len(p))
    m.mav.command_long_send(st["target"][0], st["target"][1], c, 0, *p)
    e = time.time() + 5
    while time.time() < e:
        pump(0.1)
        if c in st["ack"]:
            return st["ack"].pop(c)
    return None


def armed():
    return bool(st["hb"] and st["hb"].base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED)


def goto(lat, lon, alt, tol=3.0, timeout=60):
    cmd(mavutil.mavlink.MAV_CMD_DO_REPOSITION, -1, 1, 0, math.nan, lat, lon, alt)
    e = time.time() + timeout
    while time.time() < e:
        pump()
        if st["pos"]:
            dn = (st["pos"]["lat"] - lat) * 111320.0
            de = (st["pos"]["lon"] - lon) * 111320.0 * math.cos(math.radians(lat))
            if math.hypot(dn, de) < tol and abs(st["pos"]["alt"] - alt) < tol:
                return True
    return False


ev = {"t_start": datetime.now(UTC).isoformat()}
t0 = time.time()
while (st["hb"] is None or st["pos"] is None) and time.time() - t0 < 60:
    pump()
if st["hb"] is None or st["pos"] is None:
    print("NO HB/POS")
    sys.exit(2)
home = dict(st["pos"])
ev["home"] = home
wait(5)
res = None
for _ in range(40):
    res = cmd(mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 1)
    if res == 0:
        break
    wait(2)
ev["arm_result"] = res
if res != 0:
    print("ARM REJECTED", res)
    stop.set()
    sys.exit(3)
ev["t_armed"] = datetime.now(UTC).isoformat()
tgt = home["alt"] + a.alt
ev["takeoff"] = cmd(
    mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, math.nan, 0, 0, math.nan, math.nan, math.nan, tgt
)
e = time.time() + 60
while time.time() < e and (st["pos"] is None or st["pos"]["alt"] < tgt - 2):
    pump()
dlat = a.side / 111320.0
dlon = a.side / (111320.0 * math.cos(math.radians(home["lat"])))
legs = [(dlat, 0), (dlat, dlon), (0, dlon), (0, 0)] * a.laps
ev["legs_reached"] = []
for x, y in legs:
    ev["legs_reached"].append(goto(home["lat"] + x, home["lon"] + y, tgt))
    wait(2)
ev["land"] = cmd(
    mavutil.mavlink.MAV_CMD_NAV_LAND, 0, 0, 0, math.nan, math.nan, math.nan, home["alt"]
)
e = time.time() + 90
while time.time() < e and armed():
    pump()
ev["disarmed_after_land"] = not armed()
ev["t_end"] = datetime.now(UTC).isoformat()
wait(3)
stop.set()
th.join(timeout=5)
tlog.close()
ls = sorted(lat)
summ = {
    "environment": "SITL",
    "claim_class": "link-level (no attack injected)",
    "ml_enabled": model is not None,
    "profile": a.profile,
    "frames": st["n"],
    "decisions": sum(classes.values()),
    "classes": dict(classes),
    "lat_ms_p50": ls[len(ls) // 2] if ls else None,
    "lat_ms_p99": ls[int(0.99 * (len(ls) - 1))] if ls else None,
    "events": ev,
    "duration_s": round(time.time() - t0, 1),
}
out.with_suffix(".summary.json").write_text(json.dumps(summ, indent=2))
print(json.dumps(summ, indent=2))
