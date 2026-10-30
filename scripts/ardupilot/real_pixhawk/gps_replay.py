# ruff: noqa  (bench script: quick one-off driver against a real, DISARMED, prop-less flight controller; not library code)
"""Replay the captured real-GPS bench log through the repo's FeatureExtractor + PhysicsDetector (no attacks). usage: gps_replay.py LOG"""
import sys, json, collections
from pymavlink.dialects.v20 import ardupilotmega as mav
from aegisflight.config import load_config
from aegisflight.core.types import MessageEnvelope
from aegisflight.features.extractor import FeatureExtractor
from aegisflight.detectors.physics import PhysicsDetector

IDS = {c.name: i for i, c in mav.mavlink_map.items()}
cfg = load_config("configs/ardupilot_copter")
det = cfg.detector if hasattr(cfg, "detector") else cfg["detector"]
rows = [json.loads(l) for l in open(sys.argv[1])]

def run(label, step, use_ekf):
    ex = FeatureExtractor(); ph = PhysicsDetector(det["physics"])
    n = flagged = 0; hits = collections.Counter(); k = 0; mx = 0.0; first = None
    for r in rows:
        name = r["mavpackettype"]
        if name == "EKF_STATUS_REPORT" and not use_ekf: continue
        if name == "GLOBAL_POSITION_INT":
            k += 1
            if (k - 1) % step: continue
        elif step > 1 and name in ("GPS_RAW_INT", "ATTITUDE", "VIBRATION", "SYS_STATUS"):
            continue
        f = {a: v for a, v in r.items() if a not in ("mavpackettype", "_t")}
        ex.update(MessageEnvelope(recv_time=r["_t"], sysid=1, compid=1, msgid=IDS[name], msgname=name, seq=0, signed=False, byte_len=30, fields=f))
        if name == "GLOBAL_POSITION_INT":
            fr = ex.extract(r["_t"]); res = ph.process(fr)
            n += 1; mx = max(mx, fr.pos_residual_m)
            if res.score >= 0.5:
                flagged += 1; first = first if first is not None else round(r["_t"], 1)
                hits[(res.evidence[0] if res.evidence else '')[:48]] += 1
    print(f"{label:34s} ticks {n:4d}  GPS-spoofing evidence on {flagged:4d} ({100*flagged/max(n,1):4.1f}%)  max residual {mx:5.1f} m  first at {first}  {dict(hits.most_common(2))}")
run("4 Hz, EKF status present", 1, True)
run("4 Hz, EKF status ABSENT", 1, False)
run("1 Hz, EKF status present", 4, True)
run("1 Hz, EKF status ABSENT (my tests)", 4, False)
