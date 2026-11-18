"""Long-run pilot for the Pi soak: take off, hold, benign mode probe every 30 s, forged LAND every 5 min.

usage: soak_pilot.py <label> <seconds> -- writes soak_<label>.json
"""

import json
import os
import sys
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil

label, total = sys.argv[1], float(sys.argv[2])
m = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=255, source_component=190)
a = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=66, source_component=190)
m.wait_heartbeat(timeout=30)
ts, tc = m.target_system, m.target_component
m.mav.request_data_stream_send(ts, tc, mavutil.mavlink.MAV_DATA_STREAM_ALL, 5, 1)
for n, v in (
    ("SR1_POSITION", 5),
    ("SR1_EXTRA1", 5),
    ("SR1_EXTRA2", 5),
    ("SR1_RAW_SENS", 2),
    ("SR1_EXT_STAT", 2),
    ("SR1_EXTRA3", 2),
    ("ARMING_CHECK", 0),
):
    m.param_set_send(n, v)
    time.sleep(0.2)
st = {"mode": None, "armed": False, "alt": 0.0}
hb_t = []
msgs = 0
acks = {"sent": 0, "ok": 0}
attacks = 0
lands = 0
mode_log = []


def pump(sec):
    global msgs
    end = time.time() + sec
    while time.time() < end:
        while (
            a.recv_match(blocking=False) is not None
        ):  # keep the attacker's socket drained or the hub drops it
            pass
        x = m.recv_match(blocking=True, timeout=0.3)
        if x is None:
            continue
        msgs += 1
        t = x.get_type()
        if t == "HEARTBEAT" and x.get_srcSystem() == 1 and x.get_srcComponent() == 1:
            hb_t.append(time.time())
            st["armed"] = bool(x.base_mode & 0x80)
            if st["mode"] != x.custom_mode:
                mode_log.append((round(time.time() - t0, 1), x.custom_mode))
            st["mode"] = x.custom_mode
        elif t == "GLOBAL_POSITION_INT":
            st["alt"] = x.relative_alt / 1000.0
        elif t == "COMMAND_ACK" and x.command == 176:
            if x.result == 0:
                acks["ok"] += 1


t0 = time.time()
pump(45)
m.mav.set_mode_send(ts, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 4)
pump(3)
m.mav.command_long_send(ts, tc, 400, 0, 1, 0, 0, 0, 0, 0, 0)
pump(4)
m.mav.command_long_send(ts, tc, 22, 0, 0, 0, 0, 0, 0, 0, 30)
pump(25)
print("airborne", st, flush=True)
tf = time.time()
last_probe = tf
last_att = tf
last_hb = 0.0
while time.time() - tf < total:
    if time.time() - last_hb >= 1.0:
        m.mav.heartbeat_send(
            mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0
        )
        last_hb = time.time()
    if time.time() - last_probe >= 30:
        m.mav.command_long_send(ts, tc, 176, 0, 1, 4, 0, 0, 0, 0, 0)
        acks["sent"] += 1
        last_probe = time.time()
    if time.time() - last_att >= 300:
        a.mav.set_mode_send(ts, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 9)  # forged LAND
        a.mav.command_long_send(ts, tc, 176, 0, 1, 9, 0, 0, 0, 0, 0)
        attacks += 1
        last_att = time.time()
        pump(3)
        if st["mode"] == 9:
            lands += 1
    pump(0.5)
gaps = [
    (round(x - hb_t[0], 1), round(y - x, 1))
    for x, y in zip(hb_t, hb_t[1:], strict=False)
    if y - x > 1.5
]
out = {
    "flight_s": round(time.time() - tf),
    "heartbeats": len(hb_t),
    "msgs": msgs,
    "gaps": gaps,
    "probes": acks,
    "forged_land_attempts": attacks,
    "vehicle_went_to_land": lands,
    "final": st,
    "mode_changes": mode_log,
}
json.dump(out, open(f"C:/afsitl/soak_{label}.json", "w"))
print("soak done", json.dumps(out)[:600], flush=True)
