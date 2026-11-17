"""Legitimate GCS traffic suite through the radio hub (tcp 5801) against a DISARMED, prop-less ArduCopter. Never arms, never flies.
usage: px_legit.py [HOST:PORT]   -> prints PASS/FAIL per step"""

import os
import sys
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil

addr = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:5801"
m = mavutil.mavlink_connection(f"tcp:{addr}", source_system=255, source_component=190)
res = []


def hb():
    m.mav.heartbeat_send(
        mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0
    )


last_hb = [0.0]


def wait(types, timeout, cond=lambda x: True):
    end = time.time() + timeout
    while time.time() < end:
        if time.time() - last_hb[0] >= 1:
            hb()
            last_hb[0] = time.time()
        x = m.recv_match(blocking=True, timeout=0.3)
        if x is None:
            continue
        if x.get_srcSystem() != 1 or x.get_type() == "BAD_DATA":
            continue
        if x.get_type() in types and cond(x):
            return x
    return None


def step(name, ok, detail=""):
    res.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}", flush=True)


def mode():
    h = wait(("HEARTBEAT",), 5)
    return None if h is None else (h.custom_mode, bool(h.base_mode & 128))


def pread(name):
    m.mav.param_request_read_send(1, 1, name.encode(), -1)
    return wait(("PARAM_VALUE",), 8, lambda x: x.param_id.rstrip("\x00") == name)


h = wait(("HEARTBEAT",), 15)
step("vehicle heartbeat via radio+bridge", h is not None, f"mode/armed {mode()}")
if h is None or (h.base_mode & 128):
    sys.exit("no heartbeat or ARMED - stopping")
for st in (2, 6, 10, 12):
    m.mav.request_data_stream_send(1, 1, st, 1, 1)
t0 = time.time()
got = set()
while time.time() - t0 < 12:
    x = wait(
        ("SYS_STATUS", "ATTITUDE", "GLOBAL_POSITION_INT", "EKF_STATUS_REPORT", "GPS_RAW_INT"), 2
    )
    if x:
        got.add(x.get_type())
step("stream request answered (1 Hz)", len(got) >= 4, sorted(got))
for p in ("SYSID_THISMAV", "FRAME_CLASS", "BATT_MONITOR"):
    v = pread(p)
    step(f"param read {p}", v is not None, "" if v is None else v.param_value)
v = pread("SCR_USER1")
if v is None:
    step("param write/readback/restore (SCR_USER1)", True, "skipped: parameter not present")
else:
    orig = v.param_value
    m.mav.param_set_send(1, 1, b"SCR_USER1", orig + 1.0, mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
    a = wait(("PARAM_VALUE",), 8, lambda x: x.param_id.rstrip("\x00") == "SCR_USER1")
    ok1 = a is not None and abs(a.param_value - (orig + 1)) < 1e-3
    m.mav.param_set_send(1, 1, b"SCR_USER1", orig, mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
    b = wait(("PARAM_VALUE",), 8, lambda x: x.param_id.rstrip("\x00") == "SCR_USER1")
    ok2 = b is not None and abs(b.param_value - orig) < 1e-3
    step(
        "param write + readback + restore (SCR_USER1)",
        ok1 and ok2,
        f"{orig} -> {None if a is None else a.param_value} -> {None if b is None else b.param_value}",
    )
m.mav.command_long_send(1, 1, 512, 0, 148, 0, 0, 0, 0, 0, 0)  # REQUEST_MESSAGE AUTOPILOT_VERSION
ack = wait(("COMMAND_ACK",), 6, lambda x: x.command == 512)
ver = wait(("AUTOPILOT_VERSION",), 6)
step(
    "command REQUEST_MESSAGE(AUTOPILOT_VERSION)",
    ack is not None and ack.result == 0,
    f"ack={None if ack is None else ack.result} version_msg={ver is not None}",
)
for target, nm in ((2, "ALT_HOLD"), (0, "STABILIZE")):
    m.mav.command_long_send(1, 1, 176, 0, 1, target, 0, 0, 0, 0, 0)
    a = wait(("COMMAND_ACK",), 6, lambda x: x.command == 176)
    time.sleep(2.5)
    md = mode()
    step(
        f"legit pilot mode change -> {nm}",
        a is not None and a.result == 0 and md is not None and md[0] == target,
        f"ack={None if a is None else a.result} mode={md}",
    )
for _i in range(20):
    m.mav.rc_channels_override_send(1, 1, 1500, 1500, 1000, 1500, 0, 0, 0, 0)
    time.sleep(0.1)
for _i in range(5):
    m.mav.rc_channels_override_send(1, 1, 0, 0, 0, 0, 0, 0, 0, 0)
    time.sleep(0.1)
md = mode()
step(
    "RC override (neutral sticks, throttle low) then release",
    md is not None and not md[1],
    f"mode/armed={md}",
)
m.mav.mission_request_list_send(1, 1)
cnt = wait(("MISSION_COUNT",), 8)
step("mission download: count", cnt is not None, "" if cnt is None else f"count={cnt.count}")
if cnt is not None and cnt.count == 0:
    g = wait(("GLOBAL_POSITION_INT",), 6)
    lat, lon = (g.lat, g.lon) if g else (0, 0)
    m.mav.mission_count_send(1, 1, 2, 0)
    ok = True
    sent = 0
    for _ in range(2):
        r = wait(("MISSION_REQUEST_INT", "MISSION_REQUEST"), 8)
        if r is None:
            ok = False
            break
        m.mav.mission_item_int_send(
            1, 1, r.seq, 6, 16 if r.seq else 16, 0, 1, 0, 0, 0, 0, lat, lon, 10.0, 0
        )
        sent += 1
    mack = wait(("MISSION_ACK",), 8)
    step(
        "mission upload (2 items) accepted",
        ok and mack is not None and mack.type == 0,
        f"sent={sent} ack={None if mack is None else mack.type}",
    )
    m.mav.mission_clear_all_send(1, 1, 0)
    cack = wait(("MISSION_ACK",), 8)
    step("mission clear", cack is not None and cack.type == 0)
else:
    step("mission upload", True, "skipped: vehicle already has a mission (not touched)")
t0 = time.time()
m.mav.param_request_list_send(1, 1)
seen = set()
total = None
while time.time() - t0 < 170:
    x = wait(("PARAM_VALUE",), 5)
    if x is None:
        break
    total = x.param_count
    seen.add(x.param_index)
    if len(seen) >= total:
        break
step(
    "full parameter download",
    total is not None and len(seen) >= total * 0.98,
    f"{len(seen)}/{total} in {time.time() - t0:.0f}s",
)
md = mode()
step("final state disarmed", md is not None and not md[1], f"mode/armed={md}")
print("RESULT", sum(ok for _, ok in res), "of", len(res), "steps passed")
