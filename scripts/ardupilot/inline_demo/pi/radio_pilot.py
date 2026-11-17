"""Pilot for the real-radio session. Low stream rates (the LR900 carries ~1 KB/s each way), takeoff, hold, benign probes,
forged LAND at the given times. usage: radio_pilot.py <label> <flight_seconds> [attack_at_s ...]"""

import json
import os
import sys
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil

label, total = sys.argv[1], float(sys.argv[2])
attack_at = [float(x) for x in sys.argv[3:]]
m = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=255, source_component=190)
a = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=66, source_component=190)
m.wait_heartbeat(timeout=60)
ts, tc = m.target_system, m.target_component
print("heartbeat over the radio", ts, tc, flush=True)
RATES = (
    ("SR1_POSITION", 2),
    ("SR1_EXTRA1", 2),
    ("SR1_EXTRA2", 1),
    ("SR1_EXT_STAT", 1),
    ("SR1_EXTRA3", 1),
    ("SR1_RAW_SENS", 0),
    ("SR1_RC_CHAN", 0),
    ("SR1_RAW_CTRL", 0),
    ("SR1_PARAMS", 0),
    ("SR1_ADSB", 0),
    ("ARMING_CHECK", 0),
)
for n, v in RATES:
    m.mav.param_set_send(ts, tc, n.encode(), float(v), mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
    time.sleep(0.5)
# a running ArduPilot only changes its stream rates on REQUEST_DATA_STREAM (the SR1_* parameters apply at boot):
# ~1 KB/s total fits the LR900 downlink
for sid, hz in (
    (mavutil.mavlink.MAV_DATA_STREAM_RAW_SENSORS, 0),
    (mavutil.mavlink.MAV_DATA_STREAM_RC_CHANNELS, 0),
    (mavutil.mavlink.MAV_DATA_STREAM_RAW_CONTROLLER, 0),
    (mavutil.mavlink.MAV_DATA_STREAM_EXTENDED_STATUS, 1),
    (mavutil.mavlink.MAV_DATA_STREAM_POSITION, 2),
    (mavutil.mavlink.MAV_DATA_STREAM_EXTRA1, 2),
    (mavutil.mavlink.MAV_DATA_STREAM_EXTRA2, 1),
    (mavutil.mavlink.MAV_DATA_STREAM_EXTRA3, 1),
):
    m.mav.request_data_stream_send(ts, tc, sid, hz, 1 if hz else 0)
    time.sleep(0.4)
st = {"mode": None, "armed": False, "alt": 0.0}
hb = []
msgs = 0
probes = {"sent": 0, "acked": 0}
mode_log = []
lands = 0


def pump(sec):
    global msgs
    end = time.time() + sec
    while time.time() < end:
        while a.recv_match(blocking=False) is not None:
            pass
        x = m.recv_match(blocking=True, timeout=0.3)
        if x is None:
            continue
        msgs += 1
        t = x.get_type()
        if t == "HEARTBEAT" and x.get_srcSystem() == 1 and x.get_srcComponent() == 1:
            hb.append(time.time())
            st["armed"] = bool(x.base_mode & 0x80)
            if st["mode"] != x.custom_mode:
                mode_log.append((round(time.time() - t0, 1), x.custom_mode))
            st["mode"] = x.custom_mode
        elif t == "GLOBAL_POSITION_INT":
            st["alt"] = x.relative_alt / 1000.0
        elif t == "COMMAND_ACK" and x.command == 176 and x.result == 0:
            probes["acked"] += 1


t0 = time.time()
pump(50)
m.mav.set_mode_send(ts, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 4)
pump(4)
m.mav.command_long_send(ts, tc, 400, 0, 1, 0, 0, 0, 0, 0, 0)
pump(5)
m.mav.command_long_send(ts, tc, 22, 0, 0, 0, 0, 0, 0, 0, 30)
pump(30)
print("airborne", st, flush=True)
tf = time.time()
last_hb = 0.0
last_probe = tf
pending = sorted(attack_at)
while time.time() - tf < total:
    if time.time() - last_hb >= 1.0:
        m.mav.heartbeat_send(
            mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0
        )
        last_hb = time.time()
    if time.time() - last_probe >= 20:
        m.mav.command_long_send(ts, tc, 176, 0, 1, 4, 0, 0, 0, 0, 0)
        probes["sent"] += 1
        last_probe = time.time()
    if pending and time.time() - tf >= pending[0]:
        pending.pop(0)
        a.mav.set_mode_send(ts, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 9)
        a.mav.command_long_send(ts, tc, 176, 0, 1, 9, 0, 0, 0, 0, 0)
        print("forged LAND sent", round(time.time() - tf), flush=True)
        pump(4)
        if st["mode"] == 9:
            lands += 1
    pump(0.5)
gaps = [
    (round(x - hb[0], 1), round(y - x, 1)) for x, y in zip(hb, hb[1:], strict=False) if y - x > 3.0
]
out = {
    "flight_s": round(time.time() - tf),
    "heartbeats": len(hb),
    "msgs": msgs,
    "gaps_over_3s": gaps,
    "probes": probes,
    "vehicle_went_to_land": lands,
    "final": st,
    "mode_changes": mode_log,
}
json.dump(out, open(f"C:/afsitl/radiopilot_{label}.json", "w"))
print("pilot done", json.dumps(out)[:500], flush=True)
