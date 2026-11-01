# ruff: noqa  (bench script: quick one-off driver against a real, DISARMED, prop-less flight controller; not library code)
"""Shared helpers for px_snapshot.py / px_restore.py / px_signing.py: parameter and mission read/write over a direct link."""
import json
import os
import sys
import time

os.environ.setdefault("MAVLINK20", "1")
from pymavlink import mavutil

# parameters that change by themselves (counters, or re-measured / re-calibrated at every boot): shown nowhere as a
# difference and never "restored" (restoring stale sensor calibration over a fresh one would be wrong, not safer).
VOLATILE = {
    "STAT_BOOTCNT", "STAT_FLTCNT", "STAT_FLTTIME", "STAT_RESET", "STAT_RUNTIME",
    "BARO1_GND_PRESS", "BARO2_GND_PRESS", "BARO3_GND_PRESS",  # barometer ground reference, re-measured every boot
    "COMPASS_DEC",  # magnetic declination, auto-set from GPS once a fix is available (COMPASS_AUTODEC)
    # gyro bias calibration + the temperature it was taken at, redone every boot while stationary
    "INS_GYROFFS_X", "INS_GYROFFS_Y", "INS_GYROFFS_Z", "INS_GYR1_CALTEMP",
    "INS_GYR2OFFS_X", "INS_GYR2OFFS_Y", "INS_GYR2OFFS_Z", "INS_GYR2_CALTEMP",
    "INS_GYR3OFFS_X", "INS_GYR3OFFS_Y", "INS_GYR3OFFS_Z", "INS_GYR3_CALTEMP",
    # telemetry stream rates set by REQUEST_DATA_STREAM: on this firmware they are not persisted to EEPROM
    "SR0_RAW_SENS", "SR0_EXT_STAT", "SR0_RC_CHAN", "SR0_RAW_CTRL", "SR0_POSITION", "SR0_EXTRA1", "SR0_EXTRA2", "SR0_EXTRA3",
}


def connect(port, baud=115200, key=None):
    m = mavutil.mavlink_connection(port, baud=baud, source_system=255, source_component=190)
    if key is not None:
        # accept unsigned replies: a USB link is exempt from signing on ArduPilot, and pymavlink would otherwise drop them silently
        m.setup_signing(key, sign_outgoing=True, allow_unsigned_callback=lambda mav, msgid: True)
    hb = None
    t0 = time.time()
    while time.time() - t0 < 15 and hb is None:
        m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
        x = m.recv_match(type="HEARTBEAT", blocking=True, timeout=1)
        if x is not None and x.get_srcSystem() == 1 and x.get_srcComponent() == 1:
            hb = x
    if hb is None:
        sys.exit("no heartbeat from the flight controller (is the bridge stopped? is signing on and the key missing?)")
    if hb.base_mode & 128:
        sys.exit("vehicle is ARMED - refusing to continue")
    return m, hb


def get_params(m, timeout=120):
    """Full parameter table {name: (value, type)}: bulk download, then per-index re-requests until complete."""
    got, total = {}, None
    m.mav.param_request_list_send(1, 1)
    end = time.time() + timeout
    last = time.time()
    while time.time() < end:
        x = m.recv_match(type="PARAM_VALUE", blocking=True, timeout=1.0)
        if x is None:
            if total and len(got) >= total:
                break
            if time.time() - last > 3 and total:
                missing = sorted(set(range(total)) - {i for i, _ in got.values()})
                for i in missing[:50]:
                    m.mav.param_request_read_send(1, 1, b"", i)
                    time.sleep(0.02)
                last = time.time()
            continue
        total = x.param_count
        got[x.param_id.rstrip("\x00")] = (x.param_index, (x.param_value, x.param_type))
        last = time.time()
        if len(got) >= total and len({i for i, _ in got.values()}) >= total:
            break
    if not total or len(got) < total:
        sys.exit(f"incomplete parameter download: {len(got)}/{total}")
    return {k: v[1] for k, v in got.items()}


MISSION_FIELDS = ("seq", "frame", "command", "current", "autocontinue", "param1", "param2", "param3", "param4", "x", "y", "z", "mission_type")


def get_mission(m):
    m.mav.mission_request_list_send(1, 1)
    c = m.recv_match(type="MISSION_COUNT", blocking=True, timeout=8)
    if c is None:
        sys.exit("no MISSION_COUNT")
    items = []
    for seq in range(c.count):
        for _attempt in range(5):
            m.mav.mission_request_int_send(1, 1, seq)
            x = m.recv_match(type="MISSION_ITEM_INT", blocking=True, timeout=3)
            if x is not None and x.seq == seq:
                items.append({k: getattr(x, k) for k in MISSION_FIELDS})
                break
        else:
            sys.exit(f"mission item {seq} not received")
    m.mav.mission_ack_send(1, 1, 0, 0)
    return items


def put_mission(m, items):
    m.mav.mission_count_send(1, 1, len(items), 0)
    sent = set()
    end = time.time() + 30
    while len(sent) < len(items) and time.time() < end:
        r = m.recv_match(type=["MISSION_REQUEST_INT", "MISSION_REQUEST"], blocking=True, timeout=3)
        if r is None:
            continue
        i = items[r.seq]
        m.mav.mission_item_int_send(1, 1, i["seq"], i["frame"], i["command"], i["current"], i["autocontinue"],
                                    i["param1"], i["param2"], i["param3"], i["param4"], i["x"], i["y"], i["z"], i["mission_type"])
        sent.add(r.seq)
    a = m.recv_match(type="MISSION_ACK", blocking=True, timeout=8)
    return a is not None and a.type == 0


def write_snapshot(outdir, params, mission, hb, version):
    os.makedirs(outdir, exist_ok=True)
    json.dump({k: list(v) for k, v in sorted(params.items())}, open(os.path.join(outdir, "params.json"), "w"), indent=0)
    with open(os.path.join(outdir, "params.param"), "w", newline="\n") as f:  # Mission Planner / QGC loadable
        for k, (v, _t) in sorted(params.items()):
            f.write(f"{k},{v:.9g}\n")
    json.dump(mission, open(os.path.join(outdir, "mission.json"), "w"), indent=1)
    with open(os.path.join(outdir, "mission.waypoints"), "w", newline="\n") as f:  # QGC WPL 110, Mission Planner loadable
        f.write("QGC WPL 110\n")
        for i in mission:
            f.write(f"{i['seq']}\t{i['current']}\t{i['frame']}\t{i['command']}\t{i['param1']}\t{i['param2']}\t{i['param3']}\t{i['param4']}"
                    f"\t{i['x'] / 1e7:.8f}\t{i['y'] / 1e7:.8f}\t{i['z']}\t{i['autocontinue']}\n")
    meta = {"taken": time.strftime("%Y-%m-%d %H:%M:%S"), "params": len(params), "mission_items": len(mission),
            "custom_mode": hb.custom_mode, "base_mode": hb.base_mode, "autopilot_version": version}
    json.dump(meta, open(os.path.join(outdir, "manifest.json"), "w"), indent=1)
    return meta


def load_snapshot(d):
    p = {k: tuple(v) for k, v in json.load(open(os.path.join(d, "params.json"))).items()}
    return p, json.load(open(os.path.join(d, "mission.json"))), json.load(open(os.path.join(d, "manifest.json")))


def diff_params(snap, cur):
    changed = {k: (snap[k][0], cur[k][0]) for k in snap
               if k in cur and k not in VOLATILE and abs(snap[k][0] - cur[k][0]) > 1e-6 * max(1.0, abs(snap[k][0]))}
    missing = [k for k in snap if k not in cur]
    new = [k for k in cur if k not in snap]
    return changed, missing, new
