"""Signed GCS pilot + optional compound attacker for the PX4 SITL inline-bridge test. [SITL, command-path]

    python pilot_px4.py --key /h/gcs.key --scenario signing --out /h/pilot_signing_active.json
    python pilot_px4.py --key /h/gcs.key --scenario gps     --out /h/pilot_gps_active.json

This process is the TCP *server* on 127.0.0.1:5800; `aegis onboard` connects to it as the GCS-side client, and to
PX4 through `udp_tcp_shim.py`. Everything the pilot sends is MAVLink-2 signed with --key. Flight: arm, takeoff to
--alt metres, DO_REPOSITION one leg, hold (PX4 reports AUTO_LOITER).

scenario `signing`: stages of attacker frames written onto the same GCS stream, each followed by a mode check and a
bridge-counter delta (GET /status on --status-url):
  unsigned_sys66      forged DO_SET_MODE(AUTO_LAND), NAV_LAND and SET_MODE from sysid 66, unsigned
  unsigned_sys255     the same from sysid 255 (impersonates the GCS), plus NAV_RETURN_TO_LAUNCH, unsigned
  wrong_key_sys255    DO_SET_MODE(AUTO_LAND) from 255 signed with a wrong key
  replay_signed       a byte-identical replay of the pilot's own signed DO_SET_MODE(AUTO_RTL), sent after the pilot
                      switched back to AUTO_LOITER
  flood               unsigned HEARTBEAT flood from sysid 77 (--flood-hz for --flood-s)
Between stages the pilot restores AUTO_LOITER with a signed DO_SET_MODE, so one run measures every stage even when
an attack lands the vehicle (the passive control).
scenario `gps`: no attacker frames; a downlink position-drift relay (px4_relay_attack.py) sits between PX4 and the
shim; the pilot records the mode timeline for --observe-s after it is airborne (marker file --ready-file).

Writes --out as JSON: baseline mode, per-stage results, mode timeline, bridge status samples.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import struct
import sys
import threading
import time
import urllib.request

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402
from pymavlink.dialects.v20 import common as c2  # noqa: E402

MAIN = {1: "MANUAL", 2: "ALTCTL", 3: "POSCTL", 4: "AUTO", 5: "ACRO", 6: "OFFBOARD", 7: "STABILIZED"}
SUB = {1: "READY", 2: "TAKEOFF", 3: "LOITER", 4: "MISSION", 5: "RTL", 6: "LAND"}
MODE_PARAMS = {"AUTO_LOITER": (4, 3), "AUTO_LAND": (4, 6), "AUTO_RTL": (4, 5), "ALTCTL": (2, 0)}

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument("--key", required=True)
ap.add_argument("--scenario", choices=("signing", "gps"), required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--port", type=int, default=5800)
ap.add_argument("--alt", type=float, default=20.0)
ap.add_argument("--status-url", default="http://127.0.0.1:8090/status")
ap.add_argument("--flood-hz", type=int, default=2000)
ap.add_argument("--flood-s", type=float, default=8.0)
ap.add_argument("--observe-s", type=float, default=45.0)
ap.add_argument("--ready-file", default="/h/READY_FOR_FAULT")
ap.add_argument(
    "--manual-control",
    action="store_true",
    help="stream signed MANUAL_CONTROL at 10 Hz (PX4 refuses manual modes such as ALTCTL without a manual source)",
)
a = ap.parse_args()

key = open(a.key, "rb").read()
m = mavutil.mavlink_connection(f"tcpin:127.0.0.1:{a.port}", source_system=255, source_component=190)
m.mav.WIRE_PROTOCOL_VERSION = "2.0"
m.setup_signing(key, sign_outgoing=True, allow_unsigned_callback=lambda *x: True, link_id=1)
wlock = threading.Lock()
sent: list[bytes] = []
_orig_write = m.write


def _write(buf):
    with wlock:
        sent.append(bytes(buf))
        _orig_write(buf)


m.write = _write
t0 = time.time()
st = {
    "hb": None,
    "pos": None,
    "ack": {},
    "last_hb": 0.0,
    "mode": None,
    "armed": False,
    "target": (1, 1),
}
timeline: list[dict] = []
status_samples: list[dict] = []
rx = {"n": 0, "statustext": []}


def mode_name(cm: int) -> str:
    main, sub = (cm >> 16) & 0xFF, (cm >> 24) & 0xFF
    return MAIN.get(main, str(main)) + (("_" + SUB.get(sub, str(sub))) if main == 4 else "")


def status() -> dict:
    try:
        return json.load(urllib.request.urlopen(a.status_url, timeout=2))
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def policy() -> dict:
    p = status().get("policy") or {}
    return {k: v for k, v in p.items() if isinstance(v, int) and not isinstance(v, bool)}


def pump(timeout=0.05):
    now = time.time()
    if now - st["last_hb"] >= 1.0:
        m.mav.heartbeat_send(
            mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0
        )
        st["last_hb"] = now
    if a.manual_control and now - st.get("last_mc", 0) >= 0.1:
        m.mav.manual_control_send(1, 0, 0, 500, 0, 0)
        st["last_mc"] = now
    while True:
        msg = m.recv_match(blocking=True, timeout=timeout)
        timeout = 0
        if msg is None:
            return
        rx["n"] += 1
        t = msg.get_type()
        if (
            t == "HEARTBEAT"
            and msg.get_srcComponent() == 1
            and msg.type != mavutil.mavlink.MAV_TYPE_GCS
        ):
            st["hb"] = msg
            st["target"] = (msg.get_srcSystem(), msg.get_srcComponent())
            name = mode_name(msg.custom_mode)
            st["armed"] = bool(msg.base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED)
            if name != st["mode"]:
                timeline.append(
                    {"t": round(time.time() - t0, 2), "mode": name, "armed": st["armed"]}
                )
                st["mode"] = name
        elif t == "COMMAND_ACK":
            st["ack"][msg.command] = msg.result
        elif t == "GLOBAL_POSITION_INT":
            st["pos"] = {
                "lat": msg.lat / 1e7,
                "lon": msg.lon / 1e7,
                "alt": msg.alt / 1e3,
                "rel": msg.relative_alt / 1e3,
            }
        elif t == "STATUSTEXT":
            rx["statustext"].append({"t": round(time.time() - t0, 1), "text": msg.text})


def wait(s):
    e = time.time() + s
    while time.time() < e:
        pump()


def cmd(c, *p, retries=1):
    p = tuple(p) + (0.0,) * (7 - len(p))
    m.mav.command_long_send(st["target"][0], st["target"][1], c, 0, *p)
    e = time.time() + 5
    while time.time() < e:
        pump(0.1)
        if c in st["ack"]:
            return st["ack"].pop(c)
    return None


def set_mode(name):
    main, sub = MODE_PARAMS[name]
    return cmd(mavutil.mavlink.MAV_CMD_DO_SET_MODE, 1, main, sub)


def await_mode(want, secs):
    e = time.time() + secs
    while time.time() < e:
        pump()
        if st["mode"] == want:
            return True
    return st["mode"] == want


def restore():
    for _ in range(3):
        if st["mode"] == "AUTO_LOITER":
            return True
        set_mode("AUTO_LOITER")
        if await_mode("AUTO_LOITER", 3):
            return True
    return False


# ---- raw writers for attacker frames on the same stream
class _W:
    def write(self, b):
        with wlock:
            m.port.sendall(bytes(b))


def attacker(sysid, comp=1, signed_key=None):
    mav = c2.MAVLink(_W(), srcSystem=sysid, srcComponent=comp)
    mav.WIRE_PROTOCOL_VERSION = "2.0"
    if signed_key is not None:
        mav.signing.secret_key = signed_key
        mav.signing.sign_outgoing = True
        mav.signing.link_id = 1
        mav.signing.timestamp = int((time.time() - 1420070400) * 1e5)
    return mav


def forged_modes(mav, extra_rtl=False):
    ts, tc = st["target"]
    for _ in range(3):
        mav.command_long_send(ts, tc, 176, 0, 1, 4, 6, 0, 0, 0, 0)  # DO_SET_MODE AUTO_LAND
        mav.set_mode_send(ts, 1, (4 << 16) | (6 << 24))  # SET_MODE msg: AUTO_LAND
        mav.command_long_send(ts, tc, 21, 0, 0, 0, 0, 0, 0, 0, 0)  # NAV_LAND
        if extra_rtl:
            mav.command_long_send(ts, tc, 20, 0, 0, 0, 0, 0, 0, 0, 0)  # NAV_RETURN_TO_LAUNCH
        time.sleep(0.4)


def find_signed_set_mode(name):
    main, sub = MODE_PARAMS[name]
    for b in sent:
        if len(b) > 40 and b[0] == 0xFD and b[2] & 1 and b[7:10] == bytes([76, 0, 0]):
            p = struct.unpack("<7f", b[10:38])
            cmdid = struct.unpack("<H", b[38:40])[0]
            if cmdid == 176 and p[1] == main and p[2] == sub:
                return b
    return None


stages: list[dict] = []


def stage(name, fn):
    before = policy()
    mode_before = st["mode"]
    n_tl = len(timeline)
    fn()
    wait(3)
    after = policy()
    delta = {k: after[k] - before.get(k, 0) for k in after if after[k] != before.get(k, 0)}
    rec = {
        "stage": name,
        "mode_before": mode_before,
        "mode_after": st["mode"],
        "modes_seen": [e["mode"] for e in timeline[n_tl:]],
        "armed": st["armed"],
        "rel_alt_m": round(st["pos"]["rel"], 1) if st["pos"] else None,
        "bridge_policy_delta": delta,
    }
    stages.append(rec)
    print("STAGE", json.dumps(rec), flush=True)
    rec["restored"] = restore()


def sampler():
    while True:
        s = status()
        status_samples.append(
            {
                "t": round(time.time() - t0, 1),
                "analyser": s.get("analyser"),
                "policy": s.get("policy"),
                "mode": s.get("mode"),
                "state": s.get("state"),
            }
        )
        time.sleep(2)


# ---------------- flight
ev: dict = {"scenario": a.scenario}
while (st["hb"] is None or st["pos"] is None) and time.time() - t0 < 120:
    pump()
if st["hb"] is None or st["pos"] is None:
    print("NO HB/POS")
    json.dump({"error": "no heartbeat/position through the bridge"}, open(a.out, "w"))
    sys.exit(2)
ev["vehicle"] = {"sysid": st["target"][0], "autopilot": st["hb"].autopilot, "type": st["hb"].type}
home = dict(st["pos"])
threading.Thread(target=sampler, daemon=True).start()
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
    ev["error"] = f"arm rejected {res}"
    json.dump({**ev, "timeline": timeline}, open(a.out, "w"), indent=1)
    sys.exit(3)
tgt = home["alt"] + a.alt
ev["takeoff_ack"] = cmd(
    mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, math.nan, 0, 0, math.nan, math.nan, math.nan, tgt
)
e = time.time() + 60
while time.time() < e and (st["pos"] is None or st["pos"]["alt"] < tgt - 2):
    pump()
lat = home["lat"] + 40 / 111320.0
cmd(mavutil.mavlink.MAV_CMD_DO_REPOSITION, -1, 1, 0, math.nan, lat, home["lon"], tgt)
wait(8)
ev["baseline_mode"] = st["mode"]
ev["baseline_rel_alt_m"] = round(st["pos"]["rel"], 1)
print("AIRBORNE mode", st["mode"], "alt", ev["baseline_rel_alt_m"], flush=True)

if a.scenario == "signing":
    unsigned66 = attacker(66)
    unsigned255 = attacker(255, 190)
    stage("unsigned_sys66", lambda: forged_modes(unsigned66))
    stage("unsigned_sys255", lambda: forged_modes(unsigned255, extra_rtl=True))
    stage("wrong_key_sys255", lambda: forged_modes(attacker(255, 190, signed_key=os.urandom(32))))
    # replay: legit signed AUTO_RTL, pilot goes back to AUTO_LOITER, then the captured bytes are replayed
    set_mode("AUTO_RTL")
    await_mode("AUTO_RTL", 3)
    restore()
    captured = find_signed_set_mode("AUTO_RTL")
    ev["replay_frame_captured"] = captured is not None

    def replay():
        if captured is None:
            return
        for _ in range(3):
            with wlock:
                m.port.sendall(captured)
            time.sleep(0.5)

    stage("replay_signed", replay)

    def flood():
        f = attacker(77, 1)
        end = time.time() + a.flood_s
        n = 0
        while time.time() < end:
            t1 = time.time()
            for _ in range(max(1, a.flood_hz // 100)):
                f.heartbeat_send(2, 3, 0, 0, 0)
                n += 1
            time.sleep(max(0.0, 0.01 - (time.time() - t1)))
        ev["flood_frames_sent"] = n

    stage("flood", flood)
    # legit control after the attacks: a signed mode change must still go through
    set_mode("AUTO_RTL")
    ev["legit_after_attack_reached_RTL"] = await_mode("AUTO_RTL", 4)
    restore()
else:
    open(a.ready_file, "w").write(str(time.time()))
    print("READY_FOR_FAULT", flush=True)
    t_fault = (
        time.time()
    )  # the drift relay (px4_relay_attack.py) starts its own onset clock; see its frames log
    end = t_fault + a.observe_s
    while time.time() < end:
        pump()
    ev["observe_s"] = a.observe_s
    ev["rel_alt_end_m"] = round(st["pos"]["rel"], 1)
    ev["t_fault"] = round(t_fault - t0, 2)

ev["end_mode"] = st["mode"]
ev["stages"] = stages
ev["timeline"] = timeline
ev["statustext"] = rx["statustext"][-40:]
ev["status_final"] = status()
ev["status_samples"] = status_samples[-5:]
ev["rx_frames"] = rx["n"]
ev["sent_frames"] = len(sent)
cmd(mavutil.mavlink.MAV_CMD_NAV_LAND, 0, 0, 0, math.nan, math.nan, math.nan, home["alt"])
e = time.time() + 60
while time.time() < e and st["armed"]:
    pump()
ev["landed_disarmed"] = not st["armed"]
json.dump(ev, open(a.out, "w"), indent=1, default=str)
print("DONE", flush=True)
