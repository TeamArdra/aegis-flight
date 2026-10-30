"""Driver for the SITL validation of the in-band management channel (see run_mgmt.sh and docs/MGMT_CHANNEL.md).

usage: mgmt_drive.py <label> <on|off>
Runs after the pilot (fly_unsigned.py) has reached GUIDED flight.  `on`: tests a, b, c, d, e, g (the bridge starts in
`passive`; the ground `aegis serve` on hub port 5803 transmits the signed commands).  `off`: only the nominal window and the
forged-LAND burst in active-ips, with the management channel disabled on the bridge (reference for test f).
Everything is loopback.  Keys live in C:/afsitl and are never printed.  Writes C:/afsitl/mdrive_<label>.json.
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

from aegisflight.hal.mgmt_channel import OP_STATUS_NOW, build_command_frame, verify_audit_log  # noqa: E402

LABEL, VARIANT = sys.argv[1], sys.argv[2]
D = Path("C:/afsitl")
GCS, BRIDGE = "http://127.0.0.1:8104", "http://127.0.0.1:8090"
KEY, WRONG = (D / "mgmt.key").read_bytes(), (D / "wrongmgmt.key").read_bytes()
TOKEN = (D / "ctl.token").read_text().strip()
CFG = Path(__file__).resolve().parents[3] / "configs" / "ardupilot_copter"
HUB, FC, AUDIT, LOCK = (D / f"mhub_{LABEL}.jsonl", D / f"mfc_{LABEL}.json", D / f"maudit_{LABEL}.jsonl",
                        D / f"mlock_{LABEL}.flag")
R: dict = {"variant": VARIANT}
# PI_SSH=user@host (+ PI_KEY): the bridge runs on a Raspberry Pi (run_mgmt_pi.sh); its lock-posture file and audit log
# live in ~/aegis_runs/<label>/ there
PI = os.environ.get("PI_SSH")
PI_RUN = f"~/aegis_runs/{LABEL}"


def pi_run(cmd: str) -> None:
    subprocess.run(["ssh", "-i", os.environ.get("PI_KEY", ""), "-o", "BatchMode=yes", PI, cmd], check=False, timeout=30)


def set_lock(on: bool) -> None:
    if PI:
        pi_run(f"touch {PI_RUN}/lock.flag" if on else f"rm -f {PI_RUN}/lock.flag")
    elif on:
        LOCK.write_text("lock")
    else:
        LOCK.unlink()


def fetch_audit() -> None:
    if PI:
        subprocess.run(["scp", "-i", os.environ.get("PI_KEY", ""), "-o", "BatchMode=yes", f"{PI}:{PI_RUN}/audit.jsonl", str(AUDIT)],
                       check=False, capture_output=True, timeout=30)



def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def get(url):
    try:
        return json.load(urllib.request.urlopen(url, timeout=4))
    except Exception as exc:  # noqa: BLE001
        return {"_error": str(exc)}


def post(url, body, headers=None):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json", **(headers or {})})
    try:
        return json.load(urllib.request.urlopen(req, timeout=4))
    except urllib.error.HTTPError as exc:
        return {"_http": exc.code, **json.loads(exc.read() or b"{}")}
    except Exception as exc:  # noqa: BLE001
        return {"_error": str(exc)}


def remote():
    return get(f"{GCS}/api/status").get("bridge_remote") or {}


def bridge():
    return get(f"{BRIDGE}/status")


def fc():
    try:
        return json.loads(FC.read_text())
    except Exception:  # noqa: BLE001
        return {}


def hub_window(t0, t1):
    rows = []
    for line in HUB.read_text().splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if t0 <= r["t"] <= t1:
            rows.append(r)
    n = max(1, len(rows))
    out = {"seconds": len(rows)}
    for k in ("down_mgmt", "down_cross", "down_other", "down_mgmt_frames", "up_mgmt", "up_mgmt_frames"):
        out[k + "_total"] = sum(r[k] for r in rows)
        out[k + "_avg_per_s"] = round(sum(r[k] for r in rows) / n, 1)
        out[k + "_max_1s"] = max([r[k] for r in rows] or [0])
    return out


def wait(pred, timeout, step=0.25):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(step)
    return None


def recent_text(sub, since):
    for e in remote().get("recent") or []:
        if e["t"] >= since and sub in e["text"]:
            return e
    return None


def posture_via_gcs(mode, allow_unsigned=True, confirm=False):
    t0 = time.time()
    resp = post(f"{GCS}/api/bridge/posture", {"mode": mode, "allow_unsigned": allow_unsigned, "confirm": confirm})
    end = time.time() + 6
    cmd = None
    while time.time() < end:
        cmd = remote().get("last_command")
        if cmd and cmd["result"] != "pending" and cmd["age_s"] < time.time() - t0 + 0.5:
            break
        time.sleep(0.2)
    return {"http": resp, "last_command": cmd, "answer_s": round(time.time() - t0, 2)}


def attack(secs, hz, sysid=66):
    a = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=sysid, source_component=190)
    end = time.time() + secs
    n = 0
    while time.time() < end:
        a.mav.command_long_send(1, 1, 176, 0, 1, 9, 0, 0, 0, 0, 0)
        a.mav.set_mode_send(1, 1, 9)
        n += 2
        time.sleep(1.0 / hz)
    a.close()
    return n


def ext_cmds(frames, listen_s=2.5, gap=0.05):
    """Send raw frames from a separate ground client on hub port 5803; return the ACKs (from 1/191) that came back."""
    c = mavutil.mavlink_connection("tcp:127.0.0.1:5803", source_system=254, source_component=190)
    time.sleep(0.3)
    acks = []
    for fr in frames:
        c.write(fr)
        time.sleep(gap)
    end = time.time() + listen_s
    while time.time() < end:
        m = c.recv_match(type="COMMAND_ACK", blocking=True, timeout=0.2)
        if m is not None and m.get_srcSystem() == 1 and m.get_srcComponent() == 191 and m.command == 31010:
            acks.append({"result": m.result, "rp2": getattr(m, "result_param2", None)})
    c.close()
    return acks


def kill_serve():
    ps = ("Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'serve --port 8104' -and "
          "$_.ProcessId -ne $PID -and $_.Name -notmatch 'powershell' } | "
          "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }")
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=False)


def start_serve():
    cmd = ["C:/afvenv/Scripts/aegis.exe", "serve", "--port", "8104", "--source", "serial", "--serial-port",
           "socket://127.0.0.1:5803", "--allow-url", "--baud", "115200", "--config-dir", str(CFG), "--db",
           f"C:/afsitl/mgcs2_{LABEL}.sqlite", "--mgmt-key-file", "C:/afsitl/mgmt.key"]
    subprocess.Popen(cmd, stdout=open(D / f"mserve2_{LABEL}.log", "w"), stderr=subprocess.STDOUT)


def events_summary():
    ev = get(f"{GCS}/api/events")
    rows = ev if isinstance(ev, list) else ev.get("events", [])
    kinds: dict = {}
    for e in rows:
        k = f"{e.get('attack_type') or e.get('type') or '?'}/{e.get('severity', '?')}"
        kinds[k] = kinds.get(k, 0) + 1
    return {"n": len(rows), "kinds": kinds}


def nominal():
    t0 = time.time()
    ages = []
    while time.time() - t0 < 25:
        ages.append(remote().get("age_s"))
        time.sleep(1)
    t1 = time.time()
    b = bridge()
    b.pop("policy", None)
    R["nominal"] = {"hub": hub_window(t0 + 2, t1), "age_s_max": max([a for a in ages if a is not None] or [None]),
                    "age_s_samples": len(ages), "bridge_remote": remote(), "bridge": b,
                    "events": events_summary()}
    log("nominal", json.dumps(R["nominal"]["hub"]), R["nominal"]["age_s_max"])


def burst():
    b0, e0, f0 = bridge(), events_summary(), fc()
    t0 = time.time()
    n = attack(15, 20)
    time.sleep(3)
    t1 = time.time()
    b1 = bridge()
    R["burst"] = {"frames_sent": n, "hub": hub_window(t0, t1), "bridge_frames_before": b0.get("frames"),
                  "bridge_frames_after": b1.get("frames"), "events_before": e0, "events_after": events_summary(),
                  "fc_before": f0, "fc_after": fc()}
    log("burst", json.dumps(R["burst"]["hub"]))


def finish():
    R["fc_final"] = fc()
    R["bridge_final"] = bridge()
    R["bridge_final"].pop("policy", None)
    R["events_final"] = events_summary()
    R["hub_all"] = hub_window(0, time.time())
    (D / f"mdrive_{LABEL}.json").write_text(json.dumps(R, indent=1, default=str))


if VARIANT == "off":
    nominal()
    r = post(f"{BRIDGE}/posture", {"mode": "active-ips", "allow_unsigned": True}, {"X-Aegis-Token": TOKEN})
    R["raise_local"] = {"ok": bool(r.get("ok")), "resp_keys": sorted(r)}
    time.sleep(2)
    burst()
    finish()
    log("off variant done")
    sys.exit(0)

# ------------------------------------------------------------------------------------------------------------- on
nominal()

# (c) control from the ground: passive -> advisory -> active-ips with allow_unsigned
R["c_raise"] = [posture_via_gcs("advisory")]
time.sleep(1.3)
R["c_raise"].append(posture_via_gcs("active-ips"))
R["c_raise_bridge_mode"] = bridge().get("mode")
log("raise", json.dumps(R["c_raise"]), R["c_raise_bridge_mode"])

# lock-posture file blocks lowering
set_lock(True)
time.sleep(1.2)
R["c_lock_file_lower"] = posture_via_gcs("passive")
set_lock(False)
time.sleep(1.2)
R["c_lock_file_lower_bridge_mode"] = bridge().get("mode")
log("lockfile", json.dumps(R["c_lock_file_lower"]))

# (a) forged LAND from sysid 66, active-ips
b0 = bridge()
ta = time.time()
attack(3, 2.5)
e_alert = wait(lambda: recent_text("COMMAND_INJECTION", ta), 10)
e_block = wait(lambda: recent_text("blocked ", ta), 10)
time.sleep(3)
rem = remote()
R["a"] = {"alert": e_alert, "blocked": e_block,
          "alert_latency_s": round(e_alert["t"] - ta, 1) if e_alert else None,
          "blocked_latency_s": round(e_block["t"] - ta, 1) if e_block else None,
          "status_age_s": rem.get("age_s"), "posture": rem.get("posture"), "counters": rem.get("counters"),
          "flags": rem.get("flags"), "recent": rem.get("recent"),
          "bridge_dropped_up_before": (b0.get("frames") or {}).get("dropped_up"),
          "bridge_dropped_up_after": (bridge().get("frames") or {}).get("dropped_up")}
log("a", json.dumps({k: R["a"][k] for k in ("alert_latency_s", "blocked_latency_s", "status_age_s", "posture")}))

# (e) burst
burst()

# lowering active-ips -> passive needs the second confirm
r1 = posture_via_gcs("passive")
time.sleep(1.2)
r2 = posture_via_gcs("passive", confirm=True)
R["c_lower"] = {"first": r1, "confirm": r2, "bridge_mode": bridge().get("mode")}
log("lower", json.dumps(R["c_lower"]))

# (b) alerts in passive; nothing management-related may reach the FC
f0 = fc()
tb = time.time()
attack(3, 2.5)
eb = wait(lambda: recent_text("COMMAND_INJECTION", tb), 10)
time.sleep(3)
f1 = fc()
R["b"] = {"alert": eb, "posture": remote().get("posture"), "bridge_mode": bridge().get("mode"),
          "fc_by_src_before": f0.get("to_fc_by_src"), "fc_by_src_after": f1.get("to_fc_by_src"),
          "mgmt_to_fc": {k: f1.get(k, 0) - f0.get(k, 0) for k in
                         ("to_fc_from_1_191", "to_fc_user1_cmds", "to_fc_statustext", "to_fc_memory_vect")}}
log("b", json.dumps(R["b"]["mgmt_to_fc"]), bool(eb))

# (c) rate limit, wrong key, replay (external signed frames; the ground dashboard stays idle meanwhile)
time.sleep(1.5)
R["c_rate_limit_acks"] = ext_cmds([build_command_frame(KEY, OP_STATUS_NOW) for _ in range(3)], gap=0.05)
time.sleep(1.5)
R["c_wrong_key_acks"] = ext_cmds([build_command_frame(WRONG, OP_STATUS_NOW) for _ in range(3)], gap=0.2)
time.sleep(1.5)
good = build_command_frame(KEY, OP_STATUS_NOW)
R["c_valid_acks"] = ext_cmds([good])
time.sleep(1.5)
R["c_replay_of_valid_acks"] = ext_cmds([good])
log("ext", json.dumps({k: R[k] for k in R if k.startswith("c_") and k.endswith("acks")}))

# raise back to active-ips (needed for g)
time.sleep(1.5)
R["c_reraise"] = posture_via_gcs("active-ips")

# (c) lockout: 5 wrong-key frames, then a VALID command must be denied (locked)
time.sleep(1.2)
tl = time.time()
ext_cmds([build_command_frame(WRONG, OP_STATUS_NOW) for _ in range(5)], listen_s=0.5, gap=0.1)
R["c_lockout_announced"] = bool(wait(lambda: recent_text("LOCKED", tl), 8))
R["c_valid_during_lock_acks"] = ext_cmds([build_command_frame(KEY, OP_STATUS_NOW)])
t_lock = tl
log("lockout", R["c_lockout_announced"], R["c_valid_during_lock_acks"])

# (g) lose the management link (stop the ground dashboard); the bridge keeps its posture and keeps blocking
b0 = bridge()
kill_serve()
tg = time.time()
time.sleep(2)
attack(3, 2.5)
time.sleep(10)
bg = bridge()
R["g"] = {"serve_api_after_kill": get(f"{GCS}/api/status").get("_error", "still up?"), "bridge_mode": bg.get("mode"),
          "dropped_up_before": (b0.get("frames") or {}).get("dropped_up"),
          "dropped_up_after": (bg.get("frames") or {}).get("dropped_up"),
          "hub_during_outage": hub_window(tg + 2, time.time())}
start_serve()
wait(lambda: remote().get("present"), 40)
tr = time.time()
attack(3, 2.5)
e_re = wait(lambda: recent_text("AEGIS:", tr), 10)
time.sleep(2)
rem = remote()
R["g"]["after_restart"] = {"alert_seen": bool(e_re), "age_s": rem.get("age_s"), "posture": rem.get("posture"),
                           "bridge_mode": bridge().get("mode")}
log("g", json.dumps(R["g"]["after_restart"]), R["g"]["bridge_mode"])

# the lockout expires after 60 s: a valid command from the ground works again
wait(lambda: time.time() - t_lock > 62, 80, 1)
R["c_after_lock"] = posture_via_gcs("active-ips")
log("after lock", json.dumps(R["c_after_lock"]))

finish()
fetch_audit()
ok, n, detail = verify_audit_log(AUDIT)
R["d"] = {"verified": ok, "entries": n, "detail": detail}
ev: dict = {}
for line in AUDIT.read_text().splitlines():
    e = json.loads(line)
    k = e["event"] + ":" + str(e.get("result") or e.get("reason") or e.get("origin") or "")
    ev[k] = ev.get(k, 0) + 1
R["d"]["events"] = ev
(D / f"mdrive_{LABEL}.json").write_text(json.dumps(R, indent=1, default=str))
log("audit", json.dumps(R["d"]))
log("on variant done")
