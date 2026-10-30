# ruff: noqa  (bench script: quick one-off driver against a real, DISARMED, prop-less flight controller; not library code)
"""Signed-link attack sequence through the radio hub (tcp 5801) against a DISARMED, prop-less ArduCopter behind an ips-bridge that
enforces MAVLink-2 signing (--signing-key-file). The vehicle itself is the oracle: a forged command that changes its flight mode got
past the bridge. Never arms. usage: px_signed_attack.py KEYFILE [HOST:PORT]"""
import os
import socket
import sys
import time

from pymavlink.dialects.v20 import ardupilotmega as mav

key = bytes.fromhex(open(sys.argv[1]).read().strip())
addr = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1:5801"
host, port = addr.split(":")
sock = socket.create_connection((host, int(port)))
sock.settimeout(0.02)
wrong = os.urandom(32)
now10 = lambda: int((time.time() - 1420070400) * 100000)


def mk(sysid, comp, k=None, seq=0):
    m = mav.MAVLink(None, srcSystem=sysid, srcComponent=comp)
    m.seq = seq
    if k is not None:
        m.signing.secret_key = k
        m.signing.sign_outgoing = True
        m.signing.link_id = 0
        m.signing.timestamp = now10()
    return m


pilot, evil, spoof, wrongkey = mk(255, 190, key), mk(77, 1, None, 40), mk(255, 190, None, 100), mk(255, 190, wrong, 150)
rx = mav.MAVLink(None)
rx.robust_parsing = True
NAMES = {0: "STABILIZE", 2: "ALT_HOLD", 5: "LOITER", 6: "RTL", 9: "LAND", 4: "GUIDED", 3: "AUTO"}
T0 = time.time()
st = {"mode": None, "armed": None}
texts, acks, mode_log = [], [], []
next_hb = [T0]


def now():
    return round(time.time() - T0, 1)


def send(m, msg):
    raw = bytes(msg.pack(m))
    m.seq = (m.seq + 1) % 256
    if m.signing.sign_outgoing:
        m.signing.timestamp += 1
    sock.sendall(raw)
    return raw


def cmd(m, command, p1=0, p2=0):
    return m.command_long_encode(1, 1, command, 0, p1, p2, 0, 0, 0, 0, 0)


def poll(sec):
    end = time.time() + sec
    while time.time() < end:
        if time.time() >= next_hb[0]:
            send(pilot, pilot.heartbeat_encode(mav.MAV_TYPE_GCS, mav.MAV_AUTOPILOT_INVALID, 0, 0, 0))
            next_hb[0] += 1
        try:
            data = sock.recv(4096)
        except socket.timeout:
            data = b""
        for b in data:
            r = rx.parse_char(bytes([b]))
            if r is None or r.get_type() == "BAD_DATA":
                continue
            t = r.get_type()
            if t == "HEARTBEAT" and r.get_srcSystem() == 1 and r.get_srcComponent() == 1:
                if st["mode"] != r.custom_mode:
                    mode_log.append((now(), NAMES.get(r.custom_mode, r.custom_mode)))
                st["mode"], st["armed"] = r.custom_mode, bool(r.base_mode & 128)
                if st["armed"]:
                    raise SystemExit(f"ABORT: vehicle reports ARMED at t={now()}")
            elif t == "STATUSTEXT":
                texts.append((now(), r.text))
            elif t == "COMMAND_ACK":
                acks.append((now(), r.command, r.result))


mode_name = lambda: NAMES.get(st["mode"], st["mode"])
restore = lambda: send(pilot, cmd(pilot, 176, 1, 0))  # signed set STABILIZE
poll(3)
for stream in (2, 6, 10, 12):
    send(pilot, pilot.request_data_stream_encode(1, 1, stream, 1, 1))
poll(7)
if st["armed"] is None:
    raise SystemExit("no heartbeat from the vehicle")
print(f"start: mode {mode_name()} armed {st['armed']}")
events = []


def event(name, attack, wait=6):
    t_a = now()
    before = mode_name()
    attack()
    poll(wait)
    after = mode_name()
    restore()
    poll(6)
    leaked = after != before
    aegis = [x for t, x in texts if t >= t_a and str(x).startswith("AEGIS")]
    events.append({"event": name, "mode_before": before, "mode_after_attack": after, "restored": mode_name(), "leaked": leaked})
    print(f"{t_a:6.1f} {name:34s} mode {before}->{after} {'LEAKED to the vehicle' if leaked else 'held'} (restored {mode_name()}) acks={[(c, r) for t, c, r in acks if t >= t_a][:3]} AEGIS={sorted(set(aegis))[:3]}", flush=True)


cap = {}


def legit_signed_alt_hold():
    cap["raw"] = send(pilot, cmd(pilot, 176, 1, 2))


event("legit signed set ALT_HOLD (must pass)", legit_signed_alt_hold, 4)
event("unsigned forged LAND (sysid 77)", lambda: send(evil, cmd(evil, 21)))
event("unsigned RTL spoofing sysid 255", lambda: send(spoof, cmd(spoof, 20)))
event("wrong-key signed LAND spoofing 255", lambda: send(wrongkey, cmd(wrongkey, 21)))
event("unsigned forged LOITER (sysid 77)", lambda: send(evil, cmd(evil, 176, 1, 5)))
event("replay of the captured signed ALT_HOLD", lambda: sock.sendall(cap["raw"]))
event("unsigned force-disarm (sysid 77)", lambda: send(evil, cmd(evil, 400, 0, 21196)))


def flood():
    end = time.time() + 5
    n = 0
    while time.time() < end:
        send(evil, evil.heartbeat_encode(mav.MAV_TYPE_QUADROTOR, mav.MAV_AUTOPILOT_ARDUPILOTMEGA, 81, 0, 3))
        n += 1
        time.sleep(0.01)
    print("   flood frames written:", n)


event("unsigned heartbeat flood (sysid 77, 5 s)", flood)
poll(4)
bad = [e for e in events[1:] if e["leaked"]]
print("mode log:", mode_log)
print("RESULT: legit signed command", "PASSED" if events[0]["leaked"] else "did NOT pass", "| forged/replayed events that reached the vehicle:", len(bad), "of", len(events) - 1)
