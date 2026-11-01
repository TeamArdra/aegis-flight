# ruff: noqa  (bench script: quick one-off driver against a real, DISARMED, prop-less flight controller; not library code)
"""Pi-side relay for the flight controller's USB serial port, with an optional telemetry rewriter (an attacker on the FC-to-bridge link).

    FC (serial) <--> px_fc_proxy.py <--(tcp 5810)--> ips-bridge  (--fc-port socket://127.0.0.1:5810 --allow-url)

Everything is forwarded unchanged until a control line arrives on 127.0.0.1:5811 (one line, loopback only):
    off | alt_bias <metres> | batt_jump <volts> | freeze | heading <degrees>
Then the matching vehicle telemetry in the FC -> bridge direction is rewritten (re-encoded with the original sysid / compid / seq):
    alt_bias   GLOBAL_POSITION_INT.alt and relative_alt  += metres
    batt_jump  SYS_STATUS.voltage_battery                += volts
    freeze     ATTITUDE repeats the first frame seen after the command
    heading    VFR_HUD.heading                           += degrees (mod 360)
The bridge -> FC direction is never touched. Stats go to $PROXY_OUT once a second. usage: px_fc_proxy.py /dev/ttyACM0 [data_port]"""
import json
import os
import selectors
import socket
import sys
import time

os.environ["MAVLINK20"] = "1"
import serial
from pymavlink.dialects.v20 import ardupilotmega as mav

dev = sys.argv[1]
data_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5810
ctl_port = data_port + 1
OUT = os.environ.get("PROXY_OUT", "/tmp/px_proxy.json")
ser = serial.Serial(dev, 115200, timeout=0)
rd = mav.MAVLink(None)
rd.robust_parsing = True
enc = mav.MAVLink(None)
enc.robust_parsing = True
mode = {"kind": "off", "val": 0.0}
stats = {"rewritten": 0, "to_bridge_bytes": 0, "to_fc_bytes": 0, "mode": "off", "bridge_connects": 0}
frozen = {"att": None}


def rewrite(msg):
    k, v, t = mode["kind"], mode["val"], msg.get_type()
    if k == "alt_bias" and t == "GLOBAL_POSITION_INT":
        msg.alt += int(v * 1000)
        msg.relative_alt += int(v * 1000)
    elif k == "batt_jump" and t == "SYS_STATUS":
        msg.voltage_battery = max(0, min(65535, msg.voltage_battery + int(v * 1000)))
    elif k == "freeze" and t == "ATTITUDE":
        if frozen["att"] is None:
            frozen["att"] = (msg.roll, msg.pitch, msg.yaw, msg.rollspeed, msg.pitchspeed, msg.yawspeed)
        msg.roll, msg.pitch, msg.yaw, msg.rollspeed, msg.pitchspeed, msg.yawspeed = frozen["att"]
    elif k == "heading" and t == "VFR_HUD":
        msg.heading = int((msg.heading + v) % 360)
    else:
        return None
    enc.srcSystem, enc.srcComponent, enc.seq = msg.get_srcSystem(), msg.get_srcComponent(), msg.get_seq()
    stats["rewritten"] += 1
    return bytes(msg.pack(enc))


sel = selectors.DefaultSelector()


def listen(port, tag):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(4)
    s.setblocking(False)
    sel.register(s, selectors.EVENT_READ, tag)


listen(data_port, "bridge_in")
listen(ctl_port, "ctl")
sel.register(ser.fileno(), selectors.EVENT_READ, "fc")
bridge = None
last = 0.0
while True:
    for key, _ in sel.select(timeout=0.5):
        tag = key.data
        if tag == "bridge_in":
            if bridge is not None:
                sel.unregister(bridge)
                bridge.close()
            bridge, _a = key.fileobj.accept()
            bridge.setblocking(False)
            sel.register(bridge, selectors.EVENT_READ, "bridge")
            stats["bridge_connects"] += 1
        elif tag == "ctl":
            c, _a = key.fileobj.accept()
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
            data = ser.read(4096)
            if not data or bridge is None:
                continue
            if mode["kind"] == "off":
                out = data
            else:
                out = b""
                for m in rd.parse_buffer(data) or []:
                    out += rewrite(m) or bytes(m.get_msgbuf())
            try:
                bridge.sendall(out)
                stats["to_bridge_bytes"] += len(out)
            except OSError:
                pass
        elif tag == "bridge":
            try:
                data = key.fileobj.recv(65536)
            except OSError:
                data = b""
            if not data:
                sel.unregister(bridge)
                bridge.close()
                bridge = None
                continue
            ser.write(data)
            stats["to_fc_bytes"] += len(data)
    if time.time() - last > 1:
        last = time.time()
        with open(OUT, "w") as f:
            f.write(json.dumps(stats))
