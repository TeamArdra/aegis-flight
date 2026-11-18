"""Transparent TCP tap between `aegis ips-bridge` and the SITL flight controller (the 'FC side' of the bridge).

  bridge --5805--> fc_tap --5762--> ArduCopter SITL SERIAL1
Counts the frames the FC is sent (per sysid/compid/message, and MAV_CMD_USER_1 commands) and the frames it returns, and
writes the totals to $FC_TAP_OUT (JSON) every second.  Used to show that management frames never reach the FC.
Loopback only.
"""
import json
import os
import selectors
import socket
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

OUT = os.environ["FC_TAP_OUT"]
tot = {"to_fc_frames": 0, "to_fc_bytes": 0, "to_fc_from_1_191": 0, "to_fc_user1_cmds": 0, "to_fc_statustext": 0,
       "to_fc_memory_vect": 0, "to_fc_by_src": {}, "to_fc_1_191_types": {}, "from_fc_frames": 0}
sel = selectors.DefaultSelector()
pa, pb = mavutil.mavlink.MAVLink(None), mavutil.mavlink.MAVLink(None)
pa.robust_parsing = pb.robust_parsing = True
ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", 5805))
ls.listen(1)
b, _ = ls.accept()
f = socket.create_connection(("127.0.0.1", 5762))
b.setblocking(False)
f.setblocking(False)
sel.register(b, selectors.EVENT_READ, "b")
sel.register(f, selectors.EVENT_READ, "f")
nxt = time.time() + 1
while True:
    for key, _ in sel.select(timeout=0.5):
        s = key.fileobj
        try:
            data = s.recv(65536)
        except OSError:
            data = b""
        if not data:
            raise SystemExit(0)
        if key.data == "b":
            f.sendall(data)
            tot["to_fc_bytes"] += len(data)
            for x in data:
                m = pa.parse_char(bytes([x]))
                if m is None:
                    continue
                tot["to_fc_frames"] += 1
                src = f"{m.get_srcSystem()}/{m.get_srcComponent()}"
                tot["to_fc_by_src"][src] = tot["to_fc_by_src"].get(src, 0) + 1
                if src == "1/191":
                    tot["to_fc_from_1_191"] += 1
                    tot["to_fc_1_191_types"][m.get_type()] = tot["to_fc_1_191_types"].get(m.get_type(), 0) + 1
                t = m.get_type()
                if t == "COMMAND_LONG" and m.command == 31010:
                    tot["to_fc_user1_cmds"] += 1
                elif t == "STATUSTEXT" and str(m.text).startswith("AEGIS"):
                    tot["to_fc_statustext"] += 1
                elif t == "MEMORY_VECT":
                    tot["to_fc_memory_vect"] += 1
        else:
            b.sendall(data)
            for x in data:
                if pb.parse_char(bytes([x])) is not None:
                    tot["from_fc_frames"] += 1
    if time.time() >= nxt:
        nxt += 1
        with open(OUT, "w") as fh:
            json.dump(tot, fh)
