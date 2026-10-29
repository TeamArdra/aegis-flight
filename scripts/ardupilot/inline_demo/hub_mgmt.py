"""Loopback 'radio' hub with a byte meter for the in-band management channel test.

  bridge (client) --5800--> hub --5801--> GCS clients (read/write: pilot, attacker)
                                  --5802--> observers (read-only copy of the downlink)
                                  --5803--> read/write ground-dashboard clients (`aegis serve` must TRANSMIT control)
Every second one JSON line is appended to $HUB_STATS: downlink bytes of the management stream (sysid 1 / compid 191)
separately from all other downlink bytes, and the same for the uplink (management = COMMAND_LONG MAV_CMD_USER_1).
Loopback only.  usage: HUB_STATS=<file> [HUB_TAP=<uplink capture>] python hub_mgmt.py
"""
import json
import os
import selectors
import socket
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil  # noqa: E402

TAP = open(os.environ["HUB_TAP"], "ab") if os.environ.get("HUB_TAP") else None
STATS = open(os.environ["HUB_STATS"], "a") if os.environ.get("HUB_STATS") else None
sel = selectors.DefaultSelector()
bridge = None
lists = {"gcs": [], "obs": [], "dash": []}
parsers = {}
acc = {"down_cross": 0, "down_mgmt": 0, "down_other": 0, "down_mgmt_frames": 0, "up_mgmt": 0, "up_other": 0, "up_mgmt_frames": 0}


def listen(port, tag):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(8)
    s.setblocking(False)
    sel.register(s, selectors.EVENT_READ, ("listen", tag))


def drop(sock):
    global bridge
    try:
        sel.unregister(sock)
    except Exception:
        pass
    sock.close()
    for lst in lists.values():
        if sock in lst:
            lst.remove(sock)
    parsers.pop(sock, None)
    if sock is bridge:
        bridge = None


def meter(sock, data, down):
    p = parsers.setdefault(sock, mavutil.mavlink.MAVLink(None))
    p.robust_parsing = True
    for b in data:
        m = p.parse_char(bytes([b]))
        if m is None:
            continue
        n = len(m.get_msgbuf())
        if down:
            if m.get_srcSystem() == 1 and m.get_srcComponent() == 191:
                if m.get_type() == "MEMORY_VECT" and m.address == 0xAE15:  # cross-end summary: outside the budget
                    acc["down_cross"] += n
                    continue
                acc["down_mgmt"] += n
                acc["down_mgmt_frames"] += 1
            else:
                acc["down_other"] += n
        elif m.get_type() == "COMMAND_LONG" and m.command == 31010:
            acc["up_mgmt"] += n
            acc["up_mgmt_frames"] += 1
        else:
            acc["up_other"] += n


for port, tag in ((5800, "bridge"), (5801, "gcs"), (5802, "obs"), (5803, "dash")):
    listen(port, tag)
print("hub up", flush=True)
nxt = time.time() + 1
while True:
    for key, _ in sel.select(timeout=0.5):
        kind, tag = key.data
        sock = key.fileobj
        if kind == "listen":
            c, _a = sock.accept()
            c.setblocking(False)
            sel.register(c, selectors.EVENT_READ, ("conn", tag))
            if tag == "bridge":
                bridge = c
            else:
                lists[tag].append(c)
            print("accepted", tag, flush=True)
            continue
        try:
            data = sock.recv(65536)
        except OSError:
            data = b""
        if not data:
            drop(sock)
            continue
        if tag == "bridge":
            meter(sock, data, True)
            for c in lists["gcs"] + lists["obs"] + lists["dash"]:
                try:
                    c.sendall(data)
                except OSError:
                    drop(c)
        elif tag in ("gcs", "dash") and bridge is not None:
            meter(sock, data, False)
            if TAP is not None:
                TAP.write(data)
                TAP.flush()
            try:
                bridge.sendall(data)
            except OSError:
                drop(bridge)
        # observers are read-only
    if time.time() >= nxt:
        nxt += 1
        if STATS:
            STATS.write(json.dumps({"t": round(time.time(), 1), **acc}) + "\n")
            STATS.flush()
        for k in acc:
            acc[k] = 0
