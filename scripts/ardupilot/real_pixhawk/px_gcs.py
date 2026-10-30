# ruff: noqa  (bench script: quick one-off driver against a real, DISARMED, prop-less flight controller; not library code)
"""Benign GCS on the ground radio: 1 Hz heartbeat (sysid 255) + low-rate REQUEST_DATA_STREAM, decodes what comes back. usage: px_gcs.py PORT SECS"""
import sys, time, collections, serial
from pymavlink.dialects.v20 import ardupilotmega as mav
port, secs = sys.argv[1], float(sys.argv[2])
s = serial.Serial(port, 115200, timeout=0.05)
tx = mav.MAVLink(None, srcSystem=255, srcComponent=190)
rx = mav.MAVLink(None); rx.robust_parsing = True
types = collections.Counter(); srcs = collections.Counter(); sent = collections.Counter(); first = {}
t0 = time.time(); nexthb = t0; req_at = [t0 + 3, t0 + 20]
while time.time() - t0 < secs:
    now = time.time()
    if now >= nexthb:
        s.write(tx.heartbeat_encode(mav.MAV_TYPE_GCS, mav.MAV_AUTOPILOT_INVALID, 0, 0, 0).pack(tx)); sent["HEARTBEAT"] += 1; nexthb += 1
    if req_at and now >= req_at[0]:
        req_at.pop(0)
        for stream in (2, 6, 10):  # EXTENDED_STATUS, POSITION, EXTRA1 (attitude), 1 Hz each
            s.write(tx.request_data_stream_encode(1, 1, stream, 1, 1).pack(tx)); sent["REQUEST_DATA_STREAM"] += 1
    for b in s.read(2048):
        r = rx.parse_char(bytes([b]))
        if r is not None and r.get_type() != "BAD_DATA":
            n = r.get_type(); types[n] += 1; srcs[(r.get_srcSystem(), r.get_srcComponent())] += 1; first.setdefault(n, r)
print("sent:", dict(sent)); print("received by type:", dict(types.most_common(20))); print("by source:", dict(srcs))
for k in ("SYS_STATUS", "ATTITUDE", "GPS_RAW_INT", "STATUSTEXT"):
    if k in first: print(k, {a: v for a, v in first[k].to_dict().items() if a != "mavpackettype"})
