import collections
import sys
import time

import serial
from pymavlink import mavutil

port = sys.argv[1]
secs = float(sys.argv[2])
s = serial.Serial(port, 115200, timeout=0.2)
m = mavutil.mavlink.MAVLink(None)
m.robust_parsing = True
counts = collections.Counter()
first = {}
srcs = set()
signed = 0
total = 0
raw = 0
t0 = time.time()
while time.time() - t0 < secs:
    b = s.read(4096)
    raw += len(b)
    for byte in b:
        try:
            msg = m.parse_char(bytes([byte]))
        except Exception:
            continue
        if msg is None:
            continue
        total += 1
        n = msg.get_type()
        counts[n] += 1
        first.setdefault(n, msg)
        srcs.add((msg.get_srcSystem(), msg.get_srcComponent()))
        mb = msg.get_msgbuf()
        signed += mb[0] == 0xFD and bool(mb[2] & 1)
        counts["v2" if mb[0] == 0xFD else "v1"] += 1
print("bytes", raw, "frames", total, "signed", signed, "sources", sorted(srcs))
print(dict(counts.most_common(20)))
hb = first.get("HEARTBEAT")
if hb:
    print("HEARTBEAT", hb.to_dict())
for k in ("SYS_STATUS", "AUTOPILOT_VERSION", "STATUSTEXT", "GPS_RAW_INT", "ATTITUDE"):
    if k in first:
        print(k, first[k].to_dict())
