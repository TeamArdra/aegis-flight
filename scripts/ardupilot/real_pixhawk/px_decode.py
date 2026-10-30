# ruff: noqa  (bench script: quick one-off driver against a real, DISARMED, prop-less flight controller; not library code)
"""Read-only: capture raw bytes from a serial port for N seconds, then decode with the full ArduPilot dialect. usage: px_decode.py PORT SECS OUTFILE"""
import sys, time, collections, serial
from pymavlink.dialects.v20 import ardupilotmega as mav

port, secs, out = sys.argv[1], float(sys.argv[2]), sys.argv[3]
s = serial.Serial(port, 115200, timeout=0.2)
buf = bytearray(); t0 = time.time()
while time.time() - t0 < secs:
    buf += s.read(4096)
open(out, "wb").write(bytes(buf))
m = mav.MAVLink(None); m.robust_parsing = True
types = collections.Counter(); bad = 0; badbytes = 0; good = 0; goodbytes = 0; srcs = collections.Counter()
for msg in m.parse_buffer(bytes(buf)) or []:
    pass
# parse_buffer returns messages only in some versions; use a byte-wise pass with sizes for accounting
m = mav.MAVLink(None); m.robust_parsing = True
prev_total = 0
for b in buf:
    r = m.parse_char(bytes([b]))
    if r is None:
        continue
    n = r.get_type()
    sz = len(r.get_msgbuf())
    if n == "BAD_DATA":
        bad += 1; badbytes += sz
    else:
        good += 1; goodbytes += sz; types[n] += 1; srcs[(r.get_srcSystem(), r.get_srcComponent())] += 1
print(f"raw bytes {len(buf)} in {secs:.0f}s  | decoded frames {good} ({goodbytes} B)  | bad-data runs {bad} ({badbytes} B) | other/unaccounted {len(buf)-goodbytes-badbytes} B")
print("by type:", dict(types.most_common(15)))
print("by source:", dict(srcs))
