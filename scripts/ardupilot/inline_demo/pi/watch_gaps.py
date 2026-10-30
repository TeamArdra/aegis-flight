# ruff: noqa  (bench script: quick one-off driver, not library code)
"""Observer on the hub (5802): log arrival time of every vehicle HEARTBEAT, report outages > 1.5 s."""

import json
import sys
import time

from pymavlink import mavutil

m = mavutil.mavlink_connection("tcp:127.0.0.1:5802", source_system=254, source_component=1)
dur = float(sys.argv[1])
out = sys.argv[2]
ts = []
msgs = 0
end = time.time() + dur
while time.time() < end:
    msg = m.recv_match(blocking=True, timeout=0.5)
    if msg is None:
        continue
    msgs += 1
    if msg.get_type() == "HEARTBEAT" and msg.get_srcSystem() == 1 and msg.get_srcComponent() == 1:
        ts.append(time.time())
gaps = [(round(a - ts[0], 1), round(b - a, 1)) for a, b in zip(ts, ts[1:]) if b - a > 1.5]
json.dump({"heartbeats": len(ts), "msgs": msgs, "gaps_at_s_len_s": gaps}, open(out, "w"))
print("watch done", len(ts), "heartbeats", msgs, "msgs gaps", gaps, flush=True)
