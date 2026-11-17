"""Benign GCS soak through the radio hub: 1 Hz heartbeat, stream requests every 5 min, counts, heartbeat gaps, AEGIS texts per minute. usage: px_soak.py SECS OUT.json"""

import collections
import json
import os
import sys
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil

secs, out = float(sys.argv[1]), sys.argv[2]
m = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=255, source_component=190)
t0 = time.time()
hb_t = 0
req_t = 0
last_veh = None
gaps = []
per_min = collections.defaultdict(collections.Counter)
texts = collections.Counter()
modes = []
armed_seen = False
rx = 0
while time.time() - t0 < secs:
    now = time.time()
    if now - hb_t >= 1:
        m.mav.heartbeat_send(6, 8, 0, 0, 0)
        hb_t = now
    if now - req_t >= 300:
        for st in (2, 6, 10, 12):
            m.mav.request_data_stream_send(1, 1, st, 1, 1)
        req_t = now
    x = m.recv_match(blocking=True, timeout=0.3)
    if x is None or x.get_type() == "BAD_DATA":
        continue
    rx += 1
    mn = int((now - t0) // 60)
    per_min[mn][x.get_type()] += 1
    if x.get_srcSystem() == 1 and x.get_srcComponent() == 1 and x.get_type() == "HEARTBEAT":
        if last_veh is not None and now - last_veh > 3:
            gaps.append((round(now - t0), round(now - last_veh, 1)))
        last_veh = now
        armed_seen |= bool(x.base_mode & 128)
        if not modes or modes[-1][1] != x.custom_mode:
            modes.append((round(now - t0), x.custom_mode))
    if x.get_type() == "STATUSTEXT" and str(x.text).startswith("AEGIS"):
        texts[x.text.split(" ")[1] if " " in x.text else x.text] += 1
tot = collections.Counter()
for c in per_min.values():
    tot.update(c)
res = {
    "secs": secs,
    "rx_frames": rx,
    "heartbeat_gaps_over_3s": gaps,
    "armed_ever": armed_seen,
    "mode_changes": modes,
    "aegis_text_kinds": dict(texts),
    "frames_per_minute": [sum(per_min[k].values()) for k in sorted(per_min)],
    "totals": dict(tot.most_common(14)),
}
json.dump(res, open(out, "w"))
print(json.dumps(res)[:1500])
