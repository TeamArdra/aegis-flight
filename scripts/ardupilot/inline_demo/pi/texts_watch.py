"""Log every AEGIS STATUSTEXT (and vehicle mode/altitude) seen on the GCS side with times. usage: texts_watch.py <secs> <out.json>"""

import json
import os
import sys
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil

m = mavutil.mavlink_connection("tcp:127.0.0.1:5802", source_system=254, source_component=1)
secs, out = float(sys.argv[1]), sys.argv[2]
t0 = time.time()
texts = []
modes = []
alts = []
mode = None
while time.time() - t0 < secs:
    x = m.recv_match(blocking=True, timeout=0.5)
    if x is None:
        continue
    t = x.get_type()
    if t == "STATUSTEXT" and x.text.startswith("AEGIS"):
        texts.append((round(time.time() - t0, 1), x.text))
    elif (
        t == "HEARTBEAT"
        and x.get_srcSystem() == 1
        and x.get_srcComponent() == 1
        and x.custom_mode != mode
    ):
        mode = x.custom_mode
        modes.append((round(time.time() - t0, 1), mode))
    elif t == "GLOBAL_POSITION_INT":
        alts.append((round(time.time() - t0), round(x.relative_alt / 1000.0, 1)))
json.dump({"t0": t0, "texts": texts, "modes": modes, "alt_samples": alts[::5]}, open(out, "w"))
print("texts_watch done", len(texts), "texts", flush=True)
