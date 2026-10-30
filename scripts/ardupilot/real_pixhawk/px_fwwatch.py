# ruff: noqa  (bench script: quick one-off driver against a real, DISARMED, prop-less flight controller; not library code)
import os, sys, time
os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil
m = mavutil.mavlink_connection("tcp:127.0.0.1:5802", source_system=254, source_component=1)
t0 = time.time(); hits = []
while time.time() - t0 < float(sys.argv[1]):
    x = m.recv_match(type="STATUSTEXT", blocking=True, timeout=0.5)
    if x is not None and str(x.text).startswith("AEGIS"):
        hits.append((round(time.time() - t0, 1), x.text)); print(f"{hits[-1][0]:6.1f}  {x.text}", flush=True)
