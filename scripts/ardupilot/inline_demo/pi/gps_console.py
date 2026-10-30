# ruff: noqa  (bench script: quick one-off driver, not library code)
"""Holds SITL SERIAL0 (5760) like holder.py and writes the GPS fault when the flag file appears. usage: gps_console.py <label>"""

import os, sys, time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil

label = sys.argv[1]
flag = f"C:/afsitl/gps_fault_{label}.flag"
c = mavutil.mavlink_connection("tcp:127.0.0.1:5760", source_system=254, source_component=190)
c.wait_heartbeat(timeout=60)
print("console up", flush=True)
while True:
    c.recv_match(blocking=True, timeout=0.5)
    if os.path.exists(flag):
        os.remove(flag)
        c.param_set_send("SIM_GPS1_GLTCH_X", 0.001)
        print("FAULT written", round(time.time()), flush=True)
