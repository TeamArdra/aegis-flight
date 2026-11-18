"""GCS-side flood: an untrusted sysid sends heartbeats as fast as it can for N seconds through the hub."""

import os
import sys
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil

secs = float(sys.argv[1])
rate = float(sys.argv[2])
a = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=66, source_component=190)
n = 0
t0 = time.time()
while time.time() - t0 < secs:
    a.mav.heartbeat_send(
        mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0
    )
    n += 1
    if n % 40 == 0:
        while a.recv_match(blocking=False) is not None:
            pass
    nxt = t0 + n / rate
    if nxt > time.time():
        time.sleep(nxt - time.time())
print(
    f"flood sent {n} frames in {time.time() - t0:.1f}s ({n / (time.time() - t0):.0f}/s)", flush=True
)
