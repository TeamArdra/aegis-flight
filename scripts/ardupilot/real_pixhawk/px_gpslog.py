"""Read-only-ish GPS capture: GCS heartbeat + standard stream requests, logs position/GPS/EKF messages as JSON lines. usage: px_gpslog.py PORT SECS OUT RATE_HZ"""

import json
import sys
import time

import serial
from pymavlink.dialects.v20 import ardupilotmega as mav

port, secs, out, rate = sys.argv[1], float(sys.argv[2]), sys.argv[3], int(sys.argv[4])
s = serial.Serial(port, 115200, timeout=0.05)
tx = mav.MAVLink(None, srcSystem=255, srcComponent=190)
rx = mav.MAVLink(None)
rx.robust_parsing = True


def send(msg):
    s.write(msg.pack(tx))
    tx.seq = (tx.seq + 1) % 256


WANT = {
    "GLOBAL_POSITION_INT",
    "GPS_RAW_INT",
    "EKF_STATUS_REPORT",
    "ATTITUDE",
    "VIBRATION",
    "HEARTBEAT",
    "GPS2_RAW",
    "SYS_STATUS",
}
f = open(out, "w")
t0 = time.time()
nexthb = t0
reqs = [t0 + 2, t0 + 30]
cnt = {}
while time.time() - t0 < secs:
    now = time.time()
    if now >= nexthb:
        send(tx.heartbeat_encode(mav.MAV_TYPE_GCS, mav.MAV_AUTOPILOT_INVALID, 0, 0, 0))
        nexthb += 1
    if reqs and now >= reqs[0]:
        reqs.pop(0)
        for st in (1, 2, 3, 6, 10, 11, 12):
            send(tx.request_data_stream_encode(1, 1, st, rate, 1))
    for b in s.read(2048):
        r = rx.parse_char(bytes([b]))
        if r is None:
            continue
        n = r.get_type()
        if n in WANT and r.get_srcSystem() == 1:
            d = r.to_dict()
            d["_t"] = round(time.time() - t0, 3)
            f.write(json.dumps(d) + "\n")
            cnt[n] = cnt.get(n, 0) + 1
f.close()
print("captured", cnt)
