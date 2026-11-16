# ruff: noqa  (bench script: quick one-off driver against a real, DISARMED, prop-less flight controller; not library code)
"""Minimal, focused probe: request streams, bias GLOBAL_POSITION_INT.alt by +40 m through px_fc_proxy for 20 s, watch
for TELEMETRY_MANIPULATION. Used to isolate whether the signed-link detection gap (campaign batch 6) is caused by the
link type itself or by something else, with one variable (signing) changed between two otherwise-identical runs.
usage: px_altbias_probe.py HOST:PORT PI_KEY PI_HOST PROXY_PORT LABEL"""
import collections
import subprocess
import sys
import time

sys.path.insert(0, ".")
import os

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil

hub_addr, ssh_key, pi_host, proxy_port, label = sys.argv[1:6]
m = mavutil.mavlink_connection(f"tcp:{hub_addr}", source_system=255, source_component=190)
t0 = time.time()
hb = None
while time.time() - t0 < 15 and hb is None:
    m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
    x = m.recv_match(type="HEARTBEAT", blocking=True, timeout=1)
    if x is not None and x.get_srcSystem() == 1:
        hb = x
print(f"[{label}] heartbeat ok, armed={bool(hb.base_mode & 128) if hb else None}", flush=True)
for sid, hz in ((mavutil.mavlink.MAV_DATA_STREAM_POSITION, 2), (mavutil.mavlink.MAV_DATA_STREAM_EXTENDED_STATUS, 1)):
    m.mav.request_data_stream_send(1, 1, sid, hz, 1)
    time.sleep(0.3)

subprocess.run(["ssh", "-i", ssh_key, "-o", "BatchMode=yes", pi_host,
                f"~/aegis_test/venv/bin/python ~/aegis_test/scripts/ardupilot/real_pixhawk/px_proxy_ctl.py {proxy_port} alt_bias 40"],
               check=False, timeout=20, capture_output=True)
print(f"[{label}] alt_bias on", flush=True)

texts = []
alts = []
t0 = time.time()
last_hb = 0.0
while time.time() - t0 < 20:
    if time.time() - last_hb >= 1:
        m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
        last_hb = time.time()
    x = m.recv_match(blocking=True, timeout=0.3)
    if x is None:
        continue
    if x.get_type() == "STATUSTEXT" and str(x.text).startswith("AEGIS"):
        texts.append((round(time.time() - t0, 1), x.text))
        print(f"[{label}] {round(time.time() - t0, 1):5.1f}  {x.text}", flush=True)
    elif x.get_type() == "GLOBAL_POSITION_INT" and x.get_srcSystem() == 1:
        alts.append(x.alt / 1000.0)

subprocess.run(["ssh", "-i", ssh_key, "-o", "BatchMode=yes", pi_host,
                f"~/aegis_test/venv/bin/python ~/aegis_test/scripts/ardupilot/real_pixhawk/px_proxy_ctl.py {proxy_port} off"],
               check=False, timeout=20, capture_output=True)
print(f"[{label}] alt_bias off; altitudes seen (first 3 / last 3): {alts[:3]} / {alts[-3:]}", flush=True)
print(f"[{label}] RESULT: {len(texts)} AEGIS texts, kinds: {collections.Counter(t for _, t in texts)}", flush=True)
