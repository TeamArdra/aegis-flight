"""Plain GCS (no bridge, unsigned): arm, take off, then DO_SET_MODE ALTCTL; print ACKs, HEARTBEAT mode, STATUSTEXT."""

import os
import time

from pymavlink import mavutil

MC = os.environ.get("MC") == "1"  # stream MANUAL_CONTROL like a joystick/RC

m = mavutil.mavlink_connection("udpout:127.0.0.1:18570", source_system=255, source_component=190)
t0 = time.time()
last = [None]


def pump(sec, tag):
    end = time.time() + sec
    nxt = 0
    while time.time() < end:
        if time.time() >= nxt:
            m.mav.heartbeat_send(6, 8, 0, 0, 0)
            nxt = time.time() + 1
        if MC:
            m.mav.manual_control_send(1, 0, 0, 500, 0, 0)
        x = m.recv_match(blocking=True, timeout=0.1)
        if x is None:
            continue
        t = x.get_type()
        if t == "HEARTBEAT" and x.get_srcSystem() == 1 and x.type == 2:
            k = ((x.custom_mode >> 16) & 255, (x.custom_mode >> 24) & 255, bool(x.base_mode & 128))
            if k != last[0]:
                last[0] = k
                print(f"{time.time() - t0:6.1f} HB main={k[0]} sub={k[1]} armed={k[2]}", flush=True)
        elif t == "COMMAND_ACK":
            print(f"{time.time() - t0:6.1f} ACK cmd={x.command} result={x.result}", flush=True)
        elif t == "STATUSTEXT":
            print(f"{time.time() - t0:6.1f} TEXT {x.text}", flush=True)


for _ in range(20):
    m.mav.heartbeat_send(6, 8, 0, 0, 0)
    pump(0.5, "hb")
m.wait_heartbeat(timeout=10)
ts, tc = 1, 1
m.mav.command_long_send(ts, tc, 400, 0, 1, 0, 0, 0, 0, 0, 0)
pump(3, "arm")
m.mav.command_long_send(ts, tc, 22, 0, 0, 0, 0, float("nan"), float("nan"), float("nan"), 20)
pump(25, "takeoff")
print("--- send DO_SET_MODE ALTCTL", flush=True)
m.mav.command_long_send(ts, tc, 176, 0, 1, 2, 0, 0, 0, 0, 0)
pump(8, "altctl")
print("--- send SET_MODE msg ALTCTL", flush=True)
m.mav.set_mode_send(ts, 1, 2 << 16)
pump(5, "setmode")
print("--- restore AUTO_LOITER + land", flush=True)
m.mav.command_long_send(ts, tc, 21, 0, 0, 0, 0, float("nan"), float("nan"), float("nan"), 0)
pump(5, "land")
