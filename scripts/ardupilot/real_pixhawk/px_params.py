import os
import time

os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil

m = mavutil.mavlink_connection("tcp:127.0.0.1:5801", source_system=255, source_component=190)
seen = set()
total = [None]
state = {"hb": 0}


def pump(sec):
    end = time.time() + sec
    while time.time() < end:
        if time.time() - state["hb"] >= 1:
            m.mav.heartbeat_send(6, 8, 0, 0, 0)
            state["hb"] = time.time()
        x = m.recv_match(type="PARAM_VALUE", blocking=True, timeout=0.3)
        if x is not None and x.get_srcSystem() == 1:
            total[0] = x.param_count
            seen.add(x.param_index)


t0 = time.time()
m.mav.param_request_list_send(1, 1)
pump(60)
first = len(seen)
print(f"bulk download: {first}/{total[0]} in {time.time() - t0:.0f}s", flush=True)
rounds = 0
while total[0] and len(seen) < total[0] and rounds < 6:
    rounds += 1
    missing = sorted(set(range(total[0])) - seen)
    for i in missing[:150]:
        m.mav.param_request_read_send(1, 1, b"", i)
        pump(0.25)
    pump(2)
    print(
        f"  retry round {rounds}: {len(seen)}/{total[0]} after {time.time() - t0:.0f}s", flush=True
    )
print(
    "FINAL",
    len(seen),
    "/",
    total[0],
    "complete" if total[0] and len(seen) >= total[0] else "incomplete",
)
