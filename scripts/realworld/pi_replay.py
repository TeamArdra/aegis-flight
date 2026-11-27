"""Runs ON THE PI: a stand-in flight controller on a pty that replays the DOWNLINK of a recorded scenario at 1x and logs the uplink
the bridge delivers to it. Polls the bridge status API for alerts. Waits for /tmp/go before starting.

    python pi_replay.py scenario.pkl /tmp/fcpty result.json [status_port]
"""
from __future__ import annotations

import json
import os
import pickle
import select
import sys
import threading
import time
import tty
import urllib.request

sys.path.insert(0, os.path.expanduser("~/aegis-flight/src"))
from aegisflight.proxy.transport import split_frames  # noqa: E402

sc = pickle.load(open(sys.argv[1], "rb"))
link, outp = sys.argv[2], sys.argv[3]
port = int(sys.argv[4]) if len(sys.argv) > 4 else 8765
m, s = os.openpty()
tty.setraw(m)
tty.setraw(s)
if os.path.lexists(link):
    os.remove(link)
os.symlink(os.ttyname(s), link)
print("ready", link, flush=True)
while not os.path.exists("/tmp/go"):
    time.sleep(0.02)
frames = sc["frames"]
down = [(t, raw) for t, raw, d in frames if d == "down"]
inj = set(sc["inj_up"])
dur = frames[-1][0] + 3.0
alerts, stop = [], threading.Event()
t0 = time.monotonic()


def poll() -> None:
    last = 0
    while not stop.is_set():
        try:
            d = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=1))
            a = d["analyser"]
            if a["alerts"] > last:
                alerts.append({"t": round(time.monotonic() - t0, 2), "n": a["alerts"], "summary": a["summary"][:110]})
                last = a["alerts"]
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.4)


threading.Thread(target=poll, daemon=True).start()
rx_inj = rx_other = rx_bytes = 0
rx_frames: list = []
sent = 0
i = 0
while time.monotonic() - t0 < dur:
    now = time.monotonic() - t0
    while i < len(down) and down[i][0] <= now:
        os.write(m, down[i][1])
        sent += 1
        i += 1
    r_, _, _ = select.select([m], [], [], 0.002)
    if r_:
        data = os.read(m, 4096)
        rx_bytes += len(data)
        for f in split_frames(data)[0]:
            if f.raw in inj:
                rx_inj += 1
            else:
                rx_other += 1
            rx_frames.append((round(time.monotonic() - t0, 2), f.msgid))
stop.set()
final = {}
try:
    final = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=2))
except Exception as e:  # noqa: BLE001
    final = {"error": repr(e)}
fr = final.get("frames", {})
res = {"name": sc["name"], "attack": sc["attack"], "window": sc["window"], "fc_down_sent": sent, "down_total": len(down),
       "uplink_injected_total": len(inj), "uplink_injected_delivered": rx_inj, "uplink_other_delivered": rx_other,
       "alerts": alerts, "bridge_frames": fr, "latency_us": final.get("latency_us"), "analyser": final.get("analyser"),
       "mode": final.get("mode"), "state": final.get("state"), "late_end_s": round(time.monotonic() - t0 - dur, 2)}
json.dump(res, open(outp, "w"))
print("done", json.dumps({k: res[k] for k in ("name", "uplink_injected_delivered", "fc_down_sent")}), flush=True)
