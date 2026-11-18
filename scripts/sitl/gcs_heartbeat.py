"""Benign GCS for the issue #25 bridge evidence run: 1 Hz HEARTBEAT plus a one-off data-stream request.

Connects to a loopback hub (``scripts/ardupilot/inline_demo/hub.py`` GCS port 5801) so traffic flows both ways through
``aegis ips-bridge``. Sends nothing that changes the vehicle's state (no arm, no mode change, no parameter write).
Exits 1 if no vehicle HEARTBEAT was received.

    python gcs_heartbeat.py --url tcp:127.0.0.1:5801 --seconds 80
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="tcp:127.0.0.1:5801")
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--rate-hz", type=int, default=4, help="requested telemetry rate for REQUEST_DATA_STREAM(ALL)")
    a = ap.parse_args(argv)

    from pymavlink import mavutil

    m = mavutil.mavlink_connection(a.url, source_system=255, source_component=190, autoreconnect=True)
    rx: Counter[str] = Counter()
    sent = 0
    vehicle: tuple[int, int] | None = None
    end = time.monotonic() + a.seconds
    next_hb = 0.0
    while time.monotonic() < end:
        now = time.monotonic()
        if now >= next_hb:
            m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
            sent += 1
            next_hb = now + 1.0
        msg = m.recv_match(blocking=True, timeout=0.2)
        if msg is None or msg.get_type() == "BAD_DATA":
            continue
        rx[msg.get_type()] += 1
        if vehicle is None and msg.get_type() == "HEARTBEAT" and msg.get_srcComponent() == 1:
            vehicle = (msg.get_srcSystem(), msg.get_srcComponent())
            m.mav.request_data_stream_send(vehicle[0], vehicle[1], mavutil.mavlink.MAV_DATA_STREAM_ALL, a.rate_hz, 1)
            sent += 1
    m.close()
    print(json.dumps({"vehicle": vehicle, "sent": sent, "rx_total": sum(rx.values()), "rx": dict(rx.most_common())}))
    return 0 if vehicle is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
