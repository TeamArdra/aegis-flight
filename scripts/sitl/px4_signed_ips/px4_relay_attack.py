"""Downlink attack relay between PX4 SITL and the shim (SITL, link-level). Runs until SIGTERM.

    python px4_relay_attack.py --px4-port 18570 --listen-port 18670 --onset-s 90 --duration-s 40 \
        --rate-ms 4 --bearing-deg 45 --frames-log /h/drift.frames.jsonl --stats /h/drift.stats.json

--attack gnss uses GnssDegradationAttack instead (GPS_RAW_INT fix_type/satellites rewritten to 0/2 for --duration-s).
Uses the repo's PositionDriftAttack through MavlinkRelay (the same hook as scripts/sitl/run_p2_trial.py); the onset is
measured from the first vehicle frame the hook sees. Ground truth is written by the hook itself.
"""

from __future__ import annotations

import argparse
import json
import signal
import threading

from aegisflight.proxy import (
    FrameLogWriter,
    GnssDegradationAttack,
    GnssDegradationParams,
    PositionDriftAttack,
)
from aegisflight.proxy.attacks_live import PositionDriftParams
from aegisflight.proxy.transport import make_udp_relay

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument("--attack", choices=("drift", "gnss"), default="drift")
ap.add_argument("--px4-port", type=int, default=18570)
ap.add_argument("--listen-port", type=int, default=18670)
ap.add_argument("--onset-s", type=float, default=90.0)
ap.add_argument("--duration-s", type=float, default=40.0)
ap.add_argument("--rate-ms", type=float, default=4.0)
ap.add_argument("--bearing-deg", type=float, default=45.0)
ap.add_argument("--frames-log", required=True)
ap.add_argument("--stats", required=True)
a = ap.parse_args()

log = FrameLogWriter(a.frames_log)
if a.attack == "gnss":
    attack = GnssDegradationAttack(
        GnssDegradationParams(1, 0, a.onset_s, a.duration_s, 0, 2), frame_log=log
    )
else:
    attack = PositionDriftAttack(
        PositionDriftParams(1, 0, a.onset_s, a.duration_s, a.rate_ms, a.bearing_deg), frame_log=log
    )
relay = make_udp_relay("127.0.0.1", a.px4_port, a.listen_port, down_hook=attack)
relay.start()
stop = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop.set())
signal.signal(signal.SIGINT, lambda *_: stop.set())
stop.wait()
relay.close()
log.close()
json.dump(
    {
        "frames_seen": attack.frames_seen,
        "frames_modified": attack.frames_modified,
        "frames_dropped": attack.frames_dropped,
        "relay": relay.stats,
    },
    open(a.stats, "w"),
    indent=1,
)
