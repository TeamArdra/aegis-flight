"""READ-ONLY snapshot of a flight controller's state: every parameter, the mission, firmware version, flight mode.
usage: px_snapshot.py PORT OUTDIR [--key KEYFILE]      (run where the FC's USB port is; stop the bridge first)
Writes params.json / params.param (Mission Planner loadable) / mission.json / mission.waypoints / manifest.json."""

import sys

from px_common import connect, get_mission, get_params, write_snapshot

port, outdir = sys.argv[1], sys.argv[2]
key = (
    bytes.fromhex(open(sys.argv[sys.argv.index("--key") + 1]).read().strip())
    if "--key" in sys.argv
    else None
)
m, hb = connect(port, key=key)
m.mav.command_long_send(1, 1, 512, 0, 148, 0, 0, 0, 0, 0, 0)
v = m.recv_match(type="AUTOPILOT_VERSION", blocking=True, timeout=6)
version = (
    None
    if v is None
    else {"flight_sw_version": v.flight_sw_version, "board_version": v.board_version, "uid": v.uid}
)
params = get_params(m)
mission = get_mission(m)
meta = write_snapshot(outdir, params, mission, hb, version)
print("snapshot written to", outdir, meta)
