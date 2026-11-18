"""Compare a flight controller with a snapshot (px_snapshot.py) and, with --apply, put it back: the differing parameters, the
mission, the snapshot's flight mode, and (with --disable-signing + the key in force) MAVLink signing switched off.
usage: px_restore.py PORT SNAPSHOT_DIR [--apply] [--key KEYFILE] [--disable-signing]
Without --apply it only prints the differences. Never touches an armed vehicle."""

import sys
import time

from px_common import connect, diff_params, get_mission, get_params, load_snapshot, put_mission

port, snap_dir = sys.argv[1], sys.argv[2]
apply_ = "--apply" in sys.argv
key = (
    bytes.fromhex(open(sys.argv[sys.argv.index("--key") + 1]).read().strip())
    if "--key" in sys.argv
    else None
)
snap_p, snap_m, meta = load_snapshot(snap_dir)
m, hb = connect(port, key=key)
if "--disable-signing" in sys.argv:
    if key is None:
        sys.exit("--disable-signing needs --key (the key currently set in the vehicle)")
    if apply_:
        m.mav.setup_signing_send(1, 1, [0] * 32, 0)
        time.sleep(1.5)
        print("sent SETUP_SIGNING with a zero key (signing off)")
        m.mav.signing.sign_outgoing = False
cur = get_params(m)
changed, missing, new = diff_params(snap_p, cur)
cur_m = get_mission(m)
mission_same = cur_m == snap_m
print(f"snapshot {meta['taken']}: {meta['params']} params, {meta['mission_items']} mission items")
print(
    f"parameters changed: {len(changed)}  missing now: {len(missing)}  new since snapshot: {len(new)}  "
    f"mission identical: {mission_same}  mode now {hb.custom_mode} (snapshot {meta['custom_mode']})"
)
for k, (a, b) in list(changed.items())[:30]:
    print(f"   {k}: snapshot {a} -> now {b}")
if not apply_:
    print("dry run: nothing changed (use --apply to restore)")
    sys.exit(0)
for k, (a, _) in changed.items():
    m.mav.param_set_send(1, 1, k.encode(), a, snap_p[k][1])
    time.sleep(0.15)
if not mission_same:
    print("mission restore:", "ok" if put_mission(m, snap_m) else "FAILED")
if hb.custom_mode != meta["custom_mode"]:
    m.mav.command_long_send(1, 1, 176, 0, 1, meta["custom_mode"], 0, 0, 0, 0, 0)
time.sleep(1)
cur2 = get_params(m)
ch2, miss2, _ = diff_params(snap_p, cur2)
same_m = get_mission(m) == snap_m
print(
    f"AFTER restore: parameters changed {len(ch2)}  missing {len(miss2)}  mission identical {same_m}"
)
print(
    "RESTORED (listed parameters and mission only; hidden parameters such as SCR_USER1..6 are not covered)"
    if not ch2 and not miss2 and same_m
    else "NOT FULLY RESTORED: " + str(list(ch2)[:10])
)
