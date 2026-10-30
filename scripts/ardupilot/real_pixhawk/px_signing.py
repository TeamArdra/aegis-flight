# ruff: noqa  (bench script: quick one-off driver against a real, DISARMED, prop-less flight controller; not library code)
"""Switch MAVLink-2 signing ON or OFF in the flight controller (SETUP_SIGNING). REVERSIBLE: 'off' sends a zero key, signed with the key in force.
usage: px_signing.py PORT on  KEYFILE          (key = 64 hex chars; the vehicle is unsigned before)
       px_signing.py PORT off KEYFILE          (the key currently in the vehicle)
       px_signing.py PORT check [KEYFILE]      (does an UNSIGNED parameter read work? with a key: does a SIGNED one?)"""
import sys
import time

from px_common import connect, mavutil

port, op = sys.argv[1], sys.argv[2]
key = bytes.fromhex(open(sys.argv[3]).read().strip()) if len(sys.argv) > 3 else None
now10us = int((time.time() - 1420070400) * 100000)
if op == "on":
    m, hb = connect(port)
    m.mav.setup_signing_send(1, 1, list(key), now10us - 60_000_000)  # floor 10 minutes in the past: clock skew between signers must not lock us out
    time.sleep(1.5)
    print("SETUP_SIGNING sent")
elif op == "off":
    # connect WITHOUT the key: with a key pymavlink drops the vehicle's unsigned replies (a USB link is exempt from signing on ArduPilot)
    m, hb = connect(port)
    m.mav.setup_signing_send(1, 1, [0] * 32, 0)
    time.sleep(1.5)
    print("zero key sent: signing off (verified below: with no key active a SIGNED request is accepted again, too)")
checks = [("UNSIGNED", None)] + ([("SIGNED", key)] if key is not None and op in ("on", "off", "check") else [])
for label, k in checks:
    mm = mavutil.mavlink_connection(port, baud=115200, source_system=255, source_component=190)
    if k is not None:
        mm.setup_signing(k, sign_outgoing=True, allow_unsigned_callback=lambda mav, msgid: True, initial_timestamp=now10us + 5000)
    ok = None
    for _ in range(3):
        mm.mav.param_request_read_send(1, 1, b"SYSID_THISMAV", -1)
        ok = mm.recv_match(type="PARAM_VALUE", blocking=True, timeout=3)
        if ok is not None:
            break
    print(f"{label} parameter read: {'ANSWERED' if ok is not None else 'no answer (rejected)'}")
