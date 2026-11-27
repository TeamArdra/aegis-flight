"""Put a DISARMED flight controller back into STABILIZE (the tests change its mode). Run it where the FC's USB serial port is
(the Pi, with the bridge stopped).  usage: px_restore_mode.py /dev/ttyACM0   -- refuses to touch an armed vehicle."""

import sys
import time

import serial
from pymavlink.dialects.v20 import ardupilotmega as mav


def mode_now(s, rx, sec):
    m = a = None
    end = time.time() + sec
    while time.time() < end:
        for b in s.read(1024):
            r = rx.parse_char(bytes([b]))
            if r is not None and r.get_type() == "HEARTBEAT" and r.get_srcSystem() == 1:
                m, a = r.custom_mode, bool(r.base_mode & 128)
    return m, a


def main(argv: list[str] | None = None, *, wait_sec: float = 4.0) -> None:
    args = sys.argv[1:] if argv is None else argv
    s = serial.Serial(args[0], 115200, timeout=0.2)
    rx = mav.MAVLink(None)
    rx.robust_parsing = True
    tx = mav.MAVLink(None, srcSystem=255, srcComponent=190)

    m, a = mode_now(s, rx, wait_sec)
    print("mode now", m, "armed", a)
    if m is None or a is None:
        sys.exit("NO HEARTBEAT - refusing to transmit")
    if a:
        sys.exit("ARMED - not touching it")
    if m != 0:
        s.write(tx.command_long_encode(1, 1, 176, 0, 1, 0, 0, 0, 0, 0, 0).pack(tx))
        print("sent DO_SET_MODE STABILIZE")
        print("mode after", mode_now(s, rx, wait_sec))


if __name__ == "__main__":
    main()
