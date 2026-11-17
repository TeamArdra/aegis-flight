"""Pi-side relay for the flight controller's USB serial port, with an optional telemetry rewriter (an attacker on the FC-to-bridge link).

    FC (serial) <--> px_fc_proxy.py <--(tcp 5810)--> ips-bridge  (--fc-port socket://127.0.0.1:5810 --allow-url)

Everything is forwarded unchanged until a control line arrives on 127.0.0.1:5811 (one line, loopback only):
    off | alt_bias <metres> | batt_jump <volts> | freeze | heading <degrees>
Then the matching vehicle telemetry in the FC -> bridge direction is rewritten (re-encoded with the original sysid / compid / seq):
    alt_bias   GLOBAL_POSITION_INT.alt and relative_alt  += metres
    batt_jump  SYS_STATUS.voltage_battery                += volts
    freeze     ATTITUDE repeats the first frame seen after the command
    heading    VFR_HUD.heading                           += degrees (mod 360)
The bridge -> FC direction is never touched. Stats go to $PROXY_OUT once a second. usage: px_fc_proxy.py /dev/ttyACM0 [data_port]

BENCH ONLY, props off, vehicle disarmed. This relay makes a real flight controller look like a socket:// (SITL-style)
link, which is exactly what the receive-only rule (AGENTS.md section 5) exists to prevent, so it carries its own guards:
* it refuses to start unless AEGIS_REAL_FC_BENCH=props-off-disarmed is set, and prints a banner;
* it relays NOTHING towards the flight controller until a heartbeat from the vehicle shows it disarmed;
* the moment a vehicle heartbeat shows it armed it stops relaying towards the FC and stops rewriting telemetry for the
  rest of the run (restart the proxy to re-enable), and records it in the stats.
Whether this tooling belongs in the repository at all is an open maintainer decision (PR #39 review, M3)."""

import json
import os
import selectors
import socket
import sys
import time

os.environ["MAVLINK20"] = "1"
from pymavlink.dialects.v20 import ardupilotmega as mav

OPT_IN_ENV, OPT_IN_VALUE = "AEGIS_REAL_FC_BENCH", "props-off-disarmed"
MAV_MODE_FLAG_SAFETY_ARMED = 128
NOT_THE_VEHICLE = (6, 18, 26, 27)  # MAV_TYPE GCS, onboard controller, gimbal, ADS-B


class ArmGate:
    """Relay towards the FC only after a disarmed vehicle heartbeat, and never again after an armed one."""

    def __init__(self) -> None:
        self.disarmed_seen = False
        self.armed_seen = False
        self.blocked_to_fc_bytes = 0

    def observe(self, msg) -> None:
        if msg.get_type() != "HEARTBEAT" or msg.type in NOT_THE_VEHICLE or msg.get_srcComponent() != 1:
            return
        if msg.base_mode & MAV_MODE_FLAG_SAFETY_ARMED:
            self.armed_seen = True
        else:
            self.disarmed_seen = True

    @property
    def to_fc_allowed(self) -> bool:
        return self.disarmed_seen and not self.armed_seen

    @property
    def rewrite_allowed(self) -> bool:
        return not self.armed_seen


def opt_in_ok(env=os.environ) -> bool:
    return env.get(OPT_IN_ENV) == OPT_IN_VALUE


class Rewriter:
    def __init__(self) -> None:
        self.enc = mav.MAVLink(None)
        self.enc.robust_parsing = True
        self.mode = {"kind": "off", "val": 0.0}
        self.frozen = None
        self.rewritten = 0

    def rewrite(self, msg):
        k, v, t = self.mode["kind"], self.mode["val"], msg.get_type()
        if k == "alt_bias" and t == "GLOBAL_POSITION_INT":
            msg.alt += int(v * 1000)
            msg.relative_alt += int(v * 1000)
        elif k == "batt_jump" and t == "SYS_STATUS":
            msg.voltage_battery = max(0, min(65535, msg.voltage_battery + int(v * 1000)))
        elif k == "freeze" and t == "ATTITUDE":
            if self.frozen is None:
                self.frozen = (msg.roll, msg.pitch, msg.yaw, msg.rollspeed, msg.pitchspeed, msg.yawspeed)
            msg.roll, msg.pitch, msg.yaw, msg.rollspeed, msg.pitchspeed, msg.yawspeed = self.frozen
        elif k == "heading" and t == "VFR_HUD":
            msg.heading = int((msg.heading + v) % 360)
        else:
            return None
        self.enc.srcSystem, self.enc.srcComponent, self.enc.seq = msg.get_srcSystem(), msg.get_srcComponent(), msg.get_seq()
        self.rewritten += 1
        return bytes(msg.pack(self.enc))


def fc_to_bridge(data: bytes, rd, gate: ArmGate, rw: Rewriter) -> bytes:
    """Parse every FC frame (the arm gate must see each heartbeat); rewrite only while allowed."""
    out = b""
    for m in rd.parse_buffer(data) or []:
        gate.observe(m)
        new = rw.rewrite(m) if rw.mode["kind"] != "off" and gate.rewrite_allowed else None
        out += new or bytes(m.get_msgbuf())
    return out


def main() -> int:
    if not opt_in_ok():
        print(f"px_fc_proxy: refusing to start. It relays a REAL flight controller as a socket:// link (bench only, props "
              f"off, disarmed). Set {OPT_IN_ENV}={OPT_IN_VALUE} to confirm.", file=sys.stderr)
        return 2
    print("=" * 78 + "\npx_fc_proxy: REAL FLIGHT CONTROLLER RELAY -- bench only, props off, vehicle disarmed.\n"
          "Nothing is sent to the FC until it reports disarmed; an armed heartbeat stops all FC-bound traffic.\n"
          + "=" * 78, file=sys.stderr, flush=True)
    import serial

    dev = sys.argv[1]
    data_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5810
    out_path = os.environ.get("PROXY_OUT", "/tmp/px_proxy.json")
    ser = serial.Serial(dev, 115200, timeout=0)
    rd = mav.MAVLink(None)
    rd.robust_parsing = True
    gate, rw = ArmGate(), Rewriter()
    stats = {"to_bridge_bytes": 0, "to_fc_bytes": 0, "bridge_connects": 0}
    sel = selectors.DefaultSelector()

    def listen(port, tag):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(4)
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ, tag)

    listen(data_port, "bridge_in")
    listen(data_port + 1, "ctl")
    sel.register(ser.fileno(), selectors.EVENT_READ, "fc")
    bridge = None
    last = 0.0
    while True:
        for key, _ in sel.select(timeout=0.5):
            tag = key.data
            if tag == "bridge_in":
                if bridge is not None:
                    sel.unregister(bridge)
                    bridge.close()
                bridge, _a = key.fileobj.accept()
                bridge.setblocking(False)
                sel.register(bridge, selectors.EVENT_READ, "bridge")
                stats["bridge_connects"] += 1
            elif tag == "ctl":
                c, _a = key.fileobj.accept()
                c.settimeout(1)
                try:
                    parts = c.recv(200).decode().split()
                    rw.mode["kind"] = parts[0]
                    rw.mode["val"] = float(parts[1]) if len(parts) > 1 else 0.0
                    rw.frozen = None
                    c.sendall(b"ok\n" if gate.rewrite_allowed else b"refused: vehicle armed\n")
                except Exception:
                    pass
                c.close()
            elif tag == "fc":
                data = ser.read(4096)
                if not data:
                    continue
                out = fc_to_bridge(data, rd, gate, rw)
                if bridge is None:
                    continue
                try:
                    bridge.sendall(out)
                    stats["to_bridge_bytes"] += len(out)
                except OSError:
                    pass
            elif tag == "bridge":
                try:
                    data = key.fileobj.recv(65536)
                except OSError:
                    data = b""
                if not data:
                    sel.unregister(bridge)
                    bridge.close()
                    bridge = None
                    continue
                if gate.to_fc_allowed:
                    ser.write(data)
                    stats["to_fc_bytes"] += len(data)
                else:
                    gate.blocked_to_fc_bytes += len(data)
        if time.time() - last > 1:
            last = time.time()
            with open(out_path, "w") as f:
                f.write(json.dumps({**stats, "rewritten": rw.rewritten, "mode": rw.mode["kind"],
                                    "disarmed_seen": gate.disarmed_seen, "armed_seen": gate.armed_seen,
                                    "blocked_to_fc_bytes": gate.blocked_to_fc_bytes}))


if __name__ == "__main__":
    raise SystemExit(main())
