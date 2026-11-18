"""The vehicle uplink filter over REAL transports (pyserial socket:// virtual ports and the bridge's own threads): the lock-out
safeguards as they run, not just as unit calls. SYNTHETIC frames; the key is a throwaway test value."""

from __future__ import annotations

import socket
import threading
import time

from pymavlink.dialects.v20 import common as mav2

from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.mavlink.signing import MAVLINK_EPOCH_UNIX_S, sign_mavlink2_frame
from aegisflight.mitigation.inline_policy import MAV_CMD_DO_SET_MODE
from aegisflight.proxy.transport import split_frames
from aegisflight.sources.mavlink_serial import SerialMavlinkTransport

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
BRIDGE_COMPIDS = (191, 192)


def _ts() -> int:
    return int((time.time() - MAVLINK_EPOCH_UNIX_S) * 100_000)


def _gcs_frame(kind: str, sysid: int = 255, p2: float = 4.0) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=190)
    m.robust_parsing = True
    if kind == "heartbeat":
        return bytes(m.heartbeat_encode(6, 8, 0, 0, 4).pack(m))
    return bytes(m.command_long_encode(1, 1, MAV_CMD_DO_SET_MODE, 0, 1.0, p2, 0, 0, 0, 0, 0).pack(m))


def _listener() -> socket.socket:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s


def _rig(tmp_path, **kw):
    fc_srv, gcs_srv = _listener(), _listener()
    conns: dict[str, socket.socket] = {}

    def accept(name, srv):
        conns[name], _ = srv.accept()

    for name, srv in (("fc", fc_srv), ("gcs", gcs_srv)):
        threading.Thread(target=accept, args=(name, srv), daemon=True).start()
    fc = SerialMavlinkTransport(f"socket://127.0.0.1:{fc_srv.getsockname()[1]}", allow_url=True, accept_unverified_ids=True)
    gcs = SerialMavlinkTransport(f"socket://127.0.0.1:{gcs_srv.getsockname()[1]}", allow_url=True, accept_unverified_ids=True)
    bridge = InlineIpsBridge(fc, gcs, mode="passive", secret_key=KEY, vehicle_filter=True, **kw)
    fc.start()
    gcs.start()
    bridge.start()
    deadline = time.monotonic() + 5
    while len(conns) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(conns) == 2
    return bridge, conns, (fc_srv, gcs_srv)


def _received_at_fc(sock: socket.socket, want: int, timeout: float = 3.0) -> list[bytes]:
    """Frames that reached the flight controller (the bridge's own frames, compid 191 / 192, are not the subject here)."""
    sock.settimeout(0.1)
    buf, end = b"", time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            buf += sock.recv(4096)
        except TimeoutError:
            pass
        got = [f.raw for f in split_frames(buf)[0] if f.compid not in BRIDGE_COMPIDS]
        if len(got) >= want:
            time.sleep(0.2)
            try:
                buf += sock.recv(4096)
            except TimeoutError:
                pass
            return [f.raw for f in split_frames(buf)[0] if f.compid not in BRIDGE_COMPIDS]
    return [f.raw for f in split_frames(buf)[0] if f.compid not in BRIDGE_COMPIDS]


def _wait(cond, timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def test_a_gcs_signing_with_the_wrong_key_is_never_locked_out_over_real_transports(tmp_path):
    bridge, conns, servers = _rig(tmp_path)
    try:
        frames = [sign_mavlink2_frame(_gcs_frame("heartbeat"), OTHER_KEY, link_id=0, timestamp_10us=_ts())]
        frames += [sign_mavlink2_frame(_gcs_frame("cmd", p2=float(i)), OTHER_KEY, link_id=0, timestamp_10us=_ts() + 10 + i)
                   for i in range(5)]
        for f in frames:
            conns["gcs"].sendall(f)
            time.sleep(0.02)
        assert _received_at_fc(conns["fc"], len(frames)) == frames        # every one reached the flight controller
        assert bridge.dropped_up == 0 and bridge.policy.filter_state == "learning"
    finally:
        bridge.close()
        for c in conns.values():
            c.close()
        for s in servers:
            s.close()


def test_the_filter_engages_on_the_right_key_and_the_override_file_switches_it_off_and_on(tmp_path):
    flag = tmp_path / "filter_off"
    bridge, conns, servers = _rig(tmp_path, filter_override_file=str(flag))
    bridge._override_interval_s = 0.05
    try:
        hb = sign_mavlink2_frame(_gcs_frame("heartbeat"), KEY, link_id=0, timestamp_10us=_ts())
        conns["gcs"].sendall(hb)
        assert _wait(lambda: bridge.policy.filter_state == "engaged")
        forged = _gcs_frame("cmd", sysid=66)
        conns["gcs"].sendall(forged)
        assert _wait(lambda: bridge.dropped_up == 1)                     # engaged: dropped

        flag.write_text("off", encoding="ascii")                         # the operator's local switch, no restart
        assert _wait(lambda: bridge.policy.filter_override)
        conns["gcs"].sendall(forged)
        assert forged in _received_at_fc(conns["fc"], 2)                 # overridden: it reaches the flight controller
        assert bridge.status()["vehicle_filter_state"] == "override"
    finally:
        bridge.close()
        for c in conns.values():
            c.close()
        for s in servers:
            s.close()
