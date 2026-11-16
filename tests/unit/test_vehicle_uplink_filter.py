"""The vehicle uplink filter (docs/VEHICLE_UPLINK_FILTER.md): receive-only-compatible filtering for a vehicle link.

SYNTHETIC frames; the key is a throwaway test value. What these tests pin down:
  * it needs a signing key and is not combinable with active-ips;
  * on a serial-device FC port it runs, while active-ips on that port is still refused;
  * it drops forged / unsigned / wrong-key / replayed control frames and forwards the validly signed pilot command;
  * it never touches the downlink and never sends a counter-command;
  * it is fixed at construction: no posture change can switch it on or off;
  * without it, passive and advisory still forward every frame byte-identically."""

from __future__ import annotations

import importlib
import time

import pytest
from pymavlink.dialects.v20 import common as mav2

from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.mavlink.signing import MAVLINK_EPOCH_UNIX_S, sign_mavlink2_frame
from aegisflight.mitigation.inline_policy import MAV_CMD_DO_SET_MODE
from aegisflight.mitigation.types import DefenseMode

cli = importlib.import_module("aegisflight.cli.main")  # the package re-exports main(), which shadows the module

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


def now_ts() -> int:
    return int((time.time() - MAVLINK_EPOCH_UNIX_S) * 100_000)


def _enc(sysid: int, comp: int) -> mav2.MAVLink:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=comp)
    m.robust_parsing = True
    return m


def cmd(sysid: int, p2: float = 4.0) -> bytes:
    m = _enc(sysid, 190)
    return bytes(m.command_long_encode(1, 1, MAV_CMD_DO_SET_MODE, 0, 1.0, p2, 0, 0, 0, 0, 0).pack(m))


def signed(raw: bytes, ts: int, key: bytes = KEY) -> bytes:
    return sign_mavlink2_frame(raw, key, link_id=0, timestamp_10us=ts)


def heartbeat() -> bytes:
    m = _enc(1, 1)
    return bytes(m.heartbeat_encode(2, 3, 128 | 1, 4, 4, 3).pack(m))


def gpi(rel_alt_m: float = 30.0) -> bytes:
    m = _enc(1, 1)
    return bytes(m.global_position_int_encode(1000, int(19.0 * 1e7), int(72.9 * 1e7), int(rel_alt_m * 1000), int(rel_alt_m * 1000),
                                              0, 0, 0, 0).pack(m))


class FakeLink:
    def __init__(self) -> None:
        self.inbox: list[tuple[int, bytes]] = []
        self.sent: list[bytes] = []

    def feed(self, *frames: bytes, stamp: int = 1_000_000_000) -> None:
        self.inbox.extend((stamp, f) for f in frames)

    def poll(self):
        out, self.inbox = self.inbox, []
        return out

    def send(self, data: bytes) -> bool:
        self.sent.append(bytes(data))
        return True

    def close(self) -> None:
        return None


class SerialLink(FakeLink):
    """A FakeLink that looks like a serial device, which may be a physical flight controller."""

    port = "/dev/ttyACM0"


def serial_bridge(mode: str = "passive", **kw):
    fc, gcs = SerialLink(), FakeLink()
    return InlineIpsBridge(fc, gcs, mode=mode, secret_key=KEY, vehicle_filter=True, **kw), fc, gcs


def test_it_needs_a_signing_key():
    with pytest.raises(ValueError, match="signing key"):
        InlineIpsBridge(FakeLink(), FakeLink(), mode="passive", vehicle_filter=True)


def test_it_is_not_combinable_with_active_ips():
    with pytest.raises(ValueError, match="alternative to active-ips"):
        InlineIpsBridge(FakeLink(), FakeLink(), mode="active-ips", secret_key=KEY, vehicle_filter=True)


@pytest.mark.parametrize("mode", ["passive", "advisory"])
def test_it_runs_on_a_serial_device_port_where_active_ips_is_refused(mode):
    b, fc, gcs = serial_bridge(mode)
    assert b.policy.enforce and b.policy.uplink_filter_only
    with pytest.raises(ValueError, match="receive-only"):
        InlineIpsBridge(SerialLink(), FakeLink(), mode="active-ips", secret_key=KEY)
    with pytest.raises(ValueError, match="receive-only"):
        b.set_mode("active-ips")
    assert b.policy.enforce and b.policy.uplink_filter_only   # a refused change leaves the filter exactly as it was


def test_it_drops_forged_control_and_forwards_the_signed_pilot_command():
    b, fc, gcs = serial_bridge()
    pilot = signed(cmd(255), now_ts())
    forged = [cmd(66), cmd(255, p2=9.0), signed(cmd(255, p2=7.0), now_ts() + 10, key=OTHER_KEY)]
    gcs.feed(*forged, pilot)
    b.pump_once()
    assert fc.sent == [pilot]
    assert b.dropped_up == 3
    assert b.policy.dropped_unsigned == 2 and b.policy.dropped_bad_signature == 1


def test_it_drops_a_replayed_signed_frame():
    b, fc, gcs = serial_bridge()
    pilot = signed(cmd(255), now_ts())
    gcs.feed(pilot)
    b.pump_once()
    gcs.feed(pilot)
    b.pump_once()
    assert fc.sent == [pilot]
    assert b.policy.dropped_replay == 1


def test_it_never_touches_the_downlink():
    b, fc, gcs = serial_bridge()
    frames = [heartbeat(), gpi(), gpi(rel_alt_m=31.0)] * 30
    fc.feed(*frames)
    b.pump_once()
    assert gcs.sent == frames and b.dropped_down == 0
    assert b.policy.rewritten == 0 and b.policy.dropped_dynamic == 0 and b.policy.dropped_forged_down == 0


def test_an_unsigned_frame_from_a_source_that_was_signing_is_reported_not_dropped_on_the_downlink():
    """In ACTIVE_IPS this frame is a forgery and is dropped; with the filter alone the downlink stays untouched."""
    b, fc, gcs = serial_bridge()
    for i in range(30):
        fc.feed(signed(heartbeat(), now_ts() + i))
    b.pump_once()
    unsigned = heartbeat()
    fc.feed(unsigned)
    b.pump_once()
    assert gcs.sent[-1] == unsigned
    assert b.policy.dropped_forged_down == 0 and b.policy.observed_forged_down == 1


def test_no_counter_command_is_ever_sent_to_the_flight_controller():
    b, fc, gcs = serial_bridge()
    b.set_mode(DefenseMode.ADVISORY)
    assert b.controller.mode == DefenseMode.ADVISORY
    assert b.counter_frames_sent == 0 and fc.sent == []


def test_no_posture_change_can_switch_it_on_or_off():
    b, fc, gcs = serial_bridge()
    for mode in ("advisory", "passive", "advisory"):
        b.set_mode(mode)
        assert b.policy.enforce and b.policy.uplink_filter_only
    assert b.status()["vehicle_filter"] is True
    assert not any(hasattr(b, name) for name in ("set_vehicle_filter", "enable_vehicle_filter", "disable_vehicle_filter"))
    plain = InlineIpsBridge(FakeLink(), FakeLink(), mode="passive", secret_key=KEY)
    assert plain.status()["vehicle_filter"] is False


def test_on_a_socket_link_active_ips_replaces_the_filter_with_full_enforcement():
    fc, gcs = FakeLink(), FakeLink()
    b = InlineIpsBridge(fc, gcs, mode="passive", secret_key=KEY, vehicle_filter=True)
    assert b.policy.uplink_filter_only
    b.set_mode("active-ips")
    assert b.policy.enforce and not b.policy.uplink_filter_only
    b.set_mode("passive")
    assert b.policy.enforce and b.policy.uplink_filter_only


def test_without_the_filter_passive_and_advisory_forward_every_frame_byte_identically():
    for mode in ("passive", "advisory"):
        fc, gcs = SerialLink(), FakeLink()
        b = InlineIpsBridge(fc, gcs, mode=mode, secret_key=KEY)
        hostile = [cmd(66), cmd(255)]
        gcs.feed(*hostile)
        b.pump_once()
        assert fc.sent == hostile and b.dropped_up == 0 and not b.policy.enforce


def test_cli_refuses_the_filter_without_a_key_and_with_active_ips(capsys):
    base = ["ips-bridge", "--fc-port", "socket://127.0.0.1:1", "--gcs-port", "socket://127.0.0.1:2", "--allow-url",
            "--vehicle-uplink-filter"]
    assert cli.main(base) == 2
    assert "needs --signing-key-file" in capsys.readouterr().err


def test_cli_refuses_the_filter_together_with_active_ips(capsys, tmp_path):
    keyfile = tmp_path / "k.hex"
    keyfile.write_text(KEY.hex(), encoding="ascii")
    args = ["ips-bridge", "--fc-port", "socket://127.0.0.1:1", "--gcs-port", "socket://127.0.0.1:2", "--allow-url",
            "--vehicle-uplink-filter", "--signing-key-file", str(keyfile), "--defense-mode", "active-ips"]
    assert cli.main(args) == 2
    assert "alternative to --defense-mode active-ips" in capsys.readouterr().err
