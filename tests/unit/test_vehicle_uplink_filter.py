"""The vehicle uplink filter (docs/VEHICLE_UPLINK_FILTER.md): receive-only-compatible filtering for a vehicle link.

SYNTHETIC frames; the key is a throwaway test value. What these tests pin down:
  * it needs a signing key and is not combinable with active-ips;
  * on a serial-device FC port it runs, while active-ips on that port is still refused;
  * it drops forged / unsigned / wrong-key / replayed control frames and forwards the validly signed pilot command;
  * it never touches the downlink and never sends a counter-command;
  * it is fixed at construction: no posture change can switch it on or off;
  * lock-out safeguards: it only drops after a validly signed ground-station frame proved the key (a wrong key can never lock the
    pilot out), a LOCAL override file switches it off and on at run time, and an optional watchdog fails open on a suspected lock-out;
  * without it, passive and advisory still forward every frame byte-identically."""

from __future__ import annotations

import importlib
import time

import pytest
from pymavlink.dialects.v20 import common as mav2

from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.mavlink.signing import MAVLINK_EPOCH_UNIX_S, sign_mavlink2_frame
from aegisflight.mitigation.inline_policy import MAV_CMD_DO_SET_MODE, InlinePolicy
from aegisflight.mitigation.sanitizer import FrameSanitizer
from aegisflight.mitigation.types import DefenseMode
from aegisflight.proxy.hooks import FrameContext
from aegisflight.proxy.transport import split_frames

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


def gcs_heartbeat(sysid: int = 255) -> bytes:
    m = _enc(sysid, 190)
    return bytes(m.heartbeat_encode(6, 8, 0, 0, 4).pack(m))


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


def engage(b, gcs, ts: int | None = None):
    """The pilot's GCS sends one validly signed frame: that proves the key and the filter starts dropping."""
    gcs.feed(signed(gcs_heartbeat(), ts if ts is not None else now_ts()))
    b.pump_once()
    assert b.policy.filter_state == "engaged"


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
    engage(b, gcs)
    fc.sent.clear()
    pilot = signed(cmd(255), now_ts() + 1000)
    forged = [cmd(66), cmd(255, p2=9.0), signed(cmd(255, p2=7.0), now_ts() + 10, key=OTHER_KEY)]
    gcs.feed(*forged, pilot)
    b.pump_once()
    assert fc.sent == [pilot]
    assert b.dropped_up == 3
    assert b.policy.dropped_unsigned == 2 and b.policy.dropped_bad_signature == 1


def test_it_drops_a_replayed_signed_frame():
    b, fc, gcs = serial_bridge()
    engage(b, gcs)
    fc.sent.clear()
    pilot = signed(cmd(255), now_ts() + 1000)
    gcs.feed(pilot)
    b.pump_once()
    gcs.feed(pilot)
    b.pump_once()
    assert fc.sent == [pilot]
    assert b.policy.dropped_replay == 1


def test_it_never_touches_the_downlink():
    b, fc, gcs = serial_bridge()
    engage(b, gcs)
    frames = [heartbeat(), gpi(), gpi(rel_alt_m=31.0)] * 30
    fc.feed(*frames)
    b.pump_once()
    assert gcs.sent[-len(frames):] == frames and b.dropped_down == 0
    assert b.policy.rewritten == 0 and b.policy.dropped_dynamic == 0 and b.policy.dropped_forged_down == 0


def test_an_unsigned_frame_from_a_source_that_was_signing_is_reported_not_dropped_on_the_downlink():
    """In ACTIVE_IPS this frame is a forgery and is dropped; with the filter alone the downlink stays untouched."""
    b, fc, gcs = serial_bridge()
    engage(b, gcs)
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
    engage(b, gcs)
    for mode in ("advisory", "passive", "advisory"):
        b.set_mode(mode)
        assert b.policy.enforce and b.policy.uplink_filter_only and b.policy.filter_state == "engaged"
    assert b.status()["vehicle_filter"] is True
    assert not any(hasattr(b, name) for name in ("set_vehicle_filter", "enable_vehicle_filter", "disable_vehicle_filter"))
    plain = InlineIpsBridge(FakeLink(), FakeLink(), mode="passive", secret_key=KEY)
    assert plain.status()["vehicle_filter"] is False


def test_on_a_socket_link_active_ips_replaces_the_filter_with_full_enforcement():
    fc, gcs = FakeLink(), FakeLink()
    b = InlineIpsBridge(fc, gcs, mode="passive", secret_key=KEY, vehicle_filter=True)
    assert b.policy.uplink_filter_only
    b.set_mode("active-ips")
    assert b.policy.enforce and not b.policy.uplink_filter_only and b.policy.filter_state == "off"
    b.set_mode("passive")
    assert b.policy.enforce and b.policy.uplink_filter_only and b.policy.filter_state == "learning"


def test_without_the_filter_passive_and_advisory_forward_every_frame_byte_identically():
    for mode in ("passive", "advisory"):
        fc, gcs = SerialLink(), FakeLink()
        b = InlineIpsBridge(fc, gcs, mode=mode, secret_key=KEY)
        hostile = [cmd(66), cmd(255)]
        gcs.feed(*hostile)
        b.pump_once()
        assert fc.sent == hostile and b.dropped_up == 0 and not b.policy.enforce


def test_cli_refuses_the_filter_without_a_key_and_with_active_ips(capsys, tmp_path):
    base = ["ips-bridge", "--fc-port", "socket://127.0.0.1:1", "--gcs-port", "socket://127.0.0.1:2", "--allow-url",
            "--vehicle-uplink-filter"]
    assert cli.main(base) == 2
    assert "needs --signing-key-file" in capsys.readouterr().err
    keyfile = tmp_path / "k.hex"
    keyfile.write_text(KEY.hex(), encoding="ascii")
    assert cli.main([*base, "--signing-key-file", str(keyfile), "--defense-mode", "active-ips"]) == 2
    assert "alternative to --defense-mode active-ips" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# lock-out safeguards
# --------------------------------------------------------------------------- #

def test_a_wrong_key_never_locks_the_pilot_out_because_the_filter_never_engages():
    """The GCS signs with a key the bridge does not have: nothing is dropped, everything is reported."""
    b, fc, gcs = serial_bridge()
    frames = [signed(gcs_heartbeat(), now_ts() + i, key=OTHER_KEY) for i in range(5)]
    frames += [signed(cmd(255, p2=float(i)), now_ts() + 100 + i, key=OTHER_KEY) for i in range(5)]
    gcs.feed(*frames)
    b.pump_once()
    assert fc.sent == frames and b.dropped_up == 0
    assert b.policy.filter_state == "learning"
    assert b.policy.observed_bad_signature >= 5            # reported, so the operator sees the mismatch
    assert b.status()["vehicle_filter_state"] == "learning"


def test_an_unsigned_pilot_is_forwarded_and_reported_until_a_signed_frame_proves_the_key():
    b, fc, gcs = serial_bridge()
    unsigned = [cmd(255), cmd(255, p2=5.0)]
    gcs.feed(*unsigned)
    b.pump_once()
    assert fc.sent == unsigned and b.policy.filter_state == "learning"
    assert b.policy.observed_unsigned == 2
    engage(b, gcs)
    fc.sent.clear()
    gcs.feed(cmd(255, p2=6.0))
    b.pump_once()
    assert fc.sent == [] and b.dropped_up == 1             # engaged now: the same unsigned frame is dropped


def test_engaging_is_announced_to_the_console_and_the_gcs():
    alarms: list[str] = []
    fc, gcs = SerialLink(), FakeLink()
    b = InlineIpsBridge(fc, gcs, mode="passive", secret_key=KEY, vehicle_filter=True, on_alarm=alarms.append)
    engage(b, gcs)
    assert any("filter engaged" in a for a in alarms)


def test_the_local_override_file_turns_the_filter_off_and_back_on_at_run_time(tmp_path):
    flag = tmp_path / "filter_off"
    fc, gcs = SerialLink(), FakeLink()
    alarms: list[str] = []
    b = InlineIpsBridge(fc, gcs, mode="passive", secret_key=KEY, vehicle_filter=True, filter_override_file=str(flag),
                        on_alarm=alarms.append)
    b._override_interval_s = 0.0
    engage(b, gcs)
    forged = cmd(66)
    fc.sent.clear()
    gcs.feed(forged)
    b.pump_once()
    assert fc.sent == [] and b.dropped_up == 1                              # engaged: dropped

    flag.write_text("off", encoding="ascii")
    gcs.feed(forged)
    b.pump_once()
    assert fc.sent == [forged] and b.policy.filter_state == "override"      # overridden: forwarded, reported
    assert b.status()["vehicle_filter_state"] == "override"
    assert any("override" in a for a in alarms)

    flag.unlink()
    gcs.feed(forged)
    b.pump_once()
    assert b.policy.filter_state == "learning" and fc.sent == [forged, forged]   # not dropping again until the key is re-proved
    engage(b, gcs, ts=now_ts() + 5000)
    before = len(fc.sent)
    gcs.feed(forged)
    b.pump_once()
    assert len(fc.sent) == before and b.dropped_up == 2                     # engaged again: dropped


def test_the_override_cannot_be_reached_through_the_posture_api():
    b, fc, gcs = serial_bridge()
    engage(b, gcs)
    b.set_mode("advisory")
    b.mgmt_set_posture("passive", allow_unsigned=False)
    assert b.policy.filter_state == "engaged" and not b.policy.filter_override


def test_override_and_watchdog_settings_need_the_filter():
    with pytest.raises(ValueError, match="only apply with vehicle_filter"):
        InlineIpsBridge(FakeLink(), FakeLink(), mode="passive", secret_key=KEY, filter_override_file="x")
    with pytest.raises(ValueError, match="only apply with vehicle_filter"):
        InlineIpsBridge(FakeLink(), FakeLink(), mode="passive", secret_key=KEY, filter_lockout_failopen_s=10.0)
    with pytest.raises(ValueError, match="must be > 0"):
        InlineIpsBridge(FakeLink(), FakeLink(), mode="passive", secret_key=KEY, vehicle_filter=True, filter_lockout_failopen_s=0.0)


class _Clock:
    t = 100.0

    def __call__(self) -> float:
        return self.t


def _policy(watchdog_s: float | None):
    clock = _Clock()
    p = InlinePolicy(FrameSanitizer(), signing_key=KEY, clock=clock)
    p.set_enforce(True)
    p.set_uplink_filter_only(True)
    p.lockout_failopen_s = watchdog_s

    def up(raw: bytes) -> list[bytes]:
        fr = split_frames(raw)[0][0]
        return p.up(FrameContext(direction="up", raw=fr.raw, recv_ns=1, sysid=fr.sysid, compid=fr.compid,  # type: ignore[arg-type]
                                 seq=fr.seq, msgid=fr.msgid, signed=fr.signed))

    return p, clock, up


def test_the_watchdog_is_off_by_default_so_a_lockout_keeps_dropping():
    p, clock, up = _policy(None)
    up(signed(gcs_heartbeat(), now_ts()))
    assert p.filter_state == "engaged"
    for i in range(10):
        clock.t += 10.0
        assert up(cmd(255, p2=float(i))) == []
    assert p.filter_state == "engaged"


def test_the_watchdog_fails_open_after_a_silent_signing_loss_and_reengages_on_a_valid_frame():
    p, clock, up = _policy(30.0)
    up(signed(gcs_heartbeat(), now_ts()))
    assert p.filter_state == "engaged"
    outs = []
    for i in range(4):                      # the GCS lost its signing: unsigned control from the trusted sysid keeps arriving
        clock.t += 10.0
        outs.append(up(cmd(255, p2=float(i))))
    assert outs[0] == [] and outs[1] == []   # dropped while the silence is shorter than the watchdog
    assert p.filter_state == "failopen"
    assert outs[3] != []                     # once failed open, everything is forwarded
    assert p.take_filter_events()[-1][0] == "failopen"
    up(signed(gcs_heartbeat(), now_ts() + 10_000))   # signing is back: a valid frame re-engages the filter
    assert p.filter_state == "engaged"


def test_a_valid_signed_stream_keeps_the_watchdog_quiet_while_a_forger_is_still_dropped():
    p, clock, up = _policy(30.0)
    ts = now_ts()
    up(signed(gcs_heartbeat(), ts))
    for i in range(20):
        clock.t += 10.0
        ts += 100
        up(signed(gcs_heartbeat(), ts))      # the real GCS keeps sending signed frames
        assert up(cmd(255, p2=float(i))) == []   # the forger spoofing its sysid is dropped every time
    assert p.filter_state == "engaged"


def test_cli_override_and_watchdog_flags_need_the_filter(capsys):
    args = ["ips-bridge", "--fc-port", "socket://127.0.0.1:1", "--gcs-port", "socket://127.0.0.1:2", "--allow-url",
            "--filter-override-file", "/tmp/x"]
    assert cli.main(args) == 2
    assert "only apply with --vehicle-uplink-filter" in capsys.readouterr().err
