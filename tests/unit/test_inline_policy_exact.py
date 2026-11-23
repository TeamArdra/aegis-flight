"""Exact-behaviour tests for ``InlinePolicy`` (the inline IPS decision point).

Each test pins one observable decision of the policy: which frame is forwarded or dropped, which counter moves by
exactly how much, which reason text the operator sees, and which arguments reach the semantic firewall. They exist
because mutation testing showed the broader suites only pinned the happy path of these branches.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from pymavlink.dialects.v10 import common as mav1
from pymavlink.dialects.v20 import ardupilotmega as apm
from pymavlink.dialects.v20 import common as mav2

from aegisflight.mavlink.signing import MAVLINK_EPOCH_UNIX_S, sign_mavlink2_frame
from aegisflight.mitigation.inline_policy import (
    FORCE_MAGIC,
    MAV_CMD_COMPONENT_ARM_DISARM,
    MAV_CMD_DO_SET_MODE,
    InlinePolicy,
)
from aegisflight.mitigation.sanitizer import FrameSanitizer
from aegisflight.proxy.hooks import FrameContext
from aegisflight.proxy.transport import split_frames

KEY = bytes(range(32))
NOT_SENSITIVE = 31000  # a command id outside SENSITIVE_COMMANDS


class Clock:
    def __init__(self, t: float = 100.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def enc(sysid: int, comp: int = 190, dialect=mav2) -> object:
    m = dialect.MAVLink(None, srcSystem=sysid, srcComponent=comp)
    m.robust_parsing = True
    return m


def command(sysid: int = 255, cmd: int = MAV_CMD_DO_SET_MODE, p1: float = 1.0, p2: float = 4.0, comp: int = 190,
            confirmation: int = 0) -> bytes:
    m = enc(sysid, comp)
    return bytes(m.command_long_encode(1, 1, cmd, confirmation, p1, p2, 0, 0, 0, 0, 0).pack(m))


def command_v1(sysid: int = 255, cmd: int = MAV_CMD_DO_SET_MODE, p1: float = 1.0, comp: int = 190) -> bytes:
    m = enc(sysid, comp, mav1)
    return bytes(m.command_long_encode(1, 1, cmd, 0, p1, 4.0, 0, 0, 0, 0, 0).pack(m))


def command_int(sysid: int, cmd: int) -> bytes:
    m = enc(sysid)
    return bytes(m.command_int_encode(1, 1, 0, cmd, 0, 0, 0, 0, 0, 0, 0, 0, 0.0).pack(m))


def set_mode(sysid: int = 255) -> bytes:
    m = enc(sysid)
    return bytes(m.set_mode_encode(1, 1, 4).pack(m))


def heartbeat(sysid: int = 1, armed: bool = True, comp: int = 1) -> bytes:
    m = enc(sysid, comp)
    return bytes(m.heartbeat_encode(2, 3, 0x80 if armed else 0, 4, 4).pack(m))


def gcs_heartbeat(sysid: int = 255) -> bytes:
    m = enc(sysid, 190)
    return bytes(m.heartbeat_encode(6, 8, 0, 0, 4).pack(m))


def gpi(lat: float = 19.0, lon: float = 72.9, rel_alt_m: float = 30.0) -> bytes:
    m = enc(1, 1)
    return bytes(m.global_position_int_encode(1000, int(lat * 1e7), int(lon * 1e7), 0, int(rel_alt_m * 1000), 0, 0, 0, 0).pack(m))


def signed(raw: bytes, ts: int, key: bytes = KEY) -> bytes:
    return sign_mavlink2_frame(raw, key, link_id=0, timestamp_10us=ts)


def mk(raw: bytes, direction: str = "up", recv_ns: int = 1_000_000_000, seq: int | None = None) -> FrameContext:
    fr = split_frames(raw)[0][0]
    return FrameContext(direction=direction, raw=fr.raw, recv_ns=recv_ns, sysid=fr.sysid,  # type: ignore[arg-type]
                        compid=fr.compid, seq=fr.seq if seq is None else seq, msgid=fr.msgid, signed=fr.signed)


def policy(**kw) -> tuple[InlinePolicy, Clock]:
    clock = Clock()
    kw.setdefault("clock", clock)
    p = InlinePolicy(FrameSanitizer(), **kw)
    p.set_enforce(True)
    return p, clock


def filter_policy(**kw) -> tuple[InlinePolicy, Clock]:
    p, clock = policy(signing_key=KEY, **kw)
    p.set_uplink_filter_only(True)
    return p, clock


def now_ts() -> int:
    return int((time.time() - MAVLINK_EPOCH_UNIX_S) * 100_000)


# -- _is_control ------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    (set_mode(), True),
    (command(cmd=MAV_CMD_DO_SET_MODE), True),
    (command(cmd=MAV_CMD_COMPONENT_ARM_DISARM, p1=0.0), True),
    (command_int(255, MAV_CMD_DO_SET_MODE), True),
    (command(cmd=NOT_SENSITIVE), False),
    (command(cmd=1, p1=float(MAV_CMD_DO_SET_MODE)), False),  # p1 equal to a sensitive id must not count
    (command(cmd=NOT_SENSITIVE, p1=float(MAV_CMD_COMPONENT_ARM_DISARM)), False),
    (heartbeat(), False),
    (gcs_heartbeat(), False),
])
def test_is_control_truth_table(raw: bytes, expected: bool) -> None:
    p, _ = policy()
    assert p._is_control(mk(raw)) is expected


def test_is_control_ignores_the_command_payload_of_a_non_command_message() -> None:
    p, _ = policy()
    ctx = mk(command(cmd=MAV_CMD_DO_SET_MODE))
    forged = FrameContext(ctx.direction, ctx.raw, ctx.recv_ns, ctx.sysid, ctx.compid, ctx.seq, 0, ctx.signed)
    assert p._is_control(forged) is False  # msgid 0 (HEARTBEAT) with a command-shaped body is not a command


# -- uplink filter state machine ---------------------------------------------------------------------------------------------

def test_without_a_key_the_filter_gate_forwards_everything() -> None:
    p, _ = policy()
    p.set_uplink_filter_only(True)
    raw = set_mode(sysid=77)
    assert p.up(mk(raw)) == [raw]
    assert p.dropped_untrusted_control == 0


def test_override_and_its_clearing_are_reported_with_their_exact_reasons() -> None:
    p, _ = filter_policy()
    p.filter_override = True
    raw = set_mode(sysid=77)
    assert p.up(mk(raw)) == [raw]
    assert p.filter_state == "override"
    assert p.take_filter_events() == [("override", "local override file present: forwarding everything, reporting only")]
    p.filter_override = False
    assert p.up(mk(raw)) == [raw]
    assert p.filter_state == "learning"
    assert p.take_filter_events() == [("learning", "override cleared: waiting for a validly signed ground-station frame")]
    assert p.take_filter_events() == []


def test_first_valid_signed_ground_station_frame_engages_and_is_itself_forwarded() -> None:
    p, _ = filter_policy()
    assert p.filter_state == "learning"
    raw = signed(command(), now_ts())
    assert p.up(mk(raw)) == [raw]  # a control frame: a False gate result would re-verify it and drop it as a replay
    assert p.filter_state == "engaged"
    assert p.take_filter_events() == [
        ("engaged", "a validly signed ground-station frame proves the key: filtering uplink control")]
    assert p.signed_ok == 1 and p.dropped_replay == 0


@pytest.mark.parametrize("state", ["learning", "failopen"])
def test_learning_and_failopen_both_engage_on_a_valid_signed_frame(state: str) -> None:
    p, _ = filter_policy()
    p.filter_state = state
    raw = signed(command(), now_ts())
    assert p.up(mk(raw)) == [raw]
    assert p.filter_state == "engaged"


def test_a_bad_signature_while_learning_is_observed_not_dropped_and_not_engaging() -> None:
    p, _ = filter_policy()
    forged = signed(command(), now_ts(), key=bytes(range(1, 33)))
    assert p.up(mk(forged)) == [forged]
    assert p.filter_state == "learning"
    # (the gate verifies once and _observe_signature verifies again, so the observation counter may run ahead of 1)
    assert p.observed_bad_signature >= 1 and p.dropped_bad_signature == 0
    assert p.take_observed() == [("bad_signature", forged, 255, 76)]


def test_a_vehicle_sysid_frame_never_engages_the_filter() -> None:
    p, _ = filter_policy()
    raw = signed(command(sysid=1), now_ts())
    assert p.up(mk(raw)) == [raw]
    assert p.filter_state == "learning" and p._last_valid_t is None


def test_an_unsigned_ground_station_frame_never_engages_the_filter() -> None:
    p, _ = filter_policy()
    raw = command()
    assert p.up(mk(raw)) == [raw]
    assert p.filter_state == "learning"
    assert p.observed_unsigned == 1 and p.take_observed() == [("unsigned", raw, 255, 76)]


def test_an_engaged_filter_drops_forged_control_and_keeps_the_pilot() -> None:
    p, _ = filter_policy()
    ts = now_ts()
    pilot = signed(command(), ts)
    assert p.up(mk(pilot)) == [pilot]
    forged = command(p2=2.0)  # unsigned
    assert p.up(mk(forged)) == []
    assert p.dropped_unsigned == 1
    assert p.up(mk(signed(command(p2=3.0), ts + 10))) != []


def test_engaged_filter_without_a_watchdog_does_not_inspect_non_control_frames() -> None:
    p, _ = filter_policy()
    assert p.up(mk(signed(command(), now_ts()))) != []
    p._last_valid_t = None
    before = (p.observed_unsigned, p.observed_replay, p.observed_bad_signature, p.signed_ok)
    hb = gcs_heartbeat()
    assert p.up(mk(hb)) == [hb]
    assert (p.observed_unsigned, p.observed_replay, p.observed_bad_signature, p.signed_ok) == before
    assert p._last_valid_t is None


def test_engaged_watchdog_notes_a_valid_signed_non_control_gcs_frame_only() -> None:
    p, clock = filter_policy()
    p.lockout_failopen_s = 30.0
    assert p.up(mk(signed(command(), now_ts()))) != []
    assert p._last_valid_t == 100.0
    clock.t = 150.0
    hb = signed(gcs_heartbeat(), now_ts() + 50)
    assert p.up(mk(hb)) == [hb]
    assert p._last_valid_t == 150.0 and p._lockout_drops == 0
    # an unsigned GCS frame is not inspected (and so cannot count as proof of life)
    clock.t = 200.0
    p.up(mk(gcs_heartbeat()))
    assert p._last_valid_t == 150.0 and p.observed_unsigned == 0
    # a signed *control* frame is judged by the normal path, not by the gate
    ok_before = p.signed_ok
    ctl = signed(command(p2=9.0), now_ts() + 100)
    assert p.up(mk(ctl)) == [ctl]
    assert p.signed_ok == ok_before + 1
    # a signed frame from a vehicle sysid does not count as a ground-station frame
    clock.t = 300.0
    veh = signed(heartbeat(sysid=1), now_ts() + 200)
    p.up(mk(veh))
    assert p._last_valid_t != 300.0


def test_lockout_failopen_needs_three_drops_and_forwards_the_triggering_frame() -> None:
    p, clock = filter_policy()
    p.lockout_failopen_s = 30.0
    assert p.up(mk(signed(command(), now_ts()))) != []
    clock.t = 131.0
    drops = [p.up(mk(command(p2=float(i)))) for i in range(2)]
    assert drops == [[], []] and p.filter_state == "engaged" and p._lockout_drops == 2
    third = command(p2=7.0)
    assert p.up(mk(third)) == [third]
    assert p.filter_state == "failopen"
    (state, detail), = p.take_filter_events()[-1:]
    assert state == "failopen"
    assert detail == ("pilot lock-out suspected: no valid signed ground-station frame for 30 s while control frames "
                      "from a trusted sysid were dropped; forwarding everything until a signed frame is seen")
    again = command(p2=8.0)
    assert p.up(mk(again)) == [again]  # fail-open keeps forwarding


def test_lockout_failopen_is_not_triggered_by_untrusted_senders_or_other_verdicts() -> None:
    p, clock = filter_policy()
    p.lockout_failopen_s = 30.0
    assert p.up(mk(signed(command(), now_ts()))) != []
    clock.t = 500.0
    for i in range(5):
        assert p.up(mk(command(sysid=77, p2=float(i)))) == []
    assert p.filter_state == "engaged" and p._lockout_drops == 0
    for i in range(5):
        p._note_lockout_drop(mk(command(p2=float(i))), "replay")
        p._note_lockout_drop(mk(command(p2=float(i))), "ok")
    assert p._lockout_drops == 0
    p.lockout_failopen_s = None
    p._note_lockout_drop(mk(command()), "unsigned")
    assert p._lockout_drops == 0


def test_lockout_failopen_uses_the_engaged_time_when_no_valid_frame_was_noted() -> None:
    p, clock = filter_policy()
    p.lockout_failopen_s = 30.0
    p.filter_state = "engaged"
    p._engaged_t, p._last_valid_t = 100.0, None
    clock.t = 129.0
    for i in range(3):
        p._note_lockout_drop(mk(command(p2=float(i))), "unsigned")
    assert p.filter_state == "engaged"
    clock.t = 130.0
    p._note_lockout_drop(mk(command(p2=9.0)), "bad_signature")
    assert p.filter_state == "failopen"


def test_lockout_failopen_waits_for_the_silence_to_reach_the_threshold_exactly() -> None:
    p, clock = filter_policy()
    p.lockout_failopen_s = 30.0
    p.filter_state = "engaged"
    p._last_valid_t = 100.0
    clock.t = 129.999
    for i in range(3):
        p._note_lockout_drop(mk(command(p2=float(i))), "unsigned")
    assert p.filter_state == "engaged"
    clock.t = 130.0
    p._note_lockout_drop(mk(command(p2=9.0)), "unsigned")
    assert p.filter_state == "failopen"


def test_set_filter_state_event_log_is_capped_and_idempotent() -> None:
    p, _ = filter_policy()
    for i in range(40):
        p._set_filter_state("engaged" if i % 2 else "learning", f"d{i}")
    assert len(p.filter_events) == 16
    n = len(p.filter_events)
    p._set_filter_state(p.filter_state, "same")
    assert len(p.filter_events) == n
    p.filter_events = []
    p._set_filter_state("engaged", "x")
    assert p._engaged_t is not None
    p._set_filter_state("learning", "y")
    assert p._engaged_t is None and p._lockout_drops == 0


# -- semantic firewall wiring ------------------------------------------------------------------------------------------------

def _param_set(sysid: int = 255, name: bytes = b"SYSID_THISMAV", value: float = 42.0) -> bytes:
    m = apm.MAVLink(file=None, srcSystem=sysid, srcComponent=190)
    return bytes(apm.MAVLink_param_set_message(1, 1, name, value, apm.MAV_PARAM_TYPE_REAL32).pack(m))


def _fence_item(lat: float = 20.0, lon: float = 73.0) -> bytes:
    m = apm.MAVLink(file=None, srcSystem=255, srcComponent=190)
    return bytes(apm.MAVLink_mission_item_int_message(
        1, 1, 0, apm.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT, apm.MAV_CMD_NAV_FENCE_CIRCLE_INCLUSION, 0, 1, 50.0, 0, 0, 0,
        int(lat * 1e7), int(lon * 1e7), 50.0, 1).pack(m))


def _recorder(blocked: bool, reason: str = "r"):
    calls: list[tuple] = []

    def fake(event, **kw):
        calls.append((event, kw))
        return SimpleNamespace(blocked=blocked, reason=reason)

    return calls, fake


def test_param_write_event_carries_every_field_to_the_firewall_and_counts_each_block() -> None:
    p, _ = policy()
    p.armed = True
    calls, fake = _recorder(True, "no param writes while armed")
    p.semantic_firewall.evaluate_param_write = fake  # type: ignore[method-assign]
    raw = _param_set()
    for _ in range(2):
        assert p.up(mk(raw, recv_ns=5_000_000_000)) == []
    assert p.dropped_semantic_param == 2 and p.dropped_semantic_fence == 0
    assert p.last_semantic_reason == "no param writes while armed"
    ev, kw = calls[0]
    assert (ev.recv_time, ev.sysid, ev.compid, ev.param_id, ev.source_kind) == (5.0, 255, 190, "SYSID_THISMAV", "param_set")
    assert ev.param_value == 42.0 and ev.param_type == apm.MAV_PARAM_TYPE_REAL32
    assert kw == {"armed": True}


def test_param_write_that_is_not_blocked_is_forwarded() -> None:
    p, _ = policy()
    calls, fake = _recorder(False)
    p.semantic_firewall.evaluate_param_write = fake  # type: ignore[method-assign]
    raw = _param_set()
    assert p.up(mk(raw)) == [raw]
    assert p.dropped_semantic_param == 0 and p.last_semantic_reason is None and len(calls) == 1


def test_fence_event_carries_every_field_to_the_firewall_and_counts_each_block() -> None:
    p, _ = policy()
    p.armed = True
    p._home_lat_lon = (19.1, 72.9)
    calls, fake = _recorder(True, "fence change refused")
    p.semantic_firewall.evaluate_fence_change = fake  # type: ignore[method-assign]
    raw = _fence_item()
    for _ in range(2):
        assert p.up(mk(raw, recv_ns=7_000_000_000)) == []
    assert p.dropped_semantic_fence == 2 and p.dropped_semantic_param == 0
    assert p.last_semantic_reason == "fence change refused"
    ev, kw = calls[0]
    assert (ev.recv_time, ev.sysid, ev.compid) == (7.0, 255, 190)
    assert ev.action == "fence_item"
    assert ev.count is None and ev.command == apm.MAV_CMD_NAV_FENCE_CIRCLE_INCLUSION and ev.radius_m == 50.0
    assert ev.lat_deg == pytest.approx(20.0) and ev.lon_deg == pytest.approx(73.0)
    assert ev.mission_type == 1
    assert kw == {"armed": True, "home_lat_lon": (19.1, 72.9)}


def test_semantic_firewall_is_skipped_by_the_receive_only_filter_and_when_disabled() -> None:
    p, _ = filter_policy()
    p.filter_state = "engaged"
    calls, fake = _recorder(True)
    p.semantic_firewall.evaluate_param_write = fake  # type: ignore[method-assign]
    raw = signed(_param_set(), now_ts())
    assert p.up(mk(raw)) == [raw]
    assert calls == [] and p.dropped_semantic_param == 0
    q, _ = policy(semantic_firewall_enabled=False)
    q.armed = True
    raw2 = _param_set()
    assert q.up(mk(raw2)) == [raw2]
    assert q.dropped_semantic_param == 0


def test_a_rule_that_raises_forwards_the_frame_and_counts_every_error(monkeypatch: pytest.MonkeyPatch) -> None:
    p, _ = policy()

    def boom(*a, **k):
        raise RuntimeError("x")

    monkeypatch.setattr(p, "_command_rule", boom)
    raw = command()
    assert p.up(mk(raw)) == [raw] and p.up(mk(raw)) == [raw]
    assert p.hook_errors == 2
    monkeypatch.setattr(p, "_learn_state", boom)
    hb = heartbeat()
    assert p.down(mk(hb, "down")) == [hb]
    assert p.hook_errors == 3


# -- contested source scoping --------------------------------------------------------------------------------------------------

def test_a_contested_identity_is_dropped_only_for_the_exact_sysid_and_compid() -> None:
    p, clock = policy(contested_policy="drop-sensitive")
    p.armed, p.rel_alt_m = True, 30.0
    a = command(cmd=MAV_CMD_DO_SET_MODE, p2=1.0)
    b = command(cmd=MAV_CMD_DO_SET_MODE, p2=2.0)
    p.up(mk(a, seq=9))
    assert p.up(mk(b, seq=9)) == []  # same (sysid, compid, seq), different payload: two transmitters
    assert p.is_contested(255, 190) and p.contested_events == 1
    other_comp = command(cmd=MAV_CMD_DO_SET_MODE, p2=3.0, comp=191)
    assert p.up(mk(other_comp, seq=10)) == [other_comp]
    assert p.dropped_contested == 1


# -- signature accounting --------------------------------------------------------------------------------------------------

def test_check_signature_return_values_and_counters_are_exact() -> None:
    p, _ = policy(signing_key=KEY)
    ts = now_ts()
    good = signed(command(), ts)
    assert p._check_signature(mk(good)) == "ok" and p.signed_ok == 1
    assert p._check_signature(mk(good)) == "replay"
    assert (p.dropped_replay, p.observed_replay) == (1, 0)
    assert p._check_signature(mk(good), observe=True) == "replay"
    assert (p.dropped_replay, p.observed_replay) == (1, 1)
    forged = signed(command(), ts + 5, key=bytes(range(1, 33)))
    for n in (1, 2):
        assert p._check_signature(mk(forged)) == "bad_signature"
        assert p.dropped_bad_signature == n
    for n in (1, 2):
        assert p._check_signature(mk(forged), observe=True) == "bad_signature"
        assert p.observed_bad_signature == n
    assert p.dropped_bad_signature == 2
    raw = command()
    for n in (1, 2):
        assert p._check_signature(mk(raw)) == "unsigned" and p.dropped_unsigned == n
    for n in (1, 2):
        assert p._check_signature(mk(raw), observe=True) == "unsigned" and p.observed_unsigned == n
    assert p.dropped_unsigned == 2


def test_max_age_boundary_and_counters(monkeypatch: pytest.MonkeyPatch) -> None:
    now = float(MAVLINK_EPOCH_UNIX_S) + 1000.0
    monkeypatch.setattr(time, "time", lambda: now)
    threshold = 99_000_000  # (now - epoch) * 1e5 - max_age * 1e5

    def fresh() -> InlinePolicy:
        return policy(signing_key=KEY, max_age_s=10.0)[0]

    assert fresh()._check_signature(mk(signed(command(), threshold))) == "ok"  # exactly at the limit is still fresh
    assert fresh()._check_signature(mk(signed(command(), threshold + 1))) == "ok"
    for ts in (threshold - 1, threshold - 5):  # just past the limit: needs the exact multiplier to be rejected
        p = fresh()
        assert p._check_signature(mk(signed(command(), ts))) == "replay"
        assert p.dropped_replay == 1 and p.observed_replay == 0 and p.signed_ok == 0
    # counters accumulate: stale frames with increasing timestamps reach the age check every time
    p = fresh()
    for n in (1, 2, 3):
        assert p._check_signature(mk(signed(command(p2=float(n)), threshold - 1000 + n))) == "replay"
        assert p.dropped_replay == n
    q = fresh()
    for n in (1, 2, 3):
        assert q._check_signature(mk(signed(command(p2=float(n)), threshold - 1000 + n)), observe=True) == "replay"
        assert q.observed_replay == n
    assert q.dropped_replay == 0


# -- command rule ------------------------------------------------------------------------------------------------------------

def test_burst_rule_is_judged_on_the_payload_not_the_header() -> None:
    p, clock = policy(cadence_s=1.0)
    a = command(p1=1.0)
    assert p.up(mk(a, seq=1)) == [a]
    b = command(p1=1.0)
    assert p.up(mk(b, seq=2)) == []  # same payload, new sequence number: still a repeat
    assert p.dropped_burst == 1
    c = command(p1=1.0000001)  # differs only in the first payload byte
    assert p.up(mk(c, seq=3)) == [c]


def test_burst_rule_sees_a_difference_in_the_last_payload_byte() -> None:
    p, clock = policy(cadence_s=1.0)
    a = command(confirmation=1)
    assert p.up(mk(a, seq=1)) == [a]
    b = command(confirmation=2)
    assert p.up(mk(b, seq=2)) == [b]
    assert p.dropped_burst == 0


def test_burst_rule_on_a_v1_frame_compares_the_whole_frame() -> None:
    p, _ = policy(cadence_s=1.0, provenance=False)
    a = command_v1()
    assert p.up(mk(a, seq=1)) == [a]
    assert p.up(mk(a, seq=2)) == []  # byte-identical v1 frame: a burst
    assert p.dropped_burst == 1
    b = command_v1(p1=2.0)
    assert p.up(mk(b, seq=3)) == [b]
    # v1 frames that differ only in their header/sequence byte are different frames (the v1 body is the whole raw)
    m = enc(255, 190, mav1)
    m.seq = 7
    c1 = bytes(m.command_long_encode(1, 1, MAV_CMD_DO_SET_MODE, 0, 5.0, 4.0, 0, 0, 0, 0, 0).pack(m))
    m.seq = 8
    c2 = bytes(m.command_long_encode(1, 1, MAV_CMD_DO_SET_MODE, 0, 5.0, 4.0, 0, 0, 0, 0, 0).pack(m))
    assert c1 != c2
    assert p.up(mk(c1)) == [c1]
    assert p.up(mk(c2)) == [c2]


def test_burst_window_is_exclusive_at_exactly_the_cadence() -> None:
    p, clock = policy(cadence_s=1.0, provenance=False)
    a = command()
    assert p.up(mk(a)) == [a]
    clock.t += 1.0
    assert p.up(mk(a)) == [a] and p.dropped_burst == 0
    clock.t += 0.999
    assert p.up(mk(a)) == [] and p.dropped_burst == 1


def test_last_command_table_is_bounded_at_exactly_256_keys() -> None:
    p, _ = policy()
    sizes = []
    for i in range(257):
        raw = command(comp=i % 256, cmd=MAV_CMD_DO_SET_MODE if i < 256 else MAV_CMD_COMPONENT_ARM_DISARM, p1=float(i % 7 + 1))
        p.up(mk(raw))
        sizes.append(len(p._last_cmd))
    assert sizes[254] == 255 and sizes[255] == 256 and sizes[256] == 256


def test_forced_disarm_in_flight_passes_and_plain_disarm_is_dropped() -> None:
    p, _ = policy()
    p.armed, p.rel_alt_m = True, 50.0
    plain = command(cmd=MAV_CMD_COMPONENT_ARM_DISARM, p1=0.0, p2=0.0)
    forced = command(cmd=MAV_CMD_COMPONENT_ARM_DISARM, p1=0.0, p2=FORCE_MAGIC)
    assert p.up(mk(plain)) == [] and p.dropped_inflight_disarm == 1
    assert p.up(mk(forced)) == [forced]
    arm = command(cmd=MAV_CMD_COMPONENT_ARM_DISARM, p1=1.0, p2=0.0)
    assert p.up(mk(arm)) == [arm]


def test_untrusted_sensitive_command_is_dropped_and_counted() -> None:
    p, _ = policy()
    assert p.up(mk(command(sysid=77))) == [] and p.dropped_untrusted_control == 1
    assert p.up(mk(set_mode(sysid=77))) == [] and p.dropped_untrusted_control == 2
