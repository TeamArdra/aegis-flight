"""Exact-behaviour tests for InlinePolicy's state: defaults, sequence tracker, downlink forgery, persistence, parsers."""

from __future__ import annotations

import json
import struct
import time
import zlib
from pathlib import Path

import pytest
from test_inline_policy_exact import (  # type: ignore[import-not-found]
    KEY,
    Clock,
    command,
    command_int,
    enc,
    gcs_heartbeat,
    gpi,
    heartbeat,
    mk,
    now_ts,
    policy,
    signed,
)

from aegisflight.mavlink.signing import MAVLINK_EPOCH_UNIX_S
from aegisflight.mitigation.inline_policy import (
    _V1,
    _V2,
    InlinePolicy,
    SeqProvenance,
    _command,
    _payload,
    _payload_crc32,
)
from aegisflight.proxy.hooks import FrameContext

# -- defaults ----------------------------------------------------------------------------------------------------------------


def test_constructor_defaults_are_exactly_the_documented_ones() -> None:
    p = InlinePolicy()
    assert p.trusted_sysids == {255, 254} and p.vehicle_sysids == {1}
    assert (p.cadence_s, p.dynamic_ttl_s, p.in_flight_alt_m, p.in_flight_speed_ms) == (0.05, 3.0, 2.0, 1.0)
    assert p.allow_unsigned_from_trusted is False and p.max_age_s is None and p._verifier is None
    assert (p.provenance, p.provenance_window, p.replay_memory) == (True, 16, 4096)
    assert (p.contested_policy, p.contested_hold_s, p.contested_alarm_interval_s) == ("alert", 60.0, 10.0)
    assert p.semantic_firewall.enabled is True
    assert p.enforce is False and p.uplink_filter_only is False and p.filter_override is False
    assert p.filter_state == "off" and p.lockout_failopen_s is None
    assert p._last_valid_t is None and p._engaged_t is None and p._lockout_drops == 0 and p.filter_events == []
    assert p._state_dirty is False and p._last_persist == 0.0 and p._state_path is None
    assert p._last_touch is None and p.armed is None and p.rel_alt_m is None and p.groundspeed_ms is None
    assert p._home_lat_lon is None and p.last_semantic_reason is None
    zeros = ["signed_ok", "dropped_unsigned", "dropped_bad_signature", "dropped_replay", "dropped_provenance",
             "suspect_provenance", "dropped_replay_unsigned", "resyncs", "contested_events", "dropped_contested",
             "contested_alarms", "dropped_untrusted_control", "dropped_inflight_disarm", "dropped_burst",
             "dropped_dynamic", "observed_unsigned", "observed_bad_signature", "observed_replay", "max_signed_ts",
             "dropped_forged_down", "observed_forged_down", "signing_lapsed", "rewritten", "hook_errors",
             "dropped_semantic_param", "dropped_semantic_fence"]
    assert {k: getattr(p, k) for k in zeros} == dict.fromkeys(zeros, 0)
    assert p.take_observed() == [] and p.take_alarms() == [] and p.take_filter_events() == []
    assert p.next_signing_timestamp() is None


def test_semantic_stats_and_observed_stats_have_exact_keys() -> None:
    p = InlinePolicy(semantic_firewall_enabled=False)
    p.last_semantic_reason = "why"
    p.dropped_semantic_param, p.dropped_semantic_fence = 3, 4
    assert p.semantic_stats() == {"enabled": False, "dropped_param": 3, "dropped_fence": 4, "last_reason": "why"}
    p.observed_unsigned, p.observed_bad_signature, p.observed_replay = 1, 2, 3
    p.observed_forged_down, p.dropped_forged_down = 4, 5
    assert p.observed_stats() == {"unsigned": 1, "bad_signature": 2, "replay": 3, "forged_down_observed": 4,
                                  "forged_down_dropped": 5}


def test_invalid_contested_policy_and_replay_memory_floor() -> None:
    with pytest.raises(ValueError, match="^contested_policy must be 'alert' or 'drop-sensitive'$"):
        InlinePolicy(contested_policy="nope")
    assert InlinePolicy(replay_memory=0).replay_memory == 1
    assert InlinePolicy(replay_memory=1).replay_memory == 1
    assert InlinePolicy(replay_memory=7).replay_memory == 7


def test_set_enforce_false_clears_the_tracking_tables_and_true_keeps_them() -> None:
    p, _ = policy(cadence_s=1.0)
    p.up(mk(command(), seq=1))
    assert p._last_cmd and p._seq and p._seen
    p.set_enforce(True)
    assert p._last_cmd and p._seq and p._seen
    p.set_enforce(False)
    assert not p._last_cmd and not p._seq and not p._seen and not p._recent and not p._alarms


def test_set_uplink_filter_only_resets_the_lockout_counter_and_is_idempotent() -> None:
    p, _ = policy(signing_key=KEY)
    p._lockout_drops = 5
    p.set_uplink_filter_only(True)
    assert p.filter_state == "learning" and p._lockout_drops == 0
    p._lockout_drops = 5
    p.set_uplink_filter_only(True)
    assert p._lockout_drops == 5
    p.set_uplink_filter_only(False)
    assert p.filter_state == "off" and p.uplink_filter_only is False


def test_note_valid_records_the_time_and_clears_the_drop_counter() -> None:
    p, clock = policy(signing_key=KEY)
    p._lockout_drops = 4
    clock.t = 321.0
    p._note_valid()
    assert p._last_valid_t == 321.0 and p._lockout_drops == 0


# -- SeqProvenance -------------------------------------------------------------------------------------------------------------


def test_seq_provenance_initial_state() -> None:
    t = SeqProvenance()
    assert (t.last, t.count, t.bad, t.window, t.resyncs, t.quiet_s, t.last_t) == (-1, 0, [], 16, 0, 2.0, 0.0)
    assert t.known is False


def test_seq_provenance_learns_after_three_consistent_frames_with_the_exact_window() -> None:
    t = SeqProvenance()
    assert [t.observe(s) for s in (10, 11, 12)] == ["unknown"] * 3 and t.known
    assert t.observe(12 + 16) == "consistent"  # exactly the window ahead
    assert t.observe(28 + 17) == "inconsistent"  # one past the window
    assert t.observe(28) == "inconsistent"  # not ahead at all
    t2 = SeqProvenance(window=16)
    for s in (10, 11, 12):
        t2.observe(s)
    assert t2.observe(12) == "inconsistent"  # (seq - last) % 256 == 0 is not forward progress


def test_seq_provenance_counts_only_runs_inside_the_window_while_learning() -> None:
    t = SeqProvenance()
    t.observe(10, 1.0)
    t.observe(26, 2.0)  # +16: inside the window, counts
    assert t.count == 2 and t.last == 26 and t.last_t == 2.0
    t.observe(26 + 17, 3.0)  # +17: outside, restarts the run
    assert t.count == 1 and t.last == 43
    t3 = SeqProvenance()
    t3.observe(5)
    t3.observe(5)  # +0 is not progress
    assert t3.count == 1


def test_seq_provenance_wraps_modulo_256() -> None:
    t = SeqProvenance()
    for s in (254, 255, 0):
        t.observe(s)
    assert t.known and t.observe(1) == "consistent"
    u = SeqProvenance()
    for s in (250, 251, 252):
        u.observe(s)
    assert u.observe(12) == "consistent"  # +16 across the wrap (a mod-257 counter would see +17)
    v = SeqProvenance()
    for s in (255, 0, 1):
        v.observe(s)
    assert v.observe(2) == "consistent"


def test_seq_provenance_bad_run_uses_the_same_window_and_modulus() -> None:
    t = SeqProvenance()
    for s in (10, 11, 12):
        t.observe(s, 0.0)
    assert t.observe(100, 0.1) == "inconsistent" and t.bad == [100]
    assert t.observe(100 + 16, 0.2) == "inconsistent" and t.bad == [100, 116]  # within the window of the last bad
    assert t.observe(116 + 17, 0.3) == "inconsistent" and t.bad == [133]  # past it: a new run
    t2 = SeqProvenance()
    for s in (10, 11, 12):
        t2.observe(s, 0.0)
    t2.observe(250, 0.1)
    t2.observe(10, 0.2)  # +16 from 250 across the wrap: inside the window of the last bad frame
    assert t2.bad == [250, 10]


def test_seq_provenance_resync_needs_three_and_the_quiet_period() -> None:
    t = SeqProvenance(quiet_s=2.0)
    for s in (10, 11, 12):
        t.observe(s, 0.0)
    assert t.observe(100, 1.0) == "inconsistent"
    assert t.observe(101, 1.5) == "inconsistent"
    assert t.observe(102, 1.9) == "inconsistent" and t.resyncs == 0  # live stream still within quiet_s
    assert t.observe(103, 2.0) == "consistent" and t.resyncs == 1  # exactly quiet_s since the last good frame
    assert t.last == 103 and t.last_t == 2.0 and t.bad == []
    assert t.observe(104, 2.1) == "consistent" and t.resyncs == 1
    # without a clock the quiet check is skipped
    u = SeqProvenance()
    for s in (10, 11, 12):
        u.observe(s)
    assert [u.observe(s) for s in (100, 101, 102)] == ["inconsistent", "inconsistent", "consistent"] and u.resyncs == 1
    assert u.last == 102 and u.last_t == 0.0
    # a second resync increments, not resets
    for s in (200, 201, 202):
        u.observe(s)
    assert u.resyncs == 2


def test_seq_provenance_consistent_frame_clears_the_bad_run_and_records_time() -> None:
    t = SeqProvenance()
    for s in (10, 11, 12):
        t.observe(s, 0.0)
    t.observe(100, 0.5)
    assert t.bad == [100]
    assert t.observe(13, 0.6) == "consistent" and t.bad == [] and t.last == 13 and t.last_t == 0.6


# -- downlink forgery ----------------------------------------------------------------------------------------------------------


def sv(ts: int, sysid: int = 1, comp: int = 1, key: bytes = KEY) -> bytes:
    return signed(heartbeat(sysid=sysid, comp=comp), ts, key)


def down_ctx(raw: bytes, recv_ns: int) -> FrameContext:
    return mk(raw, "down", recv_ns=recv_ns)


def sign_n(p: InlinePolicy, n: int, start_ts: int, recv_ns: int = 1_000_000_000, sysid: int = 1) -> int:
    ts = start_ts
    for _ in range(n):
        assert p._down_forged(down_ctx(sv(ts, sysid=sysid), recv_ns)) is None
        ts += 10
    return ts


def test_a_source_is_judged_only_after_twenty_valid_signed_frames() -> None:
    p, _ = policy(signing_key=KEY)
    ts = sign_n(p, 19, 1000)
    assert p._down_signed[(1, 1)] == 19
    assert p._down_forged(down_ctx(heartbeat(), 1_000_000_000)) is None  # 19 signed: still unjudged
    ts = sign_n(p, 1, ts)
    assert p._down_signed[(1, 1)] == 20
    assert p._down_forged(down_ctx(heartbeat(), 1_000_000_000)) == "unsigned"


def test_never_signing_sources_are_left_alone_and_other_sources_do_not_count() -> None:
    p, _ = policy(signing_key=KEY)
    assert p._down_forged(down_ctx(heartbeat(), 1)) is None
    sign_n(p, 25, 1000, sysid=7)
    assert p._down_forged(down_ctx(heartbeat(sysid=1), 1)) is None
    assert p._down_forged(down_ctx(heartbeat(sysid=7), 1)) == "unsigned"


def test_a_bad_signature_after_twenty_is_a_forgery_but_a_replay_or_foreign_key_unsigned_state_is_not() -> None:
    p, _ = policy(signing_key=KEY)
    ts = sign_n(p, 20, 1000)
    forged = sv(ts + 100, key=bytes(range(1, 33)))
    assert p._down_forged(down_ctx(forged, 1)) == "bad_signature"
    old = sv(1000)  # an old, already-seen timestamp: reordering, not forgery
    assert p._down_forged(down_ctx(old, 1)) is None
    # fewer than twenty valid frames: a bad signature is not yet a forgery
    q, _ = policy(signing_key=KEY)
    sign_n(q, 19, 1000)
    assert q._down_forged(down_ctx(sv(5000, key=bytes(range(1, 33))), 1)) is None


def test_the_signed_source_counter_stops_at_twenty_five() -> None:
    p, _ = policy(signing_key=KEY)
    sign_n(p, 40, 1000)
    assert p._down_signed[(1, 1)] == 25
    assert p.max_signed_ts == 1000 + 39 * 10


def test_signing_lapse_is_exactly_ten_seconds_and_is_reported_once() -> None:
    p, _ = policy(signing_key=KEY)
    t0 = 1_000_000_000
    ts = sign_n(p, 20, 1000, recv_ns=t0)
    boundary = down_ctx(heartbeat(), t0 + 10_000_000_000)
    assert p._down_forged(boundary) == "unsigned" and p.signing_lapsed == 0
    late = down_ctx(heartbeat(), t0 + 10_000_000_001)
    assert p._down_forged(late) is None  # judged afresh
    assert p.signing_lapsed == 1 and (1, 1) not in p._down_signed
    assert p.take_observed() == [("signing_lapsed", late.raw, 1, 0)]
    assert p._down_forged(down_ctx(heartbeat(), t0 + 11_000_000_000)) is None and p.signing_lapsed == 1
    assert ts > 0


def test_signing_lapse_reports_stop_at_sixty_four_pending_entries() -> None:
    p, _ = policy(signing_key=KEY)
    p._observed_pending = [("x", b"", 0, 0)] * 63
    t0 = 1_000_000_000
    sign_n(p, 20, 1000, recv_ns=t0)
    p._down_forged(down_ctx(heartbeat(), t0 + 20_000_000_000))
    assert len(p._observed_pending) == 64
    sign_n(p, 20, 9000, recv_ns=t0 + 30_000_000_000)
    p._down_forged(down_ctx(heartbeat(), t0 + 60_000_000_000))
    assert len(p._observed_pending) == 64 and p.signing_lapsed == 2


def test_down_signed_table_evicts_the_oldest_source_at_256() -> None:
    p, _ = policy(signing_key=KEY)
    for i in range(256):
        assert p._down_forged(down_ctx(sv(1000 + i, sysid=1 + (i % 250), comp=i // 250 + 1), 5)) is None
    assert len(p._down_signed) == 256 and len(p._down_signed_t) == 256
    first = next(iter(p._down_signed))
    assert p._down_forged(down_ctx(sv(9999, sysid=77, comp=77), 5)) is None
    assert len(p._down_signed) == 256 and first not in p._down_signed and first not in p._down_signed_t
    assert (77, 77) in p._down_signed
    # a known source at a full table evicts nothing
    known = next(iter(p._down_signed))
    keys = set(p._down_signed)
    assert p._down_forged(down_ctx(sv(10_000, sysid=known[0], comp=known[1]), 5)) is None
    assert set(p._down_signed) == keys


def test_down_enforcement_drops_forged_and_otherwise_only_observes() -> None:
    p, _ = policy(signing_key=KEY)
    sign_n(p, 20, 1000)
    raw = heartbeat()
    assert p.down(down_ctx(raw, 1)) == []
    assert (p.dropped_forged_down, p.observed_forged_down) == (1, 0)
    assert p.down(down_ctx(raw, 1)) == []
    assert p.dropped_forged_down == 2
    q, _ = policy(signing_key=KEY)
    q.set_enforce(False)
    sign_n(q, 20, 1000)
    for n in (1, 2):
        assert q.down(down_ctx(raw, 1)) == [raw] and q.observed_forged_down == n
    assert q.dropped_forged_down == 0
    assert q.take_observed() == [("unsigned", raw, 1, 0)] * 2
    r, _ = policy(signing_key=KEY)
    r.set_uplink_filter_only(True)
    sign_n(r, 20, 1000)
    assert r.down(down_ctx(raw, 1)) == [raw] and r.observed_forged_down == 1 and r.dropped_forged_down == 0


def test_down_observed_pending_is_capped_at_sixty_four() -> None:
    p, _ = policy(signing_key=KEY)
    p.set_enforce(False)
    sign_n(p, 20, 1000)
    raw = heartbeat()
    for _ in range(70):
        p.down(down_ctx(raw, 1))
    assert p.observed_forged_down == 70 and len(p.take_observed()) == 64


def test_down_error_counts_every_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    p, _ = policy()

    def boom(*a, **k):
        raise RuntimeError("x")

    monkeypatch.setattr(p, "_learn_state", boom)
    raw = heartbeat()
    assert p.down(down_ctx(raw, 1)) == [raw] and p.down(down_ctx(raw, 1)) == [raw]
    assert p.hook_errors == 2


# -- learnt vehicle state -------------------------------------------------------------------------------------------------------


def raw_heartbeat(base_mode: int, htype: int = 2, autopilot: int = 3, sysid: int = 1) -> bytes:
    m = enc(sysid, 1)
    return bytes(m.heartbeat_encode(htype, autopilot, base_mode, 4, 4).pack(m))


def test_heartbeat_arming_rules() -> None:
    p, _ = policy()
    p.down(mk(raw_heartbeat(0x80), "down"))
    assert p.armed is True
    p.down(mk(raw_heartbeat(0x00), "down"))
    assert p.armed is False
    p.down(mk(raw_heartbeat(0x81), "down"))
    assert p.armed is True  # bit 7 only matters
    p.down(mk(raw_heartbeat(0x01), "down"))
    assert p.armed is False
    p.down(mk(raw_heartbeat(0x00, htype=6), "down"))  # a GCS-type heartbeat from the vehicle sysid is ignored
    assert p.armed is False
    p.down(mk(raw_heartbeat(0x80, htype=6), "down"))
    assert p.armed is False
    p.down(mk(raw_heartbeat(0x80, autopilot=8), "down"))  # a peripheral heartbeat is ignored
    assert p.armed is False
    p.down(mk(raw_heartbeat(0x80, htype=5), "down"))
    assert p.armed is True
    p.down(mk(raw_heartbeat(0x00, sysid=9), "down"))  # other sysids never teach the policy
    assert p.armed is True


def test_heartbeat_armed_bit_is_exactly_0x80() -> None:
    p, _ = policy()
    p.down(mk(raw_heartbeat(0x7F), "down"))
    assert p.armed is False
    p.down(mk(raw_heartbeat(0x40), "down"))
    assert p.armed is False


def test_global_position_teaches_home_altitude_and_groundspeed() -> None:
    p, _ = policy()
    p.down(mk(gpi(lat=0.0, lon=0.0, rel_alt_m=3.0), "down"))
    assert p._home_lat_lon is None and p.rel_alt_m == 3.0  # (0, 0) is "no fix": not a home
    p.down(mk(gpi(lat=19.5, lon=0.0, rel_alt_m=3.0), "down"))
    assert p._home_lat_lon == (19.5, 0.0)  # a single non-zero coordinate is enough
    p2, _ = policy()
    p2.down(mk(gpi(lat=0.0, lon=72.25, rel_alt_m=3.0), "down"))
    assert p2._home_lat_lon == (0.0, 72.25)
    p2.down(mk(gpi(lat=20.0, lon=73.0, rel_alt_m=9.0), "down"))
    assert p2._home_lat_lon == (0.0, 72.25)  # first fix only
    assert p2.rel_alt_m == 9.0


def test_groundspeed_is_the_euclidean_norm_and_altitude_may_be_negative() -> None:
    p, _ = policy()
    m = enc(1, 1)
    raw = bytes(m.global_position_int_encode(1, 191_000_000, 729_000_000, 0, -1500, 300, 400, 0, 0).pack(m))
    p.down(mk(raw, "down"))
    assert p.groundspeed_ms == pytest.approx(5.0) and p.rel_alt_m == pytest.approx(-1.5)
    raw = bytes(m.global_position_int_encode(1, 191_000_000, 729_000_000, 0, 0, -300, 400, 0, 0).pack(m))
    p.down(mk(raw, "down"))
    assert p.groundspeed_ms == pytest.approx(5.0)
    assert p._home_lat_lon == (19.1, 72.9)


def test_in_flight_thresholds_are_strict() -> None:
    p, _ = policy()
    p.armed = True
    p.rel_alt_m, p.groundspeed_ms = 2.0, 1.0
    assert p.in_flight is False
    p.rel_alt_m = 2.01
    assert p.in_flight is True
    p.rel_alt_m, p.groundspeed_ms = 0.0, 1.01
    assert p.in_flight is True
    p.armed = False
    assert p.in_flight is False


# -- unsigned dual transmitter ----------------------------------------------------------------------------------------------------


def test_dual_transmitter_window_is_inclusive_at_two_seconds_and_ring_holds_32() -> None:
    p, clock = policy()
    a, b = command(p2=1.0), command(p2=2.0)
    p.up(mk(a, seq=5))
    clock.t += 2.0
    p.up(mk(b, seq=5))
    assert p.contested_events == 1  # exactly 2.0 s apart still counts
    q, c2 = policy()
    q.up(mk(a, seq=5))
    c2.t += 2.001
    q.up(mk(b, seq=5))
    assert q.contested_events == 0
    # the ring only remembers 32 frames
    r, c3 = policy()
    r.up(mk(command(p2=1.0), seq=200))
    for i in range(32):
        r.up(mk(command(p2=float(10 + i)), seq=i))
    r.up(mk(command(p2=99.0), seq=200))
    assert r.contested_events == 0
    s, c4 = policy()
    s.up(mk(command(p2=1.0), seq=200))
    for i in range(31):
        s.up(mk(command(p2=float(10 + i)), seq=i))
    s.up(mk(command(p2=99.0), seq=200))
    assert s.contested_events == 1


def test_contested_alarm_is_raised_once_per_interval_and_hold_is_exact() -> None:
    p, clock = policy(contested_hold_s=60.0, contested_alarm_interval_s=3.0)
    p.up(mk(command(p2=1.0), seq=7))
    p.up(mk(command(p2=2.0), seq=7))
    assert p.contested_alarms == 1 and p.take_alarms() == [255]
    clock.t += 1.5
    p.up(mk(command(p2=3.0), seq=7))
    assert p.contested_events == 2 and p.contested_alarms == 1 and p.take_alarms() == []
    clock.t += 1.5  # exactly the alarm interval since the last alarm
    p.up(mk(command(p2=4.0), seq=7))
    assert p.contested_alarms == 2 and p.take_alarms() == [255]
    assert p.is_contested(255) and p.is_contested(255, 190) and not p.is_contested(255, 191) and not p.is_contested(254)
    until = p._contested_until[(255, 190)]
    assert until == clock.t + 60.0
    clock.t = until - 0.001
    assert p.is_contested(255) and p.stats()["contested_sources"] == 1
    clock.t = until
    assert not p.is_contested(255) and p.stats()["contested_sources"] == 0


def test_a_fresh_contest_after_expiry_alarms_again_even_inside_the_interval() -> None:
    p, clock = policy(contested_hold_s=1.0, contested_alarm_interval_s=100.0)
    p.up(mk(command(p2=1.0), seq=7))
    p.up(mk(command(p2=2.0), seq=7))
    assert p.contested_alarms == 1
    clock.t += 1.0  # hold over exactly now: no longer contested
    p.up(mk(command(p2=3.0), seq=7))
    assert p.contested_alarms == 2


# -- observed signatures -------------------------------------------------------------------------------------------------------


def test_observe_signature_reports_everything_except_ok_and_allowed_unsigned() -> None:
    p, _ = policy(signing_key=KEY, allow_unsigned_from_trusted=True)
    p.set_enforce(False)
    raw = command(sysid=255)
    p.up(mk(raw))
    assert p.take_observed() == []  # trusted + allowed + unsigned
    other = command(sysid=77)
    p.up(mk(other))
    assert p.take_observed() == [("unsigned", other, 77, 76)]
    q, _ = policy(signing_key=KEY, allow_unsigned_from_trusted=False)
    q.set_enforce(False)
    q.up(mk(raw))
    assert q.take_observed() == [("unsigned", raw, 255, 76)]
    good = signed(command(sysid=255), now_ts())
    q.up(mk(good))
    assert q.take_observed() == [] and q.observed_unsigned == 1
    q.up(mk(gcs_heartbeat()))  # not a control frame: never judged
    assert q.take_observed() == [] and q.observed_unsigned == 1
    q.up(mk(command(cmd=31000)))
    assert q.take_observed() == []


def test_observe_signature_pending_is_capped_at_sixty_four() -> None:
    p, _ = policy(signing_key=KEY)
    p.set_enforce(False)
    for i in range(70):
        p.up(mk(command(sysid=77, p2=float(i))))
    assert len(p.take_observed()) == 64 and p.observed_unsigned == 70


def test_next_signing_timestamp_follows_the_newest_valid_frame() -> None:
    p, _ = policy(signing_key=KEY)
    assert p.next_signing_timestamp() is None
    p._check_signature(mk(signed(command(), 5000)))
    assert p.max_signed_ts == 5000 and p.next_signing_timestamp() == 5001
    p._check_signature(mk(signed(command(p2=1.0), 4000)))  # older: replayed, no change
    assert p.next_signing_timestamp() == 5001


def test_replay_filter_hashes_header_bytes_and_payload() -> None:
    p, _ = policy(cadence_s=0.0)
    a = command(p2=1.0)
    assert p.up(mk(a, seq=3)) == [a]
    assert p.up(mk(a, seq=3)) == []  # exact repeat
    assert p.dropped_replay_unsigned == 1
    assert p.up(mk(a, seq=4)) == [a]  # a new sequence number is a new frame
    b = command(p2=1.0, comp=191)
    assert p.up(mk(b, seq=3)) == [b]  # a different component is a different frame
    c = command(sysid=254, p2=1.0)
    assert p.up(mk(c, seq=3)) == [c]
    assert p.up(mk(a, seq=3 + 256)) == []  # the sequence number is truncated to 8 bits
    assert p.dropped_replay_unsigned == 2


def test_replay_memory_is_count_bounded() -> None:
    p, _ = policy(cadence_s=0.0, replay_memory=2)
    frames = [command(p2=float(i)) for i in range(4)]
    for i, f in enumerate(frames):
        assert p.up(mk(f, seq=i)) == [f]
    assert len(p._seen) == 2
    assert p.up(mk(frames[0], seq=0)) == [frames[0]]  # forgotten: forwarded again
    assert p.up(mk(frames[3], seq=3)) == [] and p.dropped_replay_unsigned == 1


# -- persistence -----------------------------------------------------------------------------------------------------------------


def test_signing_state_round_trips_through_the_state_file(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    p, clock = policy(signing_key=KEY, state_path=path)
    p._check_signature(mk(signed(command(), 777)))
    p.flush()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data == {"streams": {"0:255:190": 777}}
    assert not (tmp_path / "state.json.tmp").exists()
    q, _ = policy(signing_key=KEY, state_path=path)
    assert q._verifier._last_timestamps == {(0, 255, 190): 777}
    assert q._check_signature(mk(signed(command(p2=2.0), 777))) == "replay"
    assert q._check_signature(mk(signed(command(p2=2.0), 778))) == "ok"


def test_state_file_is_written_at_most_once_a_second_unless_flushed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "state.json"
    t = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: t[0])
    p, _ = policy(signing_key=KEY, state_path=path)
    assert p._state_dirty is False and p._last_persist == 0.0
    p._check_signature(mk(signed(command(), 100)))
    assert json.loads(path.read_text())["streams"]["0:255:190"] == 100 and p._last_persist == 1000.0
    assert p._state_dirty is False
    t[0] = 1000.5
    p._check_signature(mk(signed(command(p2=2.0), 200)))
    assert json.loads(path.read_text())["streams"]["0:255:190"] == 100  # throttled
    assert p._state_dirty is True and p._last_persist == 1000.0
    t[0] = 1001.0  # exactly one second: due
    p._check_signature(mk(signed(command(p2=3.0), 300)))
    assert json.loads(path.read_text())["streams"]["0:255:190"] == 300 and p._state_dirty is False
    t[0] = 1001.2
    p._check_signature(mk(signed(command(p2=4.0), 400)))
    assert json.loads(path.read_text())["streams"]["0:255:190"] == 300
    p.flush()
    assert json.loads(path.read_text())["streams"]["0:255:190"] == 400


def test_persistence_needs_a_path_a_key_and_a_dirty_flag(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    p, _ = policy(signing_key=KEY, state_path=path)
    p._state_dirty = False
    p._maybe_persist(force=True)
    assert not path.exists()
    q, _ = policy(signing_key=KEY)
    q._state_dirty = True
    q._maybe_persist(force=True)
    r, _ = policy(state_path=path)
    r._state_dirty = True
    r._maybe_persist(force=True)
    assert not path.exists()
    p._state_dirty = True
    p._maybe_persist()  # force defaults to False but the first write is never throttled
    assert path.exists()


@pytest.mark.parametrize("content", ["{not json", "[]", '{"streams": 5}', '{"streams": {"a:b:c": 1}}',
                                     '{"streams": {"0:1": 1}}', '{"streams": {"0:1:2": "x"}}', '{"streams": {"0:1:2": null}}'])
def test_a_corrupt_state_file_starts_clean_instead_of_crashing(tmp_path: Path, content: str) -> None:
    path = tmp_path / "state.json"
    path.write_text(content, encoding="utf-8")
    p, _ = policy(signing_key=KEY, state_path=path)
    assert p._verifier._last_timestamps == {}


def test_a_missing_state_file_and_unicode_content(tmp_path: Path) -> None:
    p, _ = policy(signing_key=KEY, state_path=tmp_path / "absent.json")
    assert p._verifier._last_timestamps == {}
    path = tmp_path / "state.json"
    path.write_bytes('{"streams": {"0:1:2": 5, "noteé": 1}}'.encode())
    q, _ = policy(signing_key=KEY, state_path=path)
    assert q._verifier._last_timestamps == {(0, 1, 2): 5}  # entries before the unreadable one are kept


def test_state_is_only_loaded_with_both_a_key_and_a_path(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text('{"streams": {"0:1:2": 5}}', encoding="utf-8")
    p, _ = policy(state_path=path)  # no key: nothing to load into
    assert p._verifier is None
    q, _ = policy(signing_key=KEY)
    assert q._verifier._last_timestamps == {}


# -- frame parsers -----------------------------------------------------------------------------------------------------------------


def v2(payload_len: int, total: int | None = None) -> bytes:
    n = 12 + payload_len if total is None else total
    return bytes([_V2, payload_len]) + bytes(range(1, n - 2 + 1))[: n - 2]


def test_payload_length_gates_and_padding() -> None:
    assert _payload(b"") is None
    assert _payload(bytes([_V2]) + b"\x00" * 10) is None  # 11 bytes: too short for v2
    short_v2 = bytes([_V2, 0]) + bytes(10)
    assert len(short_v2) == 12 and _payload(short_v2) == bytes(40)  # exactly 12: accepted, empty payload
    assert _payload(bytes([_V1, 0]) + bytes(5)) is None  # 7 bytes: too short for v1
    assert _payload(bytes([_V1, 0]) + bytes(6)) == bytes(40)  # exactly 8
    assert _payload(b"\x01" * 20) is None  # neither magic byte
    assert _payload(bytes([0x00]) + b"\x01" * 30) is None
    body = bytes(range(1, 8))
    raw = bytes([_V2, 7]) + bytes(8) + body + b"\xaa\xbb"
    assert _payload(raw) == body + bytes(40) and len(_payload(raw)) == 47
    raw1 = bytes([_V1, 7]) + bytes(4) + body + b"\xaa\xbb"
    assert _payload(raw1) == body + bytes(40)
    assert _payload(bytes([_V2, 0]) + bytes(10), 5) == bytes(40)  # the unused signed_len argument changes nothing


@pytest.mark.parametrize("raw", [
    b"", bytes([_V2]) + bytes(10), bytes([_V2, 0]) + bytes(10), bytes([_V2, 3]) + bytes(8) + b"abc" + b"zz",
    bytes([_V1]) + bytes(6), bytes([_V1, 0]) + bytes(6), bytes([_V1, 3]) + bytes(4) + b"abc" + b"zz",
    b"\x01" * 20, b"\x00", bytes([_V2, 5]) + bytes(8) + b"ab",
])
def test_payload_crc32_equals_the_crc_of_the_padded_payload(raw: bytes) -> None:
    assert _payload_crc32(raw) == zlib.crc32(_payload(raw) or raw)


def test_command_parsing_reads_unsigned_ids_and_both_command_messages() -> None:
    raw = command(cmd=40000, p1=1.5, p2=-2.5)
    assert _command(raw, 76) == (40000, 1.5, -2.5)
    assert _command(raw, 75) is not None
    assert _command(raw, 0) is None
    assert _command(b"", 76) is None
    m = enc(255, 190)
    ci = bytes(m.command_int_encode(1, 1, 0, 22, 0, 0, 3.0, 4.0, 0, 0, 0, 0, 0.0).pack(m))
    got = _command(ci, 75)
    assert got is not None and got[0] == 22 and struct.unpack("<2f", struct.pack("<2f", 3.0, 4.0)) == (got[1], got[2])
    assert command_int(255, 22)  # builder sanity


def test_payload_start_offsets_do_not_leak_into_the_next_field() -> None:
    raw = command(cmd=400, p1=0.0, p2=21196.0)
    assert _command(raw, 76) == (400, 0.0, 21196.0)
    assert Clock()() == 100.0
    assert MAVLINK_EPOCH_UNIX_S > 0


# -- additional boundary pins ----------------------------------------------------------------------------------------------------


def test_default_semantic_stats_report_enabled_and_default_filter_event_detail() -> None:
    assert InlinePolicy().semantic_stats()["enabled"] is True
    p, _ = policy()
    p._set_filter_state("engaged")
    assert p.take_filter_events() == [("engaged", "")]


def test_engaged_watchdog_counts_a_forged_non_control_frame_as_observed_not_dropped() -> None:
    p, _ = policy(signing_key=KEY)
    p.set_uplink_filter_only(True)
    p.lockout_failopen_s = 30.0
    assert p.up(mk(signed(command(), now_ts()))) != []
    forged = signed(gcs_heartbeat(), now_ts() + 50, key=bytes(range(1, 33)))
    assert p.up(mk(forged)) == [forged]
    assert p.observed_bad_signature == 1 and p.dropped_bad_signature == 0


def test_seq_provenance_learning_phase_wraps_modulo_256() -> None:
    t = SeqProvenance()
    t.observe(250)
    t.observe(10)  # +16 across the wrap: inside the window
    assert t.count == 2
    u = SeqProvenance()
    u.observe(250)
    u.observe(11)  # +17: outside it
    assert u.count == 1


def test_after_a_lapse_the_source_is_relearned_from_one() -> None:
    p, _ = policy(signing_key=KEY)
    t0 = 1_000_000_000
    sign_n(p, 20, 1000, recv_ns=t0)
    late = t0 + 20_000_000_000
    assert p._down_forged(down_ctx(sv(9000), late)) is None  # the lapse is detected by a valid signed frame
    assert p.signing_lapsed == 1 and p._down_signed[(1, 1)] == 1


def _v1_heartbeat_ctx(length: int) -> FrameContext:
    raw = bytes([_V1, length - 8]) + bytes(length - 2)
    assert len(raw) == length
    return FrameContext("down", raw, 1, 1, 1, 0, 0, False)


@pytest.mark.parametrize("length,learns", [(11, False), (12, True), (13, True)])
def test_heartbeat_state_is_learnt_only_from_frames_of_at_least_twelve_bytes(length: int, learns: bool) -> None:
    p, _ = policy()
    assert p.down(_v1_heartbeat_ctx(length)) == [_v1_heartbeat_ctx(length).raw]
    assert p.armed is (False if learns else None)


def test_command_int_ids_above_32767_stay_unsigned() -> None:
    m = enc(255, 190)
    raw = bytes(m.command_int_encode(1, 1, 0, 40000, 0, 0, 0, 0, 0, 0, 0, 0, 0.0).pack(m))
    got = _command(raw, 75)
    assert got is not None and got[0] == 40000


def test_a_mission_count_reaches_the_firewall_with_its_count() -> None:
    from types import SimpleNamespace

    from pymavlink.dialects.v20 import ardupilotmega as apm

    p, _ = policy()
    seen: list = []

    def fake(event, **kw):
        seen.append(event)
        return SimpleNamespace(blocked=True, reason="count")

    p.semantic_firewall.evaluate_fence_change = fake  # type: ignore[method-assign]
    m = apm.MAVLink(file=None, srcSystem=255, srcComponent=190)
    raw = bytes(apm.MAVLink_mission_count_message(1, 1, 3, 1).pack(m))
    assert p.up(mk(raw)) == []
    assert (seen[0].action, seen[0].count, seen[0].mission_type) == ("upload_fence", 3, 1)


def test_persisting_into_a_missing_directory_is_swallowed(tmp_path: Path) -> None:
    p, _ = policy(signing_key=KEY, state_path=tmp_path / "no" / "such" / "state.json")
    assert p._check_signature(mk(signed(command(), 500))) == "ok"
    assert p._state_dirty is False  # the attempt was made and its failure ignored


def test_state_file_is_replaced_atomically_through_a_tmp_sibling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    calls: list[tuple[str, str]] = []
    real = os.replace
    monkeypatch.setattr(os, "replace", lambda a, b: (calls.append((str(a), str(b))), real(a, b))[1])
    path = tmp_path / "state.json"
    p, _ = policy(signing_key=KEY, state_path=path)
    p._check_signature(mk(signed(command(), 500)))
    assert calls == [(str(path) + ".tmp", str(path))]


def test_a_timestamp_replay_is_counted_as_observed_every_time() -> None:
    p, _ = policy(signing_key=KEY)
    good = signed(command(), 5000)
    assert p._check_signature(mk(good)) == "ok"
    for n in (1, 2, 3):
        assert p._check_signature(mk(good), observe=True) == "replay"
        assert p.observed_replay == n
    assert p.dropped_replay == 0
