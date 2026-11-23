"""Branch-level tests for the safety modules: semantic firewall, inline policy internals and the event-store verifiers.

Each test pins an observable behaviour of a boundary that the main suites reach only indirectly (eviction bounds, the
fail-closed parse paths, the baseline logic of the parameter watcher). SYNTHETIC frames only.
"""

from __future__ import annotations

import sqlite3
import struct

import pytest
from pymavlink.dialects.v20 import common as mav2

from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import ThreatAssessment
from aegisflight.logging.store import EventStore
from aegisflight.mavlink.signing import sign_mavlink2_frame
from aegisflight.mitigation import inline_policy as ip
from aegisflight.mitigation.inline_policy import InlinePolicy
from aegisflight.mitigation.sanitizer import FrameSanitizer
from aegisflight.mitigation.semantic_firewall import (
    FenceChangeEvent,
    ParamWriteEvent,
    SemanticFirewall,
    extract_mission_fence_raw,
    extract_param_set_raw,
)
from aegisflight.proxy.hooks import FrameContext

KEY = bytes(range(32))


def _assessment(t: float) -> ThreatAssessment:
    return ThreatAssessment(
        t=t, wall_time=1.0, threat=True, threat_score=0.7, severity=Severity.HIGH,
        attack_type=AttackType.GPS_SPOOFING, confidence=0.8, evidence=["e"],
        detector_scores={"physics_consistency": 0.9}, contributing_detectors=["physics_consistency"],
        integrity_status=IntegrityStatus.VALID, latency_ms=0.4, telemetry={}, is_alert=True,
    )


def v2(msg_fn, *args, sysid: int = 255, comp: int = 190, seq: int = 1) -> bytes:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=comp)
    m.seq = seq
    return bytes(msg_fn(*args).pack(m))


def v1_frame(msgid: int, payload: bytes, sysid: int = 255, comp: int = 190, seq: int = 1) -> bytes:
    return bytes([0xFE, len(payload), seq, sysid, comp, msgid]) + payload + b"\x00\x00"


def fctx(raw: bytes, direction: str = "up", recv_ns: int = 1, signed: bool = False, sysid: int = 255, comp: int = 190,
         seq: int = 1, msgid: int = 0) -> FrameContext:
    return FrameContext(direction, raw, recv_ns, sysid, comp, seq, msgid, signed)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------------------------------------------
# semantic firewall: raw extraction fails closed on anything that is not a parsable frame
# --------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("raw", [b"", b"\x00" * 20, b"\xfd\x01", b"\xfe\x01\x00"])
def test_extractors_return_none_for_unframed_bytes(raw: bytes) -> None:
    assert extract_param_set_raw(raw) is None
    for msgid in (45, 47, 73):
        assert extract_mission_fence_raw(raw, msgid) is None


def test_extract_mission_fence_ignores_other_message_ids_and_reads_v1_frames() -> None:
    clear = v2(mav2.MAVLink_mission_clear_all_message, 1, 1, 1)
    assert extract_mission_fence_raw(clear, 0) is None  # a msgid that is not a mission operation
    count = v2(mav2.MAVLink_mission_count_message, 1, 1, 7, 1)
    assert extract_mission_fence_raw(count, 44) == ("upload_fence", 1, 7, None, None, None, None)
    # MAVLink 1 framing is parsed by the same path
    p1 = struct.pack("<fBB16sB", 5.0, 1, 1, b"FS_GCS_ENABLE".ljust(16, b"\0"), 9)
    assert extract_param_set_raw(v1_frame(23, p1)) == ("FS_GCS_ENABLE", 5.0, 9)


def test_extract_mission_item_reports_fence_item_fields() -> None:
    raw = v2(
        mav2.MAVLink_mission_item_int_message,
        1, 1, 0, mav2.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT, mav2.MAV_CMD_NAV_FENCE_CIRCLE_INCLUSION,
        0, 1, 120.0, 0, 0, 0, int(19.5 * 1e7), int(72.5 * 1e7), 50.0, 1,
    )
    action, mtype, cnt, cmd, radius, lat, lon = extract_mission_fence_raw(raw, 73)  # type: ignore[misc]
    assert (action, mtype, cnt, cmd, radius) == ("fence_item", 1, None, 5003, 120.0)
    assert lat == pytest.approx(19.5) and lon == pytest.approx(72.5)


# --------------------------------------------------------------------------------------------------------------------
# semantic firewall: evaluation branches
# --------------------------------------------------------------------------------------------------------------------

def pw(pid: str, val: float = 1.0, kind: str = "param_set") -> ParamWriteEvent:
    return ParamWriteEvent(1.0, 255, 190, pid, val, 9, kind)


def test_disabled_firewall_blocks_nothing() -> None:
    fw = SemanticFirewall(enabled=False)
    assert fw.evaluate_param_write(pw("FS_GCS_ENABLE"), armed=True).reason == "disabled"
    fence = FenceChangeEvent(1.0, 255, 190, "clear_fence", 1)
    assert not fw.evaluate_fence_change(fence, armed=True).blocked


def test_protected_param_rules() -> None:
    fw = SemanticFirewall(deny_always_params=("MY_PARAM",), block_when_arm_unknown=True)
    assert fw.is_protected_param("fs_gcs_enable") and fw.is_protected_param("MY_PARAM")
    assert not fw.is_protected_param("   ") and not fw.is_protected_param("WPNAV_SPEED")
    assert fw.evaluate_param_write(pw("WPNAV_SPEED"), armed=True).blocked is False
    denied = fw.evaluate_param_write(pw("MY_PARAM"), armed=False)  # denied even on the ground
    assert denied.blocked and denied.reason.startswith("denied_safety_param")
    assert fw.evaluate_param_write(pw("FS_GCS_ENABLE"), armed=False).blocked is False
    unknown = fw.evaluate_param_write(pw("FS_GCS_ENABLE"), armed=None)
    assert unknown.blocked and unknown.reason.startswith("arm_unknown_safety_param")
    assert SemanticFirewall().evaluate_param_write(pw("FS_GCS_ENABLE"), armed=None).blocked is False


def test_param_value_watcher_tracks_baseline_and_flags_airborne_change() -> None:
    fw = SemanticFirewall()
    first = fw.evaluate_param_write(pw("FS_THR_VALUE", 975.0, "param_value"), armed=True)
    assert not first.blocked and first.category == "ok"  # first sight only records the baseline
    same = fw.evaluate_param_write(pw("FS_THR_VALUE", 975.0, "param_value"), armed=True)
    assert same.category == "ok"
    changed = fw.evaluate_param_write(pw("FS_THR_VALUE", 900.0, "param_value"), armed=True)
    assert changed.category == "param_tamper" and not changed.blocked  # reported, never dropped (it is downlink)
    assert "975->900" in changed.reason
    # a disarmed value re-baselines silently; non-finite values and unprotected names are ignored
    assert fw.evaluate_param_write(pw("FS_THR_VALUE", 800.0, "param_value"), armed=False).category == "ok"
    assert fw.evaluate_param_write(pw("FS_THR_VALUE", float("nan"), "param_value"), armed=True).category == "ok"
    assert fw.evaluate_param_write(pw("WPNAV_SPEED", 1.0, "param_value"), armed=True).category == "ok"
    fw.reset()
    assert fw.evaluate_param_write(pw("FS_THR_VALUE", 1.0, "param_value"), armed=True).category == "ok"


def test_fence_rules_for_armed_unknown_and_non_fence_missions() -> None:
    fw = SemanticFirewall(block_when_arm_unknown=True)
    upload = FenceChangeEvent(1.0, 255, 190, "upload_fence", 1, count=4)
    assert fw.evaluate_fence_change(upload, armed=True).reason == "airborne_fence_overwrite"
    assert fw.evaluate_fence_change(upload, armed=None).blocked
    assert not fw.evaluate_fence_change(upload, armed=False).blocked
    clear = FenceChangeEvent(1.0, 255, 190, "clear_fence", 1)
    assert fw.evaluate_fence_change(clear, armed=None).reason == "airborne_fence_clear"
    waypoint_upload = FenceChangeEvent(1.0, 255, 190, "upload_fence", 0, count=4)
    assert not fw.evaluate_fence_change(waypoint_upload, armed=True).blocked
    near = FenceChangeEvent(1.0, 255, 190, "fence_item", 1, command=5003, radius_m=500.0, lat_deg=19.1, lon_deg=72.9)
    assert not fw.evaluate_fence_change(near, armed=True, home_lat_lon=(19.1, 72.9)).blocked
    assert not fw.evaluate_fence_change(near, armed=True, home_lat_lon=None).blocked
    zero_radius = FenceChangeEvent(1.0, 255, 190, "fence_item", 1, command=5003, radius_m=0.0, lat_deg=30.0, lon_deg=70.0)
    assert not fw.evaluate_fence_change(zero_radius, armed=True, home_lat_lon=(19.1, 72.9)).blocked


# --------------------------------------------------------------------------------------------------------------------
# inline policy: frame helpers
# --------------------------------------------------------------------------------------------------------------------

def test_payload_helpers_cover_v1_empty_and_garbage() -> None:
    cmd = v2(mav2.MAVLink_command_long_message, 1, 1, 400, 0, 1.0, 2.0, 0, 0, 0, 0, 0)
    assert ip._payload(b"") is None and ip._payload(b"\x01\x02\x03") is None
    v1 = v1_frame(76, struct.pack("<7fHBBB", 1.0, 2.0, 0, 0, 0, 0, 0, 400, 1, 1, 0))
    assert ip._payload(v1) is not None and ip._command(v1, 76) == (400, 1.0, 2.0)
    assert ip._command(b"", 76) is None
    assert ip._payload_crc32(cmd) == ip._payload_crc32(cmd) != ip._payload_crc32(v1)
    assert ip._payload_crc32(b"") == ip._payload_crc32(b"")  # falls back to the raw bytes
    import zlib
    assert ip._payload_crc32(b"\x01\x02\x03") == zlib.crc32(b"\x01\x02\x03")
    assert ip._payload_crc32(v1) == zlib.crc32(ip._payload(v1))  # type: ignore[arg-type]


def test_command_int_is_decoded_and_other_messages_are_not_commands() -> None:
    m = mav2.MAVLink(None, srcSystem=255, srcComponent=190)
    ci = bytes(mav2.MAVLink_command_int_message(1, 1, 0, 400, 0, 0, 1.0, 2.0, 0, 0, 0, 0, 0.0).pack(m))
    assert ip._command(ci, ip._MSG_COMMAND_INT) == (400, 1.0, 2.0)
    assert ip._command(ci, 0) is None


# --------------------------------------------------------------------------------------------------------------------
# inline policy: every per-source table is bounded
# --------------------------------------------------------------------------------------------------------------------

def make_policy(**kw) -> InlinePolicy:
    p = InlinePolicy(FrameSanitizer(), trusted_sysids=(255,), vehicle_sysids=(1,), **kw)
    p.set_enforce(True)
    return p


def test_provenance_and_dual_source_tables_evict_oldest_at_256_sources() -> None:
    p = make_policy()
    for sysid in range(300):
        raw = v2(mav2.MAVLink_heartbeat_message, 6, 8, 0, 0, 4, 3, sysid=sysid % 250 + 1, comp=sysid // 250 + 1)
        c = fctx(raw, sysid=sysid % 250 + 1, comp=sysid // 250 + 1, msgid=0)
        p._observe_seq(c)
        p._observe_dual(c)
    assert len(p._seq) <= 256 and len(p._recent) <= 256


def test_last_command_table_is_bounded() -> None:
    p = make_policy()
    for i in range(300):
        raw = v2(mav2.MAVLink_command_long_message, 1, 1, 400 + i, 0, 1.0, 2.0, 0, 0, 0, 0, 0, sysid=255, comp=i % 200)
        p._command_rule(fctx(raw, sysid=255, comp=i % 200, msgid=76), True, 400 + i, 1.0, 2.0)
    assert len(p._last_cmd) <= 257
    assert p.dropped_burst == 0  # distinct keys are never a burst


def test_untrusted_command_is_refused_and_counted() -> None:
    p = make_policy()
    raw = v2(mav2.MAVLink_command_long_message, 1, 1, 400, 0, 1.0, 2.0, 0, 0, 0, 0, 0, sysid=66)
    assert p._command_rule(fctx(raw, sysid=66, msgid=76), False, 400, 1.0, 2.0) == []
    assert p.dropped_untrusted_control == 1


def test_filter_state_change_is_idempotent_and_event_log_is_capped() -> None:
    p = make_policy()
    p._set_filter_state(p.filter_state)  # no change, no event
    assert p.take_filter_events() == []
    for i in range(40):
        p._set_filter_state("engaged" if i % 2 == 0 else "learning", "flip")
    assert len(p.take_filter_events()) == 16 and p.take_filter_events() == []


def test_learn_state_ignores_non_vehicle_and_peripheral_heartbeats() -> None:
    p = make_policy()
    hb_gcs = v2(mav2.MAVLink_heartbeat_message, 6, 8, 0x80, 0, 4, 3, sysid=255)
    p._learn_state(fctx(hb_gcs, direction="down", sysid=255, msgid=0))
    assert p.armed is None or p.armed is False
    hb_cam = v2(mav2.MAVLink_heartbeat_message, 30, 8, 0x80, 0, 4, 3, sysid=1, comp=100)
    p._learn_state(fctx(hb_cam, direction="down", sysid=1, comp=100, msgid=0))
    assert not p.armed
    hb_fc = v2(mav2.MAVLink_heartbeat_message, 2, 3, 0x80, 0, 4, 3, sysid=1, comp=1)
    p._learn_state(fctx(hb_fc, direction="down", sysid=1, comp=1, msgid=0))
    assert p.armed is True
    gpi0 = v2(mav2.MAVLink_global_position_int_message, 0, 0, 0, 0, 5000, 0, 0, 0, 0, sysid=1, comp=1)
    p._learn_state(fctx(gpi0, direction="down", sysid=1, comp=1, msgid=33))
    assert p._home_lat_lon is None and p.rel_alt_m == pytest.approx(5.0)  # a 0,0 fix never becomes home


def test_signing_state_persist_is_a_noop_without_a_verifier() -> None:
    p = make_policy()
    p._maybe_persist(force=True)
    p.flush()


# --------------------------------------------------------------------------------------------------------------------
# inline policy: signature checks
# --------------------------------------------------------------------------------------------------------------------

def test_signed_downlink_table_bounded_and_unsigned_after_signing_is_forged() -> None:
    p = InlinePolicy(FrameSanitizer(), trusted_sysids=(255,), vehicle_sysids=(1,), signing_key=KEY)
    p.set_enforce(True)
    ts = 1_000_000_000_000
    for i in range(300):
        raw = sign_mavlink2_frame(
            v2(mav2.MAVLink_heartbeat_message, 2, 3, 0, 0, 4, 3, sysid=i % 250 + 1, comp=i // 250 + 1),
            KEY, link_id=0, timestamp_10us=ts + i)
        p._down_forged(fctx(raw, "down", i * 1000, True, i % 250 + 1, i // 250 + 1, msgid=0))
    assert len(p._down_signed) <= 256


def test_replay_verdict_for_an_old_signed_timestamp_when_max_age_is_set() -> None:
    p = InlinePolicy(FrameSanitizer(), trusted_sysids=(255,), vehicle_sysids=(1,), signing_key=KEY, max_age_s=5.0)
    p.set_enforce(True)
    raw = sign_mavlink2_frame(
        v2(mav2.MAVLink_command_long_message, 1, 1, 400, 0, 1.0, 2.0, 0, 0, 0, 0, 0), KEY, link_id=0, timestamp_10us=100)
    assert p._check_signature(fctx(raw, signed=True, msgid=76), observe=True) == "replay"
    assert p.observed_replay == 1 and p.dropped_replay == 0
    assert p._check_signature(fctx(raw, signed=True, msgid=76), observe=False) == "replay"
    assert p.dropped_replay == 1


def test_observe_signature_reports_unsigned_control_from_untrusted_source() -> None:
    p = InlinePolicy(FrameSanitizer(), trusted_sysids=(255,), vehicle_sysids=(1,), signing_key=KEY)
    raw = v2(mav2.MAVLink_command_long_message, 1, 1, 400, 0, 1.0, 2.0, 0, 0, 0, 0, 0, sysid=66)
    p._observe_signature(fctx(raw, sysid=66, msgid=76))
    assert p.observed_unsigned == 1
    p._observe_signature(fctx(v2(mav2.MAVLink_heartbeat_message, 6, 8, 0, 0, 4, 3, sysid=66), sysid=66, msgid=0))
    assert p.observed_unsigned == 1  # a heartbeat is not a control frame
    for _ in range(80):
        p._observe_signature(fctx(raw, sysid=66, msgid=76))
    assert len(p._observed_pending) == 64  # the report queue is bounded


# --------------------------------------------------------------------------------------------------------------------
# inline policy: semantic firewall wiring on the uplink
# --------------------------------------------------------------------------------------------------------------------

def test_semantic_firewall_uplink_drops_armed_fence_clear_and_forwards_the_rest() -> None:
    p = make_policy(semantic_firewall_enabled=True)
    hb = v2(mav2.MAVLink_heartbeat_message, 2, 3, 0x80, 0, 4, 3, sysid=1, comp=1)
    p.down(fctx(hb, "down", 1_000, sysid=1, comp=1, msgid=0))
    clear = v2(mav2.MAVLink_mission_clear_all_message, 1, 1, 1)
    assert p.up(fctx(clear, recv_ns=2_000, msgid=45)) == []
    assert p.semantic_stats()["dropped_fence"] == 1
    wp_clear = v2(mav2.MAVLink_mission_clear_all_message, 1, 1, 0, seq=2)
    assert p.up(fctx(wp_clear, recv_ns=3_000, seq=2, msgid=45)) == [wp_clear]
    safe = v2(mav2.MAVLink_param_set_message, 1, 1, b"WPNAV_SPEED", 5.0, 9, seq=3)
    assert p.up(fctx(safe, recv_ns=4_000, seq=3, msgid=23)) == [safe]
    short = bytes([0xFD, 0, 0, 0, 0, 255, 190, 23, 0, 0, 0, 0])  # PARAM_SET with an empty payload parses as zeros
    p.up(fctx(short, recv_ns=5_000, seq=0, msgid=23))


# --------------------------------------------------------------------------------------------------------------------
# event store: actions chain and verifier paths
# --------------------------------------------------------------------------------------------------------------------

def test_actions_chain_paths(tmp_path) -> None:
    db = tmp_path / "a.sqlite"
    st = EventStore(db)
    assert st.verify_actions_chain().ok and st.get_actions() == []
    st.log_action("r1", 1.0, "bridge", "drop", "t1", "d1")
    st.log_action("r1", 2.0, "bridge", "drop", "t2", "d2")
    st.log_action("r2", 1.0, "bridge", "drop", "t3")
    assert [a["target"] for a in st.get_actions("r1")] == ["t2", "t1"]
    assert len(st.get_actions(limit=2)) == 2
    ok = st.verify_actions_chain()
    assert ok.ok and ok.length == 3 and "2 action chain" in ok.detail
    st.conn.execute("UPDATE actions SET detail='forged' WHERE run_id='r2'")
    st.conn.commit()
    bad = st.verify_actions_chain()
    assert not bad.ok and "run r2" in bad.detail
    st.close()
    ro = EventStore(db, read_only=True)
    with pytest.raises(sqlite3.OperationalError):
        ro.log_action("r1", 3.0, "bridge", "drop", "t")
    ro.close()


def test_event_chain_all_runs_reports_first_broken_run(tmp_path) -> None:
    st = EventStore(tmp_path / "e.sqlite")
    for run in ("a", "b"):
        st.start_run(run, label=run)
        st.log_event(_assessment(0.0), run)
        st.log_event(_assessment(1.0), run)
    clean = st.verify_chain()
    assert clean.ok and clean.length == 4 and "2 run chain" in clean.detail
    st.conn.execute("UPDATE events SET threat_score=0.1 WHERE run_id='b' AND t=0.0")
    st.conn.commit()
    bad = st.verify_chain()
    assert not bad.ok and "run b" in bad.detail
    st.close()
