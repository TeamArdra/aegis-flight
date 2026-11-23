"""Unit tests for the Airborne Semantic Firewall (W1)."""

from __future__ import annotations

from pymavlink.dialects.v20 import ardupilotmega as apm

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


def _pack(msg: object, sysid: int, compid: int, seq: int = 1) -> bytes:
    m = apm.MAVLink(file=None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    return bytes(msg.pack(m))


def test_extract_and_block_protected_param_while_armed() -> None:
    fw = SemanticFirewall(enabled=True)
    raw = _pack(
        apm.MAVLink_param_set_message(1, 1, b"SYSID_THISMAV", 42.0, apm.MAV_PARAM_TYPE_REAL32),
        sysid=255,
        compid=190,
    )
    parsed = extract_param_set_raw(raw)
    assert parsed is not None
    pid, pval, ptype = parsed
    assert pid == "SYSID_THISMAV"
    ev = ParamWriteEvent(1.0, 255, 190, pid, pval, ptype)

    v_disarmed = fw.evaluate_param_write(ev, armed=False)
    assert not v_disarmed.blocked

    v_armed = fw.evaluate_param_write(ev, armed=True)
    assert v_armed.blocked
    assert "SYSID_THISMAV" in v_armed.reason

    safe_raw = _pack(
        apm.MAVLink_param_set_message(1, 1, b"MIS_DIST_MAX", 500.0, apm.MAV_PARAM_TYPE_REAL32),
        sysid=255,
        compid=190,
    )
    parsed_safe = extract_param_set_raw(safe_raw)
    assert parsed_safe is not None
    assert not fw.evaluate_param_write(ParamWriteEvent(1.2, 255, 190, *parsed_safe), armed=True).blocked


def test_block_geofence_clear_and_exclusion_of_home_while_armed() -> None:
    fw = SemanticFirewall(enabled=True)
    clear_raw = _pack(apm.MAVLink_mission_clear_all_message(1, 1, 1), sysid=255, compid=190)
    parsed_clr = extract_mission_fence_raw(clear_raw, 45)
    assert parsed_clr is not None and parsed_clr[0] == "clear_fence" and parsed_clr[1] == 1
    ev_clr = FenceChangeEvent(1.0, 255, 190, *parsed_clr)
    assert fw.evaluate_fence_change(ev_clr, armed=True).blocked

    # Regular waypoint clear (mission_type=0) is not blocked as geofence mutation
    wp_clr = _pack(apm.MAVLink_mission_clear_all_message(1, 1, 0), sysid=255, compid=190)
    parsed_wp = extract_mission_fence_raw(wp_clr, 45)
    assert parsed_wp is not None
    assert not fw.evaluate_fence_change(FenceChangeEvent(1.1, 255, 190, *parsed_wp), armed=True).blocked

    # Armed fence waypoint far from home triggers home-exclusion block (>10 km away)
    item_raw = _pack(
        apm.MAVLink_mission_item_int_message(
            1, 1, 0, apm.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
            apm.MAV_CMD_NAV_FENCE_CIRCLE_INCLUSION, 0, 1, 50.0, 0, 0, 0,
            int(20.0 * 1e7), int(73.0 * 1e7), 50.0, 1,
        ),
        sysid=255,
        compid=190,
    )
    parsed_item = extract_mission_fence_raw(item_raw, 73)
    assert parsed_item is not None
    verdict = fw.evaluate_fence_change(
        FenceChangeEvent(1.2, 255, 190, *parsed_item),
        armed=True,
        home_lat_lon=(19.1334, 72.9133),
    )
    assert verdict.blocked


def test_inline_policy_enforces_semantic_firewall_and_captures_home() -> None:
    pol = InlinePolicy(FrameSanitizer(), trusted_sysids=(255,), vehicle_sysids=(1,), semantic_firewall_enabled=True)
    pol.set_enforce(True)

    # First vehicle heartbeat (armed) + GPI -> learns armed=True and home
    hb = _pack(apm.MAVLink_heartbeat_message(2, 3, 0x81 | 0x80, 5, 4, 3), 1, 1, seq=1)
    pol.down(FrameContext("down", hb, 1_000_000_000, 1, 1, 1, 0, False))
    gpi = _pack(
        apm.MAVLink_global_position_int_message(1000, int(19.1334 * 1e7), int(72.9133 * 1e7), 50000, 40000, 0, 0, 0, 0),
        1, 1, seq=2,
    )
    pol.down(FrameContext("down", gpi, 1_100_000_000, 1, 1, 2, 33, False))
    assert pol._home_lat_lon is not None

    # Armed protected parameter write is dropped pre-FC even from trusted sysid
    pset = _pack(apm.MAVLink_param_set_message(1, 1, b"BRD_SAFETYENABLE", 0.0, 9), 255, 190, seq=3)
    out = pol.up(FrameContext("up", pset, 1_200_000_000, 255, 190, 3, 23, False))
    assert out == []
    assert pol.semantic_stats()["dropped_param"] == 1


def test_fence_home_exclusion_only_blocks_while_armed() -> None:
    """R13: a disarmed or arm-unknown fence plan that excludes the first-seen position is not a hijack."""
    fw = SemanticFirewall(enabled=True, block_when_arm_unknown=True)
    item_raw = _pack(
        apm.MAVLink_mission_item_int_message(
            1, 1, 0, apm.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
            apm.MAV_CMD_NAV_FENCE_CIRCLE_INCLUSION, 0, 1, 50.0, 0, 0, 0,
            int(20.0 * 1e7), int(73.0 * 1e7), 50.0, 1,
        ),
        sysid=255,
        compid=190,
    )
    parsed = extract_mission_fence_raw(item_raw, 73)
    assert parsed is not None
    ev = FenceChangeEvent(1.2, 255, 190, *parsed)
    home = (19.1334, 72.9133)
    assert fw.evaluate_fence_change(ev, armed=False, home_lat_lon=home).blocked is False
    assert fw.evaluate_fence_change(ev, armed=None, home_lat_lon=home).blocked is False
    assert fw.evaluate_fence_change(ev, armed=True, home_lat_lon=home).blocked is True


def test_armed_signed_param_set_is_dropped() -> None:
    """A legitimately signed PARAM_SET (e.g. FS_GCS_ENABLE) is dropped while armed."""
    pol = InlinePolicy(FrameSanitizer(), trusted_sysids=(255,), vehicle_sysids=(1,), semantic_firewall_enabled=True)
    pol.set_enforce(True)

    hb = _pack(apm.MAVLink_heartbeat_message(2, 3, 0x81 | 0x80, 5, 4, 3), 1, 1, seq=1)
    pol.down(FrameContext("down", hb, 1_000_000_000, 1, 1, 1, 0, True))

    pset = _pack(apm.MAVLink_param_set_message(1, 1, b"FS_GCS_ENABLE", 0.0, 9), 255, 190, seq=2)
    out = pol.up(FrameContext("up", pset, 1_100_000_000, 255, 190, 2, 23, True))
    assert out == []
    assert pol.semantic_stats()["dropped_param"] == 1


def test_arm_unknown_param_set_blocked_when_configured() -> None:
    """When armed=None, block_when_arm_unknown=True fails closed on protected PARAM_SET."""
    from aegisflight.mitigation.semantic_firewall import ParamWriteEvent

    ev = ParamWriteEvent(recv_time=1.0, sysid=255, compid=190, param_id="FS_GCS_ENABLE", param_value=0.0, param_type=9)
    fw_strict = SemanticFirewall(enabled=True, block_when_arm_unknown=True)
    fw_permissive = SemanticFirewall(enabled=True, block_when_arm_unknown=False)

    assert fw_strict.evaluate_param_write(ev, armed=None).blocked is True
    assert fw_permissive.evaluate_param_write(ev, armed=None).blocked is False
