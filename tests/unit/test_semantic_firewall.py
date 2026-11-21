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

    # 3D-fix GPS_RAW_INT + vehicle heartbeat (armed) + GPI -> learns armed=True and the arming-time home
    raw_gps = _pack(
        apm.MAVLink_gps_raw_int_message(1000, 3, int(19.1334 * 1e7), int(72.9133 * 1e7), 50000, 100, 100, 0, 0, 10),
        1, 1, seq=0,
    )
    pol.down(FrameContext("down", raw_gps, 900_000_000, 1, 1, 0, 24, False))
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


# ---- R13: fence home-exclusion is armed-only and uses a trustworthy home ------------------------------------------- #

def _fence_circle_item(lat: float, lon: float, radius: float = 50.0) -> bytes:
    return _pack(
        apm.MAVLink_mission_item_int_message(
            1, 1, 0, apm.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
            apm.MAV_CMD_NAV_FENCE_CIRCLE_INCLUSION, 0, 1, radius, 0, 0, 0,
            int(lat * 1e7), int(lon * 1e7), 50.0, 1,
        ),
        sysid=255, compid=190,
    )


def _policy() -> InlinePolicy:
    pol = InlinePolicy(FrameSanitizer(), trusted_sysids=(255,), vehicle_sysids=(1,), semantic_firewall_enabled=True)
    pol.set_enforce(True)
    return pol


_SEQ = [100]


def _down(pol: InlinePolicy, msg: object, msgid: int, t_s: float) -> None:
    _SEQ[0] += 1
    raw = _pack(msg, 1, 1, seq=_SEQ[0] % 256)
    pol.down(FrameContext("down", raw, int(t_s * 1e9), 1, 1, _SEQ[0] % 256, msgid, False))


def _gps3d(pol, lat, lon, t_s, fix=3):
    _down(pol, apm.MAVLink_gps_raw_int_message(1000, fix, int(lat * 1e7), int(lon * 1e7), 50000, 100, 100, 0, 0, 10), 24, t_s)


def _gpi(pol, lat, lon, t_s):
    _down(pol, apm.MAVLink_global_position_int_message(1000, int(lat * 1e7), int(lon * 1e7), 50000, 40000, 0, 0, 0, 0), 33, t_s)


def _hb(pol, armed: bool, t_s):
    _down(pol, apm.MAVLink_heartbeat_message(2, 3, 0x01 | (0x80 if armed else 0), 5, 4, 3), 0, t_s)


def _up_fence(pol, lat, lon, t_s):
    raw = _fence_circle_item(lat, lon)
    return pol.up(FrameContext("up", raw, int(t_s * 1e9), 255, 190, 7, 73, False))


def test_disarmed_inclusion_circle_away_from_first_fix_is_forwarded() -> None:
    pol = _policy()
    _hb(pol, False, 1.0)
    _gps3d(pol, 19.1334, 72.9133, 1.1)
    _gpi(pol, 19.1334, 72.9133, 1.2)  # first fix of the session (the old "home")
    assert pol._home_lat_lon is None  # a first fix is never home
    out = _up_fence(pol, 20.0, 73.0, 2.0)  # ~150 km away: would have been fence_excludes_home before
    assert len(out) == 1
    assert pol.semantic_stats()["dropped_fence"] == 0
    # the firewall itself also ignores the home rule when not armed, even with a home supplied
    parsed = extract_mission_fence_raw(_fence_circle_item(20.0, 73.0), 73)
    assert parsed is not None
    fw = SemanticFirewall(enabled=True)
    assert not fw.evaluate_fence_change(FenceChangeEvent(1.0, 255, 190, *parsed), armed=False,
                                        home_lat_lon=(19.1334, 72.9133)).blocked
    assert not fw.evaluate_fence_change(FenceChangeEvent(1.0, 255, 190, *parsed), armed=None,
                                        home_lat_lon=(19.1334, 72.9133)).blocked


def test_armed_inclusion_circle_excluding_home_is_blocked_home_from_arming_position() -> None:
    pol = _policy()
    _hb(pol, False, 1.0)
    _gps3d(pol, 19.1334, 72.9133, 1.1)
    _gpi(pol, 19.1334, 72.9133, 1.2)
    _hb(pol, True, 2.0)  # arming transition: position + fresh 3D fix -> home
    assert pol._home_lat_lon == (19.1334, 72.9133) and pol._home_src == "arming"
    assert _up_fence(pol, 20.0, 73.0, 3.0) == []  # excludes home -> blocked
    assert pol.semantic_stats()["dropped_fence"] == 1
    assert len(_up_fence(pol, 19.1334, 72.9133, 3.5)) == 1  # circle that contains home -> forwarded


def test_arming_without_a_3d_fix_gives_no_home_and_the_rule_stays_off() -> None:
    pol = _policy()
    _gps3d(pol, 19.1334, 72.9133, 1.1, fix=2)  # 2D fix only
    _gpi(pol, 19.1334, 72.9133, 1.2)
    _hb(pol, True, 2.0)
    assert pol._home_lat_lon is None
    assert len(_up_fence(pol, 20.0, 73.0, 3.0)) == 1  # no trustworthy home -> not judged
    _gps3d(pol, 19.1334, 72.9133, 3.1, fix=3)  # fix arrives while armed -> next position becomes home
    _gpi(pol, 19.1334, 72.9133, 3.2)
    assert pol._home_lat_lon == (19.1334, 72.9133)
    assert _up_fence(pol, 20.0, 73.0, 4.0) == []


def test_home_position_message_is_used_and_not_overwritten_at_arming() -> None:
    pol = _policy()
    _hb(pol, False, 1.0)
    _gps3d(pol, 10.0, 10.0, 1.1)
    _gpi(pol, 10.0, 10.0, 1.2)  # a (wrong) first fix far from the real home
    _down(pol, apm.MAVLink_home_position_message(int(19.1334 * 1e7), int(72.9133 * 1e7), 50000, 0, 0, 0,
                                                 [1, 0, 0, 0], 0, 0, 0), 242, 1.5)
    assert pol._home_lat_lon == (19.1334, 72.9133) and pol._home_src == "home_position"
    _hb(pol, True, 2.0)
    assert pol._home_lat_lon == (19.1334, 72.9133)  # the arming fallback does not replace HOME_POSITION
    assert _up_fence(pol, 10.0, 10.0, 3.0) == []  # excludes the real home -> blocked
    assert len(_up_fence(pol, 19.1334, 72.9133, 3.5)) == 1


def test_home_from_non_vehicle_sysid_is_ignored() -> None:
    pol = _policy()
    raw = _pack(apm.MAVLink_home_position_message(int(19.0 * 1e7), int(72.0 * 1e7), 0, 0, 0, 0, [1, 0, 0, 0], 0, 0, 0),
                99, 1, seq=1)
    pol.down(FrameContext("down", raw, 1_000_000_000, 99, 1, 1, 242, False))
    assert pol._home_lat_lon is None
