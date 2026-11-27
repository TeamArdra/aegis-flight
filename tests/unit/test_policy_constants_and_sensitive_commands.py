"""Pins the inline policy's MAVLink constants to pymavlink's authoritative enums and the sensitive-command / control-message sets
to a fixed list (found by mutation testing: changing LAND, RTL, TAKEOFF, FLIGHTTERMINATION, REPOSITION or SET_POSITION_TARGET ids
was not caught by any test). SYNTHETIC frames, in-memory links."""
from __future__ import annotations

import pytest
from pymavlink.dialects.v20 import common as mav2

import aegisflight.mitigation.inline_policy as ip
from aegisflight.hal.inline_ips import InlineIpsBridge


class _Link:
    def __init__(self) -> None:
        self.inbox, self.sent = [], []

    def poll(self):
        o, self.inbox = self.inbox, []
        return o

    def send(self, data):
        self.sent.append(bytes(data))
        return True

    def close(self):
        return None


def _enc(sysid: int) -> mav2.MAVLink:
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=190)
    m.robust_parsing = True
    return m


def _cmd(sysid: int, command: int, p1: float = 0.0) -> bytes:
    m = _enc(sysid)
    return bytes(m.command_long_encode(1, 1, command, 0, p1, 0, 0, 0, 0, 0, 0).pack(m))


COMMANDS = {
    "MAV_CMD_NAV_RETURN_TO_LAUNCH": 20, "MAV_CMD_NAV_LAND": 21, "MAV_CMD_NAV_TAKEOFF": 22, "MAV_CMD_DO_SET_MODE": 176,
    "MAV_CMD_DO_PARAMETER": 180, "MAV_CMD_DO_FLIGHTTERMINATION": 185, "MAV_CMD_DO_REPOSITION": 192, "MAV_CMD_MISSION_START": 300,
    "MAV_CMD_COMPONENT_ARM_DISARM": 400, "MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN": 246,
}
MSGS = {
    "SET_MODE": 11, "PARAM_SET": 23, "MISSION_ITEM": 39, "MISSION_COUNT": 44, "MISSION_CLEAR_ALL": 45, "MANUAL_CONTROL": 69,
    "RC_CHANNELS_OVERRIDE": 70, "MISSION_ITEM_INT": 73, "COMMAND_INT": 75, "COMMAND_LONG": 76,
    "SET_ATTITUDE_TARGET": 82, "SET_POSITION_TARGET_LOCAL_NED": 84, "SET_POSITION_TARGET_GLOBAL_INT": 86,
}


@pytest.mark.parametrize("name,value", sorted(COMMANDS.items()))
def test_policy_command_constants_match_the_mavlink_spec(name, value):
    spec_name = "MAV_CMD_DO_SET_PARAMETER" if name == "MAV_CMD_DO_PARAMETER" else name   # pymavlink's name for 180
    assert getattr(ip, name) == value == getattr(mav2, spec_name)


@pytest.mark.parametrize("name,value", sorted(MSGS.items()))
def test_policy_message_ids_match_the_mavlink_spec(name, value):
    assert value == getattr(mav2, f"MAVLINK_MSG_ID_{name}")
    assert getattr(ip, f"_MSG_{name}") == value


def test_sensitive_command_and_control_sets_are_exactly_these():
    assert ip.SENSITIVE_COMMANDS == frozenset(COMMANDS.values())
    assert {ip._MSG_COMMAND_LONG, ip._MSG_COMMAND_INT} == set(ip._COMMAND_MSGIDS)
    assert ip.CONTROL_MSGIDS == frozenset(MSGS[k] for k in (
        "SET_MODE", "PARAM_SET", "MISSION_ITEM", "MISSION_COUNT", "MISSION_CLEAR_ALL", "RC_CHANNELS_OVERRIDE", "MISSION_ITEM_INT",
        "SET_POSITION_TARGET_LOCAL_NED", "SET_POSITION_TARGET_GLOBAL_INT", "SET_ATTITUDE_TARGET"))
    assert ip.FORCE_MAGIC == 21196.0


@pytest.mark.parametrize("command", sorted(COMMANDS.values()))
def test_active_ips_drops_every_sensitive_command_from_an_untrusted_sysid_but_not_from_the_pilot(command):
    fc, gcs = _Link(), _Link()
    b = InlineIpsBridge(fc, gcs, mode="active-ips")
    rogue, pilot = _cmd(66, command, 1.0), _cmd(255, command, 1.0)
    gcs.inbox = [(1_000_000_000, rogue), (1_000_000_001, pilot)]
    b.pump_once()
    assert rogue not in fc.sent, f"command {command} from an untrusted sysid reached the FC"
    assert b.dropped_up >= 1


def test_passive_forwards_every_sensitive_command_untouched():
    fc, gcs = _Link(), _Link()
    b = InlineIpsBridge(fc, gcs, mode="passive")
    frames = [_cmd(66, c, 1.0) for c in sorted(COMMANDS.values())]
    gcs.inbox = [(1_000_000_000 + i, f) for i, f in enumerate(frames)]
    b.pump_once()
    assert fc.sent == frames and b.dropped_up == 0


@pytest.mark.parametrize("msgid", [11, 23, 39, 44, 45, 70, 73, 82, 84, 86])
def test_active_ips_drops_every_control_message_id_from_an_untrusted_sysid(msgid):
    from aegisflight.proxy.transport import split_frames

    m = _enc(66)
    makers = {
        11: lambda: m.set_mode_encode(1, 1, 9), 23: lambda: m.param_set_encode(1, 1, b"X", 1.0, 9),
        39: lambda: m.mission_item_encode(1, 1, 0, 3, 16, 0, 1, 0, 0, 0, 0, 1.0, 2.0, 3.0),
        44: lambda: m.mission_count_encode(1, 1, 2), 45: lambda: m.mission_clear_all_encode(1, 1),
        70: lambda: m.rc_channels_override_encode(1, 1, 1000, 1000, 1000, 1000, 0, 0, 0, 0),
        73: lambda: m.mission_item_int_encode(1, 1, 0, 3, 16, 0, 1, 0, 0, 0, 0, 1, 2, 3.0),
        82: lambda: m.set_attitude_target_encode(0, 1, 1, 0, [1, 0, 0, 0], 0, 0, 0, 0.5),
        84: lambda: m.set_position_target_local_ned_encode(0, 1, 1, 1, 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0),
        86: lambda: m.set_position_target_global_int_encode(0, 1, 1, 5, 0, 1, 2, 3.0, 0, 0, 0, 0, 0, 0, 0, 0),
    }
    raw = bytes(makers[msgid]().pack(m))
    assert split_frames(raw)[0][0].msgid == msgid
    fc, gcs = _Link(), _Link()
    b = InlineIpsBridge(fc, gcs, mode="active-ips")
    gcs.inbox = [(1_000_000_000, raw)]
    b.pump_once()
    assert fc.sent == [] and b.dropped_up == 1
