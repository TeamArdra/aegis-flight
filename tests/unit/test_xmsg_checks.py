"""Cross-message consistency checks (battery SYS_STATUS vs BATTERY_STATUS, attitude repeat, VFR_HUD heading vs ATTITUDE yaw)."""

from __future__ import annotations

import math

import pytest
from pymavlink.dialects.v20 import ardupilotmega as apm

from aegisflight.config import load_config
from aegisflight.core.types import MessageEnvelope
from aegisflight.detectors.physics import PhysicsDetector
from aegisflight.features.extractor import FeatureExtractor

_IDS = {c.msgname: i for i, c in apm.mavlink_map.items()}
_UNUSED = [65535] * 6


def env(t: float, name: str, **fields) -> MessageEnvelope:
    return MessageEnvelope(recv_time=t, sysid=1, compid=1, msgid=_IDS[name], msgname=name, seq=0, signed=False,
                           byte_len=30, fields=fields)


def sys_status(t: float, mv: int) -> MessageEnvelope:
    return env(t, "SYS_STATUS", voltage_battery=mv, battery_remaining=80, current_battery=100)


def batt_status(t: float, cells: list[int], bid: int = 0) -> MessageEnvelope:
    return env(t, "BATTERY_STATUS", id=bid, voltages=cells + [65535] * (10 - len(cells)))


def attitude(t: float, roll: float = 0.01, yaw: float = 0.5) -> MessageEnvelope:
    return env(t, "ATTITUDE", roll=roll, pitch=-0.02, yaw=yaw, rollspeed=0.0, pitchspeed=0.0, yawspeed=0.0)


def vfr(t: float, heading: int) -> MessageEnvelope:
    return env(t, "VFR_HUD", groundspeed=0.0, heading=heading, throttle=0, alt=10.0, climb=0.0, airspeed=0.0)


@pytest.fixture
def live():
    return PhysicsDetector(load_config("configs/ardupilot_copter").detector["physics"])


def run(det: PhysicsDetector, msgs: list[MessageEnvelope], t: float):
    ex = FeatureExtractor()
    for m in msgs:
        ex.update(m)
    fr = ex.extract(t)
    return fr, det.process(fr)


def flagged(res, needle: str) -> bool:
    return any(needle in e for e in res.evidence)


def test_battery_messages_agree(live):
    fr, res = run(live, [sys_status(1.0, 15000), batt_status(1.0, [3750] * 4)], 1.2)
    assert fr.batt_msg_diff_v == pytest.approx(0.0)
    assert not flagged(res, "BATTERY_STATUS")


def test_battery_step_in_one_message_is_flagged(live):
    fr, res = run(live, [sys_status(1.0, 12000), batt_status(1.0, [3750] * 4)], 1.2)
    assert fr.batt_msg_diff_v == pytest.approx(3.0)
    assert flagged(res, "BATTERY_STATUS")
    assert live.process(fr).score >= 0.55  # the detector's persistence rule releases the full score on the second tick


def test_pack_voltage_in_first_field_and_unused_fields(live):
    fr, _ = run(live, [sys_status(1.0, 15091), batt_status(1.0, [15091])], 1.2)
    assert fr.batt_msg_diff_v == pytest.approx(0.0)  # 65535 = field not in use, not a 65 V cell


def test_resting_voltage_offset_stays_inside_the_tolerance(live):
    fr, res = run(live, [sys_status(1.0, 15600), batt_status(1.0, [3750] * 4)], 1.2)  # +0.6 V, as a resting-voltage option gives
    assert fr.batt_msg_diff_v == pytest.approx(0.6)
    assert not flagged(res, "BATTERY_STATUS")


def test_only_sys_status_is_inert(live):
    fr, res = run(live, [sys_status(1.0, 12000)], 1.2)
    assert fr.batt_msg_diff_v is None and not flagged(res, "BATTERY_STATUS")


def test_secondary_battery_is_ignored(live):
    fr, _ = run(live, [sys_status(1.0, 15000), batt_status(1.0, [2000] * 2, bid=1)], 1.2)
    assert fr.batt_msg_diff_v is None


def test_stale_pair_is_not_compared(live):
    fr, _ = run(live, [sys_status(10.0, 12000), batt_status(1.0, [3750] * 4)], 10.2)
    assert fr.batt_msg_diff_v is None


def test_attitude_repeat_counts_and_flags(live):
    msgs = [attitude(0.1 * i, roll=0.01) for i in range(10)]  # 10 bit-identical attitudes = 9 repeats
    fr, res = run(live, msgs, 1.0)
    assert fr.att_repeat == 9
    assert flagged(res, "ATTITUDE repeated")
    assert live.process(fr).score >= 0.6


def test_a_few_identical_attitudes_are_not_enough(live):
    fr, res = run(live, [attitude(0.1 * i) for i in range(7)], 0.8)  # 6 repeats < 8
    assert fr.att_repeat == 6 and not flagged(res, "ATTITUDE repeated")


def test_varying_attitude_never_flags(live):
    fr, res = run(live, [attitude(0.1 * i, roll=0.01 * math.sin(i)) for i in range(40)], 4.1)
    assert fr.att_repeat == 0 and not flagged(res, "ATTITUDE repeated")


def test_attitude_repeat_resets_when_the_value_changes(live):
    msgs = [attitude(0.1 * i) for i in range(6)] + [attitude(0.6, roll=0.2)] + [attitude(0.7)]
    fr, _ = run(live, msgs, 0.9)
    assert fr.att_repeat == 0


def test_heading_matches_yaw(live):
    fr, res = run(live, [attitude(1.0, yaw=math.radians(30)), vfr(1.0, 30)], 1.1)
    assert fr.heading_yaw_diff_deg == pytest.approx(0.0, abs=1e-6) and not flagged(res, "heading")


def test_heading_rewritten_is_flagged(live):
    fr, res = run(live, [attitude(1.0, yaw=math.radians(30)), vfr(1.0, 120)], 1.1)
    assert fr.heading_yaw_diff_deg == pytest.approx(90.0)
    assert flagged(res, "VFR_HUD heading")


def test_heading_wraps_around_north(live):
    fr, res = run(live, [attitude(1.0, yaw=math.radians(-0.6)), vfr(1.0, 359)], 1.1)  # yaw 359.4 deg vs heading 359
    assert fr.heading_yaw_diff_deg == pytest.approx(0.4, abs=1e-6) and not flagged(res, "heading")


def test_checks_are_off_in_the_default_config():
    det = PhysicsDetector(load_config().detector["physics"])
    fr, res = run(det, [attitude(0.1 * i) for i in range(12)] + [sys_status(1.0, 12000), batt_status(1.0, [3750] * 4)], 1.3)
    assert fr.att_repeat >= 8 and fr.batt_msg_diff_v is not None  # the features exist ...
    assert not flagged(res, "ATTITUDE repeated") and not flagged(res, "BATTERY_STATUS")  # ... but no rule reads them
