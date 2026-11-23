"""Fix-up tests for #114: armed-state-unknown re-check and policy pins of ProtocolDetector."""

from aegisflight.core.types import AttackType, TelemetrySnapshot
from aegisflight.detectors.protocol import ProtocolDetector
from aegisflight.features.extractor import CommandEvent, FeatureFrame

_FORCE = (0.0, 21196.0, 0.0, 0.0, 0.0, 0.0, 0.0)
_PLAIN = (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)


def _frame(*, armed: bool | None, t: float, cmd_t: float, params: tuple[float, ...]) -> FeatureFrame:
    """A frame at time ``t`` whose sliding window still holds a command received at ``cmd_t``."""
    snap = TelemetrySnapshot(t=t, armed=armed, groundspeed=0.0, rel_alt=10.0)
    cmd = CommandEvent(recv_time=cmd_t, sysid=255, compid=190, command=400, params=params)
    return FeatureFrame(t=t, snapshot=snap, commands_recent=(cmd,))


def test_force_disarm_is_rechecked_once_armed_state_becomes_known_true() -> None:
    """A disarm that arrives while armed is False (stale heartbeat) must not be consumed.

    Heartbeats are ~1 Hz. A command can land right after the vehicle armed but before the next
    heartbeat flips ``snap.armed``. It stays in the 2 s command window, so the next decision,
    which sees armed=True, must evaluate it.
    """
    det = ProtocolDetector({})
    first = det.process(_frame(armed=False, t=10.0, cmd_t=10.0, params=_FORCE))
    assert AttackType.COMMAND_INJECTION not in first.attack_votes  # armed False: nothing to flag yet
    second = det.process(_frame(armed=True, t=10.5, cmd_t=10.0, params=_FORCE))
    assert second.attack_votes.get(AttackType.COMMAND_INJECTION, 0.0) >= 0.95
    assert any("force-disarm" in e for e in second.evidence)


def test_force_disarm_is_rechecked_when_armed_state_unknown_then_true() -> None:
    det = ProtocolDetector({})
    first = det.process(_frame(armed=None, t=10.0, cmd_t=10.0, params=_FORCE))
    assert AttackType.COMMAND_INJECTION not in first.attack_votes
    second = det.process(_frame(armed=True, t=10.5, cmd_t=10.0, params=_FORCE))
    assert second.attack_votes.get(AttackType.COMMAND_INJECTION, 0.0) >= 0.95


def test_rechecked_force_disarm_alerts_once_not_on_every_decision() -> None:
    det = ProtocolDetector({})
    det.process(_frame(armed=False, t=10.0, cmd_t=10.0, params=_FORCE))
    fired = det.process(_frame(armed=True, t=10.5, cmd_t=10.0, params=_FORCE))
    again = det.process(_frame(armed=True, t=11.0, cmd_t=10.0, params=_FORCE))
    assert AttackType.COMMAND_INJECTION in fired.attack_votes
    assert AttackType.COMMAND_INJECTION not in again.attack_votes


def test_armed_command_is_still_consumed_after_one_evaluation() -> None:
    """Existing behaviour: a command seen while armed alerts once, not on every window slide."""
    det = ProtocolDetector({})
    first = det.process(_frame(armed=True, t=10.0, cmd_t=10.0, params=_FORCE))
    second = det.process(_frame(armed=True, t=10.5, cmd_t=10.0, params=_FORCE))
    assert AttackType.COMMAND_INJECTION in first.attack_votes
    assert AttackType.COMMAND_INJECTION not in second.attack_votes


def test_disarm_while_disarmed_and_staying_disarmed_never_alerts() -> None:
    det = ProtocolDetector({})
    for t in (10.0, 10.5, 11.0, 11.5):
        res = det.process(_frame(armed=False, t=t, cmd_t=10.0, params=_FORCE))
        assert AttackType.COMMAND_INJECTION not in res.attack_votes


def test_pending_recheck_is_dropped_when_command_leaves_the_window() -> None:
    """The re-check is bounded by the command window; it never outlives the command."""
    det = ProtocolDetector({})
    det.process(_frame(armed=False, t=10.0, cmd_t=10.0, params=_FORCE))
    assert det._disarm_pending
    snap = TelemetrySnapshot(t=13.0, armed=True, groundspeed=0.0, rel_alt=10.0)
    det.process(FeatureFrame(t=13.0, snapshot=snap, commands_recent=()))  # command aged out
    assert not det._disarm_pending


def test_policy_pin_legitimate_gcs_emergency_stop_alarms_by_default() -> None:
    """POLICY PIN (maintainer decision pending, not a bug fix).

    A force-disarm (param2=21196) from an EXPECTED GCS (sysid 255) while armed scores
    COMMAND_INJECTION 0.95 under the default profile and is NOT gated by
    ``cadence_guard_enabled``. A genuine GCS emergency stop therefore alarms. Changing this is
    a policy change; this test documents the current behaviour.
    """
    det = ProtocolDetector({})  # default profile: cadence_guard_enabled False
    assert det.cadence_guard_enabled is False
    res = det.process(_frame(armed=True, t=10.0, cmd_t=10.0, params=_FORCE))
    assert res.attack_votes.get(AttackType.COMMAND_INJECTION) == 0.95
    assert any("force-disarm" in e and "sys255" in e for e in res.evidence)


def test_policy_pin_non_force_inflight_disarm_is_off_by_default() -> None:
    """The plain (non-force) in-flight disarm check only runs with ``cadence_guard_enabled``."""
    off = ProtocolDetector({}).process(_frame(armed=True, t=10.0, cmd_t=10.0, params=_PLAIN))
    assert AttackType.COMMAND_INJECTION not in off.attack_votes
    on = ProtocolDetector({"cadence_guard_enabled": True}).process(
        _frame(armed=True, t=10.0, cmd_t=10.0, params=_PLAIN)
    )
    assert on.attack_votes.get(AttackType.COMMAND_INJECTION) == 0.95
