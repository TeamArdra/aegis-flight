"""Paired regression tests for ConstDet netem seq-gap/reorder guard."""

from __future__ import annotations

from aegisflight.core.types import FlightState
from aegisflight.detectors.physics import PhysicsDetector
from aegisflight.features.extractor import FeatureFrame


def _make_detector() -> PhysicsDetector:
    return PhysicsDetector(
        {
            "control_semantics_enabled": True,
            "control_accel_residual_ms2": 4.5,
        }
    )


def _make_frame(
    *,
    t: float,
    control_accel_residual_ms2: float,
    max_seq_gap: int = 0,
    reorder_count: int = 0,
) -> FeatureFrame:
    snap = FlightState(
        t=t,
        lat=0.0,
        lon=0.0,
        alt_msl=10.0,
        rel_alt=10.0,
        vx=0.0,
        vy=0.0,
        vz=0.0,
        groundspeed=0.0,
        vertical_speed=0.0,
        ax=0.0,
        ay=0.0,
        az=0.0,
        roll=0.0,
        pitch=0.0,
        yaw=0.0,
        rollspeed=0.0,
        pitchspeed=0.0,
        yawspeed=0.0,
        heading=0.0,
        throttle=0.5,
        battery_voltage=16.0,
        battery_remaining=80.0,
        satellites=10,
        gps_fix_type=3,
        hdop=1.0,
        baro_alt=10.0,
        flight_mode="GUIDED",
        armed=True,
        mission_seq=0,
    )
    return FeatureFrame(
        t=t,
        snapshot=snap,
        max_seq_gap=max_seq_gap,
        reorder_count=reorder_count,
        control_accel_residual_ms2=control_accel_residual_ms2,
    )


def test_constdet_true_accel_spike_still_alerts() -> None:
    """An injected true acceleration residual spike with clean link still alerts."""
    det = _make_detector()
    res = det.process(_make_frame(t=1.0, control_accel_residual_ms2=10.0))
    assert "control_accel_residual_ms2" in res.signals
    assert res.score > 0.0
    assert any("ConstDet" in e for e in res.evidence)


def test_constdet_netem_seq_gap_and_reorder_suppressed() -> None:
    """Netem seq-gap and reordered frames do not trigger ConstDet false alarms."""
    det = _make_detector()

    # Case 1: seq-gap present (e.g. packet loss)
    res_gap = det.process(_make_frame(t=1.0, control_accel_residual_ms2=15.0, max_seq_gap=2))
    assert "control_accel_residual_ms2" not in res_gap.signals
    assert not any("ConstDet" in e for e in res_gap.evidence)

    # Case 2: packet reorder occurred (reorder_count incremented)
    res_reorder = det.process(
        _make_frame(t=1.1, control_accel_residual_ms2=15.0, max_seq_gap=0, reorder_count=1)
    )
    assert "control_accel_residual_ms2" not in res_reorder.signals
    assert not any("ConstDet" in e for e in res_reorder.evidence)

    # Case 3: subsequent clean frame with no new reorder and no seq_gap still works
    res_clean = det.process(
        _make_frame(t=1.2, control_accel_residual_ms2=10.0, max_seq_gap=0, reorder_count=1)
    )
    assert "control_accel_residual_ms2" in res_clean.signals
    assert res_clean.score > 0.0
