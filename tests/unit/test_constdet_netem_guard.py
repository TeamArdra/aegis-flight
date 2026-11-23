"""ConstDet keeps the conservative base behaviour (maintainer decision D14 on #4, applying to #125).

ConstDet is NOT muted on a window with a sequence gap or a reorder. A narrower guard needs benign
link-stress evidence first. These tests pin that ConstDet's output is independent of the link-stress
features, i.e. identical to the #82 base, which never read them.
"""

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


def _signature(res) -> tuple:
    return (res.score, sorted(res.signals), list(res.evidence))


def test_constdet_true_accel_spike_still_alerts() -> None:
    det = _make_detector()
    res = det.process(_make_frame(t=1.0, control_accel_residual_ms2=10.0))
    assert "control_accel_residual_ms2" in res.signals
    assert res.score > 0.0
    assert any("ConstDet" in e for e in res.evidence)


def test_constdet_output_ignores_seq_gap_and_reorder() -> None:
    """Same inputs but for max_seq_gap / reorder_count: ConstDet output must be identical (not muted).

    Fails on #125's head, which muted ConstDet whenever max_seq_gap > 0 or reorder_count > 0.
    """
    for residual in (3.0, 10.0, 15.0):  # below, above and well above the 4.5 m/s^2 threshold
        clean = _signature(_make_detector().process(_make_frame(t=1.0, control_accel_residual_ms2=residual)))
        for gap, reorder in ((2, 0), (0, 1), (3, 2)):
            link_stressed = _signature(
                _make_detector().process(
                    _make_frame(t=1.0, control_accel_residual_ms2=residual, max_seq_gap=gap, reorder_count=reorder)
                )
            )
            assert link_stressed == clean, (residual, gap, reorder)


def test_constdet_fires_on_gap_and_reorder_windows() -> None:
    det = _make_detector()
    for k, (gap, reorder) in enumerate(((2, 0), (0, 1), (2, 1))):
        res = det.process(
            _make_frame(t=1.0 + 0.1 * k, control_accel_residual_ms2=15.0, max_seq_gap=gap, reorder_count=reorder)
        )
        assert "control_accel_residual_ms2" in res.signals, (gap, reorder)
        assert any("ConstDet" in e for e in res.evidence), (gap, reorder)
