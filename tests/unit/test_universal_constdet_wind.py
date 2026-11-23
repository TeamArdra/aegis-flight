"""ConstDet threshold in the universal-flight profile must clear benign wind drag, yet still catch gross spoofs.

Evidence (SITL, ArduCopter, 12 m/s wind, turbulence 4, GPS noise 0.8 m, benign guided flight, netem link):
armed-frame ConstDet residual p50 4.42 / p99 6.15 / max 6.43 m/s^2, so the Stage-1 value 4.5 alerted
continuously. Stage-1 ``configs/detector.yaml`` is untouched.
"""

from __future__ import annotations

from aegisflight.config import load_config
from aegisflight.core.types import MessageEnvelope
from aegisflight.features.extractor import FeatureExtractor

BENIGN_WIND_MAX_RESIDUAL = 6.43


def test_universal_profile_threshold_clears_benign_wind_residual_with_margin() -> None:
    thr = float(load_config("configs/universal_flight").detector["physics"]["control_accel_residual_ms2"])
    assert thr >= BENIGN_WIND_MAX_RESIDUAL * 1.2


def test_stage1_default_threshold_is_unchanged() -> None:
    assert float(load_config(None).detector["physics"]["control_accel_residual_ms2"]) == 4.5


def test_gross_level_attitude_spoof_still_exceeds_the_threshold() -> None:
    thr = float(load_config("configs/universal_flight").detector["physics"]["control_accel_residual_ms2"])
    ext = FeatureExtractor()
    att = {"roll": 0.0, "pitch": 0.0, "yaw": 0.0, "rollspeed": 0.0, "pitchspeed": 0.0, "yawspeed": 0.0}
    for k in range(12):
        t = k * 0.2
        ext.update(MessageEnvelope(t, 1, 1, 0, "HEARTBEAT", k, False, 17, {"type": 2, "autopilot": 3, "base_mode": 0x81 | 0x80, "custom_mode": 5}))
        ext.update(MessageEnvelope(t, 1, 1, 30, "ATTITUDE", k, False, 36, att))
        vx = 0 if k < 6 else (k - 5) * 600  # 30 m/s^2 of GPS acceleration under level attitude
        ext.update(MessageEnvelope(t, 1, 1, 33, "GLOBAL_POSITION_INT", k, False, 36, {"lat": 191334000, "lon": 729133000, "alt": 50_000, "relative_alt": 40_000, "vx": vx, "vy": 0, "vz": 0}))
    frame = ext.extract(2.2)
    assert frame.control_accel_residual_ms2 is not None and frame.control_accel_residual_ms2 > thr


def test_universal_heading_yaw_tolerance_clears_benign_turbulence_and_stage1_is_unchanged() -> None:
    # benign SITL turbulence flight: VFR_HUD vs ATTITUDE yaw disagreement observed up to 15 deg
    assert float(load_config("configs/universal_flight").detector["physics"]["heading_yaw_tolerance_deg"]) >= 15.0 * 1.25
    assert float(load_config(None).detector["physics"].get("heading_yaw_tolerance_deg", 10.0)) == 10.0


def _gpi(ext, t: float, vx_cm: int) -> None:
    from aegisflight.core.types import MessageEnvelope

    ext.update(MessageEnvelope(t, 1, 1, 33, "GLOBAL_POSITION_INT", int(t * 100) % 256, False, 36, {
        "lat": 191334000, "lon": 729133000, "alt": 50_000, "relative_alt": 40_000, "vx": vx_cm, "vy": 0, "vz": 0}))


def test_accel_min_dt_ignores_jitter_compressed_velocity_samples() -> None:
    """Two velocity samples 5 ms apart (link jitter/reorder) must not read as a 60 m/s2 acceleration."""
    from aegisflight.features.extractor import FeatureExtractor

    def feed(ext) -> float:
        _gpi(ext, 0.0, 0)
        _gpi(ext, 0.2, 30)
        _gpi(ext, 0.205, 60)  # 0.3 m/s step arriving 5 ms after the previous sample
        accel, _ = ext._accel_jerk(0.205)
        return accel

    assert feed(FeatureExtractor()) > 50.0  # Stage-1 definition (default 0.0) is unchanged
    assert feed(FeatureExtractor(accel_min_dt_s=0.15)) < 3.0


def test_accel_min_dt_still_sees_a_spoofed_velocity_step() -> None:
    from aegisflight.features.extractor import FeatureExtractor

    ext = FeatureExtractor(accel_min_dt_s=0.15)
    _gpi(ext, 0.0, 0)
    _gpi(ext, 0.2, 0)
    _gpi(ext, 0.4, 1500)  # 15 m/s step in one 0.2 s update
    accel, _ = ext._accel_jerk(0.4)
    assert accel > 70.0


def test_universal_profile_sets_accel_min_dt_and_stage1_default_is_off() -> None:
    assert load_config("configs/universal_flight").detector["features"]["accel_min_dt_s"] == 0.15
    assert load_config(None).detector["features"]["accel_min_dt_s"] == 0.0
