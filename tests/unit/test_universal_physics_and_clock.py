"""Unit tests for ConstDet physics, ground baro bias calibration, optflow, and clock skew (W3, W4)."""

from __future__ import annotations

from aegisflight.config import load_config
from aegisflight.core.enums import AttackType
from aegisflight.core.types import MessageEnvelope
from aegisflight.features.extractor import FeatureExtractor
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.stream import TelemetryTick


def test_learned_baro_offset_eliminates_benign_alt_false_positive() -> None:
    cfg = load_config("configs/universal_flight")
    pipe = IDSPipeline(cfg, model_path=None)

    # 20 ticks disarmed on the ground with constant +24 m MSL-vs-baro offset
    for k in range(20):
        t = k * 0.2
        msgs = [
            MessageEnvelope(t, 1, 1, 0, "HEARTBEAT", k % 256, False, 17, {"type": 2, "autopilot": 3, "base_mode": 0x01, "custom_mode": 5}),
            MessageEnvelope(t, 1, 1, 24, "GPS_RAW_INT", (k + 1) % 256, False, 40, {"fix_type": 3, "satellites_visible": 10}),
            MessageEnvelope(t, 1, 1, 33, "GLOBAL_POSITION_INT", (k + 2) % 256, False, 36, {
                "lat": 191334000, "lon": 729133000, "alt": 124_000, "relative_alt": 0, "vx": 0, "vy": 0, "vz": 0,
            }),
            MessageEnvelope(t, 1, 1, 74, "VFR_HUD", (k + 3) % 256, False, 24, {"groundspeed": 0.0, "heading": 0.0, "throttle": 0.0, "alt": 100.0, "climb": 0.0}),
        ]
        res = pipe.process_tick(TelemetryTick(tick=k, t=t, messages=msgs))
        if res is not None:
            assert not res.is_alert, f"unexpected false alarm with static baro bias: {res.evidence}"

    assert pipe.last_frame is not None
    assert pipe.last_frame.learned_baro_offset_m is not None
    assert abs(pipe.last_frame.learned_baro_offset_m - 24.0) < 0.5

    # Now arm and inject a +20 m spoofed altitude jump beyond learned offset
    alerts: list[AttackType] = []
    for k in range(20, 32):
        t = k * 0.2
        msgs = [
            MessageEnvelope(t, 1, 1, 0, "HEARTBEAT", k % 256, False, 17, {"type": 2, "autopilot": 3, "base_mode": 0x81 | 0x80, "custom_mode": 5}),
            MessageEnvelope(t, 1, 1, 33, "GLOBAL_POSITION_INT", (k + 2) % 256, False, 36, {
                "lat": 191334000, "lon": 729133000, "alt": 144_000, "relative_alt": 20_000, "vx": 0, "vy": 0, "vz": 0,
            }),
            MessageEnvelope(t, 1, 1, 74, "VFR_HUD", (k + 3) % 256, False, 24, {"groundspeed": 0.0, "heading": 0.0, "throttle": 20.0, "alt": 100.0, "climb": 0.0}),
        ]
        res = pipe.process_tick(TelemetryTick(tick=k, t=t, messages=msgs))
        if res is not None and res.is_alert:
            alerts.append(res.attack_type)
    assert AttackType.TELEMETRY_MANIPULATION in alerts


def test_constdet_optflow_and_gnss_clock_skew_rules() -> None:
    ext = FeatureExtractor(learn_baro_offset=True)
    # Feed benign baseline with level attitude, zero velocity, matching optflow & Unix time
    base_unix = 1_760_000_000_000_000
    for k in range(6):
        t = k * 0.2
        ext.update(MessageEnvelope(t, 1, 1, 0, "HEARTBEAT", k, False, 17, {"type": 2, "autopilot": 3, "base_mode": 0x81 | 0x80, "custom_mode": 5}))
        ext.update(MessageEnvelope(t, 1, 1, 30, "ATTITUDE", k, False, 36, {"roll": 0.0, "pitch": 0.0, "yaw": 0.0, "rollspeed": 0.0, "pitchspeed": 0.0, "yawspeed": 0.0}))
        ext.update(MessageEnvelope(t, 1, 1, 33, "GLOBAL_POSITION_INT", k, False, 36, {"lat": 191334000, "lon": 729133000, "alt": 50_000, "relative_alt": 40_000, "vx": 0, "vy": 0, "vz": 0}))
        ext.update(MessageEnvelope(t, 1, 1, 2, "SYSTEM_TIME", k, False, 20, {"time_unix_usec": base_unix + int(t * 1e6)}))

    # Inject spoofed high velocity while attitude stays completely level + optflow stays 0 + clock backward step
    for k in range(6, 12):
        t = k * 0.2
        vx_cm = (k - 5) * 600  # aggressive fake acceleration
        ext.update(MessageEnvelope(t, 1, 1, 30, "ATTITUDE", k, False, 36, {"roll": 0.0, "pitch": 0.0, "yaw": 0.0, "rollspeed": 0.0, "pitchspeed": 0.0, "yawspeed": 0.0}))
        ext.update(MessageEnvelope(t, 1, 1, 33, "GLOBAL_POSITION_INT", k, False, 36, {"lat": 191334000, "lon": 729133000, "alt": 50_000, "relative_alt": 40_000, "vx": vx_cm, "vy": 0, "vz": 0}))
        ext.update(MessageEnvelope(t, 1, 1, 100, "OPTICAL_FLOW", k, False, 24, {"flow_comp_m_x": 0.0, "flow_comp_m_y": 0.0}))
        ext.update(MessageEnvelope(t, 1, 1, 2, "SYSTEM_TIME", k, False, 20, {"time_unix_usec": base_unix - 10_000_000}))

    frame = ext.extract(2.2)
    assert frame.control_accel_residual_ms2 is not None and frame.control_accel_residual_ms2 > 4.5
    assert frame.optflow_gps_speed_diff_ms is not None and frame.optflow_gps_speed_diff_ms > 4.0
    assert frame.gnss_clock_backward is True
