"""GPS fix vs GPS health vs estimator health in the backend link block (SYNTHETIC messages, no hardware).

``gps.valid_fix`` is only the receiver's report against the GNSS-loss thresholds. The vehicle's own view
(SYS_STATUS GPS-health bit, EKF_STATUS_REPORT horizontal solution) is reported separately and is ``None``
(unknown) until it has actually been received.
"""

from __future__ import annotations

from types import SimpleNamespace

from pymavlink.dialects.v20 import ardupilotmega as apm

from aegisflight.backend.engine import LinkMonitor
from aegisflight.detectors.protocol import ProtocolDetector
from aegisflight.features.extractor import FeatureExtractor

GPS = 32  # MAV_SYS_STATUS_SENSOR_GPS
EKF_HORIZ_ABS = apm.EKF_POS_HORIZ_ABS


def _tick(t, *msgs):
    return SimpleNamespace(t=t, messages=[SimpleNamespace(msgname=n, fields=f) for n, f in msgs])


def _raw(fix=3, sats=9):
    return ("GPS_RAW_INT", {"fix_type": fix, "satellites_visible": sats})


def _sys(health, present=GPS, enabled=GPS):
    return ("SYS_STATUS", {"onboard_control_sensors_present": present, "onboard_control_sensors_enabled": enabled,
                           "onboard_control_sensors_health": health})


def _snap(*ticks):
    lm = LinkMonitor(3.0, 3, 5)
    for tk in ticks:
        lm.observe(tk)
    return lm.snapshot()


def test_3d_fix_with_unhealthy_gps_bit_and_no_horizontal_solution_is_not_called_healthy():
    # the observed bench condition: receiver says 3D fix / 7 sats, vehicle says GPS unhealthy, EKF 0xa7
    s = _snap(_tick(1.0, _raw(3, 7), _sys(0), ("EKF_STATUS_REPORT", {"flags": 0xA7})))
    assert s["gps"]["valid_fix"] is True            # receiver report only
    assert s["gps"]["health_ok"] is False           # vehicle's GPS-health bit
    assert s["estimator"]["horizontal_position_ok"] is False
    assert s["estimator"]["flags"] == 0xA7


def test_healthy_vehicle_reports_all_three_ok():
    s = _snap(_tick(1.0, _raw(3, 9), _sys(GPS), ("EKF_STATUS_REPORT", {"flags": EKF_HORIZ_ABS})))
    assert (s["gps"]["valid_fix"], s["gps"]["health_ok"], s["estimator"]["horizontal_position_ok"]) == (True, True, True)


def test_health_and_estimator_are_unknown_not_healthy_until_received():
    s = _snap(_tick(1.0, _raw(3, 9)))
    assert s["gps"]["valid_fix"] is True
    assert s["gps"]["health_ok"] is None and s["gps"]["health_age_s"] is None
    assert s["estimator"] == {"horizontal_position_ok": None, "flags": None, "age_s": None}


def test_gps_sensor_not_present_is_unknown_not_unhealthy():
    s = _snap(_tick(1.0, _raw(), _sys(0, present=0, enabled=0)))
    assert s["gps"]["health_ok"] is None


def test_ages_are_reported_so_stale_health_is_visible():
    s = _snap(_tick(1.0, _sys(GPS), ("EKF_STATUS_REPORT", {"flags": EKF_HORIZ_ABS})), _tick(6.0, _raw()))
    assert s["gps"]["health_age_s"] == 5.0 and s["estimator"]["age_s"] == 5.0


def test_unknown_satellite_count_255_is_unknown_not_255_satellites():
    assert _snap(_tick(1.0, _raw(3, 255)))["gps"]["satellites"] is None
    assert _snap(_tick(1.0, _raw(3, 255)))["gps"]["valid_fix"] is None
    assert _snap(_tick(1.0, _raw(0, 255)))["gps"]["valid_fix"] is False  # no fix is no fix whatever the count


def _run_detector(fix, sats, seconds=5.0):
    from aegisflight.config import DEFAULT_DETECTOR
    from aegisflight.core.types import MessageEnvelope
    ext, det, out = FeatureExtractor(), ProtocolDetector(DEFAULT_DETECTOR["protocol"]), []
    for k in range(int(seconds / 0.2)):
        t = round(k * 0.2, 6)
        for name, f in ([("HEARTBEAT", {"base_mode": 0, "custom_mode": 0})] if k % 5 == 0 else []) + [
                ("GLOBAL_POSITION_INT", {"lat": 473977420, "lon": 85455940, "alt": 600000, "relative_alt": 0,
                                         "vx": 0, "vy": 0, "vz": 0, "hdg": 0}),
                ("GPS_RAW_INT", {"fix_type": fix, "satellites_visible": sats, "eph": 100})]:
            ext.update(MessageEnvelope(recv_time=t, sysid=1, compid=1, msgid=0, msgname=name, seq=0,
                                       signed=False, byte_len=20, fields=f))
        out.append((ext.extract(t), det.process(ext.extract(t))))
    return out


def test_extractor_does_not_turn_255_into_255_satellites():
    frame, _ = _run_detector(3, 255)[-1]
    assert frame.snapshot.satellites is None and frame.snapshot.gps_fix_type == 3


def test_unknown_satellite_count_with_3d_fix_is_not_gnss_loss_evidence():
    assert all(not any(e.startswith("GNSS fix") for e in r.evidence) for _, r in _run_detector(3, 255))


def test_no_fix_is_still_flagged_when_the_satellite_count_is_unknown():
    _, last = _run_detector(0, 255)[-1]
    assert any(e.startswith("GNSS fix never acquired: fix_type=0") for e in last.evidence)
