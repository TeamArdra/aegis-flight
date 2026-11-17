"""Guards of the real-flight-controller bench relay (scripts/ardupilot/real_pixhawk/px_fc_proxy.py, PR #39 review M3)."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

os.environ.setdefault("MAVLINK20", "1")

from pymavlink.dialects.v20 import ardupilotmega as mav  # noqa: E402

_P = Path(__file__).resolve().parents[2] / "scripts" / "ardupilot" / "real_pixhawk" / "px_fc_proxy.py"
_spec = importlib.util.spec_from_file_location("px_fc_proxy", _P)
px = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(px)  # type: ignore[union-attr]


def _hb(armed: bool, mav_type: int = 2, compid: int = 1) -> bytes:
    m = mav.MAVLink(None, srcSystem=1, srcComponent=compid)
    return bytes(m.heartbeat_encode(mav_type, 3, 128 if armed else 0, 0, 4).pack(m))


def _gpi() -> bytes:
    m = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    return bytes(m.global_position_int_encode(1000, 0, 0, 10000, 5000, 0, 0, 0, 0).pack(m))


def _run(*frames: bytes, kind: str = "off"):
    gate, rw = px.ArmGate(), px.Rewriter()
    rw.mode.update(kind=kind, val=40.0)
    rd = mav.MAVLink(None)
    rd.robust_parsing = True
    out = [px.fc_to_bridge(f, rd, gate, rw) for f in frames]
    return gate, rw, out


def test_refuses_to_start_without_the_explicit_opt_in(capsys, monkeypatch):
    monkeypatch.delenv(px.OPT_IN_ENV, raising=False)
    assert px.main() == 2
    assert "refusing to start" in capsys.readouterr().err
    assert px.opt_in_ok({px.OPT_IN_ENV: "1"}) is False
    assert px.opt_in_ok({px.OPT_IN_ENV: px.OPT_IN_VALUE}) is True


def test_nothing_reaches_the_fc_before_a_disarmed_heartbeat():
    gate, _rw, _ = _run(_gpi(), _hb(False, mav_type=6, compid=190))  # a GCS heartbeat does not count
    assert gate.to_fc_allowed is False
    gate, _rw, _ = _run(_hb(False))
    assert gate.to_fc_allowed is True


def test_an_armed_heartbeat_stops_fc_bound_traffic_and_rewriting_for_good():
    gate, rw, out = _run(_hb(False), _gpi(), _hb(True), _gpi(), _hb(False), _gpi(), kind="alt_bias")
    assert gate.armed_seen and gate.to_fc_allowed is False and gate.rewrite_allowed is False
    assert rw.rewritten == 1  # only the frame before the arm transition
    assert out[3] == _gpi() and out[5] == _gpi()  # passed through unchanged after arming, even once disarmed again
