"""Regression tests for review findings R9 (blocking work in async routes) and R12 (hard-coded zero-TX flags).

SYNTHETIC: fakes only, no serial port is opened and nothing is transmitted.
"""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from aegisflight.backend import app as backend_app
from aegisflight.backend.engine import LiveEngine
from aegisflight.backend.sources import SourceSpec
from aegisflight.testing import field_drill

BLOCK_S = 0.8


@pytest.fixture()
def sim_engine(monkeypatch):
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)
    eng = LiveEngine(spec=SourceSpec(kind="sim"))
    eng.pipeline.extractor.snapshot.armed = False
    monkeypatch.setattr(backend_app, "engine", eng)
    return eng


async def _other_route_answers_during(method: str, path: str, **kw) -> tuple[float, float, int]:
    """Start a slow route, then call /health. Returns (health latency, slow-route total, slow status)."""
    transport = httpx.ASGITransport(app=backend_app.app, client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        t0 = time.perf_counter()
        slow = asyncio.create_task(client.request(method, path, **kw))
        await asyncio.sleep(0.1)  # let the slow handler start and block
        health = await client.get("/health")
        health_s = time.perf_counter() - t0  # from the slow request's start: a blocked loop delays even the sleep above
        assert health.status_code == 200
        resp = await slow
        return health_s, time.perf_counter() - t0, resp.status_code


def _assert_not_blocked(health_s: float, total_s: float) -> None:
    assert total_s >= BLOCK_S * 0.9, "the patched blocking call did not run"
    assert health_s < BLOCK_S / 2, f"/health waited {health_s:.2f}s behind a blocking route (event loop blocked)"


def test_drill_route_does_not_block_the_event_loop(sim_engine, monkeypatch) -> None:
    def slow_drill(scenario: str = "all") -> dict:
        time.sleep(BLOCK_S)
        return {"ok": True, "zero_real_fc_tx": True, "passed": 1, "total": 1, "scenarios": []}

    monkeypatch.setattr(field_drill, "run_field_drill", slow_drill)
    health_s, total_s, status = asyncio.run(_other_route_answers_during("POST", "/api/drill/run", json={"scenario": "all"}))
    assert status == 200
    _assert_not_blocked(health_s, total_s)


def test_forensic_report_route_does_not_block_the_event_loop(sim_engine, monkeypatch, tmp_path) -> None:
    from aegisflight.reporting import forensic_report

    db = tmp_path / "events.sqlite"
    db.write_bytes(b"")
    monkeypatch.setattr(sim_engine, "db_path", str(db), raising=False)

    def slow_build(db_path, **k):
        time.sleep(BLOCK_S)
        return {"schema": "aegisflight.forensic_report/1", "verified": True}

    monkeypatch.setattr(forensic_report, "build_forensic_report", slow_build)
    health_s, total_s, status = asyncio.run(_other_route_answers_during("GET", "/api/forensic/report?format=json"))
    assert status == 200
    _assert_not_blocked(health_s, total_s)


def test_preflight_route_does_not_block_the_event_loop(sim_engine, monkeypatch) -> None:
    import aegisflight.onboard as onboard

    def slow_preflight(cfg):
        time.sleep(BLOCK_S)
        return {"ok": True}

    monkeypatch.setattr(onboard, "run_preflight", slow_preflight)
    health_s, total_s, status = asyncio.run(_other_route_answers_during("POST", "/api/setup/preflight", json={}))
    assert status == 200
    _assert_not_blocked(health_s, total_s)


def test_enroll_firmware_route_does_not_block_the_event_loop(sim_engine, monkeypatch) -> None:
    from aegisflight.hal import auto_port

    def slow_capture(port, **kw):
        time.sleep(BLOCK_S)
        return {"sysid": 1}

    monkeypatch.setattr(auto_port, "capture_autopilot_version_passive", slow_capture)
    health_s, total_s, status = asyncio.run(
        _other_route_answers_during("POST", "/api/setup/enroll-firmware", json={"port": "COM9"})
    )
    assert status == 200
    _assert_not_blocked(health_s, total_s)


# ---- R12: zero-TX flags are measured -------------------------------------------------------------------------- #

class _OtherTransport:
    """Not a shadow sink: stands in for any real link (UDP/serial wrapper)."""

    port = None

    def __init__(self, name: str) -> None:
        self.name = name
        self.connected = True
        self.sent_frames: list[bytes] = []

    def recv(self):
        return []

    def send(self, frame: bytes) -> bool:
        self.sent_frames.append(frame)
        return True

    def close(self) -> None:
        self.connected = False


def test_zero_tx_helper() -> None:
    assert field_drill._zero_real_tx() is True
    assert field_drill._zero_real_tx(field_drill._ShadowTransport("a"), field_drill._ShadowTransport("b")) is True
    assert field_drill._zero_real_tx(field_drill._ShadowTransport("a"), _OtherTransport("x")) is False
    dev = field_drill._ShadowTransport("dev")
    dev.port = "/dev/ttyAMA0"
    assert field_drill._zero_real_tx(dev) is False


def test_shadow_drills_still_report_zero_tx() -> None:
    res = field_drill.run_field_drill("all")
    assert res["ok"] is True and res["zero_real_fc_tx"] is True
    assert all(s["zero_real_fc_tx"] is True for s in res["scenarios"])


def test_non_shadow_transport_flips_the_flag(monkeypatch) -> None:
    monkeypatch.setattr(field_drill, "_new_transport", lambda name: _OtherTransport(name))
    one = field_drill.run_field_drill("signed_spoof_rejection")
    assert one["scenarios"][0]["zero_real_fc_tx"] is False
    assert one["zero_real_fc_tx"] is False
    everything = field_drill.run_field_drill("all")
    assert everything["zero_real_fc_tx"] is False
    by_name = {s["name"]: s["zero_real_fc_tx"] for s in everything["scenarios"]}
    assert by_name["signed_spoof_rejection"] is False and by_name["semantic_param_fence_block"] is False
    assert by_name["gps_spoof_escalation"] is True and by_name["clock_skew_sdr_spoof"] is True  # no transport used


@pytest.mark.parametrize(("nbytes", "expect_zero"), [(0, True), (5, False)])
def test_discover_ports_zero_tx_is_measured(sim_engine, monkeypatch, nbytes, expect_zero) -> None:
    from aegisflight.hal import auto_port

    class _Ser:
        def write(self, data: bytes) -> int:
            return len(data)

        def read(self, n: int) -> bytes:
            return b""

        def close(self) -> None:
            pass

    def fake_discover(*, probe_window_s=0.6, serial_opener=None, **_k):
        ser = serial_opener("COM9", 115200, 0.05)
        if nbytes:
            ser.write(b"x" * nbytes)
        ser.close()
        return []

    monkeypatch.setattr(auto_port, "discover_mavlink_ports", fake_discover)
    monkeypatch.setattr(auto_port, "_open_passive_serial", lambda device, baud, timeout=0.05: _Ser())
    with TestClient(backend_app.app, client=("127.0.0.1", 50000)) as client:
        client.post("/api/simulation/stop")
        sim_engine.pipeline.extractor.snapshot.armed = False
        r = client.get("/api/setup/discover-ports")
    assert r.status_code == 200
    assert r.json()["zero_tx"] is expect_zero and r.json()["tx_bytes"] == nbytes
