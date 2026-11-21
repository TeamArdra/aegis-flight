"""Unit tests for End-to-End Backend Command Security, Replay Protection & Bench Setup Gate (W12, W13)."""

from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient

from aegisflight.backend import app as backend_app
from aegisflight.backend.engine import LiveEngine
from aegisflight.backend.security import (
    GLOBAL_RATE_LIMITER,
    GLOBAL_REPLAY_CACHE,
    compute_request_hmac,
)
from aegisflight.backend.sources import SourceSpec


def test_hmac_nonce_replay_lockout_and_security_headers(monkeypatch) -> None:
    GLOBAL_RATE_LIMITER.clear("testclient")
    GLOBAL_RATE_LIMITER.clear("unknown")
    token = "test-secret-hmac-key-2026"
    monkeypatch.setenv("AEGIS_API_TOKEN", token)
    eng = LiveEngine(spec=SourceSpec(kind="sim"))
    monkeypatch.setattr(backend_app, "engine", eng)
    try:
        with TestClient(backend_app.app) as client:
            # Verify CSP and security headers
            r_health = client.get("/health")
            assert r_health.status_code == 200
            assert "content-security-policy" in r_health.headers
            assert r_health.headers["x-frame-options"] == "DENY"
            assert r_health.headers["x-content-type-options"] == "nosniff"

            body = json.dumps({"mode": "advisory"}).encode()
            ts = f"{time.time():.3f}"
            nonce = "nonce-unique-12345678"
            sig = compute_request_hmac(
                token, method="POST", path="/api/defense/mode", timestamp=ts, nonce=nonce, body=body
            )
            headers = {
                "Content-Type": "application/json",
                "X-Aegis-Token": token,
                "X-Aegis-Timestamp": ts,
                "X-Aegis-Nonce": nonce,
                "X-Aegis-Signature": sig,
            }
            # 1) Valid signed request succeeds
            ok_resp = client.post("/api/defense/mode", content=body, headers=headers)
            assert ok_resp.status_code == 200

            # 2) Replaying identical nonce + signature is rejected!
            replay_resp = client.post("/api/defense/mode", content=body, headers=headers)
            assert replay_resp.status_code == 401
            assert "replay" in replay_resp.json()["error"].lower()

            # 3) Tampered payload fails HMAC check
            bad_body = json.dumps({"mode": "active-ips"}).encode()
            nonce2 = "nonce-unique-87654321"
            sig_for_other = compute_request_hmac(
                token, method="POST", path="/api/defense/mode", timestamp=ts, nonce=nonce2, body=body
            )
            tamper_resp = client.post(
                "/api/defense/mode",
                content=bad_body,
                headers={**headers, "X-Aegis-Nonce": nonce2, "X-Aegis-Signature": sig_for_other},
            )
            assert tamper_resp.status_code == 401

            # Signed POST /api/simulation/attack verifies HMAC over the actual JSON body
            atk_body = json.dumps({"attack": "gps_spoofing", "mode": "gradual_drift"}).encode("utf-8")
            atk_nonce = "nonce-sim-attack-1234"
            atk_sig = compute_request_hmac(
                token, method="POST", path="/api/simulation/attack", timestamp=ts, nonce=atk_nonce, body=atk_body
            )
            atk_ok = client.post(
                "/api/simulation/attack",
                content=atk_body,
                headers={
                    "X-Aegis-Token": token,
                    "X-Aegis-Timestamp": ts,
                    "X-Aegis-Nonce": atk_nonce,
                    "X-Aegis-Signature": atk_sig,
                    "Content-Type": "application/json",
                },
            )
            assert atk_ok.status_code == 200 and atk_ok.json()["ok"] is True
            assert atk_ok.json()["attack"] == "gps_spoofing"
    finally:
        GLOBAL_RATE_LIMITER.clear("testclient")
        GLOBAL_RATE_LIMITER.clear("unknown")
        monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)


def test_bench_setup_routes_locked_when_armed_and_non_loopback(monkeypatch) -> None:
    monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)
    eng = LiveEngine(spec=SourceSpec(kind="sim"))
    monkeypatch.setattr(backend_app, "engine", eng)
    with TestClient(backend_app.app) as client:
        client.post("/api/simulation/stop")
        eng.pipeline.extractor.snapshot.armed = False
        # Disarmed: config generator works
        r_gen = client.post("/api/setup/generate-config", json={"topology": "side-tap", "fc_port": "/dev/ttyAMA0"})
        assert r_gen.status_code == 200
        assert "side-tap" in r_gen.json()["yaml"]

        # Armed: setup routes refuse with 409 vehicle_armed
        eng.pipeline.extractor.snapshot.armed = True
        r_locked = client.post("/api/setup/generate-config", json={"topology": "side-tap"})
        assert r_locked.status_code == 409
        assert r_locked.json()["error"] == "vehicle_armed"

        # Forensic & zero-TX drill endpoints work cleanly
        r_drill = client.post("/api/drill/run", json={"scenario": "all"})
        assert r_drill.status_code == 200 and r_drill.json()["ok"] is True

        r_rep = client.get("/api/forensic/report?format=json")
        assert r_rep.status_code == 200 and r_rep.json()["schema"] == "aegisflight.forensic_report/1"
    assert GLOBAL_REPLAY_CACHE.ttl_s > 0


def test_bad_hmac_does_not_burn_a_valid_nonce(monkeypatch) -> None:
    """R3 P3: the nonce is recorded only after the signature verifies."""
    GLOBAL_RATE_LIMITER.clear("testclient")
    GLOBAL_RATE_LIMITER.clear("unknown")
    token = "test-secret-hmac-key-2026"
    monkeypatch.setenv("AEGIS_API_TOKEN", token)
    eng = LiveEngine(spec=SourceSpec(kind="sim"))
    monkeypatch.setattr(backend_app, "engine", eng)
    try:
        with TestClient(backend_app.app) as client:
            body = json.dumps({"mode": "advisory"}).encode()
            ts = f"{time.time():.3f}"
            nonce = "nonce-burn-test-1234567"
            good = compute_request_hmac(
                token, method="POST", path="/api/defense/mode", timestamp=ts, nonce=nonce, body=body
            )
            base = {"Content-Type": "application/json", "X-Aegis-Token": token,
                    "X-Aegis-Timestamp": ts, "X-Aegis-Nonce": nonce}
            # forged signature with the same nonce: rejected as a bad HMAC (not as a replay)
            bad = client.post("/api/defense/mode", content=body, headers={**base, "X-Aegis-Signature": "0" * 64})
            assert bad.status_code == 401
            assert "hmac" in bad.json()["error"].lower()
            # the legitimate request with that nonce still succeeds
            ok = client.post("/api/defense/mode", content=body, headers={**base, "X-Aegis-Signature": good})
            assert ok.status_code == 200
            # and a replay of the now-recorded valid nonce is still rejected
            again = client.post("/api/defense/mode", content=body, headers={**base, "X-Aegis-Signature": good})
            assert again.status_code == 401
            assert "replay" in again.json()["error"].lower()
    finally:
        GLOBAL_RATE_LIMITER.clear("testclient")
        GLOBAL_RATE_LIMITER.clear("unknown")
        GLOBAL_REPLAY_CACHE._seen.clear()
        monkeypatch.delenv("AEGIS_API_TOKEN", raising=False)


def test_replay_cache_check_is_read_only_and_record_is_atomic() -> None:
    from aegisflight.backend.security import ReplayCache

    cache = ReplayCache(ttl_s=60.0)
    now = 1000.0
    assert cache.check("nonce-12345678", now, now_s=now) == (True, "ok")
    assert cache.check("nonce-12345678", now, now_s=now) == (True, "ok")  # check never records
    assert cache.record("nonce-12345678", now, now_s=now) == (True, "ok")
    assert cache.record("nonce-12345678", now, now_s=now)[0] is False  # second record loses
    assert cache.check("nonce-12345678", now, now_s=now)[0] is False
