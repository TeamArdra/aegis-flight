"""The shared Python request signer (scripts/tests/bench tooling) is accepted by the control plane."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from aegisflight.backend import app as backend_app
from aegisflight.backend.client_auth import key_id, signed_headers
from aegisflight.backend.engine import LiveEngine
from aegisflight.backend.security import (
    GLOBAL_RATE_LIMITER,
    GLOBAL_REPLAY_CACHE,
    compute_request_hmac,
)
from aegisflight.backend.sources import SourceSpec

TOKEN = "client-auth-secret-2026"


def _reset() -> None:
    for k in ("testclient", "unknown"):
        GLOBAL_RATE_LIMITER.clear(k)
    GLOBAL_REPLAY_CACHE._seen.clear()


def test_signed_headers_shape_and_signature() -> None:
    body = b'{"mode":"advisory"}'
    h = signed_headers(TOKEN, "post", "/api/defense/mode?x=1", body, now_s=1_700_000_000.0, nonce="nonce-abcdefgh")
    assert h["X-Aegis-Token"] == TOKEN
    assert h["X-Aegis-Key-Id"] == key_id(TOKEN) and len(h["X-Aegis-Key-Id"]) == 16
    assert h["X-Aegis-Timestamp"] == "1700000000.000" and h["X-Aegis-Nonce"] == "nonce-abcdefgh"
    # the query string is not part of the signed path (the backend verifies request.url.path)
    assert h["X-Aegis-Signature"] == compute_request_hmac(
        TOKEN, method="POST", path="/api/defense/mode", timestamp="1700000000.000", nonce="nonce-abcdefgh", body=body)


def test_include_token_false_never_sends_the_secret() -> None:
    h = signed_headers(TOKEN, "POST", "/api/x", b"{}", include_token=False)
    assert "X-Aegis-Token" not in h and TOKEN not in json.dumps(h)
    assert signed_headers("", "POST", "/api/x") == {}


def test_nonce_is_fresh_per_call() -> None:
    assert signed_headers(TOKEN, "POST", "/p")["X-Aegis-Nonce"] != signed_headers(TOKEN, "POST", "/p")["X-Aegis-Nonce"]


def test_backend_accepts_signed_helper_headers_and_refuses_replay(monkeypatch) -> None:
    _reset()
    monkeypatch.setenv("AEGIS_API_TOKEN", TOKEN)
    monkeypatch.setattr(backend_app, "engine", LiveEngine(spec=SourceSpec(kind="sim")))
    body = json.dumps({"mode": "advisory"}).encode()
    try:
        with TestClient(backend_app.app) as client:
            h = {"Content-Type": "application/json", **signed_headers(TOKEN, "POST", "/api/defense/mode", body)}
            assert client.post("/api/defense/mode", content=body, headers=h).status_code == 200
            assert client.post("/api/defense/mode", content=body, headers=h).status_code == 401  # replay
            bad = {"Content-Type": "application/json", **signed_headers("wrong-token", "POST", "/api/defense/mode", body)}
            assert client.post("/api/defense/mode", content=body, headers=bad).status_code == 401
    finally:
        _reset()
