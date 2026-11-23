"""Signed-only control auth (proposal #93): rejection matrix for every way a request can fail to authenticate.

Each case asserts the HTTP status and the error text; the stale-timestamp case also asserts the nonce is not burned.
"""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from aegisflight.backend import app as backend_app
from aegisflight.backend.engine import LiveEngine
from aegisflight.backend.security import (
    GLOBAL_RATE_LIMITER,
    GLOBAL_REPLAY_CACHE,
    compute_request_hmac,
    key_id,
)
from aegisflight.backend.sources import SourceSpec

TOKEN = "matrix-secret-2026"
PATH = "/api/defense/mode"
BODY = json.dumps({"mode": "advisory"}).encode()


def _headers(*, nonce: str, ts: float | None = None, token: str = TOKEN, kid: str | None = None,
             body: bytes = BODY, raw_token: bool = False, sig: str | None = None) -> dict[str, str]:
    stamp = f"{(time.time() if ts is None else ts):.3f}"
    signature = sig if sig is not None else compute_request_hmac(
        token, method="POST", path=PATH, timestamp=stamp, nonce=nonce, body=body)
    h = {"Content-Type": "application/json", "X-Aegis-Timestamp": stamp, "X-Aegis-Nonce": nonce,
         "X-Aegis-Signature": signature, "X-Aegis-Key-Id": kid if kid is not None else key_id(TOKEN)}
    if raw_token:
        h["X-Aegis-Token"] = TOKEN
    return h


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("AEGIS_API_TOKEN", TOKEN)
    monkeypatch.delenv("AEGIS_REQUIRE_SIGNED_API", raising=False)  # default: ON because a token is set
    monkeypatch.setattr(backend_app, "engine", LiveEngine(spec=SourceSpec(kind="sim")))
    for k in ("testclient", "unknown"):
        GLOBAL_RATE_LIMITER.clear(k)
    GLOBAL_REPLAY_CACHE._seen.clear()
    with TestClient(backend_app.app) as c:
        yield c
    for k in ("testclient", "unknown"):
        GLOBAL_RATE_LIMITER.clear(k)
    GLOBAL_REPLAY_CACHE._seen.clear()


def _post(c: TestClient, headers: dict[str, str], body: bytes = BODY):
    return c.post(PATH, content=body, headers=headers)


def test_valid_signed_only_request_is_accepted(client) -> None:
    h = _headers(nonce="matrix-ok-nonce-001")
    assert "X-Aegis-Token" not in h
    assert _post(client, h).status_code == 200


def test_missing_signature_is_rejected_by_default(client) -> None:
    # no auth headers at all
    r = _post(client, {"Content-Type": "application/json"})
    assert r.status_code == 401
    # raw token only (legacy client) is refused too: a replayable secret is no longer enough
    r = _post(client, {"Content-Type": "application/json", "X-Aegis-Token": TOKEN})
    assert r.status_code == 401
    assert "signed request" in r.json()["error"].lower()
    # Bearer form behaves the same
    r = _post(client, {"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 401


def test_incomplete_signed_headers_are_a_400(client) -> None:
    h = _headers(nonce="matrix-incomplete-01")
    del h["X-Aegis-Nonce"]
    assert _post(client, h).status_code == 400


def test_invalid_signature_is_rejected(client) -> None:
    r = _post(client, _headers(nonce="matrix-badsig-0001", sig="0" * 64))
    assert r.status_code == 401
    assert "hmac" in r.json()["error"].lower()
    # a signature made with another key, correct key id header
    r = _post(client, _headers(nonce="matrix-badsig-0002", token="other-key"))
    assert r.status_code == 401
    # a signature over a different body (tampered payload)
    other = json.dumps({"mode": "active-ips"}).encode()
    h = _headers(nonce="matrix-badsig-0003", body=BODY)
    assert _post(client, h, body=other).status_code == 401


def test_signature_binds_the_path(client) -> None:
    h = _headers(nonce="matrix-path-nonce-1")  # signed for PATH
    r = client.post("/api/defense/override", content=BODY, headers=h)
    assert r.status_code == 401


def test_replayed_nonce_is_rejected(client) -> None:
    h = _headers(nonce="matrix-replay-nonce1")
    assert _post(client, h).status_code == 200
    again = _post(client, h)
    assert again.status_code == 401
    assert "replay" in again.json()["error"].lower()


@pytest.mark.parametrize("skew_s", [-3600.0, -120.0, 120.0, 3600.0])
def test_expired_or_future_timestamp_is_rejected(client, skew_s) -> None:
    n = f"matrix-skew-{int(skew_s)}-nonce"
    r = _post(client, _headers(nonce=n, ts=time.time() + skew_s))
    assert r.status_code == 401
    assert "stale" in r.json()["error"].lower()
    # the rejected nonce was not burned: the same nonce with a fresh timestamp is accepted
    assert _post(client, _headers(nonce=n)).status_code == 200


def test_malformed_timestamp_and_nonce_are_rejected(client) -> None:
    h = _headers(nonce="matrix-ts-nonce-0001")
    h["X-Aegis-Timestamp"] = "not-a-number"
    assert _post(client, h).status_code == 400
    assert _post(client, _headers(nonce="short")).status_code == 401  # nonce < 8 chars


def test_wrong_key_id_is_rejected_and_counts_toward_lockout(client) -> None:
    r = _post(client, _headers(nonce="matrix-kid-nonce-0001", kid="0" * 16))
    assert r.status_code == 401
    assert "key-id" in r.json()["error"].lower()
    saw_429 = False
    for i in range(12):
        r = _post(client, _headers(nonce=f"matrix-kid-lock-{i:04d}x", kid="f" * 16))
        saw_429 = saw_429 or r.status_code == 429
    assert saw_429, "repeated bad key ids must trigger the lockout"


def test_compat_switch_still_requires_a_valid_signature_when_one_is_sent(client, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_REQUIRE_SIGNED_API", "0")
    legacy = {"Content-Type": "application/json", "X-Aegis-Token": TOKEN}
    assert _post(client, legacy).status_code == 200  # legacy token-only is the whole point of the switch
    assert _post(client, {"Content-Type": "application/json", "X-Aegis-Token": "wrong"}).status_code == 401
    # a client that DOES sign cannot be downgraded by the switch: a forged signature is still refused
    forged = _headers(nonce="matrix-compat-forge1", sig="0" * 64, raw_token=True)
    assert _post(client, forged).status_code == 401
    # and signed-only requests keep working
    assert _post(client, _headers(nonce="matrix-compat-ok-001")).status_code == 200


def test_force_on_rejects_legacy_token_only(client, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_REQUIRE_SIGNED_API", "1")
    assert _post(client, {"Content-Type": "application/json", "X-Aegis-Token": TOKEN}).status_code == 401


def test_cors_preflight_allows_the_key_id_header(client) -> None:
    """A dashboard on another allow-listed dev origin signs with X-Aegis-Key-Id; the preflight must allow it."""
    r = client.options(
        PATH,
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-aegis-key-id,x-aegis-nonce,x-aegis-signature,x-aegis-timestamp",
        },
    )
    assert r.status_code == 200, r.text
    allowed = r.headers.get("access-control-allow-headers", "").lower()
    for name in ("x-aegis-key-id", "x-aegis-nonce", "x-aegis-signature", "x-aegis-timestamp"):
        assert name in allowed
