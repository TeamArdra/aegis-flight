"""scripts/verify_stage2.py suite 7 must authenticate with signed-only requests (D9, #93).

The script runs the real backend verifier in-process. It must pass against the signed-only default (token set, no
``AEGIS_REQUIRE_SIGNED_API``), and the requests it sends must carry no raw token.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegisflight.backend.security import GLOBAL_RATE_LIMITER, GLOBAL_REPLAY_CACHE

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify_stage2.py"
TOKEN_HEADERS = {"x-aegis-token", "authorization"}


def _load_script():
    spec = importlib.util.spec_from_file_location("verify_stage2_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_suite7_sends_signed_only_requests_and_passes(monkeypatch, capsys):
    monkeypatch.delenv("AEGIS_REQUIRE_SIGNED_API", raising=False)  # default: signed required whenever a token is set
    for k in ("testclient", "unknown"):
        GLOBAL_RATE_LIMITER.clear(k)
    GLOBAL_REPLAY_CACHE._seen.clear()
    mod = _load_script()
    sent: list[dict[str, str]] = []

    class RecordingClient(TestClient):
        def request(self, method, url, **kwargs):
            sent.append({k.lower(): v for k, v in (kwargs.get("headers") or {}).items()})
            return super().request(method, url, **kwargs)

    monkeypatch.setattr(mod, "TestClient", RecordingClient)
    mod.audit_control_plane_security()  # sys.exit(1) on any unexpected status
    assert "[PASS]" in capsys.readouterr().out
    signed = [h for h in sent if "x-aegis-signature" in h]
    assert len(signed) >= 3, "accepted, replayed and tampered requests are all signed"
    for h in signed:
        assert {"x-aegis-key-id", "x-aegis-timestamp", "x-aegis-nonce"} <= h.keys()
        assert not (TOKEN_HEADERS & h.keys()), "signed-only: no raw token on the wire"


def test_token_only_request_is_refused_by_default(monkeypatch):
    """The failure the script used to hit: a raw token with no signature is 401 under the signed-only default."""
    from aegisflight.backend import app as backend_app

    monkeypatch.setenv("AEGIS_API_TOKEN", "audit-token-2026")
    monkeypatch.delenv("AEGIS_REQUIRE_SIGNED_API", raising=False)
    GLOBAL_REPLAY_CACHE._seen.clear()
    for k in ("testclient", "unknown"):
        GLOBAL_RATE_LIMITER.clear(k)
    r = TestClient(backend_app.app).post(
        "/api/defense/mode", json={"mode": "passive"},
        headers={"X-Aegis-Token": "audit-token-2026", "Origin": "tauri://localhost"})
    assert r.status_code == 401


@pytest.mark.parametrize("flag", ["0"])
def test_compat_switch_allows_token_only(monkeypatch, flag):
    from aegisflight.backend import app as backend_app

    monkeypatch.setenv("AEGIS_API_TOKEN", "audit-token-2026")
    monkeypatch.setenv("AEGIS_REQUIRE_SIGNED_API", flag)
    for k in ("testclient", "unknown"):
        GLOBAL_RATE_LIMITER.clear(k)
    r = TestClient(backend_app.app).post(
        "/api/defense/mode", json={"mode": "passive"},
        headers={"X-Aegis-Token": "audit-token-2026", "Origin": "tauri://localhost"})
    assert r.status_code == 200
