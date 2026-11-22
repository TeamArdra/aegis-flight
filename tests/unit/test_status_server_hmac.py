"""Adversarial tests for the bridge status server's POST /posture authentication path.

Each test pins one property of the token + optional HMAC + replay + rate-limit chain: what is signed is
what the server's body reader returned, a rejected request never changes posture, a forged request cannot
burn a nonce, and non-finite timestamps are refused. Raw sockets control Content-Length and the body bytes.
"""
from __future__ import annotations

import json
import socket
import time

import pytest

from aegisflight.backend.security import ReplayCache, compute_request_hmac
from aegisflight.hal.status_server import BridgeStatusServer
from aegisflight.mitigation import DefenseMode

TOKEN = "s3cret-token"


class _Ctl:
    mode = DefenseMode.PASSIVE


class FakeBridge:
    crossend_sent = 0

    def __init__(self):
        self.controller = _Ctl()
        self.calls = []

    def set_mode(self, m):
        self.calls.append(m)
        self.controller.mode = DefenseMode(m)

    def status(self):
        return {"mode": self.controller.mode.value}


@pytest.fixture
def srv():
    made = []

    def make(**kw):
        b = FakeBridge()
        s = BridgeStatusServer(b, control_token=TOKEN, signing_configured=True, **kw).start()
        made.append(s)
        return s, b

    yield make
    for s in made:
        s.close()


def _sign(body, *, nonce, ts=None, token=TOKEN, path="/posture"):
    ts = ts if ts is not None else f"{time.time():.3f}"
    return {
        "Authorization": f"Bearer {TOKEN}",
        "X-Aegis-Nonce": nonce,
        "X-Aegis-Timestamp": ts,
        "X-Aegis-Signature": compute_request_hmac(token, method="POST", path=path, timestamp=ts, nonce=nonce, body=body),
    }


def _raw(port, headers, sent, *, declared=None, timeout=8.0):
    """POST /posture with an explicit Content-Length (default len(sent)) and exactly the bytes sent as the body.
    Returns the HTTP status, or 0 if the server closed without answering."""
    n = len(sent) if declared is None else declared
    head = "POST /posture HTTP/1.1\r\nHost: x\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    head += f"Content-Length: {n}\r\n\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as c:
        c.sendall(head.encode() + sent)
        try:
            data = b""
            while b"\r\n" not in data:
                chunk = c.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            return 0
    return int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else 0


BODY = json.dumps({"mode": "advisory"}).encode()


def test_valid_signed_request_is_accepted_over_the_exact_body(srv):
    s, b = srv()
    assert _raw(s.port, _sign(BODY, nonce="nonce-0001"), BODY) == 200
    assert b.calls == ["advisory"]


def test_signature_over_a_different_body_is_rejected(srv):
    s, b = srv()
    other = json.dumps({"mode": "passive"}).encode()
    assert _raw(s.port, _sign(other, nonce="nonce-0002"), BODY) == 401
    assert b.calls == []


def test_signature_over_a_different_path_or_wrong_key_is_rejected(srv):
    s, b = srv()
    assert _raw(s.port, _sign(BODY, nonce="nonce-0003", path="/status"), BODY) == 401
    assert _raw(s.port, _sign(BODY, nonce="nonce-0004", token="other-key"), BODY) == 401
    assert b.calls == []


def test_replayed_nonce_is_rejected_even_with_a_valid_signature(srv):
    s, b = srv()
    h = _sign(BODY, nonce="nonce-0005")
    assert _raw(s.port, h, BODY) == 200
    assert _raw(s.port, h, BODY) == 401
    assert b.calls == ["advisory"]


def test_bad_signature_does_not_burn_the_nonce_for_the_legitimate_request(srv):
    """A forged request carrying a victim's nonce must not make the victim's real request a replay."""
    s, b = srv()
    forged = _sign(BODY, nonce="nonce-0006")
    forged["X-Aegis-Signature"] = "0" * 64
    assert _raw(s.port, forged, BODY) == 401
    assert _raw(s.port, _sign(BODY, nonce="nonce-0006"), BODY) == 200
    assert b.calls == ["advisory"]


def test_nonce_and_timestamp_without_signature_does_not_burn_the_nonce(srv):
    s, b = srv()
    h = _sign(BODY, nonce="nonce-0007")
    partial = dict(h)
    del partial["X-Aegis-Signature"]
    assert _raw(s.port, partial, BODY) == 401
    assert _raw(s.port, h, BODY) == 200


@pytest.mark.parametrize("bad_ts", ["nan", "NaN", "inf", "-inf", "", "abc", "1e999"])
def test_non_finite_or_malformed_timestamp_is_rejected(srv, bad_ts):
    s, b = srv()
    h = _sign(BODY, nonce="nonce-0008", ts=bad_ts)
    assert _raw(s.port, h, BODY) in (400, 401)
    assert b.calls == []


def test_stale_timestamp_is_rejected(srv):
    s, b = srv()
    assert _raw(s.port, _sign(BODY, nonce="nonce-0009", ts=f"{time.time() - 3600:.3f}"), BODY) == 401
    assert b.calls == []


def test_body_over_the_cap_is_never_authorised_by_a_signature_over_its_prefix(srv):
    """The server keeps at most 4096 body bytes. A larger body is dropped (treated as absent): a signature over
    the first 4096 bytes must not authorise it, and nothing may change posture."""
    s, b = srv()
    big = (BODY + b" " * 6000)[:6000]  # valid-JSON prefix then padding; in budget (at most 64 KiB)
    assert _raw(s.port, _sign(big[:4096], nonce="nonce-0010"), big) == 401
    assert b.calls == []


def test_body_over_the_cap_with_a_signature_over_empty_never_changes_posture(srv):
    s, b = srv()
    big = BODY + b" " * 6000
    code = _raw(s.port, _sign(b"", nonce="nonce-0011"), big)
    assert code in (400, 401, 413)  # never a 2xx
    assert b.calls == []


def test_declared_length_above_budget_is_refused_before_auth(srv):
    s, b = srv()
    assert _raw(s.port, _sign(BODY, nonce="nonce-0012"), BODY, declared=10_000_000) in (0, 413)
    assert b.calls == []
    assert _raw(s.port, _sign(BODY, nonce="nonce-0013"), BODY) == 200  # server still serves afterwards


def test_content_length_shorter_than_body_signs_only_the_declared_bytes(srv):
    s, b = srv()
    trailing = b'{"mode": "passive"}'
    # Declared length covers BODY only; the trailing bytes are not part of the request.
    assert _raw(s.port, _sign(BODY + trailing, nonce="nonce-0014"), BODY + trailing, declared=len(BODY)) == 401
    assert b.calls == []
    assert _raw(s.port, _sign(BODY, nonce="nonce-0015"), BODY + trailing, declared=len(BODY)) == 200
    assert b.calls == ["advisory"]


def test_content_length_longer_than_body_times_out_and_changes_nothing(srv):
    s, b = srv()
    s._httpd.RequestHandlerClass.timeout = 0.5  # class attribute read per connection (production default 5 s)
    code = _raw(s.port, _sign(BODY, nonce="nonce-0016"), BODY, declared=len(BODY) + 50)
    assert code != 200
    assert b.calls == []


def test_no_unauthenticated_request_ever_returns_2xx(srv):
    s, b = srv()
    variants = [
        {}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic czNjcmV0LXRva2Vu"},
        {"X-Aegis-Token": ""}, {"Authorization": "Bearer "}, {"X-Aegis-Token": TOKEN + "x"},
        {"X-Aegis-Token": TOKEN[:-1]},
    ]
    for hdrs in variants:
        assert _raw(s.port, hdrs, BODY) in (401, 429), hdrs
    # A valid-looking signature without the token header is still unauthorised.
    h = _sign(BODY, nonce="nonce-0017")
    del h["Authorization"]
    assert _raw(s.port, h, BODY) == 401
    assert b.calls == []


def test_rate_limit_locks_out_a_client_after_repeated_bad_signatures(srv):
    s, b = srv()
    for i in range(12):
        h = _sign(BODY, nonce=f"nonce-bad{i:03d}")
        h["X-Aegis-Signature"] = "f" * 64
        _raw(s.port, h, BODY)
    assert _raw(s.port, _sign(BODY, nonce="nonce-good-1"), BODY) == 429
    assert b.calls == []


def test_rejected_request_body_is_drained_so_the_reply_is_not_reset(srv):
    s, _b = srv()
    for i in range(10):
        h = _sign(BODY, nonce=f"nonce-drn{i:03d}")
        h["X-Aegis-Signature"] = "0" * 64
        assert _raw(s.port, h, b"x" * 50_000) == 401


def test_replaycache_rejects_non_finite_timestamps():
    rc = ReplayCache()
    for bad in (float("nan"), float("inf"), float("-inf")):
        ok, _ = rc.check("abcdefgh", bad)
        assert not ok
        ok, _ = rc.check_and_record("abcdefgh", bad)
        assert not ok


def test_slow_drip_body_is_dropped_by_a_total_deadline(srv):
    """A client trickling one byte per interval (each within the per-recv timeout) must still be cut off."""
    s, b = srv()
    s._httpd.RequestHandlerClass.timeout = 0.5  # production default 5 s
    t0 = time.monotonic()
    with socket.create_connection(("127.0.0.1", s.port), timeout=10) as c:
        c.sendall(b"POST /posture HTTP/1.1\r\nHost: x\r\nContent-Length: 4000\r\n\r\n")
        dropped = False
        for _ in range(40):
            try:
                c.sendall(b"a")
                time.sleep(0.3)
            except OSError:
                dropped = True
                break
        elapsed = time.monotonic() - t0
    assert dropped and elapsed < 5, f"handler kept reading a dripped body for {elapsed:.1f}s"
    assert b.calls == []


def test_future_dated_nonce_cannot_be_replayed_after_its_receipt_time_ages_out():
    """A timestamp up to +ttl ahead is accepted, so its nonce must be remembered until the
    timestamp itself is stale, not just until the receipt time is (independent review on #142)."""
    cache = ReplayCache(ttl_s=60.0)
    ok, _ = cache.check_and_record("nonce-future-1", 1059.0, now_s=1000.0)
    assert ok
    ok, why = cache.check_and_record("nonce-future-1", 1059.0, now_s=1061.0)
    assert not ok and "replay" in why
    ok, why = cache.check("nonce-future-1", 1059.0, now_s=1100.0)
    assert not ok and "replay" in why
    ok, why = cache.check_and_record("nonce-future-1", 1059.0, now_s=1120.0)  # the timestamp is now stale
    assert not ok and "stale" in why
