"""End-to-end backend control security & audit hardening (W13)."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import math
import os
import threading
import time
from collections import OrderedDict, deque
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

_CSP_HEADER = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)


def _client_ip(request: Request) -> str:
    if request.client is not None and request.client.host:
        return str(request.client.host)
    return "unknown"


def is_loopback_client(request: Request) -> bool:
    """Return True if the TCP peer (or ASGI TestClient) is local loopback."""
    host = _client_ip(request).strip().lower()
    if host in ("localhost", "testclient", "::1", "127.0.0.1"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ReplayCache:
    """Bounded TTL cache preventing nonce replay on control-plane requests."""

    def __init__(self, *, ttl_s: float = 60.0, max_entries: int = 4096) -> None:
        self.ttl_s = float(ttl_s)
        self.max_entries = int(max_entries)
        self._lock = threading.Lock()
        self._seen: OrderedDict[str, float] = OrderedDict()

    def _format_error(self, nonce: str, timestamp_s: float, now: float) -> str | None:
        if not nonce or len(nonce) < 8 or len(nonce) > 128:
            return "invalid nonce format"
        if not math.isfinite(timestamp_s):  # nan compares False against every bound, so it would never look stale
            return "invalid timestamp"
        if abs(now - timestamp_s) > self.ttl_s:
            return f"stale timestamp (skew {abs(now - timestamp_s):.1f}s > {self.ttl_s:.0f}s)"
        return None

    def _evict(self, now: float) -> None:
        cutoff = now - self.ttl_s
        while self._seen:
            _oldest_k, oldest_t = next(iter(self._seen.items()))
            if oldest_t >= cutoff:
                break
            self._seen.popitem(last=False)

    def check(self, nonce: str, timestamp_s: float, *, now_s: float | None = None) -> tuple[bool, str]:
        """Validate format, freshness and novelty WITHOUT recording the nonce.

        Used before signature verification so an unauthenticated request cannot burn a nonce
        that a legitimate client may still use. Call :meth:`record` after the signature verifies.
        """
        now = time.time() if now_s is None else float(now_s)
        if (err := self._format_error(nonce, timestamp_s, now)) is not None:
            return False, err
        with self._lock:
            self._evict(now)
            if nonce in self._seen:
                return False, "nonce replay rejected"
        return True, "ok"

    def record(self, nonce: str, timestamp_s: float, *, now_s: float | None = None) -> tuple[bool, str]:
        """Atomically record a nonce; False if it was already seen (closes the check/record race)."""
        return self.check_and_record(nonce, timestamp_s, now_s=now_s)

    def check_and_record(self, nonce: str, timestamp_s: float, *, now_s: float | None = None) -> tuple[bool, str]:
        now = time.time() if now_s is None else float(now_s)
        if (err := self._format_error(nonce, timestamp_s, now)) is not None:
            return False, err
        with self._lock:
            self._evict(now)
            if nonce in self._seen:
                return False, "nonce replay rejected"
            if len(self._seen) >= self.max_entries:
                self._seen.popitem(last=False)
            # A timestamp up to +ttl ahead is accepted, so remember the nonce until that timestamp
            # is itself stale; keyed on receipt time alone it could be replayed after eviction.
            self._seen[nonce] = max(now, float(timestamp_s))
        return True, "ok"


class RateLimiter:
    """Sliding-window failure lockout & mutating-endpoint rate limiter."""

    def __init__(self, *, max_failures: int = 10, window_s: float = 60.0, lockout_s: float = 300.0) -> None:
        self.max_failures = max(1, int(max_failures))
        self.window_s = float(window_s)
        self.lockout_s = float(lockout_s)
        self._lock = threading.Lock()
        self._failures: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}

    def check_allowed(self, key: str, *, now: float | None = None) -> int | None:
        """Return Retry-After seconds if locked out, else None."""
        t = time.monotonic() if now is None else float(now)
        with self._lock:
            until = self._locked_until.get(key)
            if until is not None:
                if t < until:
                    return max(1, int(until - t))
                self._locked_until.pop(key, None)
        return None

    def record_failure(self, key: str, *, now: float | None = None) -> int | None:
        """Record an authentication failure; return Retry-After seconds if lockout triggered."""
        t = time.monotonic() if now is None else float(now)
        with self._lock:
            if key not in self._failures and len(self._failures) >= 4096:
                self._failures.pop(next(iter(self._failures)))
            q = self._failures.setdefault(key, deque())
            cutoff = t - self.window_s
            while q and q[0] < cutoff:
                q.popleft()
            q.append(t)
            if len(q) >= self.max_failures:
                q.clear()
                if key not in self._locked_until and len(self._locked_until) >= 4096:
                    self._locked_until.pop(next(iter(self._locked_until)))
                self._locked_until[key] = t + self.lockout_s
                return int(self.lockout_s)
        return None

    def clear(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)


def key_id(token: str) -> str:
    """Public, non-reversible identifier of a shared token (sent as ``X-Aegis-Key-Id`` instead of the token)."""
    return hashlib.sha256(b"aegis-key-id:" + token.encode()).hexdigest()[:16]


def signed_api_required(token: str) -> bool:
    """Whether unsigned control requests are refused.

    ``AEGIS_REQUIRE_SIGNED_API=1`` forces it on, ``=0`` is the documented compatibility switch that
    allows legacy token-only clients, and when unset it is ON whenever an API token is configured.
    """
    raw = os.environ.get("AEGIS_REQUIRE_SIGNED_API", "").strip()
    if raw == "1":
        return True
    if raw == "0":
        return False
    return bool(token)


def compute_request_hmac(
    token: str,
    *,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> str:
    """Compute canonical HMAC-SHA256 signature verified by the backend and frontend."""
    body_sha = hashlib.sha256(body).hexdigest()
    msg = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_sha}".encode()
    return hmac.new(token.encode(), msg, hashlib.sha256).hexdigest()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach restrictive CSP and anti-clickjacking/no-store headers."""

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        resp = await call_next(request)
        resp.headers.setdefault("Content-Security-Policy", _CSP_HEADER)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp


GLOBAL_REPLAY_CACHE = ReplayCache()
GLOBAL_RATE_LIMITER = RateLimiter()


async def read_bounded_body(request: Request, max_bytes: int = 16384) -> bytes:
    """Read request body up to ``max_bytes`` (raises ValueError if oversized)."""
    raw = await request.body()
    if len(raw) > max_bytes:
        raise ValueError(f"payload too large ({len(raw)} > {max_bytes} bytes)")
    return raw


def verify_signed_headers(
    request: Request,
    *,
    token: str,
    body: bytes,
    require_signed: bool = False,
) -> JSONResponse | None:
    """Validate optional/required ``X-Aegis-Nonce``, ``X-Aegis-Timestamp``, and ``X-Aegis-Signature``."""
    nonce = request.headers.get("x-aegis-nonce", "").strip()
    ts_str = request.headers.get("x-aegis-timestamp", "").strip()
    sig = request.headers.get("x-aegis-signature", "").strip().lower()

    has_any = bool(nonce or ts_str or sig)
    if not has_any:
        if require_signed or signed_api_required(token):
            return JSONResponse(
                status_code=401,
                content={"ok": False, "error": "signed request headers (nonce, timestamp, signature) required"},
            )
        return None

    if not (nonce and ts_str and sig):
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "incomplete signed request headers"},
        )
    try:
        ts_val = float(ts_str)
    except ValueError:
        return JSONResponse(status_code=400, content={"ok": False, "error": "invalid X-Aegis-Timestamp"})

    ip = _client_ip(request)
    if (retry_after := GLOBAL_RATE_LIMITER.check_allowed(ip)) is not None:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            content={"ok": False, "error": "too many invalid authentication attempts"},
        )

    claimed_kid = request.headers.get("x-aegis-key-id", "").strip().lower()
    if claimed_kid and not hmac.compare_digest(claimed_kid.encode(), key_id(token).encode()):
        retry = GLOBAL_RATE_LIMITER.record_failure(ip)
        headers = {"Retry-After": str(retry)} if retry else {}
        return JSONResponse(
            status_code=401 if not retry else 429,
            headers=headers,
            content={"ok": False, "error": "unknown X-Aegis-Key-Id"},
        )

    # Read-only freshness/replay check first; the nonce is recorded only AFTER the HMAC verifies, so a
    # forged or corrupted request cannot burn a nonce that a legitimate client has yet to use.
    ok, detail = GLOBAL_REPLAY_CACHE.check(nonce, ts_val)
    if not ok:
        GLOBAL_RATE_LIMITER.record_failure(ip)
        return JSONResponse(status_code=401, content={"ok": False, "error": detail})

    expected = compute_request_hmac(
        token,
        method=request.method,
        path=request.url.path,
        timestamp=ts_str,
        nonce=nonce,
        body=body,
    )
    if not hmac.compare_digest(sig, expected):
        retry = GLOBAL_RATE_LIMITER.record_failure(ip)
        headers = {"Retry-After": str(retry)} if retry else {}
        return JSONResponse(
            status_code=401 if not retry else 429,
            headers=headers,
            content={"ok": False, "error": "invalid request HMAC signature"},
        )
    # Atomic record: a concurrent request with the same (validly signed) nonce loses here.
    recorded, detail = GLOBAL_REPLAY_CACHE.record(nonce, ts_val)
    if not recorded:
        GLOBAL_RATE_LIMITER.record_failure(ip)
        return JSONResponse(status_code=401, content={"ok": False, "error": detail})
    GLOBAL_RATE_LIMITER.clear(ip)
    return None
