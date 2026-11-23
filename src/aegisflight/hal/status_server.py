"""HTTP status endpoint for the inline IPS bridge (``aegis ips-bridge --status-port``).

``GET /status`` (read-only) returns ``InlineIpsBridge.status()`` plus crossend, signing and control info.
``POST /posture`` changes the bridge posture; it works only when a control token was configured
(``--control-token-file``) and requires that token. Everything else is refused with 405.
"""
from __future__ import annotations

import hmac
import json
import math
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..backend.security import RateLimiter, ReplayCache, compute_request_hmac

ALLOWED_ORIGINS = frozenset({
    "http://localhost:5173", "http://127.0.0.1:5173",
    "http://localhost:8000", "http://127.0.0.1:8000",
    "http://localhost:8008", "http://127.0.0.1:8008",
    "tauri://localhost", "http://tauri.localhost", "https://tauri.localhost",
})


class BridgeStatusServer:
    def __init__(self, bridge: Any, port: int = 0, *, host: str = "127.0.0.1", control_token: str | None = None,
                 signing_configured: bool = False, allow_unsigned: bool = False) -> None:
        self.bridge = bridge
        self.control_token = (control_token or "").strip() or None
        self.signing_configured = bool(signing_configured)
        self.unsigned_acknowledged = bool(allow_unsigned) and not self.signing_configured
        self._replay = ReplayCache()
        self._limiter = RateLimiter()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a: Any) -> None:  # silent
                pass

            def _cors(self) -> None:
                origin = self.headers.get("Origin")
                if origin in ALLOWED_ORIGINS:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")

            # A stalled or slow-drip client may not hold a handler thread forever.
            timeout = 5.0

            def handle_one_request(self) -> None:
                self._body_done = False
                self.oversize = False
                super().handle_one_request()

            def _read_body(self, limit: int = 4096, budget: int = 65536) -> bytes | None:
                """Consume a small request body so the socket closes cleanly (an unread body turns the close
                into a TCP reset, which aborts the client's read on Windows). Returns the body if it is
                1..limit bytes, else None. A declared length above ``budget`` is NOT read: the request is
                flagged ``oversize`` and the connection is closed after the reply (an abusive client may
                see a reset; it never ties up the handler)."""
                if self._body_done:  # already consumed for this request
                    return self._body
                self._body_done, self._body = True, None
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    return None
                if n <= 0:
                    return None
                if n > budget:
                    self.oversize = True
                    self.close_connection = True
                    return None
                # The socket timeout is per recv(), so a client dripping one byte per few seconds would otherwise
                # hold this thread for hours: bound the whole body read with one monotonic deadline.
                deadline = time.monotonic() + (self.timeout or 5.0)
                try:
                    data = self._read_until(min(n, limit), deadline)
                    remaining = n - len(data)
                    while remaining > 0:  # discard the excess (<= budget in total)
                        chunk = self._read_until(min(remaining, 65536), deadline)
                        if not chunk:
                            break
                        remaining -= len(chunk)
                except OSError:  # timeout / reset while reading: drop the connection
                    self.close_connection = True
                    return None
                self._body = data if n <= limit else None
                return self._body

            def _read_until(self, n: int, deadline: float) -> bytes:
                """Read up to n bytes (fewer only at EOF) before the deadline; raises TimeoutError past it."""
                buf = bytearray()
                try:
                    while len(buf) < n:
                        left = deadline - time.monotonic()
                        if left <= 0:
                            raise TimeoutError("request body not received within the deadline")
                        self.connection.settimeout(left)
                        chunk = self.rfile.read1(n - len(buf))
                        if not chunk:
                            break
                        buf += chunk
                finally:
                    self.connection.settimeout(self.timeout)  # the reply is written under the normal timeout
                return bytes(buf)

            def _close_hdr(self) -> None:
                if self.close_connection:
                    self.send_header("Connection", "close")

            def _send(self, code: int, body: bytes, ctype: str = "application/json", extra_headers: dict[str, str] | None = None) -> None:
                self.send_response(code)
                self._cors()
                self.send_header("Content-Type", ctype)
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                if extra_headers:
                    for hk, hv in extra_headers.items():
                        self.send_header(hk, hv)
                self.send_header("Content-Length", str(len(body)))
                self._close_hdr()
                self.end_headers()
                self.wfile.write(body)

            def _json(self, code: int, obj: dict, extra_headers: dict[str, str] | None = None) -> None:
                self._send(code, json.dumps(obj).encode(), extra_headers=extra_headers)

            def do_GET(self) -> None:  # noqa: N802
                if self.path.split("?", 1)[0] != "/status":
                    self._send(404, b'{"error":"not found"}')
                    return
                try:
                    self._send(200, json.dumps(outer._status()).encode())
                except Exception:  # noqa: BLE001
                    self._send(500, b'{"error":"status unavailable"}')

            def _refuse(self) -> None:
                self._read_body()
                self.send_response(405)
                self.send_header("Allow", "GET, POST, OPTIONS")
                self.send_header("Content-Length", "0")
                self._close_hdr()
                self.end_headers()

            def _token_ok(self) -> bool:
                provided = self.headers.get("X-Aegis-Token", "").strip()
                if not provided:
                    auth = self.headers.get("Authorization", "").strip()
                    if auth.lower().startswith("bearer "):
                        provided = auth[7:].strip()
                return bool(provided) and hmac.compare_digest(provided.encode(), (outer.control_token or "").encode())

            def do_OPTIONS(self) -> None:  # noqa: N802
                if self.path.split("?", 1)[0] != "/posture":
                    self._refuse()
                    return
                origin = self.headers.get("Origin")
                self.send_response(204)
                if origin in ALLOWED_ORIGINS:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")
                    self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
                    self.send_header(
                        "Access-Control-Allow-Headers",
                        "Authorization, X-Aegis-Token, X-Aegis-Nonce, X-Aegis-Timestamp, X-Aegis-Signature, Content-Type",
                    )
                    self.send_header("Access-Control-Max-Age", "600")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self) -> None:  # noqa: N802
                raw = self._read_body()  # always consume a small body, even when we are about to reject
                if self.oversize:
                    self._json(413, {"ok": False, "error": "payload_too_large"})
                    return
                if self.path.split("?", 1)[0] != "/posture":
                    self._refuse()
                    return
                origin = self.headers.get("Origin")
                if origin is not None and origin not in ALLOWED_ORIGINS:
                    self._json(403, {"ok": False, "error": "forbidden_origin"})
                    return
                if outer.control_token is None:
                    self._json(403, {"error": "control_disabled"})
                    return
                client_ip = str(self.client_address[0]) if self.client_address else "unknown"
                if (retry_after := outer._limiter.check_allowed(client_ip)) is not None:
                    self._json(429, {"ok": False, "error": "rate_limited"}, extra_headers={"Retry-After": str(retry_after)})
                    return
                if not self._token_ok():
                    retry = outer._limiter.record_failure(client_ip)
                    if retry is not None:
                        self._json(429, {"ok": False, "error": "rate_limited"}, extra_headers={"Retry-After": str(retry)})
                    else:
                        self._json(401, {"ok": False, "error": "unauthorized"})
                    return
                raw_body = raw if raw is not None else b""  # already consumed and bounded by _read_body
                nonce = self.headers.get("X-Aegis-Nonce", "").strip()
                ts_str = self.headers.get("X-Aegis-Timestamp", "").strip()
                sig = self.headers.get("X-Aegis-Signature", "").strip().lower()
                if nonce or ts_str or sig:
                    try:
                        ts_val = float(ts_str)
                    except ValueError:
                        ts_val = float("nan")
                    if not math.isfinite(ts_val):  # float() accepts nan/inf; nan would defeat the freshness check
                        self._json(400, {"ok": False, "error": "invalid_timestamp"})
                        return
                    # Read-only freshness/replay check first; the nonce is recorded only AFTER the HMAC verifies,
                    # so a forged request cannot burn a nonce a legitimate client has yet to use (#89).
                    ok_replay, detail = outer._replay.check(nonce, ts_val)
                    if not ok_replay:
                        outer._limiter.record_failure(client_ip)
                        self._json(401, {"ok": False, "error": detail})
                        return
                    expected_sig = compute_request_hmac(
                        outer.control_token,
                        method="POST",
                        path="/posture",
                        timestamp=ts_str,
                        nonce=nonce,
                        body=raw_body,
                    )
                    if not sig or not hmac.compare_digest(sig, expected_sig):
                        outer._limiter.record_failure(client_ip)
                        self._json(401, {"ok": False, "error": "invalid_signature"})
                        return
                    recorded, detail = outer._replay.record(nonce, ts_val)  # atomic: a concurrent twin loses here
                    if not recorded:
                        outer._limiter.record_failure(client_ip)
                        self._json(401, {"ok": False, "error": detail})
                        return
                outer._limiter.clear(client_ip)
                try:
                    body = json.loads(raw_body.decode("utf-8")) if raw_body else None
                except (ValueError, UnicodeDecodeError):
                    body = None
                if not isinstance(body, dict):
                    self._json(400, {"ok": False, "error": "bad_request"})
                    return
                mode = body.get("mode")
                allow = body.get("allow_unsigned", False)
                if mode not in ("passive", "advisory", "active-ips") or not isinstance(allow, bool):
                    self._json(400, {"ok": False, "error": "bad_request",
                                     "choices": ["passive", "advisory", "active-ips"]})
                    return
                if mode == "active-ips" and not outer.signing_configured and allow is not True:
                    self._json(409, {"ok": False, "error": "signing_required",
                                     "message": "Unsigned links cannot stop a counter-tracking forger; provision a key "
                                                "and start the bridge with --signing-key-file, or acknowledge the risk.",
                                     "signing": {"configured": False}})
                    return
                try:
                    outer.bridge.set_mode(mode)
                    outer.unsigned_acknowledged = (mode == "active-ips" and not outer.signing_configured)
                    ack = ", unsigned acknowledged" if outer.unsigned_acknowledged else ""
                    print(f"aegis ips-bridge: posture -> {mode} (remote{ack})", flush=True)
                    self._json(200, {"ok": True, "status": outer._status()})
                except ValueError as exc:  # receive-only boundary: active-ips on a serial-device FC port
                    self._json(409, {"ok": False, "error": "receive_only_link", "message": str(exc)})
                except Exception:  # noqa: BLE001
                    self._json(500, {"ok": False, "error": "posture change failed"})

            do_PUT = do_DELETE = do_PATCH = _refuse  # noqa: N815

        self._httpd = ThreadingHTTPServer((host, port), Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="bridge-status", daemon=True)

    def _status(self) -> dict[str, Any]:
        st = dict(self.bridge.status())
        st["crossend"] = {"sent": int(getattr(self.bridge, "crossend_sent", 0))}
        st["signing"] = {"configured": self.signing_configured, "unsigned_acknowledged": self.unsigned_acknowledged}
        st["control"] = {"enabled": self.control_token is not None}
        return st

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def start(self) -> BridgeStatusServer:
        self._thread.start()
        return self

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
