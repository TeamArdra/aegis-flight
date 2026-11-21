"""Client-side request signing for non-browser callers of the control plane (scripts, tests, bench tooling).

The browser console signs with Web Crypto (``frontend/src/lib/requestAuth.ts``); every Python client uses this one helper so
the canonical string stays in a single place (:func:`aegisflight.backend.security.compute_request_hmac`).

Transport compatibility:

* The current backend requires the raw token (``X-Aegis-Token`` / Bearer) and *optionally* verifies a signature.
* The signed-only proposal (#93) requires a signature and treats the raw token as optional (and refuses a token-only request
  by default).

``signed_headers`` therefore sends the signature set **and, by default, the raw token**, which both backends accept. Pass
``include_token=False`` once the signed-only scheme is the deployed backend, so the secret never crosses the wire.
"""

from __future__ import annotations

import hashlib
import secrets
import time

from .security import compute_request_hmac


def key_id(token: str) -> str:
    """Public identifier of ``token`` (same derivation the signed-only backend checks in ``X-Aegis-Key-Id``)."""
    return hashlib.sha256(b"aegis-key-id:" + token.encode()).hexdigest()[:16]


def signed_headers(
    token: str,
    method: str,
    path: str,
    body: bytes | str = b"",
    *,
    include_token: bool = True,
    now_s: float | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Headers authenticating one request; the signature covers method, path (no query), timestamp, nonce and body.

    ``body`` must be the exact bytes sent. Each call draws a fresh nonce: build headers per request, never reuse them.
    """
    if not token:
        return {}
    raw = body.encode() if isinstance(body, str) else body
    signed_path = path.split("?", 1)[0]  # the backend verifies request.url.path, which excludes the query string
    ts = f"{(time.time() if now_s is None else now_s):.3f}"
    n = nonce or secrets.token_hex(16)
    headers = {
        "X-Aegis-Key-Id": key_id(token),
        "X-Aegis-Timestamp": ts,
        "X-Aegis-Nonce": n,
        "X-Aegis-Signature": compute_request_hmac(
            token, method=method, path=signed_path, timestamp=ts, nonce=n, body=raw),
    }
    if include_token:
        headers["X-Aegis-Token"] = token
    return headers
