"""Minimal GitHub REST/GraphQL client (standard library only).

Design points:
- Tokens are held in memory and sent only to the configured API host. Redirects (artifact
  downloads go to a storage host) are followed manually WITHOUT the Authorization header.
- Reads retry transient failures (connection errors, 5xx, 429, secondary rate limits) with
  exponential backoff. Writes are not retried automatically unless the caller says the
  operation is idempotent: the merge gate re-reads state after every write instead.
- Error messages never include request headers or the token.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any, Protocol

API_URL = "https://api.github.com"
_TRANSIENT_STATUS = {500, 502, 503, 504, 429}
_MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024  # review records are a few KiB


class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str, path: str) -> None:
        super().__init__(f"GitHub API {status} for {path}: {message}")
        self.status = status
        self.message = message
        self.path = path


class GitHubLike(Protocol):
    """The subset of the client the automation uses (implemented by test fakes too)."""

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any: ...
    def paginate(self, path: str, params: dict[str, Any] | None = None,
                 item_key: str | None = None) -> list[Any]: ...
    def post(self, path: str, body: dict[str, Any] | None = None) -> Any: ...
    def put(self, path: str, body: dict[str, Any] | None = None) -> Any: ...
    def patch(self, path: str, body: dict[str, Any] | None = None) -> Any: ...
    def delete(self, path: str) -> Any: ...
    def graphql(self, query: str, variables: dict[str, Any] | None = None) -> Any: ...
    def download(self, path: str) -> bytes: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None  # surface 3xx to the caller so the token is never forwarded


class GitHubAPI:
    def __init__(
        self,
        token: str,
        *,
        api_url: str = API_URL,
        attempts: int = 3,
        sleep: Callable[[float], None] = time.sleep,
        user_agent: str = "aegisflight-automation",
    ) -> None:
        if not token:
            raise ValueError("a GitHub token is required")
        self._token = token
        self._api = api_url.rstrip("/")
        self._attempts = max(1, attempts)
        self._sleep = sleep
        self._ua = user_agent
        self._opener = urllib.request.build_opener(_NoRedirect)

    # ------------------------------------------------------------------ core request
    def _url(self, path: str, params: dict[str, Any] | None) -> str:
        url = path if path.startswith("https://") else f"{self._api}/{path.lstrip('/')}"
        if not url.startswith(self._api + "/"):
            raise ValueError(f"refusing to send the token to a non-API URL: {url}")
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        return url

    def _send(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: Any = None,
        accept: str = "application/vnd.github+json",
        retry: bool = True,
    ) -> tuple[int, dict[str, str], bytes]:
        url = self._url(path, params)
        data = json.dumps(body).encode() if body is not None else None
        attempts = self._attempts if retry else 1
        last: Exception | None = None
        for attempt in range(attempts):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Authorization", f"Bearer {self._token}")
            req.add_header("Accept", accept)
            req.add_header("X-GitHub-Api-Version", "2022-11-28")
            req.add_header("User-Agent", self._ua)
            if data is not None:
                req.add_header("Content-Type", "application/json")
            try:
                with self._opener.open(req, timeout=60) as resp:
                    return resp.status, dict(resp.headers.items()), resp.read()
            except urllib.error.HTTPError as exc:
                payload = exc.read() if exc.fp else b""
                if 300 <= exc.code < 400:
                    return exc.code, dict(exc.headers.items()), payload
                transient = exc.code in _TRANSIENT_STATUS or (
                    exc.code == 403 and b"secondary rate limit" in payload.lower()
                )
                if transient and attempt + 1 < attempts:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    delay = float(retry_after) if retry_after and retry_after.isdigit() else 2.0 ** attempt
                    self._sleep(min(delay, 60.0))
                    last = exc
                    continue
                raise GitHubError(exc.code, _message(payload), _redact(path)) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last = exc
                if attempt + 1 < attempts:
                    self._sleep(2.0 ** attempt)
                    continue
                raise GitHubError(0, f"network error: {type(exc).__name__}", _redact(path)) from None
        raise GitHubError(0, f"exhausted retries ({type(last).__name__})", _redact(path))

    def _json(self, method: str, path: str, *, retry: bool, **kw: Any) -> Any:
        status, headers, payload = self._send(method, path, retry=retry, **kw)
        _raise_if_redirect(status, headers, payload, path)
        if not payload:
            return None
        return json.loads(payload)

    # ------------------------------------------------------------------ public API
    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self._json("GET", path, params=params, retry=True)

    def post(self, path: str, body: dict[str, Any] | None = None, *, idempotent: bool = False) -> Any:
        return self._json("POST", path, body=body or {}, retry=idempotent)

    def put(self, path: str, body: dict[str, Any] | None = None, *, idempotent: bool = False) -> Any:
        return self._json("PUT", path, body=body or {}, retry=idempotent)

    def patch(self, path: str, body: dict[str, Any] | None = None) -> Any:
        return self._json("PATCH", path, body=body or {}, retry=False)

    def delete(self, path: str) -> Any:
        return self._json("DELETE", path, retry=True)

    def paginate(self, path: str, params: dict[str, Any] | None = None,
                 item_key: str | None = None, max_pages: int = 50) -> list[Any]:
        params = {"per_page": 100, **(params or {})}
        url: str | None = self._url(path, params)
        items: list[Any] = []
        pages = 0
        while url and pages < max_pages:
            status, headers, payload = self._send("GET", url)
            _raise_if_redirect(status, headers, payload, path)
            data = json.loads(payload) if payload else []
            page = data[item_key] if item_key else data
            if not isinstance(page, list):
                raise GitHubError(status, f"expected a JSON list page, got {type(page).__name__}",
                                  _redact(path))
            items.extend(page)
            url = _next_link(headers.get("Link") or headers.get("link") or "")
            pages += 1
        return items

    def graphql(self, query: str, variables: dict[str, Any] | None = None) -> Any:
        result = self._json("POST", "graphql", body={"query": query, "variables": variables or {}},
                            retry=query.lstrip().startswith("query"))
        if not isinstance(result, dict) or result.get("errors"):
            errors = result.get("errors") if isinstance(result, dict) else result
            raise GitHubError(200, f"GraphQL errors: {json.dumps(errors)[:500]}", "graphql")
        return result["data"]

    def download(self, path: str) -> bytes:
        """Download an artifact archive: API call, then the redirect target without auth."""
        status, headers, payload = self._send("GET", path)
        if status in (301, 302, 303, 307, 308):
            location = headers.get("Location") or headers.get("location")
            if not location or not location.startswith("https://"):
                raise GitHubError(status, "redirect without an https location", _redact(path))
            req = urllib.request.Request(location, headers={"User-Agent": self._ua})
            with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - https only
                payload = resp.read(_MAX_DOWNLOAD_BYTES + 1)
        if len(payload) > _MAX_DOWNLOAD_BYTES:
            raise GitHubError(413, "artifact larger than the review-record limit", _redact(path))
        return payload


def _raise_if_redirect(status: int, headers: dict[str, str], payload: bytes, path: str) -> None:
    """JSON calls never follow a redirect (the token must not leave the API host) and never parse a
    3xx body as data. A renamed or transferred repository answers 301 "Moved Permanently"."""
    if not 300 <= status < 400:
        return
    location = headers.get("Location") or headers.get("location") or ""
    if not location:
        try:
            location = str(json.loads(payload).get("url") or "")
        except (ValueError, UnicodeDecodeError, AttributeError):
            location = ""
    where = urllib.parse.urlsplit(location).path or "an unknown location"
    raise GitHubError(status, f"resource moved to {where} (renamed or transferred repository?); "
                              "redirects are not followed", _redact(path))


def _next_link(link_header: str) -> str | None:
    for part in link_header.split(","):
        segs = part.split(";")
        if len(segs) >= 2 and 'rel="next"' in segs[1]:
            return segs[0].strip().strip("<>")
    return None


def _message(payload: bytes) -> str:
    try:
        data = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        return payload[:200].decode("utf-8", "replace")
    if isinstance(data, dict):
        return str(data.get("message", ""))[:300]
    return str(data)[:300]


def _redact(path: str) -> str:
    """Strip query strings (they can carry signed URLs) from paths used in messages."""
    return path.split("?", 1)[0]
