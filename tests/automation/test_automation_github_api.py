"""GitHubAPI: a redirect (e.g. a renamed repository) must fail loudly, never be parsed as data (#152)."""

from __future__ import annotations

import io
import json
import urllib.error
from email.message import Message

import pytest

from aegis_automation import issue_claim
from aegis_automation.github_api import GitHubAPI, GitHubError

MOVED = {"message": "Moved Permanently",
         "url": "https://api.github.com/repositories/1/issues?labels=agent-ready",
         "documentation_url": "https://docs.github.com/rest/guides/best-practices-for-using-the-rest-api"}


def _headers(**kw: str) -> Message:
    m = Message()
    for k, v in kw.items():
        m[k.replace("_", "-")] = v
    return m


class _Resp:
    def __init__(self, status: int, body: bytes, headers: Message) -> None:
        self.status, self._body, self.headers = status, body, headers

    def read(self, *_a) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_a) -> None:
        return None


class _Opener:
    """Replays scripted responses; records each request's URL and whether it carried the token."""

    def __init__(self, *responses) -> None:
        self.responses = list(responses)
        self.requests: list[tuple[str, bool]] = []

    def open(self, req, timeout=None):  # noqa: ANN001
        self.requests.append((req.full_url, req.has_header("Authorization")))
        status, body, headers = self.responses.pop(0)
        if status >= 300:
            raise urllib.error.HTTPError(req.full_url, status, "x", headers, io.BytesIO(body))
        return _Resp(status, body, headers)


def _api(*responses) -> tuple[GitHubAPI, _Opener]:
    api = GitHubAPI("t0k3n", sleep=lambda _s: None)
    opener = _Opener(*responses)
    api._opener = opener
    return api, opener


def _moved() -> tuple[int, bytes, Message]:
    return 301, json.dumps(MOVED).encode(), _headers(Location=MOVED["url"])


def test_paginate_raises_on_a_redirect_instead_of_iterating_the_moved_body():
    api, opener = _api(_moved())
    with pytest.raises(GitHubError) as e:
        api.paginate("repos/TeamArdra/techfest-2026/issues", {"state": "open"})
    assert e.value.status == 301
    assert "moved" in str(e.value).lower() and "/repositories/1/issues" in str(e.value)
    assert len(opener.requests) == 1  # the redirect target is never requested with the token


@pytest.mark.parametrize("call", [
    lambda api: api.get("repos/TeamArdra/techfest-2026/issues/14"),
    lambda api: api.post("repos/TeamArdra/techfest-2026/issues/14/comments", {"body": "x"}),
    lambda api: api.patch("repos/TeamArdra/techfest-2026/issues/14", {"state": "open"}),
])
def test_json_calls_raise_on_a_redirect_instead_of_returning_the_moved_body(call):
    api, opener = _api(_moved())
    with pytest.raises(GitHubError) as e:
        call(api)
    assert e.value.status == 301
    assert len(opener.requests) == 1


def test_paginate_rejects_a_page_that_is_not_a_list():
    api, _ = _api((200, json.dumps({"message": "unexpected"}).encode(), _headers()))
    with pytest.raises(GitHubError):
        api.paginate("repos/o/r/issues")


def test_paginate_still_follows_link_pages_and_item_key():
    nxt = '<https://api.github.com/repos/o/r/issues?page=2>; rel="next"'
    api, opener = _api((200, b'[{"n": 1}]', _headers(Link=nxt)), (200, b'[{"n": 2}]', _headers()))
    assert api.paginate("repos/o/r/issues") == [{"n": 1}, {"n": 2}]
    assert [url.endswith("page=2") for url, _ in opener.requests] == [False, True]
    api, _ = _api((200, b'{"total_count": 1, "workflow_runs": [{"id": 7}]}', _headers()))
    assert api.paginate("repos/o/r/actions/runs", item_key="workflow_runs") == [{"id": 7}]


def test_download_still_follows_its_redirect_without_the_token(monkeypatch):
    target = "https://storage.example/archive.zip"
    seen: list[tuple[str, bool]] = []

    def fake_urlopen(req, timeout=None):  # noqa: ANN001
        seen.append((req.full_url, req.has_header("Authorization")))
        return _Resp(200, b"PK-zip", _headers())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    api, _ = _api((302, b"", _headers(Location=target)))
    assert api.download("repos/o/r/actions/artifacts/1/zip") == b"PK-zip"
    assert seen == [(target, False)]


def test_issue_claim_defaults_to_the_current_repository_name(monkeypatch):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    captured: dict[str, str] = {}

    def fake_ready(api, repo, limit):  # noqa: ANN001
        captured["repo"] = repo
        return []

    monkeypatch.setattr(issue_claim, "ready", fake_ready)
    monkeypatch.setattr(issue_claim, "GitHubAPI", lambda *a, **k: object(), raising=False)
    monkeypatch.setenv("GH_TOKEN", "x")
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    issue_claim.main(["ready"])
    assert captured["repo"] == "TeamArdra/aegis-flight"
