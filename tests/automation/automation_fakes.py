"""In-memory GitHub API fake and a fully-eligible baseline PR scenario.

Every merge-gate test starts from `Scenario()` (which passes all gates) and perturbs one
fact, so each test isolates exactly one condition. No network access is used.
"""

from __future__ import annotations

import copy
import io
import json
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aegis_automation.github_api import GitHubError
from aegis_automation.policy import load_policy
from aegis_automation.review_record import build_record

REPO_ROOT = Path(__file__).resolve().parents[2]

REPO = "TeamArdra/techfest-2026"
PR = 42
HEAD = "a" * 40
BASE = "b" * 40
MERGE_SHA = "c" * 40
ISSUE = 16
BRANCH = "fix/16-sats-unknown"
APP_LOGIN = "aegis-merge-gate[bot]"
REVIEW_PATH = ".github/workflows/claude-review.yml"
CI_PATH = ".github/workflows/ci.yml"


def policy():
    return load_policy(REPO_ROOT / ".github/automation/policy.toml")


class FakeGitHub:
    """Routes keyed by (METHOD, path). Values may be data, callables or exceptions."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], Any] = {}
        self.calls: list[tuple[str, str, Any]] = []

    def set(self, method: str, path: str, value: Any) -> None:
        self.routes[(method, path)] = value

    def _resolve(self, method: str, path: str, body: Any = None) -> Any:
        self.calls.append((method, path, body))
        key = (method, path)
        if key not in self.routes:
            if method == "GET":
                raise GitHubError(404, "Not Found", path)
            return {}
        value = self.routes[key]
        if isinstance(value, Exception):
            raise value
        if callable(value):
            return value(body)
        return copy.deepcopy(value)

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self._resolve("GET", path)

    def paginate(self, path: str, params: dict[str, Any] | None = None,
                 item_key: str | None = None) -> list[Any]:
        data = self._resolve("GET", path)
        return data[item_key] if item_key else data

    def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        return self._resolve("POST", path, body)

    def put(self, path: str, body: dict[str, Any] | None = None) -> Any:
        return self._resolve("PUT", path, body)

    def patch(self, path: str, body: dict[str, Any] | None = None) -> Any:
        return self._resolve("PATCH", path, body)

    def delete(self, path: str) -> Any:
        return self._resolve("DELETE", path)

    def graphql(self, query: str, variables: dict[str, Any] | None = None) -> Any:
        kind = "MUTATION" if query.lstrip().startswith("mutation") else "QUERY"
        return self._resolve(kind, "graphql", variables)

    def download(self, path: str) -> bytes:
        return self._resolve("DOWNLOAD", path)

    # helpers for assertions
    def writes(self) -> list[tuple[str, str, Any]]:
        return [c for c in self.calls if c[0] in ("POST", "PUT", "PATCH", "DELETE", "MUTATION")]


def model_output(findings: list[dict[str, Any]] | None = None, *, verdict: str | None = None,
                 acceptance: list[dict[str, str]] | None = None, previous=None,
                 escalate: bool = False, linked: int = ISSUE) -> dict[str, Any]:
    findings = findings or []
    counts = {s: sum(1 for f in findings if f["severity"] == s.upper()) for s in ("p0", "p1", "p2", "p3")}
    if verdict is None:
        verdict = ("BLOCKING" if counts["p0"] + counts["p1"] else
                   "NON_BLOCKING" if counts["p2"] else "READY")
    return {
        "verdict": verdict, "linked_issue": linked, "findings": findings,
        "previous_findings": previous or [],
        "acceptance_criteria": acceptance if acceptance is not None else [
            {"criterion": "A", "status": "met"}, {"criterion": "B", "status": "met"}],
        "escalate": escalate, "escalation_reason": "", **counts,
        "info": sum(1 for f in findings if f["severity"] == "INFO"),
    }


def finding(fid: str, sev: str, conf: str = "Confirmed", title: str = "problem",
            category: str | None = None) -> dict[str, Any]:
    if category is None:
        category = "IMPROVEMENT" if sev in ("P3", "INFO") else "DEFECT"
    return {"id": fid, "severity": sev, "category": category, "confidence": conf,
            "path": "frontend/src/x.tsx", "line": 3, "title": title}


def make_record(output: dict[str, Any] | None = None, *, head: str = HEAD, run_id: int = 200,
                outcome: str = "success", created_at: str = "2026-11-17T01:10:00Z") -> dict[str, Any]:
    return build_record(
        output_text=json.dumps(output if output is not None else model_output()),
        outcome=outcome,
        meta={"repository": REPO, "pr_number": PR, "head_sha": head, "base_sha": BASE,
              "base_ref": "main", "run_id": run_id, "model": "claude-sonnet-5-5",
              "mode": "full", "created_at": created_at},
    )


def zip_record(record: dict[str, Any], name: str = "review-record.json") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(name, json.dumps(record))
    return buf.getvalue()


def run(run_id: int, path: str, *, head: str = HEAD, event: str = "pull_request",
        prs: list[int] | None = None, status: str = "completed", conclusion: str | None = "success",
        created_at: str = "2026-11-17T01:00:00Z", attempt: int = 1, repo: str = REPO) -> dict[str, Any]:
    return {"id": run_id, "path": path, "name": "x", "event": event, "head_sha": head,
            "head_repository": {"full_name": repo},
            "pull_requests": [{"number": n} for n in (prs if prs is not None else [PR])],
            "status": status, "conclusion": conclusion, "created_at": created_at,
            "run_attempt": attempt}


class Scenario:
    """A PR that passes every gate. Mutate attributes, then call `install()`."""

    def __init__(self) -> None:
        self.pr: dict[str, Any] = {
            "number": PR, "state": "open", "merged": False, "draft": False,
            "title": "fix: treat satellites 255 as unknown (#16)",
            "user": {"login": "alice", "type": "User"},
            "head": {"sha": HEAD, "ref": BRANCH, "repo": {"full_name": REPO}},
            "base": {"ref": "main", "sha": BASE},
            "labels": [], "mergeable": True, "mergeable_state": "blocked",
        }
        self.files: list[dict[str, Any]] = [
            {"filename": "frontend/src/components/evalPanels.tsx", "status": "modified",
             "additions": 8, "deletions": 2, "changes": 10,
             "patch": "@@ -1,2 +1,8 @@\n+const label = 'unknown';\n-const label = '255';"},
            {"filename": "tests/unit/test_gps_unknown.py", "status": "added",
             "additions": 20, "deletions": 0, "changes": 20, "patch": "@@ -0,0 +1 @@\n+def test_x(): ..."},
        ]
        self.commits = [{"sha": HEAD, "author": {"login": "alice"}, "committer": {"login": "web-flow"}}]
        self.reviews: list[dict[str, Any]] = []
        self.comments: list[dict[str, Any]] = []
        self.issue = {"number": ISSUE, "state": "OPEN",
                      "body": "### Context\nx\n\n### Acceptance criteria\n- [ ] A\n- [ ] B\n\n### Test plan\nt",
                      "repository": {"nameWithOwner": REPO}, "labels": {"nodes": [{"name": "agent-ready"}]}}
        self.linked: list[dict[str, Any]] | None = None
        self.threads: list[dict[str, Any]] = []
        self.ci_run = run(100, CI_PATH)
        self.review_run = run(200, REVIEW_PATH, created_at="2026-11-17T01:00:05Z")
        self.extra_runs: list[dict[str, Any]] = []
        self.ci_jobs = [{"name": "ci-python", "conclusion": "success"},
                        {"name": "ci-frontend", "conclusion": "success"}]
        self.check_runs = [
            {"name": "ci-python", "status": "completed", "conclusion": "success", "started_at": "1"},
            {"name": "ci-frontend", "status": "completed", "conclusion": "success", "started_at": "1"},
            {"name": "claude-review", "status": "completed", "conclusion": "success", "started_at": "1"},
        ]
        self.statuses = [{"context": "claude-review", "state": "success"}]
        self.rules: Any = [
            {"type": "pull_request"},
            {"type": "required_status_checks", "parameters": {"required_status_checks": [
                {"context": "ci-python"}, {"context": "ci-frontend"}]}},
        ]
        self.same_branch: list[dict[str, Any]] | None = None
        self.record: dict[str, Any] | None = make_record()
        self.artifacts: list[dict[str, Any]] | None = None
        self.permissions = {"alice": "write", "maria": "maintain", "rob": "read"}
        self.remediation_runs: list[dict[str, Any]] = []
        self.merge_response: Any = {"sha": MERGE_SHA, "merged": True}
        self.approval_state = "APPROVED"
        self.merge_parents = 1
        self.head_after_eval: str | None = None

    def install(self, api: FakeGitHub | None = None) -> FakeGitHub:
        api = api or FakeGitHub()
        r = f"repos/{REPO}"
        state = {"merged": False, "reads": 0}

        def pr_view(_body: Any) -> dict[str, Any]:
            state["reads"] += 1
            data = copy.deepcopy(self.pr)
            if self.head_after_eval and state["reads"] > 1:
                data["head"]["sha"] = self.head_after_eval
            if state["merged"]:
                data.update(merged=True, state="closed", merge_commit_sha=MERGE_SHA)
            return data

        def do_merge(body: Any) -> Any:
            if isinstance(self.merge_response, Exception):
                raise self.merge_response
            state["merged"] = True
            return copy.deepcopy(self.merge_response)

        api.set("GET", f"{r}/pulls/{PR}", pr_view)
        api.set("GET", f"{r}/pulls/{PR}/files", self.files)
        api.set("GET", f"{r}/pulls/{PR}/commits", self.commits)
        api.set("GET", f"{r}/pulls/{PR}/reviews", lambda _b: self.reviews)
        api.set("GET", f"{r}/issues/{PR}/comments", lambda _b: self.comments)
        api.set("QUERY", "graphql", {"repository": {"pullRequest": {
            "closingIssuesReferences": {"nodes": self.linked if self.linked is not None else [self.issue]},
            "reviewThreads": {"nodes": self.threads}}}})
        api.set("GET", f"{r}/actions/runs", {"workflow_runs": [self.ci_run, self.review_run, *self.extra_runs]})
        api.set("GET", f"{r}/commits/{HEAD}/check-runs", {"check_runs": self.check_runs})
        api.set("GET", f"{r}/commits/{HEAD}/status", {"statuses": self.statuses})
        api.set("GET", f"{r}/rules/branches/main", self.rules)
        api.set("GET", f"{r}/pulls", self.same_branch if self.same_branch is not None else [self.pr])
        api.set("GET", f"{r}/actions/runs/100/jobs", {"jobs": self.ci_jobs})
        api.set("GET", f"{r}/actions/workflows/claude-remediate.yml/runs",
                {"workflow_runs": self.remediation_runs})
        arts = self.artifacts if self.artifacts is not None else (
            [{"id": 300, "name": "aegis-review-record", "expired": False}] if self.record else [])
        api.set("GET", f"{r}/actions/runs/{self.review_run['id']}/artifacts", {"artifacts": arts})
        if self.record is not None:
            api.set("DOWNLOAD", f"{r}/actions/artifacts/300/zip", zip_record(self.record))
        for login, perm in self.permissions.items():
            api.set("GET", f"{r}/collaborators/{login}/permission", {"permission": perm})
        api.set("POST", f"{r}/pulls/{PR}/reviews", {"id": 900})
        api.set("GET", f"{r}/pulls/{PR}/reviews/900", lambda _b: {
            "id": 900, "state": self.approval_state, "commit_id": HEAD, "user": {"login": APP_LOGIN}})
        api.set("PUT", f"{r}/pulls/{PR}/merge", do_merge)
        api.set("GET", f"{r}/commits/{MERGE_SHA}",
                lambda _b: {"sha": MERGE_SHA, "parents": [{"sha": BASE}] * self.merge_parents})
        api.set("GET", f"{r}/compare/{MERGE_SHA}...main", {"status": "identical"})
        return api


def comment(cid: int, login: str, body: str, *, created_at: str = "2026-11-17T02:00:00Z",
            user_type: str = "User", app_id: int | None = None) -> dict[str, Any]:
    c = {"id": cid, "user": {"login": login, "type": user_type}, "body": body,
         "created_at": created_at}
    if app_id is not None:
        c["performed_via_github_app"] = {"id": app_id}
    return c


Mutator = Callable[[Scenario], None]
