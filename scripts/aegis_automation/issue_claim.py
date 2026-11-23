"""Issue-claiming protocol for coding agents (and humans) working the AegisFlight backlog.

GitHub has no atomic "claim" operation, so claiming is a deterministic two-phase protocol:

1. Check eligibility: open, `agent-ready`, unassigned, no `status:*` claim label, no
   excluded label, every "Blocked by" issue closed, no open PR already referencing it.
2. Post a claim comment carrying a machine marker. Re-read the comments: among active
   claims (claims not followed by a release from the same agent) the EARLIEST comment wins
   (ordered by creation time, then comment id). The winner assigns itself and adds
   `status:in-progress`; a loser deletes its own claim comment and picks another issue.

Two agents racing therefore always agree on one winner without any shared lock. The
issue is never closed by this tool: it closes only when its PR is merged (`Closes #n`),
after the merge gate or a human has verified the acceptance criteria.

Usage (token from GH_TOKEN / GITHUB_TOKEN, or `gh auth token`):
    python -m aegis_automation.issue_claim ready [--limit N]
    python -m aegis_automation.issue_claim claim N --branch fix/N-slug --agent my-session
    python -m aegis_automation.issue_claim status N in-review|blocked|in-progress
    python -m aegis_automation.issue_claim release N --agent my-session --reason "..."
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

from .github_api import GitHubAPI, GitHubError, GitHubLike

READY_LABEL = "agent-ready"
STATUS_LABELS = ("status:in-progress", "status:in-review", "status:blocked")
EXCLUDED_LABELS = ("needs:hardware", "model:human", "needs:human-approval", "needs:frozen-contract",
                   "type:epic", "type:tracking", "automerge:hold")
CLAIM = re.compile(r"<!-- aegis-claim agent=(?P<agent>[A-Za-z0-9._@:/-]{1,80}) "
                   r"branch=(?P<branch>[A-Za-z0-9._/-]{1,120}) -->")
RELEASE = re.compile(r"<!-- aegis-claim-release agent=(?P<agent>[A-Za-z0-9._@:/-]{1,80}) -->")
BRANCH = re.compile(r"^(feat|fix|chore|docs|test|evidence|refactor|perf)/(?P<n>[0-9]+)-[a-z0-9][a-z0-9._-]*$")
AGENT = re.compile(r"^[A-Za-z0-9._@:/-]{1,80}$")


class ClaimError(RuntimeError):
    pass


# ---------------------------------------------------------------------------------------
# pure logic (unit-tested)
# ---------------------------------------------------------------------------------------
def parse_blocked_by(body: str | None) -> list[int]:
    """Issue numbers this issue is blocked by: table column, heading or inline form."""
    if not body:
        return []
    lines = body.splitlines()
    found: set[int] = set()
    for i, line in enumerate(lines):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if "|" in line and any(c.lower() == "blocked by" for c in cells):
            col = [c.lower() for c in cells].index("blocked by")
            for row in lines[i + 1:i + 4]:
                if re.match(r"^\s*\|?\s*:?-{3,}", row):
                    continue
                rcells = [c.strip() for c in row.strip().strip("|").split("|")]
                if len(rcells) > col:
                    found |= {int(n) for n in re.findall(r"#([0-9]+)", rcells[col])}
                break
        elif re.match(r"^#{1,6}\s*blocked by\s*$", line.strip(), re.I):
            for nxt in lines[i + 1:i + 4]:
                if nxt.strip():
                    found |= {int(n) for n in re.findall(r"#([0-9]+)", nxt)}
                    break
        else:
            m = re.match(r"^\s*[-*]?\s*\**blocked by\**\s*:\s*(.*)$", line, re.I)
            if m:
                found |= {int(n) for n in re.findall(r"#([0-9]+)", m.group(1))}
    return sorted(found)


@dataclass
class Eligibility:
    ok: bool
    reasons: list[str]


def eligibility(issue: dict[str, Any], *, blocker_states: dict[int, str],
                referencing_open_prs: list[int]) -> Eligibility:
    reasons: list[str] = []
    labels = {lb["name"] for lb in issue.get("labels", [])}
    if issue.get("state") != "open":
        reasons.append("issue is not open")
    if issue.get("pull_request"):
        reasons.append("is a pull request, not an issue")
    if READY_LABEL not in labels:
        reasons.append(f"missing `{READY_LABEL}`")
    if issue.get("assignees"):
        reasons.append("already assigned: " + ", ".join(a["login"] for a in issue["assignees"]))
    if labels & set(STATUS_LABELS):
        reasons.append("already has a status label: " + ", ".join(sorted(labels & set(STATUS_LABELS))))
    if labels & set(EXCLUDED_LABELS):
        reasons.append("excluded label: " + ", ".join(sorted(labels & set(EXCLUDED_LABELS))))
    open_blockers = [n for n, s in blocker_states.items() if s != "closed"]
    if open_blockers:
        reasons.append("blocked by open issue(s): " + ", ".join(f"#{n}" for n in open_blockers))
    if referencing_open_prs:
        reasons.append("open PR already references it: " + ", ".join(f"#{n}" for n in referencing_open_prs))
    return Eligibility(not reasons, reasons)


def active_claims(comments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Claim comments still in force, earliest first."""
    ordered = sorted(comments, key=lambda c: (str(c.get("created_at", "")), int(c.get("id", 0))))
    active: dict[str, dict[str, Any]] = {}
    for c in ordered:
        body = c.get("body") or ""
        m = CLAIM.search(body)
        if m:
            active.setdefault(m.group("agent"), {"comment": c, **m.groupdict()})
            continue
        r = RELEASE.search(body)
        if r:
            active.pop(r.group("agent"), None)
    return sorted(active.values(), key=lambda a: (str(a["comment"].get("created_at", "")),
                                                  int(a["comment"].get("id", 0))))


def claim_winner(comments: list[dict[str, Any]]) -> str | None:
    claims = active_claims(comments)
    return claims[0]["agent"] if claims else None


# ---------------------------------------------------------------------------------------
# GitHub operations
# ---------------------------------------------------------------------------------------
def _issue_numbers_referenced(body: str) -> set[int]:
    return {int(n) for n in re.findall(r"(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?|part of)\s+#([0-9]+)",
                                       body or "", re.I)}


def check(api: GitHubLike, repo: str, number: int) -> Eligibility:
    issue = api.get(f"repos/{repo}/issues/{number}")
    blockers = {n: api.get(f"repos/{repo}/issues/{n}").get("state", "unknown")
                for n in parse_blocked_by(issue.get("body"))}
    prs = api.paginate(f"repos/{repo}/pulls", {"state": "open"})
    refs = [p["number"] for p in prs if number in _issue_numbers_referenced(p.get("body") or "")
            or re.search(rf"/{number}-", p["head"]["ref"])]
    return eligibility(issue, blocker_states=blockers, referencing_open_prs=refs)


def ready(api: GitHubLike, repo: str, limit: int) -> list[tuple[int, str]]:
    issues = api.paginate(f"repos/{repo}/issues", {"state": "open", "labels": READY_LABEL})
    out: list[tuple[int, str]] = []
    for issue in issues:
        if issue.get("pull_request"):
            continue
        if check(api, repo, issue["number"]).ok:
            out.append((issue["number"], issue["title"]))
        if len(out) >= limit:
            break
    return out


def claim(api: GitHubLike, repo: str, number: int, *, agent: str, branch: str, login: str) -> str:
    if not AGENT.match(agent):
        raise ClaimError("agent id may contain only letters, digits and . _ @ : / -")
    m = BRANCH.match(branch)
    if not m or int(m.group("n")) != number:
        raise ClaimError(f"branch must look like fix/{number}-short-slug")
    status = check(api, repo, number)
    if not status.ok:
        raise ClaimError("not claimable: " + "; ".join(status.reasons))
    mine = api.post(f"repos/{repo}/issues/{number}/comments", {
        "body": f"<!-- aegis-claim agent={agent} branch={branch} -->\n"
                f"Claiming #{number} for `{agent}` on branch `{branch}`."})
    winner = claim_winner(api.paginate(f"repos/{repo}/issues/{number}/comments"))
    if winner != agent:
        api.delete(f"repos/{repo}/issues/comments/{mine['id']}")
        raise ClaimError(f"lost the claim race to `{winner}`; pick another issue")
    api.post(f"repos/{repo}/issues/{number}/assignees", {"assignees": [login]})
    api.post(f"repos/{repo}/issues/{number}/labels", {"labels": ["status:in-progress"]})
    return f"claimed #{number} for {agent} on {branch}"


def set_status(api: GitHubLike, repo: str, number: int, state: str) -> str:
    label = f"status:{state}"
    if label not in STATUS_LABELS:
        raise ClaimError(f"state must be one of {[s.split(':')[1] for s in STATUS_LABELS]}")
    for other in STATUS_LABELS:
        if other != label:
            try:
                api.delete(f"repos/{repo}/issues/{number}/labels/{other}")
            except GitHubError as exc:
                if exc.status != 404:
                    raise
    api.post(f"repos/{repo}/issues/{number}/labels", {"labels": [label]})
    return f"#{number} -> {label}"


def release(api: GitHubLike, repo: str, number: int, *, agent: str, login: str, reason: str) -> str:
    if not AGENT.match(agent):
        raise ClaimError("invalid agent id")
    api.post(f"repos/{repo}/issues/{number}/comments", {
        "body": f"<!-- aegis-claim-release agent={agent} -->\nReleasing #{number}: "
                f"{reason.replace('<', '&lt;')[:300]}"})
    for label in STATUS_LABELS:
        try:
            api.delete(f"repos/{repo}/issues/{number}/labels/{label}")
        except GitHubError as exc:
            if exc.status != 404:
                raise
    _unassign(api, repo, number, login)
    return f"released #{number}"


def _unassign(api: GitHubLike, repo: str, number: int, login: str) -> None:
    # The minimal client sends no body with DELETE, so rewrite the assignee list instead.
    issue = api.get(f"repos/{repo}/issues/{number}")
    keep = [a["login"] for a in issue.get("assignees", []) if a["login"] != login]
    api.patch(f"repos/{repo}/issues/{number}", {"assignees": keep})


def _token() -> str:
    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if tok:
        return tok
    try:
        return subprocess.run(["gh", "auth", "token"], check=True, capture_output=True,
                              text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ClaimError("no GitHub token: set GH_TOKEN or log in with `gh auth login`") from exc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aegis_automation.issue_claim")
    p.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "TeamArdra/aegis-flight"))
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("ready")
    r.add_argument("--limit", type=int, default=10)
    c = sub.add_parser("check")
    c.add_argument("number", type=int)
    cl = sub.add_parser("claim")
    cl.add_argument("number", type=int)
    cl.add_argument("--branch", required=True)
    cl.add_argument("--agent", required=True)
    s = sub.add_parser("status")
    s.add_argument("number", type=int)
    s.add_argument("state", choices=["in-progress", "in-review", "blocked"])
    rl = sub.add_parser("release")
    rl.add_argument("number", type=int)
    rl.add_argument("--agent", required=True)
    rl.add_argument("--reason", required=True)
    args = p.parse_args(argv)
    try:
        api = GitHubAPI(_token())
        if args.cmd == "ready":
            for n, title in ready(api, args.repo, args.limit):
                print(f"#{n}\t{title}")
        elif args.cmd == "check":
            e = check(api, args.repo, args.number)
            print("claimable" if e.ok else "not claimable: " + "; ".join(e.reasons))
            return 0 if e.ok else 3
        else:
            login = api.get("user")["login"]
            if args.cmd == "claim":
                print(claim(api, args.repo, args.number, agent=args.agent, branch=args.branch,
                            login=login))
            elif args.cmd == "status":
                print(set_status(api, args.repo, args.number, args.state))
            else:
                print(release(api, args.repo, args.number, agent=args.agent, login=login,
                              reason=args.reason))
    except (ClaimError, GitHubError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
