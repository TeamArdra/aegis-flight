"""Issue-claiming protocol: eligibility, dependencies and race resolution."""

from __future__ import annotations

import pytest
from automation_fakes import REPO, FakeGitHub, comment

from aegis_automation import issue_claim as ic

TABLE = ("| Plan ID | Priority | Parent | Blocked by | Model |\n|---|---|---|---|---|\n"
         "| AF-07 | P1 | #6 | {blocked} | Sonnet |\n\n### Acceptance criteria\n- [ ] x\n")


@pytest.mark.parametrize("body,expected", [
    (TABLE.format(blocked="none"), []),
    (TABLE.format(blocked="#12, #14"), [12, 14]),
    ("### Blocked by\n\n#3\n\n### Other\n#9", [3]),
    ("Blocked by: #5 and #6", [5, 6]),
    ("- **Blocked by**: #8", [8]),
    (None, []),
    ("Parent #6 only", []),
])
def test_parse_blocked_by(body, expected):
    assert ic.parse_blocked_by(body) == expected


def issue(**kw):
    base = {"number": 16, "state": "open", "labels": [{"name": "agent-ready"}], "assignees": [],
            "body": TABLE.format(blocked="none")}
    return {**base, **kw}


def test_ready_issue_is_eligible():
    assert ic.eligibility(issue(), blocker_states={}, referencing_open_prs=[]).ok


@pytest.mark.parametrize("kw,blockers,prs,reason", [
    ({"state": "closed"}, {}, [], "not open"),
    ({"labels": []}, {}, [], "agent-ready"),
    ({"assignees": [{"login": "bob"}]}, {}, [], "assigned"),
    ({"labels": [{"name": "agent-ready"}, {"name": "status:in-progress"}]}, {}, [], "status label"),
    ({"labels": [{"name": "agent-ready"}, {"name": "needs:hardware"}]}, {}, [], "excluded"),
    ({"labels": [{"name": "agent-ready"}, {"name": "needs:human-approval"}]}, {}, [], "excluded"),
    ({}, {12: "open"}, [], "blocked by"),
    ({}, {}, [99], "open PR"),
    ({"pull_request": {"url": "x"}}, {}, [], "pull request"),
])
def test_ineligible_issues(kw, blockers, prs, reason):
    e = ic.eligibility(issue(**kw), blocker_states=blockers, referencing_open_prs=prs)
    assert not e.ok and any(reason in r for r in e.reasons)


def claim_c(cid, agent, t):
    return comment(cid, "x", f"<!-- aegis-claim agent={agent} branch=fix/16-a -->", created_at=t)


def test_earliest_active_claim_wins_and_releases_reopen():
    comments = [claim_c(2, "agent-b", "2026-11-17T01:00:01Z"), claim_c(1, "agent-a", "2026-11-17T01:00:01Z")]
    assert ic.claim_winner(comments) == "agent-a"  # same second: lower comment id wins
    comments.append(comment(3, "x", "<!-- aegis-claim-release agent=agent-a -->",
                            created_at="2026-11-17T01:05:00Z"))
    assert ic.claim_winner(comments) == "agent-b"
    assert ic.claim_winner([]) is None


def _claim_api(existing_comments):
    api = FakeGitHub()
    state = {"comments": list(existing_comments)}

    def post_comment(body):
        c = comment(100, "me", body["body"], created_at="2026-11-17T02:00:00Z")
        state["comments"].append(c)
        return c

    api.set("GET", f"repos/{REPO}/issues/16", issue())
    api.set("GET", f"repos/{REPO}/pulls", [])
    api.set("POST", f"repos/{REPO}/issues/16/comments", post_comment)
    api.set("GET", f"repos/{REPO}/issues/16/comments", lambda _b: state["comments"])
    return api


def test_claim_wins_assigns_and_labels():
    api = _claim_api([])
    msg = ic.claim(api, REPO, 16, agent="session-1", branch="fix/16-sats-unknown", login="me")
    assert "claimed" in msg
    paths = [(m, p) for m, p, _ in api.writes()]
    assert ("POST", f"repos/{REPO}/issues/16/assignees") in paths
    assert ("POST", f"repos/{REPO}/issues/16/labels") in paths


def test_claim_loses_race_and_withdraws():
    earlier = claim_c(50, "other-agent", "2026-11-17T01:59:59Z")
    api = _claim_api([earlier])
    with pytest.raises(ic.ClaimError, match="lost the claim race"):
        ic.claim(api, REPO, 16, agent="session-1", branch="fix/16-sats-unknown", login="me")
    assert ("DELETE", f"repos/{REPO}/issues/comments/100", None) in api.writes()
    assert not any(p.endswith("/assignees") for _, p, _ in api.writes())


@pytest.mark.parametrize("branch", ["fix/17-other", "feature/16-x", "fix/16-"])
def test_claim_requires_a_matching_branch_name(branch):
    with pytest.raises(ic.ClaimError, match="branch"):
        ic.claim(_claim_api([]), REPO, 16, agent="a", branch=branch, login="me")


def test_claim_refuses_ineligible_issue():
    api = _claim_api([])
    api.set("GET", f"repos/{REPO}/issues/16", issue(assignees=[{"login": "bob"}]))
    with pytest.raises(ic.ClaimError, match="not claimable"):
        ic.claim(api, REPO, 16, agent="a", branch="fix/16-x", login="me")
    assert api.writes() == []


def test_open_pr_referencing_the_issue_blocks_check():
    api = _claim_api([])
    api.set("GET", f"repos/{REPO}/pulls", [{"number": 5, "body": "Closes #16", "head": {"ref": "x"}}])
    assert not ic.check(api, REPO, 16).ok


def test_status_and_invalid_agent_ids():
    api = FakeGitHub()
    assert ic.set_status(api, REPO, 16, "in-review") == "#16 -> status:in-review"
    with pytest.raises(ic.ClaimError):
        ic.set_status(api, REPO, 16, "done")
    with pytest.raises(ic.ClaimError):
        ic.claim(api, REPO, 16, agent="bad agent -->", branch="fix/16-x", login="me")
