"""Event routing, recursion prevention, bounded retry and auto-remediation decisions."""

from __future__ import annotations

import json

import pytest
from automation_fakes import (
    APP_LOGIN,
    CI_PATH,
    HEAD,
    PR,
    REPO,
    REVIEW_PATH,
    FakeGitHub,
    Scenario,
    comment,
    finding,
    make_record,
    model_output,
    policy,
    run,
)

from aegis_automation import orchestrator as orch
from aegis_automation.merge_gate import MARKER, Identity, evaluate, gather
from aegis_automation.policy import PolicyError


def settings(**kw):
    base = {"repo": REPO, "mode": "dry-run", "autoremediate": True, "max_cycles": 2,
            "identity": Identity(APP_LOGIN), "run_url": "u"}
    return orch.Settings(**{**base, **kw})


# --------------------------------------------------------------------------- settings
def test_default_mode_is_dry_run_and_never_on():
    s = orch.resolve_settings({"GITHUB_REPOSITORY": REPO}, policy())
    assert s.mode == "dry-run" and s.autoremediate is False and s.identity is None
    assert s.max_cycles == policy().max_remediation_cycles


@pytest.mark.parametrize("env,msg", [
    ({"AEGIS_AUTOMERGE": "yes"}, "AEGIS_AUTOMERGE"),
    ({"AEGIS_AUTOREMEDIATE": "maybe"}, "AEGIS_AUTOREMEDIATE"),
    ({"AEGIS_AUTOMERGE": "on"}, "requires the merge App"),
    ({"APP_TOKEN": "t", "APP_SLUG": "other-app", "EXPECTED_APP_SLUG": "aegis-merge-gate"}, "does not match"),
    ({"APP_TOKEN": "t", "APP_SLUG": "aegis-merge-gate", "EXPECTED_APP_SLUG": ""}, "does not match"),
])
def test_invalid_or_insecure_settings_are_refused(env, msg):
    with pytest.raises(PolicyError, match=msg):
        orch.resolve_settings({"GITHUB_REPOSITORY": REPO, **env}, policy())


def test_on_mode_with_matching_app_identity():
    s = orch.resolve_settings({"GITHUB_REPOSITORY": REPO, "AEGIS_AUTOMERGE": "on", "APP_TOKEN": "t",
                               "APP_SLUG": "aegis-merge-gate", "EXPECTED_APP_SLUG": "aegis-merge-gate",
                               "MAX_CYCLES": "3"}, policy())
    assert s.identity.login == APP_LOGIN and s.max_cycles == 3


# --------------------------------------------------------------------------- routing
def wr_event(path=REVIEW_PATH, event="pull_request", prs=(PR,), repo=REPO):
    return {"workflow_run": {**run(200, path, event=event, prs=list(prs), repo=repo), "name": "Claude PR review"}}


def test_review_completion_is_routed():
    targets, _ = orch.route("workflow_run", wr_event(), policy(), FakeGitHub(), REPO)
    assert [(t.pr, t.reason) for t in targets] == [(PR, "review_completed")]
    targets, _ = orch.route("workflow_run", wr_event(CI_PATH), policy(), FakeGitHub(), REPO)
    assert targets[0].reason == "ci_completed"


@pytest.mark.parametrize("kw", [
    {"path": ".github/workflows/evil.yml"},  # same workflow *name*, different file
    {"event": "push"},                        # e.g. the post-merge CI on main
    {"repo": "evil/fork"},
])
def test_untrusted_workflow_runs_are_ignored(kw):
    targets, note = orch.route("workflow_run", wr_event(**kw), policy(), FakeGitHub(), REPO)
    assert targets == [] and note.startswith("ignored")


def test_pr_lookup_when_run_has_no_pr_association():
    api = FakeGitHub()
    api.set("GET", f"repos/{REPO}/commits/{HEAD}/pulls", [
        {"number": PR, "state": "open", "head": {"sha": HEAD, "repo": {"full_name": REPO}}},
        {"number": 7, "state": "open", "head": {"sha": HEAD, "repo": {"full_name": "evil/fork"}}},
    ])
    targets, _ = orch.route("workflow_run", wr_event(prs=()), policy(), api, REPO)
    assert [t.pr for t in targets] == [PR]


def comment_event(body, login="maria", user_type="User", on_pr=True):
    issue = {"number": PR, **({"pull_request": {"url": "x"}} if on_pr else {})}
    return {"issue": issue, "comment": {"body": body, "user": {"login": login, "type": user_type}}}


@pytest.mark.parametrize("event,expected", [
    (comment_event("/aegis merge-check"), [PR]),
    (comment_event(f"/aegis waive R2 {HEAD[:7]} fine"), [PR]),
    (comment_event("/aegis merge-check", login="rob"), []),             # read-only
    (comment_event("/aegis merge-check", login=APP_LOGIN, user_type="Bot"), []),  # own comments
    (comment_event("@claude fix R1"), []),
    (comment_event("/aegis merge-check", on_pr=False), []),
    (comment_event("/aegis approve"), []),                              # unknown command
])
def test_comment_routing(event, expected):
    api = FakeGitHub()
    for login, perm in {"maria": "maintain", "rob": "read"}.items():
        api.set("GET", f"repos/{REPO}/collaborators/{login}/permission", {"permission": perm})
    targets, _ = orch.route("issue_comment", event, policy(), api, REPO)
    assert [t.pr for t in targets] == expected


def test_dispatch_and_unknown_events():
    assert [t.pr for t in orch.route("workflow_dispatch", {"inputs": {"pr": "42"}}, policy(),
                                     FakeGitHub(), REPO)[0]] == [42]
    assert orch.route("workflow_dispatch", {"inputs": {"pr": "x"}}, policy(), FakeGitHub(), REPO)[0] == []
    assert orch.route("pull_request_review", {}, policy(), FakeGitHub(), REPO)[0] == []


# --------------------------------------------------------------------------- auto-remediation
def evaluated(sc: Scenario, s=None):
    api = sc.install()
    s = s or settings()
    return evaluate(gather(api, REPO, PR, policy()), policy(), identity=s.identity, mode=s.mode,
                    max_cycles=s.max_cycles)


def blocking_scenario(*findings):
    sc = Scenario()
    sc.record = make_record(model_output(list(findings) or [finding("R1", "P1")]))
    return sc


def test_confirmed_findings_are_sent_for_remediation():
    ids, why = orch.decide_auto_remediation(
        evaluated(blocking_scenario(finding("R1", "P1"), finding("R2", "P2"), finding("R3", "P3"),
                                    finding("R4", "P2", conf="Plausible"))), policy(), settings())
    assert ids == ["R1", "R2"] and "cycle 1 of 2" in why


@pytest.mark.parametrize("change,why", [
    (lambda sc, s: s.__setattr__("autoremediate", False), "off"),
    (lambda sc, s: s.__setattr__("identity", None), "App token"),
    (lambda sc, s: sc.__setattr__("record", make_record(model_output([finding("R1", "P2", conf="Plausible")]))),
     "Confirmed"),
    (lambda sc, s: sc.__setattr__("record", make_record(model_output([finding("R1", "P3")]))), "needs no"),
    (lambda sc, s: sc.files.append({"filename": "src/aegisflight/logging/store.py", "status": "modified",
                                    "additions": 1, "deletions": 0, "changes": 1, "patch": "+x"}), "escalated"),
    (lambda sc, s: sc.comments.extend(comment(i, "github-actions[bot]", "<!-- aegis-remediation-cycle -->",
                                              user_type="Bot", created_at="2026-11-17T00:00:00Z")
                                      for i in range(2)), "exhausted"),
    (lambda sc, s: sc.comments.append(comment(9, APP_LOGIN, f"@claude fix ...\n<!-- aegis-auto-remediation sha={HEAD} findings=R1 -->",
                                              user_type="Bot")), "already requested"),
    (lambda sc, s: sc.pr.update(draft=True), "draft"),
])
def test_auto_remediation_is_bounded(change, why):
    sc = blocking_scenario()
    s = settings()
    change(sc, s)
    ids, reason = orch.decide_auto_remediation(evaluated(sc, s), policy(), s)
    assert ids == [] and why in reason


def test_remediation_request_body_matches_the_remediate_trigger():
    body = orch.remediation_request_body(["R1", "R2"], HEAD, "cycle 1 of 2", policy())
    assert body.startswith("@claude fix ")
    assert f"<!-- aegis-auto-remediation sha={HEAD} findings=R1,R2 -->" in body


# --------------------------------------------------------------------------- bounded retry
@pytest.mark.parametrize("attempt,conclusion,record,expect_rerun", [
    (1, "success", make_record(outcome="failure"), True),    # ERROR -> one retry
    (1, "success", None, True),                              # no record at all -> retry
    (2, "success", make_record(outcome="failure"), False),   # budget used
    (1, "cancelled", None, False),                           # superseded by a newer push
    (1, "success", make_record(), False),                    # READY: nothing to retry
])
def test_review_retry_is_bounded(attempt, conclusion, record, expect_rerun):
    api = FakeGitHub()
    r = run(200, REVIEW_PATH, attempt=attempt, conclusion=conclusion)
    orch.maybe_retry_review(api, REPO, r, record, policy())
    reruns = [w for w in api.writes() if w[1] == f"repos/{REPO}/actions/runs/200/rerun"]
    assert bool(reruns) is expect_rerun


def test_retry_without_app_token_only_reports():
    note = orch.maybe_retry_review(None, REPO, run(200, REVIEW_PATH), None, policy())
    assert "not configured" in note


# --------------------------------------------------------------------------- end to end (mocked)
def _env(tmp_path, event_name, event, **extra):
    path = tmp_path / "event.json"
    path.write_text(json.dumps(event), encoding="utf-8")
    from automation_fakes import REPO_ROOT
    return {"GITHUB_REPOSITORY": REPO, "GITHUB_EVENT_NAME": event_name, "GITHUB_EVENT_PATH": str(path),
            "READ_TOKEN": "read", "POLICY_PATH": str(REPO_ROOT / ".github/automation/policy.toml"),
            "GITHUB_RUN_ID": "1", **extra}


def test_main_off_does_nothing(tmp_path):
    calls = []
    rc = orch.main(_env(tmp_path, "workflow_run", wr_event(), AEGIS_AUTOMERGE="off"),
                   api_factory=lambda tok: calls.append(tok) or FakeGitHub())
    assert rc == 0 and calls == []


def test_main_dry_run_reports_without_approving(tmp_path):
    api = Scenario().install()
    rc = orch.main(_env(tmp_path, "workflow_run", wr_event(CI_PATH)), api_factory=lambda tok: api)
    assert rc == 0
    writes = api.writes()
    assert len(writes) == 1 and writes[0][1] == f"repos/{REPO}/issues/{PR}/comments"
    assert MARKER in writes[0][2]["body"] and "Dry-run" in writes[0][2]["body"]


def test_main_on_merges_with_the_app_token_only(tmp_path):
    api = Scenario().install()
    tokens = []

    def factory(tok):
        tokens.append(tok)
        return api

    rc = orch.main(_env(tmp_path, "workflow_run", wr_event(), AEGIS_AUTOMERGE="on", APP_TOKEN="app",
                        APP_SLUG="aegis-merge-gate", EXPECTED_APP_SLUG="aegis-merge-gate"),
                   api_factory=factory)
    assert rc == 0
    assert "read" not in tokens  # the workflow token is never used once the App token exists
    assert any(w[0] == "PUT" and w[1].endswith("/merge") for w in api.writes())


def test_main_review_error_triggers_retry_and_skips_gate(tmp_path):
    sc = Scenario()
    sc.record = make_record(outcome="failure")
    api = sc.install()
    rc = orch.main(_env(tmp_path, "workflow_run", wr_event(), AEGIS_AUTOMERGE="on", APP_TOKEN="app",
                        APP_SLUG="aegis-merge-gate", EXPECTED_APP_SLUG="aegis-merge-gate"),
                   api_factory=lambda tok: api)
    assert rc == 0
    assert [w[1] for w in api.writes()] == [f"repos/{REPO}/actions/runs/200/rerun"]


def test_main_posts_auto_remediation_and_does_not_merge(tmp_path):
    api = blocking_scenario().install()
    rc = orch.main(_env(tmp_path, "workflow_run", wr_event(), AEGIS_AUTOMERGE="on",
                        AEGIS_AUTOREMEDIATE="on", APP_TOKEN="app", APP_SLUG="aegis-merge-gate",
                        EXPECTED_APP_SLUG="aegis-merge-gate"), api_factory=lambda tok: api)
    assert rc == 0
    bodies = [w[2]["body"] for w in api.writes() if w[0] == "POST" and w[1].endswith("/comments")]
    assert any(b.startswith("@claude fix") for b in bodies)
    assert not any(w[0] == "PUT" for w in api.writes())


def test_main_bad_config_exits_nonzero(tmp_path):
    rc = orch.main(_env(tmp_path, "workflow_run", wr_event(), AEGIS_AUTOMERGE="on"),
                   api_factory=lambda tok: FakeGitHub())
    assert rc == 1
