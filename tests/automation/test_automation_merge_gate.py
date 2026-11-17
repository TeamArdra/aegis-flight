"""Merge-gate conditions, provenance checks and execution, against a mocked GitHub API.

Each test starts from a scenario that passes every gate and changes exactly one fact.
These are mocked integrations: they prove the decision logic, not GitHub's live behaviour.
"""

from __future__ import annotations

import pytest
from automation_fakes import (
    APP_LOGIN,
    BRANCH,
    CI_PATH,
    HEAD,
    ISSUE,
    PR,
    REPO,
    REVIEW_PATH,
    Scenario,
    comment,
    finding,
    make_record,
    model_output,
    policy,
    run,
)

from aegis_automation.github_api import GitHubError
from aegis_automation.merge_gate import (
    MARKER,
    Identity,
    evaluate,
    execute,
    gather,
    parse_acceptance_criteria,
    render_report,
    run_gate,
    upsert_report,
)

IDENT = Identity(APP_LOGIN)


def gate(sc: Scenario, *, mode: str = "dry-run", identity: Identity | None = IDENT, cycles: int = 2):
    api = sc.install()
    facts = gather(api, REPO, PR, policy())
    return evaluate(facts, policy(), identity=identity, mode=mode, max_cycles=cycles), api


def failed_ids(result) -> set[str]:
    return {c.id for c in result.failed()}


# --------------------------------------------------------------------------- happy path
def test_baseline_scenario_is_eligible_and_dry_run_writes_nothing():
    result, api = gate(Scenario())
    assert result.eligible, [(c.id, c.detail) for c in result.failed()]
    assert not result.escalations
    assert api.writes() == []


def test_mode_on_approves_merges_and_verifies_squash():
    sc = Scenario()
    api = sc.install()
    result, outcome = run_gate(api, REPO, PR, policy(), mode="on", identity=IDENT, writer=api,
                               max_cycles=2)
    assert result.eligible
    assert outcome is not None and outcome.action == "merged", outcome
    writes = api.writes()
    assert [w[0] for w in writes] == ["POST", "PUT"]
    approve, merge = writes
    assert approve[2] == {"commit_id": HEAD, "event": "APPROVE", "body": approve[2]["body"]}
    assert merge[2]["sha"] == HEAD and merge[2]["merge_method"] == "squash"
    assert f"Closes #{ISSUE}" in merge[2]["commit_message"]
    assert "Co-authored-by" not in merge[2]["commit_message"]
    assert outcome.merge_sha == "c" * 40


def test_squash_message_names_the_review_run_and_never_prints_none():
    sc = Scenario()
    api = sc.install()
    run_gate(api, REPO, PR, policy(), mode="on", identity=IDENT, writer=api, max_cycles=2)
    message = [w for w in api.writes() if w[0] == "PUT"][0][2]["commit_message"]
    assert "review run 200, verdict READY" in message and "None" not in message


def test_skip_ci_markers_are_stripped_from_the_squash_title():
    sc = Scenario()
    sc.pr["title"] = "fix: thing [skip ci]"
    api = sc.install()
    _, outcome = run_gate(api, REPO, PR, policy(), mode="on", identity=IDENT, writer=api, max_cycles=2)
    merge = [w for w in api.writes() if w[0] == "PUT"][0]
    assert "skip ci" not in merge[2]["commit_title"].lower()
    assert outcome.action == "merged"


# --------------------------------------------------------------------------- G01-G03
@pytest.mark.parametrize("change,expected", [
    (lambda sc: sc.pr.update(draft=True), "G01"),
    (lambda sc: sc.pr.update(state="closed"), "G01"),
    (lambda sc: sc.pr["base"].update(ref="develop"), "G01"),
    (lambda sc: sc.pr["head"].update(repo={"full_name": "evil/fork"}), "G02"),
    (lambda sc: sc.pr["head"].update(ref="main"), "G02"),
    (lambda sc: sc.pr["head"].update(ref="my-random-branch"), "G02"),
])
def test_pr_shape_conditions(change, expected):
    sc = Scenario()
    change(sc)
    result, _ = gate(sc)
    assert expected in failed_ids(result)
    assert not result.eligible


def test_author_without_write_access_is_rejected():
    sc = Scenario()
    sc.pr["user"]["login"] = "rob"  # read-only collaborator
    result, _ = gate(sc)
    assert "G03" in failed_ids(result)


def test_unknown_author_is_rejected():
    sc = Scenario()
    sc.pr["user"]["login"] = "stranger"  # 404 from the permission API
    result, _ = gate(sc)
    assert "G03" in failed_ids(result)


def test_approved_agent_identity_may_author():
    sc = Scenario()
    sc.pr["user"]["login"] = "coder-agent[bot]"
    pol = policy()
    pol.raw["authors"]["trusted_agent_identities"] = ["coder-agent[bot]"]
    api = sc.install()
    result = evaluate(gather(api, REPO, PR, pol), pol, identity=IDENT, mode="dry-run", max_cycles=2)
    assert "G03" not in failed_ids(result)


@pytest.mark.parametrize("author", ["claude[bot]", APP_LOGIN])
def test_reviewer_or_merge_identity_can_never_author(author):
    sc = Scenario()
    sc.pr["user"]["login"] = author
    pol = policy()
    pol.raw["authors"]["trusted_agent_identities"] = [author]
    api = sc.install()
    result = evaluate(gather(api, REPO, PR, pol), pol, identity=IDENT, mode="dry-run", max_cycles=2)
    assert "G03" in failed_ids(result)


# --------------------------------------------------------------------------- G04-G05
def test_missing_linked_issue_is_rejected():
    sc = Scenario()
    sc.linked = []
    result, _ = gate(sc)
    assert "G04" in failed_ids(result)


def test_closed_issue_is_rejected():
    sc = Scenario()
    sc.issue["state"] = "CLOSED"
    result, _ = gate(sc)
    assert "G04" in failed_ids(result)


def test_branch_number_must_match_the_issue():
    sc = Scenario()
    sc.pr["head"]["ref"] = "fix/99-other"
    result, _ = gate(sc)
    assert "G04" in failed_ids(result)


def test_issue_from_another_repository_does_not_count():
    sc = Scenario()
    sc.issue["repository"] = {"nameWithOwner": "someone/else"}
    result, _ = gate(sc)
    assert "G04" in failed_ids(result)


def test_issue_without_acceptance_criteria_is_rejected():
    sc = Scenario()
    sc.issue["body"] = "### Context\nNo criteria here."
    result, _ = gate(sc)
    assert "G05" in failed_ids(result)


@pytest.mark.parametrize("acceptance", [
    [{"criterion": "A", "status": "met"}, {"criterion": "B", "status": "cannot_verify"}],
    [{"criterion": "A", "status": "met"}, {"criterion": "B", "status": "not_met"}],
    [{"criterion": "A", "status": "met"}],  # fewer assessed than the issue lists
    [],
])
def test_acceptance_criteria_must_all_be_assessed_as_met(acceptance):
    sc = Scenario()
    sc.record = make_record(model_output(acceptance=acceptance))
    result, _ = gate(sc)
    assert "G05" in failed_ids(result)


def test_record_for_a_different_issue_fails_acceptance():
    sc = Scenario()
    sc.record = make_record(model_output(linked=99))
    result, _ = gate(sc)
    assert "G05" in failed_ids(result)


def test_parse_acceptance_criteria_handles_issue_forms():
    body = "### Acceptance criteria\n\n- [ ] one\n- [x] two\n* three\n1. four\n\n### Test plan\n- not this"
    assert parse_acceptance_criteria(body, "acceptance criteria") == ["one", "two", "three", "four"]
    assert parse_acceptance_criteria("## Acceptance Criteria\n- [ ]\n", "acceptance criteria") == []


# --------------------------------------------------------------------------- G06-G08 CI
def test_ci_run_failure_is_rejected():
    sc = Scenario()
    sc.ci_run["conclusion"] = "failure"
    result, _ = gate(sc)
    assert {"G06", "G07"} <= failed_ids(result)


def test_single_ci_job_failure_is_rejected():
    sc = Scenario()
    sc.ci_jobs[1]["conclusion"] = "failure"
    result, _ = gate(sc)
    assert "G07" in failed_ids(result) and "G06" not in failed_ids(result)


def test_ci_from_an_untrusted_workflow_path_is_ignored():
    sc = Scenario()
    sc.ci_run["path"] = ".github/workflows/fake-ci.yml"  # same job names, wrong file
    result, _ = gate(sc)
    assert {"G06", "G07"} <= failed_ids(result)


def test_missing_required_ruleset_check_is_rejected():
    sc = Scenario()
    sc.rules[1]["parameters"]["required_status_checks"].append({"context": "security-scan"})
    result, _ = gate(sc)
    assert "G08" in failed_ids(result)


def test_unreadable_ruleset_fails_closed():
    sc = Scenario()
    sc.rules = GitHubError(403, "Resource not accessible", "rules")
    result, _ = gate(sc)
    assert "G08" in failed_ids(result)


@pytest.mark.parametrize("check", [
    {"name": "codeql", "status": "completed", "conclusion": "failure", "started_at": "2"},
    {"name": "codeql", "status": "in_progress", "conclusion": None, "started_at": "2"},
])
def test_other_failing_or_pending_checks_are_rejected(check):
    sc = Scenario()
    sc.check_runs.append(check)
    result, _ = gate(sc)
    assert "G08" in failed_ids(result)


def test_advisory_claude_review_failure_status_is_not_double_counted():
    sc = Scenario()
    sc.statuses = [{"context": "claude-review", "state": "failure"}]
    result, _ = gate(sc)
    assert "G08" not in failed_ids(result)


# --------------------------------------------------------------------------- G09-G11 review
def test_missing_review_is_rejected():
    sc = Scenario()
    sc.review_run = run(201, ".github/workflows/other.yml")
    sc.record = None
    result, _ = gate(sc)
    assert "G09" in failed_ids(result)


@pytest.mark.parametrize("record_kw", [
    {"outcome": "failure"},                      # ERROR
    {"output": model_output(verdict="INCOMPLETE")},  # INCOMPLETE
])
def test_error_or_incomplete_review_is_rejected(record_kw):
    sc = Scenario()
    output = record_kw.pop("output", None)
    sc.record = make_record(output, **record_kw)
    result, _ = gate(sc)
    assert "G09" in failed_ids(result)


def test_forged_status_without_a_trusted_run_is_not_a_review():
    """A `claude-review` success status (writable by any workflow token) proves nothing."""
    sc = Scenario()
    sc.review_run = run(201, ".github/workflows/evil.yml")  # forger's run
    sc.record = make_record(run_id=201)
    sc.statuses = [{"context": "claude-review", "state": "success",
                    "creator": {"login": "github-actions[bot]"}}]
    result, _ = gate(sc)
    assert "G09" in failed_ids(result)


@pytest.mark.parametrize("override", [
    {"event": "push"},
    {"event": "workflow_dispatch"},
    {"prs": [43]},
    {"repo": "evil/fork"},
    {"head": "d" * 40},
])
def test_review_runs_with_wrong_provenance_are_ignored(override):
    sc = Scenario()
    sc.review_run = run(200, REVIEW_PATH, **override)
    result, _ = gate(sc)
    assert "G09" in failed_ids(result) or "G10" in failed_ids(result)
    assert not result.eligible


def test_stale_review_cannot_authorise_a_newer_commit():
    sc = Scenario()
    sc.record = make_record(head="e" * 40)
    result, _ = gate(sc)
    assert {"G10", "G16"} <= failed_ids(result)


def test_record_from_another_run_is_not_bound():
    sc = Scenario()
    sc.record = make_record(run_id=999)  # artifact claims a different producing run
    result, _ = gate(sc)
    assert "G10" in failed_ids(result)


def test_tampered_record_is_rejected():
    sc = Scenario()
    rec = make_record(model_output([finding("R1", "P1")]))
    rec["counts"]["p1"] = 0  # hide the finding
    rec["verdict"] = "READY"
    sc.record = rec
    result, _ = gate(sc)
    assert "G09" in failed_ids(result)


def test_duplicate_record_artifacts_fail_closed():
    sc = Scenario()
    sc.artifacts = [{"id": 300, "name": "aegis-review-record", "expired": False},
                    {"id": 301, "name": "aegis-review-record", "expired": False}]
    result, _ = gate(sc)
    assert "G09" in failed_ids(result)


def test_deduplicated_newer_run_without_record_falls_back_to_the_same_head_record():
    sc = Scenario()
    sc.extra_runs = [run(205, REVIEW_PATH, created_at="2026-11-17T01:40:00Z")]
    api = sc.install()
    api.set("GET", f"repos/{REPO}/actions/runs/205/artifacts", {"artifacts": []})
    result = evaluate(gather(api, REPO, PR, policy()), policy(), identity=IDENT, mode="dry-run",
                      max_cycles=2)
    assert result.eligible and result.facts.review_run["id"] == 200


def test_newest_record_wins_even_when_older_one_was_ready():
    sc = Scenario()
    sc.extra_runs = [run(205, REVIEW_PATH, created_at="2026-11-17T01:40:00Z")]
    api = sc.install()
    from automation_fakes import zip_record
    api.set("GET", f"repos/{REPO}/actions/runs/205/artifacts",
            {"artifacts": [{"id": 305, "name": "aegis-review-record", "expired": False}]})
    api.set("DOWNLOAD", f"repos/{REPO}/actions/artifacts/305/zip",
            zip_record(make_record(outcome="failure", run_id=205)))
    result = evaluate(gather(api, REPO, PR, policy()), policy(), identity=IDENT, mode="dry-run",
                      max_cycles=2)
    assert "G09" in failed_ids(result)


def test_head_branch_shared_with_a_pr_to_another_base_is_rejected():
    sc = Scenario()
    other = {"number": 77, "base": {"ref": "evil-base"}, "head": {"ref": BRANCH}}
    sc.same_branch = [sc.pr, other]
    result, _ = gate(sc)
    assert "G11" in failed_ids(result)


def test_pr_that_edits_the_reviewer_workflow_is_never_trusted():
    sc = Scenario()
    sc.files.append({"filename": REVIEW_PATH, "status": "modified", "additions": 1,
                     "deletions": 0, "changes": 1, "patch": "+# tweak"})
    result, _ = gate(sc)
    assert {"G11", "G18"} <= failed_ids(result)


# --------------------------------------------------------------------------- G12-G13 findings
def test_p0_or_p1_blocks():
    for sev in ("P0", "P1"):
        sc = Scenario()
        sc.record = make_record(model_output([finding("R1", sev)]))
        result, _ = gate(sc)
        assert "G12" in failed_ids(result), sev


def test_p3_only_is_ready():
    sc = Scenario()
    sc.record = make_record(model_output([finding("R1", "P3")]))
    result, _ = gate(sc)
    assert result.eligible


def test_unwaived_p2_blocks():
    sc = Scenario()
    sc.record = make_record(model_output([finding("R2", "P2")]))
    result, _ = gate(sc)
    assert failed_ids(result) == {"G13"}


def test_p2_waived_by_a_maintainer_for_this_head_passes():
    sc = Scenario()
    sc.record = make_record(model_output([finding("R2", "P2")]))
    sc.comments = [comment(1, "maria", f"/aegis waive R2 {HEAD[:7]} documented in the issue thread")]
    result, _ = gate(sc)
    assert result.eligible, failed_ids(result)
    assert result.waivers and result.waivers[0].by == "maria"


@pytest.mark.parametrize("who,sha,user_type", [
    ("alice", HEAD[:7], "User"),        # the PR author cannot waive
    ("rob", HEAD[:7], "User"),          # read-only collaborator
    ("maria", "f" * 7, "User"),         # bound to another commit
    ("maria", HEAD[:6], "User"),        # prefix too short
    ("maria", HEAD[:7], "Bot"),         # bots cannot waive
])
def test_invalid_waivers_are_ignored(who, sha, user_type):
    sc = Scenario()
    sc.record = make_record(model_output([finding("R2", "P2")]))
    sc.comments = [comment(1, who, f"/aegis waive R2 {sha} because reasons", user_type=user_type)]
    result, _ = gate(sc)
    assert "G13" in failed_ids(result)


def test_waiver_cannot_cover_p1():
    sc = Scenario()
    sc.record = make_record(model_output([finding("R1", "P1")]))
    sc.comments = [comment(1, "maria", f"/aegis waive R1 {HEAD[:7]} accept the risk")]
    result, _ = gate(sc)
    assert "G12" in failed_ids(result)


# --------------------------------------------------------------------------- G14-G17
def _cycle_marker(cid: int, created_at: str, login: str = "github-actions[bot]"):
    return comment(cid, login, "<!-- aegis-remediation-cycle -->\nstarted", created_at=created_at,
                   user_type="Bot")


def test_remediation_budget_exceeded_blocks():
    sc = Scenario()
    sc.comments = [_cycle_marker(i, f"2026-11-17T00:00:0{i}Z") for i in range(3)]
    result, _ = gate(sc, cycles=2)
    assert "G14" in failed_ids(result)


def test_remediation_started_after_the_review_blocks():
    sc = Scenario()
    sc.comments = [_cycle_marker(1, "2026-11-17T01:20:00Z")]  # record created 01:10
    result, _ = gate(sc)
    assert "G14" in failed_ids(result)


def test_forged_cycle_markers_by_users_do_not_count():
    sc = Scenario()
    sc.comments = [_cycle_marker(i, f"2026-11-17T00:00:0{i}Z", login="alice") for i in range(5)]
    result, _ = gate(sc)
    assert "G14" not in failed_ids(result)


def test_active_remediation_run_blocks():
    sc = Scenario()
    sc.remediation_runs = [{"id": 5, "status": "in_progress"}]
    result, _ = gate(sc)
    assert "G14" in failed_ids(result)


def test_review_still_running_blocks():
    sc = Scenario()
    sc.extra_runs = [run(202, REVIEW_PATH, status="in_progress", conclusion=None,
                         created_at="2026-11-17T01:30:00Z")]
    result, _ = gate(sc)
    assert "G15" in failed_ids(result)


def test_unresolved_human_thread_blocks():
    sc = Scenario()
    sc.threads = [{"id": "T1", "isResolved": False, "isOutdated": False,
                   "comments": {"nodes": [{"author": {"login": "maria"}, "body": "why?"}]}}]
    result, _ = gate(sc)
    assert "G17" in failed_ids(result)


def _reviewer_thread(fid: str, extra_authors: tuple[str, ...] = ()):
    nodes = [{"author": {"login": "claude"}, "body": f"**{fid} · P2 · Confirmed** problem"}]
    nodes += [{"author": {"login": a}, "body": "reply"} for a in extra_authors]
    return {"id": f"T-{fid}", "isResolved": False, "isOutdated": True, "comments": {"nodes": nodes}}


def test_fixed_reviewer_thread_is_auto_resolved_in_mode_on():
    sc = Scenario()
    sc.record = make_record(model_output(previous=[{"id": "R1", "status": "fixed"}]))
    sc.threads = [_reviewer_thread("R1")]
    api = sc.install()
    result, outcome = run_gate(api, REPO, PR, policy(), mode="on", identity=IDENT, writer=api,
                               max_cycles=2)
    assert result.eligible and result.resolvable_threads == ["T-R1"]
    assert ("MUTATION", "graphql", {"id": "T-R1"}) in api.writes()
    assert outcome.action == "merged"


def test_reviewer_thread_with_human_replies_is_not_auto_resolved():
    sc = Scenario()
    sc.record = make_record(model_output(previous=[{"id": "R1", "status": "fixed"}]))
    sc.threads = [_reviewer_thread("R1", ("maria",))]
    result, _ = gate(sc)
    assert "G17" in failed_ids(result)


def test_still_present_reviewer_thread_blocks():
    sc = Scenario()
    sc.record = make_record(model_output(previous=[{"id": "R1", "status": "still_present"}]))
    sc.threads = [_reviewer_thread("R1")]
    result, _ = gate(sc)
    assert "G17" in failed_ids(result)


# --------------------------------------------------------------------------- G18 escalation
@pytest.mark.parametrize("path", [
    ".github/workflows/ci.yml", ".github/claude/review-policy.md", "AGENTS.md", "CLAUDE.md",
    "scripts/aegis_automation/merge_gate.py", "src/aegisflight/mavlink/signing.py",
    "src/aegisflight/sources/mavlink_serial.py", "src/aegisflight/features/extractor.py",
    "src/aegisflight/logging/store.py", "src/aegisflight/detectors/protocol.py",
    "configs/detector.yaml", "artifacts/benchmarks/summary.md", "pyproject.toml",
])
def test_escalation_paths_block(path):
    sc = Scenario()
    sc.files.append({"filename": path, "status": "modified", "additions": 1, "deletions": 0,
                     "changes": 1, "patch": "+x"})
    result, _ = gate(sc)
    assert "G18" in failed_ids(result), path


@pytest.mark.parametrize("label_on", ["pr", "issue"])
def test_escalation_labels_block(label_on):
    sc = Scenario()
    if label_on == "pr":
        sc.pr["labels"] = [{"name": "automerge:hold"}]
    else:
        sc.issue["labels"]["nodes"].append({"name": "needs:human-approval"})
    result, _ = gate(sc)
    assert "G18" in failed_ids(result)


def test_reviewer_escalation_flag_blocks():
    sc = Scenario()
    sc.record = make_record(model_output(escalate=True))
    result, _ = gate(sc)
    assert "G18" in failed_ids(result)


# --------------------------------------------------------------------------- G19-G20
def test_merge_conflicts_block():
    sc = Scenario()
    sc.pr["mergeable_state"] = "dirty"
    result, _ = gate(sc)
    assert "G19" in failed_ids(result)


def test_commit_by_the_merge_identity_breaks_separation_of_duties():
    sc = Scenario()
    sc.commits.append({"sha": "9" * 40, "author": {"login": APP_LOGIN}, "committer": None})
    result, _ = gate(sc)
    assert "G20" in failed_ids(result)


def test_missing_identity_is_informational_in_dry_run_but_blocking_in_on():
    dry, _ = gate(Scenario(), identity=None, mode="dry-run")
    assert dry.eligible
    on, _ = gate(Scenario(), identity=None, mode="on")
    assert "G20" in failed_ids(on)


def test_mode_on_without_writer_fails_closed():
    sc = Scenario()
    api = sc.install()
    result, outcome = run_gate(api, REPO, PR, policy(), mode="on", identity=IDENT, writer=None,
                               max_cycles=2)
    assert outcome is None and result.error and not result.eligible
    assert api.writes() == []


# --------------------------------------------------------------------------- execution failures
def _execute(sc: Scenario):
    api = sc.install()
    result = evaluate(gather(api, REPO, PR, policy()), policy(), identity=IDENT, mode="on",
                      max_cycles=2)
    assert result.eligible
    return execute(api, result, policy(), IDENT), api


def test_head_change_between_evaluation_and_approval_aborts():
    sc = Scenario()
    sc.head_after_eval = "f" * 40
    outcome, api = _execute(sc)
    assert outcome.action == "aborted"
    assert api.writes() == []


def test_rejected_approval_stops_before_merge():
    sc = Scenario()
    api = sc.install()
    api_routes_post = GitHubError(422, "Can not approve your own pull request", "reviews")
    result = evaluate(gather(api, REPO, PR, policy()), policy(), identity=IDENT, mode="on",
                      max_cycles=2)
    api.set("POST", f"repos/{REPO}/pulls/{PR}/reviews", api_routes_post)
    outcome = execute(api, result, policy(), IDENT)
    assert outcome.action == "approval_failed"
    assert not [w for w in api.writes() if w[0] == "PUT"]


def test_approval_not_recorded_stops_before_merge():
    sc = Scenario()
    sc.approval_state = "COMMENTED"
    outcome, api = _execute(sc)
    assert outcome.action == "approval_failed"
    assert not [w for w in api.writes() if w[0] == "PUT"]


def test_existing_approval_for_this_head_is_reused():
    sc = Scenario()
    sc.reviews = [{"id": 900, "state": "APPROVED", "commit_id": HEAD, "user": {"login": APP_LOGIN}}]
    outcome, api = _execute(sc)
    assert outcome.action == "merged"
    assert not [w for w in api.writes() if w[0] == "POST"]


def test_merge_refusal_is_reported_and_not_retried():
    sc = Scenario()
    sc.merge_response = GitHubError(405, "Required status check is expected", "merge")
    outcome, api = _execute(sc)
    assert outcome.action == "merge_failed"
    assert len([w for w in api.writes() if w[0] == "PUT"]) == 1


def test_non_squash_result_is_flagged():
    sc = Scenario()
    sc.merge_parents = 2
    outcome, _ = _execute(sc)
    assert outcome.action == "merge_failed" and "squash" in outcome.detail


def test_api_failure_during_gather_fails_closed():
    sc = Scenario()
    api = sc.install()
    api.set("GET", f"repos/{REPO}/pulls/{PR}/files", GitHubError(502, "Bad gateway", "files"))
    result, outcome = run_gate(api, REPO, PR, policy(), mode="on", identity=IDENT, writer=api,
                               max_cycles=2)
    assert result.error and not result.eligible and outcome is None
    assert api.writes() == []


# --------------------------------------------------------------------------- reporting
def test_report_lists_failures_and_neutralises_mentions():
    sc = Scenario()
    sc.record = make_record(model_output([finding("R1", "P1", title="@team <!-- x --> | y")]))
    result, _ = gate(sc)
    text = render_report(result, mode="dry-run")
    assert MARKER in text and "G12" in text and "Not eligible" in text
    assert "@team" not in text


def test_report_is_upserted_in_place():
    sc = Scenario()
    sc.comments = [comment(55, "github-actions[bot]", f"{MARKER}\nold", user_type="Bot")]
    api = sc.install()
    upsert_report(api, REPO, PR, "new body", "github-actions[bot]")
    assert api.writes() == [("PATCH", f"repos/{REPO}/issues/comments/55", {"body": "new body"})]


def test_ci_path_constant_matches_policy():
    assert policy().ci_workflow_path == CI_PATH and policy().review_workflow_path == REVIEW_PATH
