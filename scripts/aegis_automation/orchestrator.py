"""Event router for `.github/workflows/aegis-orchestrator.yml`.

Runs only on default-branch events (workflow_run, issue_comment, workflow_dispatch), so
the code and policy it executes are always the merged versions. Per event it:

1. finds the pull request(s) concerned, ignoring forks, pushes and its own activity;
2. on a completed review run: retries an ERROR review once (bounded), and, when
   AEGIS_AUTOREMEDIATE=on, asks the remediation agent to fix Confirmed P0-P2 findings
   (bounded by the cycle limit, never for escalated PRs, at most once per head SHA);
3. evaluates the merge gate and, in mode "on", approves and merges through the merge App.

Environment (set by the workflow; tokens are never printed):
  GITHUB_REPOSITORY, GITHUB_EVENT_NAME, GITHUB_EVENT_PATH, GITHUB_SERVER_URL, GITHUB_RUN_ID,
  READ_TOKEN (workflow token), APP_TOKEN / APP_SLUG (merge App, optional),
  EXPECTED_APP_SLUG, AEGIS_AUTOMERGE, AEGIS_AUTOREMEDIATE, MAX_CYCLES, POLICY_PATH.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .github_api import GitHubAPI, GitHubError, GitHubLike
from .merge_gate import (
    GateResult,
    Identity,
    Outcome,
    evaluate,
    execute,
    gather,
    load_record,
    permission_of,
    render_report,
    trusted_runs,
    upsert_report,
)
from .policy import Policy, PolicyError, load_policy

MODES = ("off", "dry-run", "on")


@dataclass
class Target:
    pr: int
    reason: str  # review_completed | ci_completed | comment | dispatch
    run: dict[str, Any] | None = None


@dataclass
class Settings:
    repo: str
    mode: str
    autoremediate: bool
    max_cycles: int
    identity: Identity | None
    run_url: str


# ---------------------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------------------
def resolve_settings(env: dict[str, str], policy: Policy) -> Settings:
    mode = (env.get("AEGIS_AUTOMERGE") or "dry-run").strip().lower()
    if mode not in MODES:
        raise PolicyError(f"AEGIS_AUTOMERGE={mode!r} is not one of {MODES}")
    auto = (env.get("AEGIS_AUTOREMEDIATE") or "off").strip().lower()
    if auto not in ("on", "off"):
        raise PolicyError(f"AEGIS_AUTOREMEDIATE={auto!r} is not 'on' or 'off'")
    raw_cycles = (env.get("MAX_CYCLES") or "").strip()
    cycles = int(raw_cycles) if raw_cycles.isdigit() else policy.max_remediation_cycles
    identity = None
    slug = (env.get("APP_SLUG") or "").strip()
    if env.get("APP_TOKEN"):
        expected = (env.get("EXPECTED_APP_SLUG") or "").strip()
        if not slug or not expected or slug != expected:
            raise PolicyError(f"merge App slug {slug!r} does not match AEGIS_MERGE_APP_SLUG "
                              f"{expected!r}; refusing to act with an unexpected identity")
        identity = Identity(f"{slug}[bot]")
    if mode == "on" and identity is None:
        raise PolicyError("AEGIS_AUTOMERGE=on requires the merge App credentials "
                          "(AEGIS_MERGE_APP_CLIENT_ID / AEGIS_MERGE_APP_PRIVATE_KEY); "
                          "the workflow token is never used to approve or merge")
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    run_url = f"{server}/{env.get('GITHUB_REPOSITORY', '')}/actions/runs/{env.get('GITHUB_RUN_ID', '')}"
    return Settings(repo=env["GITHUB_REPOSITORY"], mode=mode, autoremediate=auto == "on",
                    max_cycles=cycles, identity=identity, run_url=run_url)


# ---------------------------------------------------------------------------------------
# routing
# ---------------------------------------------------------------------------------------
def route(event_name: str, event: dict[str, Any], policy: Policy, reader: GitHubLike,
          repo: str) -> tuple[list[Target], str]:
    """Return (targets, note). Untrusted or irrelevant events yield no targets."""
    if event_name == "workflow_run":
        wr = event.get("workflow_run") or {}
        path = str(wr.get("path", "")).split("@", 1)[0]
        if path == policy.review_workflow_path:
            reason = "review_completed"
        elif path == policy.ci_workflow_path:
            reason = "ci_completed"
        else:
            return [], f"ignored: workflow path {path!r} is not a trusted source"
        if wr.get("event") != "pull_request":
            return [], f"ignored: triggering event {wr.get('event')!r}"
        if (wr.get("head_repository") or {}).get("full_name") != repo:
            return [], "ignored: fork or foreign head repository"
        numbers = [p["number"] for p in wr.get("pull_requests") or [] if p.get("number")]
        if not numbers:
            pulls = reader.get(f"repos/{repo}/commits/{wr.get('head_sha')}/pulls") or []
            numbers = [p["number"] for p in pulls if p.get("state") == "open"
                       and p["head"]["sha"] == wr.get("head_sha")
                       and (p["head"].get("repo") or {}).get("full_name") == repo]
        return [Target(n, reason, wr) for n in numbers], f"{reason} run {wr.get('id')}"

    if event_name == "issue_comment":
        issue = event.get("issue") or {}
        comment = event.get("comment") or {}
        user = comment.get("user") or {}
        body = (comment.get("body") or "").strip()
        if not issue.get("pull_request") or user.get("type") != "User":
            return [], "ignored: not a human comment on a pull request"
        parts = body.split()
        if len(parts) < 2 or parts[0].lower() != "/aegis" or parts[1].lower() not in (
                "merge-check", "waive"):
            return [], "ignored: not an /aegis command"
        perm = permission_of(reader, repo, user.get("login", ""), {})
        if perm not in ("admin", "maintain", "write"):
            return [], f"ignored: {user.get('login')} lacks write access"
        return [Target(int(issue["number"]), "comment")], f"/aegis {parts[1].lower()}"

    if event_name == "workflow_dispatch":
        raw = str((event.get("inputs") or {}).get("pr", "")).strip()
        if not raw.isdigit():
            return [], "ignored: workflow_dispatch needs a numeric 'pr' input"
        return [Target(int(raw), "dispatch")], "manual dispatch"

    return [], f"ignored: event {event_name!r}"


# ---------------------------------------------------------------------------------------
# review-completion actions
# ---------------------------------------------------------------------------------------
def remediation_cycles_used(comments: list[dict[str, Any]], policy: Policy) -> int:
    return sum(1 for c in comments
               if (c.get("user") or {}).get("login") == policy.status_writer_login
               and policy.cycle_marker in (c.get("body") or ""))


def auto_requests_for_head(comments: list[dict[str, Any]], head: str, policy: Policy,
                           identity_login: str) -> list[dict[str, Any]]:
    """Automatic remediation requests the orchestrator App itself posted for `head`."""
    tag = f"{policy.auto_request_marker} sha={head}"
    return [c for c in comments
            if (c.get("user") or {}).get("login") == identity_login and tag in (c.get("body") or "")]


# Findings an agent must never "fix" on its own: they need the project owner's decision
# (a safety boundary or an approved decision is at stake). Defence in depth: the record
# builder already forces such PRs to escalate, which stops remediation earlier.
_OWNER_DECISION_CATEGORIES = ("SAFETY", "CONTRACT_VIOLATION")


def remediation_candidates(record: dict[str, Any], policy: Policy) -> list[str]:
    return [f["id"] for f in record.get("findings", [])
            if f.get("confidence") == "Confirmed" and f.get("severity") in policy.auto_remediation_severities
            and f.get("category") not in _OWNER_DECISION_CATEGORIES]


def decide_auto_remediation(result: GateResult, policy: Policy, settings: Settings
                            ) -> tuple[list[str], str]:
    """Return (finding ids to send, reason). Empty list = do not dispatch."""
    facts = result.facts
    if not settings.autoremediate:
        return [], "auto-remediation is off (AEGIS_AUTOREMEDIATE)"
    if facts is None or facts.record is None:
        return [], "no trusted review record"
    if settings.identity is None:
        return [], "no merge/orchestrator App token to post the request"
    record = facts.record
    if record.get("verdict") not in ("BLOCKING", "NON_BLOCKING") or record.get("head_sha") != facts.head_sha:
        return [], f"verdict {record.get('verdict')} needs no remediation"
    if result.escalations:
        return [], "escalated PR: findings go to a human"
    if facts.pr.get("draft") or (facts.pr["head"].get("repo") or {}).get("full_name") != facts.repo:
        return [], "draft or fork PR"
    ids = remediation_candidates(record, policy)
    if not ids:
        return [], "no Confirmed P0-P2 findings"
    used = remediation_cycles_used(facts.issue_comments, policy)
    if used >= settings.max_cycles:
        return [], f"remediation budget exhausted ({used}/{settings.max_cycles}); needs a human"
    # A re-request for the same head is allowed only after a NEWER review (e.g. the previous
    # remediation run failed for infrastructure reasons and the review was re-run), and at
    # most max_auto_requests_per_head times. Duplicate events for one review never re-post.
    previous = auto_requests_for_head(facts.issue_comments, facts.head_sha, policy,
                                      settings.identity.login)
    if previous:
        if len(previous) >= policy.max_auto_requests_per_head:
            return [], (f"already requested {len(previous)}x for this head "
                        f"(limit {policy.max_auto_requests_per_head}); needs a human")
        last = max(str(c.get("created_at", "")) for c in previous)
        if str(record.get("created_at", "")) <= last:
            return [], "already requested for this review of this head"
    if facts.remediation_running:
        return [], "a remediation run is already active"
    return ids, f"cycle {used + 1} of {settings.max_cycles}"


def remediation_request_body(ids: list[str], head: str, reason: str, policy: Policy) -> str:
    # Must START with "@claude fix" (claude-remediate.yml trigger). No user text included.
    return (f"@claude fix the verified findings {', '.join(ids)} from the latest automated review "
            f"of `{head[:7]}` (automatic remediation request, {reason}).\n\n"
            f"<!-- {policy.auto_request_marker} sha={head} findings={','.join(ids)} -->")


def maybe_retry_review(writer: GitHubLike | None, repo: str, run: dict[str, Any],
                       record: dict[str, Any] | None, policy: Policy) -> str | None:
    """Re-run an ERROR review once (bounded by max_review_attempts). Returns a note."""
    if run.get("conclusion") == "cancelled":
        return None  # superseded by a newer push; the newer run decides
    verdict = (record or {}).get("verdict")
    if record is not None and verdict != "ERROR":
        return None
    if int(run.get("run_attempt", 1)) >= policy.max_review_attempts:
        return f"review run {run.get('id')} ended in ERROR after {run.get('run_attempt')} attempt(s); not retried"
    if writer is None:
        return "review ended in ERROR; retry needs the App token (not configured)"
    writer.post(f"repos/{repo}/actions/runs/{run['id']}/rerun")
    return f"review run {run['id']} ended in ERROR; re-run requested (attempt {int(run.get('run_attempt', 1)) + 1})"


# ---------------------------------------------------------------------------------------
# main flow
# ---------------------------------------------------------------------------------------
def process(target: Target, *, policy: Policy, settings: Settings, reader: GitHubLike,
            writer: GitHubLike | None, log: Callable[[str], None]) -> tuple[GateResult | None, Outcome | None]:
    repo = settings.repo
    try:
        facts = gather(reader, repo, target.pr, policy)
    except (GitHubError, KeyError, TypeError, ValueError) as exc:
        return GateResult([], [], [], [], None, error=f"{type(exc).__name__}: {exc}"), None
    if facts.pr.get("state") != "open":
        log(f"PR #{target.pr} is {facts.pr.get('state')}; nothing to do")
        return None, None

    if target.reason == "review_completed" and target.run is not None:
        run = target.run
        if run.get("head_sha") != facts.head_sha:
            log(f"review run {run.get('id')} is for a stale head; a newer review will follow")
        elif trusted_runs([run], path=policy.review_workflow_path, head_sha=facts.head_sha,
                          repo=repo, pr_number=target.pr):
            record = facts.record if facts.review_run and facts.review_run.get("id") == run.get("id") \
                else load_record(reader, repo, run, policy)[0]
            note = maybe_retry_review(writer if settings.mode != "off" else None, repo, run,
                                      record, policy)
            if note:
                log(note)
                if "re-run requested" in note:
                    return None, None

    result = evaluate(facts, policy, identity=settings.identity, mode=settings.mode,
                      max_cycles=settings.max_cycles)

    if target.reason == "review_completed":
        ids, why = decide_auto_remediation(result, policy, settings)
        log(f"auto-remediation: {why}" + (f" -> {ids}" if ids else ""))
        if ids and writer is not None:
            writer.post(f"repos/{repo}/issues/{target.pr}/comments",
                        {"body": remediation_request_body(ids, facts.head_sha, why, policy)})

    if settings.mode != "on" or not result.eligible:
        return result, None
    assert writer is not None and settings.identity is not None
    try:
        return result, execute(writer, result, policy, settings.identity)
    except (GitHubError, KeyError, TypeError, ValueError) as exc:
        return result, Outcome("aborted", f"{type(exc).__name__}: {exc}")


def main(env: dict[str, str] | None = None, *, api_factory: Callable[[str], GitHubLike] = GitHubAPI
         ) -> int:
    env = dict(os.environ if env is None else env)
    log: Callable[[str], None] = lambda msg: print(msg, flush=True)  # noqa: E731
    try:
        policy = load_policy(env.get("POLICY_PATH") or ".github/automation/policy.toml")
        settings = resolve_settings(env, policy)
    except (PolicyError, KeyError, ValueError) as exc:
        print(f"::error::orchestrator configuration: {exc}")
        return 1
    if settings.mode == "off":
        log("AEGIS_AUTOMERGE=off: orchestrator disabled")
        return 0
    reader = api_factory(env.get("APP_TOKEN") or env["READ_TOKEN"])
    writer = api_factory(env["APP_TOKEN"]) if env.get("APP_TOKEN") else None
    reporter = writer or api_factory(env["READ_TOKEN"])
    reporter_login = settings.identity.login if writer and settings.identity else "github-actions[bot]"

    event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    try:
        targets, note = route(env["GITHUB_EVENT_NAME"], event, policy, reader, settings.repo)
    except GitHubError as exc:
        print(f"::error::cannot route the event: {exc}")
        return 1
    log(f"mode={settings.mode} autoremediate={settings.autoremediate} "
        f"identity={settings.identity.login if settings.identity else 'none'}: {note}")

    status = 0
    summary_parts: list[str] = []
    for target in targets:
        result, outcome = process(target, policy=policy, settings=settings, reader=reader,
                                  writer=writer, log=log)
        if result is None:
            continue
        body = render_report(result, mode=settings.mode, outcome=outcome, run_url=settings.run_url)
        summary_parts.append(body)
        try:
            upsert_report(reporter, settings.repo, target.pr, body, reporter_login)
        except GitHubError as exc:
            log(f"could not post the gate report: {exc}")
        if result.error or (outcome and outcome.action in ("approval_failed", "merge_failed")):
            status = 1
        log(f"PR #{target.pr}: eligible={result.eligible} "
            f"outcome={outcome.action if outcome else 'none'}")
    if env.get("GITHUB_STEP_SUMMARY") and summary_parts:
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write("\n\n".join(summary_parts) + "\n")
    return status


__all__ = ["main", "route", "resolve_settings", "decide_auto_remediation", "process",
           "maybe_retry_review", "remediation_request_body"]

if __name__ == "__main__":
    sys.exit(main())
