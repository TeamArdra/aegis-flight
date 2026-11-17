"""Merge gate: verify every autonomous-merge condition, then approve and squash-merge.

Trust anchors (nothing else is trusted):
- GitHub's own workflow-run metadata (path, event, head SHA, PR association, conclusion)
  for the CI run and the review run. A PR comment, label, commit status or check run that
  any workflow token could have written is never accepted as proof of a review.
- The review record artifact of that verified review run (artifacts are scoped to the run
  that uploaded them), bound to the exact head SHA and PR number.
- GitHub's file list for the PR (deterministic escalation classifier).
- Collaborator permissions read from the API at evaluation time.

Fail closed: any missing datum, API error or inconsistency makes the PR ineligible.
Modes: "dry-run" evaluates and reports only; "on" also resolves fixed reviewer threads,
approves with the merge App identity, merges with a SHA guard and verifies the result.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any

from .escalation import Escalation, classify
from .github_api import GitHubError, GitHubLike
from .policy import Policy
from .review_record import safe_text, validate_record

MARKER = "<!-- aegis-merge-gate -->"
NO_RECORD = "no review record artifact"
_WRITE_PERMS = ("admin", "maintain", "write")
_PERM_RANK = {"none": 0, "read": 1, "triage": 2, "write": 3, "maintain": 4, "admin": 5}
_BAD_CONCLUSIONS = {"failure", "timed_out", "cancelled", "action_required", "startup_failure",
                    "stale"}
_RUNNING = {"queued", "in_progress", "waiting", "requested", "pending"}
_WAIVER = re.compile(
    r"^/aegis\s+waive\s+(?P<ids>R[0-9]+(?:\s*,\s*R[0-9]+)*)\s+(?P<sha>[0-9a-f]{7,40})\s+(?P<reason>\S.{4,})",
    re.IGNORECASE,
)
_THREAD_ID = re.compile(r"^\s*\*\*(R[0-9]{1,4})\s*·")
_SKIP_CI = re.compile(r"\[(skip ci|ci skip|no ci|skip actions|actions skip)\]|skip-checks\s*:", re.I)

THREADS_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      closingIssuesReferences(first: 10) {
        nodes { number state body repository { nameWithOwner } labels(first: 50) { nodes { name } } }
      }
      reviewThreads(first: 100) {
        nodes {
          id isResolved isOutdated
          comments(first: 20) { nodes { author { login } body } }
        }
      }
    }
  }
}
"""

RESOLVE_THREAD = """
mutation($id: ID!) { resolveReviewThread(input: {threadId: $id}) { thread { id isResolved } } }
"""


# ---------------------------------------------------------------------------------------
# data model
# ---------------------------------------------------------------------------------------
@dataclass
class Check:
    id: str
    name: str
    passed: bool
    detail: str
    blocking: bool = True


@dataclass
class Waiver:
    finding_ids: tuple[str, ...]
    by: str
    reason: str
    comment_id: int


@dataclass
class Facts:
    """Everything the gate read from GitHub, gathered once per evaluation."""

    repo: str
    pr: dict[str, Any]
    files: list[dict[str, Any]]
    commits: list[dict[str, Any]]
    reviews: list[dict[str, Any]]
    issue_comments: list[dict[str, Any]]
    linked_issues: list[dict[str, Any]]
    threads: list[dict[str, Any]]
    runs: list[dict[str, Any]]
    check_runs: list[dict[str, Any]]
    statuses: list[dict[str, Any]]
    required_contexts: list[str] | None
    same_branch_prs: list[dict[str, Any]]
    permissions: dict[str, str]
    review_run: dict[str, Any] | None = None
    record: dict[str, Any] | None = None
    record_problems: list[str] = field(default_factory=list)
    ci_run: dict[str, Any] | None = None
    ci_jobs: list[dict[str, Any]] = field(default_factory=list)
    remediation_running: bool = False

    @property
    def head_sha(self) -> str:
        return str(self.pr["head"]["sha"])

    @property
    def number(self) -> int:
        return int(self.pr["number"])

    @property
    def author(self) -> str:
        return str(self.pr["user"]["login"])


@dataclass
class GateResult:
    checks: list[Check]
    escalations: list[Escalation]
    waivers: list[Waiver]
    resolvable_threads: list[str]
    facts: Facts | None
    error: str | None = None

    @property
    def eligible(self) -> bool:
        return self.error is None and all(c.passed for c in self.checks if c.blocking)

    def failed(self) -> list[Check]:
        return [c for c in self.checks if c.blocking and not c.passed]


@dataclass
class Identity:
    """The merge App's bot identity (None in dry-run without App credentials)."""

    login: str  # e.g. "aegis-merge-gate[bot]"
    app_id: int | None = None


# ---------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------
def _norm_login(login: str | None) -> str:
    return (login or "").lower().removesuffix("[bot]")


def permission_of(api: GitHubLike, repo: str, login: str, cache: dict[str, str]) -> str:
    if login in cache:
        return cache[login]
    if login.endswith("[bot]"):
        cache[login] = "none"  # apps are not collaborators; trusted only via allow-lists
        return "none"
    try:
        data = api.get(f"repos/{repo}/collaborators/{login}/permission")
        perm = str(data.get("permission", "none"))
    except GitHubError as exc:
        if exc.status != 404:
            raise
        perm = "none"
    cache[login] = perm
    return perm


def parse_acceptance_criteria(body: str | None, heading: str) -> list[str]:
    """Items under the issue's "Acceptance criteria" heading (issue-form or markdown)."""
    if not body:
        return []
    items: list[str] = []
    inside = False
    for raw in body.splitlines():
        line = raw.strip()
        if re.match(r"^#{1,6}\s", line):
            inside = line.lstrip("#").strip().lower().startswith(heading)
            continue
        if not inside or not line:
            continue
        m = re.match(r"^(?:[-*+]|\d+[.)])\s+(?:\[[ xX]\]\s*)?(.*)$", line)
        if m and m.group(1).strip():
            items.append(m.group(1).strip())
    return items


def _latest(runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not runs:
        return None
    return max(runs, key=lambda r: (str(r.get("created_at", "")), int(r.get("run_attempt", 1)),
                                    int(r.get("id", 0))))


def trusted_runs(runs: list[dict[str, Any]], *, path: str, head_sha: str, repo: str,
                 pr_number: int) -> list[dict[str, Any]]:
    """Runs that GitHub records as `path` running for a pull_request event on `head_sha`
    of PR `pr_number` from this repository. Workflow names are NOT trusted (any branch
    can add a workflow with the same name); the recorded path is."""
    out = []
    for r in runs:
        if str(r.get("path", "")).split("@", 1)[0] != path:
            continue
        if r.get("event") != "pull_request" or r.get("head_sha") != head_sha:
            continue
        if (r.get("head_repository") or {}).get("full_name") != repo:
            continue
        if pr_number not in [p.get("number") for p in r.get("pull_requests") or []]:
            continue
        out.append(r)
    return out


def load_record(api: GitHubLike, repo: str, run: dict[str, Any], policy: Policy
                ) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        arts = api.get(f"repos/{repo}/actions/runs/{run['id']}/artifacts").get("artifacts", [])
    except GitHubError as exc:
        return None, [f"cannot list artifacts of review run {run['id']}: {exc.status}"]
    named = [a for a in arts if a.get("name") == policy.review_record_artifact]
    if not named:
        return None, [NO_RECORD]
    matches = [a for a in named if not a.get("expired")]
    if len(matches) != 1:
        return None, [f"review run {run['id']} has {len(matches)} usable "
                      f"'{policy.review_record_artifact}' artifacts (expected 1)"]
    try:
        blob = api.download(f"repos/{repo}/actions/artifacts/{matches[0]['id']}/zip")
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            info = zf.getinfo(policy.review_record_file)
            if info.file_size > 1_000_000:
                return None, ["review record is implausibly large"]
            record = json.loads(zf.read(info))
    except (GitHubError, KeyError, zipfile.BadZipFile, ValueError) as exc:
        return None, [f"cannot read the review record: {type(exc).__name__}"]
    problems = validate_record(record)
    return (record if not problems else None), problems


# ---------------------------------------------------------------------------------------
# gather
# ---------------------------------------------------------------------------------------
def gather(api: GitHubLike, repo: str, number: int, policy: Policy) -> Facts:
    owner, name = repo.split("/", 1)
    pr = api.get(f"repos/{repo}/pulls/{number}")
    head = pr["head"]["sha"]
    gql = api.graphql(THREADS_QUERY, {"owner": owner, "name": name, "number": number})
    node = gql["repository"]["pullRequest"]
    threads = node["reviewThreads"]["nodes"]
    linked = node["closingIssuesReferences"]["nodes"]

    runs = api.get(f"repos/{repo}/actions/runs", {"head_sha": head, "per_page": 100}
                   ).get("workflow_runs", [])
    check_runs = api.paginate(f"repos/{repo}/commits/{head}/check-runs", item_key="check_runs")
    statuses = api.get(f"repos/{repo}/commits/{head}/status").get("statuses", [])

    required: list[str] | None
    try:
        rules = api.get(f"repos/{repo}/rules/branches/{policy.default_branch}")
        required = [c["context"] for r in rules if r.get("type") == "required_status_checks"
                    for c in r.get("parameters", {}).get("required_status_checks", [])]
    except GitHubError:
        required = None  # unknown: fail closed in evaluate()

    head_ref = pr["head"]["ref"]
    same_branch = api.paginate(f"repos/{repo}/pulls", {"state": "all", "head": f"{owner}:{head_ref}"})

    facts = Facts(
        repo=repo, pr=pr,
        files=api.paginate(f"repos/{repo}/pulls/{number}/files"),
        commits=api.paginate(f"repos/{repo}/pulls/{number}/commits"),
        reviews=api.paginate(f"repos/{repo}/pulls/{number}/reviews"),
        issue_comments=api.paginate(f"repos/{repo}/issues/{number}/comments"),
        linked_issues=linked, threads=threads, runs=runs, check_runs=check_runs,
        statuses=statuses, required_contexts=required, same_branch_prs=same_branch,
        permissions={},
    )
    review_runs = trusted_runs(runs, path=policy.review_workflow_path, head_sha=head, repo=repo,
                               pr_number=number)
    # Newest completed run that produced a record decides. A newer run without any record
    # artifact (a deduplicated re-trigger on an already-reviewed head) is skipped; every
    # candidate is bound to the same head SHA, so an older record can never cover a newer
    # commit. Running reviews are caught separately by G15.
    for candidate in sorted(review_runs, key=lambda r: (str(r.get("created_at", "")),
                                                        int(r.get("run_attempt", 1))), reverse=True):
        if candidate.get("status") != "completed":
            continue
        record, problems = load_record(api, repo, candidate, policy)
        if record is None and problems == [NO_RECORD]:
            continue
        facts.review_run, facts.record, facts.record_problems = candidate, record, problems
        break
    ci_runs = trusted_runs(runs, path=policy.ci_workflow_path, head_sha=head, repo=repo,
                           pr_number=number)
    facts.ci_run = _latest(ci_runs)
    if facts.ci_run and facts.ci_run.get("status") == "completed":
        facts.ci_jobs = api.get(f"repos/{repo}/actions/runs/{facts.ci_run['id']}/jobs"
                                ).get("jobs", [])
    try:
        rem = api.get(f"repos/{repo}/actions/workflows/claude-remediate.yml/runs",
                      {"status": "in_progress", "per_page": 20}).get("workflow_runs", [])
        queued = api.get(f"repos/{repo}/actions/workflows/claude-remediate.yml/runs",
                         {"status": "queued", "per_page": 20}).get("workflow_runs", [])
        facts.remediation_running = bool(rem or queued)
    except GitHubError as exc:
        if exc.status != 404:
            raise
    perms = facts.permissions
    permission_of(api, repo, facts.author, perms)
    for c in facts.issue_comments:
        login = (c.get("user") or {}).get("login", "")
        if _WAIVER.match((c.get("body") or "").strip()) and login:
            permission_of(api, repo, login, perms)
    return facts


# ---------------------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------------------
def collect_waivers(facts: Facts, policy: Policy) -> list[Waiver]:
    out: list[Waiver] = []
    if not policy.allow_p2_waivers:
        return out
    for c in facts.issue_comments:
        user = c.get("user") or {}
        m = _WAIVER.match((c.get("body") or "").strip())
        if not m or user.get("type") != "User":
            continue
        login = user.get("login", "")
        if facts.permissions.get(login) not in _WRITE_PERMS:
            continue
        if policy.waiver_requires_non_author and login.lower() == facts.author.lower():
            continue
        sha = m.group("sha").lower()
        if len(sha) < policy.min_waiver_sha_prefix or not facts.head_sha.startswith(sha):
            continue  # bound to an older commit: does not carry over
        ids = tuple(i.strip().upper() for i in m.group("ids").split(","))
        out.append(Waiver(ids, login, safe_text(m.group("reason"), 200), int(c.get("id", 0))))
    return out


def resolvable_threads(facts: Facts, policy: Policy) -> tuple[list[str], list[str]]:
    """(resolvable thread ids, blocking thread descriptions) for unresolved threads."""
    record = facts.record or {}
    closed = {p["id"] for p in record.get("previous_findings", [])
              if p.get("status") in ("fixed", "superseded")}
    open_ids = {f["id"] for f in record.get("findings", [])}
    reviewer = _norm_login(policy.reviewer_login)
    resolvable: list[str] = []
    blocking: list[str] = []
    for t in facts.threads:
        if t.get("isResolved"):
            continue
        comments = (t.get("comments") or {}).get("nodes", [])
        authors = {_norm_login((c.get("author") or {}).get("login")) for c in comments}
        first = comments[0] if comments else {}
        m = _THREAD_ID.match(first.get("body") or "")
        if (policy.resolve_fixed_reviewer_threads and m and authors == {reviewer}
                and m.group(1) in closed and m.group(1) not in open_ids):
            resolvable.append(str(t["id"]))
        else:
            label = m.group(1) if m else "discussion"
            blocking.append(f"{label} by {', '.join(sorted(a or '?' for a in authors))}")
    return resolvable, blocking


def evaluate(facts: Facts, policy: Policy, *, identity: Identity | None, mode: str,
             max_cycles: int) -> GateResult:
    pr = facts.pr
    head = facts.head_sha
    checks: list[Check] = []

    def add(cid: str, name: str, ok: bool, detail: str, blocking: bool = True) -> None:
        checks.append(Check(cid, name, bool(ok), detail, blocking))

    # 1. open PR to main, not draft
    add("G01", "PR is open, ready and targets the default branch",
        pr.get("state") == "open" and not pr.get("merged") and not pr.get("draft")
        and pr["base"]["ref"] == policy.default_branch,
        f"state={pr.get('state')} draft={pr.get('draft')} base={pr['base']['ref']}")

    # 2. trusted same-repository feature branch
    head_repo = (pr["head"].get("repo") or {}).get("full_name")
    m = policy.branch_pattern.match(pr["head"]["ref"])
    add("G02", "Same-repository feature branch with the required name",
        head_repo == facts.repo and pr["head"]["ref"] != policy.default_branch and m is not None,
        f"head={safe_text(head_repo, 80)}:{safe_text(pr['head']['ref'], 80)}")

    # 3. authorised author (never the reviewer or the merge identity)
    perm = facts.permissions.get(facts.author, "none")
    author_ok = (_PERM_RANK.get(perm, 0) >= _PERM_RANK.get(policy.minimum_permission, 3)
                 or facts.author in policy.trusted_agent_identities)
    independent = _norm_login(facts.author) != _norm_login(policy.reviewer_login) and (
        identity is None or _norm_login(facts.author) != _norm_login(identity.login))
    add("G03", "Author is an authorised collaborator or approved agent identity",
        author_ok and independent, f"author={facts.author} permission={perm}"
        + ("" if independent else " (author is the reviewer or merge identity)"))

    # 4/5. linked issue with acceptance criteria, assessed by the review
    issues = [i for i in facts.linked_issues
              if (i.get("repository") or {}).get("nameWithOwner", "").lower() == facts.repo.lower()]
    issue = issues[0] if len(issues) == 1 else None
    issue_ok = issue is not None and issue.get("state") == "OPEN"
    if issue_ok and policy.require_issue_number_in_branch and m is not None:
        issue_ok = int(m.group("issue")) == int(issue["number"])
    add("G04", "Linked to exactly one existing open issue (matching the branch)",
        issue_ok, "linked=" + (",".join(f"#{i['number']}({i.get('state')})" for i in issues) or "none"))

    record = facts.record
    ac_items = parse_acceptance_criteria(issue.get("body") if issue else None,
                                         policy.acceptance_heading)
    rec_ac = (record or {}).get("acceptance_criteria", [])
    ac_ok = bool(ac_items) and bool(rec_ac) and len(rec_ac) >= len(ac_items)
    if policy.require_all_acceptance_met:
        ac_ok = ac_ok and all(a.get("status") == "met" for a in rec_ac)
    if record and record.get("linked_issue") not in (None, (issue or {}).get("number")):
        ac_ok = False
    add("G05", "Issue acceptance criteria exist and the review assessed all as met", ac_ok,
        f"issue items={len(ac_items)} assessed={len(rec_ac)} statuses="
        + ",".join(sorted({a.get('status', '?') for a in rec_ac})) if rec_ac else
        f"issue items={len(ac_items)} assessed=0")

    # 6/7/8. CI
    ci = facts.ci_run
    jobs = {j.get("name"): j.get("conclusion") for j in facts.ci_jobs}
    for idx, job in enumerate(policy.required_ci_jobs):
        ok = ci is not None and ci.get("conclusion") == "success" and jobs.get(job) == "success"
        add(f"G0{6 + idx}" if idx < 2 else f"G08.{idx}", f"`{job}` passed on the head commit",
            ok, f"ci run={ci.get('id') if ci else 'none'} job={jobs.get(job, 'missing')}")
    add("G08", "All ruleset-required checks pass; no other failing or pending check",
        *_other_checks(facts, policy))

    # 9/10/11. trusted, completed review bound to this head
    run = facts.review_run
    add("G09", "An independent review completed with a valid record",
        record is not None and record.get("valid") is True
        and record.get("verdict") in ("READY", "NON_BLOCKING", "BLOCKING"),
        f"run={run.get('id') if run else 'none'} verdict={(record or {}).get('verdict', 'none')}"
        + (f" problems={'; '.join(facts.record_problems)[:200]}" if facts.record_problems else ""))
    bound = (record is not None and run is not None and record.get("head_sha") == head
             and record.get("pr_number") == facts.number and record.get("repository") == facts.repo
             and int((record.get("reviewer") or {}).get("run_id", -1)) == int(run["id"]))
    add("G10", "Review record is bound to the exact current head SHA", bound,
        f"record head={(record or {}).get('head_sha', 'none')[:12]} pr head={head[:12]}")
    other_bases = [p for p in facts.same_branch_prs if p["base"]["ref"] != policy.default_branch]
    trusted = (run is not None and run.get("conclusion") == "success" and not other_bases
               and not any(f.get("filename") == policy.review_workflow_path for f in facts.files))
    add("G11", "Review provenance verified from GitHub run metadata (not comments/statuses)",
        trusted, f"workflow={policy.review_workflow_path} event=pull_request"
        + (f"; head branch also used by PRs to other bases: {[p['number'] for p in other_bases]}"
           if other_bases else ""))

    # 12/13. findings
    counts = (record or {}).get("counts", {})
    add("G12", "No P0 or P1 findings", record is not None
        and counts.get("p0", 1) == 0 and counts.get("p1", 1) == 0
        and record.get("verdict") != "BLOCKING", f"P0={counts.get('p0', '?')} P1={counts.get('p1', '?')}")
    waivers = collect_waivers(facts, policy)
    waived = {i for w in waivers for i in w.finding_ids}
    p2 = [f["id"] for f in (record or {}).get("findings", []) if f.get("severity") == "P2"]
    unwaived = [i for i in p2 if i not in waived]
    add("G13", "Every P2 finding is resolved or waived (bound to this head)",
        record is not None and not unwaived,
        f"P2 open={p2 or 'none'} waived={sorted(waived & set(p2)) or 'none'}")

    # 14. remediation budget
    marker_comments = [c for c in facts.issue_comments
                       if (c.get("user") or {}).get("login") == policy.status_writer_login
                       and policy.cycle_marker in (c.get("body") or "")]
    used = len(marker_comments)
    last_marker = max((str(c.get("created_at", "")) for c in marker_comments), default="")
    pending_fix = bool(record) and last_marker > str(record.get("created_at", ""))
    add("G14", "Remediation within limits and none in progress",
        used <= max_cycles and not pending_fix and not facts.remediation_running,
        f"cycles used={used}/{max_cycles}" + (" (a remediation started after the review)"
                                               if pending_fix else "")
        + (" (a remediation run is active)" if facts.remediation_running else ""))

    # 15. nothing still running for this head
    running = [r for r in facts.runs if r.get("status") in _RUNNING
               and str(r.get("path", "")).split("@", 1)[0] in (policy.review_workflow_path,
                                                                policy.ci_workflow_path)]
    add("G15", "No review or CI run in progress for the head commit", not running,
        f"running={[r.get('id') for r in running] or 'none'}")

    # 16. head unchanged since the review (re-checked again right before approval)
    add("G16", "PR head has not changed since the review",
        record is not None and record.get("head_sha") == head, f"head={head[:12]}")

    # 17. threads
    resolvable, blocking_threads = resolvable_threads(facts, policy)
    add("G17", "No unresolved blocking review threads", not blocking_threads,
        f"unresolved blocking={blocking_threads or 'none'}; auto-resolvable fixed={len(resolvable)}")

    # 18. escalation
    labels = {lb["name"] for lb in pr.get("labels", [])}
    for i in issues:
        labels |= {lb["name"] for lb in (i.get("labels") or {}).get("nodes", [])}
    escalations = classify(facts.files, labels, policy)
    if record and record.get("escalate"):
        escalations.append(Escalation("reviewer", record.get("escalation_reason") or
                                      "the independent reviewer recommended escalation"))
    add("G18", "No security or architecture escalation", not escalations,
        f"{len(escalations)} escalation(s)" if escalations else "none")

    # extras: mergeability and separation of identities
    add("G19", "Mergeable (no conflicts)",
        pr.get("mergeable") is not False and pr.get("mergeable_state") not in ("dirty", "draft"),
        f"mergeable={pr.get('mergeable')} state={pr.get('mergeable_state')}")
    if identity is None:
        add("G20", "Merge identity configured and separate from author and committers",
            False, "merge App not configured", blocking=(mode == "on"))
    else:
        ident = _norm_login(identity.login)
        touched = {_norm_login((c.get("author") or {}).get("login")) for c in facts.commits} | {
            _norm_login((c.get("committer") or {}).get("login")) for c in facts.commits}
        add("G20", "Merge identity configured and separate from author and committers",
            ident not in touched and ident != _norm_login(facts.author)
            and ident != _norm_login(policy.reviewer_login),
            f"identity={identity.login}")

    return GateResult(checks=checks, escalations=escalations, waivers=waivers,
                      resolvable_threads=resolvable, facts=facts)


def _other_checks(facts: Facts, policy: Policy) -> tuple[bool, str]:
    latest: dict[str, dict[str, Any]] = {}
    for cr in facts.check_runs:
        name = cr.get("name", "")
        if name not in latest or str(cr.get("started_at", "")) > str(latest[name].get("started_at", "")):
            latest[name] = cr
    advisory = set(policy.advisory_contexts)
    problems: list[str] = []
    if facts.required_contexts is None:
        problems.append("cannot read the default-branch ruleset")
    else:
        status_ok = {s["context"] for s in facts.statuses if s.get("state") == "success"}
        for ctx in facts.required_contexts:
            cr = latest.get(ctx)
            if not ((cr and cr.get("conclusion") == "success") or ctx in status_ok):
                problems.append(f"required `{ctx}` not successful")
    for name, cr in latest.items():
        if name in advisory:
            continue
        if cr.get("status") != "completed":
            problems.append(f"`{name}` still running")
        elif cr.get("conclusion") in _BAD_CONCLUSIONS:
            problems.append(f"`{name}` {cr.get('conclusion')}")
    for s in facts.statuses:
        if s.get("context") in advisory:
            continue
        if s.get("state") in ("failure", "error", "pending"):
            problems.append(f"status `{s.get('context')}` {s.get('state')}")
    return (not problems, "; ".join(problems) or "all green")


# ---------------------------------------------------------------------------------------
# execute (mode "on")
# ---------------------------------------------------------------------------------------
@dataclass
class Outcome:
    action: str  # "none" | "merged" | "approval_failed" | "merge_failed" | "aborted"
    detail: str
    approval_id: int | None = None
    merge_sha: str | None = None


def _clean_title(title: str) -> str:
    return _SKIP_CI.sub("", title).strip()[:200] or "Automated merge"


def execute(writer: GitHubLike, result: GateResult, policy: Policy, identity: Identity) -> Outcome:
    facts = result.facts
    assert facts is not None and result.eligible
    repo, n, head = facts.repo, facts.number, facts.head_sha
    record = facts.record or {}

    for tid in result.resolvable_threads:
        writer.graphql(RESOLVE_THREAD, {"id": tid})

    # Time-of-check/time-of-use: re-read the PR right before approving.
    pr = writer.get(f"repos/{repo}/pulls/{n}")
    if pr["head"]["sha"] != head or pr.get("state") != "open" or pr.get("draft"):
        return Outcome("aborted", "the PR changed during evaluation; a new event will re-evaluate")

    existing = [r for r in writer.paginate(f"repos/{repo}/pulls/{n}/reviews")
                if _norm_login((r.get("user") or {}).get("login")) == _norm_login(identity.login)
                and r.get("commit_id") == head and r.get("state") == "APPROVED"]
    if existing:
        review_id = int(existing[-1]["id"])
    else:
        body = (f"Automated approval by the AegisFlight merge gate for `{head}`.\n\n"
                f"Verified: CI, independent review record (run {record.get('reviewer', {}).get('run_id')}, "
                f"verdict {record.get('verdict')}), acceptance criteria, escalation policy. "
                f"Details: the merge-gate report on this PR.")
        try:
            created = writer.post(f"repos/{repo}/pulls/{n}/reviews",
                                  {"commit_id": head, "event": "APPROVE", "body": body})
        except GitHubError as exc:
            return Outcome("approval_failed", f"GitHub rejected the approval ({exc.status}: "
                                              f"{safe_text(exc.message, 200)})")
        review_id = int(created["id"])
    check = writer.get(f"repos/{repo}/pulls/{n}/reviews/{review_id}")
    if not (check.get("state") == "APPROVED" and check.get("commit_id") == head
            and _norm_login((check.get("user") or {}).get("login")) == _norm_login(identity.login)):
        return Outcome("approval_failed", "approval not recorded as expected "
                                          f"(state={check.get('state')})", review_id)

    issue_no = (facts.linked_issues[0]["number"] if facts.linked_issues else None)
    run_id = (record.get("reviewer") or {}).get("run_id")
    provenance = (f"review record for `{head[:12]}` (review run {run_id}, verdict "
                  f"{record.get('verdict')})" if run_id else f"verification of `{head[:12]}`")
    message = (f"Closes #{issue_no}\n\n" if issue_no else "") + (
        f"Merged by the AegisFlight merge gate after {provenance}.")
    try:
        merged = writer.put(f"repos/{repo}/pulls/{n}/merge", {
            "sha": head, "merge_method": policy.merge_method,
            "commit_title": f"{_clean_title(pr.get('title', ''))} (#{n})",
            "commit_message": message,
        })
    except GitHubError as exc:
        return Outcome("merge_failed", f"GitHub refused the merge ({exc.status}: "
                                       f"{safe_text(exc.message, 200)}); nothing was retried",
                       review_id)
    merge_sha = str((merged or {}).get("sha", ""))

    after = writer.get(f"repos/{repo}/pulls/{n}")
    if not after.get("merged") or after.get("merge_commit_sha") != merge_sha:
        return Outcome("merge_failed", "merge API returned but the PR is not recorded as merged",
                       review_id, merge_sha or None)
    commit = writer.get(f"repos/{repo}/commits/{merge_sha}")
    if len(commit.get("parents", [])) != 1:
        return Outcome("merge_failed", f"merge commit {merge_sha[:12]} is not a squash commit",
                       review_id, merge_sha)
    cmp = writer.get(f"repos/{repo}/compare/{merge_sha}...{policy.default_branch}")
    if cmp.get("status") not in ("identical", "ahead"):
        return Outcome("merge_failed", f"{merge_sha[:12]} is not on {policy.default_branch}",
                       review_id, merge_sha)
    return Outcome("merged", f"squash-merged as {merge_sha[:12]}", review_id, merge_sha)


# ---------------------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------------------
def render_report(result: GateResult, *, mode: str, outcome: Outcome | None = None,
                  run_url: str = "") -> str:
    facts = result.facts
    head = facts.head_sha[:12] if facts else "?"
    if result.error:
        headline = f"**Merge gate error** (fail closed): {safe_text(result.error, 300)}"
    elif outcome and outcome.action == "merged":
        headline = f"**Merged automatically** at `{head}`: {outcome.detail}."
    elif outcome:
        headline = f"**Not merged** ({outcome.action}): {safe_text(outcome.detail, 300)}"
    elif result.eligible:
        headline = (f"**Eligible** at `{head}`." + (" Dry-run mode: no approval or merge was made."
                                                    if mode != "on" else ""))
    else:
        reasons = ", ".join(c.id for c in result.failed())
        headline = f"**Not eligible for automatic merge** at `{head}` (failed: {reasons})."
    lines = [MARKER, "## AegisFlight merge gate", "", headline, "",
             f"Mode: `{mode}`" + (f" · [run log]({run_url})" if run_url else ""), ""]
    if result.checks:
        lines += ["| | Gate | Detail |", "|---|---|---|"]
        for c in result.checks:
            icon = "✅" if c.passed else ("❌" if c.blocking else "ℹ️")
            lines.append(f"| {icon} {c.id} | {c.name} | {safe_text(c.detail, 220)} |")
        lines.append("")
    if result.escalations:
        lines.append("### Escalation (human review and merge required)")
        lines += [f"- {e.render()}" for e in result.escalations]
        lines.append("")
    if result.waivers:
        lines.append("### P2 waivers bound to this head")
        lines += [f"- {', '.join(w.finding_ids)} by `{w.by}`: {w.reason}" for w in result.waivers]
        lines.append("")
    if facts and facts.record and outcome and outcome.action == "merged":
        lines += ["<details><summary>Trusted review record</summary>", "", "```json",
                  json.dumps(facts.record, indent=1, sort_keys=True)[:20000], "```", "</details>", ""]
    lines.append("<sub>The gate fails closed. It trusts only GitHub run metadata, the review "
                 "record artifact of the verified review run, and API-read permissions. "
                 "See docs/AUTONOMOUS_PIPELINE.md.</sub>")
    return "\n".join(lines)


def upsert_report(api: GitHubLike, repo: str, number: int, body: str, author_login: str) -> None:
    """Keep one gate report per PR (edited in place) to avoid comment noise."""
    for c in api.paginate(f"repos/{repo}/issues/{number}/comments"):
        if (_norm_login((c.get("user") or {}).get("login")) == _norm_login(author_login)
                and MARKER in (c.get("body") or "")):
            api.patch(f"repos/{repo}/issues/comments/{c['id']}", {"body": body})
            return
    api.post(f"repos/{repo}/issues/{number}/comments", {"body": body})


def run_gate(reader: GitHubLike, repo: str, number: int, policy: Policy, *, mode: str,
             identity: Identity | None, writer: GitHubLike | None, max_cycles: int
             ) -> tuple[GateResult, Outcome | None]:
    """Evaluate (and in mode "on", act). Never raises: errors become a closed gate."""
    try:
        facts = gather(reader, repo, number, policy)
        result = evaluate(facts, policy, identity=identity, mode=mode, max_cycles=max_cycles)
    except (GitHubError, KeyError, TypeError, ValueError) as exc:
        return GateResult([], [], [], [], None, error=f"{type(exc).__name__}: {exc}"), None
    if mode != "on" or not result.eligible:
        return result, None
    if writer is None or identity is None:
        result.error = "mode is 'on' but no merge App token is available (no fallback)"
        return result, None
    try:
        return result, execute(writer, result, policy, identity)
    except (GitHubError, KeyError, TypeError, ValueError) as exc:
        return result, Outcome("aborted", f"{type(exc).__name__}: {safe_text(str(exc), 200)}")
