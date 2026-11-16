# Architecture comparison: Luxurio (reference) vs AegisFlight

Luxurio (`Krishang-Zinzuwadia/luxurio`, private) was read as a reference on 2026-11-17 at
`main` = `8710bb1` (161 commits). Nothing in it was modified. Sources read:
`.github/workflows/luxurio-review-events.yml`, `.github/workflows/pr-validation.yml` and their
history (`c2aaff1`, `a0b445e`, `4d6e2d6`), `AGENTS.md`, `.claude/orchestration/README.md`,
`.claude/agents/*.md`, and the review timeline of PR #193 (reviews, inline comments, merge).
Ruleset/branch-protection APIs returned no rulesets and "not protected" for `main` with the
token used (which has write, not admin, on Luxurio), so its enforcement could not be inspected.

## 1. How Luxurio works (traced from the code)

**PR validation** (`pr-validation.yml`): `pull_request` only (no secrets, "PR code never runs in
pull_request_target"), `permissions: contents: read`, actions pinned to full SHAs,
`persist-credentials: false`, `npm ci --ignore-scripts`, per-PR `concurrency` with
`cancel-in-progress`, lint/typecheck/tests/build each run after a successful install
(`!cancelled()`), diagnostics retained as an artifact for 7 days.

**Review orchestration** (`luxurio-review-events.yml`): an event relay, not a reviewer.
- Triggers: `pull_request_target` (opened, reopened, synchronize, ready_for_review, closed),
  `discussion_comment` / `discussion` edits on discussion #151 (the "fireside chat"),
  `workflow_dispatch`.
- Filters: repository equals Luxurio; PR events only when the author is a specific user;
  discussion events only for #151.
- Action: no checkout, no PR code, no PR text forwarded. A Python step POSTs
  `{"target": {"kind": "existing_thread", "threadId": …}}` to an external agent platform
  (secrets `BOXES_REVIEW_ENDPOINT`, `BOXES_REVIEW_TOKEN`) with an `Idempotency-Key` derived
  from the run id, a 45 s timeout and error messages that hide the response body.
- Commit `a0b445e` removed a global `concurrency` group so that unrelated events no longer
  replace pending deliveries: each delivery makes the external reviewer "scan all relevant
  PRs", so every event matters only as a wake-up.
- The reviewer itself (Codex, per `.claude/orchestration/README.md`: "the repo owner uses a
  Codex-assisted review process on their side") runs outside GitHub Actions, resumes one
  standing conversation thread, and writes to GitHub **as the maintainer's own account**.

**Observed review output (PR #193)**: formal GitHub reviews by the maintainer account:
`CHANGES_REQUESTED` with P2 findings inline, re-reviews that name the **exact head SHA**
("Re-reviewed exact head `bc3a753…`"), per-finding dispositions (resolved, accepted, still
present), threads closed when resolved, independent re-execution of tests and probes, and a
final `APPROVED` bound to the head, then a human merge.

**Agent process** (`AGENTS.md`, orchestration README): issue selection with dependency checks
("Depends on" issues must be **merged**, not just have an open PR), one issue = one
branch = one worktree = one worker = one PR, model routing from issue labels (`fable`, `opus`,
`sonnet`) with honest disclosure of the model actually used, a local work ledger
(`.claude/state/`, gitignored; GitHub is the durable record), periodic upstream sync, an
independent `code-reviewer` agent before handing a PR to maintainers, and **merges are
human-only** (agents never merge, approve, enable auto-merge or close issues before merge).

## 2. Side-by-side

| Concern | Luxurio | AegisFlight before (PR #36/#37) | AegisFlight now |
|---|---|---|---|
| Trigger of review | `pull_request_target` relay → external agent (no code checkout) | `pull_request` → Claude in Actions | unchanged trigger; dedupe of `reopened`/`ready_for_review` |
| Where the reviewer runs | external platform, standing thread | GitHub Actions, fresh session per commit | same |
| Reviewer identity | maintainer's own account | `claude[bot]` | same (separate from the merge identity) |
| Review bound to SHA | yes, by convention in review text | status on the head SHA | **machine record** (`aegis-review-record`) bound to head SHA, PR, run id; provenance verified from run metadata |
| Severity model | P0–P3 inline | P0–P3, Confirmed/Plausible | same + stable finding IDs across commits, per-criterion acceptance statuses |
| Verdict | human review states | model word + counts | deterministic `READY`/`NON_BLOCKING`/`BLOCKING`/`INCOMPLETE`/`ERROR` |
| Incremental review | reviewer's memory of the thread | newest commit with a `claude-review` status | same, but the status must point to a verified run (forged status ⇒ full review) |
| Remediation | the implementing agent re-works on feedback | `@claude fix` by a human, ≤ 2 cycles | same + optional automatic request by the merge App, verified via `performed_via_github_app` |
| Approval / merge | human only | human only | **merge App after 20 deterministic gates**; humans for escalations |
| Escalation | maintainers decide everything | reviewer's `escalate` flag → label | deterministic path/content/label classifier + reviewer flag; escalated PRs never auto-merge |
| Cost | external platform; Actions job ≤ 2 min | Claude subscription per review | same; orchestrator uses no model |
| Duplicate events | idempotency key per run | concurrency per PR | + per-head dedupe, per-head remediation marker, approval reuse |
| Issue claiming | ledger + `gh pr list` checks, merged-dependency rule | assign + comment (manual) | `issue_claim` tool: eligibility, merged/closed blockers, deterministic race resolution |

## 3. What was adopted

1. **Never execute PR code in a privileged context.** Luxurio's relay checks out nothing; the
   AegisFlight orchestrator runs only default-branch code on default-branch events and checks
   out `main` sparsely.
2. **Exact-head binding** of every review statement, from Luxurio's "re-reviewed exact head"
   practice, made machine-verifiable (record + run provenance + `commit_id` on approval + `sha`
   on merge).
3. **Finding dispositions across commits** (fixed / still present / superseded) and closing
   resolved threads: `previous_findings` in the record; the gate resolves only the reviewer's
   own threads marked fixed/superseded.
4. **Idempotency**: Luxurio's `Idempotency-Key` became per-head-SHA markers (automatic
   remediation), approval reuse, and record-based review dedupe.
5. **Issue discipline**: one issue/branch/worktree/PR, dependencies must be closed (merged),
   honest reporting, GitHub as the durable ledger; codified in `issue_claim.py`.
6. **CI hygiene** already matched (SHA pins, `persist-credentials: false`, per-PR concurrency).

## 4. What was deliberately not adopted

- `pull_request_target` and an external endpoint: AegisFlight keeps the reviewer inside
  Actions with base-branch policy, avoiding a third-party secret and endpoint.
- A reviewer acting as the maintainer's own account: AegisFlight separates reviewer
  (`claude[bot]`) and approver (merge App) so that GitHub's audit trail shows which machine did
  what, and so that the approver can be gated by deterministic checks.
- Human-only merging: replaced, by explicit requirement, with a fail-closed gate for routine
  PRs; Luxurio's human-only rule survives for every escalated PR.
- Author allow-listing by a single login: replaced by collaborator permission checks plus an
  explicit agent-identity allow-list.
- A standing, stateful reviewer thread: AegisFlight reviews are stateless sessions whose state
  lives in GitHub (comments, records), which survives runner and session loss.
