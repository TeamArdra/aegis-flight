# Claude automation: PR review and controlled remediation

This document describes the GitHub automation that reviews every pull request with Claude
and lets Claude fix verified findings, on a maintainer's request or (when enabled)
automatically. It is the reference for maintainers and repository admins. Contributors start
with [`ENGINEERING_WORKFLOW.md`](ENGINEERING_WORKFLOW.md).

> **Autonomous merge pipeline.** The trusted review record, the merge orchestrator (separate
> merge App identity, 20 fail-closed gates), automatic remediation requests and the
> issue-claiming protocol are documented in [`AUTONOMOUS_PIPELINE.md`](AUTONOMOUS_PIPELINE.md);
> admin setup in [`MERGE_APP_SETUP.md`](MERGE_APP_SETUP.md). This document stays the reference
> for the reviewer and remediation workflows themselves.

## 1. Architecture

```
            ┌────────────── pull_request (opened/reopened/synchronize/ready_for_review/labeled)
 PR push ───┤
            ├─▶ CI (ci.yml)             ci-python, ci-frontend          no secrets, read token
            └─▶ Claude review           claude-review job (Sonnet)      advisory
                 (claude-review.yml)    ├─ inline comments + 1 summary comment (claude[bot])
                                        ├─ commit status `claude-review`  P0:a P1:b P2:c P3:d
                                        └─ label claude:escalation-recommended (if escalated)

 maintainer comment "@claude fix …" ─▶ Claude remediation (claude-remediate.yml, Sonnet)
                                        ├─ deterministic gate (no model call)
                                        ├─ tag mode: verify → fix → test → push to PR branch
                                        └─ push (claude[bot]) ─▶ CI + incremental re-review
 merge ◀── human approval only (ruleset); no workflow can merge or approve
```

Design rules:
1. **Review is automatic; remediation is requested, never self-started.** A human with write
   access starts it, or (only when an admin sets `AEGIS_AUTOREMEDIATE=on`) the merge App on a
   verified review with Confirmed P0–P2 findings; at most 2 cycles per PR either way
   ([`AUTONOMOUS_PIPELINE.md`](AUTONOMOUS_PIPELINE.md) §7).
2. **The reviewer cannot change code; the fixer cannot judge its own work.** Remediation
   pushes trigger a fresh, independent review run.
3. **The rules come from `main`.** The review policy is read from the base branch; the action
   restores `CLAUDE.md`, `AGENTS.md` and `.claude/` from the base branch; and the Claude App
   token is only issued when the workflow file matches the default branch.
4. **Deterministic gates before any model call.** Who, which PR, which head, how many cycles:
   all checked in shell, with refusals posted as PR comments.

## 2. Files

| File | Purpose |
|---|---|
| `.github/workflows/ci.yml` | Deterministic CI: `ci-python` (ruff + pytest, Python 3.13), `ci-frontend` (node --test, tsc + vite build, Node 24) |
| `.github/workflows/claude-review.yml` | Automated reviewer |
| `.github/workflows/claude-remediate.yml` | Maintainer-triggered remediation |
| `.github/claude/review-policy.md` | Reviewer instructions: checklist, invariants, severities, output format (loaded from the base branch) |
| `AGENTS.md` | Engineering rules for every agent, incl. §9 Remediation protocol |
| `CLAUDE.md` | Claude-specific rules; imports `AGENTS.md` |
| `.github/pull_request_template.md`, `.github/ISSUE_TEMPLATE/*` | PR template; issue forms (engineering task, bug, evidence run) |
| `.github/CODEOWNERS` | Auto-requests human review for governance files |

## 3. Automated reviewer (`claude-review.yml`)

**Triggers**: `pull_request` `opened`, `reopened`, `synchronize` (new commits),
`ready_for_review`, and `labeled`.

| Condition | Behaviour |
|---|---|
| Non-draft PR from a branch of this repo | Reviewed automatically on every push |
| Draft PR | Skipped (saves usage) unless a maintainer adds `claude:review` |
| Fork PR | Skipped (no secrets on fork `pull_request` runs; see §6) |
| Label `claude:skip-review` | Automatic runs skipped (trivial PRs) |
| Label `claude:review` (one-shot, removed after the run) | Full review now, even on a draft |
| Label `claude:deep-review` (one-shot) | Full review with the deep model (Opus) and 60 turns: the escalation path |
| A PR that edits `claude-review.yml` itself | The action skips (Claude App token exchange requires the file to match `main`) |

**Concurrency**: one review per PR; a new push cancels the running review
(`cancel-in-progress`). Job-level concurrency, so unrelated label events never cancel a review.

**Modes**: *full* (first review, label requests) or *incremental*: on `synchronize`, the newest
earlier PR commit with a completed `claude-review` status becomes the base, and Claude reviews
`git diff <prev>..HEAD` plus interactions, and reports the status of each earlier finding.

**What Claude can do** (`--permission-mode default`, explicit allow-list): read files; `gh pr
view|diff|checks|comment`; `gh issue view`; `git log|diff|show|blame|status`; post inline
comments. Explicitly denied: `Edit`, `Write`, web access, `gh pr review|merge|edit|close`,
`gh api`, `gh workflow`, `git push|commit`. It never runs project code; it reads CI results.

**Outputs**:
- Inline comments for P0–P2 findings and one summary comment (template in the policy).
- Structured result (`--json-schema`): verdict, findings with category, P0–P3 and INFO counts,
  escalation flag.
- Commit status `claude-review` on the reviewed head SHA, set by the workflow token from the
  structured result: `success` (no P0/P1), `failure` (P0/P1 present; advisory), `error`
  (incomplete/cancelled/skipped), `pending` (running).
- Label `claude:escalation-recommended` when the reviewer escalates.

**What the reviewer looks for**: bugs, vulnerabilities, regressions, flight-safety violations
and violations of frozen contracts or recorded owner decisions. A change is not a finding
because it is new, adds files or modifies existing behaviour; intentional feature work that
is sound is listed under "Feature changes reviewed". Vehicle-command, auth, deserialisation,
listener and integrity code is always read in full ("tier 1"), or the review is `INCOMPLETE`.

**Classification**: every finding has a category (`SAFETY`, `SECURITY`, `DEFECT`,
`REGRESSION`, `CONTRACT_VIOLATION`, `EVIDENCE_GAP`, `IMPROVEMENT`), a severity (P0 critical:
unauthorised vehicle control, force-arm, critical bypass · P1 high: auth/integrity bypass,
unsafe deserialisation, unsafe command handling, serious regression, unapproved contract or
decision change · P2 medium: logic, state, leaks, races, recovery, untested change ·
P3 low · INFO optional, never counted or blocking) and a confidence (*Confirmed*, only these
may be P0/P1, or *Plausible*, ≤ P2). `review_record.py` enforces the consistency rules
(INFO only for IMPROVEMENT; IMPROVEMENT only INFO/P3; CONTRACT_VIOLATION only P0/P1) and
forces escalation for any P0, SAFETY or CONTRACT_VIOLATION finding. Full definitions and
AegisFlight examples: `.github/claude/review-policy.md`.

**Escalation mechanism**: the reviewer sets `escalate=true` for frozen-contract, hash-chain,
signing/key, receive-only-serial, bind-address, `.github/`, threshold/fusion, evidence-claim,
architectural changes, any P0, any SAFETY or CONTRACT_VIOLATION finding, or a Confirmed P1
whose impact or approval status is not established (an unconfirmed risk is a Plausible P2,
never a P1). Documented commands or defaults that enable transmission, `active-ips`, a
non-loopback bind or arming are read in full, and an unsafe documented default is a SAFETY
finding. A link counts as physical unless the code restricts it to loopback or local SITL
(policy section 4.1). The workflow adds
`claude:escalation-recommended`. A maintainer then (a) asks the human domain owner to review
and/or (b) adds `claude:deep-review` for an Opus review. Humans always own security-sensitive
architectural decisions.

## 4. Remediation (`claude-remediate.yml`)

**Command**: a PR conversation comment that **starts with** `@claude fix`, e.g.
`@claude fix the verified P1 and P2 findings from the latest review`. Other `@claude` comments
do nothing (general GitHub chat is disabled for cost).

**Automatic requests** (`AEGIS_AUTOREMEDIATE=on` only): the merge orchestrator posts, as the
merge App, `@claude fix the verified findings R1, R2 …` with a marker naming the head SHA, for
Confirmed P0–P2 findings of a verified review of a non-escalated PR, at most twice per head
and the second time only after a newer review of it
([`AUTONOMOUS_PIPELINE.md`](AUTONOMOUS_PIPELINE.md) §7).

**Subprocess isolation**: the Claude step runs with `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1`, which
makes Claude Code require bubblewrap. The job installs `bubblewrap`/`socat`, allows
unprivileged user namespaces on the ephemeral runner and checks that `bwrap` can create a
sandbox before Claude starts; if not, the run fails (isolation is never switched off).

**Gate** (shell, before any model call; each refusal is posted on the PR):
1. Commenter is a human with `write`/`maintain`/`admin` (checked via the API, not just
   `author_association`), and in `CLAUDE_REMEDIATION_ALLOWLIST` if that variable is set; **or**
   the comment is a bot comment that GitHub records as created by App id `AEGIS_MERGE_APP_ID`
   (`performed_via_github_app`, login `<AEGIS_MERGE_APP_SLUG>[bot]`), automatic remediation is
   on, and its marker names the current head.
2. PR is open, head branch is in this repository (no forks), head is not the default branch.
3. The **current head** has a `claude-review` status created by `github-actions[bot]` whose
   `target_url` is a run GitHub records as `claude-review.yml` / `pull_request` on that commit,
   that is complete (`success`/`failure`) and reports ≥ 1 P0–P2 finding. P3 is never remediated.
4. Fewer than `CLAUDE_MAX_REMEDIATION_CYCLES` (default **2**) cycles used on this PR, counted
   from marker comments posted by `github-actions[bot]` (users cannot forge them).
5. Only comments by write-access humans and the pipeline bots are passed to Claude
   (`include_comments_by_actor`).

**Run**: tag mode (`trigger_phrase: "@claude"`), so the action checks out the PR branch and its
push wrapper can update **only that branch**. `--permission-mode acceptEdits` with an explicit
allow-list (pytest, ruff, frontend test/build, read-only `gh`/`git`). Denied: editing
`.github/**`, `scripts/aegis_automation/**`, `tests/automation/**`, `AGENTS.md`, `CLAUDE.md`,
`models/**`, `artifacts/**`; web; `gh pr
merge|review|edit|create`, `gh api|workflow|secret|release`; force-push, rebase, reset.
The appended system prompt points Claude to `AGENTS.md` §9: verify each finding, fix only
confirmed ones with regression tests, run tests, push, report *fixed / not reproduced /
deferred*.

**Loop and recursion analysis**:
- Review never triggers remediation: remediation needs a `User` comment starting with
  `@claude fix` from a write-access human; `claude[bot]` comments fail both the job condition
  and the action's own bot check.
- Remediation's push triggers exactly one review (as `claude[bot]`, allowed via
  `allowed_bots: claude`). That review cannot push or start anything.
- The cycle counter bounds remediation per PR; concurrency serialises requests per PR.
- Pushes made with the workflow `GITHUB_TOKEN` would not trigger workflows; none are made.
- No workflow has permission or tools to merge or approve, and the ruleset requires a human
  approval of the latest push by someone other than its pusher.

## 5. Authentication and permissions

| Item | Value |
|---|---|
| Claude auth | Repository secret `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`), passed only to the action input `claude_code_oauth_token` in the two Claude workflows. Never printed. CI does not receive it. |
| GitHub auth for Claude | The official Claude GitHub App (installed for the TeamArdra org with access to this repo). The action exchanges the job's OIDC token (`id-token: write`) for a short-lived installation token. Comments and pushes appear as `claude[bot]`. |
| App permissions used | Contents R/W (remediation push), Pull requests R/W (comments), Issues R/W (comments). The app also requests Actions/Checks read and Workflows/Discussions for future features. |
| Workflow token | `permissions: {}` at workflow level; each job lists only what it uses (see the YAML comments). No job has `contents: write`. |
| Required repo variables | None. Optional: `CLAUDE_REVIEW_MODEL`, `CLAUDE_DEEP_REVIEW_MODEL`, `CLAUDE_REVIEW_MAX_TURNS`, `CLAUDE_REMEDIATION_MODEL`, `CLAUDE_MAX_REMEDIATION_CYCLES`, `CLAUDE_REMEDIATION_ALLOWLIST` |

**Models**: routine review and remediation use `claude-sonnet-5-5` (Claude Sonnet 5.5); the
escalation review uses `claude-opus-5-5` (Claude Opus 5.5). Change with the variables above
rather than editing YAML. Turn limits: review 30 (deep 60), remediation 60. Job timeouts: 30
and 60 minutes.

## 6. Security model

| Boundary | Control |
|---|---|
| Fork PRs (public repo) | Plain `pull_request` trigger: GitHub withholds secrets and gives a read-only token; the review job is skipped; remediation refuses cross-repository PRs. No `pull_request_target` or `workflow_run` is used anywhere. |
| PR edits the reviewer's rules | Policy read from the base branch; the action restores `CLAUDE.md`/`AGENTS.md`/`.claude/` from base; the App token requires the workflow file to equal `main`. |
| Prompt injection via PR text, issue bodies, comments | The policy treats all PR-authored text as data and reports injection attempts as P1; remediation only receives comments from write-access humans; the action strips hidden markdown; neither job interpolates untrusted text into shell (`run:` steps read event data only through `env:`). |
| Reviewer misuse of the App token | Deny-list blocks writes, `gh api`, approvals and merges; `--permission-mode default` denies anything not allow-listed. |
| Remediation running PR code | Only same-repo branches whose authors already have write access (who can already run workflows with secrets by pushing a branch), so no new trust is granted; `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` is set as a best-effort credential scrub for commands Claude runs. |
| Supply chain | Every third-party action pinned to a full commit SHA (`actions/checkout` v7.0.1, `actions/setup-python` v7.1.0, `actions/setup-node` v7.1.0, `anthropics/claude-code-action` v1.0.277). The composite action itself pins `oven-sh/setup-bun` by SHA. |
| Logs on a public repo | `show_full_output` and `display_report` stay off (defaults). Do not enable Actions debug logging (`ACTIONS_STEP_DEBUG`) on this public repo: it turns on full output. |
| Merging | No workflow has merge tools or `contents: write`; merging is human-only under the ruleset. |

**Residual risks** (accepted, documented):
- A write-access collaborator can change any workflow on a branch; trust in collaborators is
  the real boundary. Keep the collaborator list tight (21 accounts at time of writing).
- LLM review can miss defects or raise false positives; it is advisory and never replaces
  the required human approval.
- Remediation output is code written by a model; the follow-up automated review and the
  human approval are the controls.

## 7. Usage and cost

Each review/remediation run is a Claude Code session billed to the **Claude subscription
of the person who created `CLAUDE_CODE_OAUTH_TOKEN`**, shared by everyone who opens PRs. It is
not unlimited background compute: heavy days can hit the plan's usage limits, after which runs
fail (`claude-review` = `error`) until the limit resets. No API billing or extra usage is
enabled by this setup; do not enable it without the account owner's decision.

Controls in place: Sonnet by default (Opus only on an explicit `claude:deep-review` label);
turn and time limits; superseded reviews cancelled; drafts skipped; incremental re-reviews;
reviewer reads CI results instead of re-running tests; no `@claude` chat; remediation only on
request, ≤ 2 cycles per PR, and refused when there is nothing to fix.

The token from `claude setup-token` is long-lived (about one year). Record its owner and expiry
outside the repo, and rotate it by replacing the secret.

## 8. Validation status

State when the infrastructure PR (#36) was opened, 2026-11-17. "Verified" means observed on
GitHub or run locally; "not verified" items are covered by the post-merge test plan below.

| Check | Result |
|---|---|
| YAML syntax, expressions, action inputs (`actionlint` 1.7.12) | Verified: clean |
| `run:` scripts (`shellcheck` 0.11.0, severity ≥ warning) | Verified: 15/15 clean |
| Actions security lint (`zizmor` 1.32.0, default persona) | Verified: no findings; `issue_comment` trigger suppressed with justification. Auditor persona adds `secrets-outside-env` (optional hardening: move the secret to an Environment) |
| CI on GitHub (`ci-python`, `ci-frontend`) | Verified on PR #36: both green on Ubuntu (pytest + ruff 3 min; node tests 31/31 + build) |
| Unrelated `labeled` events skip the review job and do not cancel it | Verified on PR #36 (two skipped runs) |
| Reviewer fails closed when the policy is not on the base branch | Verified on PR #36: `fatal: path … exists on disk, but not in 'origin/main'`; status `pending → error` written by `github-actions[bot]` |
| Remediation gate logic (15 scenarios: no write access, allowlist, fork, closed, head=main, no/forged/pending/error status, P3-only, proceed, forged cycle marker, cycle limit) | Verified locally with a stubbed `gh` against the exact workflow script |
| Review status publisher (9 scenarios incl. malformed/injected structured output) and gate round-trip | Verified locally |
| Incremental-mode selection (ignores user-forged statuses; force-push falls back to full) | Verified locally against real branch history |
| Claude App OIDC token exchange, `CLAUDE_CODE_OAUTH_TOKEN` accepted, Sonnet model id accepted under the subscription | **Not verified**: needs the workflows on `main` |
| Review comments/inline comments/structured output on a real PR; incremental re-review | **Not verified** (post-merge test plan) |
| `@claude fix` end-to-end: tag-mode checkout, push to PR branch, re-review triggered by `claude[bot]` push | **Not verified** (post-merge test plan) |
| Ruleset enforcement / no merge without human approval | **Not verified**: the ruleset is currently disabled (§9) |

### Post-merge test plan

1. Open a small PR from a branch in this repo (ready for review) → `claude-review` run, a
   summary comment by `claude[bot]`, a `claude-review` status with counts.
2. Push another commit → incremental review naming the previous SHA; a still-running earlier
   review is cancelled.
3. `@claude fix the verified P1 and P2 findings from the latest review` on a PR whose review
   has no P0–P2 → refusal comment. Then on a PR seeded with a real defect → "cycle 1 of 2",
   a `claude[bot]` push to the same branch, and a new review run.
4. A third `@claude fix` after two cycles → refusal ("used all 2 cycles").
5. `claude:deep-review` label → Opus review, label removed afterwards.
6. With the ruleset active: merging without a second human's approval is blocked.

## 9. Admin setup and recommended repository settings

These are **not** changed by the infrastructure PR; a repository admin applies them.

> **Update 2026-11-17:** the ruleset below is now **active** on `~DEFAULT_BRANCH` with the
> listed rules and required checks `ci-python`/`ci-frontend`; its bypass list holds
> *Organization admin* and the *Repository admin* role (the admin emergency override). It
> needs no change for the merge App ([`MERGE_APP_SETUP.md`](MERGE_APP_SETUP.md) §5). The text
> below is kept as the original setup record.

1. **Ruleset "Claude Automation" (id 27404843)** (state when PR #36 was written: enforcement
   `disabled` and no target, so `main` had no protection).
   Settings → Rules → Rulesets → *Claude Automation*:
   - *Target branches* → Add target → **Include default branch**.
   - Keep: restrict deletions, block force pushes, require linear history, require a PR with
     1 approval, dismiss stale approvals, require approval of the most recent push, require
     conversation resolution, allowed merge method **squash**. Keep the bypass list **empty**.
   - *Require status checks to pass* → add **`ci-python`** and **`ci-frontend`** (source:
     GitHub Actions). Do **not** add `claude-review` or `claude-remediate`: they are advisory,
     depend on subscription capacity, and would block merges on a model's opinion.
   - "Require branches to be up to date": currently on. Each update re-runs CI and the Claude
     review (usage). Consider turning it off; linear history and squash already apply.
   - Review dismissal is restricted to repository admins and an app installation
     (`IntegrationInstallation` 168602003). If that installation is the Claude app, remove
     it: no bot should be able to dismiss a human review.
   - *Enforcement status* → **Active**. Then verify:
     `gh api repos/TeamArdra/techfest-2026/rules/branches/main` lists the rules.
2. **Labels** used by the automation (already created by the infrastructure PR author):
   `claude:review`, `claude:deep-review`, `claude:skip-review`, `claude:escalation-recommended`.
3. **Actions settings**: *Fork pull request workflows from outside collaborators* →
   **Require approval for all outside collaborators** (currently first-time contributors only).
   Optionally restrict allowed actions to `actions/*`, `anthropics/claude-code-action@*` and
   `oven-sh/setup-bun@*` (the action uses it internally).
4. **Code security**: enable secret scanning and push protection (free for public repos;
   currently disabled).
5. **Merge settings**: optionally disable merge commits and rebase merging at the repository
   level to match the ruleset (squash only). Keep auto-merge disabled.
6. **CODEOWNERS**: assign human domain owners (issue #13) and, once populated, consider
   enabling "Require review from Code Owners".

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Review run shows "Skipping action due to workflow validation" | The PR changes `claude-review.yml` (or the workflow is not on `main` yet). Expected; it works once merged. |
| `claude-review` status `error` | Open the run. Usual causes: usage limit reached, max turns hit, run cancelled by a newer push, or an expired/invalid `CLAUDE_CODE_OAUTH_TOKEN` (401 from the API: regenerate with `claude setup-token`, update the secret). |
| Run fails with "`--json-schema` was provided but Claude did not return structured_output" | This message from the action hides the real cause. Read the `run diagnosis:` line in the "Build the review record" step, which is also in the job summary and the record's `problems`. `api_error` means the CLI failed before any model call (no tokens used): a usage limit, or a rejected or expired `CLAUDE_CODE_OAUTH_TOKEN`. The diagnosis quotes the CLI's sanitised error text. Fix the account or secret and re-run; nothing in the PR is at fault. `max_turns`, `no_structured_output` and `run_error` mean the model ran. The verdict stays `ERROR`/`INCOMPLETE` in every case (issue #119). |
| "Could not fetch an OIDC token" | The job lost `id-token: write`, or the PR is from a fork. |
| No review on a PR | Draft, fork, `claude:skip-review`, or closed. Add `claude:review` to force one. |
| `@claude fix` does nothing | The comment must *start* with `@claude fix`, be on the PR conversation (not an inline thread), by a human with write access. A refusal comment explains any gate failure. |
| Remediation refused "no automated review of the current head" | A commit was pushed after the last review. Wait for that review to finish. |
| Remediation push did not trigger a review | Check that `allowed_bots: claude` is still set in `claude-review.yml` and that the push came from `claude[bot]`. |
| Review comments missing but run succeeded | Check the run log for denied tool calls; the allow-list may need a new `gh` subcommand. |

## 11. Autonomy

Implemented (see [`AUTONOMOUS_PIPELINE.md`](AUTONOMOUS_PIPELINE.md)), each behind a switch:
verified merge of routine PRs by a separate merge App (`AEGIS_AUTOMERGE`, default dry-run) and
automatic remediation requests for Confirmed P0–P2 findings (`AEGIS_AUTOREMEDIATE`, default
off; same cycle counter; never for escalated PRs).

Still not enabled:
1. **Issue-to-PR agent**: `@claude implement` on an `agent-ready` issue by a maintainer, in
   tag mode (creates `claude/issue-N` and a PR link, never merges). Needs a per-day run cap.
2. **Required advisory check**: make `claude-review` required only after weeks of
   false-positive data, with a documented human override.
Each of these increases subscription usage and the blast radius of a bad model output; none
should be enabled without the account owner's agreement.
