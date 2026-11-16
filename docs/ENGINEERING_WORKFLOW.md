# Engineering workflow: issues, branches, PRs, review

How Team Ardra and its coding agents turn a GitHub issue into a merged change. The rules
agents must follow are in [`AGENTS.md`](../AGENTS.md); the GitHub automation is described
in [`CLAUDE_AUTOMATION.md`](CLAUDE_AUTOMATION.md).

## 1. Roles

| Role | Who | Does | Never |
|---|---|---|---|
| Principal architect | Claude Opus, started by a human for a specific task | Architecture, cross-cutting design, frozen-contract migrations, this infrastructure | Routine issue work by default |
| Implementation engineer | A teammate's **local** Claude Code session on Sonnet (or the teammate) | One issue → one branch → one PR; tests; answers review findings | Works on `main`, merges, changes contracts or automation as a side effect |
| Independent reviewer | Claude Sonnet in GitHub Actions (`claude-review`) | Reviews every PR push; posts findings; sets an advisory status | Approves, merges, pushes, edits |
| Remediation agent | Claude Sonnet in GitHub Actions (`claude-remediate`), **only on a maintainer's `@claude fix` request** | Verifies and fixes P0–P2 findings on the PR branch, at most 2 cycles per PR | Starts itself, touches P3, merges |
| Humans | Team Ardra maintainers | Choose work, approve designs, approve and merge PRs, change repo settings, sign off hardware evidence | Delegate final approval or merging to an agent |

## 2. Lifecycle

```
issue (agent-ready, unassigned, unblocked)
  → claim (assign + comment)            → branch <type>/<n>-<slug> from origin/main
  → implement + test locally            → push branch, open PR "Closes #n" (template)
  → CI (ci-python, ci-frontend)  +  Claude review (comments + claude-review status)
  → author fixes / answers findings     → push → CI + incremental re-review
     (optional) maintainer: "@claude fix …" → remediation push → re-review   [≤ 2 cycles]
  → all conversations resolved, CI green → human approval → human squash-merge
```

## 3. Choosing and claiming an issue

The backlog is tracked in issue #4 (tracker) with epics #5–#9. Labels:

| Label | Meaning for an implementer |
|---|---|
| `agent-ready` | Well specified; a Sonnet session can take it |
| `prio:P0`…`P3` | Priority (P0 first) |
| `needs:human-approval` | A maintainer must approve the approach **on the issue** before code |
| `needs:frozen-contract` | Touches a frozen contract; needs the user's approval + migration (`AGENTS.md` §4) |
| `needs:hardware` / `model:human` | Not for agents |
| `model:sonnet` / `model:opus` / `model:haiku` | Recommended model |
| `type:*`, `area:*`, `size:*` | Kind, subsystem, effort |

Before starting, check that nobody else is on it:

```bash
gh issue view <n> --json assignees,state,labels,body      # unassigned? read "Blocked by"
gh pr list --state open --search "<n> in:body"            # no open PR already references it
gh issue edit <n> --add-assignee @me
gh issue comment <n> --body "Claiming: branch fix/<n>-<slug>"
```

Blocked issues ("Blocked by #m" in the table at the top of each issue) wait until `#m` is
closed. One person or agent per issue. Do not start several agents on several issues at once
just because they are available; each PR costs review time and Claude usage.

## 4. Branch and PR conventions

- Branch: `<type>/<issue#>-<short-slug>`, e.g. `fix/16-sats-255-unknown`. Types: `feat`, `fix`,
  `chore`, `docs`, `test`, `evidence`, `refactor`. Always from fresh `origin/main`:
  ```bash
  git fetch origin
  git worktree add ../wt-16 -b fix/16-sats-255-unknown origin/main
  ```
- Commits: small and logical; imperative subject; no AI attribution trailers.
- PR: target `main`; title `<type>: <summary> (#<n>)`; body from the template, with
  `Closes #<n>` (or `Part of #<n>` when the issue needs several PRs). Paste the exact commands
  and summary lines (`python -m pytest` summary line, `ruff`, frontend, Stage-1 regression when required).
- Open as **draft** while iterating: drafts are not reviewed automatically, which saves usage.
  Mark *Ready for review* when you want the automated review.
- Push in meaningful batches. Every push to a ready PR triggers a new review run.

### Starting a local Sonnet session on an issue

```bash
cd ../wt-16
claude --model sonnet
```
Then give it a prompt like:

> Work on issue #16. Read it with `gh issue view 16`, follow AGENTS.md (§7 how work happens,
> §8 definition of done). Stay inside the issue's scope. Write the test first. When done,
> run the gate commands, commit, push the branch and open a PR with the template filled in.
> Do not merge.

## 5. Reading the automated review

The reviewer posts **one summary comment** per run (heading "AegisFlight automated review:
`<sha>`"), **inline comments** for P0–P2 findings, and a commit status `claude-review`:

| Status | Meaning |
|---|---|
| `success` "P0:0 P1:0 P2:n P3:m" | No blocking findings |
| `failure` "… (blocking findings; advisory)" | At least one P0/P1. Advisory: it does not block merging by itself, but a human should not approve until each is fixed or rebutted |
| `error` | The review did not finish (turn limit, usage limit, cancelled, or the workflow skipped itself); see the run log |
| `pending` | Review running |

Severities: **P0** critical security/integrity/system-breaking, **P1** significant correctness
or regression, **P2** moderate (fix or add validation), **P3** minor/non-blocking. Each finding
is **Confirmed** (traced in code) or **Plausible** (speculative; at most P2). Each finding has
a location, the problem, why it matters, a failure scenario, a recommended fix and the
validation required.

How to respond:
- Fix confirmed findings in a new commit (the next review checks them in incremental mode).
- If you disagree, reply in the inline thread with evidence (file:line, test). The reviewer
  can be wrong. A human decides.
- The `main` ruleset requires **all conversations resolved** before merging: resolve each
  inline thread once it is fixed or answered.
- `claude:escalation-recommended` means the reviewer thinks a human domain owner (and
  possibly a `claude:deep-review`) should look. Security, integrity, frozen-contract and
  evidence changes always need a human domain review regardless.

## 6. Asking Claude to fix findings (remediation)

A maintainer (write access) comments on the PR conversation, starting with `@claude fix`:

```
@claude fix the verified P1 and P2 findings from the latest review
@claude fix R2 only; leave R1 for me
```

The workflow first checks: the PR is from this repository; the **current head** has a
finished automated review with P0–P2 findings; fewer than 2 remediation cycles have been used
on this PR. If a check fails it posts the reason and stops. Otherwise Claude verifies each
finding, fixes only confirmed ones (with tests), runs the tests, pushes to the PR branch and
reports *fixed / not reproduced / deferred*. The push triggers a new automated review.
Nothing merges automatically. Details: [`CLAUDE_AUTOMATION.md`](CLAUDE_AUTOMATION.md) §4.

Other `@claude …` comments do nothing: general chat with Claude on GitHub is disabled to save
usage. Use a local session instead.

## 7. Merging (humans only)

Merge when: CI checks are green; the latest `claude-review` status is not `failure`, or every
P0/P1 has been rebutted in its thread; all conversations are resolved; another human has
approved the latest push. Use **squash merge**. GitHub adds `Co-authored-by:` lines for other
commit authors (for example `claude[bot]` after a remediation) to the squash message. Remove
them in the merge dialog if the team wants human-only authorship.

## 8. Usage etiquette

Every automated review and remediation consumes the Claude subscription behind
`CLAUDE_CODE_OAUTH_TOKEN` (one person's plan, shared by the whole team). Use drafts while
iterating, batch your pushes, use `claude:skip-review` for trivial PRs (typo, a comment), and
request `claude:deep-review` (Opus) only for security-critical or architectural changes.
