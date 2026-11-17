# Merge App setup and post-installation verification (admin only)

The merge orchestrator (`.github/workflows/aegis-orchestrator.yml`) approves and merges only
through a **dedicated GitHub App** owned by TeamArdra. Nothing in the repository creates this
App or its key: an organisation admin does it once, in the GitHub UI. Until then the
orchestrator runs in `dry-run` and only posts gate reports.

## 1. Why a dedicated App (and not the alternatives)

| Option | Verdict |
|---|---|
| Workflow `GITHUB_TOKEN` | **Rejected.** Approving needs the repository setting "Allow GitHub Actions to create and approve pull requests" (currently off, keep it off). The identity `github-actions[bot]` is shared by every workflow, including any a collaborator adds on a feature branch, so it is neither separate nor trustworthy. |
| The Claude App (`claude[bot]`) | **Rejected.** It is the reviewer and the remediation author; it must never approve. |
| A personal access token of a human | **Rejected.** It would impersonate a person and bypass separation of duties. |
| A machine-user account + PAT | Possible fallback only if App approvals turn out not to count toward the ruleset (step 6 verifies). Costs a seat, long-lived credential. |
| **Dedicated GitHub App** | **Chosen.** Distinct bot identity (`<slug>[bot]`), short-lived installation tokens (1 h) minted per run, permissions scoped to this repository, no human account, revocable by suspending the installation. |

Facts this design relies on (GitHub documentation, checked 2026-11-17): required approvals
count reviews from accounts with **write** permission, and an App with *Contents: write* has
write access; GitHub refuses approval of one's own PR; `require_last_push_approval` requires the
approver to differ from the last pusher (the App never pushes); events caused by an App token
(unlike `GITHUB_TOKEN`) do trigger workflows, so the post-merge CI on `main` runs; ruleset bypass
can be granted to Apps, **and is not needed here**. GitHub's documentation does not state
explicitly that an App's approval satisfies a ruleset's required approval count; step 6
verifies it live before `on` is enabled.

## 2. Create the App

Organisation **TeamArdra** → Settings → Developer settings → GitHub Apps → **New GitHub App**
(or use the manifest in `.github/automation/merge-app-manifest.json` with the
[manifest flow](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest)).

| Setting | Value |
|---|---|
| Name | `aegis-merge-gate` (any unique name; its **slug** becomes `AEGIS_MERGE_APP_SLUG`) |
| Homepage URL | `https://github.com/TeamArdra/techfest-2026` |
| Webhook | **Inactive** (uncheck "Active"); no events |
| Where can it be installed | Only on this account |

**Repository permissions (exactly these; everything else "No access"):**

| Permission | Level | Used for |
|---|---|---|
| Metadata | Read | mandatory |
| Contents | Read and write | squash merge (`PUT /pulls/{n}/merge`); makes the App's approval a write-access approval |
| Pull requests | Read and write | submit the `APPROVE` review, resolve the reviewer's fixed threads, read PR files/commits/reviews |
| Issues | Read and write | the gate report and automatic remediation request comments (PR conversation comments are issue comments) |
| Actions | Read and write | read runs, jobs and the review-record artifact; re-run an `ERROR` review once |
| Checks | Read | check runs on the head commit |
| Commit statuses | Read | statuses on the head commit |

Do **not** grant: Administration, Workflows, Secrets, Environments, Members, or any
organisation permission. Do **not** add the App to any ruleset bypass list.

After creating it, note the **App ID** and **Client ID**, and **Generate a private key** (a
`.pem` download). Store the file only until step 4, then delete it.

## 3. Install it

App settings → Install App → TeamArdra → **Only select repositories** → `techfest-2026`.

## 4. Store credentials (never in the repository)

Repository → Settings → Environments → **`automerge`** (already created; its deployment
branch policy allows only `main`; keep it that way and do not add required reviewers).

- Environment secret **`AEGIS_MERGE_APP_PRIVATE_KEY`** = full contents of the `.pem`.
  Do not create it as a repository or organisation secret: those are readable by workflows on
  any branch.

Variables (all are public identifiers, not secrets):

| Variable | Where | Value |
|---|---|---|
| `AEGIS_MERGE_APP_CLIENT_ID` | environment `automerge` (or repository) | the App's Client ID |
| `AEGIS_MERGE_APP_SLUG` | **repository** (and optionally the environment, same value) | the App's slug |
| `AEGIS_MERGE_APP_ID` | **repository** (and optionally the environment, same value) | the numeric App ID |
| `AEGIS_AUTOMERGE` | repository | leave **unset** (= `dry-run`) until the live tests pass |
| `AEGIS_AUTOREMEDIATE` | repository | leave unset (= `off`) |

`claude-remediate.yml` does not run in the `automerge` environment, so it can only see
**repository** variables: `AEGIS_MERGE_APP_SLUG` and `AEGIS_MERGE_APP_ID` must exist at
repository level for automatic remediation requests to be accepted. The job-level `if:` of
both workflows also reads only repository variables (`AEGIS_AUTOMERGE`, `AEGIS_AUTOREMEDIATE`).
An environment variable with the same name overrides the repository value inside the
orchestrator job; keep them identical.

Current configuration (2026-11-17): App `aegisflight-merge-bot`, id 5795459, owned by the
`RajTib` account and installed on this repository only; private key and client id in the
environment; slug and id also set as repository variables.

## 5. Repository settings to keep (verified 2026-11-17)

Ruleset **"Claude Automation"** (id 27404843, active, target `~DEFAULT_BRANCH`) needs **no
change**:

| Rule | Keep | Why it still works with the App |
|---|---|---|
| Restrict deletions, block force pushes, require linear history | yes | squash merges are linear |
| Pull request: 1 approval, dismiss stale approvals, require approval of the most recent push, require conversation resolution, squash only | yes | the App approves the exact head; it never pushes; the gate resolves only the reviewer's fixed threads and requires all others resolved |
| Required status checks `ci-python`, `ci-frontend`, **source: GitHub Actions (integration id 15368)** | yes | the gate also requires them (and every other required check). Corrected 2026-11-17: the source had been set to the Claude App (1236702), which made every merge fail with "not set by the expected GitHub apps" |
| Bypass: Organization admin, Repository admin role (always) | yes | your emergency override; the App gets **no** bypass |

Also keep: Actions setting "Allow GitHub Actions to create and approve pull requests" = **off**;
default workflow permissions = read; repository auto-merge disabled (the orchestrator merges
directly with a SHA guard, it does not use auto-merge or a merge queue).

Review-dismissal restriction note: the ruleset lets "Repository admin" and the app
installation `168602003` dismiss reviews. If that installation is the Claude App, consider
removing it so no bot can dismiss a human or merge-App review.

## 6. Post-installation verification (do these in order)

**Status 2026-11-17 (before PR #38 merged):** the App-level checks were run live with a
temporary harness (token minting, repository scoping, comment provenance, approval counted by
the ruleset, SHA guard, squash merge of marker PR #41 by the App, workflow re-run); see
`AUTONOMOUS_PIPELINE.md` §14. Steps 3–8 below need the orchestrator and the new reviewer on
`main`, so they run after PR #38 is merged.

Use a throwaway issue with acceptance criteria (template "Engineering task") and a tiny,
non-escalated change (for example one line in `docs/DEVELOPMENT.md`; not `.github/**`).

1. **Token minting**: Actions → *AegisFlight merge orchestrator* → Run workflow → `pr` = the
   PR number. Expected log: `mode=dry-run … identity=aegis-merge-gate[bot]`. A slug mismatch
   or missing key fails loudly; fix the variable/secret.
2. **Key isolation**: on a scratch branch (not merged), add a workflow that references
   `secrets.AEGIS_MERGE_APP_PRIVATE_KEY` without `environment:`; confirm it receives an empty
   value. Delete the branch.
3. **Dry-run report**: on the test PR (branch `docs/<issue>-test`, body `Closes #<issue>`), wait
   for CI and the review. Expected: one comment "AegisFlight merge gate" by
   `aegis-merge-gate[bot]` listing G01–G20; it should say *Eligible … Dry-run mode*. If a gate
   fails, its detail column says why.
4. **Negative checks** (each must leave the PR unmerged): add label `automerge:hold` →
   `/aegis merge-check` → G18 fails; remove it. Push a commit → the report flips to "not
   eligible" (G09/G10/G15) until the new review finishes.
5. **Turn on**: set `AEGIS_AUTOMERGE=on`, comment `/aegis merge-check`.
6. **Approval counts**: expected in the run log `outcome=merged`; on the PR an approval by
   `aegis-merge-gate[bot]` at the head SHA, then a squash merge by the same App, the issue
   closed by `Closes #`, and CI running on `main`. If instead the report says
   `merge_failed (405 …review…)`, GitHub did not count the App approval: set
   `AEGIS_AUTOMERGE=dry-run` and use the machine-user fallback from §1 (open an issue first).
7. **Escalation**: open a PR touching `src/aegisflight/logging/store.py` (or any escalated path);
   confirm the report lists `event_log_integrity` and no approval happens.
8. **Automatic remediation (optional)**: set `AEGIS_AUTOREMEDIATE=on`; on a test PR with a
   deliberate, confirmable defect, expect an `@claude fix the verified findings R…` comment by
   the App, a "cycle 1 of 2" comment, a `claude[bot]` push, then a new review. Check the
   remediation gate log shows the `performed_via_github_app` check passing.
9. Record the results (date, PR numbers, outcomes) in `CLAUDE_AUTOMATION.md` §8.

## 7. Operations

- **Disable instantly**: `AEGIS_AUTOMERGE=off`, or suspend the App installation.
- **Rotate the key**: App settings → generate a new private key → replace the environment
  secret → delete the old key in the App settings.
- **Revoke**: uninstall the App; the orchestrator then fails in `on` and reports in `dry-run`.
- **Audit**: every merged PR has the gate report with the full review record JSON; the App's
  approvals and merges appear in the PR timeline and the organisation audit log.
