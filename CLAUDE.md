# CLAUDE.md: AegisFlight

Instructions for Claude Code sessions (local and in GitHub Actions). The engineering rules
shared with every agent and human are in `AGENTS.md`, imported here:

@AGENTS.md

## Claude-specific rules

### Roles
- **Implementation (Claude Sonnet, local sessions):** routine issue work. Follow `AGENTS.md`
  §7 exactly: one claimed issue, one branch/worktree, one PR. Do not redefine project-wide
  contracts, CI, automation or these instruction files as a side effect of an issue.
- **Architecture (Claude Opus, on request only):** cross-cutting design, frozen-contract
  migrations, security-sensitive changes. A human asks for it; it is not the default.
- **Automated reviewer and remediation (GitHub Actions):** see `docs/CLAUDE_AUTOMATION.md`.
  They read this file from the PR's **base** branch.

### Working style
- Read the issue (`gh issue view <n>`), its acceptance criteria and its "Blocked by" row
  before writing code. Read the code you change, its callers and its tests.
- Paste exact commands and their summary lines in the PR. If you did not run something,
  write "not run". Never claim a test, benchmark or SITL run you did not perform.
- When unsure whether a change touches a frozen contract (`AGENTS.md` §4) or a security
  boundary (§5), stop and ask on the issue instead of guessing.
- Prefer the smallest change that satisfies the acceptance criteria. No drive-by refactors.
- Do not install third-party skills, plugins or MCP servers at runtime for repository work;
  anything a task needs must be reproducible from the repo.
- Git: never commit to `main`, never force-push a shared branch, never merge. No
  `Co-Authored-By: Claude` or "Generated with Claude Code" lines in commits or PR bodies.
- `.claude/` is local configuration and is git-ignored; never commit it.

### Useful entry points
- Docs index: `docs/README.md`; hand-off and frozen-contract history: `docs/HANDOFF.md`.
- Where to add things: `docs/DEVELOPMENT.md` ("Where to add things").
- Process and review findings: `docs/ENGINEERING_WORKFLOW.md`.
- Benchmarking: `docs/BENCHMARKING.md`; evidence index: `docs/VALIDATION_EVIDENCE.md`.
