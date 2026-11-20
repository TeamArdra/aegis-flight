# AegisFlight — Third-party agent skills (policy)

> [!IMPORTANT]
> **Agents do not install skills.** AI agents working in this repository must not install, run or delete third-party
> skills or packages on their own. If a task would benefit from one, the agent says so and a person decides, reviews the
> package, installs it, and removes it afterwards. (Integration review 2026-10-27: the earlier "autonomous activation"
> protocol was removed as a supply-chain risk.)

The earlier catalogue of `npx` install commands for third-party skills was removed (issue #35): it was unrelated to the
product and invited unvetted package execution. Nothing in AegisFlight depends on any of those skills.

## Ledger

| Skill ID | Status | Last activated | Note |
|---|---|---|---|
| `security-auditor` | `REMOVED` | 2026-10-25 | Was used for the withdrawn self-assessment (`docs/REDTEAM_AUDIT_STAGE2.md`). |
