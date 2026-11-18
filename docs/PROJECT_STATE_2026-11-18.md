# Project state — 2026-11-18

Snapshot after the PR #48 / #39 recovery sprint. It is the authoritative starting point for the next sprint and supersedes
nothing else: it is dated, and older state documents (`current_state.md`, `STAGE2_PROGRESS.md`) are not edited.

## 1. Main branch

- `origin/main` = `6ef7600` (squash of #39, 2026-11-18). Before it: `2ee3ef9` (merge of #48) and `39c9e8d` (#52, the
  audit fixes for #48).
- CI on `6ef7600`:
  - `ci-frontend` passed.
  - `ci-python` failed once: 1 failed, 1764 passed, 68 skipped. The failing test was
    `tests/unit/test_radio_hub.py::test_downlink_broadcast_to_gcs_and_observers`, which asserts the per-client
    `tx_bytes` counter immediately after the bytes arrive, a timing race. The same tree passed CI three times on the
    #39 branch. A re-run was requested; see the Actions tab for the result.
- The main ruleset (`Claude Automation`, id 27404843) is active:
  - 1 approval; stale reviews are dismissed.
  - All review threads must be resolved; squash merges only; linear history.
  - No force pushes, no deletion.
  - Required checks `ci-python` and `ci-frontend`.
  - **`require_last_push_approval` was turned off on 2026-11-18 at the maintainer's request (only that field).**
- Merge automation: `AEGIS_AUTOMERGE=on`, `AEGIS_AUTOREMEDIATE=on`. Escalated PRs (security, vehicle link, frozen
  contracts, detector metrics, evidence, large diffs) are never auto-merged; a human approves and merges.
- Stage-1 regression baseline: TP/FP/TN/FN **6535 / 4 / 16826 / 65**. It was reproduced on the combined tree, and all
  378 per-session cells are equal.
- Local maintainer checkout (`D:/Ardra/techfest-2026/aegisflight`): `main` at `f9945a7`, 11 commits behind origin, with
  uncommitted Stage-2 readiness work. Preserve it; do not reset it.

## 2. Recently merged

| PR | Outcome |
|---|---|
| #48 (+#52) | Stage-2 metrics from committed artifacts (`artifacts/validation/stage2_metrics_2026-11-17/`). Single-attack no-grace count corrected 54 → 53 (engine raw tick time). `live_run_001` is excluded as superseded. Every row carries its own source's claim class. The maintainer signed off the definitions: rates are per hour of scored decision time; one-sided Poisson and two-sided Wilson; the headline macro-F1 includes BENIGN (attack-only also reported); multiclass and binary accuracy are kept distinct. Not flight validation. |
| #39 (+#53) | Management channel, performance work, signed-downlink fixes, vehicle uplink filter (proposal, off by default), BENCH evidence docs. Security fixes: timestamp poisoning, fake-signed HEARTBEAT blinding, GCS-side vehicle-sysid frames, management replay state required and fail-closed, no key bytes in errors. The golden guard is host-independent by default. Real-hardware attack and injection tooling was removed (AGENTS.md §5; it is kept in history at `c9816ff`). The squash message kept the old AI trailer lines; they were not rewritten. |
| #40, #41, #43, #47 | Loopback-test determinism; merge App live test; pytest count hint; remediation bubblewrap. |

## 3. Open PRs (current sprint: #51, then #50)

| PR | Branch | Issue | Note |
|---|---|---|---|
| #51 | `fix/16-gps-sats-unknown` | #16 | Treat `GPS_RAW_INT.satellites_visible = 255` as unknown. **First.** |
| #50 | `chore/25-evidence-provenance` | #25 | Evidence provenance guard, run manifest, bridge raw-log archive, campaign runner. **Second.** |

## 4. Open issues (32)

Milestone **code freeze, 27 Nov**:

| # | Prio | Topic | Depends on |
|---|---|---|---|
| 5 | P0 | Epic: repository baseline, CI, credibility | — |
| 6 | P0 | Epic: detection correctness / false alarms on real links | — |
| 7 | P0 | Epic: security detection (ground-visible injection, firmware identity, tamper) | — |
| 10 | P0 | Land the 3–6 Nov readiness work; remove unsupported numbers | — |
| 14 | P0 | Sequence-gap rule counts reordered frames as loss (frozen contract) | — |
| 15 | P0 | Start-up false alarms (never-acquired GNSS as DoS, first-sample physics) | — |
| 17 | P0 | Design spike: ground IDS copy of the GCS uplink | — |
| 18 | P0 | Detect command injection by its effect | — |
| 11 | P1 | Reproducible model from a clean clone | — |
| 13 | P1 | CI, branch protection, templates, CODEOWNERS, CLAUDE.md | #10 |
| 16 | P1 | `satellites_visible = 255` as unknown (**PR #51**) | — |
| 19 | P1 | Signing: bootstrap transient, unsigned-frame rule | #15 |
| 23 | P1 | Dashboard wording, remove defense-panel overclaims | #10 |
| 24 | P1 | SITL proxy: telemetry manipulation, firmware identity, restricted visibility | — |
| 25 | P1 | Evidence tooling (**PR #50**) | — |
| 20 | P2 | Firmware identity allowlist | #17 |
| 21 | P2 | Hash chain external anchor (frozen contract) | — |
| 22 | P2 | Link-level attack attribution | #14, #15 |

Milestone **submission, 2 Dec**:

| # | Prio | Topic | Depends on |
|---|---|---|---|
| 4 | P0 | Delivery tracker | — |
| 8 | P0 | Epic: evidence on the final commit | — |
| 9 | P0 | Epic: report and submission package | — |
| 26 | P0 | Final-commit SITL campaign, PX4 + ArduPilot, n = 10 | #19 |
| 27 | P0 | Real-data replays, link-stress sweep, benchmark regeneration on the freeze commit | — |
| 29 | P0 | Outdoor receive-only walk / range test (hardware, human) | — |
| 31 | P0 | Report source under version control; reconcile every number | — |
| 33 | P0 | Demonstration video (human) | #23 |
| 34 | P0 | Assemble and verify the submission package (human) | #12 (closed) |
| 30 | P1 | Companion-computer compute: paced replay, 10-min Pi-class run | — |
| 32 | P1 | Report: missing template content | #27 |
| 35 | P3 | Documentation truth pass | — |

No milestone: #44 (P3, temporary smoke test, in review) and #49 (in-flight false alerts per hour, steady DOS on
ArduPilot SITL; needs human approval).

## 5. Security limitations and safety constraints

- **Open:** a replay of a genuine signed recording on the vehicle side, or after an analyser restart, can mark an unsigned
  vehicle as signing and blind the detectors for the replay + 10 s. A keyed `socket://` active-ips variant can drop
  telemetry before the GCS. Complete replay protection is not claimed (`docs/THREAT_MODEL.md`).
- **Accepted (X1):** `_down_forged` is fail-closed; suspicious downlink traffic can drop legitimate telemetry
  (`docs/INLINE_IPS.md`).
- **Accepted (X4):** a 20 s boot-quiet window. GPS-spoofing and flood warnings are withheld while disarmed, and full
  coverage is not guaranteed in that window.
- **Constraints:**
  - Vehicle uplink filter: proposal only, off by default, never activated on physical hardware.
  - Component 191 is the bridge's identity. Do not run another compid-191 component using `MAV_CMD_USER_1` behind
    it (`docs/MGMT_CHANNEL.md`).
- **P3:**
  - A control-message flood can starve the status vector.
  - `mgmt_radio.py` and `pi_soak.py` default to a public test key.
  - `--control-token-file` errors can quote one token byte (pre-existing).
  - Flaky tests: `test_radio_hub` (above) and the `test_signing_gate` posture/CORS tests (WinError 10053).
- **Safety rules:**
  - A physical Pixhawk is receive-only: never arm it, change its mode or parameters, transmit to it, or inject into it.
  - Attack testing happens only in SITL, simulation or offline replay.
  - Real-radio and Pixhawk results are BENCH evidence, never flight validation.

## 6. Deadlines

- **27 Nov 2026: code freeze.**
- **2 Dec 2026: submission.**

## 7. Preserve (do not delete)

- **Stashes:**
  - `stash@{1}`: "GPS work preserved before Stage 2 integration" (maintainer work).
  - `stash@{0}`: sprint leftover `966fd76`; its content is fully committed.
- **Backup refs:** `refs/backup/sprint-20261118/worktree-main` and `refs/backup/wip-20261031`.
- **Backup branches:** `backup/*`, including `backup/sprint-20261118-*` and `backup/pre-trailer-strip`.
- **Sprint branches, local:**
  - `sprint/48-audit-fixes`, `sprint/39-security-fixes`, `sprint/39-tests-docs`, `sprint/39-final`,
    `sprint/39-finalize`;
  - `integration/sprint-20261118`, `integration/sprint-v2`;
  - `scratch/int04-*`.
  - `sprint/48-audit-fixes` and `sprint/39-final` are also on origin.
- **Other local branches:** `integration/stage2-defense-candidate`, `safety/iter2-wip-2026-10-26`, and the issue
  branches for #13, #42, #44 and #46.
- **Worktrees:** the sprint worktrees under the Claude scratchpad, plus older session worktrees (`wt_head`,
  `wt_integration`, `wt-infra`, `wt39`, `wt40`, `wtboth`, `wt-42`, `wt-44`, `wt-46`, `wt-auto`, `wt-smoke`).
  They hold no unique uncommitted work known to this sprint, but none were removed.
- **Sprint records:** agent reports and exploit PoCs are under the 2026-11-18 session scratchpad (`reports/`,
  `sec_poc/`), outside the repository.
