# Demo evidence and on-camera limitations (issue #33)

Preparation only. **Nothing listed in §2 has been captured yet**: every item is "to be captured at recording
time". No screenshot, log or number has been produced for this folder. Script: `DEMO_SCRIPT.md`.

## 1. Where `bytes_sent = 0` comes from (verified on `main` at `389fc02`)

The value shown in segment 1 is a **software counter** in the serial transport, not a wire measurement.

| Step | Code |
|---|---|
| Counter starts at 0 | `src/aegisflight/sources/mavlink_serial.py:484` (`self.bytes_sent = 0`) |
| The only increment is inside `send()`, after a successful write | `src/aegisflight/sources/mavlink_serial.py:614-627` |
| Exposed in the transport's `stats` | `src/aegisflight/sources/mavlink_serial.py:534`, `:553` |
| The dashboard feed keeps `bytes_sent` and `write_errors` | `src/aegisflight/backend/sources.py:304-311` |
| Put into the link status as `link.transport` | `src/aegisflight/backend/engine.py:693-712` |
| Returned by `GET /api/status` (and each WebSocket update) | `src/aegisflight/backend/app.py:159-161`, `src/aegisflight/backend/engine.py:1036`, `:1067` |
| Nothing is sent on an OS serial device | `transmit_allowed` false: `src/aegisflight/backend/sources.py:100-104` with `may_reach_vehicle`, `src/aegisflight/sources/mavlink_serial.py:337-342`; `_transmit` returns early: `src/aegisflight/backend/engine.py:491-500`; `active-ips` refused at start-up: `src/aegisflight/backend/sources.py:72-74` |
| Headless runner: run fails with exit 3 if non-zero; written to `summary.json` as `passive_check` | `scripts/hardware/run_serial_ids.py:237-240`, `:259-260` |
| Tests | `tests/integration/test_app_live_source.py:582-592` (status `bytes_sent == 0` and the device received 0 bytes), `tests/unit/test_run_serial_ids.py:95`, `tests/unit/test_serial_raw_tap.py:226-232` |

The three test files above were run on this branch's base: 68 passed, 5 skipped (PTY tests skip on Windows).

**The dashboard does not display this counter.** The source bar (`linkView`, `frontend/src/lib/source.ts:118-170`) shows link
state and frame count only. The text "0 BYTES SENT (Strict Passive IDS)" in the defense panel
(`frontend/src/components/DefensePanel.tsx:338-349`) is a fixed label shown whenever the posture is passive. So
the script reads the measured counter from `/api/status` in a terminal. Issue #33 asks for the source bar to show
"0 bytes sent"; that is not possible on `main` without a frontend change (reported, not changed here).

Rehearsed on `main` at `389fc02` without hardware (loopback virtual serial port replaying a local capture, badge
`REPLAY`): `/api/status` returned `bytes_sent 0`, `write_errors 0`, `frames_received` > 0. Not recorded, not
evidence.

## 2. Evidence to capture at recording time

All rows: **to be captured at recording time**. None exists yet.

| # | What | What it must show | Produced by |
|---|---|---|---|
| E1 | Commit and PX4 version text | `git rev-parse HEAD`; PX4 `git describe` | checklist §1, §4 |
| E2 | Test counts | pass/skip counts actually obtained | `.venv\Scripts\python.exe -m pytest -p no:cacheprovider` |
| E3 | Screenshot `dashboard_BENCH_demo.png` | badge `BENCH`, source "Physical bench (live serial)", link "Live", posture `PASSIVE`, armed `NO` | `aegis serve --source serial ...` (script segment 1) |
| E4 | Terminal capture (text) | `bytes_sent 0`, `write_errors 0`, `frames_received` > 0 | `Invoke-RestMethod .../api/status` (segment 1) |
| E5 | Bench database | the run's alerts, hash-chained (git-ignored, keep locally) | `--db <scratch>\bench_demo.sqlite` |
| E6 | SITL drift trial files | `manifest.json` (environment `SITL`, claim class, `provenance.px4_git_describe`), `frames.jsonl`, `ids_decisions.jsonl`, console JSON | `scripts/sitl/run_p2_trial.py --seed 1001 --trial-index 0 --seconds 90 --out ...` |
| E7 | SITL injection trial files | manifest (`frames_injected`, ack result, claim class), `ids_decisions.jsonl` | `scripts/sitl/run_p2_injection_trial.py --seed 2001 --trial-index 0 --seconds 100 --out ...` |
| E8 | `verify-log` text, bench db | `events: N  chain: OK` | `aegis verify-log <scratch>\bench_demo.sqlite` |
| E9 | `verify-log` text, SIM db, before and after tamper | `chain: OK`, then `chain: BROKEN ... event id=...`, exit 2 | segment 4 commands |
| E10 | Video file | name, length, format, SHA-256, size within the organisers' limit | `Get-FileHash -Algorithm SHA256` |
| E11 | PX4 tree check | empty output | checklist §4 |

The E6/E7 files contain no coordinates in the lines shown on screen, but `frames.jsonl` does hold positions:
keep the trial folders outside the repository unless a later decision adds them as evidence through the
validation owner.

Committed artifacts that the narration refers to (reference results, **not** the recording):

| Claim in narration | Environment / claim class | Artifact |
|---|---|---|
| Drift on the SITL downlink was flagged in committed trials, at or after the drift window closed | SITL / link-level detection | `artifacts/sitl/closure/final_drift_summary.md`, `artifacts/sitl/P2_summary.md` |
| Forged disarm from a rogue sysid: acked by PX4 and flagged by the IDS | SITL / command-path effect + link-level detection | `artifacts/sitl/closure/final_injection_summary.md`, `artifacts/sitl/P2_injection_summary.md` |
| Forgery with the expected GCS identity: acked, not detected | SITL / command-path effect; detection 0/10 | `artifacts/sitl/P2_gcs_impersonation_summary.md` |
| MAVLink-2 signing rejected the same forgery | SITL / command-path effect | `artifacts/sitl/P4_signing_summary.md` |
| Replayed legitimate commands not detected | SIM | `artifacts/validation/submission_rerun_20261029/` |
| Slow GPS drift missed (rules and physics, ML off) | SIM | `artifacts/validation/submission_rerun_20261029/gps_drift_sweep_ml_off/` |
| Bench board receive-only runs | BENCH / ingestion only | `artifacts/hardware/serial_ids_com7_001/`, `artifacts/hardware/serial_ids_com7_002/`, `docs/HARDWARE_BENCH_PIXHAWK6X.md` |

## 3. Limitations that must be disclosed on camera

Each segment's title card names its environment tag and claim class. In addition, say:

- **Environment tags.** `BENCH` (physical autopilot on a desk), `SITL` (PX4 software on this laptop), `SIM`
  (in-process simulator). Nothing in the video is `HITL` or `FIELD`. `REPLAY` appears only if the bench fallback
  is used, and is then said aloud.
- **No flight.** The bench board is disarmed with propellers off; SITL is software. No physical flight deviation is
  claimed.
- **No attack on real hardware, no real RF.** Both attacks run on the local SITL link through a relay on this
  laptop. Nothing is transmitted to the bench board.
- **No hardware validation of detection.** The bench segment shows receive-only ingestion, not detection of an
  attack on a real vehicle. The bench board runs ArduPilot; the SITL is PX4: different stacks.
- **`bytes_sent = 0` is a software counter**, not a wire measurement.
- **Drift segment is link-level detection only.** PX4 never receives a modified frame; this is not GPS spoofing of
  the vehicle or its estimator. In the committed trials the alert fired when the position jumped back, at or after
  the drift window closed.
- **Injection segment.** The command-path effect (PX4 acked) and detection are separate results. The IDS saw the
  command only because the harness mirrors the uplink to it; a deployed ground monitor normally sees the downlink
  only (the uplink-copy design spike #17 ended no-go). The harness's own client identities also trigger the
  unexpected-source rule (`artifacts/sitl/P2_injection_summary.md`, "Known experimental artifact"). A vehicle on
  the ground was disarmed, so "accepted" is acceptance, not a state change.
- **Known gaps.** Replayed or forged commands carrying the real ground station's identity are not detected without
  MAVLink signing; slow GPS drift is missed; status messages are unauthenticated; small sample counts (n = 3 to 10
  per scenario in the committed SITL summaries).
- **Log integrity.** The hash chain detects an edited or deleted-from-the-middle alert. It is not signed and not
  externally anchored: deleting the newest alerts or a whole run is not detected (rehearsed: deleting the last row
  of a scratch log still verified OK), and someone in control of the machine could rewrite it all.
- **Defense layer not demonstrated.** No prevention is shown or claimed; do not click or narrate ACTIVE IPS.

## 4. Status of related issues (as found on 2026-11-20)

| Issue | State | Demo decision |
|---|---|---|
| #21 external chain anchor | **Open.** Its PR #66 was closed unmerged (superseded by open PR #76); anchors also appear in open PR #79. `aegis verify-log` on `main` has no `--anchors` option (`src/aegisflight/cli/main.py:397-404`, `:558-560`). | **Not shown: #21 not implemented/verified on `main`.** |
| #24 SITL proxy scenarios | **Open.** Item 3 (restricted-visibility injection) descoped on 18 Nov after the #17 no-go; it becomes a report disclosure (#31). | Restricted-visibility **not shown**. The forged-command scenario (`run_p2_injection_trial.py`) is used instead, as #33 allows. |
| #23 dashboard wording | Closed (`389fc02` on `main`). | Prerequisite met for the freeze build. |
| #17 uplink copy | Closed (no-go). | Disclosed in segment 3. |
