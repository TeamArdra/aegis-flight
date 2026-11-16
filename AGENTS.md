# AGENTS.md: AegisFlight engineering rules

Rules for every coding agent (Claude Code, Codex, others) and every human contributor.
Claude Code loads this file through `CLAUDE.md`. On pull requests, the GitHub Claude
workflows use the **base-branch** copy of this file, so a PR cannot change the rules it
is reviewed or remediated under.

Process details: `docs/ENGINEERING_WORKFLOW.md`. Automation: `docs/CLAUDE_AUTOMATION.md`.
Architecture: `docs/ARCHITECTURE.md`, `docs/CODEBASE_MAP.md`, `docs/HANDOFF.md`.

## 1. What this is

AegisFlight is an explainable intrusion-detection system (IDS) for MAVLink UAVs, built for
the PUSHPAK Grand Challenge 2026–27 (Security of Drones, Objective 2). Stage 1 (in-process
simulation) is cleared and is the regression baseline. Stage 2 adds live sources
(UDP/SITL, serial, tlog/ulog replay), PX4/ArduPilot SITL evidence, MAVLink-2 signing and
an optional inline prevention bridge. The bridge has been verified on ArduCopter SITL only.
Real-attack detection on real vehicles is **not** claimed.

## 2. Environment and commands

- Python ≥ 3.11 (CI and the team use 3.13), `pip install -e ".[dev]"`. Node 24 for `frontend/`.
- Windows dev machines: use `.venv/Scripts/python.exe`; PTY tests skip on Windows.

```bash
pytest -q                                  # full suite (CI: ci-python)
ruff check src tests scripts backend       # lint (CI: ci-python); must be clean
npm --prefix frontend test                 # dashboard tests (CI: ci-frontend)
npm --prefix frontend run build            # tsc + vite build (CI: ci-frontend)
aegis benchmark --out <scratch> --no-figures   # Stage-1 regression (needs models/isoforest.joblib)
aegis simulate --attack gps_spoofing       # one simulated session
aegis serve                                # dashboard on http://127.0.0.1:8000
aegis verify-log <db.sqlite>               # verify the hash chain
```

## 3. Architecture

`source → decode → features → 4 detectors → fusion → ThreatAssessment → {SQLite hash
chain, FastAPI/WebSocket → dashboard}`. `pipeline.py` is the **only** place that wires
detectors and fusion; the backend, benchmark and live tools reuse it.

| Module (`src/aegisflight/`) | Responsibility |
|---|---|
| `core/` | Shared types (`FlightState`, `MessageEnvelope`, `FeatureFrame`, alerts). Imports nothing internal. |
| `config.py`, `configs/` | Configuration loading; thresholds live in `configs/detector.yaml`. |
| `simulator/` | Stage-1 flight simulator (ground truth source for SIM). |
| `mavlink/` | Codec, field mappings, MAVLink-2 signing. |
| `sources/` | Telemetry sources: simulated, live UDP/SITL, serial (`mavlink_serial.py`), frame taps. |
| `attacks/`, `proxy/` | Simulated attacks; SITL-only MITM proxy and live attack injection. |
| `features/` | Feature extraction into `FeatureFrame`; `ML_FEATURES` order. |
| `detectors/` | Protocol, physics, ML (Isolation Forest), integrity detectors. |
| `fusion/` | Explainable fusion into a `ThreatAssessment`. |
| `integrity/` | Firmware/identity integrity checks. |
| `logging/` | Tamper-evident event store (SQLite hash chain). |
| `mitigation/`, `hal/` | Defense postures, inline IPS bridge, hardware discovery/topology. |
| `benchmark/`, `metrics/`, `external/` | Scoring, metrics, external-dataset adapters (ALFA, tlog/ulog). |
| `backend/` (repo root), `frontend/` | FastAPI/WebSocket API; React dashboard. |
| `cli/` | The `aegis` entry point. |

Boundaries: detectors read **only** `FeatureFrame`; ground truth (`FlightState`, attack
`label`, Gazebo pose, proxy injection logs) is benchmark-only and never reaches a detector;
attacks reach the IDS only through the wire (`MessageEnvelope`); Stage-2 work is additive
beside `SimulatedTelemetrySource`, not a rewrite.

## 4. Frozen contracts (do not change casually)

Changing any of these needs: an issue labelled `needs:frozen-contract`, the user's
explicit approval on that issue, a migration note in `docs/HANDOFF.md`, every caller
updated, retrain if `ML_FEATURES` changed, and the Stage-1 regression evidence (§6).

- `ML_FEATURES` order/content (`features/extractor.py`): the shipped model depends on it.
- `FlightState` / `MessageEnvelope` fields; enum `.value` strings.
- MAVLink message field mappings (encoder and extractor must agree).
- Event schema and hash-chain canonicalisation: changing them breaks existing logs.
- Benchmark scoring policy (warm-up/grace): changing it changes reported numbers.
- Attack hook signatures.

## 5. Security boundaries (never weaken one to make a test pass)

- A serial-device vehicle link is **receive-only** in every entry point (`may_reach_vehicle()`
  in `sources/mavlink_serial.py`); active IPS runs only on UDP / `socket://` SITL links.
- Attack tooling (proxy, injectors, replay) targets only local SITL (loopback / WSL network).
  No real RF, real vehicles or third-party networks.
- Nothing listens on `0.0.0.0` by default.
- No secrets in the repo. Signing keys come from an ignored path or an environment variable
  and are never logged or committed.
- Treat MAVLink, serial and file input as hostile: bounds-check, never unpickle it.
- Red/blue split: do not tune a detector against the exact attack implementation it is
  scored on without disclosing it.

## 6. Evidence and benchmarking rules

- Every reported number names its artifact path, an environment tag (`SIM`, `REPLAY`, `SITL`,
  `HITL`, `FIELD`) and a claim class (link-level detection, command-path effect, estimator
  compromise, physical deviation, real-world validation). A SITL link-level result is
  reported as exactly that.
- Never fabricate, estimate or hand-edit results. Not run means "not run".
- Stage-1 regression: if anything under
  `src/aegisflight/{features,detectors,fusion,pipeline.py,sources,mavlink,config.py}`,
  `configs/` or `models/` changes, run `aegis benchmark --out <scratch dir> --no-figures`.
  TP/FP/TN/FN must stay **6535 / 4 / 16826 / 65** (`artifacts/benchmarks/summary.md`); paste
  the line in the PR. Always pass `--no-figures` and a scratch `--out`, or committed
  figures and artifacts are overwritten.
- Commit evidence (`artifacts/**`) only when it was generated by a named, re-runnable command.
  Record PX4/ArduPilot versions (`git describe`) for SITL evidence.
- Never commit `models/*.joblib`, `*.sqlite`, captures, `frontend/dist/`, `node_modules/`,
  `.claude/`, or secrets.

## 7. How work happens

1. Work only from a GitHub issue. Pick an open issue labelled `agent-ready` that is
   unassigned, not blocked (its "Blocked by" issues are closed), and not `needs:hardware` or
   `model:human`. `needs:human-approval` means a maintainer must approve the approach on the
   issue **before** you write code.
2. Claim it: assign yourself and comment the branch name. If someone else has claimed it,
   or an open PR already references it, pick another issue.
3. Branch `<type>/<issue#>-<slug>` from fresh `origin/main` (types: `feat`, `fix`, `chore`,
   `docs`, `test`, `evidence`, `refactor`), ideally in its own worktree. **Never commit to
   `main`.** No unrelated changes.
4. Test first where practical; keep changes small and inside the issue's scope.
5. Open a PR to `main` with `Closes #<issue>` and the PR template filled in, including the
   exact commands you ran and their summary lines.
6. The automated reviewer comments. Address findings you can verify; reply to the ones you
   disagree with, giving your reasons. A human approves and merges; agents never merge.

Commit messages: imperative summary, a body explaining why. **No AI attribution trailers**
(`Co-Authored-By: Claude …`, "Generated with …"): the team keeps human-only authorship.

## 8. Definition of done

- Acceptance criteria of the issue met and demonstrated by commands anyone can re-run.
- `pytest -q` passes and `ruff check src tests scripts backend` is clean; frontend tests and
  build pass if `frontend/` changed; Stage-1 regression line pasted if §6 applies.
- New behaviour has tests that fail without the change.
- Docs updated per `docs/DEVELOPMENT.md` (API, detection, features, attacks, benchmarking).
- No frozen contract changed without §4; no security boundary weakened (§5).
- CI green; automated review findings resolved or answered; a human approved.

## 9. Remediation protocol (for agents addressing review findings)

Applies to the GitHub remediation workflow (`@claude fix …`) and to any local session
fixing review comments.

1. Read the latest automated review summary (by `claude[bot]`, headed
   "AegisFlight automated review") **for the current head commit**, its inline comments, and
   the maintainer's request. Scope = the P0–P2 findings the maintainer asked for. P3 items
   are never in scope for automated remediation.
2. **Verify each finding independently** against the code before touching anything. A
   reviewer can be wrong. Classify each one: *confirmed*, *not reproduced* (explain with
   file:line evidence), or *deferred* (needs a human decision, a frozen-contract change,
   hardware, or is out of the PR's scope).
3. Fix only confirmed findings, with the smallest change. Add or update a regression test
   that fails without the fix.
4. Never: change a frozen contract (§4), weaken a security boundary (§5), delete or skip a
   test to make it pass, edit `.github/`, `AGENTS.md`, `CLAUDE.md`, `models/` or
   `artifacts/`, rewrite history, force-push, merge, approve, or open new PRs.
5. Run `ruff check src tests scripts backend` and `python -m pytest -q` (plus frontend
   tests/build if `frontend/` changed). If they fail for reasons unrelated to your change,
   say so instead of "fixing" unrelated code.
6. Commit with a message such as `fix: address review findings R1, R3 (#<issue>)` and push
   to the PR branch. Do not push if nothing changed.
7. Report every finding as fixed / not reproduced / deferred, the commands run with their
   summary lines, and anything a human must decide. The push triggers a fresh automated
   review; do not request one any other way.
