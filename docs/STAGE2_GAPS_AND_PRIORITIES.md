# Stage 2 gaps and priorities

Date 2026-11-03, on `main` `f9945a7` plus the uncommitted files in §5. Owners are "known" only where the repository or the brief says so.

The biggest gap cannot be closed in software. **The template gives flight evidence full weight and simulation limited weight
(p. 1, p. 25), and the team has no flight data and no attack on a real vehicle.** Everything else is about being complete and credible around
that fact.

## 1. P0: blocks submission or threatens integrity

| # | Gap | Owner | Blocker | Smallest next action |
|---|---|---|---|---|
| P0-1 | **No demonstration video.** Mandatory (p. 19-20) | Raj | Needs a recording | Follow `docs/STAGE2_DEMO_RUNBOOK.md` once. About 1 hour |
| P0-2 | **Indoor no-fix raises `DOS` alerts** under the default config (`REPLAY` of capture 007: 295 threat, 15 alerts of 300 decisions). Conflicts with "do not treat indoor no-fix as an attack" | Raj decides | Open policy decision since 2026-10-20 | Choose option A, B or C in `docs/STAGE2_GPS_DEGRADED_DEMO_PLAN.md` §2.3. Recommended: B for the live segment, disclosed |
| P0-3 | **Withdrawn numbers were live on the dashboard** ("Pi Zero 2W 11.4 % CPU", "₹2,900", IEEE and mIDS-UAV rows, "82.4 km", "0.4 s", "<0.08 ms Rust"), re-added by `f816f41` | Raj | Fix is uncommitted | **Review and commit** `frontend/src/components/evalPanels.tsx`. Until committed, a clean clone still shows them |
| P0-4 | **Team-only report fields:** final team targets (§3), AI verification statement (§11.1), Stage-1 evaluator questions (§2.2), commit at freeze | Team | Human knowledge | Fill the `[TEAM INPUT REQUIRED]` markers. Do not back-fit targets to results without saying so |
| P0-5 | **Integrity declaration.** The draft holds a typed name and date from the working copy. Signing states every result came from the submitted code | Team leader | Do it last | Read §11.3 after the freeze, then sign |
| P0-6 | **Archive contents.** Raw bench captures and `models/isoforest.joblib` are git-ignored, but "a link alone is not sufficient" (p. 2). **Without the model, ML is a silent no-op and the benchmark changes. `aegis train` writes a different file (sha256 `184648dc…`, not `3fe74cdd…`), and the benchmark with a retrained model did not finish (stopped for low memory, 2026-11-03), so a clean-machine train-then-benchmark is unverified** | Team | Team decision on position privacy | Include the model and the captures, or redacted copies with SHA-256. Build with `git archive` plus an explicit list: `docs/SUBMISSION_ARCHIVE_MANIFEST.md` |
| P0-7 | **The official template PDF is not in Git as a PDF.** Git holds a 23 KB text file with a `.pdf` name; the real file is an uncommitted change | Raj | -- | Commit the real PDF, or leave it out of the archive |

## 2. P1: costs marks

| # | Gap | Owner | Smallest next action |
|---|---|---|---|
| P1-1 | No fresh physical capture on this tree | Raj, at the bench | Run runbook §3 (needs your go-ahead to open the port) |
| P1-2 | **USB gives heartbeat only.** The telemetry radio is not plugged in today (only COM4 and COM5 are listed) | Raj | Connect the radio before the demo |
| P1-3 | No healthy-estimator capture on hardware: the un-gated rule has never run on real bytes | Raj | One receive-only capture with sky view, if permitted |
| P1-4 | **Inline bridge results are prose only.** `docs/INLINE_IPS.md` tables have no raw logs in the repository; it says they stayed in `C:/afsitl`, which is absent on this machine | pozo | Find those logs and commit the summaries. Otherwise keep the report's "documented, raw logs not in the archive" wording. The rubric does not credit what cannot be re-run |
| P1-5 | SITL batches last ran on 2026-10-10 code; `main` has changed since | Validation | Re-run the n = 3 smoke batches in WSL, or keep the disclosure |
| P1-6 | **Defense actions are not in the hash chain.** Only alerts are; `mitigation_actions` in `/api/events/forensic` come from memory | Lead | Say so in the demo. Persisting them is a schema change: frozen, needs approval |
| P1-14 | **The hash chain misses truncation.** Deleting the newest alerts or a whole run still verifies OK (`chain_truncation_check.txt` in the bundle). `docs/EVENT_LOGGING.md:4-5` says any deletion is detected, which is wrong | Lead | Corrected in the report. Fix that doc. A real fix needs an external head anchor, which touches the frozen event schema |
| P1-15 | `may_reach_vehicle` trusts any `socket://` host, so `active-ips` could reach a real board behind a network serial server | Lead | Disclosed in the report. Restrict to loopback: a small change, needs your go-ahead |
| P1-7 | **No outcome check after a counter-command.** Nothing reads `COMMAND_ACK` in `mitigation/` or `backend/`, and `_transmit` swallows send errors (`contextlib.suppress`) | Lead | Disclose. Fix only with a SITL re-run |
| P1-8 | No autopilot-checks baseline (p. 9, p. 11) | Validation | Needs failsafe output on attacked sessions. Keep "not done" |
| P1-9 | Install time, operator read time: not measured. Kit cost, power and mass: unknown | Team | Time them once. Price the Pi kit when it is fixed |
| P1-10 | `gps-assist/minor-adjustments` not integrated (255 satellites) | icebot90 | `docs/STAGE2_BRANCH_AUDIT.md` §3 |
| P1-11 | Licence loose ends: ALFA (CC BY 4.0 vs CC0), Tauri icon origin, `LICENSE` holder line, 391 Rust crates declared only | Team | `THIRD_PARTY_NOTICES.md` status block |
| P1-12 | Clean-machine run is older than the freeze | Validation | Re-run `clean_install.sh` on the frozen commit |
| P1-13 | Tracked `/home/astryx` and `D:\Ardra\...` paths in artifacts (about 167, counted 2026-10-29) | Team | Accept or redact copies, not the evidence |

## 3. Raspberry Pi companion computer: integration checklist

**Owner: teammate; status in this repository: nothing to integrate yet.** No branch on `origin` holds companion-computer work (the listing is in
`docs/STAGE2_BRANCH_AUDIT.md`). `hal/discovery.py` and `hal/identify.py` read the platform but have no production caller. There is no
deployment script, service unit or watchdog. **All Pi measurements below are pending; no figure exists.** The README's install steps are
instructions, not evidence. This checklist does not touch the teammate's work: please correct it where you know better.

| Area | Contract the repository expects | Status |
|---|---|---|
| Hardware and OS | Your brief says Pi with 4 GB, Raspberry Pi OS Lite 64-bit. `docs/RISK_REGISTER.md` still says "Pi Zero 2W or Pi 4" | **Pending: state the actual board and image.** Align the risk register |
| Runtime | Python ≥ 3.11; `pip install -e ".[serial]"` (numpy, scikit-learn, pandas, pymavlink, fastapi come with the core install). Tested only on 3.13 Windows and 3.12 WSL | Pending on ARM. Wheels for floor-pinned versions unchecked |
| Telemetry input | `python scripts/hardware/run_serial_ids.py --port /dev/serial0 --baud <FC baud> --out-dir <dir> --seconds <n> --no-reconnect --tlog <file>`. Pixhawk TELEM must already stream the messages | Pending. `SERIALx_BAUD` must be read, not assumed |
| Output | `events.sqlite`, `alerts.jsonl`, `health.jsonl`, `summary.json`; dashboard on 127.0.0.1 | Pending. `aegis serve` serves a non-SIM source on loopback only, so view it over an SSH tunnel |
| Command interface | **None for the monitor.** `run_serial_ids.py` and `aegis serve` never transmit on a serial device. `aegis ips-bridge` refuses `active-ips` there (`may_reach_vehicle`), but in passive or advisory it **relays the operator's frames to the FC**, so it is not receive-only | Use the monitor, not the bridge, on the vehicle. Keep the guard. Teammate commit `f816f41` undid this once; re-check after any merge (`tests/unit/test_defense_safety.py`) |
| Wiring boundary | FC TX to Pi RX and ground only. **Leave Pi TX unconnected**: that makes receive-only physical, not just a software counter | Pending. This also answers the unmeasured DTR/RTS question for a UART |
| Active defense | `aegis ips-bridge --defense-mode active-ips` works only on `socket://` SITL links. Passive and advisory bridging on a serial pair relays frames. **No hardware bypass exists: if the Pi dies the bridged link is cut** | **Do not put the bridge in a flight path** without a relay or splitter |
| Watchdog | None at process level. `hal/inline_bridge.py`'s watchdog is unused in-process code. No `systemd` unit | Pending. Monitor should restart without touching the FC |
| Failure and recovery | Transport reconnects (tested on loopback only). A dead link raises a `DOS` alert per 4 s (about 21,600 per day). No log rotation or disk cap (`docs/ONBOARD_DEPLOYMENT.md` B7) | Pending |
| Resource measurement | On the Pi: `python scripts/ardupilot/measure_replay_cost.py <tlog> --repeat 3 --json artifacts/hardware/replay_cost_<board>.json`; then `summary.json` from a live run (`cpu_pct_of_one_core_mean`, `rss_mb_max`, `decision_latency_ms`) | **Pending: every field.** Labelled "target" only when measured there |
| ML | Off on live sources. The model does not transfer. Installing scikit-learn is still required | Pending. Slim install not implemented |
| Evidence needed for the report | Board, OS, Python and package versions, commit, run command, 10-minute live run, `summary.json` committed without position data, photo of the wiring, power draw if a meter exists | Pending |

## 4. P2: tidiness and doc corrections (found, not changed)

- `docs/README.md:41` says "+ Raspberry Pi companion bench validation". False.
- `docs/INLINE_IPS.md` "Not tested against … SITL" contradicts its own later SITL sections.
- `README.md:49`, `:85` and the header diagram still say "nothing transmits on a live source" and "SIM-only" while `active-ips` runs on SITL links. `README.md:152` "100 % native cross-platform" and the Tauri badge overstate.
- `docs/ARCHITECTURE.md:114`, `docs/FILE_REFERENCE.md:192` state latency budgets per Pi model. Design figures with no measurement.
- `docs/TESTING.md` "Latest full run" is 2026-10-31; update from the bundle. Root `CLAUDE.md` and `.claude/CLAUDE.md` still mention older counts.
- `docs/DEMO_RUNBOOK.md` opens with `aegis serve --defense-mode active-ips`, has "Disarm vetoed" wording, and names `FloodMitigator`, a class that does not exist in `src/`. Use the new runbook instead.
- Dashboard: threat card says "No active threat — nominal flight" on a bench. Defense panel labels decision compute as "Detection Latency".
- `docs/stage2_report_draft.md:30,54` still says "report-only" for every live source. Submit the completed draft, not that file.
- `detectors/physics.py:201-222` duplicate CUSUM block; `PhysicsDetector.cusum` never updated.
- `CLAUDE.md` "Autonomous JIT Skills" and `docs/SKILLS_REGISTRY.md`: third-party `npx` instructions, unrelated to the product. Consider leaving them out of the archive.
- `aegis_fastpath` has no tests and no caller on the tested path. Keep it labelled prototype.
- `scripts/ardupilot/replay_ap_tlog.py` writes a hard-coded `config_dir` label in some outputs (already disclosed).

**Grep to re-run before the freeze** (should only hit audit documents):
```bash
git grep -nE "11\.4 ?%|42\.8 MB|2,900|82\.4|4\.8 h|mIDS|0\.08 ms|EKF failsafe blind|92/100|729\+" -- ':!docs/STAGE2_*' ':!docs/GPS_WORKSTREAM_PROGRESS.md' ':!docs/REDTEAM_AUDIT_STAGE2.md' ':!docs/SUBMISSION_READINESS_AUDIT.md'
```

## 5. What this audit added or changed (all uncommitted)

| Path | Why |
|---|---|
| `frontend/src/components/evalPanels.tsx` | Removed unsupported rows; corrected 3 stale lines. **The only tracked file changed** |
| `scripts/demo/make_synthetic_gps_tlog.py`, `make_stage2_report_figures.py` | Fixture, figures (the report renderer stays private under D2, see #31) |
| `tests/unit/test_synthetic_gps_demo.py` | 11 tests |
| `demo/fixtures/`, `demo/indoor_bench_profile/`, 4 files in `demo/screenshots/` | Demo inputs and evidence |
| `artifacts/validation/stage2_readiness_20261103/` | Today's evidence |
| `docs/STAGE2_*.md` | Deliverables (the completed report draft is private under D2, see #31) |

**Not changed:** detectors, features, fusion, configs, thresholds, `src/`, the template PDF, `docs/stage2_report_draft.md`, `.gitignore`. The
root `CLAUDE.md` says to add a Co-Authored-By line to commits, while the user's standing instruction is no Claude attribution: follow the user.
