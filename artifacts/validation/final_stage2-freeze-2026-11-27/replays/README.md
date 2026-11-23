# Replays on the freeze tag (issue #27 item 3)

**Environment:** `REPLAY` (recorded telemetry replayed through the unchanged pipeline). Bench captures are `REPLAY of BENCH`; the ArduCopter and PX4 tlogs are `REPLAY of SITL`; ALFA and PX4 Flight Review are public real-flight logs.
**Claim class:** none. Every number here is a **false-alarm / behaviour reference on benign or fault-only data**. No attack data is replayed, so nothing here is attack detection, and ALFA fault periods are physical faults, not attacks.
**Code:** tag `stage2-freeze-2026-11-27` = `8e5800381c4abddc970cbf134d1e95e035a3becf`, clean tree for every run (`working_tree_dirty: false`).
**Models:** `models/isoforest.joblib` sha256 `3fe74cddf3689e169610ffd783b109b6539cc6c03629bd1e4bb8b1d3842939c4` (used for every "ML on" replay); `models/isoforest_px4.joblib` sha256 `df540999dc6b43c3981d6ac6ecb91369b56ce1ba8cfdb894b76b195951260c7c` (present and verified against `models/MODELS.sha256`, **not used** here). Both were copied from the reference checkout; nothing was trained.
**Profile:** the default live profile (`configs/`, sha256 `ff7ed01a…7bf4`). Not the PX4 or ArduPilot calibrated profiles: the PX4-profile held-out evaluation is #27 item 4 (`heldout/`, another branch), and the sweep covers the calibrated profiles on `SIM` (`../sweep/`).
**Toolchain:** Python 3.13.15, scikit-learn 1.9.1, numpy 2.5.3, pymavlink 2.4.50, scipy 1.18.1 (full lists in the provenance files). The PX4 ULog replay also needed `pyulog` 1.3.0, which is not in the repository venv (declared extra `.[external]`); it was installed with `pip install --no-deps --target <scratch dir>` and put on `PYTHONPATH`, leaving the venv unchanged.

## 1. Data: where it is, and how it was verified

* **No raw log is committed.** `data/external/raw/`, `data/hardware/raw/`, `data/ardupilot/raw/` and `data/sitl/raw/*.tlog` are git-ignored. This folder holds results, manifests-by-hash and hashes only.
* **ALFA and PX4 Flight Review were already on this host** (downloaded 2026-09-23 by `scripts/fetch_external_data.py`, per `retrieved_utc` in `data/external/manifests/`). They were **not downloaded again**: re-running the fetch script would overwrite the committed manifests with new timestamps. Instead `verify_data.py` checked every file against the committed manifests. Result (`data_verification.json`): `alfa.json` 3 of 3 files, `px4_review_v1.json` 40 of 40, `px4_review_v2.json` 40 of 40 match on existence, byte size and SHA-256. All 41 extracted ALFA `flight.tlog` files are byte-identical to the members of the verified `telemetry.zip` (41 of 41). `data_sha256.csv` lists the SHA-256 of every ALFA tlog and every ULog. (The brief said "about 3.1 GB" and "24 logs": the 80 ULogs on disk (protocol v1 and v2 manifests, 40 each) total 1.2 GB; 24 of the 40 v2 logs are usable under the primary mapping, see E1.)
* Files copied here from tool output are byte for byte what the tools wrote, except for the path redaction described in `../README.md` section 10 and the fact that git normalised CRLF line endings to LF on commit (the Windows tools write CRLF).
* Downloaded files were only read through the repository's replay/adapter tools (`tlog_adapter`, `ulog_adapter`).
* `replay_table.csv` carries the byte size and SHA-256 of every replayed log (ALFA by its path inside the archive).
* Local captures present on this host and replayed: bench captures **005, 006, 007, 008, 009**, the **2026-10-28 run** (`gps_hw_verify_20261029.tlog`, sha256 `c2e3459b…`, matches `docs/SUBMISSION_ARCHIVE_MANIFEST.md`), the **5 ArduCopter benign tlogs** (`ap_benign_six_001..004`, `ap_benign_groups_001`; the `.clean.tlog` is byte-identical to the `.observed.tlog` for all five), and the 10 PX4 SITL benign tlogs (`benign_001..010`, an addition).
* **Not available:** the **#29 walk and range captures do not exist yet** (`replay_missing.json` lists no other missing path). Captures 001, 003 and 004 are empty files and were not part of the requested set.

## 2. Commands (all from the repository root, tag checked out, `PYTHONPATH` = `src;scripts`)

```
python artifacts/validation/final_stage2-freeze-2026-11-27/replays/verify_data.py --out <dir>
# bench captures, 28 Oct run, ArduCopter benign (tool JSON in local/)
python -W ignore scripts/ardupilot/replay_ap_tlog.py <tlog> --no-ml --json <out>.ml_off.json   # ML off
python -W ignore scripts/ardupilot/replay_ap_tlog.py <tlog> --json <out>.ml_on.json             # ML on
# PX4 SITL benign (10 tlogs per call)
python -W ignore scripts/sitl/replay_benign.py data/sitl/raw/benign_0*.tlog --no-ml --out local/px4_sitl_benign.ml_off.json
python -W ignore scripts/sitl/replay_benign.py data/sitl/raw/benign_0*.tlog --out local/px4_sitl_benign.ml_on.json
# ALFA E2 (ML on) and E2b (ML off, per-vehicle rate thresholds), PX4 Flight Review E1 (external/)
python scripts/external_validation.py --alfa --workers 2 --out <dir>
python scripts/external_validation.py --px4 --px4-protocol v2 --workers 2 --out <dir>
# events/hour, exposure, dominant evidence per log (this folder's own script, see section 3)
python -W ignore artifacts/validation/final_stage2-freeze-2026-11-27/replays/replay_exposure.py --out <dir> --workers 3 \
    --e2b-results artifacts/validation/final_stage2-freeze-2026-11-27/replays/external/alfa_calibrated/results.json
```

`<tlog>` is `data/hardware/raw/telemetry_radio_00{5..9}.tlog`, `data/hardware/raw/gps_hw_verify_20261029.tlog`, and `data/ardupilot/raw/ap_benign_{six_001..004,groups_001}.clean.tlog`; the per-run `--json` commands are recorded verbatim in each JSON's `run_provenance.command_line` (they point at a scratch directory; the JSON files were copied here byte for byte, except the `../README.md` section 10 path redaction). `--out` was always a scratch directory outside the repository (the tool default `artifacts/external` would have overwritten committed evidence). Provenance: the `replay_ap_tlog.py` and `replay_benign.py` JSONs embed `run_provenance` (schema `aegisflight.run_manifest/1`, status `REPRODUCIBLE`); `external_validation.py` writes none, so `external/external_validation_{alfa,px4_review_v2}.provenance.json` and `replay_exposure.provenance.json` are sidecars made by `make_provenance.py` with the repository's own `collect_run_provenance` (the command lines and start times in them are stated by the operator, as the sidecar says).

## 3. Why there is a separate script

`replay_ap_tlog.py` and `replay_benign.py` report decision, threat and alert counts but not alert events per hour of exposure, and `external_validation.py` reports rates per decision, not events. `replay_exposure.py` (this folder, not `scripts/`) calls the **same replay functions** (`replay_ap_tlog.replay`, `replay_benign.replay`, `external_validation._alfa_one`) and adds only arithmetic. It does not change any tool. Cross-checks that it agrees with the tools: decisions, threat decisions and alert decisions equal the tool JSON for all 22 (log, ML) bench / 28 Oct / ArduCopter cells; PX4 SITL pooled 5565 decisions and 5565 false alarms equal the `replay_benign.py` pooled figure in both ML modes; the ALFA totals after de-duplication equal the tool's headline (E2 137,926 decisions, 7.66 h; E2b 83,577 decisions, 4.64 h, benign 0.15 %, fault 0.73 %, unlabelled 6.28 %). Two runs with different worker counts gave identical values in every column they share.

Definitions: *decision* = one 5 Hz fusion decision; *threat decision* = `threat == True`; *alert decision* = the pipeline's `is_alert` flag (only the `replay_ap_tlog` runs carry it); *alert event* = a maximal run of consecutive threat decisions in one stream (same definition as the sweep); *exposure* = decisions x 0.2 s; *events/h* = alert events / exposure hours; *dominant evidence* = the most frequent normalised evidence string over threat decisions, once per decision, digits **and hyphens** collapsed to `#` (so `message-rate spike` prints as `message#rate spike`, a quirk of the sweep tool's normaliser that was reused), `coverage...` notes ignored. For ALFA, overlapping recordings of one flight are de-duplicated exactly as the tool does (largest recording first); `decisions_before_dedup` keeps the raw count.

## 4. Results

Per-log rows, byte sizes, hashes, exposure and the top evidence strings are in `replay_table.csv` (150 rows: log x ML), `replay_evidence_counts.csv` (top 8 evidence strings per log), `replay_threat_decisions.csv.gz` (every threat decision of the non-ALFA logs with its raw evidence string) and `alfa_by_ground_truth.csv`. ML off = default config with the ML detector off; ML on = default config with `models/isoforest.joblib`.

### 4.1 Pooled by group (default profile)

| group | ML | logs | decisions | threat | alert events | exposure (h) | events/h | dominant evidence (count, summed over logs) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| bench captures 005-009 | off | 5 | 1,505 | 433 | 2 | 0.0836 | 23.9 | GNSS fix never acquired (295) |
| bench captures 005-009 | on | 5 | 1,505 | 1,424 | 5 | 0.0836 | 59.8 | ML anomaly score, driver `interarrival_jitter_ms` (1,129) |
| 28 Oct run | off | 1 | 450 | 0 | 0 | 0.0250 | 0.0 | - |
| 28 Oct run | on | 1 | 450 | 431 | 1 | 0.0250 | 40.0 | ML anomaly score, driver `interarrival_jitter_ms` (431) |
| ArduCopter benign x5 | off | 5 | 3,495 | 184 | 5 | 0.1942 | 25.8 | GNSS fix never acquired (184) |
| ArduCopter benign x5 | on | 5 | 3,495 | 3,042 | 129 | 0.1942 | 664.4 | ML anomaly score, driver `interarrival_jitter_ms` (2,227) |
| PX4 SITL benign x10 | off | 10 | 5,565 | 5,565 | 10 | 0.3092 | 32.3 | message-rate spike (5,540) |
| PX4 SITL benign x10 | on | 10 | 5,565 | 5,565 | 10 | 0.3092 | 32.3 | message-rate spike (5,540) |
| ALFA, 35 non-empty tlogs (28 contributing after de-duplication), E2 config | off | 35 | 137,926 | 137,836 | 34 | 7.6626 | 4.4 | message-rate spike (137,718) |
| ALFA, 35 non-empty tlogs (28 contributing after de-duplication), E2 config | on | 35 | 137,926 | 137,841 | 29 | 7.6626 | 3.8 | message-rate spike (137,718) |
| ALFA E2b: 21 non-empty test-date tlogs (16 contributing after de-duplication), rate thresholds calibrated per vehicle | off | 21 | 83,577 | 4,386 | 71 | 4.6432 | 15.3 | GNSS fix never acquired (4,066) |

How to read it, plainly:

* **The default profile does not fit PX4 SITL or real ALFA traffic.** PX4 SITL (~378 msg/s) and ALFA (~200 msg/s) are far above the simulator's nominal 28 msg/s, so the message-rate rule fires on essentially every decision (5565 of 5565 and 137,836 of 137,926), with ML on or off. This is the known finding (`docs/EXTERNAL_DATA.md`, `docs/CALIBRATION_PX4.md`), reproduced on the freeze tag. It is a calibration-transfer result, not a measure of a deployed profile.
* **ML off on the bench/ArduCopter links**: 0 threat decisions on capture 009, 005, 006 and the 28 Oct run; capture 007 (no GNSS receiver reported) raises 295 threat / 15 alert decisions of 300 ("GNSS fix never acquired", all `DOS`); capture 008 (fix lost) 138 threat / 8 alert of 313; the five ArduCopter runs each have 36-37 start-up threat decisions in one event ("GNSS fix never acquired", the documented start-up alerts), 25-26 events/h. These agree with the committed readiness numbers (`artifacts/validation/stage2_readiness_20261103/`: 007 295/15 of 300, 008 138/8 of 313, 009 and the 28 Oct run 0).
* **ML on raises the threat rate to 79-98 % of decisions on the ArduCopter runs and 94-96 % on bench captures 005, 006, 008, 009 and the 28 Oct run (capture 007's threat count is unchanged, 295 of 300, only because the GNSS rule already covers it; `ml_anomaly` also fires there, on 281 decisions at or above 0.5 in `local/telemetry_radio_007.ml_on.json`), with the same driver everywhere, `interarrival_jitter_ms`.** `docs/ARDUPILOT_SITL.md` reports the same driver and states the Stage-1 model does not transfer to real autopilot telemetry. Events/h depends on whether alarms are continuous: `ap_benign_six_001..004` ML-on has 26-43 events per run (669-1,114 events/h), `ap_benign_groups_001` one event, and each bench capture one continuous event (40-61 events/h).
* **E2b (ML off, calibrated rate thresholds, test dates only) is the only real-link configuration with a sub-percent benign rate:** benign periods 17 threat of 11,545 (0.15 %), 2 events, 3.1 events/h over 0.64 h; fault periods 20 of 2,755 (0.73 %); unlabelled periods 4,349 of 69,277 (6.28 %, 64 events, 16.6/h; the dominant evidence over the whole E2b set is "GNSS fix never acquired", 4,066 of 4,386 threat decisions). The sample is small (0.64 h benign) and 2 events cannot support a per-hour rate; treat 3.1/h as "not measured to better than an order of magnitude" (2 events over 0.64 h). The 0.15 % also depends on which of the overlapping recordings the tool keeps: it is 3.70 % before de-duplication (section 4.2).

### 4.2 ALFA by ground truth (author labels; fault = physical fault after onset)

| config | ground truth | decisions | threat | threat % | alert events | exposure (h) | events/h |
|---|---|---:|---:|---:|---:|---:|---:|
| E2 (ML off) | benign_gt | 17,989 | 17,989 | 100.00 | 16 | 0.999 | 16.0 |
| E2 (ML off) | fault | 3,711 | 3,711 | 100.00 | 16 | 0.206 | 77.6 |
| E2 (ML off) | unlabelled | 116,226 | 116,136 | 99.92 | 34 | 6.457 | 5.3 |
| E2 (ML on) | benign_gt | 17,989 | 17,989 | 100.00 | 16 | 0.999 | 16.0 |
| E2 (ML on) | fault | 3,711 | 3,711 | 100.00 | 16 | 0.206 | 77.6 |
| E2 (ML on) | unlabelled | 116,226 | 116,141 | 99.93 | 29 | 6.457 | 4.5 |
| E2b (ML off, calibrated) | benign_gt | 11,545 | 17 | 0.15 | 2 | 0.641 | 3.1 |
| E2b (ML off, calibrated) | fault | 2,755 | 20 | 0.73 | 6 | 0.153 | 39.2 |
| E2b (ML off, calibrated) | unlabelled | 69,277 | 4,349 | 6.28 | 64 | 3.849 | 16.6 |

The tool's E2 headline is ML on (`external/alfa/summary.md`: benign 17,989 decisions, 100.00 % fused threat). The ML-off E2 row is this folder's addition.

**Sensitivity to the tool's de-duplication (not previously stated).** ALFA ships overlapping recordings of the same flights; the tool keeps the largest recording and drops overlapping decisions (E2 56,702, E2b 51,057). In E2b the dropped decisions alarm far more than the kept ones: before de-duplication the benign_gt rate is 880 of 23,799 (3.70 %), of which the 12,254 dropped decisions carry 863 threats (7.0 %) against 0.15 % for the kept ones (`alfa_before_dedup_by_ground_truth.csv`). The headline 0.15 % therefore depends on which of the overlapping recordings is kept; the dropped recordings are not a separate flight but a second recording of the same instants. I did not investigate why they alarm more (candidates: a different GCS stream rate or a partial recording), and did not change the rule.

### 4.3 PX4 Flight Review ULogs (E1, navigation features only)

`external/px4_review_v2/summary.md`. 40 ULogs listed by manifest `px4_review_v2` (protocol v2, seed 2026, one log per vehicle UUID); **24 are usable** under the primary mapping `px4_telemetry` (15 lack `vehicle_global_position`, 1 has under 60 s airborne), 26 under the two independent-sensor mappings; 12 simulated reference flights. A ULog has no MAVLink link, so there is **no decision-level alarm stream and no alert events/hour**: the tool reports airborne tick rates only.

| mapping | usable flights | airborne hours | physics trigger rate | ML navigation probe alarm rate | dominant exceedance |
|---|---:|---:|---:|---:|---|
| `px4_telemetry` | 24 | 2.18 | 5.43 % | 7.86 % | yaw/course difference 48.01 % |
| `independent_sensors` | 26 | 2.36 | 93.42 % | 94.65 % | GPS/baro altitude difference 92.99 % |
| `independent_sensors_biascorr` | 26 | 2.36 | 28.56 % | 34.82 % | yaw/course difference 50.14 % |
| simulator reference (12 flights) | 12 | 0.35 | 0.00 % | 0.30 % | - |

The ML column is the tool's *navigation probe* (network features held at the training mean), not an ML validation. Under the PX4 semantics the GPS/VFR and GPS/baro cross-checks cannot fire (same estimator); the physics alarms are dominated by the heading-vs-course rule on multirotors.

### 4.4 Drift against the committed `artifacts/external/` (older code)

The freeze tag reproduces the committed ALFA and PX4 counts exactly (E2 35 tlogs, 137,926 decisions; E2b 21 tlogs, 83,577 decisions; E1 24 / 26 / 26 usable flights) but a few rates moved, consistent with extractor changes since 2026-09-23 (the committed files do not record the commit): E2 unlabelled fused threat 99.93 % (committed 99.99 %); E2b benign 0.147 % (0.156 %), fault 0.726 % (0.762 %), unlabelled 6.278 % (6.338 %); E1 `px4_telemetry` physics trigger 5.43 % (5.51 %), position-residual exceedance 0.04 % (0.15 %). The committed `artifacts/external/` was not touched. The freeze-tag numbers supersede them.

## 5. Problems met on the way (recorded, nothing tuned or patched)

1. **`external_validation.py` ALFA step died with `MemoryError`** in a worker (`tlog_adapter.segments`) with `--workers 8` while other processes held memory on this 16 GB host; my own replay script hit `OSError 1450` when returning large results at the same time. Both were re-run with 2-3 workers; the tool output does not depend on the worker count. (The first attempt's console log is not committed; there is no `logs/` directory in this folder.)
2. **First E1 attempt parsed 0 logs** (`No module named 'pyulog'`, all 40 logs "excluded" with a parse error rather than a hard stop). Discarded; the second attempt (pyulog 1.3.0) is the result.
3. **`replay_ap_tlog.py` silently ran ML-off but recorded `ml_enabled: true`.** For capture 005 with ML on, `joblib` raised `MemoryError` while loading the model under memory pressure; the tool printed "ML model requested but not loaded ... ML detector is OFF" and still wrote a JSON with `ml_enabled: true` and 0 threats. This is a **tool bug to report** (the JSON should record that ML is off); the bad JSON is kept in `local/discarded/`, and the replay was re-run (277 threat of 296, matching the same-size capture 006). That a scan of all other stdout files of the local runs found no such warning is operator-stated: those console logs are not committed.
4. The sweep and these replays share no state; the sweep (`../sweep/`) ran on a different invocation of the same clean tree.

## 6. Not run

* #29 walk and range captures (do not exist yet).
* The calibrated PX4 and ArduPilot profiles on any replay (PX4 held-out evaluation is `heldout/`; the ArduCopter calibrated-profile replay of `ap_benign_*` is documented in `artifacts/validation/inflight_fa_per_hour_20261119/` and was not regenerated here).
* ALFA replay with the ArduPilot-calibrated profile or a forced ML model.
* PX4 Flight Review protocol v1 (the documented failed protocol).
* Real attack data of any kind.

## 7. Files

| Path | What |
|---|---|
| `replay_table.csv`, `replay_evidence_counts.csv`, `replay_threat_decisions.csv.gz`, `alfa_by_ground_truth.csv`, `alfa_before_dedup_by_ground_truth.csv`, `replay_missing.json` | `replay_exposure.py` outputs |
| `replay_exposure.py`, `make_provenance.py`, `verify_data.py` | the three helper scripts of this folder |
| `replay_exposure.provenance.json`, `external/*.provenance.json` | provenance sidecars |
| `data_verification.json`, `data_sha256.csv` | dataset verification against the committed manifests; ALFA tlog and ULog hashes |
| `local/*.json` | the tools' own JSON for bench / 28 Oct / ArduCopter / PX4 SITL replays (provenance embedded); `local/discarded/` the failed capture-005 ML-on run |
| `external/alfa/`, `external/alfa_calibrated/`, `external/px4_review_v2/` | `external_validation.py` outputs (E2, E2b, E1; `feature_samples.npz`, 3.3 MB, is regenerable and not committed) |
| `logs/` | not committed: the console logs of the long runs, including the failed first attempts, stayed in the scratch directory, so statements here that rest on them are operator-stated |
