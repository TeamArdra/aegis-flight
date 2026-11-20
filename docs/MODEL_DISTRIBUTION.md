# Model distribution and integrity (issue #11)

`models/*.joblib` is git-ignored and **`aegis train` does not reproduce the shipped model** (different
bytes, hence a different SHA-256). The Stage-1 headline (TP/FP/TN/FN = 6535 / 4 / 16826 / 65, SIM) uses the
ML detector, so a run without the exact model must never look like a normal run.

## What is committed

| File | Purpose |
|---|---|
| `models/MODELS.sha256` | `sha256sum`-format SHA-256 of `isoforest.joblib` and `isoforest_px4.joblib`. The hashes are the ones recorded by the committed evidence (`artifacts/ardupilot/*/manifest.json`, `artifacts/sitl/calibration/isoforest_px4_training.json`). |
| `scripts/fetch_models.py` | Download, then verify. A download is only installed when its SHA-256 matches; otherwise it is deleted and the script exits non-zero. `--verify-only` makes no network call. |
| `src/aegisflight/model_integrity.py` | Reads the manifest, hashes files, and resolves the model for the CLI. |

## Getting the models

```bash
python scripts/fetch_models.py                      # fetch + verify
python scripts/fetch_models.py --verify-only        # check files you copied in yourself
python scripts/fetch_models.py --base-url file:///path/to/dir   # a mirror / local directory
```

The default `--base-url` is a GitHub Release (`models-v1`). **That release has not been published**: it needs
the model-distribution decision (D3) first. Until then, obtain the two files from a maintainer, place them in
`models/`, and run `--verify-only`.

## Behaviour

- `aegis benchmark` / `aegis simulate` / `scripts/benchmark.py`:
  - model **missing** -> exit 2 and print `python scripts/fetch_models.py`;
  - model listed in `MODELS.sha256` but **SHA-256 differs** -> exit 2, unless `--allow-unverified-model`
    (prints a warning; use it for `aegis train` output);
  - a custom `--model` with no manifest entry runs with a note;
  - `--no-model` is the explicit ML-off opt-out (unchanged).
- `AnomalyDetector(model_path=...)`: a path that does not exist or cannot be loaded now logs a **WARNING**
  naming the path and reason, then degrades to ML off as before (live sources run ML-off by design).
  `model_path=None` stays silent: it is the explicit opt-out.
- Every `aegis benchmark` `summary.md` header and `results.json` records `model_sha256` (or `none`).

## `model_path=` callers audited for #11

| Caller | Before | Now |
|---|---|---|
| `aegis benchmark`, `scripts/benchmark.py` | missing model silently ran ML off | exit 2 with the fetch command; SHA checked; `model_sha256` in summary |
| `aegis simulate` | same | same (exit 2) |
| `benchmark.harness.run_benchmark` (library) | silent fallback to ML off | still falls back (API unchanged) but logs a WARNING; records `model_sha256` |
| `benchmark.extended.run_extended`, `scripts/benchmark_extended.py` | silent fallback | unchanged (no CLI check); `model_used` is recorded as before |
| `scripts/baseline_comparison.py` | passes the path straight to the detector | the detector now WARNs if it is missing; its own `model_sha256` field is unchanged |
| `benchmark/plots.py` (figures) | hard-coded path | the detector WARNs if missing |
| `scripts/ardupilot/replay_ap_tlog.py`, `run_ap_sitl_ids.py`, `scripts/external_validation.py`, `backend/engine.py` | `exists()` guard, silent ML off | unchanged; `ml_enabled` is in their manifests (#25) |
| `scripts/hardware/run_serial_ids.py` | already prints a WARNING | unchanged |
| `scripts/hardware/paced_replay.py`, `measure_replay_cost.py` | error / skip when missing | unchanged |
| `hal/inline_ips.py` | `model_path=None` | unchanged (ML off by design) |
| `scripts/make_golden.py` | uses the canonical model if present | unchanged |

The silent `exists()` guards that remain in the evidence scripts are a candidate follow-up, not changed here
to avoid altering evidence tooling in this PR.

## Release workflow (prepared, not active)

Publishing is manual and waits for D3 approval. When approved, a maintainer (with the real model files):

```bash
sha256sum -c models/MODELS.sha256            # run in models/ ; must say OK for both files
gh release create models-v1 models/isoforest.joblib models/isoforest_px4.joblib \
  --title "AegisFlight trained models v1" --notes "SHA-256 in models/MODELS.sha256"
python scripts/fetch_models.py               # from a fresh clone: must verify
```

Nothing in this PR publishes a release or depends on one existing; CI does not fetch models.

## Limits

- The author of this change did not have the shipped model files, so the fetch path was tested with
  `file://` fixtures only. The manifest hashes come from committed manifests; they were **not** re-verified
  against the actual files.
- Without the model the 9 model-dependent tests still skip on a clean clone.
