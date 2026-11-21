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

The default `--base-url` is the GitHub Release `models-v1` on `TeamArdra/aegis-flight` (tag at `8605cea`). It is
**published and verified**: the two assets are

| Asset | SHA-256 | Size |
|---|---|---|
| `isoforest.joblib` | `3fe74cddf3689e169610ffd783b109b6539cc6c03629bd1e4bb8b1d3842939c4` | 2,302,587 B |
| `isoforest_px4.joblib` | `df540999dc6b43c3981d6ac6ecb91369b56ce1ba8cfdb894b76b195951260c7c` | 1,607,791 B |

`python scripts/fetch_models.py` downloads both and installs each only if its SHA-256 matches `models/MODELS.sha256`.
To check files you already have, from the repo root: `(cd models && sha256sum -c MODELS.sha256)`.

## Behaviour

- `aegis benchmark` / `aegis simulate` / `scripts/benchmark.py`:
  - model **missing** -> exit 2 and print `python scripts/fetch_models.py`;
  - model that is not verified OK, i.e. listed in `MODELS.sha256` but **SHA-256 differs**, or a custom `--model`
    with **no manifest entry** (`unlisted`) -> exit 2 naming `--allow-unverified-model`, which prints a warning
    and is the only way to use it (e.g. `aegis train` output). This matches `AnomalyDetector`, which refuses the
    same files before deserialization, so the CLI can never report an ML run that silently ran ML-off;
  - `--no-model` is the explicit ML-off opt-out (unchanged).
- `AnomalyDetector(model_path=...)`: a path that does not exist or cannot be loaded now logs a **WARNING**
  naming the path and reason, then degrades to ML off as before (live sources run ML-off by design).
  `model_path=None` stays silent: it is the explicit opt-out.
- Every `aegis benchmark` `summary.md` header and `results.json` records `model_used` and `model_sha256` from
  what the pipeline **actually loaded** (`none` / `False` when the model was refused, unreadable or absent), not
  from the requested path.

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

## Release workflow (how `models-v1` was published; manual)

Publishing a release is a manual maintainer step. For reference, with the real model files:

```bash
(cd models && sha256sum -c MODELS.sha256)    # from the repo root; must say OK for both files
gh release create models-v1 models/isoforest.joblib models/isoforest_px4.joblib \
  --title "AegisFlight trained models v1" --notes "SHA-256 in models/MODELS.sha256"
python scripts/fetch_models.py               # from a fresh clone: must verify
```

`ci-python` runs `python scripts/fetch_models.py` before pytest (a missing file or hash mismatch fails the job) and sets
`AEGIS_REQUIRE_MODEL=1`, which turns every model-missing skip of the model-dependent tests (golden ML-on, the fused-GPS ML
limitation test, extended-benchmark session 51, the fast-IsolationForest check on the repository model) into a failure.
Local runs without the model still skip, with the reason in `pytest -r s`.

## Limits

- The unit tests drive the fetch path with `file://` fixtures only (no network in the unit tests; the CI fetch step is the live check). The live `models-v1`
  download was verified separately: both assets matched the manifest hashes above.
- Without the model the model-dependent tests still skip on a clean clone unless `AEGIS_REQUIRE_MODEL=1` is set (CI sets it).
