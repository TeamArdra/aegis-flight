# Link-level attribution, before / after `protocol.semantic_link_attribution` (issue #22)

- **Environment tag:** `SIM` (in-process simulator, ML off: `model_path=None`).
- **Claim class:** link-level detection (attribution of detected link-layer attack decisions to a class). Nothing here says anything about a vehicle, an estimator, a flight or real RF.
- **Seed:** `master_seed=20261119` (24 sessions: 4 benign plus 4 sessions for each of `mavlink_anomaly:packet_loss`, `mavlink_anomaly:rate_spike`, `dos:latency`, `dos:flood`, `dos:blackout`).
- **Code under test:** `024baab3791a29ee24b1e04f50bfa2bfb8aafba1` (`origin/main`), clean tracked tree. `git diff 8e58003 024baab --stat -- src configs models` is empty, so `src/`, `configs/` and `models/` are identical to the freeze tag `stage2-freeze-2026-11-27` (`8e58003`). The script and the modules it uses (`benchmark/`, `metrics/`) are identical too.
- **Interpreter:** CPython 3.13.15, scikit-learn 1.9.1, numpy 2.5.3, pandas 3.0.6 (the model is not loaded).

## Command (from the repository root, Windows Git Bash)

```
PYTHONPATH=src python scripts/eval_link_attribution.py --seed 20261119 > artifacts/validation/link_attribution_20261119/eval_link_attribution_seed20261119.json
```

The script has no `--out` option; it prints its JSON to stdout, so the file is the shell-redirected stdout, byte for byte, not edited. Wall time about 26 s. Run twice: the two outputs were byte-identical (`cmp`). Python on Windows wrote CRLF line endings; `.gitattributes` (`* text=auto eol=lf`) normalises them to LF on commit, so the only difference between the raw stdout and the committed file is line endings. sha256 of the raw stdout (CRLF): `539be4beb1ed05d3b83374de257ccc9fe504772917dac8e270385c10d857ecdb`; sha256 of the committed file (LF): `d4d741229da27a0bd7ecaa220c47463d95ce21b6d7129e7b7c5bc726ca70f663`.

## Result (copied from the JSON; keys `before` and `after_semantic`)

`strict_acc` and `hierarchical_acc` are computed **among detected decisions** (`detected`), not over all attack decisions, so they are not recall. `hierarchical_acc` counts a prediction as correct if both the truth and the predicted class are in `{DOS, MAVLINK_ANOMALY}`.

| Mode | attack decisions | detected | strict before | strict after | hierarchical (before = after) |
|---|---:|---:|---:|---:|---:|
| `mavlink_anomaly:packet_loss` | 493 | 61 | 0.0000 | **0.9508** | 0.9508 |
| `mavlink_anomaly:rate_spike` | 508 | 500 | 0.0000 | 0.0000 | 1.0000 |
| `dos:latency` | 554 | 15 | 0.0000 | 0.0000 | 0.0000 |
| `dos:blackout` | 497 | 376 | 0.7952 | **0.6676** | 0.8005 |
| `dos:flood` (control) | 501 | 500 | 1.0000 | 1.0000 | 1.0000 |

Binary recall over these five attack modes: `0.5687` before, `0.5687` after. Benign false-positive rate: `0.0` before, `0.0` after (benign decisions: 4 sessions; the JSON does not record the denominator). The recall figure covers this five-mode subset only and is not comparable with the Stage-1 `0.9902`.

## Limits

One seed, 4 sessions per mode, ML off. The rules in the detector were written with knowledge of the simulator's attack definitions (`docs/DETECTION.md`, "Methodology disclosure"). The acceptance reading of these numbers is in `docs/acceptance/ISSUE_22_link_attribution.md`.
