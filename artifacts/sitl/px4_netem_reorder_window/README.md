# PX4 SITL under tc netem: `reorder_window` 16 vs 48 [SITL + SIM, link-level, benign-only on PX4]

Claim class: link-level false-alarm behaviour (PX4) and link-level detection (simulator `seq_scramble`).
No attack was injected on PX4. Nothing here is real-vehicle or detection-on-PX4 evidence.

## Provenance

- Code under test: a clean merge of #82 (`68c956a`, has the harness) and this PR (`bb63e86`, has the profile value), merge commit `53b4d24` (local, clean tree). Installed with `pip install /app` from `git archive` of that commit; `aegisflight` 0.1.0, Python 3.13.18.
- Model: `models/isoforest.joblib`, sha256 `3fe74cddf3689e169610ffd783b109b6539cc6c03629bd1e4bb8b1d3842939c4` (matches `models/MODELS.sha256`), ML on.
- PX4 `v1.16.2`, Gazebo Sim `8.15.0`, `gz_x500`, `HEADLESS=1`, native aarch64 Docker; IDS container shares PX4's network namespace (`--cap-add NET_ADMIN`, `iproute2-6.15.0`). Fresh PX4 process per run.
- Raw tlogs are not committed; sha256 in `tlog_sha256.txt`.

## Commands

```
# per run (fresh PX4 first); netem runs first execute scripts/hardware/px4_netem_on.sh
python scripts/hardware/px4_benign_netem.py --out <stem> --profile <dir> --laps 1
```
`<dir>` = `configs/universal_flight` (window 48) or a copy of it without the `reorder_window` line (window 16, the shipped Stage-1 value).
Netem: `delay 40ms 20ms loss 1%` on UDP to/from GCS port 18570 only.

## PX4 results (same mission each run: arm, 20 m, square legs, land)

| Run | Netem | Window | Decisions | Alerts |
|---|---|---|---|---|
| A1 | no | 48 | 556 | 0 |
| A2 | no | 48 | 555 | 1 (`TELEMETRY_MANIPULATION`, t=23.4 s: `VFR_HUD heading and ATTITUDE yaw disagree by 21 deg > 20 deg`) |
| B1 | yes | 16 | 559 | 195 (`MAVLINK_ANOMALY`, sequence gap) |
| B2 | yes | 16 | 560 | 112 (`MAVLINK_ANOMALY`, sequence gap) |
| C1 | yes | 48 | 561 | 0 |
| C2 | yes | 48 | 560 | 0 |

A2's single alert is not related to the reorder window (no netem); it is the profile's 20 deg heading tolerance being exceeded by 1 deg during a benign flight. Not addressed here.

## Simulator `seq_scramble`, window 16 vs 48 (`seq_scramble_e2e_sim.json`)

`scripts/hardware/seq_scramble_window_ab.py`, 20 seeds, ML off, `universal_flight` with and without the window line, `attacks.mavlink_anomaly.mode = seq_scramble`:

| Window | Sessions with a detection | Mean time to detect | Mean decision recall | Benign-session mean FPR | Attack-session mean FPR |
|---|---|---|---|---|---|
| 16 | 20/20 | 0.05 s | 0.966 | 0.0348 (5 of 20 seeds nonzero) | 0.0518 |
| 48 | 20/20 | 0.09 s | 0.911 | 0.0348 (5 of 20 seeds nonzero) | 0.0518 |

Cost of 48 on this attack: about 5.5 points of attack-decision recall and 0.04 s slower detection; every session still detects it. A scrambler that keeps jumps within 48 behind the high-water mark would not be flagged by the gap rule; not tested.

### Correction (benign FPR)

An earlier version of this README and of the PR body gave a benign mean FPR of 0.0000. That row does not reproduce with the `configs/universal_flight` this PR ships; it was reported to come from the profile of #82 (not verified here). Regenerated with the profile as committed here, the simulator benign sessions show mean FPR 0.0348 for window 16 **and** for window 48 (identical, so the window does not change it). In seed 1, 80 of 575 scored decisions are false alarms and all are `GPS_SPOOFING` (profile-level, not a sequence-gap alert); its cause was not investigated here. Attack time-to-detect and recall are unchanged by the regeneration. The value 48 is unchanged; whether to ship it is the maintainer's decision.

Regenerate (SIM, link-level; run from the repo root at this PR's head, `PYTHONPATH=src`):

```
# window-16 profile = configs/universal_flight/detector.yaml minus the "reorder_window: 48" line
mkdir <scratch>/prof16 && grep -v "^  reorder_window: 48" configs/universal_flight/detector.yaml > <scratch>/prof16/detector.yaml
python scripts/hardware/seq_scramble_window_ab.py <scratch>/prof16 configs/universal_flight seq_scramble_e2e_sim.json
```
Regenerated at `37c9217` with Python 3.13, ML off; no PX4 run artifact (`runs/`, `tlog_sha256.txt`) was touched.
