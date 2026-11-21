# P2 DELAY summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: DELAY (all unsigned downlink frames held a fixed delay, released in order). Claim class: **link-level detection** only (the vehicle is disarmed on the ground; PX4 is the sender and is unaffected; no estimator/physical/signing claim). Regenerate: `scripts/sitl/make_p2dd_summary.py --attack delay <manifests> --out <this file>`.

- Trials: **3**; passing the integrity gates: **3** (`hook_errors == 0` and no frames left held).
- **Link-level detection (SITL): 3/3** integrity-passing trials (any threat decision in the scoring window).
- Pre-onset false alarms (integrity-passing trials pooled): **0/575** decisions.
- Time from onset to first detection: median 9.33 s, min 7.07 s, max 11.49 s (n=3).

| trial | idx | onset s | dur s | delay s | frames delayed | hook_errors | held@end | pre-onset FA | detected | latency s | threat decisions in window | types | evidence (sample) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| delay_001 | 1 | 42.51 | 10.52 | 0.939 | 3918 | 0 | 0 | 0/213 | yes | 11.49 | 5 | DOS | message-rate spike: 724 msg/s > 1×nominal (529); message-rate spike: 724 msg/s > 1×nominal (529); message-rate spike: 724 msg/s > 1×nominal (529) |
| delay_002 | 2 | 50.67 | 8.54 | 0.671 | 3193 | 0 | 0 | 0/254 | yes | 9.33 | 5 | DOS | message-rate spike: 621 msg/s > 1×nominal (529); message-rate spike: 631 msg/s > 1×nominal (529); message-rate spike: 631 msg/s > 1×nominal (529) |
| delay_003 | 3 | 21.53 | 6.44 | 0.48 | 2394 | 0 | 0 | 0/108 | yes | 7.07 | 5 | DOS | message-rate spike: 560 msg/s > 1×nominal (529); message-rate spike: 545 msg/s > 1×nominal (529); message-rate spike: 543 msg/s > 1×nominal (529) |

## Provenance
- PX4: ['v1.16.2']; detector profile ['configs/px4_sitl'], model ['px4']; aegisflight commit ['2b9eab3']; `src`/`scripts`/`configs` dirty-path counts [0] (uncommitted changes at run time; not a clean-commit reproduction until committed).
- Threat decisions after the scoring window (not attributed to the attack): 0.

## Limitations
- n=10 is the design floor, reported as counts (no confidence interval); one airframe/world/host; fresh SITL boot per trial; vehicle disarmed (no flight driver); unsigned link; SITL only.
- Detection is **link-level**: it says the IDS can see this manipulation of the downlink it is tapped on, nothing about vehicle behaviour.
- The scoring window counts ANY threat decision; a decision need not be caused by the delay (see types/evidence per trial). Absence of detection is a legitimate, reported result: the delay changes arrival times, not content or sequence, so little detector signal is expected.
