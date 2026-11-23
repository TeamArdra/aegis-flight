# P4 MAVLink-2 signing summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: the same informed expected-GCS-impersonation forgery as the P2 batch (sysid 255/190, correctly-tracked sequence), run once signing is bootstrapped and the IDS profile's `require_signing` is forced on. Five questions scored separately (see module docstring): legitimate-command acceptance, forged-command acceptance (command-path effect), IDS observation, detection via the new signing rule, detection via any rule. Regenerate: `scripts/sitl/make_p4_summary.py <manifests> --out <this file>`.

- Trials: **2**; passing the integrity gate (no hook errors, >=1 forged frame, legit ack confirmed signed): **0**.
- **Legitimate signed command accepted**: **0/0**.
- **Unsigned forged command REJECTED (0 acks)** -- command-path effect: **0/0**.
- **IDS observed the forged bytes** (verifying parser's `sig_invalid` rose by >= the number of forged frames): **0/0**.
- **Link-level detection via the new signing rule** (`sig_invalid_count` evidence) in the forged-frame window: **0/0**.
- **Any rule fired** in that window (includes the pre-existing, cruder `signed_ratio` rule -- see Limitations): **0/0**.
- Pre-onset false alarms, new signing rule only (clean baseline): **0/0** decisions.
- Pre-onset false alarms, ANY rule (includes the one-time bootstrap transient + the continuously-noisy `signed_ratio` rule -- see Limitations): **0/0** decisions.

**Integrity-gate failures (NOT scored as evidence about the detector):** sign_001 (hook_errors=0), sign_002 (hook_errors=0)

| trial | idx | forged | legit ack ok | path rejected | sig observed | sig-rule detected | any detected | pre FA (sig-rule) | pre FA (any) | evidence (sample) |
|---|---|---|---|---|---|---|---|---|---|---|
| sign_001 | 1 | 2 | yes | NO | yes | yes | yes | 40/40 | 40/40 | 73 frame(s) failed MAVLink-2 signature verification; coverage: GLOBAL_POSITION_INT never received (GPS_RAW_INT ne |
| sign_002 | 2 | 2 | yes | NO | yes | yes | yes | 40/40 | 40/40 | 72 frame(s) failed MAVLink-2 signature verification; coverage: GLOBAL_POSITION_INT never received (GPS_RAW_INT ne |

## Provenance
- PX4: ['v1.16.2']; detector profile ['configs/px4_sitl'], model ['px4']; aegisflight commit ['2b9eab3']; dirty-path counts [0] (uncommitted changes at run time; not a clean-commit reproduction until committed).

## Limitations
- n=10 is the design floor, reported as counts (no confidence interval); one airframe/world/host; fresh SITL boot AND a cleared signing-key file per trial (`run_trial_batch.sh`); unsigned-until-bootstrapped link; vehicle disarmed on the ground; SITL only.
- **The one-time signing-bootstrap transient**: characterized separately, SITL-free in spirit but confirmed live across 6 independent diagnostic runs before this batch -- ~1s of spurious `sig_invalid` right after `enable_signing()` as PX4's own downlink and the verifier's per-stream timestamp tracking settle, then exactly 0 for the remainder of a clean trial. This is NOT an ongoing noise floor; it is bucketed into the trial's PRE-onset window (onset is several seconds later), so it shows up as pre-onset false alarms, not as attack detections -- reported, not hidden.
- **The pre-existing `signed_ratio` rule is link-wide and blunt**: it fires on ANY unsigned traffic regardless of source, and this harness deliberately has one always-unsigned inert carrier client (the attack's own piggyback-delivery mechanism, not a calibrated real deployment) -- so 'any rule fired' / 'any FA' numbers above are expected to look noisy and must not be read as a false-alarm rate for a real deployment. The NEW `sig_invalid_count` rule is the clean, intended signal and is reported separately for exactly this reason.
- Detection here is **link-level** (IDS-side), separate from and in addition to PX4's own command-path rejection -- the two are never merged into one number.
- A single command (force-disarm) against an already-disarmed vehicle; not evidence about a different command or one with in-flight consequence.
- The informed attacker's identity-impersonation mechanics are unchanged from the P2 batch; this experiment is only about what happens once signing is active, not a new attack design.
