# P2 expected-GCS impersonation summary - live SITL trials (generated; do not edit)

Environment: **SITL**. Attack: a fresh forged `COMMAND_LONG` (force-disarm) stamped with an EXPECTED GCS identity (sysid 255/compid 190), not a replay. Command-path effect, harness delivery and detection are scored separately (see the script docstring). Vehicle disarmed: an ACCEPTED ack is acceptance only, not an observable state change. Regenerate: `scripts/sitl/make_p2g_summary.py --variant LABEL=GLOB ... --out <this file>`.

## Variant: informed track_identity

- Trials: **3**; passing the integrity gate (no hook errors, >=1 injection): **3**; forged frames injected: **14**.
- **Command-path effect (SITL)**: trials where PX4 acked the forged command `MAV_RESULT_ACCEPTED`: **3/3**.
- **Harness delivery**: trials where every forged frame reached the IDS pipeline input: **3/3** (14/14 frames).
- **Seq continuity achieved** (attack-implementation check, not detection): **14/14** forged frames carried exactly (previous real 255/190 seq + 1).
- **Link-level detection (SITL)** within the forged-frame window (+5s): any threat decision **0/3**; identity/provenance rule **0/3**; sequence-continuity rule **0/3**.
- Pre-injection false alarms (pooled): **0/563** decisions.

| trial | idx | injected | acks | first ack | delivered | seq-continuous | any | identity | seq-gap | pre FA | evidence (sample) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| gcsimp_001 | 1 | 4 | 4 | MAV_RESULT_ACCEPTED | yes | 4/4 | NO | NO | NO | 0/131 | - |
| gcsimp_002 | 2 | 5 | 5 | MAV_RESULT_ACCEPTED | yes | 5/5 | NO | NO | NO | 0/201 | - |
| gcsimp_003 | 3 | 5 | 5 | MAV_RESULT_ACCEPTED | yes | 5/5 | NO | NO | NO | 0/231 | - |

## Provenance
- PX4: ['v1.16.2']; detector profile ['configs/px4_sitl'], model ['px4']; aegisflight commit ['2b9eab3']; dirty-path counts [0] (uncommitted changes at run time; not a clean-commit reproduction until committed).

## Limitations
- n=10 per variant is the design floor, reported as counts (no confidence interval); one airframe/world/host; fresh SITL boot per trial; unsigned link; vehicle disarmed on the ground; SITL only.
- The informed attacker reads the 255/190 heartbeat sequence off the clear-text link; that is a statement about an attacker with read access to the link (the MITM position this proxy already assumes), not about a remote one.
- Link-level only: this says what the IDS could see on its tap; it says nothing about vehicle behaviour, and an ACCEPTED ack of a disarm sent to an already-disarmed vehicle is not a demonstrated physical effect.
- Only the rules present in the PX4-profile detector were exercised; a deliberately designed duplicate-sequence or timing-consistency check (not implemented) is not evaluated here.
