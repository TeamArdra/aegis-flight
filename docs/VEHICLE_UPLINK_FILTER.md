# Vehicle uplink filter: enforcement on a real vehicle link, kept apart from the postures

**Status (2026-11-17): a proposal with an implementation on a local branch. It is NOT agreed with the team and must not be merged on this
document's say-so.** It touches a security boundary (`AGENTS.md` section 5: a serial-device vehicle link is receive-only in every entry point),
so it needs the maintainers' approval on an issue first (`needs:human-approval`). It is off by default and changes nothing unless the operator
passes a new command-line flag.

## 1. The problem

The bridge has three postures: `passive`, `advisory` and `active-ips`. `passive` and `advisory` forward every frame byte-identically and only
report. `active-ips` drops forged frames and sends counter-commands. Since `eb829e9`, `active-ips` is refused whenever the flight-controller
port is a serial device (`/dev/ttyACM0`, `/dev/ttyAMA0`, `COMx`), because that port may be a physical flight controller.

On a real vehicle the bridge sits on exactly such a port. So on a real vehicle the system detects and reports a forged command, and the forged
command still reaches the flight controller. The campaign evidence that signed `active-ips` blocked 10 of 10 forged events (`docs/REAL_PIXHAWK_TEST.md`,
section 11) was produced through a `socket://` proxy, so it describes the bench, not a flight configuration.

## 2. The proposal

A separate, explicit capability: the **vehicle uplink filter**. It is not a posture and not a fourth value of `--defense-mode`.

What it does: with it on, the bridge **drops** control frames from the GCS side that fail the signing rules before they reach the flight
controller: unsigned, wrong-key, replayed, or from an untrusted sender. A validly signed command from the pilot's GCS is forwarded as it came.

What it never does:

* It never writes a byte the pilot's GCS did not send. The rules return the original frame or nothing; there is no rewrite and no injected frame.
* It never changes the downlink (flight controller to GCS). An unsigned frame from a source that had been signing is reported, not dropped.
* It never sends a counter-command. Counter-commands are gated on the controller being in `active-ips`, and the filter requires a reporting posture.
* It never applies the dynamic rules (flood quarantine, rate limiting, GPS rewriting): those stay with `active-ips`.

## 3. Rules for turning it on

* Command line only: `aegis ips-bridge ... --vehicle-uplink-filter`. It needs `--signing-key-file` (without a key it cannot tell the pilot from a
  forger and would block the pilot) and a reporting posture (`passive` or `advisory`). `--defense-mode active-ips` with it is refused, exit code 2.
* Fixed at construction. There is no setter. The status API's `POST /posture`, the management channel over the radio and `set_mode` cannot switch it
  on or off, and a refused `active-ips` request on a serial port leaves it exactly as it was.
* It is reported: `status()["vehicle_filter"]`, `policy.uplink_filter_only`, and a start-up notice on the console.
* On a `socket://` SITL link, `set_mode("active-ips")` replaces the filter with full enforcement, and going back to a reporting posture restores it.
* The receive-only refusal of `active-ips` on a serial device is unchanged, in every entry point.

## 4. What it blocks and what it does not

| | Blocked by the filter | Not covered |
|---|---|---|
| Forged control from a sender without the key (a wrong sysid, an unsigned frame, a wrong-key frame) | yes | |
| A replay of a captured signed frame | yes (timestamp rule) | |
| A plain disarm in flight (the autopilot refuses it anyway); identical repeats of a sensitive command inside the cadence window | yes | |
| A GCS or an attacker that holds the key | | no |
| Traffic that does not pass the Pi (a radio wired straight to the flight controller, a second link) | | no |
| Telemetry manipulation on the downlink | reported only | no |
| Jamming or loss of the radio | | no |

## 5. Risks, stated plainly

1. **Pilot lock-out.** If the key, the signing timestamps or the GCS's signing do not match, the filter drops the pilot's own control frames. This is the
   main risk and the reason the bench is mandatory before any flight use. Mitigations in the code: it needs a key; it fails open on a rule exception
   (the frame is forwarded and `hook_errors` counts it); `--signing-permissive` (existing) lets unsigned frames from a trusted sysid through during rollout, at
   the price of not stopping a forger who uses that sysid.
2. **Cannot be turned off in flight.** Because nothing can switch it at run time, removing the filter needs a restart of the bridge. That is deliberate
   (an attacker cannot remove it over the radio) and it is the trade-off the team has to accept or reject.
3. **Legitimate frames the rules drop.** The burst rule and the in-flight plain-disarm rule can drop a pilot's own repeated command. Both are existing
   `active-ips` rules; the filter runs them on a vehicle link.
4. **Clock and restart.** Signed timestamps must advance. A bridge restart without `--signing-state` opens a short replay window; with it the last timestamp survives.
5. **It is software on one companion computer.** A crash of the bridge is a loss of the link (the bridge is in line), as for every posture today.

## 6. What has been shown, and what has not

Shown (software only, 14 unit tests in `tests/unit/test_vehicle_uplink_filter.py`, with `ruff` clean and the full suite passing):

* it refuses to start without a key and with `active-ips`, in the constructor and in the command line;
* it runs on a serial-device port where `active-ips` is still refused, in both reporting postures;
* it drops unsigned, wrong-key and replayed control frames and forwards the validly signed one;
* the downlink is forwarded untouched, including an unsigned frame from a source that had been signing;
* no counter-command is sent, and no posture change switches it on or off;
* without it, `passive` and `advisory` forward every frame byte-identically (unchanged behaviour).

Not shown:

* any run against the real Pixhawk through a real serial port with the filter on (needs the hardware);
* a pilot-lock-out test with a real GCS signing its commands (needs the hardware, and a flight controller that accepts the GCS key);
* any flight. Nothing here is a flight claim.

## 7. Decisions the team has to make

1. Whether a filter that drops frames is acceptable on a vehicle link at all, given the receive-only rule's wording ("never transmits").
   The filter transmits nothing of its own, but it does decide which of the pilot's frames reach the flight controller.
2. Whether it should additionally require signing to be enabled on the flight controller, so the pilot's commands are authenticated end to end.
3. Fail-open (current) or fail-closed when a rule throws.
4. Whether a local, physical override is wanted (for example a lock file that disables the filter at the next frame), which is not a radio switch.
5. The flag name and where it is documented (this file, `docs/INLINE_IPS.md`).
6. The acceptance test before any flight use: a bench run with props off in which the pilot's signed commands pass 100% and each forged class is dropped.

## 8. Code

* `src/aegisflight/mitigation/inline_policy.py`: `uplink_filter_only` and `set_uplink_filter_only` (with `enforce` on, only the uplink rules run).
* `src/aegisflight/hal/inline_ips.py`: the `vehicle_filter` argument, its checks, `_apply_enforcement`, and `status()["vehicle_filter"]`.
* `src/aegisflight/cli/main.py`: `--vehicle-uplink-filter` and its refusals.
* `tests/unit/test_vehicle_uplink_filter.py`.
