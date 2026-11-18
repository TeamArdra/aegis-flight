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

## 3. Rules for turning it on, and the lock-out safeguards

* Command line only: `aegis ips-bridge ... --vehicle-uplink-filter`. It needs `--signing-key-file` (without a key it cannot tell the pilot from a
  forger and would block the pilot) and a reporting posture (`passive` or `advisory`). `--defense-mode active-ips` with it is refused, exit code 2.
* Fixed at construction. There is no setter. The status API's `POST /posture`, the management channel over the radio and `set_mode` cannot switch it
  on or off, and a refused `active-ips` request on a serial port leaves it exactly as it was. A change between `passive` and `advisory` does not
  disturb it.
* It is reported: `status()["vehicle_filter"]` and `status()["vehicle_filter_state"]`, `policy.uplink_filter_only`, and a start-up notice on the console.
* On a `socket://` SITL link, `set_mode("active-ips")` replaces the filter with full enforcement, and going back to a reporting posture restores it
  (in the learning state, below).
* The receive-only refusal of `active-ips` on a serial device is unchanged, in every entry point.

**The filter has four states** (`status()["vehicle_filter_state"]`). Every change is announced: a short `AEGIS:` STATUSTEXT to the pilot's GCS and the
full reason on the console.

| State | What the bridge does | How it gets there |
|---|---|---|
| `learning` | forwards everything, reports signature verdicts only | the start state; also after an override is removed |
| `engaged` | drops forged / unsigned / wrong-key / replayed control before the flight controller | the first **validly signed** frame from a ground-station sysid proves the key |
| `override` | forwards everything, reports only | the local override file exists |
| `failopen` | forwards everything, reports only | the optional watchdog (below) suspects a lock-out; a valid signed frame re-engages |

1. **A wrong key can never lock the pilot out.** The filter drops nothing until a validly signed ground-station frame has been seen. If the key, the
   signing timestamps or the GCS's signing do not match, no such frame ever arrives, the filter stays in `learning`, the pilot's commands pass, and the
   mismatch shows up as reported bad-signature verdicts. The price: until the pilot's GCS has sent one validly signed frame (any frame counts, for example a
   signed heartbeat; how soon a real GCS sends one has not been measured) a forged frame is forwarded, as with no filter.
2. **A local off switch that needs no restart.** `--filter-override-file PATH`: while that file exists on the bridge's own disk the filter only reports.
   It is read at most every 0.5 s. Remove it and the filter goes back to `learning` and re-proves the key before it drops anything. Nothing on the radio,
   the status API or the management channel can create or remove the file; someone with a shell on the companion computer can.
3. **An optional watchdog, off by default.** `--filter-lockout-failopen-s N`: if control frames from a *trusted* ground-station sysid keep failing the
   signature check (at least 3 drops) and no validly signed ground-station frame has been seen for N seconds, the filter fails open and says so. A valid
   signed frame re-engages it. The watchdog cannot tell a real lock-out from an attacker who spoofs the pilot's sysid while the real GCS is silent
   (for example jammed), so it is a choice: with it, a lock-out ends by itself and a jam-and-spoof attack can open the filter; without it, a lock-out
   stays until the operator uses the override file. While the real GCS keeps sending validly signed frames the watchdog stays quiet and forged frames are
   still dropped.

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
| Messages outside the filter's control set: MANUAL_CONTROL, DO_MOTOR_TEST, DO_SET_SERVO, SERIAL_CONTROL, FILE_TRANSFER_PROTOCOL, GPS_INPUT, DO_CHANGE_SPEED, DO_SET_HOME | | no (forwarded unchecked) |
| Anything before the first validly signed GCS frame (the `learning` state forwards everything) | | no |

The campaign's "0 of 10 forged events changed the mode" covers forged **mode changes** only; the messages in the row above
were not tested.

## 5. Risks, stated plainly

1. **Pilot lock-out (reduced, not removed).** A key, timestamp or signing mismatch from the first minute can no longer block the pilot: the filter never
   engages (section 3, point 1). What remains: the key or the GCS's signing breaks *after* the filter engaged. Then the pilot's frames are dropped until the
   operator creates the override file, or, if the watchdog is on, until it fails open. The bench test with props off is still mandatory before any flight use.
   It fails open on a rule exception (the frame is forwarded and `hook_errors` counts it), and `--signing-permissive` (existing) lets unsigned frames from a trusted
   sysid through, at the price of not stopping a forger who uses that sysid.
2. **Off switch.** There is a local one (the override file) and no remote one, on purpose: an attacker cannot remove the filter over the radio. Someone with a shell on
   the companion computer can, and a pilot with no access to it cannot, so the practical question is who is allowed to touch that file in flight.
3. **Legitimate frames the rules drop.** The burst rule and the in-flight plain-disarm rule can drop a pilot's own repeated command. Both are existing
   `active-ips` rules; the filter runs them on a vehicle link.
4. **Clock and restart.** Signed timestamps must advance. A bridge restart without `--signing-state` opens a short replay window; with it the last timestamp survives.
5. **It is software on one companion computer.** A crash of the bridge is a loss of the link (the bridge is in line), as for every posture today.

## 6. What has been shown, and what has not

Shown (software only: 23 unit tests in `tests/unit/test_vehicle_uplink_filter.py`, and 2 in `tests/unit/test_vehicle_uplink_filter_sockets.py` that run the bridge's own threads over real `socket://` transports (stable in 25 consecutive runs); `ruff` clean and the full suite passing):

* it refuses to start without a key and with `active-ips`, in the constructor and in the command line;
* it runs on a serial-device port where `active-ips` is still refused, in both reporting postures;
* it drops unsigned, wrong-key and replayed control frames and forwards the validly signed one;
* the downlink is forwarded untouched, including an unsigned frame from a source that had been signing;
* no counter-command is sent, and no posture change switches it on or off or makes it re-learn;
* a GCS signing with the wrong key is never blocked (5 signed heartbeats and 5 signed commands pass, the filter stays in `learning`, the verdicts are reported);
* an unsigned pilot is forwarded and reported until a signed frame proves the key, and is dropped after that;
* the override file turns the filter off and back on at run time, and the filter then re-proves the key before it drops again;
* the posture API and the management channel cannot reach the override;
* the watchdog: off by default (a lock-out keeps dropping), it fails open after the silence and three drops, it re-engages on a valid signed frame, and it stays quiet
  while a valid signed stream continues, with a spoofing forger still dropped every time;
* without the filter, `passive` and `advisory` forward every frame byte-identically (unchanged behaviour).

Not shown:

* any run against the real Pixhawk through a real serial port with the filter on (needs the hardware);
* a lock-out test with a real GCS signing its commands (needs the hardware, and a flight controller that accepts the GCS key);
* the value of the watchdog's timeout in practice, and how long a real GCS takes to send its first signed frame;
* any flight. Nothing here is a flight claim.

## 7. Decisions the team has to make

1. Whether a filter that drops frames is acceptable on a vehicle link at all, given the receive-only rule's wording ("never transmits").
   The filter transmits nothing of its own, but it does decide which of the pilot's frames reach the flight controller.
2. Whether it should additionally require signing to be enabled on the flight controller, so the pilot's commands are authenticated end to end.
3. Fail-open (current) or fail-closed when a rule throws.
4. Who may touch the override file in flight, and whether the watchdog should be on by default (section 3, point 3).
5. The flag name and where it is documented (this file, `docs/INLINE_IPS.md`).
6. The acceptance test before any flight use: a bench run with props off in which the pilot's signed commands pass 100% and each forged class is dropped.

## 8. Code

* `src/aegisflight/mitigation/inline_policy.py`: `uplink_filter_only` and `set_uplink_filter_only` (with `enforce` on, only the uplink rules run), the
  `filter_state` machine (`_filter_gate`, `_note_valid`, `_note_lockout_drop`), `filter_override` and `lockout_failopen_s`.
* `src/aegisflight/hal/inline_ips.py`: the `vehicle_filter`, `filter_override_file` and `filter_lockout_failopen_s` arguments, their checks, `_apply_enforcement`,
  `_poll_override`, `_announce_filter`, and `status()["vehicle_filter"]` / `["vehicle_filter_state"]`.
* `src/aegisflight/cli/main.py`: `--vehicle-uplink-filter`, `--filter-override-file`, `--filter-lockout-failopen-s` and their refusals.
* `tests/unit/test_vehicle_uplink_filter.py`.
