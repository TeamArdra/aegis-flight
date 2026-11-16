# Stage 2 red-team audit: withdrawn

The previous self-assessment (teammate commit `5740040`, now `5c59cdd` here; full text in that commit) was
withdrawn during the 2026-10-27 integration review. It contradicted the code and the evidence:
- it stated `bytes_sent = 0` as verified, but the defense layer could transmit counter-commands and STATUSTEXT on a
  live serial or UDP link (fixed on `integration/stage2-defense-candidate`; `f816f41` then re-enabled `active-ips`
  on live links; since 2026-10-31 a serial-device link is receive-only in `run_serial_ids.py`, `aegis serve` and
  `aegis ips-bridge`, and `active-ips` runs only on SITL UDP / `socket://` links; see `tests/unit/test_defense_safety.py`);
- it described a disarm veto, parameter attestation and a hardware fail-open watchdog that the code does not have;
- it cited Raspberry Pi measurements, a 500 Hz flood result, "729+ tests" and a self-awarded 92/100 score, none of
  which has an artifact.

The independent findings and their fixes are in `docs/GPS_WORKSTREAM_PROGRESS.md` ("Integration session"). A new
audit must cite artifacts, with the environment tag and claim class next to every result.
