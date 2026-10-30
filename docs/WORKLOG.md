# Documentation worklog

A short running log of documentation changes, so a later context can see what is done. Each entry names the brief items it used (`C:\afsitl\DOCS_WORKER_BRIEF.md`: the numbered file tasks, and the "Facts" and "Results log" sections). Nothing here is committed by the documentation worker; the lead commits.

## 2026-10-31: real Pixhawk 6X on a Pi 5 (brief files 1 to 6)

Brief items used: file tasks 1 to 6; facts on hardware and setup, benign runs, the unsigned attack sequence, the legitimate-traffic suite, the management channel, firmware tamper, GPS, the Pi 5 soak (in progress), signing (not run) and "not done"; lessons 1 to 8.

| File | What changed |
|---|---|
| `docs/RADIO_TEST_RESULTS.md` | New section "Real Pixhawk 6X on a Pi 5, 2026-10-31" (rig, benign runs, attack sequence, legitimate suite, management channel, firmware tamper, GPS open issue, soak in progress, signing not run, findings, judgement against the plan, limits, git notes). Banner points to it. One stray `\1` table prefix removed. |
| `docs/RADIO_TEST.md` | Status banner updated; a status line under phases 0 to 9; USB (not UART) and Pi 5 notes; notes on `attacks.py` and `legit_probe.py`; a limit bullet; a real-Pixhawk paragraph in section 11; a troubleshooting row for the Pi 3B+ drop. |
| `docs/REAL_PIXHAWK_TEST.md` (new) | How to reproduce the runs: rig, safety rules, software, run order, snapshot, restore and signing steps, lessons, what is not run. |
| `docs/INLINE_IPS.md` | Replaced the "not tested against a real flight controller, a radio or SITL" line; pointer to the radio results; two `\1` table prefixes removed; new "Pi deployment notes (Pi 5, bench, 2026-10-31)" at the end. |
| `docs/MINIMAL_BUILD.md` | Replaced the "nothing measured on real hardware" opening; restart note (cron on the 3B+ bench, systemd unit untested); new "Pi 5 bench deployment (2026-10-31)" section. |
| `docs/README.md` | Index links for the new and radio documents, INLINE_IPS, MINIMAL_BUILD and this log. |
| `README.md` | Statements the new results contradict now say what was measured (SITL, radio, bench Pixhawk, Pi 3B+ and Pi 5), and that nothing was flown. Links to the new documents added. |
| `docs/DETECTION.md` | "Cross-message consistency" section checked, not changed. Open point for the lead: the bullet says "800 samples over 200 s" and "802 of 802 distinct" in the same bullet. |

Line endings: existing files keep the endings they had (`docs/README.md` and `docs/MINIMAL_BUILD.md` are LF; the radio and README files are CRLF). New files are LF.

Not done, and why:

* Other docs still say "nothing measured on a companion computer" or similar. They are outside the brief's file list: `docs/ARCHITECTURE.md`, `docs/PERFORMANCE.md` (its own Pi 3B+ section contradicts its opening line), `docs/MGMT_CHANNEL.md`, `docs/HANDOFF.md`, `docs/current_state.md`, `docs/next_state.md`, `docs/HARDWARE_BENCH_PIXHAWK6X.md`. Left for the lead.
* Pi 5 soak: in progress at the time of writing; the result is not recorded. The brief's "Results log" was empty.
* Signing on the real Pixhawk: not run. The real-Pixhawk scripts have no wrong-key or signed-replay attack; this is noted in `docs/REAL_PIXHAWK_TEST.md`.

## 2026-10-31: pass 2 (coordinator review, "Results log" in the brief)

Brief items used: the "Results log" entries dated 2026-10-31 (the lead's review of pass 1, and PASS 2 tasks a to d), and the items still pending in the brief (Pi 5 soak result, signing test, snapshot and restore proof). Those three are **not** marked done.

| File | What changed |
|---|---|
| `docs/ARCHITECTURE.md` | Status note: the bridge's bench and Pi measurements now stated. Bench table row corrected: the "UART, zero frame loss, DMA verified" row replaced by a USB bench row (no UART run; no DMA measurement in the repository). |
| `docs/PERFORMANCE.md` | Two "not measured on a Raspberry Pi" statements corrected to point at the Pi 3B+ section. "Later" note added to the Pi 3B+ section (radio runs on the Pi 3B+; Pixhawk on a Pi 5; Pi 5 soak pending). |
| `docs/MGMT_CHANNEL.md` | Opening line corrected. "Later" note with the 2026-10-31 radio results (81.8 B/s nominal; flood-window and ACK latency not recorded). |
| `docs/HANDOFF.md` | Hardware validation row qualified (passive bench validation; radio and Pi 5 runs partly done; no flight). Next step notes the disarmed bench runs. |
| `docs/current_state.md` | CRLF kept. Bridge measured on a Pi 3B+ and a Pi 5 bench; target profile "partly tested"; bridge RSS on a Pi 3B+ (about 65 MiB, flat). |
| `docs/next_state.md` | Same corrections as `current_state.md`. Status line added under [P2]: what was done and what is not. |
| `docs/HARDWARE_BENCH_PIXHAWK6X.md` | Notice added under the 2026-10-10 header. Three "Later (2026-10-31)" notes beside the statements that now need them. The 2026-10 record itself is kept. |
| `docs/RADIO_TEST.md` | IP addresses replaced with `<laptop-ip>`, `<pi-ip>` and `<pi-link-local-ip>`. The `attacks.py` and `legit_probe.py` notes corrected: both are in the repository (committed in `95399be`) and have never been run. Phase 4 advisory marked as from the invalid first runs. Phase 7 names the real Pixhawk. Phase 2 and 8 text unchanged. |
| `docs/RADIO_TEST_RESULTS.md` | Link-local IP replaced with `<pi-link-local-ip>`. Management and firmware-tamper runs now stated as on the real Pixhawk (no longer "to be confirmed"). Advisory column marked as from the invalid first runs and unconfirmed. Soak marked PENDING. Snapshot and restore proof listed as pending. |
| `docs/REAL_PIXHAWK_TEST.md` | Section 5.6: snapshot and restore proof marked PENDING. Section 7: soak and snapshot and restore listed as pending. Section 10: cross-message checks pointer to `docs/DETECTION.md`. `attacks.py` described as never run. |
| `docs/WORKLOG.md` | This entry. |

Checks and notes:

* **Wi-Fi network name:** none appears in `docs/RADIO_TEST.md` or `docs/RADIO_TEST_RESULTS.md`. The only Wi-Fi items there were IP addresses, now placeholders. Nothing was invented for the name.
* **IP addresses left on purpose:** `127.0.0.1` (loopback) and the hostname `ardra.local` (not an IP address). The scripts under `scripts/` still hard-code the old address as a default (for example `laptop_ctl.py`); they were not edited (code is out of scope).
* **`docs/DETECTION.md`:** not changed by this pass. It now reads "802 attitude samples over 200 s", consistent with the attitude-repeat note in `docs/REAL_PIXHAWK_TEST.md` section 10.
* **Not changed:** `src/`, `tests/`, `scripts/`, `configs/`. No commits. No rig, SSH or Pixhawk access.
* **Still pending, not marked done:** the Pi 5 soak result, the signing test on the real Pixhawk, and the snapshot and restore proof on the Pixhawk.

## 2026-10-31: pass 3 (coordinator "RESULTS (lead)" and "PASS 3 tasks")

Brief items used: the "Results log" entry "2026-10-31 RESULTS (lead)", items 1 to 4 (soak, snapshot and restore, signing, code commits), and the "PASS 3 tasks". The PENDING markers from pass 2 are replaced by the measured results and their limits.

| File | What changed |
|---|---|
| `docs/RADIO_TEST_RESULTS.md` | Soak section rewritten as the 1,500 s result (79,135 frames to the ground; 0 dropped; 207 alerts and 457 counter-commands from false GPS alerts; vehicle held in ALT_HOLD). New signing section (one run over USB, bridge as the enforcement point; 0 of 7 forged or replayed events reached the vehicle; FC-side enforcement not tested). New snapshot and restore section (no pre-test snapshot; restore shown for one listed parameter; hidden `SCR_USER1..6` not covered). Judgement table, findings and limits updated. GPS section notes the soak's cost. |
| `docs/RADIO_TEST.md` | Banner, phase 3, phase 5, phase 6 and phase 9 status lines updated (phase 6 "partly met"; phase 9 "partly met", NOT PASS as written). Section 11 paragraph updated. Two troubleshooting rows added (hidden parameters and RESTORED; unsigned replies dropped when a key is set). |
| `docs/INLINE_IPS.md` | Stale "not run" statements corrected. New section "Signing enforcement point and the Pi 5 bench soak (2026-10-31)": unsigned-vs-signed table, limits, and the soak's GPS cost. |
| `docs/MINIMAL_BUILD.md` | Soak status updated. Two limit bullets added: signing enforced at the bridge over USB only; active-ips with the GPS issue changes a disarmed vehicle's mode. |
| `docs/REAL_PIXHAWK_TEST.md` | Rewritten to match the results: active-ips mode-change safety rule; `px_signed_attack.py` added to the run order; signing section with results and limits; snapshot and restore section with the baseline timing and hidden-parameter limit; lessons 14 to 17 added; "not run" list updated. |
| `docs/PERFORMANCE.md` | "Later" note: the Pi 5 soak is completed and its result is in the results file. |
| `docs/HARDWARE_BENCH_PIXHAWK6X.md` | The three "Later (2026-10-31)" notes now mention the signing-key test and the soak. |
| `docs/HANDOFF.md` | Signing row qualified: code and SITL complete; one USB bench run; FC-side enforcement not tested. |
| `docs/next_state.md` | [P2] status: signing run once over USB; the UART link is needed for FC-side enforcement; soak completed. |
| `docs/current_state.md` (CRLF kept) | Soak and signed-run notes added to the target-profile line. |
| `README.md` (CRLF kept) | Topology B line: one signed run over USB, enforcement not tested at the FC. Companion step: the active-ips soak changed a disarmed vehicle's mode. |

Not changed: `docs/DETECTION.md` (the lead's section), `docs/README.md` (no new file this pass), `docs/ARCHITECTURE.md`, `docs/MGMT_CHANNEL.md`. `src/`, `tests/`, `scripts/` and `configs/` were not edited.

Still NOT established, and not marked done: flight-controller-side signing enforcement (needs a UART or telemetry port wired to the Pi); a snapshot and restore that covers the whole vehicle state (hidden parameters are not covered, and there was no pre-test baseline); stale and future signing timestamps; the signing gate exit code; radio unplug and power-cut tests on the real Pixhawk; the 30 to 60 minute soak (the run was 25 minutes).

Notes for the lead (code side, not edited):

* `scripts/ardupilot/real_pixhawk/README.md`: its script table has no rows for `px_snapshot.py`, `px_restore.py`, `px_signing.py`, `px_common.py` or `px_signed_attack.py`. It also says "over the radio (about 2 KB/s)"; the 2 KB/s figure is the vendor setting, and the measured clean throughput is about 1.0 to 1.05 KB/s.
* `scripts/radio_test/laptop_ctl.py` and `campaign.py` still hard-code the old addresses as defaults.
* `px_restore.py` prints RESTORED after checking only the listed parameters. Its message could say so.
