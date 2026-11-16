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

## 2026-11-02: randomised campaign, batch 1 of 6 (brief "Results log", standing instruction)

Brief items used: the Results-log entry "Real-Pixhawk randomised campaign batch 1 of 6: px1_passive_unsigned (2026-11-02)"; the standing instruction (record each batch, cite the artifact or command for every figure, keep the same sections, conservative wording); lessons 1 to 8, which were checked and are unchanged, with new lessons 18 to 20 added from this batch. The figures were checked against the run's output files `C:/afsitl/px_campaign_px1_passive_unsigned.json`, `C:/afsitl/px_events_px1_passive_unsigned.txt` and `C:/afsitl/run_px1.log`.

| File | What changed |
|---|---|
| `docs/RADIO_TEST_RESULTS.md` (CRLF kept) | New subsection "Randomised attack campaign on the real Pixhawk: batch 1 of 6": setup and command, schedule, per-event table, what the batch shows, restore state, limits. Marked as batch 1 of 6, with no campaign-level judgement. The Rig row was corrected: the GPS fix varied by session (no fix in batch 1), and the firmware is ArduCopter 4.7.1 (version word 67503103, from the 2026-10-31 snapshot); the row had said "not recorded". Limits bullet and two Findings rows added (the GNSS masking; the missing per-event bridge counters). The "Not run" list now says batches 2 to 6 are not recorded yet. |
| `docs/REAL_PIXHAWK_TEST.md` | Rig row: the GPS fix varied by session. Safety rule 2: the campaign driver stops when armed. New safety rule 9: the forged commands change the real vehicle's mode, so check and restore it. Software: campaign notes. Run order: step 15. Lesson 9: `px_campaign.py` uses the hub. New lessons 18 (a loopback status endpoint cannot be read from another host), 19 (`~` in a local shell expands on the laptop) and 20 (a persistent alert can hide momentary ones). Not run: batches 2 to 6. Sections 8 and 9: pointers to the masking finding and to the campaign results. New section 11: how to run the campaign, the scripts, the output paths, batch 1 marked as 1 of 6. |
| `docs/WORKLOG.md` | This entry. |

Not changed in this pass, because the task was limited to the three files above: `docs/RADIO_TEST.md` (campaign status in the phase lines), `docs/INLINE_IPS.md`, `docs/MINIMAL_BUILD.md`, `docs/README.md`, `README.md`, `docs/DETECTION.md`. No new document was created. `src/`, `tests/`, `scripts/` and `configs/` were not edited.

Points found while checking the artifacts, not resolved here (for the lead):

1. Every status read the driver made from the laptop was refused (`WinError 10061`), for all ten events and the final check. The per-event bridge counters are therefore missing from `C:/afsitl/px_campaign_px1_passive_unsigned.json`. The driver reads the Pi's LAN address, and the bridge's status server binds 127.0.0.1 by default (`src/aegisflight/cli/main.py`). This is code side and was not edited. The brief did not mention it.
2. Alert timing: the brief's "5 to 9 s after each event started" does not match the bridge event log (first TELEMETRY_MANIPULATION row 3.1 s after the alt_bias start and 3.3 s after the batt_jump start) or the ground announcement texts (4.6 s and 4.9 s). Both sets are in the subsection. The record does not explain the difference.
3. The driver's docstring says 9 events. Its code schedules 10.
4. The bridge end-of-run status reports 1,633 analyser decisions; the event log has 88 rows. The record does not say how the two relate.
5. The bridge's state read SAFE_HOLD at the end of a passive run, and "AEGIS: safe_hold" texts recur through it. Not explained, not investigated.
6. The brief says "params, mission and firmware verified byte-identical". The subsection states only what the record supports: the listed parameters and the mission (dry run, 0 changed), and the file changed by `fw_tamper` restored byte-identical. The brief does not say which firmware was compared with the Pixhawk.

Still open, and not marked done: batches 2 to 6 of the campaign (not recorded); the GPS false-alarm issue (user decision, not fixed); the new masking finding under a sustained GNSS condition (not fixed); the status-read defect in the driver (not fixed); the campaign scripts `px_campaign.py`, `px_fc_proxy.py`, `px_proxy_ctl.py` and `run_px_campaign.sh` are uncommitted (lead).

## 2026-11-02: randomised campaign, batches 2 and 3 of 6 (brief "Results log", standing instruction)

Brief items used: the Results-log entries "Real-Pixhawk randomised campaign batch 2 of 6: px2_advisory_unsigned" and "batch 3 of 6: px3_active-ips_unsigned"; the "Bug found and FIXED after batch 1" paragraph; the standing instruction (cite the artifact for every figure, same sections, conservative wording, no campaign-level claim). The figures were checked against `C:/afsitl/px_campaign_px2_advisory_unsigned.json`, `C:/afsitl/px_events_px2_advisory_unsigned.txt`, `C:/afsitl/px_campaign_px3_active-ips_unsigned.json` and `C:/afsitl/px_events_px3_active-ips_unsigned.txt`. Batch 1's figures were rechecked against its files (88 event rows, 45 texts, 13 `safe_hold`, the four mode changes) and matched the write-up.

| File | What changed |
|---|---|
| `docs/RADIO_TEST_RESULTS.md` (CRLF kept) | Subsections added under batch 1: batch 2 (advisory) and batch 3 (active-ips), each with setup and command, schedule, per-event table, what the batch shows, restore state and limits. Batch 3 has a per-event counter table. Batch 1 corrected and extended: its counters are described as unavailable (status read refused), not as zero; the status-read defect is marked fixed before batch 3; a start-of-run mode-log note and a later "battery collapse" row added; the driver cosmetic bug marked fixed. Rig row: no fix in batches 1 to 3. Findings: the masking and counter rows updated, five rows added. "Not run" and limits now say batches 4 to 6 are pending. Judgement table unchanged. |
| `docs/REAL_PIXHAWK_TEST.md` | Rig row; safety rule 9 (mode changes in batches 2 and 3); lessons 18 and 20 (batch 2 ran before the status fix; batch 3 has counters; masking reproduced); section 7, 8 and 9 pointers; section 11 retitled "batches 1 to 3 of 6", with the batch 2 and 3 labels and the `--allow-unsigned` note, and the counter note updated. |
| `docs/RADIO_TEST.md` (CRLF kept) | Banner: batches 1 to 3 recorded, 4 to 6 pending. Phase 3, 4 and 5 status lines extended with the batch 2 and 3 results. The phase 4 line and the phase 4 judgement row said force-disarm and replay were not announced; that is now marked as true for the first (invalid) runs only, because the valid campaign batches announced both. All phases stay NOT PASS as written. Section 11 summary extended. |
| `docs/WORKLOG.md` | This entry. |

Not changed: `README.md` (its link text for the real-Pixhawk runs still describes the 2026-10-31 runs only), `docs/INLINE_IPS.md`, `docs/DETECTION.md`, `docs/README.md`. `src/`, `tests/`, `scripts/` and `configs/` were not edited. No rig run, no SSH, no commit.

Points found while checking, not resolved here (for the lead):

1. The lead's summary gives batch 3 as 88 % of 88 decisions DOS-class, and batch 2 as 76 of 89. The files give 77 of 88 (87.5 %) for batch 3, and 77 of 89 for batch 2 (the 76 leaves out one DOS HIGH "battery collapse" row). The docs use the file counts.
2. Batch 3: the bridge announced "blocked RETURN_TO_LAUNCH sys255 x2" and "blocked LAND sys255 x2", with two burst drops in each window, yet the vehicle changed mode both times. The record does not give the copies sent per event. Not explained.
3. Batch 3: the per-event drop changes (start to end of window) add to 375. The forged LAND and force-disarm windows overlap by about 5 s, so 3 frames are counted twice. The bridge total is 372. The lead's per-event figures (6, 3, 360, 2) are these windowed changes.
4. Batch 3: `policy.rewritten` 11 is linked to the proxy's alt_bias rewrite, but the bridge also logged `sanitize_alt` in the same window, so the counter may include bridge-side rewrites. Batch 2's final status shows `rewritten` 0, and the proxy's batch 2 count is not in the record.
5. In all three batches the mode log starts with ALT_HOLD at 0.1 s and returns to STABILIZE at about 3 s. The cause is not in the record. Batch 1's write-up did not mention it (now added to its limits).
6. Batch 3: the bridge summary says LOITER engaged, and `counter_frames_sent` is 1, but the driver's mode log has no LOITER change. Not investigated.
7. Batches 2 and 3: the schedule list in the driver JSON starts about 6 s before the actual event starts (forged RTL 41.3 s against 47.6 s). Not explained. The docs use the actual starts.
8. Batch 2: ground texts arrive about 1.5 to 2 s after the matching bridge rows. Batch 3's texts match the rows to about 0.1 s. Not explained.
9. "Pixhawk verified clean afterwards" for batches 2 and 3 is the lead's record. The restore dry run was not re-run in this pass.
10. Not done: `README.md` and `docs/INLINE_IPS.md` have no campaign note. Say if you want one.

## 2026-11-02: correction pass, batches 2 and 3 (lead's clarifications)

Brief items used: "Clarifications for batch 2-3 open points (lead, 2026-11-02)", points 1 to 4. Checked against the driver code (`scripts/ardupilot/real_pixhawk/px_campaign.py`, `src/aegisflight/mitigation/inline_policy.py`, read only) and the run records `C:/afsitl/px_campaign_*.json` and `C:/afsitl/px_events_*.txt` (read only).

| File | What changed |
|---|---|
| `docs/RADIO_TEST_RESULTS.md` (CRLF kept) | Batch 1 schedule paragraph: planned and actual times separated. Batch 2 and 3 schedule paragraphs: the time-base offset explained. Mode-log notes in batches 1 to 3: the ALT_HOLD/STABILIZE pair is the replay capture. Batch 3: the sysid-255 rows, the replay row, the bullets and the limits rewritten (three copies sent, the counts imply one passed, the burst rule explained). Findings: three rows resolved (copy count, dropped_burst, mode-log entries), one row added (schedule offset). |
| `docs/REAL_PIXHAWK_TEST.md` | Safety rule 9 (sysid-255 wording); section 11 gains three reading notes (planned vs `t_start`, the mode-log entries, the copy counts). |
| `docs/WORKLOG.md` | This entry. |

Each point:

1. **Fixed.** The "blocked x2, yet mode changed" framing no longer reads as a binary. The lead's arithmetic holds: `start_event` in `px_campaign.py` sends three identical copies for forged LAND, forced disarm, the RTL spoof and the spoofed LAND, so two drops with a mode change means one copy passed. The code gives the mechanism: `dropped_burst` counts a byte-identical sensitive command repeated within `cadence_s` (0.05 s by default, `_command_rule` in `inline_policy.py`), and sysid 255 is in the default trusted sysids (255, 254). The record does not show which copy passed; this is inferred from the counts. The other events were re-checked: forged LAND and forced disarm give 6 untrusted-control drops for 6 copies (the windows overlap; all blocked). The replay was sent twice, not three; both copies were dropped (1 replay, 1 burst) and the mode did not change, so "blocked" was already right and the row now states both drops. Batches 1 and 2 (passive, advisory) have no drops, so there is no binary-mischaracterization there.
2. **Fixed.** The ALT_HOLD at 0.1 s and STABILIZE at about 3 s is the `capture_replay()` setup (`px_campaign.py`, lines 154 to 158). It is now written as intentional test setup in all three batches, and the open row is explained.
3. **Fixed.** The JSON `schedule` is the planned time; `events[].t_start` is the actual time. Batch 1's table already used `t_start`, and its note now says so. The batch 2 and 3 sentences that said the record does not explain the offset are replaced: the offset is the time base. `t0` is set before `capture_replay()` (about 6 s of pumping), while the schedule is measured from `tstart`, which is set after it. Measured offsets: batch 1 6.1 to 7.3 s; batch 2 6.1 to 7.0 s except forged_land at 9.1 s; batch 3 6.0 to 6.5 s. The brief's "5 to 7 s" was slightly low. The batch 2 forged_land delay is not traced.
4. **Confirmed; text unchanged.** Batch 3's events file has 88 decision rows: 72 DOS SUSPICIOUS and 5 DOS CRITICAL, so 77 of 88 = 87.5 %. All 77 DOS rows cite "GNSS fix never acquired". Batch 2, from the same check: 77 of 89 DOS-class.

Not changed, and for the lead:
- Batch 4 and later are untouched.
- The three earlier open items for batches 1 to 3 in the entry above (items 2, 5 and 7) are now resolved by points 1, 2 and 3 here. The old text is kept as history.
- The 10-31 active-ips and signed runs were made with other scripts (`px_attack.py`, `px_signed_attack.py`; neither has the three-copy loop). Their doc text was not changed, because their per-event copy counts were not checked in this pass.
- The brief's statement that the three-copy pattern applies to every forged-command event is not right for the replay, which sends two copies.
- `RADIO_TEST.md`, `INLINE_IPS.md` and `README.md` were searched for the same batch 2 and 3 sysid-255 wording; none was found, so they were not edited.
- Not re-run: the restore dry run and the "Pixhawk verified clean" statements for batches 2 and 3 (the lead's record).
- No rig run, no SSH, no commit, and no edits to `src/`, `tests/`, `scripts/` or `configs/`.

## 2026-11-17: GitHub `main` merged into the management-channel and performance branch; signed-downlink fix; campaign batches 4 to 6 recorded

Branch `integration/main-plus-mgmt-perf` (from `work/mgmt-channel-and-perf` at `b3ae666`, plus `origin/main` at `d6b00b6`). Nothing was pushed.

| What | Detail |
|---|---|
| Merge | `origin/main` merged with two text conflicts, both resolved keeping both sides: `README.md` (step 3 wording: receive-only rule plus the 1,500 s proxied soak) and `src/aegisflight/hal/inline_ips.py` (imports; `set_mode` keeps the management channel's `origin` argument and the receive-only refusal). |
| Code | `MavlinkFrameParser`, `LiveMavlinkSource` and the bridge analyser accept `unsigned_allowed_sysids`; the bridge passes its vehicle sysids. Cause and scope: `docs/REAL_PIXHAWK_TEST.md`, section 11. Tests: `tests/unit/test_signed_downlink_telemetry.py` (6). |
| Docs | `docs/REAL_PIXHAWK_TEST.md` section 11 (all 6 batches, the gap, the fix), sections 7 and 9; `docs/RADIO_TEST_RESULTS.md` (batches 4 to 6, limits line); `docs/INLINE_IPS.md` (proxied-link note); `docs/README.md` (index entries for `MGMT_CHANNEL.md` and `PERFORMANCE.md`). |

Checks run on the merged tree:

* `python -m pytest`: 1455 passed, 11 skipped, 0 failed.
* `ruff check src tests scripts backend`: all checks passed.
* `aegis benchmark --out <scratch> --no-figures`: TP / FP / TN / FN 6535 / 4 / 16826 / 65, the committed line. The edit touches `src/aegisflight/sources/`, so this was required.

Not done: the frontend tests and build (`frontend/node_modules` is not installed here, and installing it downloads packages); a bench re-run of the signed campaign after the fix; the intermittent bridge test of the team's fix list (not reproduced or changed).

## 2026-11-17: software replay of the signed-link detection gap

New `scripts/ardupilot/real_pixhawk/signed_downlink_replay.py`: the real bridge, a synthetic unsigned ArduPilot-style downlink shaped like the bench, a +40 m altitude bias. n = 10 per arm: unsigned 10/10 detected, signed with the fix 10/10 (median 0.38 s), signed without the fix 0/10; no alert in any warm-up. Results and the re-run command are in `docs/REAL_PIXHAWK_TEST.md`, section 11. The vehicle stream is synthetic, so this is a software replay and not a bench result; the signed active-ips bench run is still to do.

## 2026-11-17: vehicle uplink filter (proposal and implementation on `feat/vehicle-uplink-filter`)

New `docs/VEHICLE_UPLINK_FILTER.md` and the code behind it: `--vehicle-uplink-filter` on `aegis ips-bridge`, `InlineIpsBridge(vehicle_filter=...)` and `InlinePolicy.uplink_filter_only`. It drops forged / unsigned / wrong-key / replayed control frames from the GCS side before the flight controller on a vehicle link where `active-ips` is refused, never changes the downlink, never sends a counter-command, needs a signing key, cannot be combined with `active-ips`, and is fixed for the run (no status-API, radio or `set_mode` switch). 14 unit tests (`tests/unit/test_vehicle_uplink_filter.py`). Not agreed with the team (it touches the receive-only boundary of `AGENTS.md` section 5) and not run against the Pixhawk: the document lists the decisions and the bench tests that are still needed.
