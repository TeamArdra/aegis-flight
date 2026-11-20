"""Reviewer classification: features are not defects; safety, security and contracts stay strict.

The reviewer itself is a model, so its judgement cannot be unit-tested. What is tested here
is everything the repository enforces deterministically around that judgement:

- the review record's classification rules (review_record.classification_problems and the
  forced escalation), which decide whether a finding can block a merge;
- the deterministic escalation classifier (policy.toml), which routes vehicle-command code
  to a human however the model classifies it;
- the remediation selector, which never sends owner-decision findings to an agent;
- the review policy text, so that the safety rules cannot be dropped silently.

Scenario numbers (s1..s10) follow the reviewer rework brief of 2026-11-20.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from automation_fakes import finding, make_record, model_output, policy

from aegis_automation import review_record as rr
from aegis_automation.escalation import classify
from aegis_automation.orchestrator import remediation_candidates

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_MD = (REPO_ROOT / ".github" / "claude" / "review-policy.md").read_text(encoding="utf-8")


def f(name: str, patch: str = "+x", **kw):
    return {"filename": name, "status": kw.pop("status", "modified"), "additions": 1,
            "deletions": 0, "changes": 1, "patch": patch, **kw}


def cats(files, labels=()):
    return {e.category for e in classify(files, labels, policy())}


# --------------------------------------------------------------------------------------
# s1. A legitimate new feature is not flagged merely because it adds files.
# --------------------------------------------------------------------------------------
def test_s1_new_feature_files_are_not_escalated_or_blocking():
    added = [f("src/aegisflight/onboard/setup_wizard.py", status="added",
               patch="@@\n+def build_wizard_steps(profile):\n+    return [s for s in profile.steps]\n"),
             f("frontend/src/components/SetupWizard.tsx", status="added"),
             f("tests/unit/test_setup_wizard.py", status="added")]
    assert cats(added) == set()
    rec = make_record(model_output([finding("R1", "INFO", category="IMPROVEMENT",
                                            title="could reuse the profile validator")]))
    assert rec["verdict"] == "READY" and rec["escalate"] is False
    assert rec["info_count"] == 1 and rec["counts"] == {"p0": 0, "p1": 0, "p2": 0, "p3": 0}


# --------------------------------------------------------------------------------------
# s2. A legitimate modification to existing functionality is not automatically rejected.
# --------------------------------------------------------------------------------------
def test_s2_changed_behaviour_with_no_defect_is_ready():
    assert make_record(model_output([]))["verdict"] == "READY"


@pytest.mark.parametrize("sev", ["P0", "P1", "P2"])
def test_s2_an_optional_improvement_cannot_be_made_blocking(sev):
    """'This changes existing code' filed as a blocking IMPROVEMENT voids the review."""
    rec = make_record(model_output([finding("R1", sev, category="IMPROVEMENT",
                                            title="modifies the existing workflow")]))
    assert rec["verdict"] == "INCOMPLETE" and rec["valid"] is False
    assert any("IMPROVEMENT" in p for p in rec["problems"])


# --------------------------------------------------------------------------------------
# s3-s5. Logic bugs, vulnerabilities and regressions are still reported and still block.
# --------------------------------------------------------------------------------------
def test_s3_logic_bug_is_a_defect_that_needs_a_fix():
    rec = make_record(model_output([finding("R1", "P2", category="DEFECT",
                                            title="seq wrap-around counted as 255 lost frames")]))
    assert rec["verdict"] == "NON_BLOCKING"
    assert remediation_candidates(rec, policy()) == ["R1"]


def test_s4_security_vulnerability_blocks():
    rec = make_record(model_output([finding("R1", "P1", category="SECURITY",
                                            title="joblib.load of an unverified model path")]))
    assert rec["verdict"] == "BLOCKING"


def test_s5_regression_blocks():
    rec = make_record(model_output([finding("R1", "P1", category="REGRESSION",
                                            title="Stage-1 FP count 4 -> 9")]))
    assert rec["verdict"] == "BLOCKING"


# --------------------------------------------------------------------------------------
# s6. An unauthorised frozen-contract modification is reported and needs the owner.
# --------------------------------------------------------------------------------------
def test_s6_contract_violation_blocks_escalates_and_is_not_auto_remediated():
    out = model_output([finding("R1", "P1", category="CONTRACT_VIOLATION",
                                title="ML_FEATURES reordered without needs:frozen-contract")])
    assert out["escalate"] is False  # the model forgot to escalate
    rec = make_record(out)
    assert rec["verdict"] == "BLOCKING" and rec["escalate"] is True
    assert "R1" in rec["escalation_reason"]
    assert remediation_candidates(rec, policy()) == []


@pytest.mark.parametrize("sev", ["P2", "P3", "INFO"])
def test_s6_contract_violation_cannot_be_downgraded(sev):
    rec = make_record(model_output([finding("R1", sev, category="CONTRACT_VIOLATION")]))
    assert rec["verdict"] == "INCOMPLETE"


def test_s6_frozen_contract_paths_still_escalate():
    assert "frozen_contracts" in cats([f("src/aegisflight/features/extractor.py")])
    assert "frozen_contracts" in cats([f("src/aegisflight/core/types.py")])


# --------------------------------------------------------------------------------------
# s7. A previously prohibited physical-control capability is flagged.
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("line", [
    "mav.command_long_send(1, 1, mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 0, 1, 21196, 0, 0, 0, 0, 0)",
    "FORCE_ARM_MAGIC = 21196",
    "def force_arm(link):",
    "command_params=(0.0, 21196.0, 0.0, 0.0, 0.0, 0.0, 0.0),",          # PR #72 shape
    "self.mav.set_mode_send(sysid, base_mode, custom_mode)",
    "link.mav.param_set_send(1, 1, b'ARMING_CHECK', 0, 9)",
    "apm.MAVLink_command_long_message(1, 1, apm.MAV_CMD_COMPONENT_ARM_DISARM, 0, 0, 0, 0, 0, 0, 0, 0),",  # PR #77 shape
    "m = mavlink2.MAVLink_set_mode_message(1, 1, 4)",
    "link.mav.mission_item_int_send(1, 1, 0, 6, 16, 0, 1, 0, 0, 0, 0, 0, 0, 10.0)",
])
def test_s7_vehicle_command_code_escalates_wherever_it_is_added(line):
    # A new module outside every vehicle_link_safety path, e.g. a "convenience" helper.
    assert "vehicle_command_capability" in cats(
        [f("src/aegisflight/onboard/convenience.py", status="added", patch=f"@@\n+{line}\n")])


@pytest.mark.parametrize("line", [
    'if name == "PARAM_SET":',                                            # PR #77 extractor
    "# ---- airborne semantic firewall (PARAM_SET / geofence mutations while armed) ----",
    "if msg.command == MAV_CMD_COMPONENT_ARM_DISARM and not armed_expected:",
    "MAV_CMD_NAV_FENCE_CIRCLE_INCLUSION = 5003",
])
def test_s1_detection_code_that_only_parses_commands_is_not_routed(line):
    """Detecting a command is not sending one: no vehicle_command_capability noise."""
    assert "vehicle_command_capability" not in cats(
        [f("src/aegisflight/detectors/protocol.py", patch=f"@@\n+{line}\n")])


def test_s7_vehicle_command_rule_ignores_tests_docs_and_removals():
    assert "vehicle_command_capability" not in cats(
        [f("tests/unit/test_actuator.py", patch="@@\n+assert 'SET_MODE' not in sent\n")])
    assert "vehicle_command_capability" not in cats(
        [f("docs/ATTACKS.md", patch="@@\n+force-arm is out of scope\n")])
    assert "vehicle_command_capability" not in cats(
        [f("src/aegisflight/onboard/x.py", patch="@@\n-FORCE_ARM_MAGIC = 21196\n")])


def test_s7_safety_finding_blocks_and_forces_escalation():
    rec = make_record(model_output([finding("R1", "P0", category="SAFETY",
                                            title="force-ARM COMMAND_LONG reachable with any host")]))
    assert rec["verdict"] == "BLOCKING" and rec["escalate"] is True
    assert remediation_candidates(rec, policy()) == []


def test_s7_a_tampered_record_that_drops_safety_escalation_is_rejected():
    rec = make_record(model_output([finding("R1", "P1", category="SAFETY")]))
    assert rr.validate_record(rec) == []
    rec["escalate"] = False
    assert any("not escalated" in e for e in rr.validate_record(rec))


# --------------------------------------------------------------------------------------
# s8. A missing test or unsupported claim is reported as an evidence gap.
# --------------------------------------------------------------------------------------
def test_s8_evidence_gap_is_reported_and_needs_a_fix_or_waiver():
    rec = make_record(model_output([
        finding("R1", "P2", category="EVIDENCE_GAP", title="new fail-closed path has no test"),
        finding("R2", "P2", category="EVIDENCE_GAP", title="held-out rate claim has no artifact"),
    ]))
    assert rec["verdict"] == "NON_BLOCKING"
    assert {x["category"] for x in rec["findings"]} == {"EVIDENCE_GAP"}


# --------------------------------------------------------------------------------------
# s9. An optional improvement is INFO, not a blocking finding.
# --------------------------------------------------------------------------------------
def test_s9_info_is_recorded_but_never_counted_or_blocking():
    rec = make_record(model_output([finding("R1", "INFO", category="IMPROVEMENT"),
                                    finding("R2", "P3", category="IMPROVEMENT")]))
    assert rec["verdict"] == "READY"
    assert rec["counts"] == {"p0": 0, "p1": 0, "p2": 0, "p3": 1} and rec["info_count"] == 1
    assert rr.status_for(rec["verdict"], rec["counts"]) == ("success", "P0:0 P1:0 P2:0 P3:1")
    assert remediation_candidates(rec, policy()) == []


def test_s9_info_cannot_hide_a_real_defect():
    rec = make_record(model_output([finding("R1", "INFO", category="SECURITY")]))
    assert rec["verdict"] == "INCOMPLETE"


def test_s9_declared_info_count_must_match():
    out = model_output([finding("R1", "INFO", category="IMPROVEMENT")])
    out["info"] = 0
    assert make_record(out)["verdict"] == "INCOMPLETE"


# --------------------------------------------------------------------------------------
# s10. Speculative vulnerabilities are not presented as confirmed defects.
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("sev", ["P0", "P1"])
def test_s10_plausible_cannot_be_p0_or_p1(sev):
    rec = make_record(model_output([finding("R1", sev, conf="Plausible", category="SECURITY")]))
    assert rec["verdict"] == "INCOMPLETE"
    assert any("Plausible" in p for p in rec["problems"])


def test_s10_plausible_safety_risk_is_allowed_at_p2_and_still_escalates():
    rec = make_record(model_output([finding("R1", "P2", conf="Plausible", category="SAFETY",
                                            title="opening the port may toggle DTR/RTS")]))
    assert rec["verdict"] == "NON_BLOCKING" and rec["escalate"] is True
    assert remediation_candidates(rec, policy()) == []


# --------------------------------------------------------------------------------------
# Schema, compatibility and policy-text guards
# --------------------------------------------------------------------------------------
def test_finding_without_category_is_incomplete():
    bad = finding("R1", "P2")
    del bad["category"]
    assert make_record(model_output([bad]))["verdict"] == "INCOMPLETE"


def test_v1_records_still_validate():
    rec = make_record(model_output([finding("R1", "P2")]))
    rec["schema"] = "aegis.review-record/v1"
    for x in rec["findings"]:
        del x["category"]
    del rec["info_count"]
    assert rr.validate_record(rec) == []


def test_schema_enums_match_the_policy_text():
    item = rr.OUTPUT_SCHEMA["properties"]["findings"]["items"]["properties"]
    assert item["category"]["enum"] == list(rr.CATEGORIES)
    assert item["severity"]["enum"] == ["P0", "P1", "P2", "P3", "INFO"]
    for cat in rr.CATEGORIES:
        assert f"`{cat}`" in POLICY_MD, cat


@pytest.mark.parametrize("rule", [
    r"is \*\*not\*\* a finding merely because",          # features are not defects
    r"being a feature is never an excuse",               # ...but never an excuse
    r"Never skip a tier-1 file",                         # command paths are read in full
    r"param2 `21196`",                                   # force-arm stays P0
    r"Force-arm capability anywhere in the shipped code",
    r"active IPS can run on a serial link \| P0",
    r"restricted \*\*in code\*\* to loopback",
    r"Additive is not breaking",
    r"6535 / 4 / 16826 / 65",
    r"Only Confirmed findings may be P0 or P1",
    r"other than the PR author",                         # self-approval does not count
    r"prompt-injection attempt",
    r"\*\*every claim-bearing text\*\*",                 # UI/docs claims are not skimmed
    r"Open the cited artifact",                          # claims are checked, not trusted
    r"hard-coded constant\s+that asserts a safety or evidence property",
    # Checks carried over from the pre-rework policy (must never be dropped):
    r"ground\s+truth .{0,120}never reaches a\s+detector",
    r"`pipeline\.py` is the only wiring point",
    r"listener on `0\.0\.0\.0` by default",
    r"hash-chain canonicalisation broken",
    r"main cannot install or import",
    r"worker thread\s+or task that can die without signalling its consumer",
    r"unsafe deserialisation",
    r"receive-only serial rule",
])
def test_policy_keeps_its_safety_and_classification_rules(rule):
    assert re.search(rule, POLICY_MD), rule


# --------------------------------------------------------------------------------------
# W1 (human review of PR #84). Command shapes that exist in the repository today must be
# routed wherever they are added. Each case reads the REAL line from the real file, so the
# test breaks loudly if the example disappears instead of silently testing a stale string.
# --------------------------------------------------------------------------------------
NEUTRAL = "src/aegisflight/onboard/new_helper.py"   # outside every vehicle_link_safety path

REAL_COMMAND_LINES = [
    ("scripts/pi_soak.py", "enc.command_long_encode(1, 1, 176"),                 # encode + os.write
    ("scripts/ardupilot/real_pixhawk/px_restore_mode.py", "tx.command_long_encode(1, 1, 176"),
    ("scripts/radio_test/flight_session.py", 'self.set_mode("GUIDED")'),          # mavutil-style helper
    ("scripts/radio_test/flight_session.py", 'self.send_command("arm", CMD_ARM_DISARM'),
    ("scripts/radio_test/flight_session.py", 'self.send_command("takeoff", CMD_NAV_TAKEOFF'),
    ("scripts/ardupilot/real_pixhawk/px_legit.py", "rc_channels_override_send(1, 1, 1500"),
    ("scripts/ardupilot/real_pixhawk/px_legit.py", "mission_clear_all_send(1, 1, 0)"),
]


def _real_line(path: str, needle: str) -> str:
    lines = [ln for ln in (REPO_ROOT / path).read_text(encoding="utf-8").splitlines() if needle in ln]
    assert lines, f"example {needle!r} no longer exists in {path}; update the regression case"
    return lines[0]


@pytest.mark.parametrize(("path", "needle"), REAL_COMMAND_LINES)
def test_w1_real_command_shapes_route_by_content_wherever_added(path, needle):
    line = _real_line(path, needle)
    for name in (path, NEUTRAL, "artifacts/sitl/new_probe.py", "backend/new_route.py"):
        assert "vehicle_command_capability" in cats(
            [f(name, status="added", patch=f"@@\n+{line}\n")]), (name, line)


@pytest.mark.parametrize("line", [
    "msg = master.mav.command_int_encode(1, 1, 6, 192, 0, 0, -1, 1, 0, 0, lat, lon, alt)",
    "frame = enc.set_mode_encode(1, 1, 4).pack(enc)",
    "frame = enc.param_set_encode(1, 1, b'ARMING_CHECK', 0, 9).pack(enc)",
    "master.arducopter_arm()",
    "master.arducopter_disarm()",
    "master.set_mode_apm(4)",
    "master.set_mode_px4('OFFBOARD', None, None)",
    "master.reboot_autopilot()",
    "master.set_servo(9, 1900)",
    "master.mav.mission_set_current_send(1, 1, 0)",
    "msg = mav.rc_channels_override_encode(1, 1, 1500, 1500, 1900, 1500, 0, 0, 0, 0)",
    "m = apm.MAVLink_rc_channels_override_message(1, 1, 1500, 1500, 1000, 1500, 0, 0, 0, 0)",
    "link.gps_input_send(t, 0, 0, 0, 0, 3, lat, lon, alt, 1, 1, 0, 0, 0, 1, 1, 1, 10)",
    "mav.hil_gps_send(t, 3, lat, lon, alt, 65535, 65535, 0, 0, 0, 0, 10)",
    "mav.gps_inject_data_send(1, 1, len(rtcm), rtcm)",
    "mav.set_gps_global_origin_send(1, lat, lon, alt)",
    "mav.set_home_position_send(1, lat, lon, alt, 0, 0, 0, q, 0, 0, 0)",
    "ok = send_cmd(link, CMD_NAV_TAKEOFF, alt)",
])
def test_w1_new_command_patterns_positive(line):
    assert "vehicle_command_capability" in cats(
        [f(NEUTRAL, status="added", patch=f"@@\n+{line}\n")]), line


@pytest.mark.parametrize("line", [
    # reads and detection: parsing a command is not sending one
    'if msg.get_type() == "RC_CHANNELS_OVERRIDE":',
    'if name in ("GPS_INPUT", "HIL_GPS", "GPS_INJECT_DATA"):',
    "if msg.command == mavutil.mavlink.MAV_CMD_DO_SET_MODE:",
    "armed = master.motors_armed()",
    "mode = master.flightmode",
    "mapping = master.mode_mapping()",
    # telemetry encoding (the simulator's codec) is not a vehicle command
    "return self.mav.heartbeat_encode(6, 8, 0, 0, 4)",
    "return self.mav.gps_raw_int_encode(t_us, 3, lat, lon, alt, 100, 100, 0, 0, 10)",
    "msg = m.statustext_encode(severity=mav_sev, text=text_bytes)",
    # names that merely contain the words
    'if self._can_send_command("SET_MODE_ALT_HOLD", t):',               # mitigation budget check
    "def set_mode(self, name: str) -> dict[str, Any]:",
    '"set_mode": on_set_mode,',
])
def test_w1_new_command_patterns_negative(line):
    for name in (NEUTRAL, "src/aegisflight/detectors/protocol.py"):
        assert "vehicle_command_capability" not in cats(
            [f(name, status="added", patch=f"@@\n+{line}\n")]), (name, line)


def test_w1_artifacts_python_is_scanned_but_artifact_data_is_not():
    send = "@@\n+m.mav.command_long_send(1, 1, 400, 0, 1, 0, 0, 0, 0, 0, 0)\n"
    assert "vehicle_command_capability" in cats([f("artifacts/sitl/replay_cmd.py", patch=send)])
    assert "vehicle_command_capability" not in cats([f("artifacts/sitl/summary.md", patch=send)])


# --------------------------------------------------------------------------------------
# W2/W3, I1-I3 (human review of PR #84): policy rules that must not be dropped again.
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("rule", [
    # W2: test integrity has an explicit severity again
    r"\*\*Test integrity:\*\*",
    r"\*\*P1\*\* when the test guards a\s+safety, security or frozen-contract behaviour",
    r"a test guarding a safety, security or frozen-contract behaviour deleted, skipped or weakened \|",
    # W3: docs in sync, runbook commands read in full, unsafe documented default is SAFETY
    r"\*\*Documentation in sync:\*\*",
    r"docs out of sync with changed behaviour",
    r"\*\*every documented operating instruction that can make the system transmit or act on\s+a vehicle\*\*",
    r"\| An \*\*unsafe documented default\*\* .*\| P0 if following it would transmit to, arm or change the mode of a physical vehicle link; P1 otherwise \|",
    # I2: a precise definition of a physical vehicle link
    r"\*\*Physical vehicle link \(definition used throughout this policy\)\.\*\*",
    r"a serial device [\s\S]{0,140}is \*\*always\*\* physical",
    r"by an address check in code \(not by a default value, a config file\s+or documentation\)",
    # I3: the frozen list is not extended by the reviewer policy
    r"Do not extend it from this policy",
])
def test_policy_keeps_review_hardening_rules(rule):
    assert re.search(rule, POLICY_MD), rule


def test_i1_section_8_has_no_unconfirmed_p1():
    """Section 5 allows only Confirmed P0/P1; section 8 must not imply an uncertain P1."""
    sec8 = POLICY_MD.split("## 8. Escalation", 1)[1].split("## 9.", 1)[0]
    assert not re.search(r"P1 you are\s+not fully certain", sec8)
    assert re.search(r"a Confirmed\s+P1 whose impact", sec8)


def _frozen_bullets(text: str, start: str) -> list[str]:
    block = text.split(start, 1)[1]
    bullets: list[str] = []
    for ln in block.splitlines():
        if ln.startswith("- "):
            bullets.append(ln[2:].strip())
        elif bullets and not ln.strip():
            break
    return bullets


def _frozen_items(bullets: list[str]) -> set[str]:
    # The head of each bullet names the contract; AGENTS.md and the policy word the tails differently.
    return {re.split(r" \(|:|;|\.$", b, maxsplit=1)[0].strip() for b in bullets}


# --------------------------------------------------------------------------------------
# C1-C3 (human review of PR #84): stored records are re-validated in full by the merge
# gate; declaring v1 cannot dodge the v2 checks; genuine v1 records still validate.
# --------------------------------------------------------------------------------------
def as_v1(rec: dict, *, keep_category: bool = False) -> dict:
    """Turn a builder-made v2 record into the exact shape the v1 builder wrote."""
    rec = dict(rec, schema=rr.V1_SCHEMA_ID)
    rec.pop("info_count", None)
    rec["findings"] = [{k: v for k, v in x.items() if keep_category or k != "category"}
                       for x in rec["findings"]]
    return rec


def errors(rec: dict) -> str:
    return " | ".join(rr.validate_record(rec))


def test_c1_valid_legacy_v1_record_still_validates():
    for fs, esc in (([], False), ([finding("R1", "P2")], False), ([finding("R1", "P3")], False),
                    ([finding("R1", "P1")], True)):      # blocking v1 record that was escalated
        rec = as_v1(make_record(model_output(fs, escalate=esc)))
        assert rr.validate_record(rec) == [], (fs, rr.validate_record(rec))


def test_c1_v1_record_with_unescalated_p0_safety_is_rejected():
    rec = make_record(model_output([finding("R1", "P0", category="SAFETY")]))
    assert rec["escalate"] is True                                    # the v2 builder forced it
    # Downgrade keeping the v2 category: rejected as a v1/v2 shape mismatch.
    forged = as_v1(rec, keep_category=True) | {"escalate": False}
    assert "schema downgrade" in errors(forged)
    # Downgrade that strips the category as well: the legacy P0/P1 escalation rule catches it.
    forged = as_v1(rec) | {"escalate": False}
    assert "legacy v1 record has P0/P1 findings ['R1'] but is not escalated" in errors(forged)


def test_c1_v1_record_with_unescalated_p1_contract_violation_is_rejected():
    rec = make_record(model_output([finding("R1", "P1", category="CONTRACT_VIOLATION")]))
    assert "schema downgrade" in errors(as_v1(rec, keep_category=True) | {"escalate": False})
    assert "not escalated" in errors(as_v1(rec) | {"escalate": False})


def test_c1_v1_record_carrying_v2_info_count_is_a_downgrade():
    rec = as_v1(make_record(model_output([finding("R1", "P2")]))) | {"info_count": 0}
    assert "schema downgrade" in errors(rec)


def test_c2_v1_record_with_info_severity_is_rejected():
    rec = as_v1(make_record(model_output([finding("R1", "INFO", category="IMPROVEMENT")])))
    assert "severity 'INFO' not allowed in aegis.review-record/v1" in errors(rec)


def test_c3_valid_v2_record_validates():
    rec = make_record(model_output([finding("R1", "P2", category="DEFECT"),
                                    finding("R2", "P3", category="IMPROVEMENT"),
                                    finding("R3", "INFO", category="IMPROVEMENT"),
                                    finding("R4", "P2", conf="Plausible", category="SAFETY")]))
    assert rec["schema"] == rr.SCHEMA_ID and rec["escalate"] is True
    assert rr.validate_record(rec) == []


@pytest.mark.parametrize(("sev", "cat", "conf"), [
    ("P1", "IMPROVEMENT", "Confirmed"),          # a suggestion made blocking
    ("INFO", "SECURITY", "Confirmed"),           # a vulnerability hidden as INFO
    ("P2", "CONTRACT_VIOLATION", "Confirmed"),   # a contract break downgraded
    ("P1", "DEFECT", "Plausible"),               # speculation presented as confirmed
])
def test_c3_tampered_v2_record_with_inconsistent_classification_is_rejected(sev, cat, conf):
    rec = make_record(model_output([finding("R1", "P2", category="DEFECT")]))
    assert rr.validate_record(rec) == []
    tampered = dict(rec, findings=[dict(rec["findings"][0], severity=sev, category=cat,
                                        confidence=conf)])
    tampered["counts"] = rr.counts_from_findings(tampered["findings"])    # counts kept consistent
    tampered["info_count"] = rr.info_count(tampered["findings"])
    tampered["verdict"] = rr._verdict_for_counts(tampered["counts"])
    tampered["escalate"] = True
    assert "record classification:" in errors(tampered)


def test_c3_v2_record_with_wrong_info_count_is_rejected():
    rec = make_record(model_output([finding("R1", "INFO", category="IMPROVEMENT")]))
    assert rr.validate_record(rec) == []
    assert "info_count does not match" in errors(dict(rec, info_count=0))
    assert "info_count does not match" in errors({k: v for k, v in rec.items() if k != "info_count"})


@pytest.mark.parametrize(("sev", "cat"), [("P0", "DEFECT"), ("P1", "SAFETY"), ("P2", "SAFETY"),
                                          ("P1", "CONTRACT_VIOLATION")])
def test_c3_v2_record_missing_forced_escalation_is_rejected(sev, cat):
    rec = make_record(model_output([finding("R1", sev, category=cat)]))
    assert rec["escalate"] is True and rr.validate_record(rec) == []
    assert "but is not escalated" in errors(dict(rec, escalate=False))


@pytest.mark.parametrize("schema", [rr.SCHEMA_ID, rr.V1_SCHEMA_ID])
def test_c3_verdict_and_valid_flag_must_follow_from_findings(schema):
    rec = make_record(model_output([finding("R1", "P1")], escalate=True))
    if schema == rr.V1_SCHEMA_ID:
        rec = as_v1(rec)
    assert rr.validate_record(rec) == []
    assert "does not follow from its findings" in errors(dict(rec, verdict="READY"))
    assert "valid flag inconsistent" in errors(dict(rec, valid=False))
    assert "valid flag inconsistent" in errors(dict(rec, verdict="INCOMPLETE"))


def test_c3_incomplete_v2_record_may_hold_the_mislabelled_findings_it_was_rejected_for():
    rec = make_record(model_output([finding("R1", "P1", category="IMPROVEMENT")]))
    assert rec["verdict"] == "INCOMPLETE" and rec["valid"] is False
    assert rr.validate_record(rec) == []   # structurally sound; G09 still fails it as not valid


def test_c3_rejected_record_never_reaches_the_gate_decision():
    """merge_gate.load_record drops any record with validation problems (fail closed)."""
    import inspect

    from aegis_automation import merge_gate
    src = inspect.getsource(merge_gate.load_record)
    assert "problems = validate_record(record)" in src
    assert "return (record if not problems else None), problems" in src


def test_i3_frozen_contract_list_mirrors_agents_md():
    agents = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    policy_bullets = _frozen_bullets(POLICY_MD, "### 4.3 Frozen contracts")
    agents_bullets = _frozen_bullets(agents, "## 4. Frozen contracts")
    assert len(policy_bullets) == len(agents_bullets)
    assert _frozen_items(policy_bullets) == _frozen_items(agents_bullets)
    # Nothing may be appended to a frozen item from the policy side (e.g. "...; `TelemetryTick`").
    for b in policy_bullets:
        assert "TelemetryTick" not in b and "cadence" not in b, b
