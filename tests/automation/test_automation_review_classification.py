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
