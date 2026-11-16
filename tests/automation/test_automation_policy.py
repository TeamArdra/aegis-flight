"""The repository policy loads, and invalid policies fail closed."""

from __future__ import annotations

import copy
import tomllib

import pytest
from automation_fakes import REPO_ROOT, policy

from aegis_automation.policy import PolicyError, load_policy, parse_policy

POLICY_FILE = REPO_ROOT / ".github/automation/policy.toml"


def raw():
    with POLICY_FILE.open("rb") as fh:
        return tomllib.load(fh)


def test_repository_policy_is_valid():
    p = policy()
    assert p.default_branch == "main" and p.merge_method == "squash"
    assert set(p.required_ci_jobs) == {"ci-python", "ci-frontend"}
    assert {"P0", "P1"} <= set(p.blocking_severities)
    names = {c.name for c in p.categories}
    assert {"automation_governance", "secrets_and_auth", "vehicle_link_safety", "frozen_contracts",
            "event_log_integrity", "detector_metrics", "evidence_claims", "network_listeners",
            "dependencies"} <= names


@pytest.mark.parametrize("mutate,msg", [
    (lambda r: r.update(schema=2), "schema"),
    (lambda r: r.pop("review"), "missing table"),
    (lambda r: r["merge"].update(method="merge"), "squash"),
    (lambda r: r["review"].update(blocking_severities=["P0"]), "P1"),
    (lambda r: r["escalation"]["dependencies"].update(added_line_patterns=["(unclosed"]), "regex"),
    (lambda r: r["repository"].pop("review_workflow_path"), "review_workflow_path"),
])
def test_invalid_policies_raise(mutate, msg):
    data = copy.deepcopy(raw())
    mutate(data)
    with pytest.raises(PolicyError, match=msg):
        parse_policy(data)


def test_missing_file_raises(tmp_path):
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "nope.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("schema = [", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(bad)


def test_review_policy_matches_record_contract():
    """The reviewer instructions must describe the fields the record builder validates."""
    text = (REPO_ROOT / ".github/claude/review-policy.md").read_text(encoding="utf-8")
    for token in ("acceptance_criteria", "previous_findings", "findings", "READY",
                  "NON_BLOCKING", "BLOCKING", "INCOMPLETE"):
        assert token in text, token
