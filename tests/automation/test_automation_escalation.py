"""Deterministic escalation classifier: paths, renames, added content, size, labels."""

from __future__ import annotations

import pytest
from automation_fakes import policy

from aegis_automation.escalation import added_lines, classify


def f(name: str, patch: str = "+x", **kw):
    return {"filename": name, "status": kw.pop("status", "modified"), "additions": kw.pop("add", 1),
            "deletions": kw.pop("dele", 0), "changes": kw.pop("changes", 1), "patch": patch, **kw}


def cats(files, labels=()):
    return {e.category for e in classify(files, labels, policy())}


def test_routine_change_has_no_escalation():
    assert cats([f("frontend/src/App.tsx"), f("tests/unit/test_x.py"), f("docs/DEVELOPMENT.md")]) == set()


def test_rename_out_of_a_sensitive_path_is_caught():
    assert "event_log_integrity" in cats([f("src/aegisflight/util/x.py",
                                            previous_filename="src/aegisflight/logging/store.py")])


@pytest.mark.parametrize("line,category", [
    ("server.bind(('0.0.0.0', 8000))", "network_listeners"),
    ("uvicorn.run(app, host=h)", "network_listeners"),
    ("KEY = '-----BEGIN RSA PRIVATE KEY-----'", "secrets_and_auth"),
    ("token = 'ghp_" + "A" * 36 + "'", "secrets_and_auth"),
    ("if link.may_reach_vehicle():", "vehicle_link_safety"),
])
def test_added_content_patterns(line, category):
    assert category in cats([f("src/aegisflight/backend/routes.py", patch=f"@@\n+{line}\n")])


def test_removed_lines_do_not_trigger_content_rules():
    assert cats([f("src/aegisflight/backend/routes.py", patch="@@\n-server.bind(('0.0.0.0', 1))\n")]) == set()


def test_field_claim_in_markdown_escalates_but_not_in_code():
    assert "evidence_claims" in cats([f("docs/RESULTS.md", patch="+Validated in FIELD trials")])
    assert "evidence_claims" not in cats([f("frontend/src/env.ts", patch="+const FIELD = 1")])


def test_size_limits_and_unverifiable_files():
    many = [f(f"frontend/src/c{i}.tsx") for i in range(41)]
    assert "size" in cats(many)
    assert "size" in cats([f("frontend/src/big.tsx", add=1300, changes=1300)])
    assert "unverifiable" in cats([f("docs/diagram.png", patch=None, changes=5)])
    assert "unverifiable" not in cats([f("old.png", patch=None, status="removed", changes=5)])


def test_labels():
    assert "labels" in cats([f("README.md")], ["needs:frozen-contract"])
    assert "labels" not in cats([f("README.md")], ["type:bug"])


def test_added_lines_parser():
    assert added_lines("+++ b/x\n+a\n-b\n c\n+d") == ["a", "d"]
    assert added_lines(None) == []
