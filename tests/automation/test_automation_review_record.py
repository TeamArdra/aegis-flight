"""Deterministic verdicts and record integrity for the trusted review record."""

from __future__ import annotations

import json
import re

import pytest
from automation_fakes import HEAD, finding, make_record, model_output

from aegis_automation import review_record as rr


def test_verdicts_follow_findings_not_the_models_word():
    assert make_record(model_output())["verdict"] == "READY"
    assert make_record(model_output([finding("R1", "P3")]))["verdict"] == "READY"
    assert make_record(model_output([finding("R1", "P2")]))["verdict"] == "NON_BLOCKING"
    assert make_record(model_output([finding("R1", "P1")]))["verdict"] == "BLOCKING"
    assert make_record(model_output([finding("R1", "P0")]))["verdict"] == "BLOCKING"


def test_lenient_model_verdict_is_overridden_and_noted():
    rec = make_record(model_output([finding("R1", "P1")], verdict="READY"))
    assert rec["verdict"] == "BLOCKING"
    assert any("overridden" in p for p in rec["problems"])


def test_stricter_model_verdict_than_findings_is_incomplete():
    rec = make_record(model_output([], verdict="BLOCKING"))
    assert rec["verdict"] == "INCOMPLETE" and rec["valid"] is False


@pytest.mark.parametrize("outcome", ["failure", "cancelled", "skipped"])
def test_failed_runs_are_error(outcome):
    rec = make_record(outcome=outcome)
    assert rec["verdict"] == "ERROR" and rec["valid"] is False


def test_missing_or_malformed_output_is_incomplete():
    meta = {"repository": "o/r", "pr_number": 1, "head_sha": HEAD}
    assert rr.build_record(output_text=None, outcome="success", meta=meta)["verdict"] == "INCOMPLETE"
    assert rr.build_record(output_text="{not json", outcome="success", meta=meta)["verdict"] == "INCOMPLETE"


@pytest.mark.parametrize("mutate", [
    lambda o: o.update(extra="x"),                                  # unknown key
    lambda o: o.pop("acceptance_criteria"),                         # missing key
    lambda o: o.update(p1=1),                                       # counts disagree
    lambda o: o["findings"].append(finding("R1", "P3")),            # duplicate id (with R1 present)
    lambda o: o["findings"].append({**finding("X9", "P2")}),        # bad id
    lambda o: o["findings"].append({**finding("R7", "P9")}),        # bad severity
    lambda o: o.update(verdict="INCOMPLETE"),
    lambda o: o.update(escalate="yes"),
    lambda o: o["acceptance_criteria"].append({"criterion": "z", "status": "maybe"}),
])
def test_malformed_or_inconsistent_output_is_incomplete(mutate):
    out = model_output([finding("R1", "P3")])
    mutate(out)
    rec = make_record(out)
    assert rec["verdict"] == "INCOMPLETE"


def test_status_mapping_keeps_the_remediation_gate_contract():
    """claude-remediate.yml parses `P0:a P1:b P2:c P3:d` from the status description."""
    pattern = re.compile(r"P0:([0-9]+) P1:([0-9]+) P2:([0-9]+) P3:([0-9]+)")
    counts = {"p0": 0, "p1": 2, "p2": 1, "p3": 4}
    state, desc = rr.status_for("BLOCKING", counts)
    assert state == "failure" and pattern.search(desc).groups() == ("0", "2", "1", "4")
    assert rr.status_for("NON_BLOCKING", counts | {"p1": 0})[0] == "success"
    assert rr.status_for("READY", dict.fromkeys(counts, 0))[0] == "success"
    assert rr.status_for("ERROR", counts)[0] == "error"
    assert rr.status_for("INCOMPLETE", counts)[0] == "error"


def test_untrusted_text_is_neutralised():
    rec = make_record(model_output([finding("R1", "P2", title="@everyone <!-- hide --> | `rm`\nnext")]))
    title = rec["findings"][0]["title"]
    assert "@everyone" not in title and "<!--" not in title and "\n" not in title and "`" not in title


def test_validate_record_detects_tampering():
    rec = make_record(model_output([finding("R1", "P1")]))
    assert rr.validate_record(rec) == []
    rec["counts"]["p1"] = 0
    assert any("counts" in e for e in rr.validate_record(rec))
    assert rr.validate_record({"schema": "other"})
    assert rr.validate_record([]) == ["record is not an object"]


def test_schema_is_cli_safe_and_matches_validation():
    text = json.dumps(rr.OUTPUT_SCHEMA)
    assert "'" not in text  # passed inside a single-quoted CLI argument
    keys = set(model_output())
    assert set(rr.OUTPUT_SCHEMA["required"]) <= keys <= set(rr.OUTPUT_SCHEMA["properties"])


def test_cli_build_writes_record_and_outputs(tmp_path, monkeypatch):
    out_file = tmp_path / "out.txt"
    summary = tmp_path / "summary.md"
    env = {
        "GITHUB_REPOSITORY": "TeamArdra/techfest-2026", "PR_NUMBER": "42", "HEAD_SHA": HEAD,
        "BASE_SHA": "b" * 40, "BASE_REF": "main", "GITHUB_RUN_ID": "200", "GITHUB_RUN_ATTEMPT": "1",
        "MODEL": "claude-sonnet-5-5", "MODE": "incremental", "PREV": "d" * 40, "DEEP": "false",
        "RESULT": json.dumps(model_output([finding("R1", "P2")])), "OUTCOME": "success",
        "GITHUB_OUTPUT": str(out_file), "GITHUB_STEP_SUMMARY": str(summary),
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert rr.main(["build", "--out", str(tmp_path / "rec")]) == 0
    record = json.loads((tmp_path / "rec" / "review-record.json").read_text())
    assert record["verdict"] == "NON_BLOCKING" and record["reviewer"]["run_id"] == 200
    assert record["mode"] == "incremental" and record["previous_reviewed_sha"] == "d" * 40
    outputs = dict(line.split("=", 1) for line in out_file.read_text().splitlines())
    assert outputs == {"state": "success", "description": "P0:0 P1:0 P2:1 P3:0",
                       "verdict": "NON_BLOCKING", "escalate": "false"}
    assert "NON_BLOCKING" in summary.read_text()


def test_cli_build_rejects_a_bad_head_sha(tmp_path, monkeypatch):
    monkeypatch.setenv("HEAD_SHA", "not-a-sha")
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    assert rr.main(["build", "--out", str(tmp_path)]) == 2
