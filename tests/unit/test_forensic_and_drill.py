"""Unit tests for Cryptographic Forensic Export (W9) and Zero-TX Field Drills (W10)."""

from __future__ import annotations

import json
from pathlib import Path

from aegisflight.cli.main import main as cli_main
from aegisflight.core.enums import AttackType, Severity
from aegisflight.core.types import ThreatAssessment
from aegisflight.logging.anchors import AnchorWriter
from aegisflight.logging.store import EventStore
from aegisflight.reporting.forensic_report import build_forensic_report, render_forensic_html
from aegisflight.testing.field_drill import run_field_drill


def test_forensic_report_and_cli_export(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_ANCHOR_KEY", "anchor-hmac-secret")
    db = tmp_path / "flight.sqlite"
    store = EventStore(db)
    store.start_run("flight-1", label="sitl")
    aw = AnchorWriter(store, key="anchor-hmac-secret", interval_s=0.1)
    store.log_event(
        ThreatAssessment(
            t=12.4, wall_time=12.4, threat=True, threat_score=0.9,
            severity=Severity.CRITICAL, attack_type=AttackType.COMMAND_INJECTION,
            confidence=0.9, evidence=["sys42 blocked"],
        ),
        "flight-1",
    )
    store.log_action("flight-1", 12.5, "ips", "drop_uplink", "fc", "SYSID 42")
    aw.write_now("flight-1", force=True)
    store.close()

    rep = build_forensic_report(db, run_id="flight-1")
    assert rep["verified"] is True
    assert rep["events_chain"]["ok"] is True
    assert rep["actions_chain"]["ok"] is True
    assert rep["anchors"]["ok"] is True

    html_doc = render_forensic_html(rep)
    assert "AegisFlight Cryptographic Forensic Report" in html_doc
    assert "COMMAND_INJECTION" in html_doc

    out_json = tmp_path / "out.json"
    rc = cli_main(["export-report", "--db", str(db), "--out", str(out_json), "--format", "json"])
    assert rc == 0
    loaded = json.loads(out_json.read_text(encoding="utf-8"))
    assert loaded["verified"] is True


def test_field_drill_all_scenarios_pass_with_zero_tx() -> None:
    res = run_field_drill("all")
    assert res["ok"] is True
    assert res["zero_real_fc_tx"] is True
    assert res["passed"] == res["total"] == 4
