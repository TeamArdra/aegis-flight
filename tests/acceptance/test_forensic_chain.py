"""Acceptance: the forensic log detects tampering, including across a rotation boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
from aegisflight.core.types import ThreatAssessment
from aegisflight.logging.rotation import rotate_sqlite_store
from aegisflight.logging.store import EventStore

scenarios("features/forensic_chain.feature")


def _assessment(t: float) -> ThreatAssessment:
    return ThreatAssessment(
        t=t, wall_time=1.0, threat=True, threat_score=0.7, severity=Severity.HIGH,
        attack_type=AttackType.GPS_SPOOFING, confidence=0.8, evidence=["e"],
        detector_scores={"physics_consistency": 0.9}, contributing_detectors=["physics_consistency"],
        integrity_status=IntegrityStatus.VALID, latency_ms=0.4, telemetry={}, is_alert=True,
    )


@pytest.fixture
def ctx() -> dict:
    return {}


def _rotated(ctx: dict) -> Path:
    return ctx["dir"] / "events.1.sqlite"


def _edit(path: Path, sql: str) -> None:
    st = EventStore(path)
    st.conn.execute(sql)
    st.conn.commit()
    st.close()


def _verify(path: Path):
    st = EventStore(path, read_only=True)
    try:
        return st.verify_chain()
    finally:
        st.close()


@given(parsers.parse("an event store with {n:d} events that has been rotated and then written to again"))
def rotated_store(ctx: dict, tmp_path: Path, n: int) -> None:
    st = EventStore(tmp_path / "events.sqlite")
    st.start_run("r1", label="bdd")
    for i in range(n):
        st.log_event(_assessment(float(i)), "r1")
    fresh, rotated = rotate_sqlite_store(st, max_bytes=1, max_rotations=3, run_id="r1")
    assert rotated
    for i in range(3):
        fresh.log_event(_assessment(100.0 + i), "r1")
    fresh.close()
    ctx["dir"] = tmp_path
    ctx["n"] = n


@then("every segment's event chain verifies")
def all_verify(ctx: dict) -> None:
    assert _verify(_rotated(ctx)).ok
    assert _verify(ctx["dir"] / "events.sqlite").ok


@then("the active segment records the closing hashes of the rotated segment")
def link_recorded(ctx: dict) -> None:
    old = EventStore(_rotated(ctx), read_only=True)
    last_hash = old.conn.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()["hash"]
    old.close()
    st = EventStore(ctx["dir"] / "events.sqlite", read_only=True)
    links = [a for a in st.get_actions(limit=100) if a["action"] == "ROTATION_LINK"]
    st.close()
    assert links
    detail = json.loads(links[0]["detail"])
    assert detail["last_event_hash"] == last_hash and detail["event_count"] == ctx["n"]


@when("an event in the rotated segment is edited in place")
def edit_event(ctx: dict) -> None:
    _edit(_rotated(ctx), "UPDATE events SET threat_score=0.01 WHERE t=2.0")


@when("the third event of the rotated segment is deleted")
def delete_event(ctx: dict) -> None:
    _edit(_rotated(ctx), "DELETE FROM events WHERE t=2.0")


@when("the evidence column of the rotated segment holds invalid JSON")
def corrupt_json(ctx: dict) -> None:
    _edit(_rotated(ctx), "UPDATE events SET evidence='{not json' WHERE t=1.0")


@then("the rotated segment's chain is reported broken")
def rotated_broken(ctx: dict) -> None:
    assert not _verify(_rotated(ctx)).ok


@then("the active segment still verifies")
def active_ok(ctx: dict) -> None:
    assert _verify(ctx["dir"] / "events.sqlite").ok
