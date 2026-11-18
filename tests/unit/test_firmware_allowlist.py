"""Unit and pipeline tests for AUTOPILOT_VERSION firmware identity allowlist (#20)."""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest
import yaml

from aegisflight.config import load_config
from aegisflight.core.enums import AttackType, IntegrityStatus
from aegisflight.core.types import MessageEnvelope
from aegisflight.detectors.integrity import IntegrityDetector
from aegisflight.hal.identify import EndpointIdentifier
from aegisflight.integrity.allowlist import (
    ALLOWLIST_KEY_ENV,
    AllowlistError,
    compute_allowlist_hmac,
    default_allowlist_path,
    load_firmware_allowlist,
)
from aegisflight.pipeline import IDSPipeline
from aegisflight.sources.stream import TelemetryTick

_VALID_FIELDS = {
    "flight_sw_version": (4 << 24) | (5 << 16) | (7 << 8) | 255,
    "flight_custom_version": [ord(c) for c in "a1b2c3d4"],
    "board_version": 0x1002,
    "vendor_id": 9900,
    "product_id": 57,
    "uid": 0xDEADBEEF1234,
}


def _write_allowlist(path: Path, data: dict) -> Path:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def _sample_data() -> dict:
    return {
        "schema": "aegisflight.firmware_allowlist/1",
        "vehicles": [
            {
                "name": "bench-pixhawk",
                "sysid": 1,
                "compid": 1,
                "flight_sw_version": "4.5.7",
                "flight_custom_version": "a1b2c3d4",
                "board_version": 0x1002,
                "vendor_id": 9900,
                "product_id": 57,
                "uid": 0xDEADBEEF1234,
            }
        ],
    }


def test_unsigned_allowlist_loads_with_warning(tmp_path: Path) -> None:
    p = _write_allowlist(tmp_path / "allow.yaml", _sample_data())
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        al = load_firmware_allowlist(p)
    assert al.signed is False
    assert al.unsigned_warning is not None
    assert len(al.sha256) == 64
    assert any("unsigned" in str(w.message).lower() for w in rec)


def test_signed_allowlist_valid_and_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = _sample_data()
    key = "super-secret-bench-key"
    data["hmac_sha256"] = compute_allowlist_hmac(data, key)
    p = _write_allowlist(tmp_path / "allow_signed.yaml", data)

    # Missing key -> fail closed
    monkeypatch.delenv(ALLOWLIST_KEY_ENV, raising=False)
    with pytest.raises(AllowlistError, match="AEGIS_ALLOWLIST_KEY"):
        load_firmware_allowlist(p)

    # Bad signature / wrong key -> fail closed
    monkeypatch.setenv(ALLOWLIST_KEY_ENV, "wrong-key")
    with pytest.raises(AllowlistError, match="HMAC-SHA256 verification failed"):
        load_firmware_allowlist(p)

    # Valid key -> loads cleanly without warning
    monkeypatch.setenv(ALLOWLIST_KEY_ENV, key)
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        al = load_firmware_allowlist(p)
    assert al.signed is True
    assert al.unsigned_warning is None
    assert rec == []

    # Tampered payload fails closed even with valid key
    data["vehicles"][0]["board_version"] = 9999
    _write_allowlist(p, data)
    with pytest.raises(AllowlistError, match="HMAC-SHA256 verification failed"):
        load_firmware_allowlist(p)


def test_allowlist_match_returns_no_vote(tmp_path: Path) -> None:
    p = _write_allowlist(tmp_path / "allow.yaml", _sample_data())
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        al = load_firmware_allowlist(p)
    det = IntegrityDetector(allowlist=al)
    det.observe_message("AUTOPILOT_VERSION", dict(_VALID_FIELDS), sysid=1, compid=1)
    res = det.process()
    assert res.score == 0.0
    assert res.triggered is False
    assert res.attack_votes == {}
    assert det.status is IntegrityStatus.VALID


@pytest.mark.parametrize(
    ("field_name", "bad_value"),
    [
        ("flight_sw_version", (4 << 24) | (6 << 16) | (0 << 8) | 255),
        ("flight_custom_version", [ord(c) for c in "ffffffff"]),
        ("board_version", 0x9999),
        ("vendor_id", 1234),
        ("product_id", 88),
        ("uid", 0xCAFEBABE0001),
    ],
)
def test_allowlist_each_field_mismatch_raises_vote(
    tmp_path: Path, field_name: str, bad_value: object
) -> None:
    p = _write_allowlist(tmp_path / "allow.yaml", _sample_data())
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        al = load_firmware_allowlist(p)
    det = IntegrityDetector(allowlist=al)
    fields = dict(_VALID_FIELDS)
    fields[field_name] = bad_value
    det.observe_message("AUTOPILOT_VERSION", fields, sysid=1, compid=1)
    res = det.process()
    assert res.triggered is True
    assert res.score >= 0.9
    assert res.attack_votes.get(AttackType.FIRMWARE_INTEGRITY, 0.0) >= 0.9
    assert any(field_name in ev for ev in res.evidence), res.evidence
    assert det.status is IntegrityStatus.INVALID


def test_allowlist_not_observed_emits_coverage_note_only(tmp_path: Path) -> None:
    p = _write_allowlist(tmp_path / "allow.yaml", _sample_data())
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        al = load_firmware_allowlist(p)
    det = IntegrityDetector(allowlist=al)
    res = det.process()
    assert res.score == 0.0
    assert res.triggered is False
    assert res.attack_votes == {}
    assert det.status is IntegrityStatus.UNKNOWN
    assert any("AUTOPILOT_VERSION not observed" in ev for ev in res.evidence)


def test_identify_autopilot_version_does_not_set_has_gps() -> None:
    ident = EndpointIdentifier()
    ident.fingerprint.has_gps = False
    ident.observe_message("HEARTBEAT", {"type": 2, "autopilot": 3}, sysid=1, compid=1)
    ident.observe_message("AUTOPILOT_VERSION", dict(_VALID_FIELDS), sysid=1, compid=1)
    assert ident.fingerprint.has_gps is False
    assert ident.fingerprint.autopilot_version_str == "4.5.7"


def test_pipeline_autopilot_version_mismatch_triggers_alert(tmp_path: Path) -> None:
    p = _write_allowlist(tmp_path / "allow.yaml", _sample_data())
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        al = load_firmware_allowlist(p)
    pipe = IDSPipeline(load_config(), model_path=None, firmware_allowlist=al)

    # Before AUTOPILOT_VERSION arrives: coverage only, no threat/alert
    t0 = pipe.process_tick(TelemetryTick(t=0.0, tick=0, messages=[]))
    assert t0 is not None and not t0.is_alert
    assert any("AUTOPILOT_VERSION not observed" in ev for ev in t0.evidence)

    # Matching AUTOPILOT_VERSION -> no alert
    env_ok = MessageEnvelope(
        recv_time=0.2, sysid=1, compid=1, msgid=148, msgname="AUTOPILOT_VERSION",
        seq=1, signed=False, byte_len=60, fields=dict(_VALID_FIELDS),
    )
    t1 = pipe.process_tick(TelemetryTick(t=0.2, tick=2, messages=[env_ok]))
    assert t1 is not None and not t1.is_alert and t1.integrity_status is IntegrityStatus.VALID

    # Spoofed/tampered board_version -> FIRMWARE_INTEGRITY alert
    bad_fields = dict(_VALID_FIELDS)
    bad_fields["board_version"] = 0x7777
    env_bad = MessageEnvelope(
        recv_time=0.4, sysid=1, compid=1, msgid=148, msgname="AUTOPILOT_VERSION",
        seq=2, signed=False, byte_len=60, fields=bad_fields,
    )
    t2 = pipe.process_tick(TelemetryTick(t=0.4, tick=4, messages=[env_bad]))
    assert t2 is not None
    assert t2.integrity_status is IntegrityStatus.INVALID
    assert t2.attack_type is AttackType.FIRMWARE_INTEGRITY
    assert any("board_version" in ev for ev in t2.evidence)


def test_shipped_allowlist_loads_cleanly() -> None:
    p = default_allowlist_path()
    assert p is not None and p.name == "firmware_allowlist.yaml"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        al = load_firmware_allowlist(p)
    assert al.entries == []
    assert len(al.sha256) == 64
