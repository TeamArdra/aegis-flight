"""Exact-verdict and wire-format tests for the semantic firewall.

These pin every field of every verdict (the reason string, category and severity feed the audit log and the dashboard),
the length boundaries of the frame parser, and the field widths of the MAVLink structs, so that a one-character change in
a security-boundary module is caught.
"""

from __future__ import annotations

import struct

import pytest

from aegisflight.mitigation import semantic_firewall as sf
from aegisflight.mitigation.semantic_firewall import (
    FenceChangeEvent,
    ParamWriteEvent,
    SemanticFirewall,
    SemanticVerdict,
    extract_mission_fence_raw,
    extract_param_set_raw,
)

OK = SemanticVerdict(False, "ok", "ok", 0.0)


def v2_raw(msgid: int, payload: bytes, crc: bytes = b"\xaa\xbb") -> bytes:
    """An unsigned MAVLink 2 frame with the given (already trimmed) payload; the CRC is not checked by the parser."""
    return bytes([0xFD, len(payload), 0, 0, 1, 255, 190, msgid & 0xFF, (msgid >> 8) & 0xFF, 0]) + payload + crc


def pw(pid: str, val: float = 1.0, kind: str = "param_set") -> ParamWriteEvent:
    return ParamWriteEvent(1.0, 255, 190, pid, val, 9, kind)


# -- frame parser boundaries -------------------------------------------------------------------------------------------

def test_empty_payload_frames_parse_as_zeros_at_the_exact_minimum_length() -> None:
    v2 = v2_raw(23, b"")
    assert len(v2) == 12
    assert extract_param_set_raw(v2) == ("", 0.0, 0)
    v1 = bytes([0xFE, 0, 0, 255, 190, 23]) + b"\xaa\xbb"
    assert len(v1) == 8
    assert extract_param_set_raw(v1) == ("", 0.0, 0)
    assert extract_param_set_raw(v2[:11]) is None and extract_param_set_raw(v1[:7]) is None


def test_trailing_crc_bytes_never_leak_into_a_trimmed_payload() -> None:
    # MAVLink 2 trims trailing zero bytes: param_type == 0 is dropped from the wire, the CRC follows the payload
    body = struct.pack("<fBB16s", 7.0, 1, 1, b"FS_THR_ENABLE".ljust(16, b"\0"))
    assert extract_param_set_raw(v2_raw(23, body)) == ("FS_THR_ENABLE", 7.0, 0)
    v1 = bytes([0xFE, len(body), 0, 255, 190, 23]) + body + b"\xaa\xbb"
    assert extract_param_set_raw(v1) == ("FS_THR_ENABLE", 7.0, 0)


def test_param_id_decoding_is_ascii_only_and_stops_at_the_first_nul() -> None:
    ident = b"FS_\xc3\xa9X" + b"\0" + b"HIDDEN"
    raw = v2_raw(23, struct.pack("<fBB16sB", 1.0, 1, 1, ident.ljust(16, b"\0"), 9))
    assert extract_param_set_raw(raw) == ("FS_X", 1.0, 9)  # non-ASCII bytes dropped, the tail after NUL ignored
    padded = v2_raw(23, struct.pack("<fBB16sB", 1.0, 1, 1, b"  FS_A  ".ljust(16, b"\0"), 9))
    assert extract_param_set_raw(padded) == ("FS_A", 1.0, 9)  # surrounding spaces stripped


# -- struct widths: values above the signed range must survive --------------------------------------------------------

def test_mission_fields_above_the_signed_range_round_trip() -> None:
    clear = v2_raw(45, struct.pack("<BBB", 1, 1, 200))
    assert extract_mission_fence_raw(clear, 45) == ("clear_fence", 200, None, None, None, None, None)
    count = v2_raw(44, struct.pack("<HBBB", 40000, 1, 1, 201))
    assert extract_mission_fence_raw(count, 44) == ("upload_fence", 201, 40000, None, None, None, None)
    item = v2_raw(73, struct.pack("<ffffiifHHBBBBBB", 150.0, 0.0, 0.0, 0.0, 123456789, -987654321, 5.0, 3, 40000,
                                  1, 1, 130, 1, 1, 202))
    assert extract_mission_fence_raw(item, 73) == (
        "fence_item", 202, None, 40000, 150.0, 123456789 / 1e7, -987654321 / 1e7)


# -- exact verdicts ----------------------------------------------------------------------------------------------------

def test_disabled_firewall_verdicts_are_exact() -> None:
    fw = SemanticFirewall(enabled=False)
    assert fw.evaluate_param_write(pw("FS_X"), armed=True) == SemanticVerdict(False, "disabled", "ok", 0.0)
    assert fw.evaluate_fence_change(FenceChangeEvent(1.0, 255, 190, "clear_fence", 1), armed=True) == OK


def test_param_set_verdicts_are_exact() -> None:
    fw = SemanticFirewall(deny_always_params=("MY_PARAM",), block_when_arm_unknown=True)
    assert fw.evaluate_param_write(pw("WPNAV_SPEED"), armed=True) == OK
    assert fw.evaluate_param_write(pw("MY_PARAM"), armed=False) == SemanticVerdict(
        True, "denied_safety_param:MY_PARAM", "param_tamper", 0.95)
    assert fw.evaluate_param_write(pw("fs_gcs_enable"), armed=True) == SemanticVerdict(
        True, "airborne_safety_param:FS_GCS_ENABLE", "param_tamper", 0.95)
    assert fw.evaluate_param_write(pw("FS_GCS_ENABLE"), armed=None) == SemanticVerdict(
        True, "arm_unknown_safety_param:FS_GCS_ENABLE", "param_tamper", 0.80)
    assert fw.evaluate_param_write(pw("FS_GCS_ENABLE"), armed=False) == OK
    assert SemanticFirewall().evaluate_param_write(pw("FS_GCS_ENABLE"), armed=None) == OK


def test_empty_prefix_entries_never_protect_everything() -> None:
    fw = SemanticFirewall(protected_prefixes=("", "  ", "FS_"), deny_always_params=("", "  "))
    assert fw.protected_prefixes == ("FS_",) and fw.deny_always == frozenset()
    assert not fw.is_protected_param("WPNAV_SPEED") and fw.is_protected_param("FS_X")


def test_param_value_watcher_verdicts_and_thresholds_are_exact() -> None:
    fw = SemanticFirewall()
    assert fw.evaluate_param_write(pw("FS_THR_VALUE", 0.0, "param_value"), armed=True) == OK
    # a delta of exactly 1e-6 is below the noise floor; a delta of 0.5 is a change
    assert fw.evaluate_param_write(pw("FS_THR_VALUE", 1e-6, "param_value"), armed=True) == OK
    assert fw.evaluate_param_write(pw("FS_THR_VALUE", 0.5, "param_value"), armed=True) == SemanticVerdict(
        False, "airborne_param_changed:FS_THR_VALUE:0->0.5", "param_tamper", 0.90)
    # the new value became the baseline: repeating it is quiet, the next change reports the right previous value
    assert fw.evaluate_param_write(pw("FS_THR_VALUE", 0.5, "param_value"), armed=True) == OK
    assert fw.evaluate_param_write(pw("FS_THR_VALUE", 0.75, "param_value"), armed=True).reason == (
        "airborne_param_changed:FS_THR_VALUE:0.5->0.75")
    # an unprotected parameter never reports, however much it moves
    assert fw.evaluate_param_write(pw("WPNAV_SPEED", 1.0, "param_value"), armed=True) == OK
    assert fw.evaluate_param_write(pw("WPNAV_SPEED", 9.0, "param_value"), armed=True) == OK
    # a changed value with the arm state unknown only updates nothing and reports nothing
    assert fw.evaluate_param_write(pw("FS_THR_VALUE", 3.0, "param_value"), armed=None) == OK
    assert fw.evaluate_param_write(pw("FS_THR_VALUE", 3.0, "param_value"), armed=True).reason == (
        "airborne_param_changed:FS_THR_VALUE:0.75->3")


@pytest.mark.parametrize("armed", [True, False, None])
@pytest.mark.parametrize("block_unknown", [True, False])
@pytest.mark.parametrize(("action", "reason", "severity"), [
    ("clear_fence", "airborne_fence_clear", 0.95),
    ("upload_fence", "airborne_fence_overwrite", 0.90),
])
def test_fence_clear_and_upload_matrix(armed, block_unknown, action, reason, severity) -> None:
    fw = SemanticFirewall(block_when_arm_unknown=block_unknown)
    ev = FenceChangeEvent(1.0, 255, 190, action, 1, count=3)
    expect_block = armed is True or (armed is None and block_unknown)
    got = fw.evaluate_fence_change(ev, armed=armed)
    assert got == (SemanticVerdict(True, reason, "geofence_hijack", severity) if expect_block else OK)


def test_fence_item_home_exclusion_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    fw = SemanticFirewall()
    item = FenceChangeEvent(1.0, 255, 190, "fence_item", 1, command=5003, radius_m=100.0, lat_deg=20.0, lon_deg=73.0)
    home = (19.0, 72.0)
    far = fw.evaluate_fence_change(item, armed=True, home_lat_lon=home)
    assert far.blocked and far.category == "geofence_hijack" and far.severity_score == 0.92
    assert far.reason.startswith("fence_excludes_home:dist=") and far.reason.endswith("m>r=100m")
    assert fw.evaluate_fence_change(item, armed=False, home_lat_lon=home) == OK
    assert fw.evaluate_fence_change(item, armed=None, home_lat_lon=home) == OK
    # a distance exactly equal to the radius still lies inside the circle
    monkeypatch.setattr(sf, "haversine_m", lambda *_a: 100.0)
    assert fw.evaluate_fence_change(item, armed=True, home_lat_lon=home) == OK
    monkeypatch.setattr(sf, "haversine_m", lambda *_a: 100.5)
    assert fw.evaluate_fence_change(item, armed=True, home_lat_lon=home).reason == "fence_excludes_home:dist=100m>r=100m"
    # a radius below one metre is still a circle
    tiny = FenceChangeEvent(1.0, 255, 190, "fence_item", 1, command=5003, radius_m=0.5, lat_deg=20.0, lon_deg=73.0)
    monkeypatch.undo()
    assert fw.evaluate_fence_change(tiny, armed=True, home_lat_lon=home).blocked
    # exclusion circles and other fence commands are not judged against home
    other = FenceChangeEvent(1.0, 255, 190, "fence_item", 1, command=5002, radius_m=100.0, lat_deg=20.0, lon_deg=73.0)
    assert fw.evaluate_fence_change(other, armed=True, home_lat_lon=home) == OK
