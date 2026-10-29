"""Byte-exact equivalence guard for the inline forwarding path (see scripts/make_golden_forwarding.py).

The fixture ``tests/golden_forwarding/golden.json`` was generated from the code BEFORE the forwarding-path
optimisation. For the same input bytes, clocks and configuration the bridge must forward / drop / rewrite exactly
the same bytes, emit exactly the same management frames and keep exactly the same counters, and the serial stream
framer must emit the same frames with the same error counters. Never regenerate the fixture to make this pass.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("make_golden_forwarding", REPO / "scripts" / "make_golden_forwarding.py")
mgf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mgf)  # type: ignore[union-attr]

GOLD = json.loads(mgf.GOLDEN_PATH.read_text(encoding="utf-8"))
SCN = {}
with mgf.deterministic():
    for _s in mgf.all_scenarios():
        SCN[_s.name] = _s


def _run(name: str, posture: str) -> dict:
    with mgf.deterministic():
        return mgf.run_bridge(SCN[name], posture)


@pytest.mark.parametrize("key", sorted(GOLD["bridge"]))
def test_bridge_case_matches_golden(key: str) -> None:
    name, posture = key.split("|")
    rec = _run(name, posture)
    want = GOLD["bridge"][key]
    assert mgf.summarise(rec) == want["summary"], key
    assert mgf._digest(rec) == want["digest"], f"{key}: a counter / management frame / tap entry changed"


def test_split_frames_matches_golden() -> None:
    with mgf.deterministic():
        assert mgf.split_record() == GOLD["split_frames"]


def test_crc_helpers_match_golden() -> None:
    assert mgf.crc_record() == GOLD["crc"]


def test_framer_matches_golden() -> None:
    with mgf.deterministic():
        got = mgf.framer_records()
    bad = [k for k, v in got.items() if GOLD["framer"][k] != {"digest": mgf._digest(v), "frames": v["frames"]}]
    assert not bad, bad[:10]
    assert set(got) == set(GOLD["framer"])


def test_corpus_size() -> None:
    assert len(GOLD["bridge"]) == 75 and len(GOLD["framer"]) == 260
    assert len(SCN) == 25


# --- a few explicit, human-checkable expectations (independent of the digests) ---------------------------------


def test_explicit_expectations() -> None:
    b = GOLD["bridge"]
    # PASSIVE / ADVISORY forward every uplink frame byte-identically; only ACTIVE_IPS drops hostile control traffic
    for posture in ("passive", "advisory"):
        s = b[f"rogue_ground|{posture}"]["summary"]
        assert s["to_fc"] == 45 and s["dropped_up"] == 0
    s = b["rogue_ground|active-ips"]["summary"]
    assert s["dropped_up"] == 39 and s["to_fc"] == 6
    assert b["rogue_inflight|active-ips"]["summary"]["dropped_up"] == 40
    # the detector tap always sees every original frame (including the ones that are dropped)
    assert b["rogue_ground|active-ips"]["summary"]["tap"] == b["rogue_ground|passive"]["summary"]["tap"] == 47
    # a flood is shed only with the QoS rule active, only in ACTIVE_IPS
    assert b["flood_rate_limit|active-ips"]["summary"]["dropped_down"] == 480
    assert b["flood_rate_limit|passive"]["summary"]["dropped_down"] == 0
    # no hook ever raised on the corpus
    assert all(v["summary"]["hook_errors"] == 0 for v in b.values())
    # sanity of the framer corpus: the clean stream yields all 280 frames, with zero rejects
    assert GOLD["framer"]["clean|whole|default"]["frames"] == 280
    assert GOLD["framer"]["clean|byte|default"]["frames"] == 280


def test_rewritten_gps_frame_has_valid_crc_and_full_length() -> None:
    g = mgf.Gen()
    frame = g.gpi(1, lat=19.0, lon=72.9, rel=30.0, vx=5.0, hdg=0)          # trimmed payload
    assert frame[1] < 28
    from aegisflight.mitigation.sanitizer import FrameSanitizer
    san = FrameSanitizer()
    san.configure(active=True, sanitize_gps=True, lat_offset_deg=0.0005, lon_offset_deg=0.0)
    out = san.sanitize_frame(frame, "down", 1, 1, 33)
    assert out is not None and out[1] == 28 and len(out) == 40
    crc_extra = mgf.mav2.mavlink_map[33].crc_extra
    assert int.from_bytes(out[-2:], "little") == mgf.ref_crc(bytes([crc_extra]), mgf.ref_crc(out[1:38]))
    assert int.from_bytes(out[14:18], "little", signed=True) == int(19.0 * 1e7) - 5000


def test_hook_exception_fails_open(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisflight.mitigation.inline_policy import InlinePolicy

    def boom(self, ctx):  # noqa: ANN001
        raise RuntimeError("x")

    monkeypatch.setattr(InlinePolicy, "_learn_state", boom)
    with mgf.deterministic():
        clk = mgf.Clk(mgf.T0)
        bridge, fc, gcs = mgf.make_bridge(SCN["telemetry_normal"], "passive", clk)
        frame = mgf.Gen().heartbeat(1, True)
        fc.queue.append((1, frame))
        bridge.pump_once()
    assert gcs.sent[:1] == [frame] and bridge.policy.hook_errors == 1


# --- the guard must notice a change (perturbations live only inside these tests) -------------------------------


def test_guard_catches_dropped_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    import aegisflight.hal.inline_ips as ips

    real = ips.split_frames
    monkeypatch.setattr(ips, "split_frames", lambda d, *a: (lambda r: (r[0][1:], r[1]))(real(d, *a)))
    rec = _run("telemetry_normal", "passive")
    assert mgf._digest(rec) != GOLD["bridge"]["telemetry_normal|passive"]["digest"]


def test_guard_catches_policy_change(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisflight.mitigation.inline_policy import InlinePolicy

    monkeypatch.setattr(InlinePolicy, "up", lambda self, ctx: [ctx.raw])
    rec = _run("rogue_ground", "active-ips")
    assert mgf._digest(rec) != GOLD["bridge"]["rogue_ground|active-ips"]["digest"]


def test_guard_catches_counter_change(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisflight.hal.mgmt_channel import MgmtChannel

    real = MgmtChannel.note_drop
    monkeypatch.setattr(MgmtChannel, "note_drop", lambda self, label: (real(self, label), real(self, label))[0])
    rec = _run("rogue_ground", "active-ips")
    assert mgf._digest(rec) != GOLD["bridge"]["rogue_ground|active-ips"]["digest"]


def test_guard_catches_crc_change(monkeypatch: pytest.MonkeyPatch) -> None:
    import aegisflight.sources.mavlink_serial as ms

    real = ms._crc_x25
    monkeypatch.setattr(ms, "_crc_x25", lambda d, c=0xFFFF: real(d, c) ^ (1 if len(d) == 1 else 0))
    with mgf.deterministic():
        rec = mgf.run_framer(mgf.framer_streams()["clean"], "whole", "default")
    assert mgf._digest(rec) != GOLD["framer"]["clean|whole|default"]["digest"]


def test_guard_catches_sanitizer_change(monkeypatch: pytest.MonkeyPatch) -> None:
    import aegisflight.mitigation.sanitizer as san

    monkeypatch.setattr(san, "x25_crc", lambda d, i=0xFFFF: 0)
    rec = _run("sanitizer_quarantine_qos_gps", "active-ips")
    assert mgf._digest(rec) != GOLD["bridge"]["sanitizer_quarantine_qos_gps|active-ips"]["digest"]
