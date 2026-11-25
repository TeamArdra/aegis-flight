"""Regression tests for Batch 4 audit hardening (CrossEnd, FirmwareVerifier, LiveEngine, Config, Onboard)."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from aegisflight.backend.engine import LiveEngine
from aegisflight.backend.sources import SourceSpec
from aegisflight.config import AegisConfig, load_config
from aegisflight.core.enums import AttackType, IntegrityStatus
from aegisflight.core.types import MessageEnvelope
from aegisflight.detectors.crossend import (
    _KEEP,
    MARKER_ADDRESS,
    MARKER_TYPE,
    MARKER_VER,
    MEMORY_VECT_MSGID,
    SILENCE_S,
    CrossEndMonitor,
    pack_summary,
)
from aegisflight.integrity.allowlist import (
    ALLOWLIST_KEY_ENV,
    compute_allowlist_hmac,
    load_firmware_allowlist,
)
from aegisflight.integrity.verifier import FirmwareVerifier
from aegisflight.onboard import OnboardConfig, _parse_bool, load_onboard_config, run_enroll_firmware
from aegisflight.sources.stream import TelemetryTick
from aegisflight.testing.field_drill import run_field_drill


def _summary_env(t: float, tbm: int, lat: int = 473977420, key: bytes | None = None) -> MessageEnvelope:
    vals = (tbm, lat, 85455940, 500000, 10000, 100, -50)
    return MessageEnvelope(
        recv_time=t,
        sysid=1,
        compid=191,
        msgid=MEMORY_VECT_MSGID,
        msgname="MEMORY_VECT",
        seq=0,
        signed=key is not None,
        byte_len=40,
        fields={
            "address": MARKER_ADDRESS,
            "ver": MARKER_VER,
            "type": MARKER_TYPE,
            "value": pack_summary(vals, key),
        },
    )


def _gpi_env(t: float, tbm: int, lat: int = 473977420) -> MessageEnvelope:
    return MessageEnvelope(
        recv_time=t,
        sysid=1,
        compid=1,
        msgid=33,
        msgname="GLOBAL_POSITION_INT",
        seq=0,
        signed=False,
        byte_len=36,
        fields={
            "time_boot_ms": tbm,
            "lat": lat,
            "lon": 85455940,
            "alt": 500000,
            "relative_alt": 10000,
            "vx": 100,
            "vy": -50,
        },
    )


# --------------------------------------------------------------------------- #
# 1. sources-detectors-2: CrossEnd replay monotonicity & unmatched surfacing
# --------------------------------------------------------------------------- #


def test_crossend_rejects_replayed_summary_and_preserves_silence_detection() -> None:
    key = bytes(range(32))
    mon = CrossEndMonitor(key)
    mon.update(_gpi_env(1.0, 1000))
    mon.update(_summary_env(1.0, 1000, key=key))
    res0 = mon.assess(1.0)
    assert res0 is not None and res0.score == 0.0
    assert mon.replays == 0

    # Equal time_boot_ms replay at t=2.0 -> rejected, flagged as anomaly, does not advance _last_summary_t
    mon.update(_summary_env(2.0, 1000, key=key))
    assert mon.replays == 1
    assert mon._last_summary_t == 1.0
    res1 = mon.assess(2.0)
    assert res1 is not None and res1.score >= 0.3
    assert res1.votes.get(AttackType.MAVLINK_ANOMALY, 0.0) >= 0.3
    assert any("replay" in ev.lower() for ev in res1.evidence)

    # Older time_boot_ms replay past SILENCE_S -> both replay AND silence fire
    t_late = 1.0 + SILENCE_S + 2.0
    mon.update(_summary_env(t_late, 900, key=key))
    assert mon.replays == 2
    assert mon._last_summary_t == 1.0
    res2 = mon.assess(t_late)
    assert res2 is not None and res2.score >= 0.3
    assert any("silent" in ev.lower() for ev in res2.evidence)
    assert any("replay" in ev.lower() for ev in res2.evidence)


def test_crossend_surfaces_unmatched_evictions_in_score_and_evidence() -> None:
    mon = CrossEndMonitor()
    for i in range(_KEEP + 2):
        mon.update(_summary_env(float(i) * 0.1, 1000 + i * 100))
    assert mon.unmatched >= 2
    res = mon.assess()
    assert res is not None and res.score >= 0.3
    assert res.votes.get(AttackType.MAVLINK_ANOMALY, 0.0) >= 0.3
    assert any("unmatched" in ev.lower() for ev in res.evidence)


# --------------------------------------------------------------------------- #
# 2. analytics-misc-2: FirmwareVerifier fail-closed & atomic build_manifest
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "bad_content",
    [
        "{truncated json",
        "[]",
        "{}",
        '{"components": "not-a-dict"}',
        '{"components": {"bootloader.bin": 12345}}',
    ],
)
def test_firmware_verifier_fails_closed_on_corrupt_manifest(tmp_path: Path, bad_content: str) -> None:
    v = FirmwareVerifier(tmp_path)
    v.write_fixture()
    v.manifest_path.write_text(bad_content, encoding="utf-8")

    rep = v.verify()
    assert rep.status is IntegrityStatus.INVALID
    assert rep.tampered == ["manifest.json"]
    assert any("corrupt or unreadable firmware manifest" in ev for ev in rep.evidence)


def test_firmware_verifier_build_manifest_is_atomic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    v = FirmwareVerifier(tmp_path)
    v.write_fixture()
    replaced: list[tuple[str, str]] = []
    real_replace = os.replace

    def spy_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        replaced.append((os.fspath(src), os.fspath(dst)))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy_replace)
    manifest = v.build_manifest()
    assert len(replaced) == 1
    assert Path(replaced[0][1]) == v.manifest_path
    assert not list(tmp_path.glob("*.tmp"))
    assert v.verify().status is IntegrityStatus.VALID
    assert len(manifest["components"]) == 5


# --------------------------------------------------------------------------- #
# 3. backend-logging-1: LiveEngine loop error handling & done-callback
# --------------------------------------------------------------------------- #


def test_live_engine_sim_loop_crash_sets_error_state_and_stops(tmp_path: Path) -> None:
    async def _run() -> None:
        eng = LiveEngine(cfg=load_config(), db_path=str(tmp_path / "sim.sqlite"), model_path="__no_model__")
        sub = eng.subscribe()

        async def _boom(_tick: TelemetryTick) -> None:
            raise RuntimeError("simulated pipeline boom")

        eng._process = _boom  # type: ignore[method-assign]
        await eng.start()
        assert eng._task is not None
        await asyncio.wait_for(eng._task, timeout=2.0)

        st = eng.status()
        assert eng.running is False
        assert st["running"] is False
        assert st["error"] is not None and "simulated pipeline boom" in st["error"]
        assert st["link"]["state"] == "error"
        assert "simulated pipeline boom" in (st["link"]["error"] or "")

        update = sub.get_nowait()
        assert update["link"]["state"] == "error"
        assert "simulated pipeline boom" in (update.get("error") or "")
        await eng.close()

    asyncio.run(_run())


def test_live_engine_live_loop_crash_sets_error_state_and_stops(tmp_path: Path) -> None:
    async def _run() -> None:
        dummy_tlog = tmp_path / "dummy.tlog"
        dummy_tlog.write_bytes(b"")
        spec = SourceSpec(kind="replay", tlog=str(dummy_tlog))
        eng = LiveEngine(cfg=load_config(), db_path=str(tmp_path / "live.sqlite"), model_path="__no_model__", spec=spec)
        eng.running = True
        eng._queue = asyncio.Queue()

        async def _boom(_tick: TelemetryTick) -> None:
            raise ValueError("live pipeline boom")

        eng._process = _boom  # type: ignore[method-assign]
        task = asyncio.create_task(eng._live_loop())
        task.add_done_callback(eng._on_task_done)
        eng._task = task
        eng._queue.put_nowait(TelemetryTick(tick=0, t=0.1, messages=[]))
        await asyncio.wait_for(task, timeout=2.0)

        st = eng.status()
        assert eng.running is False
        assert st["running"] is False
        assert st["error"] is not None and "live pipeline boom" in st["error"]
        assert st["link"]["state"] == "error"
        await eng.close()

    asyncio.run(_run())


# --------------------------------------------------------------------------- #
# 4. entry-config-2: Explicit missing config_dir & cwd-independent field_drill
# --------------------------------------------------------------------------- #


def test_explicit_missing_config_dir_raises_file_not_found(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist"
    with pytest.raises(FileNotFoundError, match="does_not_exist"):
        AegisConfig.load(missing)
    with pytest.raises(FileNotFoundError, match="does_not_exist"):
        load_config(missing)
    # Default None and existing empty dir continue working cleanly
    assert AegisConfig.load(None).detector["fusion"]["threat_threshold"] == 0.45
    assert AegisConfig.load(tmp_path).simulation["seed"] == 42


def test_field_drill_works_from_arbitrary_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    res_gps = run_field_drill("gps_spoof_escalation")
    res_clk = run_field_drill("clock_skew_sdr_spoof")
    assert res_gps["ok"] is True
    assert res_clk["ok"] is True


# --------------------------------------------------------------------------- #
# 5. entry-config-3: Strict boolean parsing & unknown key rejection in onboard
# --------------------------------------------------------------------------- #


def test_onboard_parse_bool_and_yaml_bool_strings(tmp_path: Path) -> None:
    assert _parse_bool(True, "k") is True
    assert _parse_bool(False, "k") is False
    for s in ("true", "TRUE", "yes", "1", "on"):
        assert _parse_bool(s, "k") is True
    for s in ("false", "FALSE", "no", "0", "off"):
        assert _parse_bool(s, "k") is False
    for bad in ("maybe", "", 1, 0, None):
        with pytest.raises(ValueError, match="invalid boolean"):
            _parse_bool(bad, "allow_url")

    cfg_file = tmp_path / "onboard_str_bools.yaml"
    cfg_file.write_text(
        'allow_url: "false"\n'
        'mgmt_enable: "no"\n'
        'fail_closed_uplink_commands: "off"\n'
        'anchors_enabled: "0"\n'
        'dashboard:\n'
        '  enabled: "false"\n',
        encoding="utf-8",
    )
    cfg = load_onboard_config(cfg_file)
    assert cfg.allow_url is False
    assert cfg.mgmt_enable is False
    assert cfg.fail_closed_uplink_commands is False
    assert cfg.anchors_enabled is False
    assert cfg.dashboard.enabled is False


def test_onboard_rejects_unknown_keys(tmp_path: Path) -> None:
    bad_top = tmp_path / "bad_top.yaml"
    bad_top.write_text("defense_mod: passive\nfoo_bar: 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown onboard config key.*defense_mod.*foo_bar"):
        load_onboard_config(bad_top)

    bad_ret = tmp_path / "bad_ret.yaml"
    bad_ret.write_text("retention:\n  max_db_bytez: 100\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown retention config key.*max_db_bytez"):
        load_onboard_config(bad_ret)

    bad_dash = tmp_path / "bad_dash.yaml"
    bad_dash.write_text("dashboard:\n  enabld: false\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown dashboard config key.*enabld"):
        load_onboard_config(bad_dash)


# --------------------------------------------------------------------------- #
# 6. entry-config-4: --enroll-firmware verifies existing HMAC & writes atomically
# --------------------------------------------------------------------------- #


def _fake_capture(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    return {
        "sysid": 1,
        "compid": 1,
        "flight_sw_version": (4 << 24) | (5 << 16) | (7 << 8) | 255,
        "flight_custom_version_hex": "a1b2c3d400000000",
        "board_version": 0x1002,
        "vendor_id": 9900,
        "product_id": 57,
        "uid": 0xDEADBEEF1234,
    }


def test_enroll_firmware_refuses_tampered_allowlist_and_writes_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import aegisflight.onboard as onboard_mod

    monkeypatch.setattr(onboard_mod, "capture_autopilot_version_passive", _fake_capture)
    key = "enroll-test-hmac-key"
    allow_path = tmp_path / "allowlist.yaml"
    cfg = OnboardConfig(fc_port="/dev/ttyAMA0", fc_baud=921600)

    # 1. Initial signed enrollment succeeds atomically
    monkeypatch.setenv(ALLOWLIST_KEY_ENV, key)
    replaced: list[tuple[str, str]] = []
    real_replace = os.replace

    def spy_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        replaced.append((os.fspath(src), os.fspath(dst)))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy_replace)
    rc = run_enroll_firmware(cfg, out_path=allow_path, vehicle_name="fc-1")
    assert rc == 0
    assert len(replaced) == 1
    assert Path(replaced[0][1]) == allow_path
    assert not list(tmp_path.glob("*.tmp"))
    al = load_firmware_allowlist(allow_path)
    assert al.signed is True and len(al.entries) == 1

    # 2. Tamper with the signed allowlist -> enroll MUST refuse (rc=2) and not overwrite
    doc = yaml.safe_load(allow_path.read_text(encoding="utf-8"))
    doc["vehicles"][0]["board_version"] = 99999
    tampered_text = yaml.safe_dump(doc, sort_keys=False)
    allow_path.write_text(tampered_text, encoding="utf-8")

    rc_tampered = run_enroll_firmware(cfg, out_path=allow_path, vehicle_name="fc-2")
    assert rc_tampered == 2
    assert allow_path.read_text(encoding="utf-8") == tampered_text

    # 3. Signed allowlist with valid HMAC -> updating/adding another vehicle succeeds
    doc["vehicles"][0]["board_version"] = 0x1002
    doc.pop("hmac_sha256", None)
    doc["hmac_sha256"] = compute_allowlist_hmac(doc, key)
    allow_path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")

    rc_ok = run_enroll_firmware(cfg, out_path=allow_path, vehicle_name="fc-2")
    assert rc_ok == 0
    al2 = load_firmware_allowlist(allow_path)
    assert al2.signed is True
    assert {e.name for e in al2.entries} == {"fc-1", "fc-2"}

    # 4. Signed allowlist without key in env -> fails closed (rc=2)
    monkeypatch.delenv(ALLOWLIST_KEY_ENV, raising=False)
    rc_no_key = run_enroll_firmware(cfg, out_path=allow_path, vehicle_name="fc-3")
    assert rc_no_key == 2
