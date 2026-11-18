"""Real-file firmware integrity on the bridge (``--firmware-dir`` + ``aegis fw-manifest``): temp files only, no hardware."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from aegisflight.cli.main import _cmd_fw_manifest
from aegisflight.config import load_config
from aegisflight.core.enums import IntegrityStatus
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.pipeline import IDSPipeline


class _Link:
    connected = True

    def poll(self):
        return []

    def send(self, raw):
        return True


def _make_dir(tmp_path: Path) -> Path:
    d = tmp_path / "fw"
    d.mkdir()
    (d / "autopilot.bin").write_bytes(bytes(range(256)) * 40)
    (d / "params.bin").write_bytes(b"ATC_RAT_RLL_P,0.135\n" * 30)
    return d


def test_manifest_then_verify_valid_and_no_fixture_written(tmp_path):
    d = _make_dir(tmp_path)
    assert _cmd_fw_manifest(argparse.Namespace(dir=str(d))) == 0
    before = {p.name: p.read_bytes() for p in d.glob("*.bin")}
    pipe = IDSPipeline(load_config(), firmware_dir=d, firmware_real=True, firmware_recheck_every=1)
    assert {p.name for p in d.glob("*.bin")} == {"autopilot.bin", "params.bin"}      # the PoC fixture is never written into it
    assert {p.name: p.read_bytes() for p in d.glob("*.bin")} == before
    assert pipe.integrity.status is IntegrityStatus.VALID


def test_tampered_file_is_detected_and_reset_does_not_overwrite_real_files(tmp_path):
    d = _make_dir(tmp_path)
    _cmd_fw_manifest(argparse.Namespace(dir=str(d)))
    pipe = IDSPipeline(load_config(), firmware_dir=d, firmware_real=True, firmware_recheck_every=1)
    assert not pipe.integrity.process().triggered
    raw = bytearray((d / "autopilot.bin").read_bytes())
    raw[100] ^= 0xFF
    (d / "autopilot.bin").write_bytes(bytes(raw))
    res = pipe.integrity.process()
    assert res.triggered and res.score == 1.0 and any("autopilot.bin" in e for e in res.evidence)
    (d / "extra.bin").write_bytes(b"x")                                             # an unexpected component is also INVALID
    assert pipe.integrity.process().triggered
    pipe.reset()
    assert (d / "autopilot.bin").read_bytes() == bytes(raw)                          # reset never "reflashes" a real file
    assert (d / "extra.bin").exists()


def test_missing_manifest_is_unknown_and_empty_dir_manifest_is_refused(tmp_path):
    d = _make_dir(tmp_path)
    pipe = IDSPipeline(load_config(), firmware_dir=d, firmware_real=True, firmware_recheck_every=1)
    assert pipe.integrity.status is IntegrityStatus.UNKNOWN and not (d / "manifest.json").exists()
    empty = tmp_path / "empty"
    empty.mkdir()
    assert _cmd_fw_manifest(argparse.Namespace(dir=str(empty))) == 2


def test_bridge_wires_the_real_directory_and_default_is_unchanged(tmp_path):
    d = _make_dir(tmp_path)
    _cmd_fw_manifest(argparse.Namespace(dir=str(d)))
    b = InlineIpsBridge(_Link(), _Link(), firmware_dir=str(d), firmware_recheck_s=1.0)
    assert b.pipeline.verifier is not None and b.pipeline.integrity.recheck_every == 5      # 1 s at the 5 Hz decision rate
    assert json.loads((d / "manifest.json").read_text())["components"].keys() == {"autopilot.bin", "params.bin"}
    plain = InlineIpsBridge(_Link(), _Link())
    assert plain.pipeline.verifier is None
