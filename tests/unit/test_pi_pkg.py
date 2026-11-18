"""scripts/radio_test/pi_pkg.py: command construction only (no ssh, no network)."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("pi_pkg", Path(__file__).resolve().parents[2] / "scripts" / "radio_test" / "pi_pkg.py")
pi_pkg = importlib.util.module_from_spec(SPEC)
sys.modules["pi_pkg"] = pi_pkg
SPEC.loader.exec_module(pi_pkg)


def _args(**kw) -> argparse.Namespace:
    base = {"host": "10.0.0.5", "user": "pi", "key": "/k/key", "venv": "~/v", "py_version": "3.13"}
    base.update(kw)
    return argparse.Namespace(**base)


def test_download_targets_the_pi_not_the_laptop():
    cmd = pi_pkg.download_cmd(_args(), ["rich", "pyyaml"], Path("/w"))
    assert cmd[1:4] == ["-m", "pip", "download"] and "--only-binary=:all:" in cmd
    assert cmd[cmd.index("--python-version") + 1] == "3.13" and cmd[cmd.index("--abi") + 1] == "cp313"
    plats = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--platform"]
    assert plats and all("aarch64" in p for p in plats)
    assert cmd[-2:] == ["rich", "pyyaml"]


def test_install_is_offline_and_quotes_names():
    cmd = pi_pkg.install_cmd(_args(), ["rich", "a b"])
    assert cmd[0] == "ssh" and "pi@10.0.0.5" in cmd and "-i" in cmd
    remote = cmd[-1]
    assert "--no-index" in remote and "--find-links ~/aegis_pkgs/wheels" in remote and "'a b'" in remote and remote.startswith("~/v/bin/pip install")


def test_scp_targets_the_package_directory_and_key_is_optional():
    cmd = pi_pkg.scp_cmd(_args(key=""), [Path("x.whl")])
    assert cmd[0] == "scp" and "-i" not in cmd and cmd[-1] == "pi@10.0.0.5:~/aegis_pkgs/"


def test_push_rejects_missing_files(capsys):
    assert pi_pkg.push(_args(), [Path("definitely-missing.whl")]) == 2
    assert "not a file" in capsys.readouterr().err
