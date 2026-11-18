#!/usr/bin/env python3
"""Install Python packages on the Raspberry Pi WITHOUT internet on the Pi: download on the laptop, copy over ssh, install offline.

    python pi_pkg.py pip rich pyyaml            # laptop downloads aarch64/py3.13 wheels (+ dependencies), pushes, installs in the Pi venv
    python pi_pkg.py push some.whl other.deb    # copy any file(s) to ~/aegis_pkgs/ on the Pi (prints how to install a .deb: needs sudo)
    python pi_pkg.py install rich               # install from wheels already pushed (no laptop internet needed)
    python pi_pkg.py list                       # what is pushed / installed on the Pi

The laptop needs internet only for ``pip`` (its own connection, e.g. a hotspot); the Pi never does. Only binary wheels are fetched
(``--only-binary=:all:``), so nothing is built or run on the laptop for the Pi; a package that has no aarch64 wheel is reported.
Environment: ARDRA_KEY (ssh private key), PI_HOST (default 169.254.225.172), PI_USER (default ardra), PI_VENV (default ~/aegis_test/venv),
PI_PY_VERSION (default 3.13). Downloads go to ~/.aegis_pi_wheels on the laptop.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REMOTE_DIR = "~/aegis_pkgs"
PLATFORMS = ("manylinux_2_28_aarch64", "manylinux_2_17_aarch64", "manylinux2014_aarch64", "linux_aarch64")


def _opts(args: argparse.Namespace) -> list[str]:
    return ["-i", args.key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"] if args.key else ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]


def ssh_cmd(args: argparse.Namespace, remote: str) -> list[str]:
    return ["ssh", *_opts(args), f"{args.user}@{args.host}", remote]


def scp_cmd(args: argparse.Namespace, files: list[Path]) -> list[str]:
    return ["scp", *_opts(args), *[str(f) for f in files], f"{args.user}@{args.host}:{REMOTE_DIR}/"]


def download_cmd(args: argparse.Namespace, packages: list[str], dest: Path) -> list[str]:
    cmd = [sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--python-version", args.py_version, "--implementation", "cp",
           "--abi", f"cp{args.py_version.replace('.', '')}", "--dest", str(dest)]
    for p in PLATFORMS:
        cmd += ["--platform", p]
    return cmd + packages


def install_cmd(args: argparse.Namespace, packages: list[str]) -> list[str]:
    quoted = " ".join(f"'{p}'" for p in packages)
    return ssh_cmd(args, f"{args.venv}/bin/pip install --no-index --find-links {REMOTE_DIR}/wheels {quoted}")


def run(cmd: list[str], what: str) -> int:
    r = subprocess.run(cmd, check=False)
    if r.returncode:
        print(f"pi_pkg: {what} failed (exit {r.returncode})", file=sys.stderr)
    return r.returncode


def push(args: argparse.Namespace, files: list[Path], sub: str = "") -> int:
    missing = [f for f in files if not f.is_file()]
    if missing:
        print(f"pi_pkg: not a file: {missing[0]}", file=sys.stderr)
        return 2
    if run(ssh_cmd(args, f"mkdir -p {REMOTE_DIR}/wheels"), "creating the remote directory"):
        return 1
    wheels = [f for f in files if f.suffix == ".whl"]
    others = [f for f in files if f.suffix != ".whl"]
    for group, target in ((wheels, f"{REMOTE_DIR}/wheels"), (others, REMOTE_DIR)):
        if group:
            cmd = scp_cmd(args, group)
            cmd[-1] = f"{args.user}@{args.host}:{target}/"
            if run(cmd, "copying"):
                return 1
    for f in others:
        if f.suffix == ".deb":
            print(f"pi_pkg: {f.name} copied; install it on the Pi yourself (needs sudo): sudo dpkg -i {REMOTE_DIR}/{f.name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="offline package installs on the Pi over ssh")
    ap.add_argument("--host", default=os.environ.get("PI_HOST", "169.254.225.172"))
    ap.add_argument("--user", default=os.environ.get("PI_USER", "ardra"))
    ap.add_argument("--key", default=os.environ.get("ARDRA_KEY", ""))
    ap.add_argument("--venv", default=os.environ.get("PI_VENV", "~/aegis_test/venv"))
    ap.add_argument("--py-version", default=os.environ.get("PI_PY_VERSION", "3.13"))
    ap.add_argument("--cache", default=str(Path.home() / ".aegis_pi_wheels"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pip", help="download wheels on the laptop, push them, install in the Pi venv")
    p.add_argument("packages", nargs="+")
    p = sub.add_parser("push", help="copy files to ~/aegis_pkgs on the Pi")
    p.add_argument("files", nargs="+", type=Path)
    p = sub.add_parser("install", help="install from the wheels already on the Pi")
    p.add_argument("packages", nargs="+")
    sub.add_parser("list", help="show what is pushed and what the venv has")
    args = ap.parse_args(argv)

    if args.cmd == "pip":
        dest = Path(args.cache)
        dest.mkdir(parents=True, exist_ok=True)
        if run(download_cmd(args, args.packages, dest), "download on the laptop (needs the laptop's own internet; a package without an aarch64 wheel cannot be fetched)"):
            return 1
        wheels = sorted(dest.glob("*.whl"))
        if not wheels:
            print("pi_pkg: nothing downloaded", file=sys.stderr)
            return 1
        if push(args, wheels):
            return 1
        return run(install_cmd(args, args.packages), "offline install on the Pi")
    if args.cmd == "push":
        return push(args, args.files)
    if args.cmd == "install":
        return run(install_cmd(args, args.packages), "offline install on the Pi")
    return run(ssh_cmd(args, f"ls -la {REMOTE_DIR} {REMOTE_DIR}/wheels 2>&1 | head -40; {args.venv}/bin/pip list 2>/dev/null | head -60"), "listing")


if __name__ == "__main__":
    raise SystemExit(main())
