#!/usr/bin/env python3
"""Laptop-side helper that drives the Pi through ssh (BatchMode, key from ``ARDRA_KEY``).

    set ARDRA_KEY=C:\\path\\to\\key
    python scripts/radio_test/laptop_ctl.py deploy
    python scripts/radio_test/laptop_ctl.py start --mode advisory --baud 57600 --laptop-ip 192.168.1.20
    python scripts/radio_test/laptop_ctl.py status | stop | restart | kill-bridge
    python scripts/radio_test/laptop_ctl.py pull-logs --out runs/radio1
    python scripts/radio_test/laptop_ctl.py reboot-pi            # prints the command only; --yes-reboot to run

Host / user default to 10.36.150.82 / ardra (``ARDRA_HOST`` / ``ARDRA_USER`` or --host / --user).
Exit code 0 = ok, 1 = the remote command failed, 2 = usage / local error.
"""

from __future__ import annotations

import argparse
import io
import os
import shlex
import subprocess
import sys
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_HOST = "10.36.150.82"
DEFAULT_USER = "ardra"
REMOTE_REPO = "aegis_test"  # relative to the remote home
RUN_SCRIPT = f"{REMOTE_REPO}/scripts/radio_test/pi_bridge_run.sh"
DEPLOY_DIRS = ("src", "configs", "scripts/radio_test")
SKIP_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
MODES = ("passive", "advisory", "active-ips")


class CtlError(Exception):
    """A local problem (missing key, bad args) reported without a traceback."""


def ssh_base(key: str, host: str, user: str, connect_timeout: int = 8) -> list[str]:
    """ssh argv up to (and including) ``user@host``; BatchMode so it never prompts."""
    return ["ssh", "-i", key, "-o", "BatchMode=yes", "-o", f"ConnectTimeout={connect_timeout}",
            "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", f"{user}@{host}"]


def scp_pull_command(key: str, host: str, user: str, remote: str, local: str, connect_timeout: int = 8) -> list[str]:
    """scp argv that copies the remote directory ``remote`` into ``local``."""
    return ["scp", "-r", "-i", key, "-o", "BatchMode=yes", "-o", f"ConnectTimeout={connect_timeout}",
            f"{user}@{host}:{remote}", local]


def remote_script(sub: str, env: dict[str, str] | None = None) -> str:
    """Shell line that runs ``pi_bridge_run.sh <sub>`` on the Pi with ``env`` set."""
    assigns = " ".join(f"{k}={shlex.quote(str(v))}" for k, v in (env or {}).items() if v not in (None, ""))
    return f"{assigns} bash {RUN_SCRIPT} {shlex.quote(sub)}".strip()


def start_env(mode: str, baud: int, laptop_ip: str | None, signing_key_file: str | None = None,
              mgmt_key_file: str | None = None, allow_unsigned: bool = False, status_port: int | None = None,
              fc_port_num: int | None = None) -> dict[str, str]:
    """Environment for ``pi_bridge_run.sh start``; the key files are paths on the Pi."""
    if mode not in MODES:
        raise CtlError(f"--mode must be one of {', '.join(MODES)}")
    if not laptop_ip:
        raise CtlError("--laptop-ip (or env LAPTOP_IP) is required: where the FC TCP port 5762 lives")
    env = {"LAPTOP_IP": laptop_ip, "MODE": mode, "BAUD": str(baud)}
    if signing_key_file:
        env["SIGNING_KEY_FILE"] = signing_key_file
    if mgmt_key_file:
        env["MGMT_KEY_FILE"] = mgmt_key_file
    if allow_unsigned:
        env["ALLOW_UNSIGNED"] = "1"
    if status_port:
        env["STATUS_PORT"] = str(status_port)
    if fc_port_num:
        env["FC_PORT_NUM"] = str(fc_port_num)
    return env


def build_deploy_archive(repo: Path = REPO) -> bytes:
    """tar.gz of src/, configs/ and scripts/radio_test (no caches), rooted so it extracts into ~/aegis_test."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel in DEPLOY_DIRS:
            base = repo / rel
            if not base.is_dir():
                raise CtlError(f"cannot deploy: {base} is not a directory")
            for path in sorted(base.rglob("*")):
                parts = path.relative_to(repo).parts
                if not path.is_file() or SKIP_PARTS & set(parts) or path.suffix == ".pyc":
                    continue
                info = tar.gettarinfo(str(path), arcname="/".join(parts))
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                if path.suffix == ".sh":
                    info.mode = 0o755
                with path.open("rb") as fh:
                    tar.addfile(info, fh)
    return buf.getvalue()


def deploy_remote_command() -> str:
    return f"mkdir -p {REMOTE_REPO} && tar xzf - -C {REMOTE_REPO} && chmod +x {REMOTE_REPO}/scripts/radio_test/*.sh"


class Ctl:
    def __init__(self, key: str, host: str, user: str) -> None:
        self.key, self.host, self.user = key, host, user

    def ssh(self, remote_cmd: str, timeout: float = 30.0, data: bytes | None = None) -> subprocess.CompletedProcess:
        argv = [*ssh_base(self.key, self.host, self.user), remote_cmd]
        try:
            return subprocess.run(argv, capture_output=True, input=data, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise CtlError(f"ssh timed out after {timeout:.0f}s running: {remote_cmd[:80]}") from exc
        except FileNotFoundError as exc:
            raise CtlError("ssh not found on PATH (install the Windows OpenSSH client)") from exc

    def run(self, remote_cmd: str, timeout: float = 30.0, data: bytes | None = None) -> int:
        """Run on the Pi, echo its output, return 0 or 1 with a readable error on failure."""
        res = self.ssh(remote_cmd, timeout, data)
        out, err = res.stdout.decode("utf-8", "replace"), res.stderr.decode("utf-8", "replace")
        if out:
            print(out, end="" if out.endswith("\n") else "\n")
        if res.returncode != 0:
            print(f"laptop_ctl: remote command failed (exit {res.returncode}): {explain_ssh_error(err, res.returncode)}",
                  file=sys.stderr)
            return 1
        if err.strip():
            print(err.strip(), file=sys.stderr)
        return 0

    def pull_logs(self, out_dir: Path, timeout: float = 180.0) -> int:
        out_dir.mkdir(parents=True, exist_ok=True)
        argv = scp_pull_command(self.key, self.host, self.user, "aegis_runs/", str(out_dir))
        try:
            res = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise CtlError(f"scp timed out after {timeout:.0f}s") from exc
        except FileNotFoundError as exc:
            raise CtlError("scp not found on PATH (install the Windows OpenSSH client)") from exc
        if res.returncode != 0:
            print(f"laptop_ctl: pull-logs failed (exit {res.returncode}): {explain_ssh_error(res.stderr, res.returncode)}",
                  file=sys.stderr)
            return 1
        print(f"logs copied to {out_dir / 'aegis_runs'}")
        return 0


def explain_ssh_error(stderr: str, code: int) -> str:
    """One-line hint for the usual ssh failures, falling back to the raw stderr."""
    low = stderr.lower()
    hints = (("permission denied", "key rejected: check ARDRA_KEY and the user"),
             ("host key verification failed", "unknown or changed host key: ssh once by hand to accept it"),
             ("timed out", "Pi unreachable: check power, Wi-Fi and the host address"),
             ("no route to host", "Pi unreachable: check Wi-Fi / address"),
             ("connection refused", "ssh server not running on the Pi"),
             ("could not resolve", "bad host name"))
    for needle, hint in hints:
        if needle in low:
            return f"{hint} ({stderr.strip().splitlines()[-1] if stderr.strip() else code})"
    return stderr.strip() or f"exit code {code}"


def resolve_key(arg: str | None) -> str:
    key = arg or os.environ.get("ARDRA_KEY", "")
    if not key:
        raise CtlError("ARDRA_KEY is not set (path of the ssh private key for the Pi)")
    if not Path(key).is_file():
        raise CtlError(f"ssh key not found: {key}")
    return key


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Control the AegisFlight bridge on the Pi over ssh")
    ap.add_argument("--host", default=os.environ.get("ARDRA_HOST", DEFAULT_HOST))
    ap.add_argument("--user", default=os.environ.get("ARDRA_USER", DEFAULT_USER))
    ap.add_argument("--key", default=None, help="ssh key (default: env ARDRA_KEY)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("deploy", help="copy src/, configs/ and scripts/radio_test to ~/aegis_test on the Pi")
    for name in ("start", "restart"):
        p = sub.add_parser(name, help=f"{name} the bridge on the Pi")
        p.add_argument("--mode", choices=MODES, default="passive")
        p.add_argument("--baud", type=int, default=57600)
        p.add_argument("--laptop-ip", default=os.environ.get("LAPTOP_IP"), help="host of the FC TCP port (env LAPTOP_IP)")
        p.add_argument("--signing-key-file", default=None, help="key path ON THE PI")
        p.add_argument("--mgmt-key-file", default=None, help="management key path ON THE PI")
        p.add_argument("--allow-unsigned", action="store_true", help="accept active-ips without signing")
        p.add_argument("--status-port", type=int, default=None)
        p.add_argument("--fc-port-num", type=int, default=None)
    sub.add_parser("stop", help="stop the bridge and the monitor (graceful)")
    sub.add_parser("status", help="bridge pid, status counters, throttling, temperature")
    sub.add_parser("kill-bridge", help="SIGKILL the bridge only (fault test); the monitor keeps recording")
    pl = sub.add_parser("pull-logs", help="copy ~/aegis_runs from the Pi")
    pl.add_argument("--out", required=True, help="local directory")
    rb = sub.add_parser("reboot-pi", help="print the reboot command; runs it only with --yes-reboot")
    rb.add_argument("--yes-reboot", action="store_true")
    return ap


def dispatch(a: argparse.Namespace, ctl: Ctl) -> int:
    if a.cmd == "deploy":
        data = build_deploy_archive()
        print(f"deploying {len(data) / 1024:.0f} KiB to {ctl.user}@{ctl.host}:~/{REMOTE_REPO}")
        return ctl.run(deploy_remote_command(), timeout=180.0, data=data)
    if a.cmd in ("start", "restart"):
        env = start_env(a.mode, a.baud, a.laptop_ip, a.signing_key_file, a.mgmt_key_file, a.allow_unsigned,
                        a.status_port, a.fc_port_num)
        if a.cmd == "restart":
            ctl.run(remote_script("stop"), timeout=40.0)
        return ctl.run(remote_script("start", env), timeout=40.0)
    if a.cmd == "stop":
        return ctl.run(remote_script("stop"), timeout=40.0)
    if a.cmd == "status":
        return ctl.run(remote_script("status"), timeout=20.0)
    if a.cmd == "kill-bridge":
        return ctl.run(remote_script("kill"), timeout=15.0)
    if a.cmd == "pull-logs":
        return ctl.pull_logs(Path(a.out))
    if a.cmd == "reboot-pi":
        cmd = [*ssh_base(ctl.key, ctl.host, ctl.user), "sudo -n reboot"]
        if not a.yes_reboot:
            print("reboot NOT run. The user must approve it. Command:\n  " + " ".join(shlex.quote(c) for c in cmd))
            print("re-run with --yes-reboot to execute")
            return 2
        res = ctl.ssh("sudo -n reboot", timeout=15.0)
        print("reboot requested" if res.returncode in (0, 255) else
              f"laptop_ctl: reboot failed: {explain_ssh_error(res.stderr.decode('utf-8', 'replace'), res.returncode)}")
        return 0 if res.returncode in (0, 255) else 1
    raise CtlError(f"unknown command {a.cmd}")


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        if a.cmd == "reboot-pi" and not a.yes_reboot:
            key = a.key or os.environ.get("ARDRA_KEY") or "$ARDRA_KEY"
            return dispatch(a, Ctl(key, a.host, a.user))
        return dispatch(a, Ctl(resolve_key(a.key), a.host, a.user))
    except CtlError as exc:
        print(f"laptop_ctl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
