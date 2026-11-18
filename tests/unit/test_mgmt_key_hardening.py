"""Management / signing key handling (security review of PR #39, F4 and F5).

F4: only the CLI refused ``--mgmt-key-file`` without ``--mgmt-state``; ``MgmtChannel`` / ``InlineIpsBridge`` accepted a key with no
replay-state path, so one recorded management command executed again after a restart.
F5: a malformed key file put a key byte into the error text the CLI prints (load_signing_key and the ips-bridge copies).
Keys are generated per test, never printed.
"""

from __future__ import annotations

import importlib
import os

import pytest

from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.hal.mgmt_channel import (
    OP_SET_POSTURE,
    FrameSender,
    MgmtChannel,
    build_command_frame,
    is_mgmt_command,
)


class _Host:
    def __init__(self) -> None:
        self.posture = "passive"
        self.calls = 0

    def mgmt_snapshot(self):  # type: ignore[no-untyped-def]
        return {"posture": self.posture, "flags": {}}

    def mgmt_set_posture(self, mode: str, allow_unsigned: bool) -> None:
        self.posture, self.calls = mode, self.calls + 1

    def mgmt_ack_alarms(self) -> None:
        pass


class _Link:
    connected = True
    port = "socket://127.0.0.1:1"

    def poll(self):  # type: ignore[no-untyped-def]
        return []

    def send(self, _data: bytes) -> bool:
        return True

    def close(self) -> None:
        pass


def _channel(host: _Host, key: bytes | None, state: str | None) -> MgmtChannel:
    return MgmtChannel(lambda _b: True, FrameSender(None), host, mgmt_key=key, state_path=state, status_interval_s=0)


def test_a_management_key_without_replay_state_is_refused_by_the_channel() -> None:
    with pytest.raises(ValueError, match="replay-state"):
        _channel(_Host(), os.urandom(32), None)
    with pytest.raises(ValueError, match="replay-state"):
        _channel(_Host(), os.urandom(32), "")


def test_a_management_key_without_replay_state_is_refused_by_the_bridge() -> None:
    with pytest.raises(ValueError, match="replay-state"):
        InlineIpsBridge(_Link(), _Link(), mgmt_key=os.urandom(32))  # type: ignore[arg-type]


def test_a_recorded_command_executes_once_across_a_restart(tmp_path) -> None:  # type: ignore[no-untyped-def]
    key = os.urandom(32)
    recorded = build_command_frame(key, OP_SET_POSTURE, posture=1)  # "advisory", captured by an eavesdropper
    host = _Host()
    state = str(tmp_path / "mgmt_state.json")
    for _restart in range(2):
        _channel(host, key, state).handle_command(recorded, is_mgmt_command(recorded))
        host.posture = "passive"  # the pilot lowers it again locally, then the bridge restarts
    assert host.calls == 1


def test_without_a_management_key_no_state_is_needed() -> None:
    assert _channel(_Host(), None, None).control_enabled is False


# --------------------------------------------------------------------------- F5
# A raw 32-byte key saved with a trailing newline (33 bytes) is decoded as hex text; the UnicodeDecodeError quoted one key byte,
# and the CLI printed it to stderr.


MARKER = 0xE7  # a recognisable non-ASCII byte placed first in the key, so decoding the file as hex text fails on it


def _bad_key_file(tmp_path) -> tuple[str, bytes]:  # type: ignore[no-untyped-def]
    body = bytearray(os.urandom(32))
    body[0] = MARKER
    path = tmp_path / "key.bin"
    path.write_bytes(bytes(body) + b"\n")  # 33 bytes: neither a raw key nor hex text
    return str(path), bytes(body)


def _quotes_a_key_byte(text: str, key: bytes) -> bool:
    """The marker in any form (hex, repr escape, the character, decimal), or any key byte as 0x.. / \\x.."""
    low = text.lower()
    marker_forms = (f"0x{MARKER:02x}", "\\x" + f"{MARKER:02x}", chr(MARKER), str(MARKER))
    if any(form in low for form in marker_forms):
        return True
    return any(f"0x{b:02x}" in low or ("\\x" + f"{b:02x}") in low for b in key)


def test_a_malformed_key_file_error_carries_fixed_text_and_no_key_byte(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from aegisflight.detectors.crossend import load_signing_key

    path, key = _bad_key_file(tmp_path)
    with pytest.raises(ValueError) as err:
        load_signing_key(path)
    assert type(err.value) is ValueError and err.value.__cause__ is None and err.value.__suppress_context__
    assert not _quotes_a_key_byte(str(err.value), key)
    assert str(err.value) == "key file must hold 32 raw bytes or 64 hex characters"


@pytest.mark.parametrize("flag", ["--mgmt-key-file", "--signing-key-file"])
def test_the_bridge_cli_never_prints_key_bytes_for_a_malformed_key_file(tmp_path, capsys, flag: str) -> None:  # type: ignore[no-untyped-def]
    cli = importlib.import_module("aegisflight.cli.main")  # the package re-exports main(), shadowing the module

    path, key = _bad_key_file(tmp_path)
    args = ["ips-bridge", "--fc-port", "socket://127.0.0.1:1", "--gcs-port", "socket://127.0.0.1:2", "--allow-url",
            flag, path, "--mgmt-state", str(tmp_path / "state.json")]
    assert cli.main(args) == 2
    err = capsys.readouterr().err
    assert f"bad {flag}" in err and not _quotes_a_key_byte(err, key)


def test_serve_never_prints_key_bytes_for_a_malformed_management_key_file(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    cli = importlib.import_module("aegisflight.cli.main")  # the package re-exports main(), shadowing the module

    path, key = _bad_key_file(tmp_path)
    assert cli.main(["serve", "--mgmt-key-file", path]) == 2
    err = capsys.readouterr().err
    assert "bad --mgmt-key-file" in err and not _quotes_a_key_byte(err, key)
