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


# --------------------------------------------------------------------------- F4 follow-up: the replay state fails closed
# A missing file is a first run. A file that cannot be read or understood, or a path that cannot be written, refuses to start;
# a write that fails at command time means the command is NOT executed.


def _recording_channel(host: _Host, key: bytes, state: str, audit: str | None = None) -> tuple[MgmtChannel, list[bytes]]:
    sent: list[bytes] = []
    ch = MgmtChannel(lambda b: sent.append(bytes(b)) or True, FrameSender(None), host, mgmt_key=key, state_path=state,
                     audit_path=audit, status_interval_s=0)
    return ch, sent


def _acks(sent: list[bytes]) -> list[dict]:
    from aegisflight.hal.mgmt_channel import decode_mgmt_frame
    from aegisflight.proxy.transport import split_frames

    return [d for f in sent for fr in split_frames(f)[0] if (d := decode_mgmt_frame(fr.raw)) and d["kind"] == "ack"]


@pytest.mark.parametrize("body", [
    b"{not json MARKER-7f3a",
    b'{"floor": "MARKER-7f3a"}',
    b'{"streams": ["MARKER-7f3a"], "floor": 5}',
    b'{"streams": {"1,2": 5}}',
    b'{"streams": {"1,2,3": -5}}',
    b'{"floor": -1}',
    b'["MARKER-7f3a"]',
    b"\xff\xfe\x00MARKER-7f3a",
])
def test_a_corrupt_replay_state_file_is_refused_without_quoting_it(tmp_path, body: bytes) -> None:  # type: ignore[no-untyped-def]
    state = tmp_path / "mgmt_state.json"
    state.write_bytes(body)
    with pytest.raises(ValueError) as err:
        _channel(_Host(), os.urandom(32), str(state))
    msg = str(err.value)
    assert str(state) in msg and "refusing to start" in msg and "replay window" in msg and "max_cmd_age_s" in msg
    assert "MARKER" not in msg and err.value.__cause__ is None


def test_a_directory_as_the_replay_state_path_is_refused(tmp_path) -> None:  # type: ignore[no-untyped-def]
    state = tmp_path / "state_dir"
    state.mkdir()
    with pytest.raises(ValueError, match="cannot be read"):
        _channel(_Host(), os.urandom(32), str(state))


def test_an_unwritable_replay_state_path_is_refused_at_construction(tmp_path) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError, match="cannot be written"):
        _channel(_Host(), os.urandom(32), str(tmp_path / "no_such_dir" / "mgmt_state.json"))


def test_a_missing_replay_state_file_starts_fresh_and_is_created(tmp_path) -> None:  # type: ignore[no-untyped-def]
    key, host = os.urandom(32), _Host()
    state = tmp_path / "mgmt_state.json"
    ch = _channel(host, key, str(state))
    assert state.exists()  # the construction-time probe wrote it
    cmd = build_command_frame(key, OP_SET_POSTURE, posture=1)
    ch.handle_command(cmd, is_mgmt_command(cmd))
    assert host.calls == 1


def test_a_state_write_failure_at_command_time_denies_the_command_and_the_replay_stays_rejected(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import json

    import aegisflight.hal.mgmt_channel as mc
    from aegisflight.mavlink.signing import MavlinkSignatureVerifier

    key, host = os.urandom(32), _Host()
    signer = MavlinkSignatureVerifier(key)
    audit = tmp_path / "audit.jsonl"
    ch, sent = _recording_channel(host, key, str(tmp_path / "mgmt_state.json"), str(audit))
    real_replace = mc.os.replace

    def _fail(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(mc.os, "replace", _fail)
    recorded = build_command_frame(key, OP_SET_POSTURE, posture=1, signer=signer)
    ch.handle_command(recorded, is_mgmt_command(recorded))
    assert host.calls == 0 and host.posture == "passive"  # NOT executed
    assert [(a["result"], a["result_param2"]) for a in _acks(sent)] == [(mc.R_DENIED, mc.D_STATE_UNWRITABLE)]
    entries = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert any(e.get("result") == "denied" and e.get("reason") == "replay_state_unwritable" for e in entries)
    monkeypatch.setattr(mc.os, "replace", real_replace)
    ch.handle_command(recorded, is_mgmt_command(recorded))  # the disk works again: the same frame is still a replay
    assert host.calls == 0
    last = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
    assert last["result"] == "ignored" and "replay" in last["reason"]  # the in-memory replay state was advanced
    fresh = build_command_frame(key, OP_SET_POSTURE, posture=1, signer=signer)
    ch.handle_command(fresh, is_mgmt_command(fresh))
    assert host.calls == 1  # a new command executes once the state can be written


def test_the_bridge_cli_refuses_an_unusable_replay_state_with_exit_2(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    cli = importlib.import_module("aegisflight.cli.main")  # the package re-exports main(), shadowing the module
    keyf = tmp_path / "mgmt.key"
    keyf.write_bytes(os.urandom(32))
    state = tmp_path / "state_dir"
    state.mkdir()
    args = ["ips-bridge", "--fc-port", "socket://127.0.0.1:1", "--gcs-port", "socket://127.0.0.1:2", "--allow-url",
            "--mgmt-key-file", str(keyf), "--mgmt-state", str(state),
            "--seconds", "0.1"]  # bounded: if the refusal ever regresses the bridge would otherwise run forever
    assert cli.main(args) == 2
    err = capsys.readouterr().err
    assert "management replay state" in err and "refusing to start" in err and "Traceback" not in err
