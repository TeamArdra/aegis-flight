"""Management-key handling (security review of PR #39, F4).

F4: only the CLI refused ``--mgmt-key-file`` without ``--mgmt-state``; ``MgmtChannel`` / ``InlineIpsBridge`` accepted a key with no
replay-state path, so one recorded management command executed again after a restart. Keys are generated per test, never printed.
"""

from __future__ import annotations

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
