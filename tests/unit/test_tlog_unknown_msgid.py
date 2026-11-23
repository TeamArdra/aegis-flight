"""Regression test: tlog_adapter ignores UNKNOWN_* frames with sysid=0, compid=0."""

from __future__ import annotations

from unittest.mock import patch

from aegisflight.external.tlog_adapter import iter_tlog


class _FakeMsg:
    def __init__(self, msg_type: str, sysid: int, compid: int, msgid: int = 99999) -> None:
        self._type = msg_type
        self._sysid = sysid
        self._compid = compid
        self._msgid = msgid
        self._timestamp = 1700000000.0

    def get_type(self) -> str:
        return self._type

    def get_srcSystem(self) -> int:  # noqa: N802
        return self._sysid

    def get_srcComponent(self) -> int:  # noqa: N802
        return self._compid

    def get_msgId(self) -> int:  # noqa: N802
        return self._msgid

    def get_seq(self) -> int:
        return 1

    def to_dict(self) -> dict[str, object]:
        return {"mavpackettype": self._type}

    def get_msgbuf(self) -> bytes:
        return b"\x00" * 12


class _FakeConn:
    def __init__(self, msgs: list[_FakeMsg]) -> None:
        self._msgs = list(msgs)

    def recv_match(self, blocking: bool = False) -> _FakeMsg | None:
        return self._msgs.pop(0) if self._msgs else None


def test_iter_tlog_ignores_unknown_sys0_comp0() -> None:
    msgs = [
        _FakeMsg("UNKNOWN_42000", sysid=0, compid=0, msgid=42000),
        _FakeMsg("HEARTBEAT", sysid=1, compid=1, msgid=0),
        _FakeMsg("UNKNOWN_42001", sysid=1, compid=1, msgid=42001),
    ]
    with patch("pymavlink.mavutil.mavlink_connection", return_value=_FakeConn(msgs)):
        envs = list(iter_tlog("dummy.tlog"))

    assert [e.msgname for e in envs] == ["HEARTBEAT", "UNKNOWN_42001"]
    assert all(not (e.msgname.startswith("UNKNOWN_") and e.sysid == 0 and e.compid == 0) for e in envs)
