"""iter_tlog against the real pymavlink parser (no mocks): undefined message ids are skipped.

pymavlink reports a frame whose message id the dialect does not define as ``UNKNOWN_<id>`` and, because no header is
attached to it, with ``srcSystem == srcComponent == 0`` even when the frame header carried the real ids. Real PX4
SITL tlogs contain such frames (about 1.6 % of ``benign_001.tlog``: ids 8, 290, 291, 380, 410, 411, 436, 441, 514).
Counted as a source they appear as a phantom ``0/0`` vehicle. ``tests/unit/test_tlog_unknown_msgid.py`` covers the
filter with fakes; this file builds a real tlog byte stream so the pymavlink behaviour itself is pinned.
"""

from __future__ import annotations

import struct
from pathlib import Path

from pymavlink.dialects.v20 import ardupilotmega as apm

from aegisflight.external.tlog_adapter import iter_tlog

_UNDEFINED_MSGID = 8  # not defined by the ardupilotmega dialect in this pymavlink, as in the real PX4 logs


def _frame_with_undefined_msgid(sysid: int, compid: int) -> bytes:
    # MAVLink 2 header: magic, len, incompat, compat, seq, sysid, compid, msgid (3 bytes LE), payload, crc (2 bytes)
    return bytes([0xFD, 3, 0, 0, 7, sysid, compid, _UNDEFINED_MSGID, 0, 0, 1, 2, 3, 0, 0])


def _write_tlog(path: Path, frames: list[bytes]) -> None:
    with path.open("wb") as fh:
        for i, frame in enumerate(frames):
            fh.write(struct.pack(">Q", 1_700_000_000_000_000 + i * 1000) + frame)  # GCS timestamp (us), big endian


def test_real_parser_undefined_msgid_is_skipped_and_known_frames_are_kept(tmp_path: Path) -> None:
    enc = apm.MAVLink(None, srcSystem=1, srcComponent=1)
    hb = bytes(apm.MAVLink_heartbeat_message(2, 3, 0x81, 5, 4, 3).pack(enc))
    path = tmp_path / "t.tlog"
    _write_tlog(path, [hb, _frame_with_undefined_msgid(1, 1), hb])

    envs = list(iter_tlog(path))

    assert [e.msgname for e in envs] == ["HEARTBEAT", "HEARTBEAT"]
    assert all((e.sysid, e.compid) == (1, 1) for e in envs)


def test_real_parser_reports_undefined_msgid_as_sys0_comp0_even_with_real_header_ids(tmp_path: Path) -> None:
    """Pins the pymavlink behaviour the filter relies on, so a pymavlink upgrade that changes it fails loudly."""
    from pymavlink import mavutil

    path = tmp_path / "t.tlog"
    _write_tlog(path, [_frame_with_undefined_msgid(1, 1)])
    conn = mavutil.mavlink_connection(str(path), dialect="ardupilotmega", robust_parsing=True)
    msg = conn.recv_match(blocking=False)

    assert msg is not None
    assert msg.get_type() == f"UNKNOWN_{_UNDEFINED_MSGID}"
    assert (msg.get_srcSystem(), msg.get_srcComponent()) == (0, 0)
