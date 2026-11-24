"""Real-PTY fault-injection tests for SerialMavlinkTransport (Gap D).

Tests byte-fragmented reads, mid-frame garbage bytes, mid-flight unplug/replug
recovery, and 0 TX bytes verified on the PTY master (may_reach_vehicle()).
"""

from __future__ import annotations

import os
import select
import sys
import time

import pytest

if sys.platform == "win32":
    pytest.skip("PTY tests skip on Windows", allow_module_level=True)

import pty
import termios

from pymavlink.dialects.v20 import common as mav

from aegisflight.sources.mavlink_serial import SerialMavlinkTransport, may_reach_vehicle


def _encode_heartbeat(seq: int = 0) -> bytes:
    m = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    m.seq = seq & 0xFF
    msg = m.heartbeat_encode(
        mav.MAV_TYPE_QUADROTOR,
        mav.MAV_AUTOPILOT_PX4,
        0,
        0,
        mav.MAV_STATE_ACTIVE,
    )
    return msg.pack(m)


def _open_raw_pty() -> tuple[int, int, str]:
    master, slave = pty.openpty()
    attrs = termios.tcgetattr(slave)
    attrs[3] &= ~(termios.ECHO | termios.ICANON | termios.ISIG)
    attrs[0] &= ~(termios.ICRNL | termios.INLCR | termios.IGNCR)
    attrs[1] &= ~termios.OPOST
    termios.tcsetattr(slave, termios.TCSANOW, attrs)
    return master, slave, os.ttyname(slave)


def test_pty_byte_fragmented_reads_and_mid_frame_garbage_zero_tx() -> None:
    master, slave, slave_path = _open_raw_pty()
    transport = SerialMavlinkTransport(
        slave_path,
        baudrate=115200,
        reconnect_interval_s=0.05,
        partial_timeout_s=0.5,
    )
    try:
        transport.start()
        assert may_reach_vehicle(slave_path) is True

        frame1 = _encode_heartbeat(seq=1)
        frame2 = _encode_heartbeat(seq=2)

        # Write frame1 1 byte at a time, then garbage bytes, then frame2
        for i in range(len(frame1)):
            os.write(master, frame1[i : i + 1])
            time.sleep(0.002)

        os.write(master, b"\xfe\x05\xff\x00\xaa\xbb\xcc")
        os.write(master, frame2)

        received: list[bytes] = []
        deadline = time.monotonic() + 3.0
        while len(received) < 2 and time.monotonic() < deadline:
            for _t, pkt in transport.poll():
                received.append(pkt)
            time.sleep(0.01)

        assert received == [frame1, frame2]
        stats = transport.stats
        assert stats["bytes_sent"] == 0
        assert stats["garbage_bytes"] > 0

        # Verify 0 TX bytes arrived on the PTY master fd
        rlist, _, _ = select.select([master], [], [], 0.05)
        assert rlist == []
    finally:
        transport.close()
        os.close(slave)
        os.close(master)


def test_pty_mid_flight_unplug_and_replug_recovers(tmp_path) -> None:
    link_path = tmp_path / "ttyMAV0"
    master1, slave1, slave1_path = _open_raw_pty()
    os.symlink(slave1_path, link_path)

    transport = SerialMavlinkTransport(
        str(link_path),
        baudrate=115200,
        reconnect=True,
        reconnect_interval_s=0.05,
    )
    master2 = slave2 = None
    try:
        transport.start()
        frame1 = _encode_heartbeat(seq=10)
        os.write(master1, frame1)

        pkt1 = None
        deadline = time.monotonic() + 2.0
        while pkt1 is None and time.monotonic() < deadline:
            polled = transport.poll()
            if polled:
                pkt1 = polled[0][1]
            else:
                time.sleep(0.01)
        assert pkt1 == frame1

        # Simulate mid-flight unplug: close first PTY and remove symlink
        os.close(slave1)
        os.close(master1)
        link_path.unlink()
        time.sleep(0.15)

        # Simulate replug: new PTY at the same symlink path
        master2, slave2, slave2_path = _open_raw_pty()
        os.symlink(slave2_path, link_path)

        frame2 = _encode_heartbeat(seq=11)
        deadline = time.monotonic() + 3.0
        pkt2 = None
        while pkt2 is None and time.monotonic() < deadline:
            os.write(master2, frame2)
            polled = transport.poll()
            if polled:
                pkt2 = polled[0][1]
            else:
                time.sleep(0.02)

        assert pkt2 == frame2
        assert transport.stats["bytes_sent"] == 0
        rlist, _, _ = select.select([master2], [], [], 0.05)
        assert rlist == []
    finally:
        transport.close()
        if slave2 is not None:
            os.close(slave2)
        if master2 is not None:
            os.close(master2)
