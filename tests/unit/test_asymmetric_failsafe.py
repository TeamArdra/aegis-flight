"""Unit tests for Asymmetric Fail-Safe Bridge (W2)."""

from __future__ import annotations

from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.mitigation.types import DefenseMode


class _QueueTransport:
    def __init__(self, name: str, port: str | None = None) -> None:
        self.name = name
        self.port = port
        self.connected = True
        self.rx: list[tuple[int, bytes]] = []
        self.tx: list[bytes] = []

    def poll(self) -> list[tuple[int, bytes]]:
        out = list(self.rx)
        self.rx.clear()
        return out

    def send(self, frame: bytes) -> bool:
        self.tx.append(frame)
        return True

    def close(self) -> None:
        self.connected = False


def test_asymmetric_failsafe_drops_control_up_keeps_down_open(monkeypatch) -> None:
    fc = _QueueTransport("fc", port="socket://127.0.0.1:5760")
    gcs = _QueueTransport("gcs", port="socket://127.0.0.1:14550")
    bridge = InlineIpsBridge(
        fc,
        gcs,
        mode=DefenseMode.ACTIVE_IPS,
        unsigned_acknowledged=True,
        fail_closed_uplink_commands=True,
    )
    try:
        def _boom(_ctx):
            raise RuntimeError("injected parser/policy bug")

        monkeypatch.setattr(bridge.policy, "up", _boom)
        monkeypatch.setattr(bridge.policy, "down", _boom)

        # Uplink control frame (msgid=76 COMMAND_LONG): MUST drop fail-closed
        cmd_long = bytes([0xFD, 4, 0, 0, 1, 255, 190, 76, 0, 0, 1, 2, 3, 4, 0xAA, 0xBB])
        fc.rx.clear()
        gcs.rx = [(1000, cmd_long)]
        # Also send non-control heartbeat up (msgid=0): fails open
        hb_up = bytes([0xFD, 4, 0, 0, 2, 255, 190, 0, 0, 0, 1, 2, 3, 4, 0xAA, 0xBB])
        gcs.rx.append((2000, hb_up))
        bridge.pump_once()

        assert cmd_long not in fc.tx
        assert hb_up in fc.tx
        assert bridge.uplink_fail_closed_drops == 1
        assert bridge.dropped_up == 1

        # Downlink frame (even if msgid 33 throws): MUST fail open so telemetry reaches pilot
        gpi_down = bytes([0xFD, 4, 0, 0, 1, 1, 1, 33, 0, 0, 1, 2, 3, 4, 0xAA, 0xBB])
        fc.rx = [(3000, gpi_down)]
        bridge.pump_once()
        assert gpi_down in gcs.tx
        assert bridge.dropped_down == 0
    finally:
        bridge.close()
