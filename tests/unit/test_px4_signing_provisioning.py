"""Unit tests for PX4-side MAVLink 2 signing provisioning (disarmed bootstrap + fail-closed)."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest
from pymavlink.dialects.v20 import common as mavlink2

# Allow importing scripts/sitl/run_p4_signing_trial.py without modifying package layout
_SITL_DIR = Path(__file__).resolve().parents[2] / "scripts" / "sitl"
if str(_SITL_DIR) not in sys.path:
    sys.path.insert(0, str(_SITL_DIR))

from run_p4_signing_trial import SigningProvisioningError, provision_px4_signing  # noqa: E402


def _make_signed_heartbeat(
    secret_key: bytes,
    *,
    sysid: int = 1,
    compid: int = 1,
    armed: bool = False,
    sign: bool = True,
) -> bytes:
    """Encode a MAVLink 2 HEARTBEAT frame, optionally signed with ``secret_key``."""
    m = mavlink2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    if sign:
        m.signing.secret_key = secret_key
        m.signing.link_id = 0
        m.signing.timestamp = 1001
        m.signing.sign_outgoing = True
    base_mode = mavlink2.MAV_MODE_FLAG_SAFETY_ARMED if armed else 0
    msg = m.heartbeat_encode(
        mavlink2.MAV_TYPE_QUADROTOR,
        mavlink2.MAV_AUTOPILOT_PX4,
        base_mode,
        0,
        mavlink2.MAV_STATE_STANDBY,
    )
    return bytes(msg.pack(m))


class _FakeGcsTransport:
    """Minimal duck-typed UdpMavlinkTransport for testing ``provision_px4_signing``."""

    def __init__(self, *, send_ok: bool = True, rx_frames: list[bytes] | None = None) -> None:
        self.send_ok = send_ok
        self.rx_frames = list(rx_frames or [])
        self.sent_messages: list[bytes] = []
        self.signing_enabled_with: tuple[bytes, int] | None = None
        self._seq = 0

    def send_gcs_message(self, encode_fn) -> tuple[bool, int]:
        m = mavlink2.MAVLink(None, srcSystem=255, srcComponent=190)
        msg = encode_fn(m)
        self.sent_messages.append(bytes(msg.pack(m)))
        self._seq += 1
        return self.send_ok, self._seq

    def enable_signing(self, secret_key: bytes, *, link_id: int = 0, initial_timestamp: int = 0) -> None:
        self.signing_enabled_with = (secret_key, initial_timestamp)

    def poll(self) -> list[tuple[float, bytes]]:
        if not self.rx_frames:
            return []
        batch = [(0.0, raw) for raw in self.rx_frames]
        self.rx_frames.clear()
        return batch


def test_disarmed_provisioning_succeeds_and_verifies_signed_frame() -> None:
    secret_key = hashlib.sha256(b"unit-test-signing-key-1").digest()
    signed_hb = _make_signed_heartbeat(secret_key, sysid=1, compid=1, armed=False, sign=True)
    gcs = _FakeGcsTransport(send_ok=True, rx_frames=[signed_hb])
    events: list[dict] = []

    def record(event: str, **fields: object) -> None:
        events.append({"event": event, **fields})

    result = provision_px4_signing(
        gcs, 1, 1, secret_key, initial_timestamp=1000, verify_timeout_s=0.5, record_fn=record, is_armed=False
    )

    assert result["verified"] is True
    assert result["msgname"] == "HEARTBEAT"
    assert result["src_sysid"] == 1
    assert gcs.signing_enabled_with == (secret_key, 1000)
    assert [e["event"] for e in events] == [
        "setup_signing_sent",
        "gcs_signing_enabled",
        "px4_signing_verified",
    ]


def test_fail_closed_when_armed() -> None:
    secret_key = hashlib.sha256(b"unit-test-signing-key-2").digest()
    gcs = _FakeGcsTransport(send_ok=True)

    with pytest.raises(SigningProvisioningError, match="armed"):
        provision_px4_signing(gcs, 1, 1, secret_key, verify_timeout_s=0.1, is_armed=True)

    assert gcs.sent_messages == []
    assert gcs.signing_enabled_with is None


def test_fail_closed_when_armed_heartbeat_observed() -> None:
    secret_key = hashlib.sha256(b"unit-test-signing-key-3").digest()
    armed_hb = _make_signed_heartbeat(secret_key, sysid=1, compid=1, armed=True, sign=True)
    gcs = _FakeGcsTransport(send_ok=True, rx_frames=[armed_hb])

    with pytest.raises(SigningProvisioningError, match="armed"):
        provision_px4_signing(gcs, 1, 1, secret_key, verify_timeout_s=0.5)


def test_fail_closed_on_missing_signed_frames() -> None:
    secret_key = hashlib.sha256(b"unit-test-signing-key-4").digest()
    unsigned_hb = _make_signed_heartbeat(secret_key, sysid=1, compid=1, armed=False, sign=False)
    gcs = _FakeGcsTransport(send_ok=True, rx_frames=[unsigned_hb])

    with pytest.raises(SigningProvisioningError, match="Timed out"):
        provision_px4_signing(gcs, 1, 1, secret_key, verify_timeout_s=0.1)


def test_fail_closed_when_setup_signing_send_fails() -> None:
    secret_key = hashlib.sha256(b"unit-test-signing-key-5").digest()
    gcs = _FakeGcsTransport(send_ok=False)

    with pytest.raises(SigningProvisioningError, match="Failed to send SETUP_SIGNING"):
        provision_px4_signing(gcs, 1, 1, secret_key, verify_timeout_s=0.1)

    assert gcs.signing_enabled_with is None


def test_zero_key_byte_leakage_in_logs() -> None:
    secret_key = hashlib.sha256(b"unit-test-signing-key-leak-check").digest()
    signed_hb = _make_signed_heartbeat(secret_key, sysid=1, compid=1, armed=False, sign=True)
    gcs = _FakeGcsTransport(send_ok=True, rx_frames=[signed_hb])
    events: list[dict] = []

    def record(event: str, **fields: object) -> None:
        events.append({"event": event, **fields})

    provision_px4_signing(
        gcs, 1, 1, secret_key, initial_timestamp=1000, verify_timeout_s=0.5, record_fn=record
    )

    serialized = json.dumps(events)
    assert secret_key.hex() not in serialized
    assert base64.b64encode(secret_key).decode("ascii") not in serialized
    assert repr(secret_key) not in serialized
