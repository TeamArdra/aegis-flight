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

from run_p4_signing_trial import (  # noqa: E402
    SigningProvisioningError,
    observe_vehicle_armed_state,
    provision_px4_signing,
    require_disarmed,
)


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


# --- MAC verification (the header bit alone is attacker-controlled) -------------------------


def test_wrong_key_signed_heartbeat_is_not_verified() -> None:
    """A HEARTBEAT that claims a signature but carries a MAC from another key must not verify."""
    good_key = hashlib.sha256(b"unit-test-signing-key-good").digest()
    wrong_key = hashlib.sha256(b"unit-test-signing-key-wrong").digest()
    forged = _make_signed_heartbeat(wrong_key, sysid=1, compid=1, armed=False, sign=True)
    gcs = _FakeGcsTransport(send_ok=True, rx_frames=[forged])
    events: list[dict] = []

    def record(event: str, **fields: object) -> None:
        events.append({"event": event, **fields})

    with pytest.raises(SigningProvisioningError, match="Timed out"):
        provision_px4_signing(gcs, 1, 1, good_key, verify_timeout_s=0.2, record_fn=record, is_armed=False)

    assert "px4_signing_verified" not in [e["event"] for e in events]


def test_wrong_key_frame_does_not_hide_behind_a_valid_neighbour_in_one_datagram() -> None:
    """A datagram with a valid frame from sysid 2 and a wrong-key frame from sysid 1 verifies nothing for sysid 1."""
    good_key = hashlib.sha256(b"unit-test-signing-key-good-2").digest()
    wrong_key = hashlib.sha256(b"unit-test-signing-key-wrong-2").digest()
    datagram = (
        _make_signed_heartbeat(good_key, sysid=2, compid=1, sign=True)
        + _make_signed_heartbeat(wrong_key, sysid=1, compid=1, sign=True)
    )
    gcs = _FakeGcsTransport(send_ok=True, rx_frames=[datagram])

    with pytest.raises(SigningProvisioningError, match="Timed out"):
        provision_px4_signing(gcs, 1, 1, good_key, verify_timeout_s=0.2, is_armed=False)


def test_correct_key_signed_heartbeat_is_verified_with_mac_flag() -> None:
    key = hashlib.sha256(b"unit-test-signing-key-correct").digest()
    gcs = _FakeGcsTransport(send_ok=True, rx_frames=[_make_signed_heartbeat(key, sysid=1, compid=1)])

    result = provision_px4_signing(gcs, 1, 1, key, verify_timeout_s=0.5, is_armed=False)

    assert result["verified"] is True
    assert result["mac_verified"] is True


class _HeartbeatGcs(_FakeGcsTransport):
    """Fake whose poll() keeps returning the same frames (a vehicle heartbeating at the GCS)."""

    def __init__(self, frames: list[bytes]) -> None:
        super().__init__(send_ok=True)
        self._frames = frames

    def poll(self) -> list[tuple[float, bytes]]:
        return [(0.0, raw) for raw in self._frames]


def test_observe_vehicle_armed_state_reports_armed_and_disarmed() -> None:
    key = hashlib.sha256(b"unit-test-signing-key-armed-obs").digest()
    armed = _HeartbeatGcs([_make_signed_heartbeat(key, sysid=1, armed=True, sign=False)])
    disarmed = _HeartbeatGcs([_make_signed_heartbeat(key, sysid=1, armed=False, sign=False)])
    assert observe_vehicle_armed_state(armed, 1, timeout_s=0.5) is True
    assert observe_vehicle_armed_state(disarmed, 1, timeout_s=0.5) is False


def test_observe_vehicle_armed_state_unknown_without_heartbeat_from_target() -> None:
    key = hashlib.sha256(b"unit-test-signing-key-armed-unk").digest()
    other = _HeartbeatGcs([_make_signed_heartbeat(key, sysid=9, armed=False, sign=False)])
    assert observe_vehicle_armed_state(other, 1, timeout_s=0.1) is None


def test_require_disarmed_fails_closed_on_armed_and_on_unknown() -> None:
    key = hashlib.sha256(b"unit-test-signing-key-require").digest()
    armed = _HeartbeatGcs([_make_signed_heartbeat(key, sysid=1, armed=True, sign=False)])
    with pytest.raises(SigningProvisioningError, match="armed"):
        require_disarmed(armed, 1, timeout_s=0.5)
    silent = _HeartbeatGcs([])
    with pytest.raises(SigningProvisioningError, match="unknown"):
        require_disarmed(silent, 1, timeout_s=0.1)
    ok = _HeartbeatGcs([_make_signed_heartbeat(key, sysid=1, armed=False, sign=False)])
    assert require_disarmed(ok, 1, timeout_s=0.5) is False
