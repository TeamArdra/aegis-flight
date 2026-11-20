"""Unplug/replug must read as a transport fault, not RF DoS / MAVLink anomaly (SIM, synthetic envelopes)."""

from __future__ import annotations

from aegisflight.core.types import MessageEnvelope
from aegisflight.features.extractor import FeatureExtractor


def _env(t: float, name: str, seq: int) -> MessageEnvelope:
    return MessageEnvelope(recv_time=t, sysid=1, compid=1, msgid=0, msgname=name, seq=seq,
                           signed=False, byte_len=20, fields={})


def _run_to(ext: FeatureExtractor, t0: float, t1: float, seq: int) -> int:
    t = t0
    while t < t1:
        ext.update(_env(t, "HEARTBEAT", seq & 0xFF))
        seq += 1
        t += 0.2
    return seq


def test_reconnect_masks_stale_heartbeat_and_seq_gap_until_fresh_heartbeat() -> None:
    ext = FeatureExtractor()
    seq = _run_to(ext, 0.0, 10.0, 0)
    ext.note_transport_connected(True)
    ext.note_transport_connected(False)
    assert ext.extract(15.0).transport_connected is False
    # replug 9 s later; first message back has a big sequence jump and heartbeat is stale
    ext.update(_env(19.0, "ATTITUDE", (seq + 200) & 0xFF))
    ext.note_transport_connected(True)
    f = ext.extract(19.0)
    assert f.heartbeat_age_s > 8.0 and f.max_seq_gap == 0
    assert f.transport_connected is False  # still resyncing: protocol treats silence as transport fault
    ext.update(_env(19.2, "HEARTBEAT", (seq + 201) & 0xFF))
    f = ext.extract(19.2)
    assert f.transport_connected is True and f.heartbeat_age_s < 1.0


def test_resync_is_bounded_so_post_reconnect_jamming_still_alerts() -> None:
    ext = FeatureExtractor()
    _run_to(ext, 0.0, 10.0, 0)
    ext.note_transport_connected(False)
    ext.note_transport_connected(True)
    assert ext.extract(20.0).transport_connected is False
    assert ext.extract(26.0).transport_connected is True  # > 5 s without a heartbeat: real silence


def test_no_disconnect_never_masks() -> None:
    ext = FeatureExtractor()
    _run_to(ext, 0.0, 10.0, 0)
    ext.note_transport_connected(True)
    assert ext.extract(30.0).transport_connected is True
