"""Unit tests for SITL proxy downlink telemetry-manipulation, firmware-identity,
and restricted-visibility injection scenarios (#24)."""

from __future__ import annotations

from pathlib import Path

from pymavlink.dialects.v20 import common as mav2

from aegisflight.proxy import (
    AltitudeBiasAttack,
    AltitudeBiasParams,
    BatteryJumpAttack,
    BatteryJumpParams,
    BenignPilotControlHook,
    FirmwareIdentityAttack,
    FirmwareIdentityParams,
    FrameContext,
    FrameLogWriter,
    FrozenAttitudeAttack,
    FrozenAttitudeParams,
    SpeedMismatchAttack,
    SpeedMismatchParams,
    build_restricted_visibility_hook,
    read_frame_log,
)

_NS = 1_000_000_000


def _mk(sysid: int = 3, compid: int = 1, seq: int = 0, signed: bool = False):
    m = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)
    m.seq = seq
    if signed:
        m.signing.secret_key = bytes(32)
        m.signing.sign_outgoing = True
        m.signing.link_id = 0
        m.signing.timestamp = 1000
    return m


def _ctx(raw: bytes, *, direction: str = "down", recv_s: float = 0.0) -> FrameContext:
    incompat = raw[2]
    seq, sysid, compid = raw[4], raw[5], raw[6]
    msgid = raw[7] | (raw[8] << 8) | (raw[9] << 16)
    return FrameContext(
        direction=direction,
        raw=raw,
        recv_ns=int(recv_s * _NS),
        sysid=sysid,
        compid=compid,
        seq=seq,
        msgid=msgid,
        signed=bool(incompat & 0x01),
    )


def _hb(seq: int = 0, sysid: int = 3, compid: int = 1, autopilot: int = 12) -> bytes:
    m = _mk(sysid, compid, seq)
    return bytes(m.heartbeat_encode(mav2.MAV_TYPE_QUADROTOR, autopilot, 0x80, 0, 4).pack(m))


def _decode(raw: bytes):
    return mav2.MAVLink(None).decode(bytearray(raw))


def test_altitude_bias_rewrites_gpi_and_vfr_with_valid_crc_and_ground_truth(tmp_path: Path) -> None:
    log_path = tmp_path / "frames.jsonl"
    with FrameLogWriter(log_path) as lw:
        atk = AltitudeBiasAttack(
            AltitudeBiasParams(onset_s=5.0, duration_s=10.0, bias_rate_ms=2.0, max_bias_m=50.0),
            warmup_s=0.0,
            frame_log=lw,
        )
        assert atk(_ctx(_hb(), recv_s=0.0))  # learns PX4 target (3, 1)

        gpi_orig = bytes(
            _mk(3, 1, 1).global_position_int_encode(1000, 470_000_000, 80_000_000, 50_000, 10_000, 0, 0, 0, 0).pack(
                _mk(3, 1, 1)
            )
        )
        out_gpi = atk(_ctx(gpi_orig, recv_s=8.0))  # 3 s into attack => +6 m = +6000 mm
        assert len(out_gpi) == 1
        d_gpi = _decode(out_gpi[0])
        assert d_gpi.relative_alt == 16_000
        assert d_gpi.alt == 56_000

        vfr_orig = bytes(_mk(3, 1, 2).vfr_hud_encode(10.0, 10.0, 90, 50, 10.0, 0.0).pack(_mk(3, 1, 2)))
        out_vfr = atk(_ctx(vfr_orig, recv_s=8.0))
        d_vfr = _decode(out_vfr[0])
        assert d_vfr.alt == 16.0

        # Signed frame untouched & counted
        gpi_signed = bytes(
            _mk(3, 1, 3, signed=True)
            .global_position_int_encode(1000, 470_000_000, 80_000_000, 50_000, 10_000, 0, 0, 0, 0)
            .pack(_mk(3, 1, 3, signed=True))
        )
        assert atk(_ctx(gpi_signed, recv_s=9.0)) == [gpi_signed]
        assert atk.frames_modified == 2
        assert atk.frames_skipped_signed == 1

    entries = read_frame_log(log_path)
    mods = [e for e in entries if e.action == "modified"]
    assert len(mods) == 2
    assert all(e.crc_recomputed is True for e in mods)
    assert mods[0].field_deltas["relative_alt_mm"] == 6000


def test_speed_mismatch_battery_jump_frozen_attitude_and_firmware_identity(tmp_path: Path) -> None:
    log_path = tmp_path / "fw.jsonl"
    with FrameLogWriter(log_path) as lw:
        spd = SpeedMismatchAttack(SpeedMismatchParams(onset_s=1.0, duration_s=10.0, scale_factor=2.0), warmup_s=0.0)
        bat = BatteryJumpAttack(BatteryJumpParams(onset_s=1.0, duration_s=10.0, delta_mv=3000), warmup_s=0.0)
        att = FrozenAttitudeAttack(FrozenAttitudeParams(onset_s=1.0, duration_s=10.0), warmup_s=0.0)
        fw = FirmwareIdentityAttack(
            FirmwareIdentityParams(onset_s=1.0, duration_s=10.0, spoof_sw_version=0xCAFEBABE, spoof_custom_version=b"12345678"),
            warmup_s=0.0,
            frame_log=lw,
        )
        for h in (spd, bat, att, fw):
            h(_ctx(_hb(), recv_s=0.0))

        vfr = bytes(_mk(3, 1, 1).vfr_hud_encode(8.0, 7.5, 90, 50, 20.0, 0.0).pack(_mk(3, 1, 1)))
        assert _decode(spd(_ctx(vfr, recv_s=2.0))[0]).groundspeed == 15.0

        sys_st = bytes(_mk(3, 1, 1).sys_status_encode(0, 0, 0, 100, 12_000, -1, 80, 0, 0, 0, 0, 0, 0).pack(_mk(3, 1, 1)))
        assert _decode(bat(_ctx(sys_st, recv_s=2.0))[0]).voltage_battery == 15_000

        att1 = bytes(_mk(3, 1, 1).attitude_encode(2000, 0.1, 0.2, 1.0, 0.01, 0.02, 0.03).pack(_mk(3, 1, 1)))
        att2 = bytes(_mk(3, 1, 2).attitude_encode(3000, 0.9, -0.5, 2.5, 0.5, 0.5, 0.5).pack(_mk(3, 1, 2)))
        att(_ctx(att1, recv_s=2.0))
        d_att2 = _decode(att(_ctx(att2, recv_s=3.0))[0])
        assert round(d_att2.roll, 2) == 0.1
        assert d_att2.time_boot_ms == 3000

        av = bytes(
            _mk(3, 1, 1)
            .autopilot_version_encode(1, 0x01040000, 0, 0, 0, b"abcdefgh", b"12345678", b"87654321", 0, 0, 0, b"\x00" * 18)
            .pack(_mk(3, 1, 1))
        )
        signed_av = bytes(
            _mk(3, 1, 2, signed=True)
            .autopilot_version_encode(1, 0x01040000, 0, 0, 0, b"abcdefgh", b"12345678", b"87654321", 0, 0, 0, b"\x00" * 18)
            .pack(_mk(3, 1, 2, signed=True))
        )
        assert fw(_ctx(signed_av, recv_s=2.0)) == [signed_av]
        assert fw.frames_skipped_signed == 1
        d_av = _decode(fw(_ctx(av, recv_s=2.5))[0])
        assert d_av.flight_sw_version == 0xCAFEBABE
        assert bytes(d_av.flight_custom_version) == b"12345678"

    entries = read_frame_log(log_path)
    assert any(e.action == "modified" and e.crc_recomputed for e in entries)


def test_restricted_visibility_injection_scenarios() -> None:
    gcs_hb = bytes(_mk(255, 190, 12).heartbeat_encode(mav2.MAV_TYPE_GCS, mav2.MAV_AUTOPILOT_INVALID, 0, 0, 4).pack(_mk(255, 190, 12)))
    gcs_hb_next = bytes(_mk(255, 190, 13).heartbeat_encode(mav2.MAV_TYPE_GCS, mav2.MAV_AUTOPILOT_INVALID, 0, 0, 4).pack(_mk(255, 190, 13)))

    h_rogue = build_restricted_visibility_hook("rogue_force_disarm", seed=1001, target_sysid=3, target_compid=1)
    h_naive = build_restricted_visibility_hook("gcs_forgery_own_counter", seed=1001, target_sysid=3, target_compid=1)
    h_inf = build_restricted_visibility_hook("gcs_forgery_track_identity", seed=1001, target_sysid=3, target_compid=1)
    h_benign = build_restricted_visibility_hook("benign_pilot_control", seed=1001)
    assert isinstance(h_benign, BenignPilotControlHook)

    for h in (h_rogue, h_naive, h_inf, h_benign):
        # Establish baseline timing and observed GCS seq before onset
        armed_hb = bytes(_mk(3, 1, 1).heartbeat_encode(mav2.MAV_TYPE_QUADROTOR, mav2.MAV_AUTOPILOT_PX4, 0x80, 0, 4).pack(_mk(3, 1, 1)))
        h(_ctx(armed_hb, direction="down", recv_s=0.0))
        h(_ctx(gcs_hb, direction="up", recv_s=1.0))
        out = h(_ctx(gcs_hb_next, direction="up", recv_s=100.0))
        if isinstance(h, BenignPilotControlHook):
            assert out == [gcs_hb_next] and h.frames_injected == 0
        else:
            assert len(out) == 2 and h.frames_injected == 1
            forged = _decode(out[1])
            if h is h_rogue:
                assert forged.command == 400 and forged.get_srcSystem() == 66
            else:
                assert forged.command == 176 and forged.get_srcSystem() == 255
            if h is h_inf:
                assert out[1][4] == 14  # continued sequence after gcs_hb_next (seq=13)


def test_rewrite_failure_counter_and_rogue_disarm_armed_precondition() -> None:
    # R3: rewrite exception increments frames_rewrite_failed instead of failing silently
    atk = AltitudeBiasAttack(AltitudeBiasParams(onset_s=1.0, duration_s=10.0), warmup_s=0.0, target_sysid=3, target_compid=1)
    atk(_ctx(_hb(), recv_s=0.0))
    # Truncated/corrupt GLOBAL_POSITION_INT frame with V2 magic so decode raises
    corrupt_gpi = bytes([0xFD, 28, 0, 0, 1, 3, 1, 33, 0, 0]) + b"\x00" * 5
    res = atk(
        FrameContext(
            raw=corrupt_gpi,
            direction="down",
            recv_ns=int(2.0 * 1e9),
            msgid=33,
            sysid=3,
            compid=1,
            seq=1,
            signed=False,
        )
    )
    assert res == [corrupt_gpi]
    assert atk.frames_rewrite_failed == 1

    # R2: RogueForceDisarmAttack builder defaults auto_arm_if_disarmed=False; auto-arm only if explicitly opted in
    h_default = build_restricted_visibility_hook("rogue_force_disarm", seed=1001, target_sysid=3, target_compid=1)
    assert h_default.auto_arm_if_disarmed is False

    h_rogue = build_restricted_visibility_hook(
        "rogue_force_disarm", seed=1001, target_sysid=3, target_compid=1, auto_arm_if_disarmed=True
    )
    assert h_rogue.auto_arm_if_disarmed is True
    disarmed_hb = bytes(_mk(3, 1, 1).heartbeat_encode(mav2.MAV_TYPE_QUADROTOR, mav2.MAV_AUTOPILOT_PX4, 0x00, 0, 4).pack(_mk(3, 1, 1)))
    armed_hb = bytes(_mk(3, 1, 2).heartbeat_encode(mav2.MAV_TYPE_QUADROTOR, mav2.MAV_AUTOPILOT_PX4, 0x80, 0, 4).pack(_mk(3, 1, 2)))
    gcs_hb = bytes(_mk(255, 190, 10).heartbeat_encode(mav2.MAV_TYPE_GCS, mav2.MAV_AUTOPILOT_INVALID, 0, 0, 4).pack(_mk(255, 190, 10)))

    h_default(_ctx(disarmed_hb, direction="down", recv_s=0.0))
    out_def = h_default(_ctx(gcs_hb, direction="up", recv_s=1.0))
    assert h_default.pre_arm_sent is False
    assert len(out_def) == 1

    h_rogue(_ctx(disarmed_hb, direction="down", recv_s=0.0))
    assert h_rogue.vehicle_armed_observed is False
    out_up = h_rogue(_ctx(gcs_hb, direction="up", recv_s=1.0))
    assert h_rogue.pre_arm_sent is True
    assert len(out_up) == 2 and _decode(out_up[1]).command == 400 and _decode(out_up[1]).param1 == 1.0

    h_rogue(_ctx(armed_hb, direction="down", recv_s=2.0))
    assert h_rogue.vehicle_armed_observed is True
