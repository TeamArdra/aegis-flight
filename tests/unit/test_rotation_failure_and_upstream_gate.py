"""PR #80 fix-up: rotation failures keep the IDS logging; the relay upstream is local-only; PASSIVE compid-191 boundary."""

from __future__ import annotations

import json
import socket
import sys
import threading
from pathlib import Path

import pytest
from test_inline_ips import FakeLink, heartbeat

from aegisflight.hal import run_archive as run_archive_mod
from aegisflight.hal.inline_ips import InlineIpsBridge
from aegisflight.hal.mgmt_channel import OP_STATUS_NOW, build_command_frame
from aegisflight.hal.run_archive import BridgeRunArchive
from aegisflight.logging import rotation as rotation_mod
from aegisflight.logging.rotation import rotate_sqlite_store
from aegisflight.logging.store import EventStore
from aegisflight.mavlink.signing import MavlinkSignatureVerifier
from aegisflight.proxy import transport as transport_mod
from aegisflight.proxy.transport import check_upstream_host, make_udp_relay, split_frames

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "sitl"))

KEY_M = bytes(range(32))


def _store(tmp_path: Path, rows: int = 20) -> EventStore:
    st = EventStore(tmp_path / "events.sqlite")
    st.start_run("r0", label="t")
    for i in range(rows):
        st.log_action("r0", float(i), "t", "ROW", "x", "d" * 50)
    return st


def _actions(path: Path) -> list[dict]:
    st = EventStore(path, read_only=True)
    try:
        return st.get_actions(limit=10_000)
    finally:
        st.close()


# -- (b) rotation.py ---------------------------------------------------------------------------


def test_rotation_success_links_previous_segment_with_real_heads(tmp_path):
    st = _store(tmp_path)
    fresh, rotated = rotate_sqlite_store(st, max_bytes=1, max_rotations=3, run_id="r1")
    assert rotated is True
    acts = {a["action"]: a for a in fresh.get_actions(limit=100)}
    link = json.loads(acts["ROTATION_LINK"]["detail"])
    assert link["last_action_hash"] and link["action_count"] == 20
    assert (tmp_path / "events.1.sqlite").exists()
    fresh.close()


def test_os_replace_failure_reopens_store_and_keeps_chain(tmp_path, monkeypatch):
    st = _store(tmp_path)

    def boom(*_a, **_k):
        raise OSError("locked")

    monkeypatch.setattr(rotation_mod.os, "replace", boom)
    fresh, rotated = rotate_sqlite_store(st, max_bytes=1, max_rotations=3, run_id="r1")
    assert rotated is False
    fresh.log_action("r0", 99.0, "t", "AFTER", "x", "still logging")  # usable, not closed
    names = [a["action"] for a in fresh.get_actions("r0", limit=100)]
    assert names.count("ROW") == 20 and "AFTER" in names
    assert "ROTATION_FAILED" in [a["action"] for a in fresh.get_actions(limit=100)]
    assert "ROTATION_LINK" not in names
    assert fresh.verify_actions_chain("r0").ok
    fresh.close()


def test_head_capture_failure_skips_rotation_and_keeps_store_open(tmp_path, monkeypatch):
    st = _store(tmp_path)

    def boom(_s):
        raise RuntimeError("cannot read heads")

    monkeypatch.setattr(rotation_mod, "_segment_heads", boom)
    same, rotated = rotate_sqlite_store(st, max_bytes=1, max_rotations=3, run_id="r1")
    assert rotated is False and same is st
    st.log_action("r0", 50.0, "t", "AFTER", "x")  # original handle never closed
    assert not (tmp_path / "events.1.sqlite").exists()
    st.close()


def test_nothing_rotated_writes_no_link(tmp_path, monkeypatch):
    st = _store(tmp_path)
    monkeypatch.setattr(rotation_mod, "rotate_file_series", lambda *a, **k: False)
    fresh, rotated = rotate_sqlite_store(st, max_bytes=1, max_rotations=3, run_id="r1")
    assert rotated is False
    assert "ROTATION_LINK" not in [a["action"] for a in fresh.get_actions(limit=100)]
    fresh.close()


def test_max_rotations_zero_does_not_claim_a_link(tmp_path):
    st = _store(tmp_path)
    fresh, rotated = rotate_sqlite_store(st, max_bytes=1, max_rotations=0, run_id="r1")
    assert rotated is True
    names = [a["action"] for a in fresh.get_actions(limit=100)]
    assert "ROTATION_LINK" not in names and "ROTATION_DISCARDED" in names
    fresh.close()


# -- (a)/(d) bridge ----------------------------------------------------------------------------


def _bridge(tmp_path: Path) -> InlineIpsBridge:
    st = EventStore(tmp_path / "events.sqlite")
    st.start_run("ips-bridge", label="t")
    return InlineIpsBridge(FakeLink(), FakeLink(), mode="passive", store=st, crossend_interval_s=0)


def test_bridge_rotate_store_survives_os_replace_failure(tmp_path, monkeypatch):
    b = _bridge(tmp_path)
    for i in range(10):
        b._log_action(float(i), "t", "ROW", "x", "d" * 60)

    def boom(*_a, **_k):
        raise OSError("locked")

    monkeypatch.setattr(rotation_mod.os, "replace", boom)
    assert b.rotate_store(max_bytes=1, max_rotations=3) is False  # does not raise
    b._log_action(100.0, "t", "AFTER", "x")
    assert b.store_rows_lost == 0
    names = [a["action"] for a in b.store.get_actions(limit=100)]
    assert "AFTER" in names and "ROTATION_FAILED" in names
    b.store.close()


def test_bridge_rotate_store_recovers_when_rotation_raises_unexpectedly(tmp_path, monkeypatch):
    b = _bridge(tmp_path)

    def explode(store, **_k):
        store.close()
        raise RuntimeError("boom after close")

    monkeypatch.setattr(rotation_mod, "rotate_sqlite_store", explode)
    assert b.rotate_store(max_bytes=1) is False
    assert b.rotation_failures == 1
    b._log_action(1.0, "t", "AFTER", "x")  # the closed handle was replaced by a reopened one
    assert b.store_rows_lost == 0
    assert any(a["action"] == "AFTER" for a in b.store.get_actions(limit=10))
    b.store.close()


def test_rotate_while_logging_loses_no_rows(tmp_path):
    b = _bridge(tmp_path)
    n = 1500
    errors: list[BaseException] = []

    def writer() -> None:
        try:
            for i in range(n):
                b._log_action(float(i), "inline_ips", "drop_frame", "up", f"r{i}")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    th = threading.Thread(target=writer)
    th.start()
    rotations = 0
    while th.is_alive():
        rotations += int(b.rotate_store(max_bytes=1, max_rotations=500, run_id_prefix=f"p{rotations}"))
    th.join()
    with b._store_lock:
        b._flush_action_backlog_locked()
    assert not errors and b.store_rows_lost == 0
    total = 0
    for f in tmp_path.glob("events*.sqlite"):
        if f == tmp_path / "events.sqlite":
            total += sum(a["action"] == "drop_frame" for a in b.store.get_actions(limit=100_000))
        else:
            total += sum(a["action"] == "drop_frame" for a in _actions(f))
    assert total == n
    b.store.close()


# -- (c) run archive ---------------------------------------------------------------------------


def test_archive_stream_survives_failed_rotation(tmp_path, monkeypatch):
    arch = BridgeRunArchive(tmp_path / "run", max_file_bytes=40, max_rotations=2, flush_interval_s=3600)

    def boom(*_a, **_k):
        raise OSError("locked")

    monkeypatch.setattr(run_archive_mod, "rotate_file_series", boom)
    for i in range(5):
        arch.action(i, "summary", "controller", summary="x" * 30)
    arch._drain()
    assert arch.stats()["write_errors"] >= 1 and arch.stats()["writer_error"]
    for i in range(5, 10):
        arch.action(i, "summary", "controller", summary="y" * 30)
    arch._drain()
    arch.close()
    lines = (tmp_path / "run" / "actions.jsonl").read_text().splitlines()
    assert len(lines) == 10  # nothing lost, the stream kept writing after the failed rotation


# -- PASSIVE compid-191 boundary (HANDOFF wording) -----------------------------------------------


def test_passive_consumes_compid191_never_forwards_and_transmits_zero_bytes(tmp_path):
    fc, gcs = FakeLink(), FakeLink()
    b = InlineIpsBridge(fc, gcs, mode="passive", mgmt_key=KEY_M, mgmt_state_path=str(tmp_path / "m.json"),
                        crossend_interval_s=1.0, mgmt_status_interval_s=1.0)
    cmd = build_command_frame(KEY_M, OP_STATUS_NOW, signer=MavlinkSignatureVerifier(KEY_M))
    hb = heartbeat()
    gcs.feed(cmd)
    fc.feed(hb)
    b.pump_once()
    assert fc.sent == []  # the compid-191 command is NOT forwarded to the FC
    assert b.mgmt.commands_consumed == 1
    assert b.mgmt.bytes_sent == 0
    assert gcs.sent == [hb]  # only the forwarded telemetry; no reply/ACK/status


# -- (1) upstream gate -------------------------------------------------------------------------


@pytest.fixture
def no_sockets(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("a socket was opened")

    monkeypatch.setattr(socket, "socket", refuse)


@pytest.mark.parametrize("host", ["192.168.1.10", "8.8.8.8", "px4.example.com", "0.0.0.0", "172.29.1.2"])
def test_make_udp_relay_refuses_non_loopback_upstream_without_opening_a_socket(host, no_sockets, monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_PRIVATE_UPSTREAM", raising=False)
    with pytest.raises(ValueError, match="refusing"):
        make_udp_relay(host, 14550, 18672)


def test_hostnames_and_public_ips_are_refused_even_with_opt_in(monkeypatch):
    _fake_ifaces(monkeypatch, ("docker0", "8.8.8.0/24"))
    for host in ("px4.example.com", "8.8.8.8", "0.0.0.0", "224.0.0.1"):
        with pytest.raises(ValueError):
            check_upstream_host(host, allow_private=True)


def _fake_ifaces(monkeypatch, *nets):
    import ipaddress

    monkeypatch.setattr(transport_mod, "_local_interface_networks",
                        lambda: [(n, ipaddress.ip_network(c)) for n, c in nets])


def test_loopback_always_accepted_and_private_needs_opt_in_and_a_local_interface(monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_PRIVATE_UPSTREAM", raising=False)
    transport_mod._PRIVATE_ACKS.clear()
    _fake_ifaces(monkeypatch, ("vEthernet (WSL)", "172.29.0.0/20"), ("Wi-Fi", "10.0.0.0/24"))
    for host in ("127.0.0.1", "localhost", "::1"):
        check_upstream_host(host)
    with pytest.raises(ValueError, match="refusing"):  # on a local interface but no opt-in
        check_upstream_host("172.29.4.5")
    assert check_upstream_host("172.29.4.5", allow_private=True) == "172.29.4.5"  # positive: WSL adapter subnet
    with pytest.raises(ValueError, match="not a virtual"):  # physical Wi-Fi subnet, opt-in given
        check_upstream_host("10.0.0.7", allow_private=True)
    monkeypatch.setenv("AEGIS_ALLOW_PRIVATE_UPSTREAM", "1")
    assert check_upstream_host("172.29.4.5") == "172.29.4.5"
    acks = transport_mod.private_upstream_acks()
    assert acks and acks[0]["interface"] == "vEthernet (WSL)" and acks[0]["network"] == "172.29.0.0/20"


@pytest.mark.parametrize("host", ["192.168.1.10", "172.16.9.9", "169.254.1.1"])
def test_private_address_not_on_a_local_interface_is_refused_even_with_opt_in(host, monkeypatch, no_sockets):
    _fake_ifaces(monkeypatch, ("vEthernet (WSL)", "172.29.0.0/20"))
    with pytest.raises(ValueError, match="not inside the subnet"):
        check_upstream_host(host, allow_private=True)
    with pytest.raises(ValueError, match="not inside the subnet"):
        make_udp_relay(host, 14550, 18672, allow_private_upstream=True)


@pytest.mark.parametrize("name,cidr,host", [
    ("vEthernet (WSL (Hyper-V firewall))", "172.29.0.0/20", "172.29.4.5"),
    ("vEthernet (WSL)", "172.29.0.0/20", "172.29.4.5"),
    ("vEthernet (Default Switch)", "172.20.0.0/20", "172.20.1.2"),
    ("docker0", "172.17.0.0/16", "172.17.0.2"),
    ("br-1a2b3c4d5e6f", "172.18.0.0/16", "172.18.0.9"),
    ("virbr0", "192.168.122.0/24", "192.168.122.50"),
    ("vboxnet0", "192.168.56.0/24", "192.168.56.101"),
    ("bridge100", "192.168.64.0/24", "192.168.64.3"),
])
def test_virtual_adapters_are_accepted_with_opt_in(name, cidr, host, monkeypatch):
    monkeypatch.delenv("AEGIS_SITL_INTERFACE", raising=False)
    transport_mod._PRIVATE_ACKS.clear()
    _fake_ifaces(monkeypatch, (name, cidr))
    assert check_upstream_host(host, allow_private=True) == host
    assert transport_mod.private_upstream_acks()[0]["interface"] == name
    transport_mod._PRIVATE_ACKS.clear()


@pytest.mark.parametrize("name", ["Wi-Fi", "Ethernet", "Ethernet 2", "en0", "eth0", "wlan0", "wlp3s0", "wl0",
                                  "utun3", "vmnet0", "vEthernet (External Switch)", "vEthernet (Wi-Fi)",
                                  "docker0-evil", "my-docker0", ""])
def test_physical_or_unlisted_interface_subnet_is_refused_even_with_opt_in(name, monkeypatch, no_sockets):
    monkeypatch.delenv("AEGIS_SITL_INTERFACE", raising=False)
    transport_mod._PRIVATE_ACKS.clear()
    _fake_ifaces(monkeypatch, (name, "192.168.1.0/24"))
    with pytest.raises(ValueError, match="not a virtual") as ei:
        check_upstream_host("192.168.1.10", allow_private=True)
    assert repr(name) in str(ei.value)
    with pytest.raises(ValueError, match="not a virtual"):
        make_udp_relay("192.168.1.10", 14550, 18672, allow_private_upstream=True)
    assert transport_mod.private_upstream_acks() == []


def test_sitl_interface_env_is_never_a_bypass_for_a_physical_nic(monkeypatch):
    _fake_ifaces(monkeypatch, ("Wi-Fi", "192.168.1.0/24"))
    monkeypatch.setenv("AEGIS_SITL_INTERFACE", "Wi-Fi")
    with pytest.raises(ValueError, match="not a virtual"):
        check_upstream_host("192.168.1.10", allow_private=True)


def test_sitl_interface_env_only_narrows_among_virtual_adapters(monkeypatch):
    transport_mod._PRIVATE_ACKS.clear()
    _fake_ifaces(monkeypatch, ("docker0", "172.17.0.0/16"), ("vEthernet (WSL)", "172.29.0.0/20"))
    monkeypatch.setenv("AEGIS_SITL_INTERFACE", "vEthernet (WSL)")
    assert check_upstream_host("172.29.4.5", allow_private=True) == "172.29.4.5"
    with pytest.raises(ValueError, match="not a virtual"):
        check_upstream_host("172.17.0.2", allow_private=True)
    transport_mod._PRIVATE_ACKS.clear()


def test_address_in_both_a_virtual_and_a_physical_subnet_is_refused(monkeypatch):
    monkeypatch.delenv("AEGIS_SITL_INTERFACE", raising=False)
    _fake_ifaces(monkeypatch, ("docker0", "192.168.1.0/24"), ("Ethernet", "192.168.1.0/24"))
    with pytest.raises(ValueError, match="'Ethernet'"):
        check_upstream_host("192.168.1.10", allow_private=True)


def test_no_interface_info_fails_closed(monkeypatch):
    _fake_ifaces(monkeypatch)
    with pytest.raises(ValueError):
        check_upstream_host("172.29.4.5", allow_private=True)


def test_real_interface_listing_never_includes_loopback_and_does_not_raise():
    for _name, net in transport_mod._local_interface_networks():
        assert not net.is_loopback


def test_run_manifest_records_the_private_upstream_acknowledgement(monkeypatch):
    from aegisflight.run_provenance import collect_run_provenance

    transport_mod._PRIVATE_ACKS.clear()
    base = collect_run_provenance(allow_dirty=True)
    assert "private_upstream_ack" not in base
    _fake_ifaces(monkeypatch, ("vEthernet (WSL)", "172.29.0.0/20"))
    check_upstream_host("172.29.4.5", allow_private=True)
    man = collect_run_provenance(allow_dirty=True)
    assert man["private_upstream_ack"][0]["host"] == "172.29.4.5"
    transport_mod._PRIVATE_ACKS.clear()


TRIAL_SCRIPTS = ["run_p2_trial", "run_p2_replay_trial", "run_p2_replay_v2_trial", "run_p2_delay_trial",
                 "run_p2_drop_trial", "run_p2_gnss_trial", "run_p2_injection_trial",
                 "run_p2_gcs_impersonation_trial", "run_p4_signing_trial"]


EXTRA_ARGS = {"run_p2_gcs_impersonation_trial": ["--seq-policy", "own_counter"]}


@pytest.mark.parametrize("name", TRIAL_SCRIPTS)
def test_trial_scripts_expose_the_opt_in_and_refuse_a_foreign_host_before_any_socket(
        name, tmp_path, no_sockets, monkeypatch, capsys):
    import importlib

    monkeypatch.delenv("AEGIS_ALLOW_PRIVATE_UPSTREAM", raising=False)
    mod = importlib.import_module(name)
    with pytest.raises(SystemExit):
        mod.main(["--help"])
    assert "--allow-private-upstream" in capsys.readouterr().out
    try:
        rc = mod.main(["--seed", "1", "--out", str(tmp_path / "x" / "t"), "--px4-host", "192.168.1.10",
                       "--allow-dirty", *EXTRA_ARGS.get(name, [])])
    except ValueError as exc:  # make_udp_relay refused: no socket was opened (no_sockets would have raised)
        assert "refusing" in str(exc)
    else:  # a script that validates up-front returns non-zero
        assert rc != 0


@pytest.mark.parametrize("host", ["192.168.1.10", "px4.example.com"])
def test_telemetry_trial_exits_nonzero_before_any_socket_or_file(host, tmp_path, no_sockets, monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_PRIVATE_UPSTREAM", raising=False)
    import run_p2_telemetry_trial as trial

    out = tmp_path / "t" / "trial"
    rc = trial.main(["--scenario", "rogue_force_disarm", "--seed", "1", "--out", str(out), "--px4-host", host,
                     "--allow-dirty"])
    assert rc == 2
    assert not out.parent.exists()  # no evidence file was created


# -- (3) removed dead ADVISORY counter-frame branch: behaviour unchanged ---------------------------


@pytest.mark.parametrize("mode", ["passive", "advisory"])
def test_non_active_postures_never_send_controller_counter_frames(mode, tmp_path):
    from test_inline_ips import command_long

    from aegisflight.core.enums import AttackType, IntegrityStatus, Severity
    from aegisflight.core.types import TelemetrySnapshot, ThreatAssessment
    from aegisflight.features.extractor import FeatureFrame
    from aegisflight.sources.stream import TelemetryTick

    fc, gcs = FakeLink(), FakeLink()
    b = InlineIpsBridge(fc, gcs, mode=mode, crossend_interval_s=0, mgmt_status_interval_s=0.0)
    snap = TelemetrySnapshot(t=1.0, lat=1.0, lon=1.0, alt_msl=1.0, rel_alt=1.0, vx=0, vy=0, vz=0, groundspeed=0,
                             roll=0, pitch=0, yaw=0, heading=0, flight_mode="AUTO", armed=True, battery_remaining=90.0)
    b.pipeline.last_frame = FeatureFrame(t=1.0, snapshot=snap, gps_seen=True, gps_raw_seen=True, heartbeat_seen=True)
    asmt = ThreatAssessment(t=1.0, wall_time=1.0, threat=True, threat_score=0.9, severity=Severity.CRITICAL,
                            attack_type=AttackType.COMMAND_INJECTION, confidence=0.9, secondary_indicators=[],
                            evidence=["x"], detector_scores={"PROTOCOL": 0.9}, contributing_detectors=["PROTOCOL"],
                            integrity_status=IntegrityStatus.VALID, is_alert=True)
    b.pipeline.process_tick = lambda _t: asmt
    real_step = b.controller.step

    def step(frame, a):
        act = real_step(frame, a)
        act.counter_frames[:] = [command_long(1, 176, 1, 4), command_long(1, 400, 0)]  # would be corrective commands
        return act

    b.controller.step = step
    b.analyse_tick(TelemetryTick(t=1.0, tick=1, messages=[]))
    assert fc.sent == []
    assert b.counter_frames_sent == 0
    assert all(fr.msgid != 76 for raw in gcs.sent for fr in split_frames(raw)[0])


# -- post-rename link failure (R1 P3): never a silent unlinked segment --------------------------


def _fail_link_writes(monkeypatch, times: int) -> list[int]:
    real = EventStore.log_action
    calls = [0]

    def flaky(self, run_id, t, actor, action, target, detail=""):
        if action == "ROTATION_LINK" and calls[0] < times:
            calls[0] += 1
            raise OSError("disk hiccup writing the link row")
        return real(self, run_id, t, actor, action, target, detail)

    monkeypatch.setattr(EventStore, "log_action", flaky)
    return calls


def test_transient_link_write_failure_is_retried_and_the_link_is_written(tmp_path, monkeypatch):
    b = _bridge(tmp_path)
    for i in range(10):
        b._log_action(float(i), "t", "ROW", "x", "d" * 60)
    calls = _fail_link_writes(monkeypatch, times=1)
    assert b.rotate_store(max_bytes=1, max_rotations=3) is True
    assert calls[0] == 1 and b.rotation_failures == 0
    names = [a["action"] for a in b.store.get_actions(limit=100)]
    assert "ROTATION_LINK" in names and "ROTATION_FAILED" not in names
    assert (tmp_path / "events.1.sqlite").exists()
    b.store.close()


def test_persistent_link_write_failure_records_rotation_failed_and_ids_keeps_logging(tmp_path, monkeypatch):
    b = _bridge(tmp_path)
    for i in range(10):
        b._log_action(float(i), "t", "ROW", "x", "d" * 60)
    _fail_link_writes(monkeypatch, times=99)
    assert b.rotate_store(max_bytes=1, max_rotations=3) is True  # the segment really was rotated
    assert b.rotation_failures == 1
    b._log_action(100.0, "t", "AFTER", "x")
    assert b.store_rows_lost == 0
    acts = {a["action"]: a for a in b.store.get_actions(limit=100)}
    assert "ROTATION_LINK" not in acts and "AFTER" in acts
    failed = json.loads(acts["ROTATION_FAILED"]["detail"])
    assert failed["rotated_path"].endswith("events.1.sqlite") and failed["action_count"] == 10
    assert failed["last_action_hash"] and "OSError" in failed["error"]
    assert b.store.verify_chain().ok is True
    b.store.close()
