"""Offline tests of the Pi-side radio test tools (pi_monitor, report, laptop_ctl); no ssh, no hardware."""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

RADIO = Path(__file__).resolve().parents[2] / "scripts" / "radio_test"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"radio_{name}", RADIO / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


pm = _load("pi_monitor")
rp = _load("report")
lc = _load("laptop_ctl")
results = _load("results")


# --- pi_monitor -------------------------------------------------------------------------------------------------

def test_decode_throttled_flags():
    assert pm.decode_throttled(0) == []
    assert pm.decode_throttled(0x50000) == ["under-voltage occurred", "throttled occurred"]
    assert pm.decode_throttled(0x5) == ["under-voltage now", "throttled now"]
    assert "soft temperature limit occurred" in pm.decode_throttled(0x80000)


def test_parse_vcgencmd_output():
    assert pm.parse_throttled("throttled=0x50000\n") == 0x50000
    assert pm.parse_throttled("throttled=0x0") == 0
    assert pm.parse_throttled("") is None
    assert pm.parse_throttled("VCHI initialization failed") is None
    assert pm.parse_temp("temp=48.3'C\n") == 48.3
    assert pm.parse_temp("error") is None


def test_parse_proc_stat_handles_spaces_in_comm():
    fields = ["S"] + ["0"] * 50
    fields[11], fields[12], fields[21] = "700", "300", "2560"  # utime, stime, rss (pages)
    text = "4242 (python3 (aegis)) " + " ".join(fields)
    assert pm.parse_proc_stat(text) == (1000.0, 2560)
    assert pm.parse_proc_stat("garbage") is None


def test_rss_slope_linear_flat_and_warmup():
    grow = [(float(t), 60.0 + 2.0 * t / 60.0) for t in range(0, 600, 10)]  # +2 MiB/min
    assert pm.rss_slope(grow) == pytest.approx(2.0)
    assert pm.rss_slope([(float(t), 61.0) for t in range(0, 300, 10)]) == pytest.approx(0.0, abs=1e-9)
    # a start-up jump followed by a flat line: warm-up exclusion removes the growth
    jump = [(0.0, 20.0), (10.0, 55.0)] + [(float(t), 60.0) for t in range(20, 300, 10)]
    assert pm.rss_slope(jump, warmup_s=30.0) == pytest.approx(0.0, abs=1e-9)
    assert pm.rss_slope(jump) > 1.0
    assert pm.rss_slope([(0.0, 1.0)]) is None


def _sample(t, rss, cpu=25.0, thr=0, pid=100, frames=0, dropped=0):
    return {"t": float(t), "pid": pid, "cpu_pct": cpu, "rss_mib": rss, "temp_c": 50.0 + t / 100, "throttled": thr,
            "load": [0.5, 0.4, 0.3],
            "status": {"mode": "advisory", "frames_down": frames, "frames_up": frames // 10, "dropped_down": dropped,
                       "dropped_up": 0, "send_failures": 0, "tap_overflow": 0, "analyser_decisions": frames,
                       "analyser_alerts": 0, "analyser_errors": 0, "latency_p95_us": 400.0 + t, "latency_max_us": 900.0}}


def test_summarize_flags_memory_growth_throttling_and_deltas():
    rows = [_sample(t, 60.0 + 0.1 * t, thr=0x50000 if t < 200 else 0x50005, frames=t * 10) for t in range(0, 400, 2)]
    s = pm.summarize(rows)
    assert s["samples"] == 200 and s["duration_s"] == 398.0
    assert s["rss_mib"]["memory_growth_flag"] is True
    assert s["rss_mib"]["slope_mib_per_min"] == pytest.approx(6.0, rel=0.01)
    assert s["throttling"]["seen_now"] is True
    assert s["throttling"]["flags_seen_now"] == ["under-voltage now", "throttled now"]
    assert "under-voltage occurred" in s["throttling"]["flags_since_boot"]
    assert s["counters"]["delta"]["frames_down"] == 3980
    assert s["cpu_percent"]["peak"] == 25.0
    assert s["latency_us"]["peak_p95_us"] == 798.0


def test_summarize_flat_run_has_no_flags_and_tolerates_lost_process():
    rows = [_sample(t, 61.0) for t in range(0, 300, 2)] + [dict(_sample(302, 61.0), pid=None, rss_mib=None, cpu_pct=None)]
    s = pm.summarize(rows)
    assert s["rss_mib"]["memory_growth_flag"] is False
    assert s["throttling"]["seen_now"] is False and s["throttling"]["flags_since_boot"] == []
    assert s["process_lost_samples"] == 1
    assert pm.summarize([]) == {"samples": 0}


def test_extract_status_and_missing_keys():
    st = {"mode": "passive", "frames": {"down": 5, "up": 2, "dropped_down": 1, "tap_overflow": 3},
          "analyser": {"decisions": 4, "alerts": 1, "errors": 0}, "latency_us": {"p50": 100.0, "p95": 200.0, "max": 300.0}}
    out = pm.extract_status(st)
    assert out["frames_down"] == 5 and out["tap_overflow"] == 3 and out["analyser_alerts"] == 1
    assert out["latency_max_us"] == 300.0 and out["send_failures"] is None
    assert pm.extract_status({})["frames_down"] is None


def test_find_pid_skips_self_and_shells(tmp_path):
    def fake(pid, comm, cmd):
        d = tmp_path / str(pid)
        d.mkdir()
        (d / "comm").write_text(comm + "\n")
        (d / "cmdline").write_bytes(cmd.replace(" ", "\0").encode())

    fake(300, "python3", "python3 -c boot aegisflight.cli.main ips-bridge --gcs-port x")
    fake(200, "bash", "bash -c aegis ips-bridge")
    fake(400, "python3", "python3 other.py")
    (tmp_path / "self").mkdir()
    assert pm.find_pid(r"aegis.*ips-bridge", str(tmp_path)) == 300
    assert pm.find_pid(r"nomatch", str(tmp_path)) is None


def test_load_samples_skips_torn_line(tmp_path):
    p = tmp_path / "m.jsonl"
    p.write_text(json.dumps({"t": 1.0}) + "\n" + '{"t": 2.0, "pi')
    assert pm.load_samples(p) == [{"t": 1.0}]


# --- report -----------------------------------------------------------------------------------------------------

def _write_phase(out: Path, name: str, ok: bool, metrics=None):
    r = results.PhaseResult(name, out)
    r.check("loss", ok, value=0 if ok else 12, threshold=1, note="" if ok else "frames lost")
    r.check("latency", True, value=120.5, threshold=500)
    r.metrics.update(metrics or {"frames": 1000, "latency": {"p50_us": 120.5, "p95_us": 300.0}})
    r.save()


def test_report_failed_checks_first_and_appendix(tmp_path):
    _write_phase(tmp_path, "p1_link", True)
    _write_phase(tmp_path, "p2_passive", False)
    (tmp_path / "pi_monitor_summary.json").write_text(json.dumps(
        pm.summarize([_sample(t, 60.0, thr=0x50000) for t in range(0, 40, 2)])))
    phases, monitors, warns = rp.load_run(tmp_path)
    text = rp.build_report(tmp_path, phases, monitors, warns)
    assert "Overall: **FAIL**" in text
    assert text.index("## Failed checks") < text.index("## Phases") < text.index("## Appendix: raw metrics")
    assert "| p2_passive | loss | 12 | 1 | frames lost |" in text
    phase_table = text.split("## Phases")[1]
    assert phase_table.index("p2_passive") < phase_table.index("p1_link")  # failed phase listed first
    assert "latency.p50_us=120.5" in text
    assert "bridge CPU mean" in text and "under-voltage occurred" in text


def test_report_tolerates_missing_phases_and_bad_files(tmp_path):
    _write_phase(tmp_path, "p1_link", True)
    (tmp_path / "broken.json").write_text("{not json")
    (tmp_path / "other.json").write_text(json.dumps({"hello": 1}))
    phases, monitors, warns = rp.load_run(tmp_path)
    assert [p["phase"] for p in phases] == ["p1_link"] and monitors == []
    text = rp.build_report(tmp_path, phases, monitors, warns, expect=["p1_link", "p3_active"])
    assert "p3_active | NOT RUN" in text and "broken.json" in text
    assert "Overall: **FAIL**" in text  # an expected phase is missing
    assert "No pi_monitor summary found" in text


def test_report_cli_empty_dir_and_pass(tmp_path, capsys):
    assert rp.main([str(tmp_path)]) == 1
    assert "NO DATA" in (tmp_path / "report.md").read_text(encoding="utf-8")
    _write_phase(tmp_path, "p1_link", True)
    assert rp.main([str(tmp_path), "--docs-section"]) == 0
    assert "Overall: **PASS**" in (tmp_path / "report.md").read_text(encoding="utf-8")
    assert rp.main([str(tmp_path / "missing")]) == 2
    assert "## Real radio test (Raspberry Pi 3B+ + SiK radios)" in capsys.readouterr().out


def test_docs_section_title_and_limits(tmp_path):
    assert rp.build_docs_section([], []).startswith("## Real radio test (Raspberry Pi 3B+ + SiK radios)")
    _write_phase(tmp_path, "p2_passive", False)
    phases, monitors, _ = rp.load_run(tmp_path)
    sec = rp.build_docs_section(phases, monitors)
    assert "| p2_passive | FAIL | 1/2 |" in sec and "Failed checks: p2_passive: loss" in sec
    assert "What this does not show" in sec


# --- laptop_ctl -------------------------------------------------------------------------------------------------

def test_ssh_base_is_batchmode_with_key():
    argv = lc.ssh_base("/k/id", "10.0.0.1", "ardra")
    assert argv[0] == "ssh" and argv[-1] == "ardra@10.0.0.1"
    assert "BatchMode=yes" in argv and "ConnectTimeout=8" in argv and argv[argv.index("-i") + 1] == "/k/id"


def test_start_command_construction():
    env = lc.start_env("advisory", 57600, "192.168.1.20", signing_key_file="/home/ardra/k.hex", allow_unsigned=False)
    cmd = lc.remote_script("start", env)
    assert cmd.endswith("bash aegis_test/scripts/radio_test/pi_bridge_run.sh start")
    for frag in ("LAPTOP_IP=192.168.1.20", "MODE=advisory", "BAUD=57600", "SIGNING_KEY_FILE=/home/ardra/k.hex"):
        assert frag in cmd
    assert "ALLOW_UNSIGNED" not in cmd
    assert lc.remote_script("stop") == "bash aegis_test/scripts/radio_test/pi_bridge_run.sh stop"
    assert "'a b'" in lc.remote_script("start", {"MGMT_KEY_FILE": "a b"})  # shell-quoted


def test_start_env_validation():
    with pytest.raises(lc.CtlError):
        lc.start_env("bogus", 57600, "1.2.3.4")
    with pytest.raises(lc.CtlError):
        lc.start_env("passive", 57600, None)
    assert lc.start_env("active-ips", 115200, "1.2.3.4", allow_unsigned=True)["ALLOW_UNSIGNED"] == "1"


def test_scp_pull_command():
    argv = lc.scp_pull_command("/k/id", "h", "u", "aegis_runs/", "out")
    assert argv[0] == "scp" and argv[-2:] == ["u@h:aegis_runs/", "out"] and "BatchMode=yes" in argv


def test_deploy_archive_contents(tmp_path):
    for rel in ("src/aegisflight/a.py", "src/aegisflight/__pycache__/a.pyc", "configs/detector.yaml",
                "scripts/radio_test/pi_bridge_run.sh", "scripts/radio_test/x.py", "scripts/other.py", "tests/t.py"):
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("x")
    with tarfile.open(fileobj=io.BytesIO(lc.build_deploy_archive(tmp_path)), mode="r:gz") as tar:
        names = set(tar.getnames())
        assert tar.getmember("scripts/radio_test/pi_bridge_run.sh").mode == 0o755
    assert names == {"src/aegisflight/a.py", "configs/detector.yaml", "scripts/radio_test/pi_bridge_run.sh",
                     "scripts/radio_test/x.py"}
    with pytest.raises(lc.CtlError):
        lc.build_deploy_archive(tmp_path / "nowhere")


def test_reboot_requires_flag_and_never_runs_ssh(monkeypatch, capsys):
    def boom(*a, **k):
        raise AssertionError("ssh must not run")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.delenv("ARDRA_KEY", raising=False)
    assert lc.main(["reboot-pi"]) == 2
    out = capsys.readouterr().out
    assert "reboot NOT run" in out and "sudo -n reboot" in out and "--yes-reboot" in out


def test_missing_key_is_a_clear_error(monkeypatch, capsys):
    monkeypatch.delenv("ARDRA_KEY", raising=False)
    assert lc.main(["status"]) == 2
    assert "ARDRA_KEY is not set" in capsys.readouterr().err
    monkeypatch.setenv("ARDRA_KEY", "/no/such/key")
    assert lc.main(["status"]) == 2
    assert "key not found" in capsys.readouterr().err


def test_run_reports_remote_failure_without_real_ssh(monkeypatch, capsys):
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 255, b"", b"ssh: connect to host h port 22: Connection timed out\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert lc.Ctl("/k", "h", "u").run("true") == 1
    err = capsys.readouterr().err
    assert "Pi unreachable" in err and seen["argv"][-1] == "true"


def test_explain_ssh_error_hints():
    assert "key rejected" in lc.explain_ssh_error("Permission denied (publickey).", 255)
    assert lc.explain_ssh_error("", 7) == "exit code 7"
