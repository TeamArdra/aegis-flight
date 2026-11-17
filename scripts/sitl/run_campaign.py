"""Evidence campaign runner (issue #25; the runner behind the #26 final-commit SITL campaign).

    .venv/Scripts/python.exe scripts/sitl/run_campaign.py --out-root artifacts/sitl/final_<tag> --n 10
    .venv/Scripts/python.exe scripts/sitl/run_campaign.py --out-root artifacts/sitl/final_<tag> --n 10 --resume
    .venv/Scripts/python.exe scripts/sitl/run_campaign.py --out-root /tmp/dry --n 1 --only px4_drift --list

Runs every scenario ``--n`` times with FIXED seeds (scenario seed, ``--trial-index`` 0..n-1, exactly the
existing drivers' convention), one process per trial, a fresh PX4 SITL boot per trial for the ``px4`` kind.
Refuses a dirty tree unless ``--allow-dirty`` (children are then stamped NOT-REPRODUCIBLE too). Writes::

    <out-root>/campaign_manifest.json     run_manifest/1 (commit, versions, command line, UTC) + scenario table
    <out-root>/campaign_state.json        per-trial status; the resume ledger
    <out-root>/campaign_summary.json|md   n requested / completed / failed per scenario (failures are listed, never dropped)
    <out-root>/<scenario>/trial_NNN.*     what the driver writes (manifests carry run_provenance)
    <out-root>/<scenario>/_incomplete/    leftovers of an interrupted or failed attempt (moved, never deleted)

``--resume`` skips trials already complete at THIS commit and re-runs the rest; it refuses to resume a campaign that
was started on a different commit (that would mix evidence from two trees). Environment: SITL. Claim class: whatever
each driver's own manifest states; this script adds no claim. The built-in table lists the PX4 scenarios that have a
driver today; scenarios from #24 / #18 / #20 and the bridge command are added with ``--scenarios-file`` (a JSON list
of objects with the fields of ``Scenario``) without editing this file.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from provenance import add_provenance_args, begin_run, finish_run, write_manifest  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
DISTRO = "Ubuntu-24.04"
STATE_SCHEMA = "aegisflight.campaign_state/1"
STATE_NAME, MANIFEST_NAME = "campaign_state.json", "campaign_manifest.json"


@dataclass
class Scenario:
    name: str
    kind: str  # px4 | ardupilot | command
    script: str = ""  # path relative to the repo (px4 / ardupilot kinds)
    seed: int = 0
    args: list[str] = field(default_factory=list)
    timeout_s: float = 600.0
    #: ``command`` kind: full command template; ``{out}`` ``{name}`` ``{seed}`` ``{index}`` ``{dir}`` are filled in
    cmd: list[str] = field(default_factory=list)
    #: files (relative to the trial stem's directory, ``{stem}`` filled in) that must exist for the trial to count as complete
    done_files: list[str] = field(default_factory=lambda: ["{stem}.manifest.json"])


# Seeds are the ones the final single-scenario artifacts already used (artifacts/sitl/*final*/manifests).
BUILTIN: list[Scenario] = [
    Scenario("px4_drift", "px4", "scripts/sitl/run_p2_trial.py", 1001),
    Scenario("px4_rogue_force_disarm", "px4", "scripts/sitl/run_p2_injection_trial.py", 2001),
    Scenario("px4_replay_identical", "px4", "scripts/sitl/run_p2_replay_v2_trial.py", 5101, ["--seconds", "70"]),
    Scenario("px4_gcs_forgery_own_counter", "px4", "scripts/sitl/run_p2_gcs_impersonation_trial.py", 6101,
             ["--seq-policy", "own_counter"]),
    Scenario("px4_gcs_forgery_informed", "px4", "scripts/sitl/run_p2_gcs_impersonation_trial.py", 6101,
             ["--seq-policy", "track_identity"]),
    Scenario("px4_position_drop", "px4", "scripts/sitl/run_p2_drop_trial.py", 3001),
    Scenario("px4_delay", "px4", "scripts/sitl/run_p2_delay_trial.py", 4001),
    Scenario("px4_gnss_degrade", "px4", "scripts/sitl/run_p2_gnss_trial.py", 7001),
    Scenario("px4_signed_forgery", "px4", "scripts/sitl/run_p4_signing_trial.py", 7001),
    Scenario("ardupilot_drift", "ardupilot", "scripts/ardupilot/run_ap_sitl_ids.py", 8001, timeout_s=900.0,
             args=["--stream", "six", "--profile", "flight", "--no-ml", "--attack",
                   "position_drift:onset=5,duration=25,rate=5,bearing=90,airborne_m=12"],
             done_files=["{dir}/run_manifest.json"]),
]


def load_scenarios(path: str | None) -> list[Scenario]:
    out = {s.name: s for s in BUILTIN}
    if path:
        for raw in json.loads(Path(path).read_text(encoding="utf-8")):
            s = Scenario(**raw)
            out[s.name] = s  # a file entry replaces a built-in of the same name
    return list(out.values())


def trial_paths(root: Path, sc: Scenario, i: int) -> dict[str, str]:
    d = root / sc.name
    return {"dir": str(d / f"trial_{i + 1:03d}"), "stem": str(d / f"trial_{i + 1:03d}"), "scenario_dir": str(d),
            "name": f"{sc.name}_{i + 1:03d}"}


def build_command(sc: Scenario, root: Path, i: int, allow_dirty: bool) -> list[str]:
    p = trial_paths(root, sc, i)
    if sc.kind == "command":
        fill = {"out": p["stem"], "name": p["name"], "seed": str(sc.seed), "index": str(i), **p}
        cmd = [c.format(**fill) for c in sc.cmd]
        return [*cmd, "--allow-dirty"] if allow_dirty else cmd
    py = sys.executable
    if sc.kind == "px4":
        cmd = [py, str(REPO / sc.script), "--seed", str(sc.seed), "--trial-index", str(i), "--out", p["stem"], *sc.args]
    elif sc.kind == "ardupilot":
        cmd = [py, str(REPO / sc.script), "--name", p["name"], "--out-dir", str(Path(p["scenario_dir"])), *sc.args]
    else:
        raise ValueError(f"unknown scenario kind {sc.kind!r} ({sc.name})")
    return [*cmd, "--allow-dirty"] if allow_dirty else cmd


def is_done(sc: Scenario, root: Path, i: int) -> bool:
    p = trial_paths(root, sc, i)
    if sc.kind == "ardupilot":  # run_ap_sitl_ids writes <out-dir>/<name>/
        p = {**p, "dir": str(Path(p["scenario_dir"]) / p["name"])}
    return all(Path(f.format(**p)).exists() for f in sc.done_files)


def quarantine_partial(sc: Scenario, root: Path, i: int) -> list[str]:
    """Move leftovers of an unfinished attempt out of the way (drivers refuse to overwrite; evidence is never deleted)."""
    p = trial_paths(root, sc, i)
    d = Path(p["scenario_dir"])
    moved: list[str] = []
    if not d.exists():
        return moved
    prefix = Path(p["stem"]).name
    cand = [x for x in d.iterdir() if x.name.startswith(prefix + ".") or x.name == p["name"] or x.name == prefix]
    if sc.kind == "ardupilot":
        cand = [x for x in d.iterdir() if x.name == p["name"]]
    if cand:
        q = d / "_incomplete" / time.strftime("%Y%m%dT%H%M%S")
        q.mkdir(parents=True, exist_ok=True)
        for x in cand:
            shutil.move(str(x), str(q / x.name))
            moved.append(x.name)
    return moved


def sitl_restart(distro: str = DISTRO) -> bool:
    """Fresh PX4 SITL boot (same procedure as run_trial_batch.sh): stop, clear the persisted signing key, start, wait."""
    script = subprocess.run(["wsl", "-d", distro, "--", "wslpath", "-a", str(REPO / "scripts/sitl/start_px4_sitl.sh")],
                            capture_output=True, text=True, timeout=30).stdout.strip()
    if not script:
        return False

    def wsl(*a: str, timeout: float = 60) -> subprocess.CompletedProcess:
        return subprocess.run(["wsl", "-d", distro, "--", *a], capture_output=True, text=True, timeout=timeout)

    wsl("bash", script, "stop")
    time.sleep(3)
    wsl("bash", "-c", "rm -f ~/aegis_sitl/i2/mavlink/mavlink-signing-key.bin")
    wsl("bash", script, "start")
    for _ in range(60):
        if wsl("bash", "-c", 'grep -q "Startup script returned successfully" ~/aegis_sitl/i2/px4.log').returncode == 0:
            time.sleep(8)
            return True
        time.sleep(1)
    return False


def write_json(path: Path, doc: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)


def run_trial(sc: Scenario, root: Path, i: int, allow_dirty: bool, restart: bool) -> dict:
    rec: dict = {"scenario": sc.name, "index": i, "seed": sc.seed, "started_utc": datetime.now(UTC).isoformat()}
    quarantine_partial(sc, root, i)
    Path(trial_paths(root, sc, i)["scenario_dir"]).mkdir(parents=True, exist_ok=True)
    if restart and sc.kind == "px4" and not sitl_restart():
        rec.update(status="failed", reason="SITL did not become ready", rc=None)
    else:
        cmd = build_command(sc, root, i, allow_dirty)
        rec["command"] = " ".join(shlex.quote(c) for c in cmd)
        log = Path(trial_paths(root, sc, i)["scenario_dir"]) / f"trial_{i + 1:03d}.stdout.txt"
        try:
            with open(log, "w", encoding="utf-8") as lf:
                r = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, timeout=sc.timeout_s,
                                   env={**os.environ, "PYTHONUNBUFFERED": "1"}, cwd=REPO)
            rc: int | None = r.returncode
            reason = None if rc == 0 else f"driver exited {rc} (see {log.name})"
        except subprocess.TimeoutExpired:
            rc, reason = None, f"timeout after {sc.timeout_s:.0f}s (see {log.name})"
        ok = rc == 0 and is_done(sc, root, i)
        if rc == 0 and not ok:
            reason = "driver exited 0 but the expected output files are missing"
        rec.update(status="done" if ok else "failed", rc=rc, **({"reason": reason} if reason else {}))
    rec["ended_utc"] = datetime.now(UTC).isoformat()
    return rec


def summarise(root: Path, scenarios: list[Scenario], n: int, state: dict) -> dict:
    rows = []
    for sc in scenarios:
        t = [state["trials"].get(f"{sc.name}/{i + 1:03d}") for i in range(n)]
        done = [x for x in t if x and x["status"] == "done"]
        failed = [{"index": x["index"], "reason": x.get("reason")} for x in t if x and x["status"] == "failed"]
        rows.append({"scenario": sc.name, "kind": sc.kind, "seed": sc.seed, "n_requested": n, "n_completed": len(done),
                     "n_failed": len(failed), "n_not_run": n - len(done) - len(failed), "failed": failed})
    doc = {"schema": "aegisflight.campaign_summary/1", "commit": state["commit"], "n": n, "scenarios": rows,
           "complete": all(r["n_completed"] == n for r in rows)}
    write_json(root / "campaign_summary.json", doc)
    md = ["| scenario | seed | requested | completed | failed | not run |", "|---|---|---|---|---|---|"]
    md += [f"| {r['scenario']} | {r['seed']} | {r['n_requested']} | {r['n_completed']} | {r['n_failed']} | {r['n_not_run']} |"
           for r in rows]
    for r in rows:
        md += [f"\n- `{r['scenario']}` trial {f['index'] + 1}: {f['reason']}" for f in r["failed"]]
    (root / "campaign_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return doc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--n", type=int, default=10, help="trials per scenario")
    ap.add_argument("--only", action="append", help="run only this scenario (repeatable)")
    ap.add_argument("--scenarios-file", help="JSON list of extra/overriding scenarios")
    ap.add_argument("--resume", action="store_true", help="skip trials already complete at this commit; re-run the rest")
    ap.add_argument("--no-sitl-restart", action="store_true", help="do not reboot PX4 SITL before each px4 trial")
    ap.add_argument("--list", action="store_true", help="print the planned commands and exit (no tree check, nothing run)")
    add_provenance_args(ap)
    a = ap.parse_args(argv)
    if a.n < 1:
        ap.error("--n must be >= 1")
    scenarios = [s for s in load_scenarios(a.scenarios_file) if not a.only or s.name in a.only]
    if a.only and {s.name for s in scenarios} != set(a.only):
        ap.error(f"unknown scenario(s): {sorted(set(a.only) - {s.name for s in scenarios})}")
    root = Path(a.out_root)
    if a.list:
        for sc in scenarios:
            for i in range(a.n):
                print(" ".join(shlex.quote(c) for c in build_command(sc, root, i, a.allow_dirty)))
        return 0
    state_path = root / STATE_NAME
    if state_path.exists() and not a.resume:
        print(f"ERROR: {state_path} exists; pass --resume to continue that campaign, or use a fresh --out-root",
              file=sys.stderr)
        return 2
    prov = begin_run(allow_dirty=a.allow_dirty, profile_dir=None, model_path=None,
                     extra={"campaign": {"n": a.n, "scenarios": [asdict(s) for s in scenarios]}})
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("commit") != prov["commit"]:
            print(f"ERROR: campaign was started at commit {state.get('commit')} but HEAD is {prov['commit']}; refusing "
                  "to mix evidence from two commits. Use a fresh --out-root.", file=sys.stderr)
            return 2
        if state.get("reproducible", True) != prov["reproducible"]:
            print("ERROR: campaign was started on a "
                  f"{'clean' if state.get('reproducible', True) else 'dirty'} tree but the tree is now "
                  f"{'clean' if prov['reproducible'] else 'dirty'}; refusing to mix reproducible and NOT-REPRODUCIBLE "
                  "evidence. Use a fresh --out-root.", file=sys.stderr)
            return 2
    else:
        state = {"schema": STATE_SCHEMA, "commit": prov["commit"], "reproducible": prov["reproducible"], "trials": {}}
    root.mkdir(parents=True, exist_ok=True)
    write_manifest(root, prov, MANIFEST_NAME)
    for sc in scenarios:
        for i in range(a.n):
            key = f"{sc.name}/{i + 1:03d}"
            if state["trials"].get(key, {}).get("status") == "done" and is_done(sc, root, i):
                print(f"skip   {key} (complete)", flush=True)
                continue
            print(f"run    {key} seed={sc.seed} index={i}", flush=True)
            rec = run_trial(sc, root, i, a.allow_dirty, restart=not a.no_sitl_restart)
            state["trials"][key] = rec
            write_json(state_path, state)  # after every trial: a crash loses at most the one in flight
            print(f"  -> {rec['status']}" + (f": {rec.get('reason')}" if rec["status"] != "done" else ""), flush=True)
    summary = summarise(root, scenarios, a.n, state)
    prov["campaign"]["summary"] = summary["scenarios"]
    write_manifest(root, finish_run(prov), MANIFEST_NAME)
    print(f"campaign {'complete' if summary['complete'] else 'INCOMPLETE'}: see {root / 'campaign_summary.md'}")
    return 0 if summary["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
