"""Wrap an evidence command with the repo's run provenance (aegisflight.run_provenance).

usage: run_with_prov.py --manifest-dir DIR [--model PATH] [--profile DIR] [--name run_manifest.json] -- CMD...
Runs CMD from the current directory (the worktree), writes DIR/<name> with the manifest. Not part of the repo.
"""
import argparse
import subprocess
import sys
from pathlib import Path

from aegisflight import run_provenance as rp

ap = argparse.ArgumentParser()
ap.add_argument("--manifest-dir", required=True)
ap.add_argument("--model", default=None)
ap.add_argument("--profile", default=None)
ap.add_argument("--name", default=rp.MANIFEST_NAME)
ap.add_argument("cmd", nargs=argparse.REMAINDER)
a = ap.parse_args()
cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
state = rp.require_clean_tree(False)
prov = rp.collect_run_provenance(profile_dir=a.profile, model_path=a.model, ml_enabled=a.model is not None,
                                 command_line=" ".join(cmd), start_state=state)
rc = subprocess.call(cmd)
rp.finish_run(prov)
prov["exit_code"] = rc
d = Path(a.manifest_dir)
d.mkdir(parents=True, exist_ok=True)
rp.write_manifest(d, prov, a.name)
print(f"manifest -> {d / a.name} reproducible={prov['reproducible']} commit={prov['commit'][:8]} exit={rc}")
sys.exit(rc)
