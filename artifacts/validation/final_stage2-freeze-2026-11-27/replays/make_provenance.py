#!/usr/bin/env python
"""Write ``<name>.provenance.json`` sidecars (issue #25 schema ``aegisflight.run_manifest/1``) for tools that do not
write their own manifest: ``scripts/external_validation.py`` and ``replays/replay_exposure.py``.

    python artifacts/validation/final_stage2-freeze-2026-11-27/replays/make_provenance.py --out <dir> \
        --name external_validation --command "<the exact command line that was run>" --started-utc <iso> \
        [--ml] [--note "..."]

Run from the repository root, on the clean tree the tool ran on. It calls the repository's own
``aegisflight.run_provenance.collect_run_provenance`` (commit, tree-clean flag, config and model sha256, Python and
package versions) and refuses a dirty tree. The ``command_line`` and ``started_utc`` are the values the caller states:
this script cannot observe them, so the sidecar says so in ``sidecar_note``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from aegisflight import run_provenance as prov


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--command", required=True)
    ap.add_argument("--started-utc", default=None)
    ap.add_argument("--ml", action="store_true", help="the run used models/isoforest.joblib (hash recorded)")
    ap.add_argument("--note", default="")
    a = ap.parse_args()
    state = prov.require_clean_tree(False)
    m = prov.collect_run_provenance(
        model_path="models/isoforest.joblib" if a.ml else None, ml_enabled=a.ml, command_line=a.command,
        started_utc=a.started_utc, start_state=state,
        extra={"sidecar_note": "written after the run by replays/make_provenance.py; command_line and started_utc "
                               "are as stated by the operator, the rest is read from the tree at write time "
                               "(clean, same commit as the run)", "note": a.note})
    prov.finish_run(m)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / f"{a.name}.provenance.json").write_text(json.dumps(m, indent=2), encoding="utf-8", newline="\n")
    print(m["status"], m["commit"], m["model_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
