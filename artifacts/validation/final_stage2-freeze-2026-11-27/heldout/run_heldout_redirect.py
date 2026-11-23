"""Run scripts/sitl/calib_evaluate.py --set heldout UNCHANGED, but with its output directory redirected.

calib_evaluate.py writes evaluation_heldout.json and heldout_lock.json into calib_common.OUT_DIR
(artifacts/sitl/calibration/ - committed, must not be touched) and refuses to run when a lock exists
there. This wrapper only re-points calib_common.OUT_DIR at the freeze folder and seeds it with the
committed derivation.json (calib_evaluate hashes OUT_DIR/derivation.json into frozen_inputs).
No repository file is modified; calib_evaluate.main() runs as is.
"""
import shutil
import sys
from pathlib import Path

REPO = Path.cwd()
out = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(REPO / "scripts" / "sitl"))
import calib_common as cc  # noqa: E402
import calib_evaluate as ce  # noqa: E402

out.mkdir(parents=True, exist_ok=True)
shutil.copyfile(REPO / "artifacts" / "sitl" / "calibration" / "derivation.json", out / "derivation.json")
cc.OUT_DIR = out
sys.argv = ["calib_evaluate.py", "--set", "heldout"]
raise SystemExit(ce.main())
