#!/bin/bash
# read-only re-runs of the extended benchmark (ML on, shipped model) at older commits, scratch output only
S=${SCRATCH:?set SCRATCH to the scratch dir that holds wt/ (worktrees) and bisect_out/}
REPO=${REPO:?set REPO to the repository checkout}
PY=$REPO/.venv/Scripts/python.exe
export PYTHONIOENCODING=utf-8
for c in 41311fa 444f385 eae85e6 3a10573; do
  d=$S/wt/c$c
  cp $REPO/models/isoforest.joblib $d/models/ 2>/dev/null || { mkdir -p $d/models; cp $REPO/models/isoforest.joblib $d/models/; }
  cd $d
  export PYTHONPATH="$(cygpath -w $d/src);$(cygpath -w $d/scripts)"
  $PY -c "import aegisflight,sys;print(aegisflight.__file__)"
  $PY scripts/benchmark_extended.py --model models/isoforest.joblib --workers 4 --out $S/bisect_out/$c > $S/bisect_$c.log 2>&1
  echo "done $c rc=$?"
done
