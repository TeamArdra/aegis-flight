"""Verify one `aegis onboard` run directory: event hash chain, action hash chain, HMAC-signed anchors (key = signing key file).

python verify_run.py /h/run_<label>/onboard-* /h/<label>/gcs.key
"""

import sys
from pathlib import Path

from aegisflight.logging import EventStore, verify_anchors

run_dir, keyfile = Path(sys.argv[1]), sys.argv[2]
store = EventStore(str(run_dir / "events.sqlite"), read_only=True)
try:
    cs = store.verify_chain()
    acs = store.verify_actions_chain()
    av = verify_anchors(store, run_dir / "events.anchors.jsonl", key=open(keyfile, "rb").read())
finally:
    store.close()
print(
    f"events chain {'OK' if cs.ok else 'BROKEN'} ({cs.length}); actions chain {'OK' if acs.ok else 'BROKEN'} ({acs.length}); "
    f"anchors checked {av.anchors_checked} signed {av.signed_anchors} unsigned {av.unsigned_anchors} "
    f"status {'OK' if av.ok else 'FAILED'}"
)
for e in av.errors[:5]:
    print("anchor error:", e)
sys.exit(0 if (cs.ok and acs.ok and av.ok) else 2)
