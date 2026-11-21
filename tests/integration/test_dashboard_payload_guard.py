"""Equivalence guard for the dashboard WebSocket payload (recorded BEFORE the dashboard perf work).

Every ``update`` the engine would send over /ws/telemetry, for a deterministic SIM run (attack, mode switch, attack
cleared) and for a REPLAY of a SYNTHETIC tlog (fix loss, motion), is canonicalised and hashed. Wall-clock fields are
masked (see dashboard_payload_driver.mask). Any optimisation must keep these digests and explicit values unchanged.

The SIM run's output depends on whether ``models/isoforest.joblib`` is present (the ML detector changes the decisions, and
so the number of updates): the model is git-ignored, so CI always runs without it. Both references were produced by the
pre-optimisation code (``15c3aaf``) and are reproduced unchanged by the current code: with the model 441 updates, without
it 446 (Windows x86-64, Python 3.13, 2026-11-17). The replay run does not use the model.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import dashboard_payload_driver as drv  # noqa: E402

_MODEL = Path(__file__).resolve().parents[2] / "models" / "isoforest.joblib"
GOLDEN = {
    "sim": ((441, "51264c85ed34b4c04b0bd7aa1e68bffda5629e32093a366aa0b2d9730fc273f2") if _MODEL.exists()
            else (446, "4b28f1b8c05c2c3f5f16c4f0a89c5f8c4a9eaffe47955e23005fc85a2402ba12")),
    "replay": (400, "2c64a0985900e3257524cec63c10acdd7cb2cc2d16f5a4b860c9329e61381b3f"),
}


# ML-on SIM run, floats rounded to 9 significant digits (``digest_portable``). The exact ``GOLDEN['sim']`` digest above
# is bit-exact on Windows / macOS only: Linux x86-64 gives a different last-bit ML score and so a different exact digest
# (d2f07d40... with the same 441 updates). The rounded digest was measured identical on macOS arm64 and Linux x86-64.
SIM_ML_PORTABLE = "0ca1cc38284ab893e070765ece78e5b65f4586af4a9fc4f71e2aad733818860a"


def test_payload_sequence_digests_unchanged() -> None:
    got = drv.collect()
    for k, (n, h) in GOLDEN.items():
        assert len(got[k]) == n, k
        if k == "sim" and _MODEL.exists():
            assert drv.digest_portable(got[k]) == SIM_ML_PORTABLE, "sim payload sequence changed (ML on, rounded)"
            continue
        assert drv.digest(got[k]) == h, f"{k} payload sequence changed"


def test_payload_explicit_values() -> None:
    got = drv.collect()
    sim, rep = got["sim"], got["replay"]
    assert {u["type"] for u in sim + rep} == {"update"}
    states = {(u["mitigation"]["state"], u["defense_mode"]) for u in sim}
    assert ("SAFE_HOLD", "active-ips") in states and ("NOMINAL", "passive") in states
    assert sum(1 for u in rep if u.get("threat", {}).get("is_alert")) == 12
    assert {u["link"]["gps"]["fix_type"] for u in rep} == {1, 3}
    assert all(u["sim"] is True for u in sim) and all(u["environment"] == "REPLAY" for u in rep)


def test_ws_text_matches_send_json_and_is_shared() -> None:
    from starlette.testclient import TestClient  # noqa: F401  (import check only)

    import aegisflight.backend.app as app_module

    msg = {"type": "update", "t": 1.5, "name": "caf\u00e9", "n": [1, 2.0, None, True]}
    expected = '{"type":"update","t":1.5,"name":"caf\u00e9","n":[1,2.0,null,true]}'
    assert app_module._ws_text(msg) == expected
    assert app_module._ws_text(msg) is app_module._ws_text(msg)  # one serialisation shared by all clients
    other = dict(msg, t=2.0)
    assert app_module._ws_text(other) != expected
