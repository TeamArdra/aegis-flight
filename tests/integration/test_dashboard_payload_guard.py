"""Equivalence guard for the dashboard WebSocket payload (recorded BEFORE the dashboard perf work).

Every ``update`` the engine would send over /ws/telemetry, for a deterministic SIM run (attack, mode switch, attack
cleared) and for a REPLAY of a SYNTHETIC tlog (fix loss, motion), is canonicalised and hashed. Wall-clock fields are
masked (see dashboard_payload_driver.mask). Any optimisation must keep these digests and explicit values unchanged.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import dashboard_payload_driver as drv  # noqa: E402

GOLDEN = {
    "sim": (441, "51264c85ed34b4c04b0bd7aa1e68bffda5629e32093a366aa0b2d9730fc273f2"),
    "replay": (400, "2c64a0985900e3257524cec63c10acdd7cb2cc2d16f5a4b860c9329e61381b3f"),
}


def test_payload_sequence_digests_unchanged() -> None:
    got = drv.collect()
    for k, (n, h) in GOLDEN.items():
        assert len(got[k]) == n, k
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
