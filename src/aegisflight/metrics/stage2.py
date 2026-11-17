"""Stage 2 evaluation metrics (issue #28): event-level false-alert rates, intervals, latency and per-class scores.

Definitions (stated here once; ``scripts/make_stage2_metrics.py`` and ``docs/BENCHMARKING.md`` refer to them):

* **Alert event**: a decision with ``is_alert`` set by the fusion engine, i.e. a threat decision at SUSPICIOUS or above
  that is not suppressed by the per-attack-type cooldown (``fusion.cooldown_s``) while an alert is active (the active
  state clears after ``fusion.clear_ticks`` consecutive non-threat decisions). One persistent condition is one event,
  not one event per 0.2 s decision. ``alert_events`` re-derives ``is_alert`` from ``(t, threat, attack_type)`` with the
  engine's own rule, for artifacts that logged only those columns. Logged ``t`` is rounded; the re-derivation maps it
  back to the engine's raw tick time (``engine_tick_time``) so the exact-cooldown boundary is decided as the engine did.
* **False alerts per flight hour**: alert events on benign ground truth / exposure hours, where exposure is the
  scored decision time of the same decisions (count x decision period). The interval is the exact one-sided 95%
  Poisson (Garwood) upper bound on the event count, divided by the exposure: with 0 events in T hours the bound is
  2.996 / T.
* **Session-level rates** (detection, session FPR): proportions over sessions with two-sided 95% Wilson intervals,
  which stay inside [0, 1] and behave at 0 / n and n / n, where the normal approximation does not.
* **Onset latency**: time from the first decision labelled with the attack to the first threat decision inside the
  attack window (the benchmark's ``time_to_detect_s``). **Release latency** (drift): from the last labelled attack
  decision (the attacker stops) to the same detection; negative when detection came before the release.
* **Per-class precision / recall / F1** from a confusion matrix ``cm[true][pred]``. A class with support but no
  predictions has precision 0 (and F1 0), not NaN, so it pulls the macro average down instead of disappearing.
  Macro-F1 is the unweighted mean over a stated class set, and two sets are reported, labelled: **attack classes only**
  (the set ``metrics/scoring.py`` ``Evaluation.macro()`` averages) and **including BENIGN** (every class with support).
* **Accuracy** is reported two ways, labelled: **binary** (attack = positive, any attack label counts as detected; the
  ``docs/BENCHMARKING.md`` definition and ``results.json`` ``binary_*.accuracy``) and **multiclass** (attribution: the
  exact class must match). Both are dominated by the benign majority and are listed last.
* **Percentiles**: nearest-rank (no interpolation), so a reported p95 is an observed value; always reported with n.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence

from scipy.stats import chi2

Z95 = 1.959963984540054
TICK_S = 1.0 / 10.0          # engine tick: 1 / configs/simulation.yaml sample_rate_hz (a test pins it to the config)


def rate_per_hour(events: int, exposure_s: float) -> float:
    """Events per hour of exposure. Exposure must be positive."""
    if exposure_s <= 0:
        raise ValueError("exposure must be > 0 s")
    return events / (exposure_s / 3600.0)


def poisson_upper(k: int, conf: float = 0.95) -> float:
    """Exact one-sided upper confidence bound on a Poisson mean given ``k`` observed events (Garwood)."""
    if k < 0:
        raise ValueError("k must be >= 0")
    return float(chi2.ppf(conf, 2 * k + 2) / 2.0)


def rate_upper_per_hour(events: int, exposure_s: float, conf: float = 0.95) -> float:
    return poisson_upper(events, conf) / (exposure_s / 3600.0)


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Two-sided Wilson score interval for k successes in n trials."""
    if n <= 0 or not 0 <= k <= n:
        raise ValueError("need 0 <= k <= n and n > 0")
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    lo = 0.0 if k == 0 else max(0.0, centre - half)          # exact ends: rounding leaves 1 - 1e-16 at n / n
    hi = 1.0 if k == n else min(1.0, centre + half)
    return lo, hi


def engine_tick_time(t: float, tick_s: float = TICK_S) -> float:
    """The engine's own float for a logged (rounded) decision time: ``k * tick_s`` with ``k = round(t / tick_s)``.

    The engine timestamps tick ``k`` as ``k * dt`` (``simulator/flight.py``, ``sources/mavlink_live.py``; ``dt = 1 /
    sample_rate_hz``) and compares those raw floats against ``cooldown_s``. Logs keep ``round(t, 2)`` or ``round(t, 3)``,
    and a 4.0 s gap differs by one ulp between the two: ``646 * 0.1 - 606 * 0.1 = 4.000000000000007`` but
    ``64.6 - 60.6 = 3.999999999999993``. Raises ``ValueError`` if ``t`` is not on the tick grid, rather than guess.
    """
    k = round(t / tick_s)
    if abs(t / tick_s - k) > 1e-6:
        raise ValueError(f"t={t!r} is not on the {tick_s} s tick grid; pass the source's tick_s (or None for raw t)")
    return k * tick_s


def alert_events(rows: Iterable[tuple[float, bool, str]], cooldown_s: float = 4.0, clear_ticks: int = 4,
                 tick_s: float | None = TICK_S) -> list[bool]:
    """``is_alert`` for each ``(t, threat, attack_type)`` decision, by the fusion engine's de-duplication rule.

    Valid when every threat decision is at or above the alert severity (true for the shipped config: the threat
    threshold equals the SUSPICIOUS band); ``tests/unit/test_stage2_metrics.py`` checks it against the engine.
    ``t`` may be the logged, rounded time: with ``tick_s`` set (default: the shipped 10 Hz tick) it is mapped back to
    the engine's raw tick time by ``engine_tick_time``, so a gap of exactly ``cooldown_s`` is decided as the engine
    decided it. ``tick_s=None`` uses ``t`` as given.
    """
    last: dict[str, float] = {}
    active, streak = False, 0
    out: list[bool] = []
    for t, threat, kind in rows:
        if tick_s is not None:
            t = engine_tick_time(t, tick_s)
        alert = False
        if threat:
            if (t - last.get(kind, -1e9)) >= cooldown_s or not active:
                alert = True
                last[kind] = t
            active, streak = True, 0
        else:
            streak += 1
            if streak >= clear_ticks:
                active = False
        out.append(alert)
    return out


def onset_latency(decisions: Sequence[tuple[float, bool, bool]]) -> dict[str, float | None]:
    """``decisions`` = ``(t, in_attack_window, threat)`` in time order. Returns onset / release / detection times and
    both latencies (``None`` when there is no window or no detection inside it)."""
    win = [(t, th) for t, inw, th in decisions if inw]
    if not win:
        return {"onset_t": None, "release_t": None, "detect_t": None, "from_onset_s": None, "from_release_s": None}
    onset, release = win[0][0], win[-1][0]
    det = next((t for t, th in win if th), None)
    return {"onset_t": onset, "release_t": release, "detect_t": det,
            "from_onset_s": None if det is None else det - onset,
            "from_release_s": None if det is None else det - release}


def nearest_rank(values: Sequence[float], q: float) -> float | None:
    """Nearest-rank percentile (q in (0, 100]); ``None`` for no values."""
    if not values:
        return None
    s = sorted(values)
    return s[max(0, math.ceil(q / 100.0 * len(s)) - 1)]


def per_class_prf(cm: Mapping[str, Mapping[str, int]]) -> dict[str, dict[str, float | int]]:
    """Per-class precision, recall, F1 and support from ``cm[true][pred]`` (labels = the union of both axes)."""
    labels = sorted(set(cm) | {p for row in cm.values() for p in row})
    out: dict[str, dict[str, float | int]] = {}
    for c in labels:
        tp = cm.get(c, {}).get(c, 0)
        support = sum(cm.get(c, {}).values())
        predicted = sum(cm.get(t, {}).get(c, 0) for t in cm)
        prec = tp / predicted if predicted else 0.0
        rec = tp / support if support else float("nan")
        f1 = 2 * prec * rec / (prec + rec) if support and (prec + rec) > 0 else (0.0 if support else float("nan"))
        out[c] = {"precision": prec, "recall": rec, "f1": f1, "support": support, "predicted": predicted, "tp": tp}
    return out


def macro_f1(prf: Mapping[str, Mapping[str, float | int]], classes: Iterable[str] | None = None) -> float:
    """Unweighted mean F1 over the given classes (default: every class with support > 0)."""
    keys = list(classes) if classes is not None else [c for c, v in prf.items() if v["support"]]
    if not keys:
        raise ValueError("no classes with support")
    return sum(float(prf[c]["f1"]) for c in keys) / len(keys)


def accuracy(cm: Mapping[str, Mapping[str, int]]) -> float:
    """Multiclass (attribution) accuracy: the diagonal over all decisions."""
    tot = sum(v for row in cm.values() for v in row.values())
    return sum(cm[c].get(c, 0) for c in cm) / tot if tot else float("nan")


def binary_accuracy(cm: Mapping[str, Mapping[str, int]], negative: str = "BENIGN") -> float:
    """Binary accuracy, attack = positive: (TN + TP) / N, where TN = ``cm[negative][negative]`` and TP counts every
    attack decision predicted as any attack class (a misattributed attack is still detected)."""
    tot = sum(v for row in cm.values() for v in row.values())
    tn = cm.get(negative, {}).get(negative, 0)
    tp = sum(v for t, row in cm.items() if t != negative for p, v in row.items() if p != negative)
    return (tn + tp) / tot if tot else float("nan")
