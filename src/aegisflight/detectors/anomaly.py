"""Detector C — lightweight ML anomaly detector (benign-trained).

An **ensemble** of two benign-only anomaly signals over the ``ML_FEATURES``
vector, combined by taking the stronger of the two:

1. **Isolation Forest** — captures subtle *multivariate, in-distribution*
   anomalies (e.g. an unusual combination of otherwise-normal values).
2. **Diagonal Mahalanobis / scaled-norm** — the L2 norm of the standardised
   feature vector. Isolation Forest cannot extrapolate past its training range,
   so it is blind to features that spike far outside benign (msg-rate floods,
   sequence gaps). The scaled-norm grows without bound for such out-of-range
   values and covers that blind spot. (Diagonal covariance and ordinary
   mean/std -- not a robust estimator.) Zero-variance benign features get unit
   scale from ``StandardScaler``, so any nonzero value registers.

Both are trained on benign flights only (see ``scripts/train_models.py``); the
bundle carries the scaler, model, feature schema, per-component benign
statistics, the calibrated score threshold/scale, and the sklearn version.
Missing/incompatible model => the detector degrades to a no-op (score 0).
"""

from __future__ import annotations

import io
import logging
import math
import warnings
from operator import attrgetter
from pathlib import Path

import numpy as np

from ..core.enums import AttackType, DetectorName
from ..core.types import DetectorResult
from ..features.extractor import ML_FEATURES, FeatureFrame
from .base import Detector

log = logging.getLogger(__name__)

# Which ML feature, when most anomalous, implies which attack class.
FEATURE_ATTACK_MAP: dict[str, AttackType] = {
    "msg_rate_hz": AttackType.DOS,
    "interarrival_jitter_ms": AttackType.DOS,
    "max_seq_gap": AttackType.DOS,
    "pos_residual_m": AttackType.GPS_SPOOFING,
    "gps_vfr_speed_diff_ms": AttackType.TELEMETRY_MANIPULATION,
    "gps_baro_alt_diff_m": AttackType.TELEMETRY_MANIPULATION,
    "alt_rate_ms": AttackType.TELEMETRY_MANIPULATION,
    "accel_ms2": AttackType.GPS_SPOOFING,
    "yaw_course_diff_deg": AttackType.TELEMETRY_MANIPULATION,
    "cmd_rate_hz": AttackType.COMMAND_INJECTION,
    "loss_ratio": AttackType.DOS,
}

def combined_anomaly_raw(bundle: dict, X: np.ndarray) -> np.ndarray:
    """Combined benign-anomaly signal per row (shared by training & inference).

    Returns ``max(iso_z, maha_z)`` where each component is standardised by its
    benign train statistics, so the two are on a comparable scale.
    """
    scaler = bundle["scaler"]
    model = bundle["model"]
    Xs = scaler.transform(X)

    iso = -model.score_samples(Xs)  # higher => more anomalous
    return _combine(bundle, iso, Xs)


def _combine(bundle: dict, iso: np.ndarray, Xs: np.ndarray) -> np.ndarray:
    """``max(iso_z, maha_z)`` from the Isolation-Forest score and the standardised rows."""
    iso_z = (iso - bundle["iso_mean"]) / max(1e-9, bundle["iso_std"])

    maha = np.linalg.norm(Xs, axis=1)  # scaled features are z-scores
    maha_z = (maha - bundle["maha_mean"]) / max(1e-9, bundle["maha_std"])

    return np.maximum(iso_z, maha_z)


class _FastScorer:
    """Single-row replica of ``StandardScaler.transform`` + ``IsolationForest.score_samples``.

    ``score_samples`` on one row costs ~12 ms (joblib dispatch, per-tree validation, warning
    context managers); this walks the same fitted trees directly. It is bit-identical by
    construction (same float32 cast of the input, same ``<=`` threshold test, the per-leaf
    ``decision_path_length + average_path_length - 1.0`` terms taken from the fitted model and
    added left to right in tree order, the same numpy ``divide`` / ``2 **`` finish) and is
    verified against the real sklearn call on probe rows before first use (:func:`_fast_scorer`);
    a mismatch, an unknown model layout or a non-finite input falls back to sklearn.
    """

    def __init__(self, model, scaler) -> None:
        n_feat = int(model.n_features_in_)
        if model._max_features != n_feat:
            raise ValueError("feature subsampling")
        self.mean = np.asarray(scaler.mean_, dtype=np.float64)
        self.scale = np.asarray(scaler.scale_, dtype=np.float64)
        if not (scaler.with_mean and scaler.with_std) or self.mean.shape != (n_feat,):
            raise ValueError("scaler layout")
        from sklearn.ensemble._iforest import _average_path_length  # noqa: PLC0415

        # flat node tables of all trees (plain lists: ~25k nodes for 200 trees, ~3 MB; typed arrays
        # would save ~2 MB but made the walk ~30 % slower)
        feat: list[int] = []
        thr: list[float] = []
        left: list[int] = []
        right: list[int] = []
        val: list[float] = []
        roots: list[int] = []
        off = 0
        for i, est in enumerate(model.estimators_):
            t = est.tree_
            contrib = model._decision_path_lengths[i] + model._average_path_length_per_tree[i] - 1.0
            roots.append(off)
            feat += t.feature.tolist()
            thr += t.threshold.tolist()
            left += [(-1 if c == -1 else c + off) for c in t.children_left.tolist()]
            right += [(-1 if c == -1 else c + off) for c in t.children_right.tolist()]
            val += np.asarray(contrib, dtype=np.float64).tolist()
            off += t.node_count
        self.feat, self.thr, self.left, self.right, self.val = feat, thr, left, right, val
        self.roots = roots
        self.n_feat = n_feat
        self.denominator = len(model.estimators_) * _average_path_length([model._max_samples])

    def transform(self, vec: np.ndarray) -> np.ndarray:
        return (vec - self.mean) / self.scale

    def iso(self, Xs: np.ndarray) -> np.ndarray | None:
        """``-model.score_samples(Xs)`` for one row (shape (1, n)); None if not finite in float32."""
        x32 = Xs.astype(np.float32)
        if not np.isfinite(x32).all():
            return None
        x = x32[0].tolist()
        feat, thr, left, right, val = self.feat, self.thr, self.left, self.right, self.val
        total = 0.0
        for n in self.roots:
            while True:
                lc = left[n]
                if lc < 0:
                    break
                n = lc if x[feat[n]] <= thr[n] else right[n]
            total += val[n]
        depths = np.array([total])
        scores = 2 ** (-np.divide(depths, self.denominator, out=np.ones_like(depths),
                                  where=self.denominator != 0))
        return scores  # == -(-scores): sklearn returns -scores and the caller negates it


_FAST_CACHE: dict[tuple, _FastScorer | None] = {}


def _fast_scorer(path: Path | None, bundle: dict, sha256: str | None = None) -> _FastScorer | None:
    """The verified fast scorer for this model (built once per process), else None.

    Cached by the SHA-256 of the loaded bytes when given (#144), else by the file's stat signature.
    """
    key: tuple | None
    if sha256 is not None:
        key = ("sha256", sha256)
    else:
        try:
            st = path.stat() if path is not None else None
            key = (str(path.resolve()), st.st_mtime_ns, st.st_size) if st is not None else None
        except OSError:
            key = None
    if key is not None and key in _FAST_CACHE:
        return _FAST_CACHE[key]
    fast: _FastScorer | None
    try:
        fast = _FastScorer(bundle["model"], bundle["scaler"])
        rs = np.random.RandomState(20261029)
        probes = [rs.randn(1, fast.n_feat) * k for k in (0.5, 1.0, 1.0, 2.0, 3.0, 5.0, 10.0, 40.0)]
        probes += [fast.mean[None, :] + rs.randn(1, fast.n_feat) * fast.scale * 2.0 for _ in range(4)]
        probes.append(np.zeros((1, fast.n_feat)))
        for raw in probes:
            xs = bundle["scaler"].transform(raw)
            iso = fast.iso(xs)
            if (iso is None or not np.array_equal(xs, fast.transform(raw))
                    or not np.array_equal(iso, -bundle["model"].score_samples(xs))):
                fast = None
                break
    except Exception:  # noqa: BLE001 - any unexpected model layout => stay on the sklearn path
        fast = None
    if key is not None:
        _FAST_CACHE[key] = fast
    return fast


class AnomalyDetector(Detector):
    name = DetectorName.ANOMALY

    def __init__(
        self,
        cfg: dict,
        model_path: str | Path | None = None,
        *,
        allow_unverified: bool = False,
    ) -> None:
        """``model_path=None`` means **ML off** (detector is a no-op).

        Previously ``None`` silently fell back to ``cfg["model_path"]``, so the
        documented ``--no-model`` / ``model_path=None`` "rule + physics only"
        runs still loaded the model whenever ``models/isoforest.joblib`` existed.
        Callers that want the model pass its path explicitly.

        Security boundary (#11 / D4): every model file is checked against ``MODELS.sha256``
        BEFORE ``joblib.load()`` deserialization; tampered (``mismatch``) or ``unlisted``
        files are refused without unpickling unless ``allow_unverified=True``.
        """
        self.enabled = bool(cfg.get("enabled", True))
        self.threshold = float(cfg.get("score_threshold", 0.62))
        self.warmup_ticks = int(cfg.get("warmup_ticks", 20))
        calibrated_override = cfg.get("calibrated_model_path")
        if not self.enabled and calibrated_override:
            path = Path(calibrated_override)
        elif not self.enabled:
            path = None
        else:
            path = Path(model_path) if model_path else None
        self.model_path = path
        self.bundle: dict | None = None
        self.load_error: str | None = None
        # SHA-256 of the file that was actually deserialised (None unless a model loaded); benchmark
        # metadata records this, never a hash of a file that was refused
        self.loaded_sha256: str | None = None
        self._ticks = 0
        self._fast: _FastScorer | None = None
        self._fast_bundle: dict | None = None
        self._get_features = attrgetter(*ML_FEATURES)
        if path is not None and not path.exists():
            log.warning(
                "ML model requested but not loaded: %s does not exist; ML detector is OFF "
                "(fetch it with `python scripts/fetch_models.py`)",
                path,
            )
        if path is not None and path.exists():
            from ..model_integrity import OK as _MODEL_OK  # noqa: PLC0415
            from ..model_integrity import read_and_check_model as _read_and_check  # noqa: PLC0415

            # one read (#144): the hash is taken over exactly the bytes that are deserialised below
            chk, model_bytes = _read_and_check(path)
            if chk.status != _MODEL_OK and not allow_unverified:
                self.bundle = None
                self.load_error = f"ModelIntegrityError ({chk.status}): {chk.message()}"
                log.warning(
                    "ML model refused before deserialization (%s): %s; ML detector is OFF",
                    chk.status,
                    chk.message(),
                )
                return
            try:
                import joblib  # noqa: PLC0415 - lazy so slim ML-off onboard installs work without joblib

                if model_bytes is None:  # removed after the exists() check: fail closed, ML off
                    raise FileNotFoundError(f"model file vanished before it could be read: {path}")
                self.bundle = joblib.load(io.BytesIO(model_bytes))
            except ImportError as exc:
                self.bundle = None
                self.load_error = f"ImportError: {exc}"
                warnings.warn(
                    f"AnomalyDetector disabled despite model file {path}: {exc} "
                    "(install scikit-learn/joblib to enable ML)",
                    RuntimeWarning,
                    stacklevel=2,
                )
            except Exception as exc:  # noqa: BLE001 - corrupt/incompatible model => degrade
                self.bundle = None
                self.load_error = f"{type(exc).__name__}: {exc}"
                log.warning(
                    "ML model requested but not loaded: %s is unreadable (%s: %s); ML detector is OFF",
                    path,
                    type(exc).__name__,
                    exc,
                )
            else:
                self._fast = _fast_scorer(path, self.bundle, chk.sha256)
                self._fast_bundle = self.bundle
                self.loaded_sha256 = chk.sha256

    @property
    def available(self) -> bool:
        return self.bundle is not None

    def process(self, frame: FeatureFrame) -> DetectorResult:
        self._ticks += 1
        signals: dict[str, float] = {}
        if self.bundle is None or self._ticks < self.warmup_ticks:
            return DetectorResult(
                detector=self.name, score=0.0, triggered=False,
                evidence=[], attack_votes={}, signals=signals,
            )

        thr = self.bundle["score_thr"]
        scale = self.bundle["score_scale"]
        vec = np.array([[float(v) for v in self._get_features(frame)]])
        fast = self._fast if self._fast_bundle is self.bundle else None
        iso = Xs = None
        if fast is not None and np.isfinite(vec).all():
            Xs = fast.transform(vec)
            iso = fast.iso(Xs)
        if iso is not None:
            raw = float(_combine(self.bundle, iso, Xs)[0])
            z = Xs[0]
        else:
            raw = float(combined_anomaly_raw(self.bundle, vec)[0])
            z = None
        norm = 1.0 / (1.0 + math.exp(-(raw - thr) / max(1e-6, scale)))
        signals["anomaly_raw"] = raw
        signals["anomaly_score"] = norm

        # Attribute to the most-deviating standardised feature.
        if z is None:
            z = self.bundle["scaler"].transform(vec)[0]
        idx = int(np.argmax(np.abs(z)))
        top_feat = ML_FEATURES[idx]
        attack = FEATURE_ATTACK_MAP.get(top_feat, AttackType.GPS_SPOOFING)

        triggered = norm >= self.threshold
        evidence: list[str] = []
        votes: dict[AttackType, float] = {}
        if triggered:
            evidence.append(
                f"ML anomaly score {norm:.2f} ≥ {self.threshold:.2f} "
                f"(driver: {top_feat}, z={z[idx]:+.1f})"
            )
            votes[attack] = norm
        return DetectorResult(
            detector=self.name,
            score=norm,
            triggered=triggered,
            evidence=evidence,
            attack_votes=votes,
            signals=signals,
        )

    def reset(self) -> None:
        # Restart the warm-up so the ML layer waits for a fresh feature window
        # to fill (the extractor is reset alongside it) before scoring again.
        self._ticks = 0
