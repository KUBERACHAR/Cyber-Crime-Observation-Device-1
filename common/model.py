"""Load the trained model bundle and score feature vectors.

The bundle (``models/model.pkl``) is produced by ``ml/train.py`` (in Colab or locally)
and contains a Random Forest classifier plus an Isolation Forest anomaly detector.
Final threat score = ``rf_weight * P(suspicious) + (1 - rf_weight) * anomaly``.

If no model is present yet, a transparent heuristic scorer is used so the pipeline and
dashboard can be exercised from day one.
"""
from __future__ import annotations

import warnings
from pathlib import Path

import numpy as np

from .config import SETTINGS
from .features import FEATURE_COLUMNS

_IDX = {c: i for i, c in enumerate(FEATURE_COLUMNS)}


class ModelMismatchError(RuntimeError):
    pass


class ThreatModel:
    kind = "ml"

    def __init__(self, bundle: dict, rf_weight: float = SETTINGS.rf_weight):
        if list(bundle.get("features", [])) != FEATURE_COLUMNS:
            raise ModelMismatchError(
                "model.pkl was trained on a different feature set - retrain it with the "
                "current common/features.py")
        self.rf = bundle["rf"]
        self.iforest = bundle.get("iforest")
        self.if_lo, self.if_hi = bundle.get("if_range", (0.0, 1.0))
        self.metrics = bundle.get("metrics", {})
        self.trained_at = bundle.get("trained_at", "?")
        self.rf_weight = rf_weight if self.iforest is not None else 1.0
        # Small batches are scored every tick: thread fan-out costs more than it saves.
        for est in (self.rf, self.iforest):
            if est is not None and hasattr(est, "n_jobs"):
                est.n_jobs = 1

    def score(self, X: np.ndarray) -> np.ndarray:
        if len(X) == 0:
            return np.zeros(0)
        p = self.rf.predict_proba(X)[:, 1]
        if self.iforest is None:
            return p
        raw = -self.iforest.score_samples(X)
        anom = np.clip((raw - self.if_lo) / max(self.if_hi - self.if_lo, 1e-9), 0.0, 1.0)
        return self.rf_weight * p + (1.0 - self.rf_weight) * anom

    def describe(self) -> str:
        acc = self.metrics.get("accuracy")
        acc_s = f", acc {acc:.1%}" if isinstance(acc, (int, float)) else ""
        return f"RandomForest+IsolationForest (trained {self.trained_at}{acc_s})"


class HeuristicModel:
    """Fallback used until a trained model.pkl exists. Not a substitute for training."""
    kind = "heuristic"
    metrics: dict = {}

    def score(self, X: np.ndarray) -> np.ndarray:
        if len(X) == 0:
            return np.zeros(0)
        g = lambda c: X[:, _IDX[c]]  # noqa: E731
        z = (-4.0 + 0.45 * g("cmd_risk") + 0.9 * (g("is_shell") + g("is_lolbin"))
             + 1.2 * g("parent_is_office")
             + 1.6 * np.tanh(g("write_ops_rate") / 80.0) * (g("sys_file_create_rate") > 5)
             + 1.5 * np.tanh(g("sys_file_create_rate") / 20.0) * (g("is_shell") + g("is_lolbin"))
             + 0.8 * np.tanh(g("num_remote_ips") / 20.0))
        return 1.0 / (1.0 + np.exp(-z))

    def describe(self) -> str:
        return "Heuristic fallback (no models/model.pkl yet - train one!)"


def load_model(path: Path | None = None):
    path = Path(path or SETTINGS.model_path)
    if not path.exists():
        return HeuristicModel()
    import joblib  # deferred: keeps import cost off the dashboard's cold path
    import sklearn
    bundle = joblib.load(path)
    trained_with = bundle.get("sklearn_version")
    if trained_with and trained_with != sklearn.__version__:
        warnings.warn(f"model.pkl was trained with scikit-learn {trained_with} but "
                      f"{sklearn.__version__} is installed - pin the same version in "
                      "requirements.txt and requirements-colab.txt", stacklevel=2)
    return ThreatModel(bundle)

