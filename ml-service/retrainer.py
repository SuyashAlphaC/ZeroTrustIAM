"""
Orchestrates training runs using only accumulated real samples drawn from the
live dataset store.

The retrain is executed synchronously (for a manual /train call) or from the
APScheduler background thread. It writes the updated model artefacts into
``MODEL_DIR/candidate`` (champion/challenger workflow — Tier B.7); the active
champion under ``MODEL_DIR`` is only swapped via promoter.promote_candidate.
``reload_fn`` is therefore NOT invoked here.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional

import numpy as np

from dataset import TrainingDataset
from model import RandomForestRiskModel

MIN_SAMPLES_FOR_TRAIN = int(os.environ.get("MIN_SAMPLES_FOR_TRAIN", "20"))


def retrain(
    dataset: TrainingDataset,
    model_dir: str,
    n_estimators: int = 200,
    max_depth: int = 12,
    seed: int = 42,
    reload_fn: Optional[Callable[[], None]] = None,
) -> Dict[str, Any]:
    """Retrain the RF with real observed samples and save to model_dir.

    Returns the metrics dict. Raises on failure — callers log the error.
    """
    X_real, y_real = dataset.fetch_all()
    run_id = dataset.record_retrain_start(
        n_real=int(X_real.shape[0]),
        n_synthetic=0,
    )

    try:
        if X_real.shape[0] == 0:
            raise RuntimeError("no training data: live dataset is empty")

        if X_real.shape[0] < MIN_SAMPLES_FOR_TRAIN:
            raise RuntimeError(
                f"not enough labeled samples ({X_real.shape[0]}); need >= {MIN_SAMPLES_FOR_TRAIN} "
                "(MIN_SAMPLES_FOR_TRAIN)"
            )

        X = X_real
        y = y_real
        sources: List[str] = [f"live:{X_real.shape[0]}"]

        if len(np.unique(y)) < 2:
            raise RuntimeError("training set has only one class; skipping retrain")

        model = RandomForestRiskModel(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=seed,
        )
        metrics = model.train(X, y, sources=sources)

        os.makedirs(model_dir, exist_ok=True)
        candidate_dir = os.path.join(model_dir, "candidate")
        os.makedirs(candidate_dir, exist_ok=True)
        model.save(candidate_dir)

        dataset.record_retrain_finish(
            run_id=run_id,
            accuracy=float(metrics["accuracy"]),
            roc_auc=float(metrics["roc_auc"]),
            training_sources=sources,
        )

        # NOTE: reload_fn is intentionally NOT called for candidate writes.
        # Promotion is gated by promoter.compare_models / promote_candidate.
        _ = reload_fn  # kept in signature for backward compatibility

        return {
            "accuracy": float(metrics["accuracy"]),
            "roc_auc": float(metrics["roc_auc"]),
            "n_samples": int(X.shape[0]),
            "n_real": int(X_real.shape[0]),
            "n_synthetic": 0,
            "training_sources": sources,
            "top_features": model.top_features(8),
            "candidate_dir": candidate_dir,
        }
    except Exception as exc:
        dataset.record_retrain_error(run_id, str(exc))
        raise
