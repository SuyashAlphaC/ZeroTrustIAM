"""
Orchestrates training runs that blend synthetic data with accumulated real
samples drawn from the live dataset store.

The retrain is executed synchronously (for a manual /train call) or from the
APScheduler background thread. It writes the updated model to MODEL_DIR and
invokes the provided reload_fn so the serving layer swaps models atomically.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional

import numpy as np

from dataset import TrainingDataset
from model import RandomForestRiskModel
from synthetic_generator import generate


def retrain(
    dataset: TrainingDataset,
    model_dir: str,
    n_synthetic: int = 5000,
    benign_fraction: float = 0.6,
    n_estimators: int = 200,
    max_depth: int = 12,
    seed: int = 42,
    reload_fn: Optional[Callable[[], None]] = None,
) -> Dict[str, Any]:
    """Retrain the RF with synthetic + live samples and save to model_dir.

    Returns the metrics dict. Raises on failure — callers log the error.
    """
    X_real, y_real = dataset.fetch_all()
    run_id = dataset.record_retrain_start(
        n_real=int(X_real.shape[0]),
        n_synthetic=int(n_synthetic),
    )

    try:
        sources: List[str] = []
        X_list: List[np.ndarray] = []
        y_list: List[np.ndarray] = []

        if n_synthetic > 0:
            Xs, ys = generate(n_synthetic, benign_fraction, seed)
            X_list.append(Xs)
            y_list.append(ys)
            sources.append(f"synthetic:{n_synthetic}")

        if X_real.shape[0] > 0:
            X_list.append(X_real)
            y_list.append(y_real)
            sources.append(f"live:{X_real.shape[0]}")

        if not X_list:
            raise RuntimeError("no training data: both synthetic and real stores empty")

        X = np.concatenate(X_list, axis=0)
        y = np.concatenate(y_list, axis=0)

        # A healthy split requires both classes — if live is all-benign (common
        # early in deployment) we're still fine because synthetic carries
        # attacks. Guard the degenerate case anyway.
        if len(np.unique(y)) < 2:
            raise RuntimeError("training set has only one class; skipping retrain")

        model = RandomForestRiskModel(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=seed,
        )
        metrics = model.train(X, y, sources=sources)

        os.makedirs(model_dir, exist_ok=True)
        model.save(model_dir)

        dataset.record_retrain_finish(
            run_id=run_id,
            accuracy=float(metrics["accuracy"]),
            roc_auc=float(metrics["roc_auc"]),
            training_sources=sources,
        )

        if reload_fn is not None:
            try:
                reload_fn()
            except Exception:
                # A reload failure doesn't invalidate the trained artefacts on
                # disk — they will be picked up on the next process start.
                pass

        return {
            "accuracy": float(metrics["accuracy"]),
            "roc_auc": float(metrics["roc_auc"]),
            "n_samples": int(X.shape[0]),
            "n_real": int(X_real.shape[0]),
            "n_synthetic": int(n_synthetic),
            "training_sources": sources,
            "top_features": model.top_features(8),
        }
    except Exception as exc:
        dataset.record_retrain_error(run_id, str(exc))
        raise
