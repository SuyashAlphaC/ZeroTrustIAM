"""
Champion / challenger promoter (Tier B.7).

The retrainer writes new artefacts to ``MODEL_DIR/candidate``. This module
compares the candidate against the active champion on a held-out validation
set and exposes atomic-ish swap / rollback primitives so the serving layer
can hot-promote a better model (or revert a regression) without a redeploy.
"""

from __future__ import annotations

import os
import shutil
from typing import Any, Dict, List

import numpy as np
from sklearn.metrics import accuracy_score, precision_score, roc_auc_score

from model import META_FILENAME, MODEL_FILENAME, RandomForestRiskModel


# Files that constitute one model snapshot on disk.
_MODEL_FILES = (MODEL_FILENAME, META_FILENAME)

# Subdirectory names under MODEL_DIR.
CANDIDATE_DIRNAME = "candidate"
PREVIOUS_DIRNAME = "previous"

# Promotion thresholds.
MIN_DELTA_AUC = 0.02
MAX_PRECISION_REGRESSION = -0.05


def _score(model: RandomForestRiskModel, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
    proba = model.clf.predict_proba(X)[:, 1]
    pred = model.clf.predict(X)
    # roc_auc_score requires both classes present
    if len(np.unique(y)) < 2:
        auc = 0.5
    else:
        auc = float(roc_auc_score(y, proba))
    return {
        "accuracy": float(accuracy_score(y, pred)),
        "roc_auc": auc,
        "precision_attack": float(
            precision_score(y, pred, pos_label=1, zero_division=0)
        ),
    }


def compare_models(
    champion_dir: str,
    candidate_dir: str,
    validation_X: np.ndarray,
    validation_y: np.ndarray,
) -> Dict[str, Any]:
    """Score champion + candidate on the validation set and recommend promotion."""
    champion = RandomForestRiskModel.load(champion_dir)
    candidate = RandomForestRiskModel.load(candidate_dir)

    champion_metrics = _score(champion, validation_X, validation_y)
    candidate_metrics = _score(candidate, validation_X, validation_y)

    delta_auc = candidate_metrics["roc_auc"] - champion_metrics["roc_auc"]
    delta_precision_attack = (
        candidate_metrics["precision_attack"] - champion_metrics["precision_attack"]
    )
    recommend_promote = (
        delta_auc >= MIN_DELTA_AUC
        and delta_precision_attack >= MAX_PRECISION_REGRESSION
    )

    return {
        "champion_metrics": champion_metrics,
        "candidate_metrics": candidate_metrics,
        "delta_auc": float(delta_auc),
        "delta_precision_attack": float(delta_precision_attack),
        "recommend_promote": bool(recommend_promote),
    }


def _has_model_files(path: str) -> bool:
    return os.path.isdir(path) and all(
        os.path.isfile(os.path.join(path, f)) for f in _MODEL_FILES
    )


def _move_model_files(src: str, dst: str) -> None:
    os.makedirs(dst, exist_ok=True)
    for f in _MODEL_FILES:
        src_path = os.path.join(src, f)
        if not os.path.isfile(src_path):
            continue
        dst_path = os.path.join(dst, f)
        if os.path.isfile(dst_path):
            os.remove(dst_path)
        shutil.move(src_path, dst_path)


def promote_candidate(model_dir: str) -> bool:
    """Move root champion → previous/, then candidate/ → root. Atomic-ish."""
    candidate_dir = os.path.join(model_dir, CANDIDATE_DIRNAME)
    if not _has_model_files(candidate_dir):
        return False

    previous_dir = os.path.join(model_dir, PREVIOUS_DIRNAME)
    # Archive the current champion (if any) before overwriting.
    if all(os.path.isfile(os.path.join(model_dir, f)) for f in _MODEL_FILES):
        _move_model_files(model_dir, previous_dir)

    _move_model_files(candidate_dir, model_dir)
    # Clean up the now-empty candidate directory.
    try:
        os.rmdir(candidate_dir)
    except OSError:
        pass
    return True


def rollback(model_dir: str) -> bool:
    """Restore previous/ as the champion. Returns False if no previous snapshot."""
    previous_dir = os.path.join(model_dir, PREVIOUS_DIRNAME)
    if not _has_model_files(previous_dir):
        return False

    # Stash the current champion in a temp dir so we don't lose it on failure.
    stash_dir: List[str] = []
    if all(os.path.isfile(os.path.join(model_dir, f)) for f in _MODEL_FILES):
        stash = os.path.join(model_dir, ".rollback_stash")
        if os.path.isdir(stash):
            shutil.rmtree(stash)
        _move_model_files(model_dir, stash)
        stash_dir.append(stash)

    _move_model_files(previous_dir, model_dir)
    try:
        os.rmdir(previous_dir)
    except OSError:
        pass

    # Discard the stash — rollback succeeded.
    for stash in stash_dir:
        if os.path.isdir(stash):
            shutil.rmtree(stash, ignore_errors=True)
    return True
