# Tier B.7: champion/challenger promoter — comparison + atomic swap + rollback.

from __future__ import annotations

import os
import tempfile

import numpy as np

import promoter
from features import FEATURE_NAMES
from model import META_FILENAME, MODEL_FILENAME, RandomForestRiskModel


def _separable_dataset(n: int, seed: int, signal: float):
    """Generate a binary classification problem where ``signal`` controls class separation."""
    rng = np.random.RandomState(seed)
    X = rng.randn(n, len(FEATURE_NAMES)).astype(np.float32) * 0.1
    y = (rng.rand(n) > 0.5).astype(np.int32)
    # Push class 1 along feature 0 by ``signal`` so a stronger model AUC tracks it.
    X[y == 1, 0] += signal
    return X, y


def _train(n_estimators: int, max_depth: int, seed: int, n: int = 240, signal: float = 0.6):
    X, y = _separable_dataset(n, seed, signal)
    model = RandomForestRiskModel(n_estimators=n_estimators, max_depth=max_depth, random_state=seed)
    model.train(X, y)
    return model, X, y


def _validation_set(seed: int, signal: float):
    return _separable_dataset(160, seed, signal)


def test_compare_models_recommends_promote_when_candidate_better():
    with tempfile.TemporaryDirectory() as td:
        champion_dir = os.path.join(td, "champion")
        candidate_dir = os.path.join(td, "candidate")
        # Champion is starved (few trees, single split) → poor AUC.
        champ, _, _ = _train(n_estimators=3, max_depth=1, seed=42, signal=0.05)
        # Candidate is well-fit → strong AUC.
        cand, _, _ = _train(n_estimators=120, max_depth=8, seed=43, signal=0.6)
        champ.save(champion_dir)
        cand.save(candidate_dir)

        X_val, y_val = _validation_set(seed=99, signal=0.6)
        result = promoter.compare_models(champion_dir, candidate_dir, X_val, y_val)
        assert result["delta_auc"] >= 0.05
        assert result["recommend_promote"] is True


def test_compare_models_blocks_promote_when_candidate_worse():
    with tempfile.TemporaryDirectory() as td:
        champion_dir = os.path.join(td, "champion")
        candidate_dir = os.path.join(td, "candidate")
        champ, _, _ = _train(n_estimators=120, max_depth=8, seed=42, signal=0.6)
        cand, _, _ = _train(n_estimators=3, max_depth=1, seed=43, signal=0.05)
        champ.save(champion_dir)
        cand.save(candidate_dir)

        X_val, y_val = _validation_set(seed=99, signal=0.6)
        result = promoter.compare_models(champion_dir, candidate_dir, X_val, y_val)
        assert result["delta_auc"] < 0
        assert result["recommend_promote"] is False


def test_promote_then_rollback_restores_champion():
    with tempfile.TemporaryDirectory() as td:
        # Stage a champion at the root.
        champ, _, _ = _train(n_estimators=20, max_depth=4, seed=11)
        champ.save(td)
        champ_meta_path = os.path.join(td, META_FILENAME)
        with open(champ_meta_path, "rb") as f:
            champ_meta_bytes = f.read()

        # Stage a candidate underneath.
        cand_dir = os.path.join(td, promoter.CANDIDATE_DIRNAME)
        cand, _, _ = _train(n_estimators=20, max_depth=4, seed=22)
        cand.save(cand_dir)
        with open(os.path.join(cand_dir, META_FILENAME), "rb") as f:
            cand_meta_bytes = f.read()
        assert champ_meta_bytes != cand_meta_bytes

        assert promoter.promote_candidate(td) is True
        # Candidate is now the champion; previous/ holds the old champion.
        assert os.path.isfile(os.path.join(td, MODEL_FILENAME))
        with open(champ_meta_path, "rb") as f:
            assert f.read() == cand_meta_bytes
        previous_dir = os.path.join(td, promoter.PREVIOUS_DIRNAME)
        with open(os.path.join(previous_dir, META_FILENAME), "rb") as f:
            assert f.read() == champ_meta_bytes

        # Rollback should restore the original champion.
        assert promoter.rollback(td) is True
        with open(champ_meta_path, "rb") as f:
            assert f.read() == champ_meta_bytes


def test_promote_returns_false_when_no_candidate():
    with tempfile.TemporaryDirectory() as td:
        assert promoter.promote_candidate(td) is False


def test_rollback_returns_false_when_no_previous():
    with tempfile.TemporaryDirectory() as td:
        assert promoter.rollback(td) is False
