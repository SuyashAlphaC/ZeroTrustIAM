# Tier B.8: PSI feature-drift detection.

from __future__ import annotations

import os
import tempfile

import numpy as np

import drift
from dataset import TrainingDataset
from features import FEATURE_NAMES


def test_compute_psi_identical_distributions_near_zero():
    rng = np.random.RandomState(42)
    sample = rng.randn(2000)
    psi = drift.compute_psi(sample, sample.copy())
    assert psi < 0.01


def test_compute_psi_shifted_distribution_large():
    rng = np.random.RandomState(42)
    reference = rng.randn(2000)
    current = rng.randn(2000) + 4.0  # heavy mean shift
    psi = drift.compute_psi(reference, current)
    assert psi > 1.0


def test_compute_psi_constant_feature_returns_zero():
    psi = drift.compute_psi(np.zeros(500), np.zeros(500))
    assert psi == 0.0


class _FakeDataset:
    def __init__(self, X: np.ndarray):
        self._X = X

    def fetch_all(self):
        return self._X, np.zeros(self._X.shape[0], dtype=np.int32)


def test_compute_drift_returns_feature_dict_for_synthetic_dataset():
    rng = np.random.RandomState(7)
    n_features = len(FEATURE_NAMES)
    baseline = rng.randn(120, n_features).astype(np.float32) * 0.1
    current = rng.randn(40, n_features).astype(np.float32) * 0.1
    current[:, 0] += 2.5  # induce drift on feature 0
    X = np.vstack([baseline, current])
    ds = _FakeDataset(X)

    result = drift.compute_drift(ds, days_baseline=3, days_current=1)
    assert set(result["features"].keys()) == set(FEATURE_NAMES)
    assert result["status"] in ("stable", "minor", "significant", "critical")
    # Feature 0 was deliberately shifted, so it should dominate max_psi.
    assert result["features"][FEATURE_NAMES[0]] > 0.1
    assert result["max_psi"] >= result["features"][FEATURE_NAMES[0]]


def test_compute_drift_insufficient_data():
    ds = _FakeDataset(np.zeros((10, len(FEATURE_NAMES)), dtype=np.float32))
    result = drift.compute_drift(ds)
    assert result["status"] == "insufficient_data"
    assert result["features"] == {}
    assert result["n_samples"] == 10


def test_compute_drift_with_real_dataset_smoke(tmp_path):
    """End-to-end smoke against the real SQLite-backed dataset."""
    db_path = os.path.join(tmp_path, "drift.db")
    ds = TrainingDataset(db_path)
    rng = np.random.RandomState(13)
    for i in range(60):
        feats = (rng.randn(len(FEATURE_NAMES)) * 0.05).tolist()
        ds.add_sample(feats, label=i % 2)
    result = drift.compute_drift(ds)
    assert "features" in result
    assert "status" in result
