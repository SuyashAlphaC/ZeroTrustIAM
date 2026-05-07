# Offline tests for RandomForestRiskModel training, explain, save/load, importance order.

from __future__ import annotations

import json
import os
import tempfile

import numpy as np

from features import FEATURE_NAMES
from model import RandomForestRiskModel


def _xor_noisy(n=400, seed=123):
    rng = np.random.RandomState(seed)
    X = rng.randn(n, len(FEATURE_NAMES)).astype(np.float32) * 0.15
    xor = (X[:, 0] > 0) ^ (X[:, 1] > 0)
    y = xor.astype(np.int32)
    flip = rng.rand(n) < 0.08
    y[flip] = 1 - y[flip]
    return X, y


def test_train_accuracy_xor_noise():
    model = RandomForestRiskModel(n_estimators=80, max_depth=10, random_state=0)
    X, y = _xor_noisy()
    metrics = model.train(X, y)
    assert metrics["accuracy"] >= 0.7


def test_predict_proba_in_unit_interval():
    model = RandomForestRiskModel(n_estimators=30, max_depth=6, random_state=1)
    X, y = _xor_noisy(120, 77)
    model.train(X, y)
    for i in range(5):
        p = model.predict_proba(X[i])
        assert 0.0 <= p <= 1.0


def test_save_load_roundtrip_predictions():
    model = RandomForestRiskModel(n_estimators=40, max_depth=8, random_state=3)
    X, y = _xor_noisy(200, 9)
    model.train(X, y)
    pred_before = model.predict_proba(X[0])

    with tempfile.TemporaryDirectory() as td:
        model.save(td)
        restored = RandomForestRiskModel.load(td)
        assert restored.predict_proba(X[0]) == pred_before
        meta_path = os.path.join(td, "rf_meta.json")
        with open(meta_path) as f:
            meta = json.load(f)
        assert meta["model_version"]


def test_top_features_descending():
    model = RandomForestRiskModel(n_estimators=60, max_depth=10, random_state=4)
    X, y = _xor_noisy(300, 11)
    model.train(X, y)
    feats = model.top_features(5)
    imps = [f[1] for f in feats]
    assert imps == sorted(imps, reverse=True)


def test_explain_top_k_ordering():
    model = RandomForestRiskModel(n_estimators=50, max_depth=8, random_state=6)
    X, y = _xor_noisy(250, 13)
    model.train(X, y)
    rows = model.explain(X[0], top_k=5)
    keys = [abs(r["contribution"]) for r in rows]
    assert keys == sorted(keys, reverse=True)
    assert len(rows) == 5
