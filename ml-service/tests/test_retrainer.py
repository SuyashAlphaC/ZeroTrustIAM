# Retrainer error paths and successful disk write (reload_fn hook; no network).

from __future__ import annotations

import importlib
import os
import tempfile

import pytest

from dataset import TrainingDataset


def test_retrain_min_samples(tmp_path, monkeypatch):
    monkeypatch.setenv("MIN_SAMPLES_FOR_TRAIN", "100")
    rmod = importlib.reload(importlib.import_module("retrainer"))

    td = tempfile.mkdtemp(dir=str(tmp_path))
    ds = TrainingDataset(os.path.join(td, "d.sqlite"))
    for i in range(5):
        feats = [0.01 + 0.001 * ((i + j) % 3) for j in range(17)]
        ds.add_sample(feats, i % 2)

    model_dir = str(tmp_path / "models")
    with pytest.raises(RuntimeError) as ei:
        rmod.retrain(ds, model_dir=model_dir)
    assert "samples" in str(ei.value).lower()


def test_retrain_single_class_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("MIN_SAMPLES_FOR_TRAIN", "5")
    rmod = importlib.reload(importlib.import_module("retrainer"))

    td = tempfile.mkdtemp(dir=str(tmp_path))
    ds = TrainingDataset(os.path.join(td, "d.sqlite"))
    for i in range(40):
        feats = [0.01 + 0.001 * ((i + j) % 4) for j in range(17)]
        ds.add_sample(feats, 0)

    model_dir = str(tmp_path / "models2")
    with pytest.raises(RuntimeError) as ei:
        rmod.retrain(ds, model_dir=model_dir)
    assert "one class" in str(ei.value).lower()


def test_retrain_success(tmp_path, monkeypatch):
    monkeypatch.setenv("MIN_SAMPLES_FOR_TRAIN", "10")
    monkeypatch.setenv("ML_RETRAIN_INTERVAL_MINUTES", "0")
    rmod = importlib.reload(importlib.import_module("retrainer"))

    td = tempfile.mkdtemp(dir=str(tmp_path))
    ds = TrainingDataset(os.path.join(td, "d.sqlite"))
    for i in range(36):
        feats = [0.01 + 0.002 * (((i ^ 5) + j * 11) % 6) / 17 for j in range(17)]
        label = (((i >> 3) ^ (i >> 7)) ^ (i & 3)) % 2
        ds.add_sample(feats, label)

    model_dir = str(tmp_path / "trained")
    out = []

    metrics = rmod.retrain(ds, model_dir=model_dir, n_estimators=50, max_depth=8, reload_fn=lambda: out.append(1))

    assert metrics["accuracy"] >= 0.0
    assert metrics["roc_auc"] >= 0.0
    assert metrics["n_samples"] == 36
    # Tier B.7: retrainer writes to MODEL_DIR/candidate, not the champion root.
    candidate_dir = os.path.join(model_dir, "candidate")
    assert metrics["candidate_dir"] == candidate_dir
    assert os.path.isfile(os.path.join(candidate_dir, "rf_model.joblib"))
    assert not os.path.isfile(os.path.join(model_dir, "rf_model.joblib"))
    # reload_fn must NOT be invoked for candidate writes.
    assert out == []
