# FastAPI TestClient checks for health, auth, ingest shapes, predict, metrics (no outbound calls).

from __future__ import annotations

import importlib
import os
import tempfile

import numpy as np
import pytest
from fastapi.testclient import TestClient

from features import UserProfileModel, RequestContextModel, RiskRequest
from model import RandomForestRiskModel


def _risk_body():
    return RiskRequest(
        username="alice",
        user_profile=UserProfileModel(registered_devices=["d1"], profile_samples=5),
        request_context=RequestContextModel(
            device_id="d1",
            timestamp="2026-05-01T12:00:00Z",
            ip="10.0.0.2",
            failed_attempts=0,
        ),
    ).model_dump()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ML_SERVICE_TOKEN", "test-token")
    monkeypatch.setenv("ML_DATASET_PATH", str(tmp_path / "live.db"))
    monkeypatch.setenv("MODEL_DIR", str(tmp_path / "models"))
    monkeypatch.setenv("ML_RETRAIN_INTERVAL_MINUTES", "0")
    os.makedirs(tmp_path / "models", exist_ok=True)
    mod = importlib.reload(importlib.import_module("app"))
    with TestClient(mod.app) as c:
        yield c


@pytest.fixture()
def reload_app(monkeypatch, tmp_path):
    def _reload():
        monkeypatch.setenv("ML_SERVICE_TOKEN", "test-token")
        monkeypatch.setenv("ML_DATASET_PATH", str(tmp_path / "live.db"))
        monkeypatch.setenv("MODEL_DIR", str(tmp_path / "models"))
        monkeypatch.setenv("ML_RETRAIN_INTERVAL_MINUTES", "0")
        os.makedirs(tmp_path / "models", exist_ok=True)
        return importlib.reload(importlib.import_module("app"))

    return _reload


def test_health_degraded_without_model(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "degraded"


def test_predict_401_without_header(client):
    r = client.post("/predict", json=_risk_body())
    assert r.status_code == 401


def test_predict_503_without_model_with_token(client):
    r = client.post("/predict", json=_risk_body(), headers={"X-ML-Service-Token": "test-token"})
    assert r.status_code == 503


def test_ingest_features_array(client):
    feats = [0.01 * (i + 1) for i in range(17)]
    r = client.post(
        "/ingest",
        json={"features": feats, "label": 0},
        headers={"X-ML-Service-Token": "test-token"},
    )
    assert r.status_code == 200
    assert r.json()["sample_id"] >= 1


def test_ingest_risk_request_nested(client):
    r = client.post(
        "/ingest",
        json={"risk_request": _risk_body(), "label": 1},
        headers={"X-ML-Service-Token": "test-token"},
    )
    assert r.status_code == 200


def test_ingest_rejects_bad_label(client):
    r = client.post(
        "/ingest",
        json={"features": [0.01] * 17, "label": 9},
        headers={"X-ML-Service-Token": "test-token"},
    )
    assert r.status_code == 422


def test_dataset_stats_zero_initial(client):
    r = client.get("/dataset/stats")
    body = r.json()
    assert body["total"] == 0


def test_metrics_counters(client):
    text = client.get("/metrics").text
    for key in (
        "ml_predict_total",
        "ml_predict_error_total",
        "ml_ingest_total",
        "ml_ingest_error_total",
        "ml_retrain_success_total",
        "ml_retrain_error_total",
        "ml_training_samples_total",
        "ml_model_loaded",
    ):
        assert key in text


def test_model_reload_requires_token(reload_app, tmp_path):
    am = reload_app()
    r = am.app
    with TestClient(r) as c:
        assert c.post("/model/reload").status_code == 401
        ok = c.post("/model/reload", headers={"X-ML-Service-Token": "test-token"})
        assert ok.status_code == 200


def test_predict_returns_score_in_range(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("ML_SERVICE_TOKEN", "test-token")
    monkeypatch.setenv("ML_DATASET_PATH", str(tmp_path / "live.db"))
    monkeypatch.setenv("MODEL_DIR", str(tmp_path / "models"))
    monkeypatch.setenv("ML_RETRAIN_INTERVAL_MINUTES", "0")
    os.makedirs(tmp_path / "models", exist_ok=True)

    X = np.random.RandomState(1).rand(60, 17).astype(np.float32) * 0.2
    y = ((X[:, 0] > 0.1) ^ (X[:, 1] > 0.1)).astype(np.int32)
    m = RandomForestRiskModel(n_estimators=40, max_depth=6, random_state=9)
    m.train(X, y)
    m.save(str(tmp_path / "models"))

    am = importlib.reload(importlib.import_module("app"))
    with TestClient(am.app) as c:
        assert c.get("/health").json()["status"] == "healthy"
        pr = c.post(
            "/predict",
            json=_risk_body(),
            headers={"X-ML-Service-Token": "test-token"},
        )
        assert pr.status_code == 200
        score = pr.json()["risk_score"]
        assert 0.0 <= score <= 1.0


def test_train_endpoint_errors_gracefully_with_few_samples(reload_app, tmp_path):
    am = reload_app()
    with TestClient(am.app) as c:
        r = c.post("/train", json={}, headers={"X-ML-Service-Token": "test-token"})
        assert r.status_code in (500, 400)


def test_model_info_requires_trained_model(reload_app, tmp_path, monkeypatch):
    am = reload_app()
    with TestClient(am.app) as c:
        r = c.get("/model/info")
        assert r.status_code == 503


def test_model_comparison_404_when_no_candidate(client):
    r = client.get("/model/comparison")
    assert r.status_code == 404


def test_model_promote_no_op_returns_false(client):
    r = client.post("/model/promote", headers={"X-ML-Service-Token": "test-token"})
    assert r.status_code == 200
    assert r.json() == {"promoted": False}


def test_model_rollback_no_op_returns_false(client):
    r = client.post("/model/rollback", headers={"X-ML-Service-Token": "test-token"})
    assert r.status_code == 200
    assert r.json() == {"rolled_back": False}


def test_drift_insufficient_data(client):
    r = client.get("/drift")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "insufficient_data"
    assert body["features"] == {}
