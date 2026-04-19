"""FastAPI serving layer for the risk Random Forest model.

Responsibilities:
  * /predict                 -- score a login attempt
  * /ingest                  -- accept a labeled feature vector for future retrain
  * /train                   -- synchronously retrain on synthetic + live store
  * /model/reload            -- hot-swap the in-memory model from disk
  * /model/info, /dataset/stats, /health, /metrics -- observability

A background APScheduler thread opportunistically retrains the model when the
accumulated sample count crosses a threshold and a minimum interval has
passed since the last run, so the RF learns from production traffic without
any operator action.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, conint

from dataset import TrainingDataset
from features import FEATURE_NAMES, RiskRequest, extract_features
from model import RandomForestRiskModel
from retrainer import retrain


MODEL_DIR = os.environ.get("MODEL_DIR", "./models")
DATASET_PATH = os.environ.get(
    "ML_DATASET_PATH", os.path.join(MODEL_DIR, "training_samples.db")
)

RETRAIN_INTERVAL_MINUTES = int(os.environ.get("ML_RETRAIN_INTERVAL_MINUTES", "30"))
RETRAIN_MIN_NEW_SAMPLES = int(os.environ.get("ML_RETRAIN_MIN_NEW_SAMPLES", "50"))
RETRAIN_ON_STARTUP_IF_MISSING = (
    os.environ.get("ML_RETRAIN_ON_STARTUP_IF_MISSING", "true").lower() == "true"
)
RETRAIN_SYNTHETIC_SAMPLES = int(os.environ.get("ML_RETRAIN_SYNTHETIC_SAMPLES", "5000"))


logger = logging.getLogger("ml-service")
logging.basicConfig(level=os.environ.get("ML_LOG_LEVEL", "INFO"))

app = FastAPI(title="Zero Trust IAM — Risk Model", version="1.1.0")

_model: Optional[RandomForestRiskModel] = None
_load_error: Optional[str] = None
_model_lock = threading.Lock()
_dataset = TrainingDataset(DATASET_PATH)

# Observability counters
_metrics: Dict[str, int] = {
    "predict_total": 0,
    "predict_error_total": 0,
    "ingest_total": 0,
    "ingest_error_total": 0,
    "retrain_success_total": 0,
    "retrain_error_total": 0,
}

# Snapshot of sample count at the last successful retrain, used by the
# scheduler to decide whether enough fresh data has accumulated.
_last_retrain_sample_count: int = 0


def _load_model() -> None:
    global _model, _load_error
    with _model_lock:
        try:
            _model = RandomForestRiskModel.load(MODEL_DIR)
            _load_error = None
            logger.info(
                "model loaded: n_samples=%s trained_at=%s",
                _model.meta.n_samples,
                _model.meta.trained_at,
            )
        except Exception as exc:
            _model = None
            _load_error = str(exc)
            logger.warning("model load failed: %s", exc)


def _scheduled_retrain() -> None:
    """APScheduler job: retrain if enough new samples have arrived."""
    global _last_retrain_sample_count
    try:
        total = _dataset.count()
        new_since_last = total - _last_retrain_sample_count
        if new_since_last < RETRAIN_MIN_NEW_SAMPLES:
            logger.debug(
                "scheduler: skipping retrain (new=%d < threshold=%d)",
                new_since_last,
                RETRAIN_MIN_NEW_SAMPLES,
            )
            return
        logger.info(
            "scheduler: triggering retrain (new_samples=%d, total=%d)",
            new_since_last,
            total,
        )
        metrics = retrain(
            dataset=_dataset,
            model_dir=MODEL_DIR,
            n_synthetic=RETRAIN_SYNTHETIC_SAMPLES,
            reload_fn=_load_model,
        )
        _last_retrain_sample_count = total
        _metrics["retrain_success_total"] += 1
        logger.info(
            "scheduler: retrain done (accuracy=%.4f roc_auc=%.4f n=%d)",
            metrics["accuracy"],
            metrics["roc_auc"],
            metrics["n_samples"],
        )
    except Exception as exc:
        _metrics["retrain_error_total"] += 1
        logger.exception("scheduled retrain failed: %s", exc)


_scheduler = BackgroundScheduler(daemon=True)


@app.on_event("startup")
def _startup() -> None:
    global _last_retrain_sample_count
    _load_model()
    _last_retrain_sample_count = _dataset.count()

    # Cold-start: if no model is present on disk, bootstrap one from synthetic
    # data so /predict is immediately available. This matches how the thesis
    # describes the sidecar being "online from the first request".
    if _model is None and RETRAIN_ON_STARTUP_IF_MISSING:
        try:
            logger.info("no model found on disk; bootstrapping from synthetic data")
            retrain(
                dataset=_dataset,
                model_dir=MODEL_DIR,
                n_synthetic=RETRAIN_SYNTHETIC_SAMPLES,
                reload_fn=_load_model,
            )
        except Exception as exc:
            logger.error("bootstrap retrain failed: %s", exc)

    if RETRAIN_INTERVAL_MINUTES > 0:
        _scheduler.add_job(
            _scheduled_retrain,
            "interval",
            minutes=RETRAIN_INTERVAL_MINUTES,
            id="retrain",
            max_instances=1,
            coalesce=True,
        )
        _scheduler.start()
        logger.info(
            "scheduler started: interval=%dm, min_new_samples=%d",
            RETRAIN_INTERVAL_MINUTES,
            RETRAIN_MIN_NEW_SAMPLES,
        )


@app.on_event("shutdown")
def _shutdown() -> None:
    if _scheduler.running:
        _scheduler.shutdown(wait=False)


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "healthy" if _model is not None else "degraded",
        "model_loaded": _model is not None,
        "model_dir": MODEL_DIR,
        "load_error": _load_error,
        "scheduler_running": _scheduler.running,
    }


@app.get("/model/info")
def model_info() -> Dict[str, Any]:
    if _model is None:
        raise HTTPException(status_code=503, detail=f"Model not loaded: {_load_error}")
    return {
        "meta": _model.meta.__dict__,
        "feature_names": FEATURE_NAMES,
        "top_features": _model.top_features(8),
    }


@app.post("/model/reload")
def model_reload() -> Dict[str, Any]:
    _load_model()
    return {"reloaded": _model is not None, "error": _load_error}


@app.post("/predict")
def predict(req: RiskRequest) -> JSONResponse:
    if _model is None:
        _metrics["predict_error_total"] += 1
        raise HTTPException(status_code=503, detail=f"Model not loaded: {_load_error}")
    try:
        x = extract_features(req)
        proba = _model.predict_proba(x)
        explanation = _model.explain(x, top_k=5)
        _metrics["predict_total"] += 1
        return JSONResponse(
            {
                "risk_score": round(proba, 4),
                "model_version": _model.meta.model_version,
                "features": dict(zip(FEATURE_NAMES, [float(v) for v in x.tolist()])),
                "explanation": explanation,
            }
        )
    except Exception as exc:
        _metrics["predict_error_total"] += 1
        raise HTTPException(status_code=400, detail=f"Prediction failed: {exc}")


class IngestRequest(BaseModel):
    """One labeled sample for online learning.

    Either supply `features` directly (length == 17, matching FEATURE_NAMES)
    or pass a full `risk_request` and let the server extract features so the
    policy-engine doesn't have to duplicate the feature logic.
    """

    features: Optional[List[float]] = None
    risk_request: Optional[RiskRequest] = None
    label: conint(ge=0, le=1) = Field(..., description="0 = benign, 1 = attack")
    source: str = "live"
    username: Optional[str] = None
    decision: Optional[str] = None
    reason: Optional[str] = None


@app.post("/ingest")
def ingest(req: IngestRequest) -> Dict[str, Any]:
    try:
        if req.features is not None:
            feats = list(req.features)
        elif req.risk_request is not None:
            feats = [float(v) for v in extract_features(req.risk_request).tolist()]
        else:
            raise HTTPException(
                status_code=400, detail="either features or risk_request is required"
            )
        sample_id = _dataset.add_sample(
            features=feats,
            label=int(req.label),
            source=req.source,
            username=req.username,
            decision=req.decision,
            reason=req.reason,
        )
        _metrics["ingest_total"] += 1
        return {"ok": True, "sample_id": sample_id, "total": _dataset.count()}
    except HTTPException:
        _metrics["ingest_error_total"] += 1
        raise
    except Exception as exc:
        _metrics["ingest_error_total"] += 1
        raise HTTPException(status_code=400, detail=f"Ingest failed: {exc}")


class TrainRequest(BaseModel):
    n_synthetic: int = RETRAIN_SYNTHETIC_SAMPLES
    benign_fraction: float = 0.6
    n_estimators: int = 200
    max_depth: int = 12


@app.post("/train")
def train(req: TrainRequest) -> Dict[str, Any]:
    global _last_retrain_sample_count
    try:
        t0 = time.time()
        result = retrain(
            dataset=_dataset,
            model_dir=MODEL_DIR,
            n_synthetic=req.n_synthetic,
            benign_fraction=req.benign_fraction,
            n_estimators=req.n_estimators,
            max_depth=req.max_depth,
            reload_fn=_load_model,
        )
        _last_retrain_sample_count = _dataset.count()
        _metrics["retrain_success_total"] += 1
        result["duration_sec"] = round(time.time() - t0, 3)
        return result
    except Exception as exc:
        _metrics["retrain_error_total"] += 1
        raise HTTPException(status_code=500, detail=f"Retrain failed: {exc}")


@app.get("/dataset/stats")
def dataset_stats() -> Dict[str, Any]:
    stats = _dataset.stats()
    stats["retrain_threshold"] = RETRAIN_MIN_NEW_SAMPLES
    stats["retrain_interval_minutes"] = RETRAIN_INTERVAL_MINUTES
    stats["new_since_last_retrain"] = max(
        stats["total"] - _last_retrain_sample_count, 0
    )
    return stats


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    """Prometheus text-format exposition."""
    stats = _dataset.stats()
    lines = [
        "# HELP ml_predict_total Total prediction requests served",
        "# TYPE ml_predict_total counter",
        f"ml_predict_total {_metrics['predict_total']}",
        "# HELP ml_predict_error_total Prediction failures",
        "# TYPE ml_predict_error_total counter",
        f"ml_predict_error_total {_metrics['predict_error_total']}",
        "# HELP ml_ingest_total Samples ingested for training",
        "# TYPE ml_ingest_total counter",
        f"ml_ingest_total {_metrics['ingest_total']}",
        "# HELP ml_ingest_error_total Ingest failures",
        "# TYPE ml_ingest_error_total counter",
        f"ml_ingest_error_total {_metrics['ingest_error_total']}",
        "# HELP ml_retrain_success_total Successful retraining runs",
        "# TYPE ml_retrain_success_total counter",
        f"ml_retrain_success_total {_metrics['retrain_success_total']}",
        "# HELP ml_retrain_error_total Failed retraining runs",
        "# TYPE ml_retrain_error_total counter",
        f"ml_retrain_error_total {_metrics['retrain_error_total']}",
        "# HELP ml_training_samples_total Training samples in live dataset",
        "# TYPE ml_training_samples_total gauge",
        f"ml_training_samples_total {stats['total']}",
        f'ml_training_samples_total{{label="benign"}} {stats["benign"]}',
        f'ml_training_samples_total{{label="attack"}} {stats["attack"]}',
        "# HELP ml_model_loaded 1 if the RF model is in memory",
        "# TYPE ml_model_loaded gauge",
        f"ml_model_loaded {1 if _model is not None else 0}",
    ]
    return "\n".join(lines) + "\n"
