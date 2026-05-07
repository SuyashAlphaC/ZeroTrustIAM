"""FastAPI serving layer for the risk Random Forest model.

Responsibilities:
  * /predict                 -- score a login attempt
  * /ingest                  -- accept a labeled feature vector for future retrain
  * /train                   -- synchronously retrain on the live sample store
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
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, conint

import drift
import promoter
from dataset import TrainingDataset
from features import FEATURE_NAMES, FEATURE_VECTOR_VERSION, RiskRequest, extract_features
from model import RandomForestRiskModel
from retrainer import retrain


MODEL_DIR = os.environ.get("MODEL_DIR", "./models")
DATASET_PATH = os.environ.get(
    "ML_DATASET_PATH", os.path.join(MODEL_DIR, "training_samples.db")
)

RETRAIN_INTERVAL_MINUTES = int(os.environ.get("ML_RETRAIN_INTERVAL_MINUTES", "30"))
RETRAIN_MIN_NEW_SAMPLES = int(os.environ.get("ML_RETRAIN_MIN_NEW_SAMPLES", "50"))
RETRAIN_ON_STARTUP_IF_MISSING = (
    os.environ.get("ML_RETRAIN_ON_STARTUP_IF_MISSING", "false").lower() == "true"
)
SERVICE_TOKEN = os.environ.get("ML_SERVICE_TOKEN", "")


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

# Drift cache: (computed_at_epoch, payload). Re-used by /drift and /metrics.
_DRIFT_CACHE_TTL_SEC = 300
_drift_cache: Dict[str, Any] = {"ts": 0.0, "payload": None}


def _validation_split(X, y, fraction: float = 0.15):
    """Deterministic last-N% split used by /model/comparison."""
    n = int(X.shape[0])
    if n == 0:
        return X, y
    cut = max(int(n * (1.0 - fraction)), 0)
    return X[cut:], y[cut:]


def _get_drift_payload() -> Dict[str, Any]:
    """Return cached drift result; recompute if stale."""
    now = time.time()
    payload = _drift_cache.get("payload")
    if payload is not None and (now - _drift_cache.get("ts", 0.0)) < _DRIFT_CACHE_TTL_SEC:
        return payload
    payload = drift.compute_drift(_dataset)
    _drift_cache["ts"] = now
    _drift_cache["payload"] = payload
    return payload


def _require_service_token(x_ml_service_token: Optional[str]) -> None:
    """Require the shared service token for mutating or scoring POST endpoints."""
    if not SERVICE_TOKEN:
        return
    if x_ml_service_token != SERVICE_TOKEN:
        raise HTTPException(status_code=401, detail="unauthorized")


def _load_model() -> None:
    global _model, _load_error
    with _model_lock:
        try:
            model = RandomForestRiskModel.load(MODEL_DIR)
            invalid_sources = [
                source for source in (model.meta.training_sources or [])
                if str(source).startswith("synthetic")
            ]
            if invalid_sources:
                raise ValueError(
                    "model was trained with non-live sources and is no longer accepted: "
                    + ", ".join(invalid_sources)
                )
            _model = model
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

    # Cold-start: only build a model when enough real samples already exist.
    if _model is None and RETRAIN_ON_STARTUP_IF_MISSING:
        try:
            logger.info("no model found on disk; attempting live-data startup retrain")
            retrain(
                dataset=_dataset,
                model_dir=MODEL_DIR,
                reload_fn=_load_model,
            )
        except Exception as exc:
            logger.info("startup retrain skipped: %s", exc)

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
        _scheduler.shutdown(wait=True)


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
def model_reload(x_ml_service_token: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_service_token(x_ml_service_token)
    _load_model()
    return {"reloaded": _model is not None, "error": _load_error}


@app.post("/predict")
def predict(
    req: RiskRequest,
    x_ml_service_token: Optional[str] = Header(default=None),
) -> JSONResponse:
    _require_service_token(x_ml_service_token)
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
                "feature_vector_version": FEATURE_VECTOR_VERSION,
                "n_features": len(FEATURE_NAMES),
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
def ingest(
    req: IngestRequest,
    x_ml_service_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _require_service_token(x_ml_service_token)
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
    n_estimators: int = 200
    max_depth: int = 12


@app.post("/train")
def train(
    req: TrainRequest,
    x_ml_service_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _require_service_token(x_ml_service_token)
    global _last_retrain_sample_count
    try:
        t0 = time.time()
        result = retrain(
            dataset=_dataset,
            model_dir=MODEL_DIR,
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


@app.get("/model/comparison")
def model_comparison() -> Dict[str, Any]:
    """Score the current candidate against the champion on a held-out validation set."""
    candidate_dir = os.path.join(MODEL_DIR, promoter.CANDIDATE_DIRNAME)
    if not os.path.isdir(candidate_dir):
        raise HTTPException(status_code=404, detail="no candidate model present")
    X, y = _dataset.fetch_all()
    if X.shape[0] == 0:
        raise HTTPException(status_code=400, detail="no validation data available")
    X_val, y_val = _validation_split(X, y)
    if len(set(y_val.tolist())) < 2:
        raise HTTPException(
            status_code=400, detail="validation split has only one class"
        )
    try:
        return promoter.compare_models(MODEL_DIR, candidate_dir, X_val, y_val)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/model/promote")
def model_promote(
    x_ml_service_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _require_service_token(x_ml_service_token)
    promoted = promoter.promote_candidate(MODEL_DIR)
    if promoted:
        _load_model()
    return {"promoted": bool(promoted)}


@app.post("/model/rollback")
def model_rollback(
    x_ml_service_token: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    _require_service_token(x_ml_service_token)
    rolled_back = promoter.rollback(MODEL_DIR)
    if rolled_back:
        _load_model()
    return {"rolled_back": bool(rolled_back)}


@app.get("/drift")
def feature_drift() -> Dict[str, Any]:
    return _get_drift_payload()


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

    try:
        drift_payload = _get_drift_payload()
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("drift metric computation failed: %s", exc)
        drift_payload = {"features": {}}

    drift_features = drift_payload.get("features") or {}
    if drift_features:
        lines.append("# HELP ml_feature_drift_psi PSI per feature (recent vs baseline window)")
        lines.append("# TYPE ml_feature_drift_psi gauge")
        for name, psi in drift_features.items():
            safe = str(name).replace('"', '')
            lines.append(f'ml_feature_drift_psi{{feature="{safe}"}} {float(psi):.6f}')

    return "\n".join(lines) + "\n"
