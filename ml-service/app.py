"""FastAPI serving layer for the risk Random Forest model."""

from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from features import FEATURE_NAMES, RiskRequest, extract_features
from model import RandomForestRiskModel


MODEL_DIR = os.environ.get("MODEL_DIR", "./models")

app = FastAPI(title="Zero Trust IAM — Risk Model", version="1.0.0")

_model: RandomForestRiskModel | None = None
_load_error: str | None = None


def _load_model() -> None:
    global _model, _load_error
    try:
        _model = RandomForestRiskModel.load(MODEL_DIR)
        _load_error = None
    except Exception as exc:
        _model = None
        _load_error = str(exc)


@app.on_event("startup")
def _startup() -> None:
    _load_model()


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "healthy" if _model is not None else "degraded",
        "model_loaded": _model is not None,
        "model_dir": MODEL_DIR,
        "load_error": _load_error,
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
        raise HTTPException(status_code=503, detail=f"Model not loaded: {_load_error}")
    try:
        x = extract_features(req)
        proba = _model.predict_proba(x)
        explanation = _model.explain(x, top_k=5)
        return JSONResponse(
            {
                "risk_score": round(proba, 4),
                "model_version": _model.meta.model_version,
                "features": dict(zip(FEATURE_NAMES, [float(v) for v in x.tolist()])),
                "explanation": explanation,
            }
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Prediction failed: {exc}")
