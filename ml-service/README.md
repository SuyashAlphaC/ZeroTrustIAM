# ml-service — Random Forest risk scoring sidecar

Python FastAPI service that serves the data-driven half of the Zero Trust IAM
risk ensemble. The Node.js policy engine calls `POST /predict` with a
`RiskRequest`; the service returns a calibrated risk probability plus a
per-prediction feature contribution explanation. If this sidecar is down, the
policy engine falls back to AHP + anomaly weights only — see
`policy-engine/riskScorerEnsemble.js`.

## Features

The model consumes a fixed 17-feature vector. The ordering in
`features.py::FEATURE_NAMES` is load-bearing and must not change without a
retrain.

## Quick start

```bash
cd ml-service
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Train from the live SQLite sample store and optionally merge a public RBA CSV
python train.py --dataset ./models/training_samples.db --public /path/to/rba-dataset.csv --model-dir ./models

# Serve
MODEL_DIR=./models uvicorn app:app --host 0.0.0.0 --port 5000
```

## API

| Method | Path           | Purpose                                |
|--------|----------------|----------------------------------------|
| GET    | `/health`      | Liveness + model-loaded flag           |
| GET    | `/model/info`  | Metadata, feature names, top features  |
| POST   | `/model/reload`| Reload the saved model from disk       |
| POST   | `/predict`     | Score a `RiskRequest`                  |

A `RiskRequest` is the JSON shape defined by the Pydantic models in
`features.py` — the Node client in `policy-engine/mlRiskScorer.js` builds it
from the existing user profile + request context.

## Training strategies

1. **Live** — `dataset.py` stores observed labeled samples ingested from the
   policy engine after real authorization decisions.
2. **Public** — `public_loader.py` reads the IEEE DataPort RBA dataset CSV and
   projects each row into the same 17-feature vector used by the live model.

Training can use the live dataset alone or combine it with the public RBA
dataset when you want additional real-world coverage.

## Integration contract

The Node client sends snake_case fields (`user_profile`, `request_context`,
`registered_devices`, …). The policy-engine config variable `ML_SERVICE_URL`
controls the base URL (default `http://localhost:5000`), and
`ML_SERVICE_TIMEOUT_MS` controls the fallback timeout.
