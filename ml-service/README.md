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

# Train on synthetic data only (fastest path — no external downloads)
python train.py --n-synthetic 10000 --model-dir ./models

# Or include the RBA public dataset if you have it
python train.py --n-synthetic 10000 --public /path/to/rba-dataset.csv --model-dir ./models

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

1. **Synthetic** — `synthetic_generator.py` samples a configurable mix of
   benign plus five attack profiles (stolen_credentials, impossible_travel,
   credential_stuffing, off_hours_privilege, insider_threat). Always available,
   no external data.
2. **Public** — `public_loader.py` reads the IEEE DataPort RBA dataset CSV and
   projects each row into the same 17-feature vector. Silently returns empty
   if the path does not exist, so the synthetic path still works.

Both sources are concatenated before training — the model sees one uniform
dataset.

## Integration contract

The Node client sends snake_case fields (`user_profile`, `request_context`,
`registered_devices`, …). The policy-engine config variable `ML_SERVICE_URL`
controls the base URL (default `http://localhost:5000`), and
`ML_SERVICE_TIMEOUT_MS` controls the fallback timeout.
