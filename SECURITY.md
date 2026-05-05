# ZeroTrustIAM — Security

This document summarizes how the main components handle **secrets**, **transport security**, **supply chain**, and **operational hygiene**. It is not a formal audit report.

## Responsible disclosure

Report suspected vulnerabilities to the repository maintainers (use private channels; do not open public issues for exploitable bugs until coordinated disclosure is complete).

## Threat model reference

See [`THREAT_MODEL.md`](./THREAT_MODEL.md) for design-level threats and mitigations.

## Secrets and key material

| Area | Practice |
|------|----------|
| **Policy Engine** | Production requires `DATABASE_URL`, JWT/OAuth secrets, `APP_ENCRYPTION_KEY`, and TLS/mTLS PEM paths. Never commit real secrets. |
| **Vault (optional)** | `policy-engine/vault.js` supports `VAULT_BOOTSTRAP_SYNC=true` with `VAULT_ADDR`, `VAULT_TOKEN`, and `VAULT_SECRET_PATH` (KV v2) to hydrate `process.env` before the app loads. For production, prefer Vault Agent or an init container writing only the needed keys. |
| **Local JSON** | `SECRETS_JSON_PATH` / `VAULT_LOCAL_SECRET_FILE` merges a JSON map into the environment (development / CI only). |
| **PostgreSQL** | Use strong `POSTGRES_PASSWORD` and network policies; do not expose Postgres to the public internet. |
| **ML sidecar** | `ML_SERVICE_TOKEN` must be shared only between policy-engine and ml-service. |
| **Web → Policy** | Compose / production paths use **HTTPS + mutual TLS** between `web-app` and `policy-engine` with a dedicated client certificate. Browsers still hit OAuth/authorize without a client certificate; service-to-service routes require a client cert. |
| **Fabric** | MSP material is highly sensitive; restrict filesystem and image access. |

Dev-only material under `certs/internal/` is labeled in `certs/internal/DEV_ONLY.txt` — rotate for any real deployment.

## Transport and API surface

- **Policy Engine** exposes **`/`** and **`/v1`** with the same route set (`express.Router()` mounted twice). Prefer **`/v1`** for new integrations.
- **mTLS exemptions** include `/health`, OIDC discovery/JWKS, and `/oauth/authorize` (browser), so users are not prompted for browser client certs.
- **Web app**: Helmet headers, cookie-based CSRF (`GET /api/csrf-token`, `X-CSRF-Token` on mutating `/api/*` calls), rate limiting, and `trust proxy` in production behind a reverse proxy.

## Dependency and CI hygiene

CI runs **`npm ci` + tests** for the policy-engine, **`pytest`** for ml-service syntax/unit checks, **`node --check`** on chaincode modules, **`npm audit`** (high severity gates are enabled where practical), ESLint where configured, and **Docker image builds**.

## Observability stack (compose profile `obs`)

Optional services: Jaeger (OTLP on `4318`), Prometheus (**`monitoring/prometheus.yml`** + rules under **`monitoring/rules/`**), Grafana provisioning under **`monitoring/grafana/`**.

Set `OTEL_EXPORTER_OTLP_ENDPOINT` on the policy-engine when tracing should export (e.g. `http://jaeger:4318/v1/traces` when OTLP collector path differs adjust in `tracing.js`).

Prometheus scrapes policy-engine **`/metrics` over HTTPS** with `insecure_skip_verify` in the sample config — tighten with proper scrape TLS in real environments.

## Kubernetes

Manifests live under **`k8s/`** (`kubectl apply -k k8s/`). Replace **`k8s/base/secrets-placeholder.yaml`** with externally managed Secrets (SealedSecrets, External Secrets Operator, Vault CSI, etc.) before production.

## ML training data

The ml-service enforces:

- Feature vector sanitization/clipping at inference (`features.clip_feature_vector`).
- Optional **L2 norm cap** on ingest (`ML_MAX_FEATURE_L2`) to reduce obvious poisoning attempts.

These do not eliminate adaptive adversaries — monitor dataset stats and retrains (`/dataset/stats`).

---

*Keep this file updated when security-relevant defaults or integrations change.*
