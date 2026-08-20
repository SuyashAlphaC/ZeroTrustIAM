# ZeroTrustIAM — Security

This document summarizes how the main components handle **secrets**, **transport security**, **supply chain**, and **operational hygiene**. It is not a formal audit report.

## Responsible disclosure

Report suspected vulnerabilities to the repository maintainers (use private channels; do not open public issues for exploitable bugs until coordinated disclosure is complete).

## Production hardening (implemented)

| Control | Status |
|---------|--------|
| Self-service `/v1/me/*` (devices, sessions, export, erasure, password change) | Implemented |
| Redis/Postgres shared failed-attempt counters + account lockout | Implemented |
| Credential anti-enumeration (uniform error + dummy bcrypt) | Implemented |
| Auth on MFA status, anomaly, audit-log, DID list | Implemented |
| Password policy + optional Argon2id/scrypt hasher | Implemented |
| Password reset flow (`/password-reset/*`) | Implemented |
| SCIM 2.0 user provisioning (`/scim/v2`) | Implemented (subset) |
| ABAC policy engine + admin CRUD | Implemented |
| ZKP opt-in only; not a security boundary | Implemented |
| Fabric fail-closed / soft failure modes | Implemented |
| Non-root multi-stage Docker images + k8s securityContext | Implemented |
| CI Trivy CRITICAL image scan on PRs | Implemented |

See also `docs/SLO_AND_FAILURE_MODES.md`.

## Enterprise features (phase 2)

| Feature | Location |
|---------|----------|
| OIDC federation (Google / Entra / Okta) | `policy-engine/federation.js`, `/v1/federation/*` |
| SAML 2.0 SP | `policy-engine/saml.js`, `/v1/federation/saml/*` |
| Multi-tenancy + plans + CMK fields | `policy-engine/tenancy.js`, migration `008` |
| External PDP (OPA / Cedar) | `policy-engine/externalPdp.js`, `policies/opa`, `policies/cedar` |
| PEP SDK | `packages/pep-sdk` |
| Gateway plugins | `packages/gateway-plugins` |
| AWS KMS JWT signing | `kmsSigner.js` `AwsKmsSigner`, `KMS_BACKEND=aws` |
| Admin SPA | `admin-console/` (Vite React) → `web-app/public/admin-console` |
| Fabric CA multi-org ops | `fabric-network/scripts/ca-ops/`, `docs/FABRIC_CA_RUNBOOK.md` |
| ZKP production policy | `docs/ZKP.md` (disabled by default) |
| Stripe billing + admin UI | `billing.js`, `/admin-console/billing`, `docs/BILLING.md` |
| Exclusive C14N SAML | `samlExclusiveC14n.js`, `samlXmlDSig.js`, `saml.js` |
| Amazon Verified Permissions | `amazonVerifiedPermissions.js`, `PDP_BACKEND=avp`, `docs/AVP.md` |
| Live Fabric CA CI | `.github/workflows/fabric-ca-ci.yaml`, `docker-compose.fabric-ca-ci.yaml` |

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

Manifests live under **`k8s/`** (`kubectl apply -k k8s/`). **Do not** apply `secrets-placeholder.yaml` as-is in production — it contains development placeholders. Use `kubectl apply -k k8s/overlays/production/` with either a **SealedSecret** (via `scripts/seal-secrets.sh` + `secrets-sealed.example.yaml`) or **ExternalSecret** (`external-secret-vault.yaml`) wired to your secret store.

## Resilience testing

- **Fabric Raft / orderer failure:** In a full local network, run **`fabric-network/scripts/chaos-orderer-kill.sh`** weekly in staging. It stops primary orderer `orderer.example.com`, waits for leadership to shift, exercises a policy-engine transaction via **`submit-test-tx.sh`**, then restores the node and re-validates. Keeps the three-orderer Raft path from bit-rotting.
- **Kubernetes / app layer:** Use the optional GitHub workflow **`.github/workflows/load-test.yaml`** (manual `workflow_dispatch`) with **`k6`** against a compose or preview stack to validate HPA targets and golden-signal latency under burst login load.

---

The ml-service enforces:

- Feature vector sanitization/clipping at inference (`features.clip_feature_vector`).
- Optional **L2 norm cap** on ingest (`ML_MAX_FEATURE_L2`) to reduce obvious poisoning attempts.

These do not eliminate adaptive adversaries — monitor dataset stats and retrains (`/dataset/stats`).

---

*Keep this file updated when security-relevant defaults or integrations change.*
