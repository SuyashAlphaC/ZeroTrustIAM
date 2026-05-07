# Operations runbook: bootstrap, backups, rollbacks, rotations, and incidents.

## 1. Bootstrapping a new environment

Recommended order: **provision secrets** → **Postgres** (PVC + password) → **`npm run migrate -- up`** on policy-engine → **Fabric network** (`setup-network.sh`, `deploy-chaincode.sh`, `InitLedger`) → **ml-service** (model PVC / cold start) → **policy-engine** deployment → **web-app** → **ingress / TLS / monitoring**.

Apply Kubernetes with `kubectl apply -k k8s/` for dev; production must use `k8s/overlays/production/` so plaintext placeholder secrets are stripped and replaced by SealedSecrets or External Secrets.

## 2. Postgres backup and restore

- **Scheduled backup:** `k8s/base/postgres-backup-cronjob.yaml` runs `pg_dump` daily into PVC `postgres-backups` (5 Gi). Ensure the job’s `PGPASSWORD` Secret key matches the database password.
- **Manual dump:** `kubectl exec` into the Postgres pod and run:

  `pg_dump -U ztiam -h localhost ztiam | gzip -c > /backups/ztiam-$(date -u +%Y%m%d).sql.gz`

  (mount or copy the archive off-cluster).

- **Restore:** stop writers, create an empty database or drop schema, then:

  `gunzip -c backup.sql.gz | psql -U ztiam -h <host> ztiam`

Verify row counts and run policy-engine health checks before resuming traffic.

## 3. Migration rollback

Use when a bad migration ships or a deploy must be backed out before app code matches schema.

- **Status:** `cd policy-engine && npm run migrate -- status`
- **Rollback:** `npm run migrate -- down 0` rolls back all migrations tracked in `schema_migrations` (drops application tables per `down` SQL). Re-apply with **`npm run migrate -- up`** after fixing code (same as `node scripts/migrate.js …`).
- **Verification:** confirm expected tables via `information_schema.tables` and that `schema_migrations` rows match the desired release.

Details align with `DATABASE_URL` / `TEST_DATABASE_URL` in CI. See also **SECURITY.md** (Kubernetes secrets).

## 4. Rotating JWT signing keys

JWT material is managed in **`signing_keys`** (see `database.js` rotation helpers). Rotate on compromise, annual policy, or org key-management requirements: insert a new active key for the relevant `key_type`, deactivate the previous row, and redeploy services that cache public keys. Prefer short overlap where both keys validate during a cutover window.

## 5. ML model rollback

1. Identify a known-good `rf_model.joblib` + `rf_meta.json` snapshot on the model PVC (or object storage).
2. Copy files into the serving **`MODEL_DIR`** (replace current artifacts).
3. Call **`POST /model/reload`** on ml-service with header **`X-ML-Service-Token`**, or restart pods to pick up disk.

Monitor `/health` and `/dataset/stats` after rollback.

## 6. Fabric peer recovery (replace / re-join)

1. Provision new peer crypto with the org’s CA (or reuse backed-up MSP TLS + signing material).
2. Start the peer container with correct `CORE_PEER_*` and channel artifacts.
3. **Join channel:** supply the channel genesis or latest config block (`peer channel join`).
4. **Install + approve** chaincode if the peer must endorse; ensure **anchor peers** and gossip policy allow discovery.

Document the new peer endpoint in gateway / connection profiles used by policy-engine.

## 7. Incident severity matrix (Prometheus-aligned)

| Severity | Meaning | Examples | Response |
|----------|---------|----------|----------|
| **SEV1** | Service down or data loss risk | Postgres unavailable, all policy-engine replicas failing, chaincode unavailable for all auth | Page on-call immediately; invoke incident commander; freeze deploys. |
| **SEV2** | Major degradation | Elevated 5xx on `/evaluate`, single AZ loss with redundancy, partial Fabric outage | Page on-call; scale / fail over; communicate status. |
| **SEV3** | Minor / contained | Single pod restarts, elevated latency under SLO, Grafana yellow | Ticket + next-business-day fix unless trend worsens. |

Map concrete alert names from **`monitoring/rules/ztiam.yml`** into this table in your org’s runbook fork.

## 8. On-call and paging

Wire **PagerDuty / Opsgenie / Slack** webhooks to alertmanager (or your Prometheus notification path). This repository leaves a **placeholder** routing name `ztiam-critical` — replace with your escalation policy and roster.

---

*Update this file whenever backup windows, migration IDs, or escalation policies change.*
