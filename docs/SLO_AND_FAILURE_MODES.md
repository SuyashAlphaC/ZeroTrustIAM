# SLOs and Failure Modes

## Service level objectives (targets)

| Signal | Target (production) | Notes |
|--------|---------------------|--------|
| Login p99 latency (`POST /evaluate`) | ≤ 2.0 s | Includes bcrypt (~250 ms) + risk + Fabric |
| Login p95 without Fabric (test mode) | ≤ 800 ms | Local path |
| Availability of policy-engine | 99.9% monthly | Multi-replica + HPA |
| ML sidecar timeout | 800 ms default | Ensemble degrades to AHP+anomaly |
| Fabric authorize | fail-closed by default | Soft mode optional for low-risk reads only |
| Decision cache hit (ALLOW only) | best-effort | Never caches DENY / MFA |

## Failure modes

### Fabric unavailable

| `FABRIC_FAILURE_MODE` | Behavior |
|----------------------|----------|
| `fail_closed` (default) | `DENY` with reason "Authorization service unavailable" |
| `soft_deny_high_risk` | Low-risk **read** only may ALLOW without grant; write/delete/manage always DENY |

Never invent a grant when the ledger is down.

### ML unavailable / timeout

| `ML_FAILURE_MODE` | Behavior |
|-------------------|----------|
| `degrade` (default) | Ensemble uses AHP + anomaly only (`mlAvailable=false`) |
| `fail_closed` | Treat as elevated risk and require MFA or DENY (configure in ensemble if enabled) |

### Redis unavailable

- Decision cache disabled silently  
- Failed-attempt counters fall back to Postgres, then process-local Map  

### Postgres unavailable

- Health returns 503  
- Auth fails closed (no user lookup)  

## ZKP (experimental)

- **Opt-in** via `ZKP_ENABLED=true`  
- Marked `securityBoundary: false`  
- Must not be the sole authorization control  
- Prefer audited libraries before enabling in regulated deployments  

## Operational checks

```bash
# Health
curl -fsS https://policy-engine/health

# Synthetic login (staging)
curl -fsS -X POST https://policy-engine/v1/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"username":"canary","password":"...","deviceId":"canary-1","location":{"country":"US","city":"NYC"}}'
```

Wire Prometheus rules in `monitoring/rules/ztiam.yml` to page on elevated 5xx and Fabric fail-closed rates.
