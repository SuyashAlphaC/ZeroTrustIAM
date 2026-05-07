# ZeroTrustIAM — Kubernetes manifests

This directory contains the kustomize bundle that deploys the ZeroTrustIAM
control plane (web-app, policy-engine, ml-service) plus the data tier
(CloudNativePG cluster, PgBouncer) and the egress / pod-to-pod NetworkPolicy
mesh.

```
k8s/
├── kustomization.yaml          # base bundle entry point
├── base/                       # operator CRs and Deployments
└── overlays/production/        # plaintext-secret deletion + tighter egress
```

Apply (dev / single-node):

```bash
# 1. Operator prerequisite — install once per cluster.
kubectl apply -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.22/releases/cnpg-1.22.0.yaml

# 2. ZeroTrustIAM workloads.
kubectl apply -k k8s/
```

Apply (production):

```bash
kubectl apply -k k8s/overlays/production/
```

---

## Database HA

The Postgres tier is managed by the [CloudNativePG](https://cloudnative-pg.io/)
operator (`base/cnpg-cluster.yaml`).

| Resource                          | Purpose                                              |
| --------------------------------- | ---------------------------------------------------- |
| `Cluster/ztiam-pg`                | 1 primary + 2 hot-standby replicas, Postgres 16     |
| `Pooler/ztiam-pg-rw`              | PgBouncer writer pool (3 instances, transaction mode)|
| `Pooler/ztiam-pg-ro`              | PgBouncer reader pool (3 instances)                  |
| `ScheduledBackup/ztiam-pg-daily`  | Daily 02:00 UTC, 30-day retention                    |
| `CronJob/postgres-restore-weekly` | Sunday 03:00 — restores latest backup, smoke-tests   |

Streaming replication, automatic failover, and PITR are handled by the
operator. The application connects through the writer Pooler service
`ztiam-pg-rw:5432`; analytic / read-only queries should target
`ztiam-pg-ro:5432`. Both are wired into `policy-engine` via
`DATABASE_URL` / `DATABASE_READ_URL`.

### Bootstrap

The cluster bootstraps from `bootstrap.initdb` using the credentials in
`Secret/ztiam-pg-app` (username `ztiam`, database `ztiam`). Replace the
placeholder password before applying — production uses an `ExternalSecret`
sourcing it from Vault (`base/external-secret-vault.yaml`).

### Restoring from backup

```bash
# 1. List Backup CRs sorted by stop time.
kubectl -n ztiam get backup -l cnpg.io/cluster=ztiam-pg \
  --sort-by=.status.stoppedAt

# 2. Pick the backup you want to restore from (or use the latest).
LATEST="$(kubectl -n ztiam get backup -l cnpg.io/cluster=ztiam-pg \
  --sort-by=.status.stoppedAt \
  -o jsonpath='{.items[?(@.status.phase=="completed")].metadata.name}' \
  | tr ' ' '\n' | tail -n1)"

# 3. Restore into a sandbox cluster with `kubectl cnpg restore` (plugin).
kubectl cnpg restore \
  --backup-name "$LATEST" \
  --pvc-storage-class "" \
  ztiam-pg-restored

# Or, declaratively, apply a Cluster CR with bootstrap.recovery.backup.name.
```

For PITR (point-in-time recovery), use:

```bash
kubectl cnpg restore \
  --backup-name "$LATEST" \
  --target-time "2026-05-07 10:00:00" \
  ztiam-pg-pitr
```

The weekly `postgres-restore-weekly` CronJob runs the same flow against the
sandbox cluster `ztiam-pg-restore-test`; a failed Job indicates the backups
are unusable and should page on-call.

### PgBouncer transaction mode caveat

The Pooler runs `pool_mode = transaction`. Applications must not rely on
session-scoped Postgres state across HTTP requests:

- No server-side prepared statements that survive between requests.
- No `LISTEN` / `NOTIFY`.
- No advisory locks held outside a transaction.
- `SET LOCAL` is fine (transaction-scoped); `SET` (session) is not.

The Node.js `pg` driver does not use server-side prepared statements unless
you explicitly call `Client.query(new PreparedStatement(...))` — so the
default code path in `policy-engine` is safe. If you start using
`pg.PreparedStatement`, switch the writer Pooler back to `session` mode and
size the pool accordingly.

---

## NetworkPolicies

See [`NETWORK_POLICIES.md`](./NETWORK_POLICIES.md) for the full traffic
diagram, per-pod policy summary, and a CNI compatibility note. The base
bundle ships a default-deny-all baseline plus per-app allowlists; the
production overlay layers tighter egress restrictions on top.
