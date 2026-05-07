# NetworkPolicies — ZeroTrustIAM

`base/networkpolicies.yaml` declares a default-deny-all baseline plus per-app
allowlists. The production overlay
(`overlays/production/network-egress-restrictions.yaml`) layers a curated
external-egress allowlist on top.

## CNI requirement

NetworkPolicy resources are inert on a CNI plugin that does not implement
them. The default `kubenet` does *not*. Use one of:

- [Calico](https://www.tigera.io/project-calico/) — recommended; works on
  every distribution.
- [Cilium](https://cilium.io/) — required if you want the FQDN-egress variant
  in `network-egress-restrictions.yaml`.
- [Weave Net](https://www.weave.works/oss/net/).

Verify before applying:

```bash
kubectl get pods -n kube-system | grep -E 'calico|cilium|weave'
```

If none are present, `kubectl apply -k k8s/` will silently leave the policies
unenforced.

## Allowed traffic graph

```
                     ┌─────────────────┐
   internet ─────►   │    Ingress      │
                     │  (nginx, 443)   │
                     └────┬─────────────┘
                          │ TCP 3000
                          ▼
                     ┌──────────────┐
                     │   web-app    │
                     └──┬───────────┘
                        │ TCP 4000
                        ▼
   prometheus  ─────►┌──────────────────┐──────► ml-service:5000
   (metrics)         │  policy-engine   │──────► vault:8200
                     │  (3 replicas)    │──────► redis:6379
                     └──────┬───────────┘──────► fabric peers:7051 (ns: fabric_iam)
                            │ 5432              ──────► jaeger/otel:4318
                            ▼
                     ┌──────────────────┐
                     │    PgBouncer     │   (Pooler/ztiam-pg-rw, ztiam-pg-ro)
                     │   transaction    │
                     │     pool_mode    │
                     └──────┬───────────┘
                            │ 5432
                            ▼
                     ┌──────────────────┐
                     │  ztiam-pg        │   (cnpg primary + 2 replicas)
                     │  (CloudNativePG) │
                     └──────────────────┘
```

Implicit:

- All pods may resolve DNS (`allow-dns-egress` → kube-system:53).
- `default-deny-all` blocks everything else.
- Production: outbound internet is restricted to the CIDRs in
  `prod-egress-internet-allowlist`; metadata service ranges are blocked by
  `prod-egress-block-metadata`.

## Per-pod policy summary

| Pod label                                  | Ingress allowed from                       | Egress allowed to                                  |
| ------------------------------------------ | ------------------------------------------ | -------------------------------------------------- |
| `app=web-app`                              | anywhere :3000                             | `app=policy-engine` :4000                          |
| `app=policy-engine`                        | `app=web-app` :4000, prometheus :4000      | pgbouncer :5432, ml-service :5000, vault :8200, redis :6379, fabric_iam ns :7051, otel :4318 |
| `app=ml-service`                           | `app=policy-engine` :5000, prometheus :5000| (DNS only — no other egress)                       |
| `app=redis`                                | `app=policy-engine` :6379                  | (DNS only)                                         |
| `cnpg.io/poolerName in {ztiam-pg-rw,ro}`   | `app=policy-engine` :5432                  | `cnpg.io/cluster=ztiam-pg` :5432                   |
| `cnpg.io/cluster=ztiam-pg`                 | pgbouncer pods, cnpg-system ns, peers      | other cluster members :5432, :8000                 |
| `app=prometheus`                           | `app=grafana` :9090                        | each scrape target on its metrics port             |

## How to test

The cleanest way is to spin up an ephemeral debug pod and confirm both an
allowed and a forbidden path. The forbidden one should *hang* (TCP retries
until timeout) — NetworkPolicy enforcement drops packets silently rather
than rejecting them.

```bash
# Allowed — web-app can reach policy-engine on 4000.
kubectl -n ztiam run debug-web --rm -it --restart=Never \
  --image=curlimages/curl --labels=app=web-app -- \
  curl -kvm 5 https://policy-engine:4000/health

# Forbidden — web-app should NOT reach the database directly.
kubectl -n ztiam run debug-web --rm -it --restart=Never \
  --image=curlimages/curl --labels=app=web-app -- \
  curl -vm 5 telnet://ztiam-pg-rw:5432
# expected: connection times out

# Forbidden — ml-service must not phone home.
kubectl -n ztiam run debug-ml --rm -it --restart=Never \
  --image=curlimages/curl --labels=app=ml-service -- \
  curl -vm 5 https://example.com
# expected: connection times out (DNS resolves; SYN dropped)
```

Calico ships an `iptables -L` view per pod that is helpful when debugging
why a flow is denied:

```bash
kubectl -n kube-system exec -it $(kubectl -n kube-system get pod -l k8s-app=calico-node -o name | head -n1) -- \
  calicoctl get networkpolicy -n ztiam -o yaml
```

## Updating policies

1. Edit `base/networkpolicies.yaml` (in-cluster baseline) or
   `overlays/production/network-egress-restrictions.yaml` (external egress).
2. `kubectl diff -k k8s/` to preview.
3. `kubectl apply -k k8s/` — policies are reconciled atomically.
4. Smoke test the affected workload against the table above.
