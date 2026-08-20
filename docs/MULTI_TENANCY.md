# Multi-tenancy

## Model

- Every user belongs to a `tenant_id` (default tenant: `default`)
- Access JWTs carry `tid` claim
- Admins may set `X-Tenant-Id` to operate across tenants
- Optional host-map: `TENANT_HOST_MAP_JSON` or `TENANT_BASE_DOMAIN` for subdomains

## Plans & limits

| Plan | Users | SCIM | SAML | CMK |
|------|------:|:----:|:----:|:---:|
| free | 25 | | | |
| team | 250 | ✓ | | |
| business | 5k | ✓ | ✓ | ✓ |
| enterprise | 1M | ✓ | ✓ | ✓ |

Enforcement helpers: `tenancy.getPlanLimits(plan)`.

## Customer-managed keys (CMK)

- `tenants.cmk_arn` / `cmk_key_id` store the AWS KMS key for the tenant
- Use `kmsSigner.createAwsTenantSigner(keyId)` for tenant-scoped envelope encryption
- Platform JWT signing can remain on org-wide KMS (`KMS_BACKEND=aws`, `AWS_KMS_KEY_ID`)

## APIs

```
GET    /v1/admin/tenants
POST   /v1/admin/tenants
GET    /v1/admin/tenants/:id
PATCH  /v1/admin/tenants/:id
POST   /v1/admin/tenants/:id/billing/events
```

Migration: `008_multitenancy_federation`.
