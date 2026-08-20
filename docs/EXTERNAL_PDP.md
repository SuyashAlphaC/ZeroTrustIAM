# External PDP (OPA & Cedar)

## Configuration

```bash
PDP_BACKEND=local|opa|cedar|avp|both|all
OPA_URL=http://opa:8181
OPA_POLICY_PATH=/v1/data/ztiam/authz/allow
CEDAR_PDP_URL=http://cedar-agent:8180
AVP_POLICY_STORE_ID=ps-xxxxxxxx
AVP_ENABLED=true
AWS_REGION=us-east-1
PDP_FAILURE_MODE=degrade|fail_closed|fail_open
PDP_TIMEOUT_MS=500
```

See also `docs/AVP.md` for Amazon Verified Permissions schema and sample Cedar.

## Policy sources

- OPA Rego: `policy-engine/policies/opa/ztiam/authz.rego`
- Cedar: `policy-engine/policies/cedar/ztiam.cedar`

## Evaluation order

1. External backends (if configured)
2. Local ABAC builtins + stored policies (`abac.js`)
3. Any **forbid** wins

## Status

`GET /v1/admin/pdp/status` (admin JWT)

## OPA sidecar (compose example)

```yaml
opa:
  image: openpolicyagent/opa:latest
  command: ["run", "--server", "--addr=:8181", "/policies"]
  volumes:
    - ./policy-engine/policies/opa:/policies
```
