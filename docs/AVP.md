# Amazon Verified Permissions

Managed Cedar PDP for ZeroTrustIAM.

## Configuration

```bash
export PDP_BACKEND=avp          # or all / both with avp
export AVP_POLICY_STORE_ID=ps-xxxxxxxx
export AVP_ENABLED=true
export AWS_REGION=us-east-1
# Standard AWS credentials (env, profile, IRSA, instance role)
```

## Entity model

Namespace `ztiam`:

- `ztiam::User` — principal (`entityId` = userId)
- `ztiam::Resource` — resource
- `ztiam::Action` — read | write | delete | manage

Context map: `riskScore` (Decimal), `country`, `role`, `tenantId`, `status`, `mfaVerified`, `hour`.

## Sample policy

```cedar
permit (
  principal,
  action == ztiam::Action::"read",
  resource
) when {
  context.status == "ACTIVE" &&
  context.riskScore < decimal("0.6")
};
```

## Status

`GET /v1/admin/pdp/status` includes `avp` block with schema hints.

## Failure modes

Same as OPA/Cedar: `PDP_FAILURE_MODE=degrade|fail_closed|fail_open`.
