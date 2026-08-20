# Zero-knowledge proofs — production policy

## Decision

**Custom Pedersen range proofs are disabled by default and must stay disabled in production.**

| Mode | Env | Behavior |
|------|-----|----------|
| **disabled** (default) | `ZKP_MODE=disabled` | No proof generation; authorization does not depend on ZKP |
| **experimental** | `ZKP_MODE=experimental` | Demo EC implementation for research only |

`ZKP_ENABLED=true` is retained as a legacy alias for experimental mode.

## Why

- The in-tree secp256k1 bit-range proof is **not an audited cryptographic library**
- Duplicated arithmetic in policy-engine and chaincode increases maintenance risk
- Authorization already has bcrypt, risk ensemble, MFA, ABAC/OPA/Cedar, and Fabric RBAC

## If you need production privacy proofs later

1. Integrate an **audited** library (e.g. bulletproofs via a reviewed crate/service, or a vendor ZKP HSM)
2. Keep proofs **off the critical path** — optional privacy attestation only
3. Publish a third-party review before enabling in regulated environments
4. Version the proof scheme on-chain (`zkpScheme`) with migration plan

## Related

- `policy-engine/zkpVerifier.js`
- `docs/SLO_AND_FAILURE_MODES.md`
- Chaincode `_validateProofFreshness` (skipped when no proof package)
