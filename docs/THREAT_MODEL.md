# Threat Model

## Trust Boundaries

```
                 UNTRUSTED            BOUNDARY              TRUSTED
                                         |
  [Browser]  ─── HTTPS ───>  [Web App :3000]  ─── HTTP ───>  [Policy Engine :4000]
                                         |                           |
                                         |                    [SQLite DB]
                                         |                           |
                                         |              [Hyperledger Fabric]
                                         |               (peer, orderer, CA)
```

### Boundary 1: Browser <-> Web App
- **Trust level**: UNTRUSTED. All browser input is adversarial.
- **Controls**: Input validation (Joi schemas), rate limiting, HttpOnly cookies, Helmet security headers, CSRF via SameSite=strict.
- **Assumption**: TLS terminates at the web app in production (or at a reverse proxy). In dev, runs on localhost (WebAuthn requires secure context).

### Boundary 2: Web App <-> Policy Engine
- **Trust level**: SEMI-TRUSTED. Web app only relays; makes no decisions.
- **Controls**: The web app proxies requests without interpretation. The policy engine independently validates all inputs. Production path uses **mTLS** (service client cert required except public OIDC/health routes).
- **Assumption**: Both services run on a trusted network or mesh; browsers never hold the mTLS client key.

### Boundary 3: Policy Engine <-> Database
- **Trust level**: TRUSTED. **PostgreSQL** (not SQLite) is required via `DATABASE_URL`.
- **Controls**: Parameterized queries (`pg`), connection pooling / PgBouncer in k8s, optional read replica URL.
- **Assumption**: Postgres is not exposed to the public internet; credentials come from Vault/ExternalSecrets in production.

### Boundary 4: Policy Engine <-> Hyperledger Fabric
- **Trust level**: TRUSTED with TLS verification.
- **Controls**: Mutual TLS with X.509 certificates. Fabric Gateway SDK handles connection lifecycle.
- **Assumption**: Fabric network is correctly configured with proper MSP identities. Peer/orderer containers are not exposed to the public internet.

## Explicit Assumptions

1. **Single-org deployment**: The current Fabric network has one organization (Org1MSP). A real deployment would require multi-org governance with independent endorsement policies.

2. **Real-Fabric dependency**: The policy engine now depends on the real Hyperledger Fabric client path for authorization decisions. If Fabric is unavailable, access evaluation fails closed rather than falling back to an in-memory mock.

3. **ZKP is experimental and opt-in**: Pedersen range proofs are disabled by default (`ZKP_ENABLED=true` to enable). They are **not a security boundary** (`securityBoundary: false`) and must not be the sole authorization control. See `zkpVerifier.js` and `docs/SLO_AND_FAILURE_MODES.md`.

4. **Anomaly detector cold-start**: With fewer than 3 login samples, the time anomaly detector returns 0 (no anomaly). An attacker who acts during the cold-start window will not trigger time-based anomaly detection.

5. **Persistent WebAuthn credentials**: Passkey credentials and challenges are stored in SQLite, so they survive process restarts. Database compromise still exposes registration metadata unless the underlying filesystem and backups are protected.

6. **Clock synchronization**: TOTP MFA requires that the server and user's authenticator app have synchronized clocks (within 30-second tolerance). NTP should be configured on the server.

7. **No external HSM/KMS**: JWT/OAuth signing keys and DID private keys are encrypted before being stored in SQLite using an application master key. This is stronger than plaintext-at-rest, but production deployments should still prefer AWS KMS, HashiCorp Vault, or an HSM for key management.

## Attack Surface

| Vector | Entry Point | Mitigations | Residual Risk |
|--------|------------|-------------|---------------|
| Credential stuffing | POST /evaluate | bcrypt (250ms/hash), rate limiting (10/min), failed attempt tracking | Distributed attacks from many IPs |
| Token theft (XSS) | Browser | HttpOnly cookies, Helmet CSP headers, no tokens in JS-accessible storage | CSP bypass, browser zero-days |
| Session hijacking | Stolen cookie | SameSite=strict, short expiry (15min), refresh token rotation | Physical access to victim's machine |
| Privilege escalation | POST /admin/* | requireAuth + requireRole('admin') middleware, RBAC on blockchain | Admin credential compromise |
| SQL injection | All POST endpoints | Prepared statements (better-sqlite3), Joi input validation | None (parameterized queries) |
| Blockchain tampering | Fabric ledger | Distributed consensus, immutable append-only log, X.509 identity | 51% attack (requires compromising majority of orgs) |
| MFA bypass | POST /mfa/challenge | Time-limited challenges (5min), single-use codes, TOTP with HMAC-SHA1 | SIM swap (not applicable for TOTP), authenticator compromise |
| DID impersonation | POST /did/create | Credential-gated DID creation, blockchain-anchored documents | Key compromise if private keys are extracted from DB |
| Impossible travel false negative | ML anomaly detector | 5-signal weighted detection, profile maturation | VPN-based location spoofing |
| Replay attack | Stolen auth code | Single-use OAuth codes, nonce in OIDC, TOTP time windows | None for implemented vectors |

## Data Classification

| Data | Classification | Storage | Protection |
|------|---------------|---------|------------|
| Passwords | SECRET | SQLite (bcrypt hash) | Never stored in plaintext; bcrypt cost 12 |
| JWT signing keys | SECRET | SQLite | Should be in HSM/KMS in production |
| MFA secrets | SECRET | SQLite | Should be encrypted at rest in production |
| Refresh tokens | CONFIDENTIAL | SQLite | Revocable, time-limited, rotated on use |
| Access tokens | CONFIDENTIAL | HttpOnly cookies | 15-minute expiry, not accessible to JS |
| Risk scores | INTERNAL | Transient (not persisted raw) | ZKP proves compliance without revealing value |
| Audit logs | INTERNAL | Blockchain + SQLite mirror | Immutable on blockchain |
| DID documents | PUBLIC | SQLite + Blockchain | Public by design (W3C DID spec) |
| User profiles | INTERNAL | SQLite | Access-controlled via admin endpoints |
