# Blockchain-Backed Zero Trust Identity and Access Management (IAM)

A production-grade, two-layer security system that combines a **Zero Trust Policy Engine** (contextual risk scoring, ML anomaly detection, zero-knowledge proofs) with **Hyperledger Fabric smart contracts** (on-chain authorization, immutable audit logs, W3C DIDs) to mitigate credential theft, impersonation attacks, and insider threats.

The system implements **12 security layers** -- from bcrypt password hashing and OAuth 2.0/OIDC to FIDO2 passwordless authentication and Pedersen commitment-based zero-knowledge proofs -- making it one of the most comprehensive blockchain-backed IAM implementations in academic and open-source literature.

---

## Table of Contents

1. [Theoretical Foundation](#1-theoretical-foundation)
2. [Novelty and Comparative Analysis](#2-novelty-and-comparative-analysis)
3. [System Architecture](#3-system-architecture)
4. [Risk Scoring Model (AHP-Weighted)](#4-risk-scoring-model-ahp-weighted)
5. [Feature Deep Dives](#5-feature-deep-dives)
   - [5.1 Two-Layer Defense Architecture](#51-two-layer-defense-architecture)
   - [5.2 Bcrypt Password Hashing + JWT Tokens](#52-bcrypt-password-hashing--jwt-tokens)
   - [5.3 OAuth 2.0 / OpenID Connect](#53-oauth-20--openid-connect)
   - [5.4 TOTP Multi-Factor Authentication with Step-Up](#54-totp-multi-factor-authentication-with-step-up)
   - [5.5 W3C Decentralized Identifiers (DIDs)](#55-w3c-decentralized-identifiers-dids)
   - [5.6 WebAuthn / FIDO2 Passwordless Authentication](#56-webauthn--fido2-passwordless-authentication)
   - [5.7 ML-Based Behavioral Anomaly Detection](#57-ml-based-behavioral-anomaly-detection)
   - [5.8 Zero-Knowledge Proof Risk Verification](#58-zero-knowledge-proof-risk-verification)
6. [Smart Contract Authorization Rules](#6-smart-contract-authorization-rules)
7. [Project Structure](#7-project-structure)
8. [Prerequisites](#8-prerequisites)
9. [Quick Start Guide](#9-quick-start-guide)
10. [API Reference](#10-api-reference)
11. [Attack Simulations](#11-attack-simulations)
12. [Technology Stack](#12-technology-stack)
13. [Production Architecture](#13-production-architecture)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Theoretical Foundation

### 1.1 Identity and Access Management (IAM)

Identity and Access Management (IAM) is a framework of policies, processes, and technologies that ensures the right individuals have appropriate access to technology resources. Traditional IAM systems rely on a **perimeter-based security model** -- once authenticated at the boundary, users are trusted implicitly within the network. This model has proven catastrophically inadequate in the era of cloud computing, remote workforces, and sophisticated attack vectors.

The fundamental challenge of IAM is the **authentication-authorization gap**: the time between verifying *who* a user is (authentication) and determining *what* they can do (authorization). During this gap, stolen credentials, session hijacking, and privilege escalation attacks thrive.

### 1.2 Zero Trust Architecture (ZTA)

Zero Trust Architecture, formalized by NIST SP 800-207, operates on the principle: **"never trust, always verify."** Unlike traditional models, ZTA assumes breach and verifies every access request as though it originates from an untrusted network. The core tenets are:

- **Continuous Verification**: Every request is authenticated and authorized, regardless of network location
- **Least Privilege Access**: Users receive the minimum permissions needed for their task
- **Micro-Segmentation**: Resources are isolated into small zones to limit lateral movement
- **Contextual Risk Assessment**: Access decisions incorporate device state, location, time, behavior patterns, and threat intelligence

Our system implements ZTA through a **contextual risk scoring engine** that evaluates four signals -- device identity, geographic location, temporal patterns, and failed attempt history -- using AHP-derived weights. This produces a continuous risk score R in [0, 1] rather than a binary allow/deny, enabling proportional security responses such as MFA step-up authentication.

### 1.3 Blockchain for IAM: Why Hyperledger Fabric?

Traditional IAM systems suffer from three critical weaknesses:

1. **Single Point of Failure**: Centralized identity providers (IdPs) are high-value targets. A breach of the IdP compromises all downstream services.
2. **Mutable Audit Trails**: Log files can be altered or deleted by insiders, making forensic analysis unreliable.
3. **Opaque Trust**: Users must trust the IAM provider to enforce policies correctly, with no verifiable guarantee.

Blockchain addresses these through:

- **Decentralized Trust**: Authorization decisions are enforced by smart contracts running on a distributed ledger, eliminating single points of failure.
- **Immutable Audit Logs**: Every access decision (ALLOW or DENY) is cryptographically committed to the blockchain, creating a tamper-evident audit trail.
- **Transparent Policies**: Smart contract code is inspectable and deterministic -- the same inputs always produce the same authorization decision.

We chose **Hyperledger Fabric** over public blockchains (Ethereum, Solana) for several reasons:

| Property | Public Blockchain | Hyperledger Fabric |
|----------|------------------|--------------------|
| Permissioning | Open (anyone can join) | Permissioned (known participants) |
| Privacy | All data visible on-chain | Channels and private data collections |
| Throughput | ~15-100 TPS | ~3,000+ TPS |
| Consensus | PoW/PoS (energy-intensive) | Raft/BFT (practical for enterprise) |
| Smart Contract Language | Solidity (limited) | JavaScript, Go, Java (full-featured) |
| Finality | Probabilistic | Deterministic (immediate) |
| Data Governance | No control over data residency | Full control, GDPR-compatible |

Hyperledger Fabric's **channel architecture** allows us to isolate IAM data from other applications, while its **chaincode-as-a-service (CCaaS)** deployment model enables independent scaling of the smart contract layer.

### 1.4 The Authentication-Authorization Pipeline

Our system implements a multi-stage pipeline that processes each access request:

```
 Request --> [Credential Verification]
               |
               v
         [Risk Score Computation] (AHP weights + ML anomaly adjustment)
               |
               v
         [Policy Engine Threshold Gate] (R >= 0.6 --> DENY)
               |
               v
         [MFA Step-Up Check] (R >= 0.3 or sensitive operation --> TOTP challenge)
               |
               v
         [Blockchain Smart Contract] (4-rule authorization + immutable audit)
               |
               v
         [ZKP Proof Generation] (proves R < threshold without revealing R)
               |
               v
         [JWT Token Issuance] (access + refresh tokens)
               |
               v
         Response (ALLOW/DENY + audit trail + ZKP + session token)
```

Each stage can independently reject a request. An attacker must defeat **all** layers simultaneously -- stolen credentials alone are insufficient if the device is unrecognized, the location is anomalous, or the behavioral pattern deviates from the learned baseline.

---

## 2. Novelty and Comparative Analysis

### 2.1 What Makes This Project Unique

This project is **the first open-source implementation** that integrates all of the following in a single, working system:

1. **Blockchain-enforced authorization** (Hyperledger Fabric smart contracts) with **zero-trust contextual risk scoring** (AHP-weighted)
2. **W3C DID/Verifiable Credentials** anchored on a permissioned blockchain
3. **Zero-knowledge proofs** for privacy-preserving risk verification
4. **ML-based behavioral anomaly detection** that adaptively adjusts risk scores
5. **Complete modern auth stack**: bcrypt, JWT, OAuth 2.0/OIDC, TOTP MFA, WebAuthn/FIDO2

### 2.2 Comparison with Existing Work

| System / Paper | Blockchain | Zero Trust | MFA | DID/VC | ZKP | ML Anomaly | WebAuthn |
|---------------|:----------:|:----------:|:---:|:------:|:---:|:----------:|:--------:|
| **This Project** | **Fabric** | **AHP Risk** | **TOTP Step-Up** | **W3C DID** | **Pedersen** | **5-Factor** | **FIDO2** |
| Hyperledger Indy | Indy | No | No | DID only | No | No | No |
| Microsoft Entra ID | No | Conditional | Yes | No | No | Yes | Yes |
| Okta / Auth0 | No | Adaptive | Yes | No | No | Partial | Yes |
| IBM Verify | No | Risk-based | Yes | No | No | Yes | Partial |
| NIST ZTA (SP 800-207) | Spec only | Yes | Recommended | No | No | Suggested | No |
| DID-based IAM (academic) | Ethereum | No | No | DID | Partial | No | No |
| Blockchain RBAC (academic) | Various | No | No | No | No | No | No |

**Key differentiators:**

- **No existing system** combines blockchain-enforced RBAC with continuous zero-trust risk scoring AND zero-knowledge proof verification
- **Academic blockchain IAM papers** (e.g., Zyskind et al. 2015, Ferdous et al. 2019) propose theoretical architectures but lack working implementations with modern auth standards
- **Commercial IAM platforms** (Entra, Okta) implement adaptive authentication but rely on centralized infrastructure without blockchain immutability
- **Hyperledger Indy** provides DID infrastructure but lacks a policy engine, risk scoring, or integrated authentication
- **Our ZKP integration** enables a privacy-preserving audit trail -- the blockchain records that the risk score was below the threshold without storing the actual score, addressing GDPR data minimization requirements

### 2.3 Novel Contributions

1. **AHP-Weighted Contextual Risk Scoring**: We apply the Analytic Hierarchy Process (a multi-criteria decision-making method from operations research) to derive optimal weights for device, location, time, and attempt signals -- mathematically justified rather than ad-hoc.

2. **Adaptive Step-Up MFA**: Instead of always requiring MFA or never requiring it, our system dynamically triggers MFA based on the computed risk score and operation sensitivity. A read operation from a known device doesn't need MFA; a write operation from a new location does.

3. **Blockchain-Anchored ZKP Audit**: By combining Pedersen commitments with Hyperledger Fabric, we create an audit trail that is simultaneously **immutable** (blockchain), **verifiable** (ZKP), and **privacy-preserving** (actual risk scores are not stored on-chain).

4. **Behavioral Baseline with Impossible Travel**: Our ML anomaly detector uses Welford's online algorithm for incremental mean/variance computation, enabling the system to learn user behavior patterns without storing raw login histories. The impossible travel detection identifies physically implausible location changes.

5. **Dual-Layer Smart Contract Verification**: Authorization is enforced by both the off-chain policy engine AND the on-chain smart contract, creating defense-in-depth that survives compromise of either layer individually.

---

## 3. System Architecture

```
                                         LAYER 1                                LAYER 2
                                    (Authentication)                        (Authorization)

 +-----------+    +-------------------------+    +-----------------------------+    +-------------------------------+
 |           |    |   Web App               |    |  Policy Engine              |    |  Hyperledger Fabric           |
 |  User /   |--->|   (Node.js :3000)       |--->|  (Node.js :4000)            |--->|  Blockchain Network           |
 | Attacker  |    |                         |    |                             |    |                               |
 |           |<---|   - Login form          |<---|  - bcrypt verification      |<---|  +-------------------------+  |
 +-----------+    |   - OAuth/OIDC login    |    |  - AHP risk scoring         |    |  | IAM Smart Contract      |  |
                  |   - WebAuthn passkeys   |    |  - ML anomaly detection     |    |  | (JavaScript)            |  |
                  |   - MFA TOTP input      |    |  - MFA step-up gate         |    |  |                         |  |
                  |   - JWT session mgmt    |    |  - ZKP proof generation     |    |  | 4 Authorization Rules:  |  |
                  |   - Collects device ID, |    |  - OAuth 2.0 / OIDC         |    |  | 1. Account ACTIVE       |  |
                  |     location, timestamp |    |  - JWT token issuance       |    |  | 2. Device registered    |  |
                  |   - Makes NO decisions  |    |  - W3C DID resolver         |    |  | 3. Risk < threshold     |  |
                  +-------------------------+    |  - WebAuthn/FIDO2 server    |    |  | 4. RBAC permissions     |  |
                                                 +-----------------------------+    |  +-------------------------+  |
                                                                                    |                               |
                                                                                    |  +-------------------------+  |
                                                                                    |  | W3C DID Documents       |  |
                                                                                    |  | (did:fabric:iam:*)      |  |
                                                                                    |  +-------------------------+  |
                                                                                    |                               |
                                                                                    |  +-------------------------+  |
                                                                                    |  | Verifiable Credentials  |  |
                                                                                    |  | (Role, Access creds)    |  |
                                                                                    |  +-------------------------+  |
                                                                                    |                               |
                                                                                    |  +-------------------------+  |
                                                                                    |  | Immutable Audit Log     |  |
                                                                                    |  | (every ALLOW/DENY)      |  |
                                                                                    |  +-------------------------+  |
                                                                                    |                               |
                                                                                    |  Peer | Orderer | CA          |
                                                                                    |  (Docker containers)          |
                                                                                    +-------------------------------+
```

### Data Flow for a Single Authentication Request

1. **User submits login** via the web app (username, password, device ID, location, timestamp, requested permission)
2. **Web app relays** the request to the policy engine at `:4000/evaluate` -- the web app makes NO security decisions
3. **Policy engine verifies credentials** against bcrypt hashes (configurable cost factor, default 12)
4. **Risk score is computed**: `R = w1*d + w2*l + w3*t + w4*a` using config-driven AHP weights (default: 0.40, 0.30, 0.20, 0.10)
5. **ML anomaly detector adjusts** the risk score based on behavioral deviation (time patterns, location novelty, impossible travel, login frequency, device novelty)
6. **Threshold gate**: If adjusted `R >= 0.6`, the request is denied immediately
7. **MFA step-up check**: If `R >= 0.3` or operation is sensitive (write/delete/manage) with any risk, a TOTP challenge is issued
8. **Blockchain smart contract** evaluates 4 authorization rules: account status, device registration, risk threshold, RBAC permissions
9. **Every decision** (ALLOW or DENY) is written to the blockchain as an immutable audit entry with transaction ID, user, device, risk score, reason, and timestamp
10. **ZKP proof** is generated proving the risk score is below the threshold without revealing the actual value
11. **JWT tokens** (access + refresh) are issued on successful authentication
12. **Response** includes decision, risk breakdown, anomaly scores, blockchain transaction ID, ZKP proof ID, and JWT tokens

---

## 4. Risk Scoring Model (AHP-Weighted)

### 4.1 The Analytic Hierarchy Process (AHP)

The Analytic Hierarchy Process is a structured decision-making method developed by Thomas Saaty (1980). It decomposes a complex decision into a hierarchy of criteria, performs pairwise comparisons between criteria, and computes mathematically consistent priority weights.

We apply AHP to determine the relative importance of four contextual signals for detecting impersonation:

**Pairwise Comparison Matrix:**

| | Device | Location | Time | Attempts |
|---|---|---|---|---|
| **Device** | 1 | 2 | 3 | 4 |
| **Location** | 1/2 | 1 | 2 | 3 |
| **Time** | 1/3 | 1/2 | 1 | 2 |
| **Attempts** | 1/4 | 1/3 | 1/2 | 1 |

**Rationale for the hierarchy:**

- **Device >> Location**: An unknown device is the strongest signal of impersonation. A stolen password used from the attacker's own device will always trigger this signal.
- **Location > Time**: Geographic anomalies (foreign country) are more indicative of attack than temporal anomalies (off-hours work is common).
- **Time > Attempts**: Off-hours access is suspicious but not definitive. Failed attempts are the weakest signal because legitimate users forget passwords.

**Computed weights** (normalized principal eigenvector): `w_device = 0.40, w_location = 0.30, w_time = 0.20, w_attempts = 0.10`

**Consistency Ratio**: CR = 0.035 < 0.10 (acceptable consistency per Saaty's threshold)

### 4.2 Risk Score Formula

```
R = 0.40 * d_score + 0.30 * l_score + 0.20 * t_score + 0.10 * a_score
```

| Factor | Weight | Score = 0 | Score = 0.5 | Score = 1 |
|--------|--------|-----------|-------------|-----------|
| **Device** (d) | 0.40 | Registered device | - | Unknown device |
| **Location** (l) | 0.30 | Usual location | Same country, different city | Different country |
| **Time** (t) | 0.20 | Within normal hours | - | Outside normal hours |
| **Attempts** (a) | 0.10 | No recent failures | - | 5+ recent failures |

### 4.3 Threshold Design

- **R < 0.3**: Low risk -- access granted without additional checks
- **0.3 <= R < 0.6**: Medium risk -- MFA step-up required (if enrolled)
- **R >= 0.6**: High risk -- access denied by policy engine before reaching blockchain

### 4.4 Example Scenarios

| Scenario | d | l | t | a | R | Decision |
|----------|---|---|---|---|---|----------|
| Legitimate user, home, normal hours | 0 | 0 | 0 | 0 | 0.00 | ALLOW |
| Stolen creds, unknown device | 1 | 0 | 0 | 0 | 0.40 | DENY (smart contract: unregistered device) |
| Known device, different city | 0 | 0.5 | 0 | 0 | 0.15 | MFA_REQUIRED (for sensitive ops) |
| Known device, foreign country | 0 | 1 | 0 | 0 | 0.30 | MFA_REQUIRED |
| Unknown device + foreign country | 1 | 1 | 0 | 0 | 0.70 | DENY (policy engine: R >= 0.6) |
| Unknown device + foreign + off-hours | 1 | 1 | 1 | 0 | 0.90 | DENY (policy engine: R >= 0.6) |
| Full attack (all signals) | 1 | 1 | 1 | 1 | 1.00 | DENY (policy engine: R >= 0.6) |

---

## 5. Feature Deep Dives

### 5.1 Two-Layer Defense Architecture

**Theory**: Defense-in-depth is a security strategy that employs multiple layers of controls. If one layer is compromised, subsequent layers provide redundant protection. Our system implements this through two independent enforcement points:

**Layer 1 -- Policy Engine (Off-Chain)**:
- Runs as a Node.js Express server at `:4000`
- Performs credential verification against bcrypt hashes
- Computes contextual risk scores using AHP weights
- Applies ML anomaly detection adjustment
- Enforces the risk threshold (R >= 0.6 = deny)
- Triggers MFA step-up when appropriate
- Generates ZKP proofs of risk compliance

**Layer 2 -- Smart Contract (On-Chain)**:
- Runs as a Hyperledger Fabric chaincode on `iamchannel`
- Enforces 4 authorization rules independently of the policy engine
- Writes every decision to the immutable ledger
- Manages user registry, role-permission mappings, and policy thresholds on-chain
- Stores W3C DID documents and Verifiable Credentials

**Why both layers matter**: An attacker who compromises the policy engine still faces the smart contract's independent device registration check. An attacker who somehow bypasses the smart contract still cannot produce a valid JWT token without passing the policy engine. The blockchain's immutable audit log ensures that even a successful attack is forensically detectable.

### 5.2 Bcrypt Password Hashing + JWT Tokens

**Theory**: Password storage is the most critical vulnerability in any authentication system. Storing passwords in plaintext or with fast hashes (MD5, SHA-256) allows attackers to recover passwords from stolen databases in seconds using GPU-accelerated brute force.

**Bcrypt** (Provos & Mazieres, 1999) addresses this through:
- **Adaptive cost factor**: Each hash iteration is deliberately slow. Our cost factor of 12 means 2^12 = 4,096 iterations per hash, taking ~250ms per verification. This makes brute-force attacks economically impractical (billions of years for a strong password).
- **Built-in salt**: Each hash includes a unique 128-bit random salt, preventing rainbow table attacks and ensuring identical passwords produce different hashes.
- **Memory-hard design**: Bcrypt requires significant memory per hash computation, making GPU parallelization less effective than for SHA-based hashes.

**JWT (JSON Web Tokens)** provide stateless session management:
- **Access tokens** (15-minute expiry): Carry user identity and role claims, signed with HMAC-SHA256. Short expiry limits the damage window if a token is stolen.
- **Refresh tokens** (7-day expiry): Used to obtain new access tokens without re-authentication. Stored server-side in a revocation set, enabling instant logout.
- **Token rotation**: Each refresh produces a new access token. Revoked refresh tokens are immediately rejected.

**Implementation**: `policy-engine/server.js` uses `bcrypt.compare()` for constant-time password verification and `jsonwebtoken` for HS256 signed tokens. JWT signing keys are persisted in the `signing_keys` database table, ensuring tokens remain valid across server restarts. The bcrypt cost factor is configurable via `BCRYPT_ROUNDS`.

### 5.3 OAuth 2.0 / OpenID Connect

**Theory**: OAuth 2.0 (RFC 6749) is the industry-standard protocol for delegated authorization. OpenID Connect (OIDC) extends OAuth 2.0 with an identity layer, enabling third-party applications to verify user identity and obtain basic profile information.

**Our implementation supports the Authorization Code flow**:

1. **Client registration**: Applications register with a `client_id`, `client_secret`, and allowed `redirect_uris`
2. **Authorization request**: User is redirected to `/oauth/authorize` with `response_type=code`
3. **User consent**: User authenticates and authorizes the client
4. **Authorization code**: A single-use, time-limited (10-minute) code is returned via redirect
5. **Token exchange**: Client exchanges the code for tokens at `/oauth/token` using its credentials
6. **ID Token**: OIDC-compliant JWT signed with RS256, containing `sub`, `iss`, `aud`, `iat`, `exp`, `nonce`

**Security features**:
- **RS256 signing**: ID tokens are signed with a 2048-bit RSA private key. The public key is available at `/oauth/.well-known/jwks.json` for verification.
- **OIDC Discovery**: The `/.well-known/openid-configuration` endpoint provides automated configuration for relying parties.
- **Single-use codes**: Authorization codes are deleted after first use, preventing replay attacks.
- **State parameter**: CSRF protection via the `state` parameter in the authorization flow.
- **Nonce binding**: The `nonce` parameter in the ID token prevents token replay.

**Implementation**: `policy-engine/oauth.js` manages RSA key generation, authorization codes, token issuance, and JWKS publication. RSA signing keys and authorization codes are persisted in the database, ensuring OIDC tokens remain verifiable across restarts and codes cannot be replayed.

### 5.4 TOTP Multi-Factor Authentication with Step-Up

**Theory**: Multi-Factor Authentication (MFA) requires users to prove their identity through two or more independent factors:
- **Something you know** (password)
- **Something you have** (TOTP authenticator app, hardware key)
- **Something you are** (biometrics)

TOTP (Time-Based One-Time Password, RFC 6238) generates 6-digit codes that change every 30 seconds, derived from a shared secret and the current timestamp:

```
TOTP = HOTP(secret, floor(time / 30))
HOTP(K, C) = Truncate(HMAC-SHA1(K, C)) mod 10^6
```

**Step-up authentication** is our novel contribution: rather than always requiring MFA (user friction) or never requiring it (security gap), we dynamically trigger MFA based on the contextual risk score:

- **Risk >= 0.3** (elevated but below deny threshold): MFA challenge is issued
- **Sensitive operations** (write, delete, manage) with **any risk > 0**: MFA challenge is issued
- **Risk = 0 with read permission**: No MFA needed (frictionless access for normal behavior)

This implements the NIST recommendation for **adaptive, risk-proportional authentication** while minimizing user friction for low-risk access patterns.

**Challenge flow**:
1. Policy engine detects that MFA step-up is required
2. A time-limited (5-minute) challenge is created with a unique `challengeId`
3. Client displays the TOTP input form
4. User enters the 6-digit code from their authenticator app
5. Server verifies the code against the shared secret with a time window tolerance
6. On success, JWT tokens are issued with an `mfaVerified: true` flag

**Implementation**: `policy-engine/mfa.js` uses `otplib` for TOTP generation/verification and `qrcode` for enrollment QR code generation.

### 5.5 W3C Decentralized Identifiers (DIDs)

**Theory**: Decentralized Identifiers (W3C DID Core v1.0, 2022) are a new type of globally unique identifier designed to enable **self-sovereign identity** -- the concept that individuals should own and control their own digital identity without dependence on a centralized authority.

A DID has the format: `did:<method>:<method-specific-id>`

Our custom DID method: **`did:fabric:iam:<userId>`**

Each DID resolves to a **DID Document** containing:
- **Verification Methods**: Public keys used for authentication and assertion
- **Authentication**: References to keys authorized for authentication
- **Service Endpoints**: URIs where the DID subject's services can be accessed

**Our DID Document (W3C-compliant)**:
```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:fabric:iam:alice",
  "controller": "did:fabric:iam:alice",
  "verificationMethod": [{
    "id": "did:fabric:iam:alice#key-1",
    "type": "JsonWebKey2020",
    "controller": "did:fabric:iam:alice",
    "publicKeyJwk": { "kty": "EC", "crv": "P-256", ... }
  }],
  "authentication": ["did:fabric:iam:alice#key-1"],
  "service": [{
    "id": "did:fabric:iam:alice#iam-service",
    "type": "ZeroTrustIAM",
    "serviceEndpoint": "http://localhost:4000"
  }]
}
```

**Verifiable Credentials (W3C VC Data Model v1.1)** are cryptographically tamper-evident claims about a subject:
- **RoleCredential**: Attests that a user holds a specific role (admin, viewer)
- **AccessCredential**: Grants specific access permissions to resources
- **Proof**: Each credential includes a `BlockchainProof2024` linking to the Fabric transaction that created it

**Why blockchain-anchored DIDs?**
- **Censorship resistance**: No central authority can revoke a DID without the owner's consent
- **Auditability**: DID creation, updates, and deactivation are recorded on the immutable ledger
- **Interoperability**: W3C DID standard ensures compatibility with the global decentralized identity ecosystem

**Implementation**: `policy-engine/didResolver.js` manages DID lifecycle operations. `chaincode/lib/iamContract.js` includes `CreateDID`, `ResolveDID`, `UpdateDID`, `DeactivateDID`, `IssueVerifiableCredential`, and `VerifyCredential` methods for on-chain operations.

### 5.6 WebAuthn / FIDO2 Passwordless Authentication

**Theory**: FIDO2 (Fast Identity Online) is an open authentication standard that enables passwordless login using **public-key cryptography** and platform authenticators (biometric sensors, security keys).

The FIDO2 stack consists of:
- **WebAuthn** (W3C): Browser API for creating and using public key credentials
- **CTAP2** (FIDO Alliance): Protocol for communicating with external authenticators (USB keys, NFC, Bluetooth)

**Why passwordless?**
- **No shared secrets**: Unlike passwords, the private key never leaves the authenticator device
- **Phishing-resistant**: Credentials are bound to the relying party's origin, making phishing sites unable to request valid assertions
- **Replay-resistant**: Each authentication includes a challenge-response with a server-generated nonce
- **User-friendly**: Biometric authentication (fingerprint, face) is faster than typing passwords

**Registration flow**:
1. Server generates registration options (challenge, RP info, user info, supported algorithms)
2. Browser calls `navigator.credentials.create()` which triggers the authenticator
3. Authenticator generates a key pair, stores the private key, and returns the public key + attestation
4. Server verifies the attestation and stores the credential

**Authentication flow**:
1. Server generates authentication options (challenge, allowed credentials)
2. Browser calls `navigator.credentials.get()` which triggers the authenticator
3. User verifies via biometric/PIN, authenticator signs the challenge with the private key
4. Server verifies the signature, checks the counter (replay protection), and issues JWT tokens

**Implementation**: `policy-engine/webauthn.js` uses `@simplewebauthn/server` for credential management, challenge generation, and cryptographic verification.

### 5.7 ML-Based Behavioral Anomaly Detection

**Theory**: Traditional rule-based security systems are brittle -- they either generate too many false positives (blocking legitimate users) or too many false negatives (missing novel attacks). Machine learning-based anomaly detection builds a **behavioral baseline** for each user and flags deviations.

Our system implements 5 anomaly detection signals:

**1. Login Time Pattern (Gaussian Model)**

We model each user's login time distribution as a Gaussian (normal distribution) using **Welford's online algorithm** for incremental mean and variance computation:

```
new_mean = old_mean + (x - old_mean) / n
new_var = ((n-2)/(n-1)) * old_var + ((x - old_mean)(x - new_mean)) / (n-1)
```

The anomaly score is the absolute z-score normalized to [0, 1]:
```
z = |hour - mean| / std
time_anomaly = min(z / 3, 1)    // 3+ standard deviations = maximum anomaly
```

**Why Welford's algorithm?** Unlike batch computation, it processes one observation at a time, requires constant memory (just mean, variance, count), and is numerically stable for large sample counts.

**2. Location Novelty**

The system maintains a set of known (country, city) pairs for each user. A login from a never-before-seen location receives a high novelty score (0.8). This is a binary signal that becomes more discriminative as the user's profile matures.

**3. Login Frequency (Rate Limiting)**

A sliding window (5 minutes) counts recent login attempts. More than 10 logins in 5 minutes suggests automated credential stuffing:
```
frequency_anomaly = min(recent_count / 10, 1)
```

**4. Impossible Travel Detection**

If a user logs in from country A at time T1 and country B at time T2, and T2 - T1 < 2 hours, this is physically impossible travel. The system flags:
- Different country in < 2 hours: anomaly score = 1.0
- Different city (same country) in < 30 minutes: anomaly score = 0.7

**5. Device Novelty**

Similar to location novelty, the system tracks known device IDs. A login from an unknown device receives a novelty score of 0.6.

**Weighted Combination**:
```
anomaly = 0.15*time + 0.25*location + 0.20*frequency + 0.25*travel + 0.15*device
```

Travel and location anomalies receive the highest weights because they are the strongest indicators of credential theft (the attacker is rarely in the same physical location as the victim).

**Risk Score Adjustment**:
```
adjusted_risk = base_risk + anomaly_combined * 0.15
```

The anomaly contribution (weight 0.15) is additive to the AHP-based risk score, allowing behavioral signals to push a borderline request over the threshold.

**Implementation**: `policy-engine/anomalyDetector.js` maintains per-user behavioral profiles in the `anomaly_profiles` database table, implements Welford's algorithm for online statistics, and provides diagnostic endpoints for inspecting learned profiles. Profiles persist across server restarts, allowing the model to continuously learn without data loss.

### 5.8 Zero-Knowledge Proof Risk Verification

**Theory**: Zero-Knowledge Proofs (ZKPs) allow one party (the prover) to convince another party (the verifier) that a statement is true without revealing any information beyond the validity of the statement itself.

In our context: the policy engine (prover) wants to convince the blockchain (verifier) that **"the risk score is below the threshold"** without revealing the actual risk score. This is critical for privacy:
- The blockchain audit log should record that access was granted with acceptable risk, not the exact risk score
- Risk scores could reveal sensitive behavioral information (e.g., a consistently low score from a single location reveals the user's work pattern)
- GDPR's data minimization principle requires collecting only the minimum necessary data

**Our implementation uses Pedersen Commitments + Range Proofs**:

**Pedersen Commitment** (Pedersen, 1991):
```
C = g^value * h^r (mod p)
```
Where:
- `g, h` are generators of a cyclic group
- `value` is the risk score (scaled to integer)
- `r` is a random blinding factor
- `p` is a large prime modulus

The commitment `C` is **hiding** (reveals nothing about `value` without knowing `r`) and **binding** (the prover cannot change `value` after committing).

**Range Proof** (simplified Schnorr-like protocol):

To prove that `value < threshold`:
1. Prover commits to `value` and to `difference = threshold - value`
2. Both commitments are published
3. A non-interactive challenge is derived via the **Fiat-Shamir heuristic** (hashing the commitments)
4. Prover computes responses using the challenge and secret values
5. Verifier checks the algebraic relationships without learning `value` or `difference`

**Security properties**:
- **Completeness**: An honest prover with risk < threshold can always produce a valid proof
- **Soundness**: A dishonest prover with risk >= threshold cannot produce a valid proof (with overwhelming probability)
- **Zero-knowledge**: The verifier learns nothing except that risk < threshold
- **Non-interactivity**: The Fiat-Shamir heuristic eliminates the need for a challenge-response round trip

**In our system**:
1. Every ALLOW decision generates a ZKP proving `risk_score < 0.6`
2. The `proofId` is included in the response for audit purposes
3. The blockchain records the proof commitment, not the raw risk score
4. Any auditor can verify the proof without learning the actual risk value

**Implementation**: `policy-engine/zkpVerifier.js` implements modular exponentiation, Pedersen commitments, range proof construction, Fiat-Shamir challenge derivation, and proof verification.

---

## 6. Smart Contract Authorization Rules

The IAM chaincode (`iam-cc`) runs on channel `iamchannel` and enforces 4 sequential authorization rules:

| Rule | Check | DENY Reason | Rationale |
|------|-------|-------------|-----------|
| 1 | User exists and status = ACTIVE | "User not found" / "Account inactive" | Suspended accounts cannot access any resource |
| 2 | Device ID in user's registered devices | "Unregistered device" | Unknown devices indicate credential theft |
| 3 | Risk score < policy threshold | "Risk score exceeds threshold" | Contextual risk is too high for access |
| 4 | User's role has required permission | "Insufficient permissions" | RBAC least-privilege enforcement |

### World State Keys

```
UserRegistry:<userId>      -> { userId, role, registeredDevices[], status, did? }
RolePermissions:<role>     -> { permissions[] }
PolicyThresholds:default   -> { riskThreshold }
AuditLog:<txId>            -> { txId, userId, deviceId, riskScore, decision, reason, timestamp }
DID:<did>                  -> { W3C DID Document }
VC:<credentialId>          -> { W3C Verifiable Credential }
```

### Chaincode Functions

| Function | Type | Args | Description |
|----------|------|------|-------------|
| `InitLedger` | invoke | none | Seeds users, roles, thresholds |
| `EvaluateAccess` | invoke | userId, deviceId, riskScore, requiredPermission | 4-rule authorization + audit log |
| `GetUser` | query | userId | Read user record |
| `RegisterDevice` | invoke | userId, deviceId | Add device to user's list |
| `UpdateUserStatus` | invoke | userId, status | Set ACTIVE / SUSPENDED |
| `GetAuditLog` | query | txId | Read specific audit entry |
| `GetAllAuditLogs` | query | none | Read all audit entries |
| `CreateDID` | invoke | userId, publicKeyJwk, authMethod | Create W3C DID Document |
| `ResolveDID` | query | did | Resolve DID Document |
| `UpdateDID` | invoke | did, newPublicKeyJwk | Rotate verification keys |
| `DeactivateDID` | invoke | did | Revoke all keys |
| `IssueVerifiableCredential` | invoke | credId, issuerDid, subjectDid, types, claims | Issue VC |
| `VerifyCredential` | query | credentialId | Verify VC on-chain |

---

## 7. Project Structure

```
ZeroTrustIAM/
├── web-app/                              # Frontend + relay server
│   ├── server.js                         # Express :3000, proxies to policy engine
│   ├── package.json                      # Express dependency
│   └── public/
│       ├── index.html                    # Login form, MFA input, session panel
│       ├── style.css                     # Dark theme UI
│       └── app.js                        # Device ID, JWT mgmt, MFA challenge UI
│
├── policy-engine/                        # Zero Trust authentication + risk scoring
│   ├── server.js                         # Express :4000, orchestrates full auth flow
│   ├── config.js                         # Centralized config (env-driven, requireEnv for prod)
│   ├── logger.js                         # Structured logging (pino + pino-pretty)
│   ├── middleware.js                     # Helmet, rate limiters, JWT auth, RBAC, validation
│   ├── database.js                       # SQLite persistence (WAL mode, prepared statements)
│   ├── riskScorer.js                     # R = w1*d + w2*l + w3*t + w4*a (config-driven)
│   ├── anomalyDetector.js                # ML behavioral anomaly detection (5 signals, DB-backed)
│   ├── zkpVerifier.js                    # Pedersen commitment ZKP range proofs
│   ├── mfa.js                            # TOTP MFA with step-up authentication (DB-backed)
│   ├── oauth.js                          # OAuth 2.0 / OIDC (RS256 keys DB-persisted)
│   ├── webauthn.js                       # WebAuthn/FIDO2 passkey management (DB-backed)
│   ├── didResolver.js                    # W3C DID resolver + Verifiable Credentials (DB-backed)
│   ├── fabricClient.js                   # Hyperledger Fabric Gateway SDK client
│   ├── mockBlockchain.js                 # In-memory mock (USE_MOCK=true)
│   ├── .env.example                      # Reference environment config with all variables
│   ├── jest.config.js                    # Jest test configuration (ESM compatibility)
│   ├── package.json                      # bcrypt, jsonwebtoken, otplib, better-sqlite3, etc.
│   └── __tests__/
│       ├── unit/
│       │   ├── riskScorer.test.js        # AHP risk scoring unit tests
│       │   ├── anomalyDetector.test.js   # Anomaly detection unit tests (DB-backed)
│       │   ├── zkpVerifier.test.js       # ZKP proof generation/verification tests
│       │   ├── database.test.js          # Database CRUD and constraint tests
│       │   └── mockBlockchain.test.js    # Mock blockchain unit tests
│       └── integration/
│           └── api.test.js               # Full API integration tests (supertest)
│
├── chaincode/                            # Hyperledger Fabric smart contract
│   ├── Dockerfile                        # Node.js Alpine image for CCaaS
│   ├── package.json                      # fabric-contract-api, fabric-shim
│   ├── index.js                          # Contract entry point
│   └── lib/
│       └── iamContract.js                # 4-rule authorization + DID/VC + audit logging
│
├── fabric-network/                       # Blockchain infrastructure
│   ├── docker-compose.yaml               # Peer, orderer, CA, chaincode, CLI containers
│   ├── configtx.yaml                     # Channel and organization config
│   ├── crypto-config-org1.yaml           # Peer organization crypto spec
│   ├── crypto-config-orderer.yaml        # Orderer organization crypto spec
│   ├── peercfg/core.yaml                 # Peer configuration
│   ├── install-fabric.sh                 # Download Fabric binaries
│   ├── bin/                              # Fabric binaries (cryptogen, configtxgen)
│   ├── builders/ccaas/bin/               # CCaaS external builder scripts
│   └── scripts/
│       ├── setup-network.sh              # Generate crypto, start network, create channel
│       ├── deploy-chaincode.sh           # Package, install, approve, commit chaincode
│       └── teardown.sh                   # Stop containers, clean up
│
└── test/
    ├── test-phase1.sh                    # cURL-based tests (mock blockchain)
    └── attack-scenarios.js               # 7 attack scenarios, 12 tests
```

---

## 8. Prerequisites

- **Node.js** >= 18
- **Docker** and **Docker Compose** v2+
- ~2 GB disk space for Fabric Docker images
- Linux or macOS (Fabric binaries are platform-specific)

---

## 9. Quick Start Guide

### 9.1 Environment Setup

```bash
# Install dependencies
cd policy-engine && npm install
cd ../web-app && npm install
```

Copy the reference environment file and customize:

```bash
cd policy-engine
cp .env.example .env
```

The `.env` file controls all runtime behavior. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | `development` | Set to `production` for production mode |
| `USE_MOCK` | `true` | `true` = in-memory mock blockchain, `false` = real Fabric |
| `SEED_DEMO` | `true` | Seeds `alice`/`bob` test users. **Never set in production** |
| `JWT_SECRET` | auto-generated | **REQUIRED in production** -- HMAC key for access tokens |
| `JWT_REFRESH_SECRET` | auto-generated | **REQUIRED in production** -- HMAC key for refresh tokens |
| `OAUTH_DEFAULT_CLIENT_SECRET` | auto-generated | **REQUIRED in production** -- OAuth client secret |
| `DB_PATH` | `./data/iam.db` | SQLite database file path |
| `BCRYPT_ROUNDS` | `12` | bcrypt cost factor (2^N iterations) |
| `LOG_LEVEL` | `info` | Pino log level (`debug`, `info`, `warn`, `error`) |

See `.env.example` for the complete list of 30+ configurable variables (risk weights, rate limits, Fabric connection, WebAuthn, MFA, etc.).

### 9.2 Development Mode (Mock Blockchain, No Docker)

The fastest way to run the system locally without Hyperledger Fabric:

```bash
# Terminal 1: Policy Engine (mock blockchain + demo users)
cd policy-engine
USE_MOCK=true SEED_DEMO=true node server.js

# Terminal 2: Web App
cd web-app
node server.js
```

Open **http://localhost:3000** in your browser.

**Demo users** (only available when `SEED_DEMO=true`):

| Username | Password | Role | Registered Device | Usual Location |
|----------|----------|------|-------------------|----------------|
| alice | pass123 | admin | dev-001 | IN / Gwalior |
| bob | bob456 | viewer | dev-002 | IN / Delhi |

**Try these experiments:**

1. **Normal login**: Log in as `alice` with default settings -- ACCESS GRANTED with risk score 0.00
2. **Foreign location**: Change country to `RU` -- MFA_REQUIRED (risk = 0.30 >= step-up threshold)
3. **Unknown device**: Change device ID to something random -- DENY (smart contract: unregistered device)
4. **Privilege escalation**: Log in as `bob` and request `delete` permission -- DENY (RBAC: viewer lacks delete)
5. **Cumulative attack**: Unknown device + foreign country + off-hours = risk 0.90 -- DENY

### 9.3 Production Mode (Real Fabric Network)

#### Start the Hyperledger Fabric Network

```bash
cd fabric-network

# Download Fabric binaries (first time only)
./install-fabric.sh --fabric-version 2.5.12 --ca-version 1.5.15 binary

# Start network: generates crypto, starts containers, creates channel
bash scripts/setup-network.sh

# Deploy and initialize the IAM smart contract
bash scripts/deploy-chaincode.sh
```

This starts 4 Docker containers:
- `orderer.example.com` -- Transaction ordering (port 7050)
- `peer0.org1.example.com` -- Endorsing peer (port 7051)
- `iam-chaincode` -- Smart contract running as a service (port 9999)
- `cli` -- Fabric CLI tools

#### Configure Production Environment

Generate secrets and set required variables:

```bash
cd policy-engine

# Generate JWT secrets
export JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
export JWT_REFRESH_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
export OAUTH_DEFAULT_CLIENT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

# Production settings
export NODE_ENV=production
export USE_MOCK=false
# SEED_DEMO is NOT set -- no demo users in production
```

The server will refuse to start in `NODE_ENV=production` if `JWT_SECRET`, `JWT_REFRESH_SECRET`, or `OAUTH_DEFAULT_CLIENT_SECRET` are missing.

#### Start the Application

```bash
# Terminal 1: Policy Engine (connects to real Fabric network)
cd policy-engine
node server.js

# Terminal 2: Web App
cd web-app
OAUTH_CLIENT_SECRET=$OAUTH_DEFAULT_CLIENT_SECRET node server.js
```

### 9.4 Run Tests

```bash
cd policy-engine

# Run all tests (unit + integration)
SEED_DEMO=true USE_MOCK=true npm test

# Unit tests only
SEED_DEMO=true USE_MOCK=true npm run test:unit

# Integration tests only (starts server on random port)
SEED_DEMO=true USE_MOCK=true npm run test:integration
```

The test suite includes:
- **Unit tests**: risk scoring, anomaly detection, ZKP proofs, database CRUD, mock blockchain
- **Integration tests**: full API endpoint testing with supertest (auth flows, token management, MFA, OAuth, DIDs)

#### Run E2E Attack Simulations

```bash
# Start the server first
cd policy-engine
SEED_DEMO=true USE_MOCK=true node server.js &

# Run 7 attack scenarios (12 total tests)
node test/attack-scenarios.js
```

Scenarios tested:

1. **Brute Force** -- 5 failed passwords escalate the attempt score
2. **Stolen Credentials + Unknown Device** -- Smart contract blocks unregistered device
3. **Location Anomaly** -- Foreign country triggers MFA step-up
4. **Off-Hours Access** -- Login outside normal hours with registered device
5. **Suspended Account** -- Non-existent/suspended user denied
6. **Privilege Escalation** -- Viewer role denied delete permission (RBAC)
7. **Cumulative Risk** -- Unknown device + foreign country + off-hours = R=0.90, denied

### 9.5 View Audit Log

```bash
curl http://localhost:4000/audit-log | python3 -m json.tool
```

Each entry contains: `txId`, `userId`, `deviceId`, `riskScore`, `decision`, `reason`, `timestamp`.

### 9.6 Teardown

```bash
cd fabric-network
bash scripts/teardown.sh
```

---

## 10. API Reference

### Core Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/evaluate` | POST | Full authentication + risk scoring + blockchain authorization |
| `/verify-token` | POST | Verify JWT access token validity |
| `/refresh-token` | POST | Exchange refresh token for new access token |
| `/logout` | POST | Revoke refresh token |

### OAuth 2.0 / OIDC

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OIDC Discovery document |
| `/oauth/.well-known/jwks.json` | GET | JSON Web Key Set (public keys) |
| `/oauth/authorize` | GET/POST | Authorization endpoint (consent + code) |
| `/oauth/token` | POST | Token exchange (code -> tokens) |
| `/oauth/userinfo` | GET | User profile (Bearer token required) |

### MFA

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mfa/enroll` | POST | Enroll user in TOTP MFA (returns QR code) |
| `/mfa/verify` | POST | Verify standalone TOTP code |
| `/mfa/challenge` | POST | Complete MFA step-up challenge |
| `/mfa/status/:username` | GET | Check MFA enrollment status |

### WebAuthn / FIDO2

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/webauthn/register/options` | POST | Begin passkey registration |
| `/webauthn/register/verify` | POST | Complete passkey registration |
| `/webauthn/login/options` | POST | Begin passwordless login |
| `/webauthn/login/verify` | POST | Complete passwordless login |
| `/webauthn/status/:username` | GET | Check passkey status |

### W3C DID / Verifiable Credentials

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/did/create` | POST | Create a new DID for a user |
| `/did/resolve/:did` | GET | Resolve DID Document |
| `/did/list` | GET | List all registered DIDs |
| `/did/credential/issue` | POST | Issue a Verifiable Credential |
| `/did/credential/verify/:id` | GET | Verify a Verifiable Credential |

### Zero-Knowledge Proofs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/zkp/prove` | POST | Generate ZKP range proof |
| `/zkp/verify` | POST | Verify ZKP range proof |

### Anomaly Detection

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/anomaly/profile/:username` | GET | Get user's behavioral profile |
| `/anomaly/detect` | POST | Detect anomalies for a given context |

### Audit

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/audit-log` | GET | Get all blockchain audit entries |

---

## 11. Attack Simulations

The system defends against the following attack vectors:

### 11.1 Credential Theft / Phishing

**Attack**: Attacker obtains valid username/password through phishing.

**Defense layers**:
- Layer 1: Unknown device (d_score = 1) increases risk by 0.40
- Layer 1: Anomalous location and time further increase risk
- Layer 1: ML anomaly detector flags location/device novelty
- Layer 2: Smart contract rejects unregistered device
- MFA: Step-up authentication blocks even if risk is below threshold

### 11.2 Credential Stuffing / Brute Force

**Attack**: Automated tools try thousands of stolen credential pairs.

**Defense layers**:
- Layer 1: Failed attempt counter escalates a_score (5 failures = max score)
- Layer 1: Anomaly detector's frequency signal detects rapid-fire logins
- Layer 1: bcrypt's 250ms per hash makes brute force economically impractical

### 11.3 Session Hijacking

**Attack**: Attacker steals JWT access token from compromised client.

**Defense layers**:
- 15-minute token expiry limits the attack window
- Refresh tokens are server-side revocable (immediate logout)
- Token replay from a different device/location triggers anomaly detection

### 11.4 Insider Privilege Escalation

**Attack**: Low-privilege user attempts high-privilege operation.

**Defense layers**:
- Layer 2: RBAC enforced by smart contract (viewer cannot delete)
- Immutable audit log captures every escalation attempt
- MFA step-up required for sensitive operations

### 11.5 Impossible Travel Attack

**Attack**: Compromised credentials used from a distant location shortly after legitimate use.

**Defense layers**:
- ML anomaly detector: different country in < 2 hours = impossible travel (score = 1.0)
- Risk score adjustment pushes combined score over threshold

### 11.6 Man-in-the-Middle

**Attack**: Attacker intercepts and replays authentication tokens.

**Defense layers**:
- WebAuthn: Origin-bound credentials prevent use on different domains
- OAuth: Single-use authorization codes prevent replay
- TOTP: Time-limited codes (30-second window) prevent delayed replay

---

## 12. Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Frontend | HTML, CSS, JavaScript | Login UI, session management |
| Web Server | Node.js, Express | Static serving, API proxying |
| Policy Engine | Node.js, Express | Authentication, risk scoring, orchestration |
| Database | SQLite via better-sqlite3 (WAL mode) | Persistent storage for all state (users, tokens, MFA, DIDs, WebAuthn, anomaly profiles) |
| Password Hashing | bcrypt (configurable cost factor) | Adaptive password storage |
| Session Tokens | JSON Web Tokens (HS256/RS256) | Stateless session management |
| OAuth / OIDC | Custom (RS256, JWKS, DB-persisted keys) | Delegated authorization, identity federation |
| MFA | otplib (TOTP, RFC 6238) | Time-based one-time passwords |
| Passwordless | @simplewebauthn/server (FIDO2) | WebAuthn passkey management |
| Decentralized Identity | Custom W3C DID resolver | Self-sovereign identity |
| Anomaly Detection | Custom ML (Welford's algorithm) | Behavioral baseline + deviation scoring |
| Zero-Knowledge Proofs | Custom (Pedersen commitments) | Privacy-preserving risk verification |
| Structured Logging | Pino + pino-pretty | JSON structured logs with request tracing |
| Security Middleware | Helmet + express-rate-limit | HTTP hardening, rate limiting, input validation |
| Input Validation | Joi | Schema-based request validation |
| Configuration | dotenv + centralized config.js | Environment-driven config with production enforcement |
| Testing | Jest + supertest | Unit tests, integration tests, ESM compatibility |
| Blockchain | Hyperledger Fabric 2.5.12 | Permissioned ledger, smart contracts |
| Smart Contract | JavaScript (fabric-contract-api) | On-chain authorization + audit |
| Blockchain SDK | @hyperledger/fabric-gateway | gRPC client for Fabric |
| Chaincode Deployment | CCaaS (Chaincode-as-a-Service) | External chaincode builder |
| Container Runtime | Docker, Docker Compose | Fabric infrastructure |
| World State DB | LevelDB (embedded in peer) | Key-value state storage |
| Consensus | Raft (single orderer) | Transaction ordering |
| Crypto Material | cryptogen (X.509 certificates) | PKI for Fabric identities |

---

## 13. Production Architecture

### 13.1 Database-Backed State (No Split-Brain)

All application state is persisted in a single SQLite database (`data/iam.db`) using WAL (Write-Ahead Logging) mode for concurrent read performance. No module uses in-memory Maps for state -- every record is the database's single source of truth:

| Table | Purpose |
|-------|---------|
| `users` | User accounts with bcrypt password hashes and roles |
| `signing_keys` | JWT and OAuth RSA keys (persisted across restarts) |
| `refresh_tokens` | Active refresh tokens with expiry tracking |
| `revoked_tokens` | Revoked access/refresh tokens |
| `mfa_secrets` | TOTP shared secrets per user |
| `mfa_challenges` | Active MFA step-up challenges with TTL |
| `oauth_clients` | Registered OAuth 2.0 clients |
| `oauth_codes` | Single-use authorization codes |
| `dids` | W3C DID Documents |
| `verifiable_credentials` | W3C Verifiable Credentials |
| `webauthn_credentials` | FIDO2 public keys, counters, transports |
| `webauthn_challenges` | Active WebAuthn registration/login challenges |
| `anomaly_profiles` | Per-user behavioral baselines (Welford statistics) |
| `failed_attempts` | Per-user failed login counters |

A background cleanup job (configurable via `CLEANUP_INTERVAL_MS`, default 5 minutes) purges expired tokens, challenges, and authorization codes.

### 13.2 Configuration Enforcement

The `config.js` module centralizes all tunable parameters. In production (`NODE_ENV=production`):

- `requireEnv()` enforces that `JWT_SECRET`, `JWT_REFRESH_SECRET`, and `OAUTH_DEFAULT_CLIENT_SECRET` are set via environment variables. The server will crash at startup with a `FATAL` error if any are missing.
- Demo data seeding (`SEED_DEMO`) is ignored in production mode regardless of its value.
- All AHP risk weights, thresholds, rate limits, token expiries, and Fabric connection parameters are overridable via environment variables.

### 13.3 Structured Logging

All modules use `pino` for structured JSON logging (configured via `logger.js`). Request-level logging is handled by middleware that logs method, URL, status code, and response time. Log level is controlled via `LOG_LEVEL` environment variable.

### 13.4 Security Middleware Stack

Every request passes through the following middleware chain (defined in `middleware.js`):

1. **Helmet** -- Sets secure HTTP headers (CSP, HSTS, X-Frame-Options, etc.)
2. **Global rate limiter** -- 30 requests per minute per IP (configurable)
3. **Auth rate limiter** -- 10 requests per minute on `/evaluate` and `/oauth/token` (configurable)
4. **JWT authentication** (`requireAuth`) -- Validates Bearer tokens on protected endpoints
5. **RBAC enforcement** (`requireRole`) -- Checks role-based permissions
6. **Input validation** (`validate`) -- Joi schema validation on request bodies
7. **Error handler** -- Catches unhandled errors, returns sanitized responses

### 13.5 Test Pyramid

| Layer | Count | Tool | What It Covers |
|-------|-------|------|----------------|
| Unit | ~85 | Jest | Risk scoring, anomaly detection, ZKP proofs, database CRUD, mock blockchain |
| Integration | ~6 | Jest + supertest | Full API flows (auth, tokens, MFA, OAuth, DIDs) with isolated test DB |
| E2E | 12 | Node.js + fetch | 7 attack scenarios against a running server |

Tests use isolated SQLite databases (`:memory:` or temp files) and random ports to avoid conflicts with running servers.

---

## 14. Troubleshooting

**Chaincode container exits immediately**
Check logs: `docker logs iam-chaincode`. The `CHAINCODE_ID` env var must match the installed package ID. Re-run `deploy-chaincode.sh`.

**Policy engine can't connect to peer**
Ensure the Fabric network is running (`docker ps` should show orderer + peer + iam-chaincode). The policy engine connects to `localhost:7051`.

**"User not found" on blockchain but credentials work**
Run `InitLedger` to seed the world state:
```bash
docker exec cli peer chaincode invoke -o orderer.example.com:7050 --tls \
  --cafile /opt/gopath/src/.../tlsca.example.com-cert.pem \
  -C iamchannel -n iam-cc --peerAddresses peer0.org1.example.com:7051 \
  --tlsRootCertFiles /opt/gopath/src/.../ca.crt \
  -c '{"function":"InitLedger","Args":[]}'
```

**Port conflicts**
The system uses ports 3000, 4000, 7050, 7051, 7053, 9443, 9444, 9999. Ensure these are free.

**MFA codes not working**
Ensure your system clock is synchronized. TOTP codes are time-sensitive (30-second windows). Use `timedatectl` to check/fix clock synchronization.

**bcrypt slow on first login**
This is by design. bcrypt with cost factor 12 takes ~250ms per hash verification. This is the security trade-off that makes brute force impractical.

**WebAuthn only works on localhost**
WebAuthn requires a secure context (HTTPS or localhost). For non-localhost deployments, configure TLS certificates.

**"FATAL: Environment variable X is required in production mode"**
Set the required secrets before starting in production. Generate them with:
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

**"User not found" when SEED_DEMO is not set**
Without `SEED_DEMO=true`, no demo users are created. Register users through the API or set `SEED_DEMO=true` for development.

**Tests fail with "EADDRINUSE :4000"**
A server is already running on port 4000. Integration tests automatically use a random port (`PORT=0`), but E2E tests (`attack-scenarios.js`) expect port 4000. Stop the running server or set a different port.

**Jest ESM errors ("Unexpected token export")**
The project includes `jest.config.js` with `transformIgnorePatterns` for ESM-only packages (`uuid`, `otplib`, `@scure`, `@noble`, `@simplewebauthn`, `cbor-x`). If adding new ESM dependencies, add them to the transform ignore pattern.

---

## References

1. NIST SP 800-207: Zero Trust Architecture (2020)
2. Saaty, T.L. "The Analytic Hierarchy Process" (1980)
3. Provos, N. & Mazieres, D. "A Future-Adaptable Password Scheme" (USENIX, 1999) -- bcrypt
4. RFC 6749: The OAuth 2.0 Authorization Framework (2012)
5. OpenID Connect Core 1.0 (2014)
6. RFC 6238: TOTP: Time-Based One-Time Password Algorithm (2011)
7. W3C DID Core v1.0: Decentralized Identifiers (2022)
8. W3C Verifiable Credentials Data Model v1.1 (2022)
9. WebAuthn Level 2: Web Authentication (W3C, 2021)
10. FIDO2: Client to Authenticator Protocol (CTAP2, FIDO Alliance)
11. Pedersen, T.P. "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing" (CRYPTO, 1991)
12. Fiat, A. & Shamir, A. "How to Prove Yourself" (CRYPTO, 1986) -- Fiat-Shamir heuristic
13. Welford, B.P. "Note on a Method for Calculating Corrected Sums of Squares and Products" (Technometrics, 1962)
14. Hyperledger Fabric Documentation v2.5 (hyperledger-fabric.readthedocs.io)
15. Androulaki, E. et al. "Hyperledger Fabric: A Distributed Operating System for Permissioned Blockchains" (EuroSys, 2018)
