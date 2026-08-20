# ZeroTrust IAM — Core Functionalities (Simple Guide)

This document explains **what the system does** in plain language.  
It is written for operators, developers, and anyone who needs the big picture without deep protocol jargon.

---

## 1. What is this project?

**ZeroTrust IAM** is an identity and access management system. It answers:

- **Who** is trying to use the service?
- **From which browser/device?**
- **How risky does this look right now?**
- **Is this allowed by policy?**
- **Can we prove and audit the decision later?**

Unlike old “login once and trust forever” systems, **every access decision is re-checked** with context (device, location, behaviour, role). Important decisions are also recorded on **Hyperledger Fabric** so the audit trail is hard to tamper with.

### Main pieces

| Piece | Simple job |
|--------|------------|
| **Web app** (port 3000) | Login page + admin console + account self-service |
| **Policy engine** | Brain: password, risk, MFA, policies, APIs |
| **Postgres** | Users, devices, sessions, local audit, MFA secrets |
| **Hyperledger Fabric** | On-chain user registry + immutable authorization/audit |
| **ML service** | Helps score “how unusual is this login?” |
| **Redis** | Rate limiting / lockout helpers (when enabled) |

---

## 2. Sign-in and access decisions

### 2.1 Login

1. User enters **username + password**.
2. Browser sends a **private device credential** automatically (not a free-text “device ID” field).
3. Policy engine:
   - Checks password (hashed; never stored plain).
   - Scores **risk** (device known? location? time? failed attempts? ML/anomaly?).
   - Checks **Fabric** (user active? device registered? permissions?).
4. Outcome:
   - **ALLOW** — session cookies set (HttpOnly).
   - **MFA required** — enter 6-digit authenticator code (if enrolled).
   - **DENY** — safe message only (no raw risk scores shown to users).

### 2.2 Risk scoring (behind the scenes)

Risk is computed on the server from signals such as:

- Unknown vs trusted device  
- Location vs usual location  
- Time of day vs normal hours  
- Failed password attempts  
- ML / anomaly models (when available)  

**Important:** end users **do not** see raw risk numbers (0.13, factor breakdowns, etc.).  
They only see a decision and a clear, safe message. Admins may see risk in the **Audit log**.

### 2.3 Sessions

After ALLOW:

- Short-lived **access** cookie  
- Longer **refresh** cookie (for renewal)  
- User can list/revoke sessions under **Account → Sessions**  
- Admin can revoke all sessions for a user  

### 2.4 Fail-closed on Fabric outage

If the blockchain authorization path is down, production mode **denies** access rather than “allowing offline.”  
That is intentional Zero Trust behaviour.

---

## 3. Devices (trusted browsers)

### 3.1 What a “device” is

A device is a **private browser credential** (UUID stored in the browser).  
Users do **not** type or invent device IDs on the login form.

### 3.2 How devices get trusted

- **Auto-enrol** (depending on `DEVICE_ENROLL_MODE`): first device, or after password when risk is acceptable.  
- **Trust this browser** on **Account → Devices**.  
- Admin can also register devices via API if needed.

### 3.3 What users can do

On **Account → Devices**:

- See registered credentials  
- See **last seen**, **location**, **current browser**  
- **Revoke** unknown devices  
- **Trust this browser**  

Revoking a device means future logins from that browser need re-verification.

---

## 4. Multi-factor authentication (MFA)

### 4.1 TOTP (authenticator app)

- User enrols under **Account → Security** (scan QR with Google/Microsoft Authenticator, Authy, etc.).  
- **Samsung Pass** often only stores an entry and does **not** show 6-digit codes — use a real TOTP app.  
- User can **Remove** MFA and re-enrol.  
- MFA is **not** asked on every login. It is **step-up** when:
  - risk is high enough, or  
  - the action is sensitive (e.g. write / delete / manage).

### 4.2 Passkeys / WebAuthn

- Optional hardware/browser-bound passkeys on **Security**.  
- Registration uses the **logged-in session** (no password re-entry for options).  
- Works on `localhost` / HTTPS browsers that support WebAuthn.

---

## 5. Admin console (Governance)

Admins (e.g. `alice`) use the left sidebar **Governance** section.

### 5.1 Overview

Dashboard: active/suspended users, devices, sessions, recent audit volume, system health (ML, risk threshold, enroll mode).  
Quick links and a short hire → leave lifecycle cheat sheet.

### 5.2 Users (lifecycle)

| Action | Meaning |
|--------|---------|
| **New user** | Create account (username, temp password, role, optional email/phone) |
| **Details** | Profile, devices, sessions, Fabric status |
| **Suspend / Activate** | Lock or unlock sign-in |
| **Revoke sessions** | Force logout everywhere |
| **Reset password** | Set temporary password; sessions revoked |
| **Evict** | Soft-delete / redact PII (GDPR-style); cannot sign in again |
| **Revoke device** | Unbind one device credential |

**Dual-write:** create/status changes go to **Postgres + Fabric** when the chain is available.

**Notifications:** if email/phone are set, lifecycle events can notify the user (email/SMS or log mode).

### 5.3 Audit log

Admin view of decisions and admin events:

- When, who, decision, risk (admin only), reason, layer, device, transaction id  
- Filters and CSV export  
- Optional feedback labels for ML training  

### 5.4 Policies

On-chain / engine **public parameters**, for example:

- Risk threshold (when to DENY)  
- MFA step-up threshold  
- Access-grant TTL  
- ZKP-related flags  

Changes can be submitted on-chain and audited.

### 5.5 ML Models

Champion/challenger risk model lifecycle:

- Model info, metrics  
- Comparison, drift (when data exists)  
- Promote / rollback candidates  

---

## 6. Account self-service (every user)

| Page | Purpose |
|------|---------|
| **Security** | Change password, TOTP, passkeys, recent access decisions |
| **Devices** | Trusted browsers |
| **Sessions** | Active logins; revoke others |
| **My Data** | GDPR export download; erase account |

### 6.1 Download my data (GDPR Art. 15)

Generates a JSON archive of profile, devices, login history, MFA metadata (no secrets), WebAuthn public keys, audit entries.

### 6.2 Erase my account (GDPR Art. 17)

Soft-deletes operational PII, revokes sessions, redacts audit fields to tombstones.  
Admin accounts need an extra confirmation. On-chain hashes remain for integrity/fraud obligations.

---

## 7. Enterprise / platform capabilities

### 7.1 Roles and permissions

Typical roles: **admin**, **editor**, **viewer**.  
Login can request a permission (read / write / delete / manage).  
Smart contracts enforce RBAC and device registration on chain.

### 7.2 Federation (SSO)

SAML / OIDC so corporate IdPs (Okta, Azure AD, etc.) can sign users in.  
Users can be **just-in-time** provisioned on first SSO login.

### 7.3 SCIM

Automated user create/update/deactivate from HR or identity providers.

### 7.4 Multi-tenancy & billing

Tenants, plans, optional Stripe checkout/portal (for SaaS packaging).

### 7.5 External policy (PDP)

Optional OPA / Cedar / Amazon Verified Permissions for extra allow/forbid rules.

### 7.6 ABAC

Attribute-based policies (e.g. forbid suspended users, time-based rules).

### 7.7 OAuth 2.0 / OpenID Connect

Policy engine can act as an authorization server for apps (authorize, token, userinfo, JWKS).

### 7.8 W3C DIDs & credentials (advanced)

Optional decentralized identifiers and verifiable credentials for research/demo flows.

### 7.9 Zero-knowledge proofs (experimental)

Optional experimental risk proofs; **not** the main production security boundary unless explicitly enabled.

### 7.10 Account lockout & password policy

Failed logins can lock accounts temporarily.  
Passwords must meet length/complexity rules (and not contain the username).

### 7.11 Notifications

Admin lifecycle events can send **email** (SMTP) and/or **SMS** (Twilio), or **log** in local mode:

- User onboarded  
- Suspended / activated  
- Sessions revoked  
- Password reset  
- Account evicted  

---

## 8. Security design principles (simple)

| Principle | How we apply it |
|-----------|------------------|
| Never trust by default | Every login is re-evaluated |
| Don’t show risk numbers to users | Prevents gaming and leakage |
| Device trust is machine-bound | No editable device ID on login |
| Dual source of truth | Postgres for ops + Fabric for registry/audit |
| Fail closed | Fabric down → deny access |
| Least privilege | Roles + permissions + step-up MFA |
| Auditability | Local + on-chain decision records |
| Privacy | Export/erase self-service; redacted tombstones |

---

## 9. Typical workflows

### New employee

1. Admin → **Users → New user** (role + temp password + email/phone).  
2. User gets notified (if configured).  
3. User signs in; browser credential binds.  
4. User optionally enrols MFA on **Security**.  

### Day-to-day login

1. Password + automatic device credential.  
2. Risk + Fabric check.  
3. MFA only if step-up required.  
4. Session issued.  

### Lost laptop

1. User or admin **revokes** that device.  
2. Admin may **revoke all sessions** and **reset password**.  

### Employee leaves

1. **Suspend** (immediate no-login).  
2. **Revoke sessions**.  
3. **Evict** when ready (PII redacted).  

### Investigate an incident

1. **Audit log** — who, when, decision, reason, risk, layer, tx.  
2. User **Security → Recent access decisions** for a personal view (no raw risk).  

---

## 10. What is *not* core product behaviour

- Public self-signup as the main path (admin / SCIM / SSO are primary).  
- User-typed device IDs on login.  
- Showing ensemble risk scores to end users.  
- Allowing access when Fabric authorization is unavailable (production fail-closed).  
- Relying on Samsung Pass for TOTP codes (use Google/Microsoft Authenticator, Authy, Aegis, etc.).

---

## 11. Where things live in the UI

| URL | Who | Purpose |
|-----|-----|---------|
| `/` | Everyone | Login |
| `/admin` | Admin | Overview dashboard |
| `/admin/users` | Admin | User lifecycle |
| `/admin/audit` | Admin | Audit log |
| `/admin/policies` | Admin | Policy parameters |
| `/admin/models` | Admin | ML model lifecycle |
| `/me/security` | User | Password, MFA, history |
| `/me/devices` | User | Trusted browsers |
| `/me/sessions` | User | Active sessions |
| `/me/data` | User | Export / erase |

---

## 12. One-sentence summary

**ZeroTrust IAM verifies every sign-in with password, device, risk, and on-chain policy; issues secure sessions; lets admins manage people and policies; lets users manage security and privacy; and keeps a durable audit trail—without exposing risk scores or fake device IDs to end users.**

---

## Related deeper docs

| File | Topic |
|------|--------|
| `docs/README.md` | Full technical / academic overview |
| `docs/SECURITY.md` | Security posture |
| `docs/OPERATIONS.md` | Runbooks |
| `docs/FEDERATION.md` | SSO |
| `docs/MULTI_TENANCY.md` | Tenants |
| `docs/BILLING.md` | Stripe / plans |
| `docs/EXTERNAL_PDP.md` | External policy engines |
| `docs/THREAT_MODEL.md` | Threats |
| `docs/SLO_AND_FAILURE_MODES.md` | Reliability / fail modes |

---

*Last updated to match the running stack: web console, dual-write provisioning, opaque devices, risk redaction, admin lifecycle, notifications, GDPR export/erase, Fabric fail-closed, MFA/passkeys, and audit/device UI fixes.*
