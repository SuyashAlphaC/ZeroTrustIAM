# ZeroTrustIAM — Ablation Study Report (v2)

> Generated: 2026-05-18T15:06:05.985Z
> Harness: `test/ablation-study.js` (isolated child processes, Fabric test mode, PostgreSQL test DB)
> Revision: v2 — consistent regression counter, ML-on baseline, evasion scenarios, warm anomaly profiles, FP/FN metrics.

## 1. Objective

This study quantifies the contribution of each major security component by **systematically removing or disabling** it and measuring the change in access decisions across thirteen canonical scenarios (ten standard plus three evasion scenarios).

## 2. Methodology

| Aspect | Setting |
|--------|---------|
| **Decision simulator** | Mirrors `policy-engine/server.js` evaluate pipeline (credentials → ensemble risk → policy threshold → MFA step-up → Fabric mock) |
| **Blockchain** | `FABRIC_TEST_MODE=true` (in-process mock chaincode with 4-rule RBAC) except `no_blockchain` (passthrough ALLOW) |
| **Database** | Fresh PostgreSQL per config (`truncateTestData` + `SEED_DEMO`) |
| **Anomaly warm-up** | 30 days of synthetic logins per user written before scenarios run (Fix 6) |
| **Baseline** | `baseline` config: AHP + ML + anomaly ensemble, MFA + blockchain mock + ZKP on |
| **ML default** | ML sidecar **enabled** in every config (Fix 2); `no_ml`, `ahp_only` opt out explicitly |
| **Regression counter** | Hard = DENY→ALLOW; Soft = DENY→MFA *or* MFA→ALLOW (Fix 1) |
| **FP / FN rates** | FP = ALLOW-expected ended in MFA or DENY; FN = DENY/MFA-expected ended in ALLOW (Fix 7) |

### 2.1 Scenarios

| ID | Category | Baseline expected |
|----|----------|-------------------|
| legitimate_login | benign | **ALLOW** |
| wrong_password | attack | **DENY** |
| unknown_user | attack | **DENY** |
| stolen_creds_unknown_device | attack | **DENY** |
| foreign_country | risk | **MFA_REQUIRED** |
| off_hours | risk | **ALLOW** |
| privilege_escalation | attack | **DENY** |
| cumulative_high_risk | attack | **DENY** |
| post_bruteforce_login | risk | **ALLOW** |
| same_country_different_city | risk | **ALLOW** |
| evasion_perfect_mimic | **evasion** | **ALLOW** |
| evasion_normal_hours_foreign_country | **evasion** | **MFA_REQUIRED** |
| evasion_credential_stuffing_known_device | **evasion** | **DENY** |

Evasion scenarios are deliberately adversarial: they are crafted to defeat at least one detection layer, and their `baselineExpected` reflects what the full ensemble *should* do — not what the attacker hopes for. `evasion_perfect_mimic` legitimately expects ALLOW because contextual signals cannot catch a credential thief who has also stolen the device; documenting it makes the ceiling of behaviour-based detection explicit and motivates hardware factors (WebAuthn).

## 3. Configuration Summary

| Config | Matches | Hard sec Δ | Soft sec Δ | Fric Δ | Attack block | FP rate | FN rate |
|--------|---------|------------|------------|--------|--------------|---------|---------|
| `baseline` | 12/13 | 0 | 0 | +1 | 100% | 20% | 0% |
| `no_ml` | 13/13 | 0 | 0 | 0 | 100% | 0% | 0% |
| `no_anomaly` | 13/13 | 0 | 0 | 0 | 100% | 0% | 0% |
| `ahp_only` | 13/13 | 0 | 0 | 0 | 100% | 0% | 0% |
| `ml_only` | 11/13 | 0 | 0 | +2 | 100% | 40% | 0% |
| `no_blockchain` | 10/13 | 0 | **+2** | +1 | 60% | 20% | 0% |
| `no_policy_threshold` | 12/13 | 0 | 0 | +1 | 100% | 20% | 0% |
| `no_mfa` | 11/13 | 0 | **+2** | 0 | 100% | 0% | 25% |
| `no_zkp` | 12/13 | 0 | 0 | +1 | 100% | 20% | 0% |
| `ablate_device` | 12/13 | 0 | 0 | +1 | 100% | 20% | 0% |
| `ablate_location` | 11/13 | 0 | **+2** | 0 | 100% | 0% | 25% |
| `ablate_time` | 12/13 | 0 | 0 | +1 | 100% | 20% | 0% |
| `ablate_attempts` | 12/13 | 0 | 0 | +1 | 100% | 20% | 0% |
| `with_ml` | 12/13 | 0 | 0 | +1 | 100% | 20% | 0% |
| `with_decision_cache` | 12/13 | 0 | 0 | +1 | 100% | 20% | 0% |

Read this table top-down: any non-zero in the *Hard sec Δ* column is a security regression where an attack that should have been DENIED was ALLOWED. *Soft sec Δ* captures the in-between outcomes (DENY→MFA or MFA→ALLOW). *FP rate* is the share of ALLOW-expected scenarios that picked up friction; *FN rate* is the share of attack-or-risk scenarios that slipped through to ALLOW.

## 4. Detailed Results by Configuration

### `baseline` — Full system (baseline)

AHP + ML ensemble + behavioral anomaly + Fabric smart contract + MFA step-up + ZKP

- Risk threshold: 0.6 | MFA step-up: 0.3
- Ensemble weights: AHP=0.4, ML=0.4, anomaly=0.2
- AHP weights: device=0.4, location=0.3, time=0.2, attempts=0.1
- ML sidecar configured: `true` · actually reachable: `true`

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.10 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.56 | ✓ |
| foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.39 | ✓ |
| off_hours | ALLOW | ALLOW | 0.19 | ✓ |
| privilege_escalation | DENY | DENY | 0.19 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.85 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.14 | ✓ |
| same_country_different_city | ALLOW | MFA_REQUIRED | 0.31 | FRIC↑ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.10 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.38 | ✓ |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.69 | ✓ |

### `no_ml` — Without ML Random Forest

Disables Python RF sidecar; ensemble redistributes ML weight to AHP + anomaly

- Risk threshold: 0.6 | MFA step-up: 0.3
- Ensemble weights: AHP=0.4, ML=0.4, anomaly=0.2
- AHP weights: device=0.4, location=0.3, time=0.2, attempts=0.1
- ML sidecar configured: `false`

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.00 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.31 | ✓ |
| foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.37 | ✓ |
| off_hours | ALLOW | ALLOW | 0.04 | ✓ |
| privilege_escalation | DENY | DENY | 0.03 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.80 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.07 | ✓ |
| same_country_different_city | ALLOW | ALLOW | 0.23 | ✓ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.06 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.35 | ✓ |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.46 | ✓ |

### `no_anomaly` — Without behavioral anomaly

Anomaly signal still computed but receives zero ensemble weight (AHP + ML only)

- Risk threshold: 0.6 | MFA step-up: 0.3
- Ensemble weights: AHP=0.5, ML=0.5, anomaly=0
- AHP weights: device=0.4, location=0.3, time=0.2, attempts=0.1
- ML sidecar configured: `true` · actually reachable: `true`

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.12 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.68 | ✓ |
| foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.38 | ✓ |
| off_hours | ALLOW | ALLOW | 0.23 | ✓ |
| privilege_escalation | DENY | DENY | 0.22 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.92 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.17 | ✓ |
| same_country_different_city | ALLOW | ALLOW | 0.29 | ✓ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.12 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.37 | ✓ |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.74 | ✓ |

### `ahp_only` — AHP contextual scoring only

Rule-based AHP weights only; no ML and no anomaly blend

- Risk threshold: 0.6 | MFA step-up: 0.3
- Ensemble weights: AHP=1, ML=0, anomaly=0
- AHP weights: device=0.4, location=0.3, time=0.2, attempts=0.1
- ML sidecar configured: `false`

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.00 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.42 | ✓ |
| foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.32 | ✓ |
| off_hours | ALLOW | ALLOW | 0.02 | ✓ |
| privilege_escalation | DENY | DENY | 0.00 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.90 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.10 | ✓ |
| same_country_different_city | ALLOW | ALLOW | 0.15 | ✓ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.00 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.30 | ✓ |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.55 | ✓ |

### `ml_only` — ML sidecar scoring only

ML Random Forest signal alone (no AHP, no anomaly). Probes the contribution of the learned model in isolation

- Risk threshold: 0.6 | MFA step-up: 0.3
- Ensemble weights: AHP=0, ML=1, anomaly=0
- AHP weights: device=0.4, location=0.3, time=0.2, attempts=0.1
- ML sidecar configured: `true` · actually reachable: `true`

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.24 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.93 | ✓ |
| foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.43 | ✓ |
| off_hours | ALLOW | MFA_REQUIRED | 0.43 | FRIC↑ |
| privilege_escalation | DENY | DENY | 0.43 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.93 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.24 | ✓ |
| same_country_different_city | ALLOW | MFA_REQUIRED | 0.43 | FRIC↑ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.24 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.43 | ✓ |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.93 | ✓ |

### `no_blockchain` — Without blockchain enforcement

Policy engine + risk scoring active; smart-contract checks bypassed (passthrough ALLOW)

- Risk threshold: 0.6 | MFA step-up: 0.3
- Ensemble weights: AHP=0.4, ML=0.4, anomaly=0.2
- AHP weights: device=0.4, location=0.3, time=0.2, attempts=0.1
- ML sidecar configured: `true` · actually reachable: `true`
- **Blockchain ablation:** passthrough

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.10 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | MFA_REQUIRED | 0.56 | *soft sec↓* |
| foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.39 | ✓ |
| off_hours | ALLOW | ALLOW | 0.19 | ✓ |
| privilege_escalation | DENY | MFA_REQUIRED | 0.19 | *soft sec↓* |
| cumulative_high_risk | DENY | DENY | 0.85 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.14 | ✓ |
| same_country_different_city | ALLOW | MFA_REQUIRED | 0.31 | FRIC↑ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.10 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.38 | ✓ |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.69 | ✓ |

### `no_policy_threshold` — Without policy-engine risk gate

RISK_THRESHOLD raised so off-chain gate never denies on score alone

- Risk threshold: 2 | MFA step-up: 0.3
- Ensemble weights: AHP=0.4, ML=0.4, anomaly=0.2
- AHP weights: device=0.4, location=0.3, time=0.2, attempts=0.1
- ML sidecar configured: `true` · actually reachable: `true`

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.10 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.56 | ✓ |
| foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.39 | ✓ |
| off_hours | ALLOW | ALLOW | 0.19 | ✓ |
| privilege_escalation | DENY | DENY | 0.19 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.85 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.14 | ✓ |
| same_country_different_city | ALLOW | MFA_REQUIRED | 0.31 | FRIC↑ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.10 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.38 | ✓ |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.69 | ✓ |

### `no_mfa` — Without MFA step-up

MFA step-up threshold disabled; sensitive ops still evaluated by risk/blockchain

- Risk threshold: 0.6 | MFA step-up: 2
- Ensemble weights: AHP=0.4, ML=0.4, anomaly=0.2
- AHP weights: device=0.4, location=0.3, time=0.2, attempts=0.1
- ML sidecar configured: `true` · actually reachable: `true`

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.10 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.56 | ✓ |
| foreign_country | MFA_REQUIRED | ALLOW | 0.39 | *soft sec↓* |
| off_hours | ALLOW | ALLOW | 0.24 | ✓ |
| privilege_escalation | DENY | DENY | 0.19 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.85 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.14 | ✓ |
| same_country_different_city | ALLOW | ALLOW | 0.31 | ✓ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.13 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | ALLOW | 0.27 | *soft sec↓* |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.66 | ✓ |

### `no_zkp` — Without zero-knowledge proofs

ZKP generation disabled (decisions unchanged; audit privacy reduced)

- Risk threshold: 0.6 | MFA step-up: 0.3
- Ensemble weights: AHP=0.4, ML=0.4, anomaly=0.2
- AHP weights: device=0.4, location=0.3, time=0.2, attempts=0.1
- ML sidecar configured: `true` · actually reachable: `true`

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.10 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.56 | ✓ |
| foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.39 | ✓ |
| off_hours | ALLOW | ALLOW | 0.19 | ✓ |
| privilege_escalation | DENY | DENY | 0.19 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.85 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.14 | ✓ |
| same_country_different_city | ALLOW | MFA_REQUIRED | 0.31 | FRIC↑ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.10 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.38 | ✓ |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.69 | ✓ |

### `ablate_device` — Ablate device signal (w_device=0)

Removes device factor from AHP score — unknown device no longer raises R via rules

- Risk threshold: 0.6 | MFA step-up: 0.3
- Ensemble weights: AHP=0.4, ML=0.4, anomaly=0.2
- AHP weights: device=0, location=0.5, time=0.33, attempts=0.17
- ML sidecar configured: `true` · actually reachable: `true`

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.10 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.40 | ✓ |
| foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.48 | ✓ |
| off_hours | ALLOW | ALLOW | 0.20 | ✓ |
| privilege_escalation | DENY | DENY | 0.19 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.83 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.17 | ✓ |
| same_country_different_city | ALLOW | MFA_REQUIRED | 0.35 | FRIC↑ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.10 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.46 | ✓ |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.57 | ✓ |

### `ablate_location` — Ablate location signal (w_location=0)

Removes geographic anomaly from AHP score

- Risk threshold: 0.6 | MFA step-up: 0.3
- Ensemble weights: AHP=0.4, ML=0.4, anomaly=0.2
- AHP weights: device=0.57, location=0, time=0.29, attempts=0.14
- ML sidecar configured: `true` · actually reachable: `true`

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.10 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.63 | ✓ |
| foreign_country | MFA_REQUIRED | ALLOW | 0.28 | *soft sec↓* |
| off_hours | ALLOW | ALLOW | 0.24 | ✓ |
| privilege_escalation | DENY | DENY | 0.19 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.84 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.15 | ✓ |
| same_country_different_city | ALLOW | ALLOW | 0.25 | ✓ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.13 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | ALLOW | 0.15 | *soft sec↓* |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.67 | ✓ |

### `ablate_time` — Ablate time signal (w_time=0)

Removes off-hours factor from AHP score

- Risk threshold: 0.6 | MFA step-up: 0.3
- Ensemble weights: AHP=0.4, ML=0.4, anomaly=0.2
- AHP weights: device=0.5, location=0.38, time=0, attempts=0.12
- ML sidecar configured: `true` · actually reachable: `true`

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.10 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.60 | ✓ |
| foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.42 | ✓ |
| off_hours | ALLOW | ALLOW | 0.19 | ✓ |
| privilege_escalation | DENY | DENY | 0.19 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.85 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.15 | ✓ |
| same_country_different_city | ALLOW | MFA_REQUIRED | 0.33 | FRIC↑ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.10 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.41 | ✓ |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.74 | ✓ |

### `ablate_attempts` — Ablate failed-attempts signal (w_attempts=0)

Removes brute-force escalation from AHP score

- Risk threshold: 0.6 | MFA step-up: 0.3
- Ensemble weights: AHP=0.4, ML=0.4, anomaly=0.2
- AHP weights: device=0.44, location=0.33, time=0.22, attempts=0
- ML sidecar configured: `true` · actually reachable: `true`

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.10 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.57 | ✓ |
| foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.40 | ✓ |
| off_hours | ALLOW | ALLOW | 0.19 | ✓ |
| privilege_escalation | DENY | DENY | 0.19 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.89 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.10 | ✓ |
| same_country_different_city | ALLOW | MFA_REQUIRED | 0.32 | FRIC↑ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.10 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.39 | ✓ |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.71 | ✓ |

### `with_ml` — Full system with ML sidecar (strict)

Same as baseline but skipped entirely if ML sidecar is unavailable — for ML availability A/B

- Risk threshold: 0.6 | MFA step-up: 0.3
- Ensemble weights: AHP=0.4, ML=0.4, anomaly=0.2
- AHP weights: device=0.4, location=0.3, time=0.2, attempts=0.1
- ML sidecar configured: `true` · actually reachable: `true`

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.10 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.56 | ✓ |
| foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.39 | ✓ |
| off_hours | ALLOW | ALLOW | 0.19 | ✓ |
| privilege_escalation | DENY | DENY | 0.19 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.85 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.14 | ✓ |
| same_country_different_city | ALLOW | MFA_REQUIRED | 0.31 | FRIC↑ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.10 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.38 | ✓ |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.69 | ✓ |

### `with_decision_cache` — Full system with Redis decision cache

Runs each scenario twice; verifies repeat ALLOWs hit the cache (Tier A.5). Skipped if Redis unreachable.

- Risk threshold: 0.6 | MFA step-up: 0.3
- Ensemble weights: AHP=0.4, ML=0.4, anomaly=0.2
- AHP weights: device=0.4, location=0.3, time=0.2, attempts=0.1
- ML sidecar configured: `true` · actually reachable: `true`
- **Decision cache run:** 4/4 second-pass hits · decision consistency: ✓

| Scenario | Expected | Actual | Risk | Δ |
|----------|----------|--------|------|---|
| legitimate_login | ALLOW | ALLOW | 0.10 | ✓ |
| wrong_password | DENY | DENY | — | ✓ |
| unknown_user | DENY | DENY | — | ✓ |
| stolen_creds_unknown_device | DENY | DENY | 0.56 | ✓ |
| foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.39 | ✓ |
| off_hours | ALLOW | ALLOW | 0.19 | ✓ |
| privilege_escalation | DENY | DENY | 0.19 | ✓ |
| cumulative_high_risk | DENY | DENY | 0.85 | ✓ |
| post_bruteforce_login | ALLOW | ALLOW | 0.14 | ✓ |
| same_country_different_city | ALLOW | MFA_REQUIRED | 0.31 | FRIC↑ |
| evasion_perfect_mimic | ALLOW | ALLOW | 0.10 | ✓ |
| evasion_normal_hours_foreign_country | MFA_REQUIRED | MFA_REQUIRED | 0.38 | ✓ |
| evasion_credential_stuffing_known_device | DENY | DENY | 0.69 | ✓ |

## 5. Component Contribution Analysis

### 5.1 Defense-in-depth layer ablations

**Without blockchain (`no_blockchain`)** — Smart-contract RBAC + device registry bypassed.
- **stolen_creds_unknown_device**: DENY → **MFA_REQUIRED** (Step-up authentication required (risk=0.56))
- **privilege_escalation**: DENY → **MFA_REQUIRED** (Step-up authentication required (risk=0.19))

**Without policy risk gate (`no_policy_threshold`)** — Off-chain R ≥ 0.6 gate disabled (only blockchain + MFA enforce).
- No decision change vs baseline.

**Without MFA step-up (`no_mfa`)** — Step-up path removed; only risk-gate and blockchain remain.
- **foreign_country**: MFA_REQUIRED → **ALLOW** (All checks passed)
- **same_country_different_city**: MFA_REQUIRED → **ALLOW** (All checks passed)
- **evasion_normal_hours_foreign_country**: MFA_REQUIRED → **ALLOW** (All checks passed)

**Without ZKP (`no_zkp`)** — ZKP package generation skipped (audit privacy reduced).
- No decision change vs baseline.

### 5.2 AHP signal ablations

| Removed AHP signal | Decisions changed vs baseline |
|--------------------|-------------------------------|
| device | none |
| location | 3 |
| time | none |
| attempts | none |

### 5.3 Scoring model ablations (with ML-on baseline — Fix 2)

- **`with_ml` (strict ML-required)**: matches baseline 12/13. 0 scenario(s) show meaningfully different risk vs baseline.
- **`ml_only`**: 11/13 matches · attack block 100% · FP rate 40%. This is the ML signal in isolation — directly comparable to `ahp_only`.
- **`ahp_only`**: 13/13 matches · attack block 100% · FP rate 0%. Pure rule-based scoring.
- **`no_ml`**: 13/13 matches · graceful weight redistribution to AHP + anomaly when sidecar disabled.
- **`no_anomaly`**: 13/13 matches · AHP + ML only.

### 5.4 Evasion-scenario performance (Fix 4)

How each configuration handles the three adversarial scenarios:

| Config | evasion_perfect_mimic | evasion_normal_hours_foreign_country | evasion_credential_stuffing_known_device |
|--------|---|---|---|
| `baseline` | ALLOW | MFA_REQUIRED | DENY |
| `no_ml` | ALLOW | MFA_REQUIRED | DENY |
| `no_anomaly` | ALLOW | MFA_REQUIRED | DENY |
| `ahp_only` | ALLOW | MFA_REQUIRED | DENY |
| `ml_only` | ALLOW | MFA_REQUIRED | DENY |
| `no_blockchain` | ALLOW | MFA_REQUIRED | DENY |
| `no_policy_threshold` | ALLOW | MFA_REQUIRED | DENY |
| `no_mfa` | ALLOW | ALLOW | DENY |
| `no_zkp` | ALLOW | MFA_REQUIRED | DENY |
| `ablate_device` | ALLOW | MFA_REQUIRED | DENY |
| `ablate_location` | ALLOW | ALLOW | DENY |
| `ablate_time` | ALLOW | MFA_REQUIRED | DENY |
| `ablate_attempts` | ALLOW | MFA_REQUIRED | DENY |
| `with_ml` | ALLOW | MFA_REQUIRED | DENY |
| `with_decision_cache` | ALLOW | MFA_REQUIRED | DENY |

`evasion_perfect_mimic` is a control: every configuration *should* ALLOW it — the system has no signal left to refuse on. `evasion_normal_hours_foreign_country` and `evasion_credential_stuffing_known_device` are the meaningful ones.

## 6. Key Findings

1. **Largest security impact**: `no_blockchain` — 0 hard and 2 soft regression(s) vs baseline.
2. **Blockchain remains the load-bearing layer**: `no_blockchain` attack block rate 60%; baseline 100%.
3. **MFA step-up handles the geographic friction**: `no_mfa` FP rate 0% but FN rate 25% — risk scenarios slip through to ALLOW.
4. **AHP vs ML in isolation**: `ahp_only` attack-block 100%, FP 0% · `ml_only` attack-block 100%, FP 40%. The two signals are comparable in isolation; the ensemble is justified only if it does strictly better than either alone.
5. **Cost of enabling ML**: baseline FP rate 20% vs `no_ml` 0%. ML can be a friction-adder if it raises risk on benign cross-city/off-hour logins.
6. **Decision cache (`with_decision_cache`)**: 4/4 second-pass cache hits, consistency ✓. ALLOW-only caching policy preserves correctness.
7. **Evasion ceiling**: `evasion_perfect_mimic` ALLOWs across every configuration — behavioural detection has a finite ceiling and hardware-bound auth (WebAuthn passkeys) is the only remaining mitigation.
8. **ZKP** removal does not change any access decision (audit privacy only).

## 7. Components Verified by Other Test Suites

Some security features cannot be exercised through the evaluate-flow harness used by this study (they live inside the chaincode, the ml-service internals, or multi-step flows the simulator does not replay). They are listed here with pointers to the test suites that do cover them, so a reviewer can audit them in one pass.

| Component | Layer | Why this study cannot ablate it | Covered by |
|-----------|-------|--------------------------------|------------|
| audit_hash_chain | Tier A.4 — chaincode | Hash chain lives inside chaincode (`AuditChainHead`, `VerifyAuditChain`). Test harness uses Fabric test mode (in-process mock) which does not execute chaincode JS. | `chaincode/tests/auditChain.test.js` |
| replay_protection | Tier E.20 — chaincode | Nonce + freshness validation runs inside `_validateProofFreshness` in chaincode. Not reachable from the evaluate-flow mock. | `chaincode/tests/replayProtection.test.js` |
| refresh_token_reuse | Tier E.19 — policy-engine | Reuse detection fires on the /refresh-token endpoint, not on /evaluate. Requires a multi-step refresh flow this harness does not perform. | `policy-engine/__tests__/integration/refreshReuse.test.js` |
| champion_challenger | Tier B.7 — ml-service | Promotion gate is internal to the ML service. No access-decision delta to ablate. | `ml-service/tests/test_promoter.py` |
| psi_drift | Tier B.8 — ml-service | Drift is a property of the feature distribution over time, not of a single decision. | `ml-service/tests/test_drift.py` |
| audit_feedback_loop | Tier B.6 — policy-engine + ml-service | Analyst feedback rewrites training labels for the next retrain, not the current decision. | `policy-engine/__tests__/integration/feedback.test.js (analyst-in-the-loop)` |

## 8. Reproducing This Study

```bash
# Start test Postgres (once)
docker run -d --name ztiam-ablation-pg \
  -e POSTGRES_DB=ztiam_test -e POSTGRES_USER=ztiam -e POSTGRES_PASSWORD=testpassword \
  -p 5433:5432 postgres:16-alpine

# Optional: point ML_SERVICE_URL at running ml-service container for `ml_only` and `with_ml`
export ML_SERVICE_URL=http://172.19.0.2:5000
export ML_SERVICE_TOKEN=local-test-ml-token

# Optional: start Redis for `with_decision_cache`
docker run -d --name ztiam-ablation-redis -p 6379:6379 redis:7-alpine
export REDIS_URL=redis://127.0.0.1:6379

node test/ablation-study.js
```

Per-config JSON output is written to `test/ablation/results/<config>.json`; an aggregated `summary.json` is written alongside.
