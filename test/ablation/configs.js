'use strict';

/**
 * Ablation configurations. Each entry sets environment overrides applied
 * before loading the policy-engine modules in an isolated child process.
 *
 * Convention after the v2 rework:
 *   - ML sidecar is ON by default for every config so that ablations are
 *     compared against a true ML-enabled baseline (apples-to-apples).
 *   - The three explicit "scoring ablation" configs (no_ml, no_anomaly,
 *     ahp_only) deliberately turn ML off — that is the thing being ablated.
 *   - Per-ablation `mlOptional: true` means "use ML if reachable, but do not
 *     skip the config when the sidecar is unavailable" (graceful fallback).
 *     `requireMl: true` means "skip this config if the sidecar isn't up"
 *     (used by configs that exist specifically to exercise the ML path).
 */
const CONFIGS = [
  {
    id: 'baseline',
    name: 'Full system (baseline)',
    description: 'AHP + ML ensemble + behavioral anomaly + Fabric smart contract + MFA step-up + ZKP',
    env: {
      ML_SERVICE_ENABLED: 'true',
      ENSEMBLE_AHP_WEIGHT: '0.4',
      ENSEMBLE_ML_WEIGHT: '0.4',
      ENSEMBLE_ANOMALY_WEIGHT: '0.2',
      ZKP_ENABLED: 'true',
    },
    mlOptional: true,
  },
  {
    id: 'no_ml',
    name: 'Without ML Random Forest',
    description: 'Disables Python RF sidecar; ensemble redistributes ML weight to AHP + anomaly',
    env: {
      ML_SERVICE_ENABLED: 'false',
      ENSEMBLE_AHP_WEIGHT: '0.4',
      ENSEMBLE_ML_WEIGHT: '0.4',
      ENSEMBLE_ANOMALY_WEIGHT: '0.2',
    },
  },
  {
    id: 'no_anomaly',
    name: 'Without behavioral anomaly',
    description: 'Anomaly signal still computed but receives zero ensemble weight (AHP + ML only)',
    env: {
      ML_SERVICE_ENABLED: 'true',
      ENSEMBLE_AHP_WEIGHT: '0.5',
      ENSEMBLE_ML_WEIGHT: '0.5',
      ENSEMBLE_ANOMALY_WEIGHT: '0',
    },
    mlOptional: true,
  },
  {
    id: 'ahp_only',
    name: 'AHP contextual scoring only',
    description: 'Rule-based AHP weights only; no ML and no anomaly blend',
    env: {
      ML_SERVICE_ENABLED: 'false',
      ENSEMBLE_AHP_WEIGHT: '1',
      ENSEMBLE_ML_WEIGHT: '0',
      ENSEMBLE_ANOMALY_WEIGHT: '0',
    },
  },
  {
    id: 'ml_only',
    name: 'ML sidecar scoring only',
    description: 'ML Random Forest signal alone (no AHP, no anomaly). Probes the contribution of the learned model in isolation',
    env: {
      ML_SERVICE_ENABLED: 'true',
      ENSEMBLE_AHP_WEIGHT: '0',
      ENSEMBLE_ML_WEIGHT: '1',
      ENSEMBLE_ANOMALY_WEIGHT: '0',
    },
    requireMl: true,
  },
  {
    id: 'no_blockchain',
    name: 'Without blockchain enforcement',
    description: 'Policy engine + risk scoring active; smart-contract checks bypassed (passthrough ALLOW)',
    env: {
      ML_SERVICE_ENABLED: 'true',
      ABLATION_BLOCKCHAIN: 'passthrough',
    },
    mlOptional: true,
  },
  {
    id: 'no_policy_threshold',
    name: 'Without policy-engine risk gate',
    description: 'RISK_THRESHOLD raised so off-chain gate never denies on score alone',
    env: {
      ML_SERVICE_ENABLED: 'true',
      RISK_THRESHOLD: '2.0',
    },
    mlOptional: true,
  },
  {
    id: 'no_mfa',
    name: 'Without MFA step-up',
    description: 'MFA step-up threshold disabled; sensitive ops still evaluated by risk/blockchain',
    env: {
      ML_SERVICE_ENABLED: 'true',
      MFA_STEP_UP_THRESHOLD: '2.0',
    },
    mlOptional: true,
  },
  {
    id: 'no_zkp',
    name: 'Without zero-knowledge proofs',
    description: 'ZKP generation disabled (decisions unchanged; audit privacy reduced)',
    env: {
      ML_SERVICE_ENABLED: 'true',
      ZKP_ENABLED: 'false',
    },
    mlOptional: true,
  },
  {
    id: 'ablate_device',
    name: 'Ablate device signal (w_device=0)',
    description: 'Removes device factor from AHP score — unknown device no longer raises R via rules',
    env: {
      ML_SERVICE_ENABLED: 'true',
      RISK_WEIGHT_DEVICE: '0',
      RISK_WEIGHT_LOCATION: '0.50',
      RISK_WEIGHT_TIME: '0.33',
      RISK_WEIGHT_ATTEMPTS: '0.17',
    },
    mlOptional: true,
  },
  {
    id: 'ablate_location',
    name: 'Ablate location signal (w_location=0)',
    description: 'Removes geographic anomaly from AHP score',
    env: {
      ML_SERVICE_ENABLED: 'true',
      RISK_WEIGHT_DEVICE: '0.57',
      RISK_WEIGHT_LOCATION: '0',
      RISK_WEIGHT_TIME: '0.29',
      RISK_WEIGHT_ATTEMPTS: '0.14',
    },
    mlOptional: true,
  },
  {
    id: 'ablate_time',
    name: 'Ablate time signal (w_time=0)',
    description: 'Removes off-hours factor from AHP score',
    env: {
      ML_SERVICE_ENABLED: 'true',
      RISK_WEIGHT_DEVICE: '0.50',
      RISK_WEIGHT_LOCATION: '0.38',
      RISK_WEIGHT_TIME: '0',
      RISK_WEIGHT_ATTEMPTS: '0.12',
    },
    mlOptional: true,
  },
  {
    id: 'ablate_attempts',
    name: 'Ablate failed-attempts signal (w_attempts=0)',
    description: 'Removes brute-force escalation from AHP score',
    env: {
      ML_SERVICE_ENABLED: 'true',
      RISK_WEIGHT_DEVICE: '0.44',
      RISK_WEIGHT_LOCATION: '0.33',
      RISK_WEIGHT_TIME: '0.22',
      RISK_WEIGHT_ATTEMPTS: '0',
    },
    mlOptional: true,
  },
  {
    id: 'with_ml',
    name: 'Full system with ML sidecar (strict)',
    description: 'Same as baseline but skipped entirely if ML sidecar is unavailable — for ML availability A/B',
    env: {
      ML_SERVICE_ENABLED: 'true',
      ENSEMBLE_AHP_WEIGHT: '0.4',
      ENSEMBLE_ML_WEIGHT: '0.4',
      ENSEMBLE_ANOMALY_WEIGHT: '0.2',
    },
    requireMl: true,
  },
  {
    id: 'with_decision_cache',
    name: 'Full system with Redis decision cache',
    description: 'Runs each scenario twice; verifies repeat ALLOWs hit the cache (Tier A.5). Skipped if Redis unreachable.',
    env: {
      ML_SERVICE_ENABLED: 'true',
      DECISION_CACHE_ENABLED: 'true',
      REDIS_URL: process.env.REDIS_URL || 'redis://127.0.0.1:6379',
      DECISION_CACHE_TTL_SECONDS: '60',
    },
    mlOptional: true,
    requireRedis: true,
    cacheTwice: true,
  },
];

/**
 * Component features that affect correctness/integrity but cannot be
 * ablated from the policy-engine evaluate path used by this harness.
 * These are exercised by their own test suites — the report links to them
 * in Section 8 so reviewers understand WHY they are absent here.
 */
const COMPONENTS_TESTED_ELSEWHERE = [
  {
    id: 'audit_hash_chain',
    layer: 'Tier A.4 — chaincode',
    why: 'Hash chain lives inside chaincode (`AuditChainHead`, `VerifyAuditChain`). Test harness uses Fabric test mode (in-process mock) which does not execute chaincode JS.',
    coveredBy: 'chaincode/tests/auditChain.test.js',
  },
  {
    id: 'replay_protection',
    layer: 'Tier E.20 — chaincode',
    why: 'Nonce + freshness validation runs inside `_validateProofFreshness` in chaincode. Not reachable from the evaluate-flow mock.',
    coveredBy: 'chaincode/tests/replayProtection.test.js',
  },
  {
    id: 'refresh_token_reuse',
    layer: 'Tier E.19 — policy-engine',
    why: 'Reuse detection fires on the /refresh-token endpoint, not on /evaluate. Requires a multi-step refresh flow this harness does not perform.',
    coveredBy: 'policy-engine/__tests__/integration/refreshReuse.test.js',
  },
  {
    id: 'champion_challenger',
    layer: 'Tier B.7 — ml-service',
    why: 'Promotion gate is internal to the ML service. No access-decision delta to ablate.',
    coveredBy: 'ml-service/tests/test_promoter.py',
  },
  {
    id: 'psi_drift',
    layer: 'Tier B.8 — ml-service',
    why: 'Drift is a property of the feature distribution over time, not of a single decision.',
    coveredBy: 'ml-service/tests/test_drift.py',
  },
  {
    id: 'audit_feedback_loop',
    layer: 'Tier B.6 — policy-engine + ml-service',
    why: 'Analyst feedback rewrites training labels for the next retrain, not the current decision.',
    coveredBy: 'policy-engine/__tests__/integration/feedback.test.js (analyst-in-the-loop)',
  },
];

module.exports = { CONFIGS, COMPONENTS_TESTED_ELSEWHERE };
