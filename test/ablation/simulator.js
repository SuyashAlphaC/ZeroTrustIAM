'use strict';

const path = require('path');
const crypto = require('crypto');
const bcrypt = require(path.join(__dirname, '../../policy-engine/node_modules/bcrypt'));

/**
 * Mirrors policy-engine/server.js evaluate flow for offline ablation runs.
 */
// Tiny in-process cache stand-in so the harness can verify cache behaviour
// without a Redis dependency. The real policy-engine uses ioredis; the shape
// of the cached entry matches what `policy-engine/decisionCache.js` writes.
const _localDecisionCache = new Map();
function _cacheKey(payload) {
  const p = payload.location || {};
  const hourBucket = Math.floor(Date.parse(payload.timestamp || new Date().toISOString()) / 3600000);
  return [
    payload.username || '',
    payload.deviceId || '',
    p.country || '',
    p.city || '',
    hourBucket,
    payload.requiredPermission || 'read',
  ].join('|');
}

async function simulateEvaluate(modules, payload, options = {}) {
  const {
    config,
    db,
    riskScorer,
    anomalyDetector,
    mlRiskScorer,
    riskScorerEnsemble,
    mfa,
    zkp,
    blockchain,
  } = modules;

  const {
    username,
    password,
    deviceId,
    timestamp,
    ip,
    location,
    requiredPermission,
  } = payload;

  const perm = requiredPermission || 'read';
  const cacheEnabled = (process.env.DECISION_CACHE_ENABLED || 'false').toLowerCase() === 'true';

  // Cache lookup for ALLOW-only decisions, mirrors policy-engine/decisionCache.js
  if (cacheEnabled && options.secondPass) {
    const cached = _localDecisionCache.get(_cacheKey(payload));
    if (cached) {
      return { ...cached, fromCache: true };
    }
  }

  const userProfile = await db.getUser(username);
  if (!userProfile) {
    return {
      decision: 'DENY',
      reason: 'Invalid credentials - user not found',
      layer: 'Policy Engine',
      riskScore: null,
      baseRiskScore: null,
      zkProof: null,
    };
  }

  const passwordValid = await bcrypt.compare(password, userProfile.passwordHash);
  if (!passwordValid) {
    riskScorer.incrementFailedAttempts(username);
    return {
      decision: 'DENY',
      reason: 'Invalid credentials - wrong password',
      layer: 'Policy Engine',
      riskScore: null,
      baseRiskScore: null,
      zkProof: null,
    };
  }

  const requestContext = {
    username,
    deviceId,
    timestamp: timestamp || new Date().toISOString(),
    ip: ip || '0.0.0.0',
    location: location || { country: 'UNKNOWN', city: 'UNKNOWN' },
  };

  const { score: baseRiskScore, breakdown } = riskScorer.computeRiskScore(userProfile, requestContext);
  const anomaly = await anomalyDetector.detectAnomalies(username, requestContext);
  const profile = await anomalyDetector.getProfileSummary(username);
  const mlOpts = {
    requiredPermission: perm,
    failedAttempts: Math.round((breakdown.a_score || 0) * 5),
    knownLocations: profile.knownLocations,
    knownDevices: profile.knownDevices,
    loginHoursMean: profile.loginHours.mean,
    loginHoursStd: profile.loginHours.std,
    profileSamples: profile.loginHours.samples,
    lastLogin: profile.lastLogin,
  };
  const mlResult = await mlRiskScorer.scoreWithML(userProfile, requestContext, mlOpts);
  const ensemble = riskScorerEnsemble.computeEnsembleRisk({
    ahpScore: baseRiskScore,
    mlResult,
    anomalyScore: anomaly.combined,
  });
  const riskScore = ensemble.ensembleScore;

  if (riskScore >= config.riskThreshold) {
    const blockchainResult = await evaluateAccessAblation(blockchain, username, deviceId, riskScore, perm, {});
    return {
      decision: 'DENY',
      reason: `Risk score too high (${riskScore} >= ${config.riskThreshold})`,
      layer: 'Policy Engine',
      riskScore,
      baseRiskScore,
      breakdown,
      ensemble,
      anomaly,
      mlAvailable: ensemble.mlAvailable,
      blockchain: blockchainResult,
      zkProof: null,
    };
  }

  const mfaData = await db.getMFASecret(username);
  const mfaEnabled = !!(mfaData && mfaData.enabled);
  const stepUpRequired = mfaEnabled && mfa.requiresStepUp(riskScore, perm);

  let zkProof = null;
  if (config.zkpEnabled) {
    const proofPackage = zkp.createZKPPackage(riskScore, config.riskThreshold);
    if (proofPackage.success) {
      zkProof = {
        proofId: proofPackage.rangeProof.proofId,
        property: proofPackage.metadata.property,
      };
    }
  }

  if (stepUpRequired && !payload.mfaCode) {
    const preflight = await evaluateAccessAblation(blockchain, username, deviceId, riskScore, perm, {
      issueGrant: false,
    });
    if (preflight.decision !== 'ALLOW') {
      return {
        decision: preflight.decision,
        reason: preflight.reason,
        layer: preflight.layer,
        riskScore,
        baseRiskScore,
        breakdown,
        ensemble,
        anomaly,
        mlAvailable: ensemble.mlAvailable,
        blockchain: preflight,
        zkProof,
      };
    }
    return {
      decision: 'MFA_REQUIRED',
      reason: `Step-up authentication required (risk=${riskScore})`,
      layer: 'Policy Engine (MFA)',
      riskScore,
      baseRiskScore,
      breakdown,
      ensemble,
      anomaly,
      mlAvailable: ensemble.mlAvailable,
      zkProof: null,
    };
  }

  const blockchainResult = await evaluateAccessAblation(blockchain, username, deviceId, riskScore, perm, {
    proofPackage: zkProof ? { rangeProof: { proofId: zkProof.proofId } } : undefined,
  });

  if (blockchainResult.decision === 'ALLOW') {
    riskScorer.resetFailedAttempts(username);
    await anomalyDetector.recordLogin(username, requestContext);
  }

  const result = {
    decision: blockchainResult.decision,
    reason: blockchainResult.reason,
    layer: blockchainResult.layer,
    riskScore,
    baseRiskScore,
    breakdown,
    ensemble,
    anomaly,
    mlAvailable: ensemble.mlAvailable,
    blockchain: blockchainResult,
    zkProof: blockchainResult.decision === 'ALLOW' ? zkProof : null,
  };

  // Cache write: only ALLOW decisions are cached (matches production policy
  // in policy-engine/decisionCache.js — DENY and MFA_REQUIRED are never cached).
  if (cacheEnabled && blockchainResult.decision === 'ALLOW') {
    _localDecisionCache.set(_cacheKey(payload), result);
  }

  return result;
}

async function evaluateAccessAblation(blockchain, userId, deviceId, riskScore, requiredPermission, options) {
  if (process.env.ABLATION_BLOCKCHAIN === 'passthrough') {
    return {
      decision: 'ALLOW',
      reason: 'Ablation: blockchain layer bypassed',
      txId: crypto.randomBytes(16).toString('hex'),
      layer: 'Ablation Stub (no blockchain)',
    };
  }
  return blockchain.evaluateAccess(userId, deviceId, riskScore, requiredPermission, options);
}

module.exports = { simulateEvaluate };
