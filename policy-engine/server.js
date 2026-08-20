'use strict';

require('dotenv').config();
require('./vault').bootstrapVaultEnvSync();
require('./tracing').initTracing();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const config = require('./config');
const { logger, requestLogger } = require('./logger');
const db = require('./database');
const { securityHeaders, globalLimiter, authLimiter, requireAuth, requireRole, validate, errorHandler } = require('./middleware');
const { computeRiskScore, incrementFailedAttempts, resetFailedAttempts } = require('./riskScorer');
const accountLockout = require('./accountLockout');
const passwordPolicy = require('./passwordPolicy');
const abac = require('./abac');
const externalPdp = require('./externalPdp');
const federation = require('./federation');
const saml = require('./saml');
const tenancy = require('./tenancy');
const billing = require('./billing');
const userProvisioning = require('./userProvisioning');
const kmsSigner = require('./kmsSigner');
const oauth = require('./oauth');
const mfa = require('./mfa');
const didResolver = require('./didResolver');
const webauthn = require('./webauthn');
const anomalyDetector = require('./anomalyDetector');
const {
  scoreWithML,
  mlHealth,
  ingestSample,
  relabelMlSample,
  mlModelInfo,
  mlModelComparison,
  mlFeatureDrift,
  mlPromoteCandidate,
  mlRollbackChampion,
} = require('./mlRiskScorer');
const { computeEnsembleRisk } = require('./riskScorerEnsemble');
const zkp = require('./zkpVerifier');
const promMetrics = require('./metrics');
const { sendPublicAuth, sanitizePublicAuthResponse } = require('./authPublicResponse');
const deviceTrust = require('./deviceTrust');
const { notifyUserAsync } = require('./notifications');
const auditMirror = require('./auditMirror');
const meRoutes = require('./meRoutes');
const scimRouter = require('./scim');

const blockchain = require('./fabricClient');

const app = express();

// ──────────────────────── Global Middleware ────────────────────────

app.use(securityHeaders);
// Capture raw body for Stripe webhooks (signature verification)
app.use(express.json({
  limit: '100kb',
  verify: (req, _res, buf) => {
    if (req.originalUrl && req.originalUrl.includes('/billing/webhooks/stripe')) {
      req.rawBody = buf.toString('utf8');
    }
  },
}));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

function tlsPeerHasSubject(req) {
  try {
    const cert = typeof req.socket.getPeerCertificate === 'function'
      ? req.socket.getPeerCertificate()
      : null;
    const subj = cert && cert.subject ? cert.subject : null;
    return !!(subj && Object.keys(subj).length > 0);
  } catch (_) {
    return false;
  }
}

/** Paths that browsers hit without presenting a mutual-TLS certificate. */
function stripVersionPrefix(p) {
  const s = p || '';
  if (s === '/v1' || s === '/v1/') return '/';
  if (s.startsWith('/v1/')) return s.slice(3) || '/';
  return s;
}

function isPublicTlsRoute(req) {
  const path = stripVersionPrefix(req.path || '');
  const method = req.method;
  if (path === '/health') return true;
  if (path.startsWith('/.well-known')) return true;
  if (path.startsWith('/oauth/.well-known')) return true;
  // OIDC authorize (GET + POST from the browser-hosted login form only)
  if (path.startsWith('/oauth/authorize')) return method === 'GET' || method === 'POST';
  return false;
}

function requireTrustedServiceCert(req, res, next) {
  if (!config.tlsEnabled || config.nodeEnv === 'test') return next();
  if (isPublicTlsRoute(req)) return next();
  if (!tlsPeerHasSubject(req)) {
    return res.status(403).json({ error: 'Forbidden', reason: 'Service TLS client certificate required' });
  }
  return next();
}

app.use(requireTrustedServiceCert);

app.use(requestLogger);
const requestContext = require('./requestContext');
app.use(requestContext.middleware());
app.use(promMetrics.httpMetricsMiddleware);
app.use(globalLimiter);
app.disable('x-powered-by');

// ──────────────────────── Key Management ────────────────────────
//
// Access tokens (RS256) are minted via the `kmsSigner` abstraction so the
// underlying key material can live in HashiCorp Vault Transit (or AWS KMS in
// future) without ever entering Node's process memory. Refresh tokens stay
// on a local HMAC secret stored in Postgres — the (lower-risk) refresh
// secret moving to KMS is a follow-up. See policy-engine/docs/KMS.md.

let JWT_REFRESH_SECRET;

async function initKeys() {
  // Warm up the KMS signer so the first request doesn't pay the init cost.
  // For Vault Transit this round-trips to ${VAULT_ADDR}; failures here are
  // surfaced explicitly by start() via kmsSigner.selfTest().
  await kmsSigner.signJwt({ sub: '__warmup__', type: 'access' }, { expiresIn: '5s' }).catch(() => {});

  let refreshKey = await db.getActiveSigningKey('jwt_refresh');
  if (!refreshKey) {
    const secret = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
    await db.storeSigningKey(`jwt-refresh-${Date.now()}`, 'jwt_refresh', secret, null, 'HS256');
    refreshKey = await db.getActiveSigningKey('jwt_refresh');
  }
  JWT_REFRESH_SECRET = refreshKey.private_key;
}

async function generateAccessToken(username, role, extra = {}) {
  const tenantId = extra.tid || extra.tenantId || tenancy.DEFAULT_TENANT;
  return kmsSigner.signJwt(
    tenancy.withTenantClaims({ sub: username, role, type: 'access' }, tenantId, extra),
    { expiresIn: config.jwtAccessExpiry, issuer: config.jwtIssuer }
  );
}

async function generateRefreshToken(username, opts = {}) {
  const token = jwt.sign(
    { sub: username, type: 'refresh', jti: crypto.randomUUID() },
    JWT_REFRESH_SECRET,
    { expiresIn: config.jwtRefreshExpiry, issuer: config.jwtIssuer }
  );
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  await db.storeRefreshToken(token, username, expiresAt, opts);
  return token;
}

function buildRequestContext(username, deviceId, timestamp, ip, location) {
  return {
    username,
    deviceId,
    timestamp: timestamp || new Date().toISOString(),
    ip: ip || '0.0.0.0',
    location: location || { country: 'UNKNOWN', city: 'UNKNOWN' },
  };
}

function buildMlOpts(profile, breakdown, requiredPermission) {
  return {
    requiredPermission: requiredPermission || 'read',
    failedAttempts: Math.round((breakdown.a_score || 0) * 5),
    knownLocations: profile.knownLocations,
    knownDevices: profile.knownDevices,
    loginHoursMean: profile.loginHours.mean,
    loginHoursStd: profile.loginHours.std,
    profileSamples: profile.loginHours.samples,
    lastLogin: profile.lastLogin,
  };
}

async function assessRequestRisk(userProfile, requestContext, requiredPermission) {
  const { score: baseRiskScore, breakdown } = await computeRiskScore(userProfile, requestContext);
  const anomaly = await anomalyDetector.detectAnomalies(requestContext.username, requestContext);
  const anomalyScore = anomaly.combined;
  const profile = await anomalyDetector.getProfileSummary(requestContext.username);
  const mlOpts = buildMlOpts(profile, breakdown, requiredPermission);
  const mlResult = await scoreWithML(userProfile, requestContext, mlOpts);
  const ensemble = computeEnsembleRisk({ ahpScore: baseRiskScore, mlResult, anomalyScore });
  const riskScore = ensemble.ensembleScore;

  return {
    baseRiskScore,
    breakdown,
    anomalyResult: {
      originalRiskScore: baseRiskScore,
      adjustedRiskScore: riskScore,
      anomalyAdjustment: Math.round((riskScore - baseRiskScore) * 100) / 100,
      anomaly,
    },
    ensemble,
    profile,
    mlOpts,
    riskScore,
  };
}

function ingestObservedDecision(userProfile, requestContext, assessment, decision, reason, auditId) {
  ingestSample(userProfile, requestContext, {
    ...assessment.mlOpts,
    decision,
    reason,
    auditId: auditId || null,
  });
}

async function getAssessmentModelVersion(ensemble) {
  const params = await db.getActivePolicyPublicParams();
  return ensemble.mlModelVersion || params?.activeModelVersion || 'rules-ahp-v1';
}

function createRiskProofPackage(riskScore) {
  // ZKP is opt-in and never a security boundary — chaincode should not require it in prod.
  if (!config.zkpEnabled) {
    return { proofPackage: null, zkProof: undefined };
  }
  const proofPackage = zkp.createZKPPackage(riskScore, config.riskThreshold);
  if (!proofPackage.success) {
    return { proofPackage: null, zkProof: undefined };
  }
  return {
    proofPackage,
    zkProof: {
      proofId: proofPackage.rangeProof.proofId,
      property: proofPackage.metadata.property,
      scheme: proofPackage.metadata.scheme,
      experimental: true,
      securityBoundary: false,
    },
  };
}

async function persistAccessGrant(grant) {
  if (grant?.grantId) {
    await db.storeAccessGrant(grant);
  }
}

async function persistObservedLogin(username, requestContext, riskScore, decision) {
  await anomalyDetector.recordLogin(username, requestContext);
  await db.recordLoginHistory(
    username,
    requestContext.deviceId,
    requestContext.location?.country,
    requestContext.location?.city,
    requestContext.timestamp,
    riskScore,
    decision
  );
}


// Versioned REST surface (mounted at `/` and `/v1`).
const api = express.Router();

// ──────────────────────── Observability ────────────────────────

api.get('/metrics', (req, res) => {
  res.set('Content-Type', 'text/plain; version=0.0.4');
  res.send(promMetrics.renderText());
});

// ──────────────────────── Health Check ────────────────────────

api.get('/health', (req, res) => {
  const dbOk = !!db.getDb();
  res.status(dbOk ? 200 : 503).json({
    status: dbOk ? 'healthy' : 'degraded',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    blockchain: 'fabric',
    database: dbOk ? 'connected' : 'disconnected',
  });
});

// ──────────────────────── Core Authentication ────────────────────────

api.post('/evaluate', authLimiter, validate('evaluate'), async (req, res, next) => {
  const { username, password, deviceId, timestamp, ip, location, requiredPermission, resource } = req.body;

  req.log.info({ username, deviceId, location }, 'Access request received');

  try {
    // Step 0: Account lockout (shared Redis/Postgres counters)
    const lock = await accountLockout.isLocked(username);
    if (lock.locked) {
      promMetrics.inc('ztiam_decisions_total', { decision: 'DENY', layer: 'policy_engine', reason: 'account_locked' });
      return sendPublicAuth(res, 429, {
        decision: 'DENY',
        reason: 'Account temporarily locked due to failed attempts',
        reasonCode: 'ACCOUNT_LOCKED',
        code: 'ACCOUNT_LOCKED',
        retryAfterSeconds: lock.remainingSeconds,
        layer: 'Policy Engine',
      });
    }

    // Opaque device credential required (never free-text user identity)
    if (!deviceTrust.isValidDeviceCredential(deviceId)) {
      promMetrics.inc('ztiam_decisions_total', { decision: 'DENY', layer: 'policy_engine', reason: 'invalid_device' });
      return sendPublicAuth(res, {
        decision: 'DENY',
        reason: 'Untrusted device',
        reasonCode: 'UNTRUSTED_DEVICE',
        layer: 'Policy Engine',
      });
    }

    // Step 1: Credential verification (anti-enumeration: uniform response + dummy verify)
    let userProfile = await db.getUser(username);
    if (!userProfile || userProfile.status === 'DELETED') {
      await passwordPolicy.dummyVerify();
      await incrementFailedAttempts(username);
      req.log.warn({ username }, 'Auth failed (user missing or deleted)');
      await db.writeAuditLog({ userId: username, deviceId, decision: 'DENY', reason: 'Invalid credentials', layer: 'Policy Engine' });
      promMetrics.inc('ztiam_decisions_total', { decision: 'DENY', layer: 'policy_engine', reason: 'invalid_credentials' });
      return sendPublicAuth(res, { decision: 'DENY', reason: 'Invalid credentials', layer: 'Policy Engine' });
    }

    if (userProfile.status && userProfile.status !== 'ACTIVE') {
      await incrementFailedAttempts(username);
      promMetrics.inc('ztiam_decisions_total', { decision: 'DENY', layer: 'policy_engine', reason: 'account_inactive' });
      return sendPublicAuth(res, { decision: 'DENY', reason: 'Invalid credentials', layer: 'Policy Engine' });
    }

    const passwordValid = await passwordPolicy.verifyPassword(password, userProfile.passwordHash);
    if (!passwordValid) {
      const attempts = await incrementFailedAttempts(username);
      req.log.warn({ username, attempts }, 'Auth failed (bad password)');
      await db.writeAuditLog({ userId: username, deviceId, decision: 'DENY', reason: 'Invalid credentials', layer: 'Policy Engine' });
      promMetrics.inc('ztiam_decisions_total', { decision: 'DENY', layer: 'policy_engine', reason: 'invalid_credentials' });
      return sendPublicAuth(res, { decision: 'DENY', reason: 'Invalid credentials', layer: 'Policy Engine' });
    }

    // Step 2: Compute contextual + anomaly + ML ensemble risk (unknown device raises risk)
    let requestContext = buildRequestContext(username, deviceId, timestamp, ip, location);
    let assessment = await assessRequestRisk(userProfile, requestContext, requiredPermission || 'read');
    let { baseRiskScore, breakdown, anomalyResult, ensemble, riskScore } = assessment;

    req.log.info({
      username,
      baseRiskScore,
      riskScore,
      ensemble: ensemble.components,
      weights: ensemble.weights,
      mlAvailable: ensemble.mlAvailable,
      breakdown,
    }, 'Risk score computed');

    // Step 2a: Device trust — enroll opaque credential per policy (never user-typed trust)
    const mfaAlready = !!(req.body.mfaCode);
    let deviceGate = await deviceTrust.ensureDeviceTrusted(userProfile, deviceId, {
      riskScore,
      mfaVerified: mfaAlready,
    });
    if (!deviceGate.ok) {
      if (deviceGate.decision === 'MFA_REQUIRED') {
        const challengeId = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + config.mfaChallengeExpiry * 1000).toISOString();
        const modelVersionEarly = await getAssessmentModelVersion(ensemble);
        await db.storeMFAChallenge(challengeId, username, {
          deviceId,
          riskScore,
          requiredPermission: requiredPermission || 'read',
          resource: resource || 'default',
          breakdown,
          modelVersion: modelVersionEarly,
          enrollDevice: true,
        }, expiresAt);
        return sendPublicAuth(res, {
          decision: 'MFA_REQUIRED',
          reason: 'New device requires step-up authentication',
          reasonCode: 'MFA_REQUIRED',
          challengeId,
          layer: 'Policy Engine (MFA)',
        });
      }
      await db.writeAuditLog({
        userId: username, deviceId, riskScore, decision: 'DENY',
        reason: 'Untrusted device', layer: 'Policy Engine',
      });
      promMetrics.inc('ztiam_decisions_total', { decision: 'DENY', layer: 'policy_engine', reason: 'untrusted_device' });
      return sendPublicAuth(res, {
        decision: 'DENY',
        reason: 'Untrusted device',
        reasonCode: deviceGate.reasonCode || 'UNTRUSTED_DEVICE',
        layer: 'Policy Engine',
      });
    }
    if (deviceGate.enrolled) {
      userProfile = deviceGate.userProfile;
      // Re-score after enrollment so d_score reflects trusted device
      assessment = await assessRequestRisk(userProfile, requestContext, requiredPermission || 'read');
      ({ baseRiskScore, breakdown, anomalyResult, ensemble, riskScore } = assessment);
    }

    // Step 2b: External PDP (OPA/Cedar) + local ABAC — forbid wins
    const pdpResult = await externalPdp.evaluate({
      userId: username,
      role: userProfile.role,
      action: requiredPermission || 'read',
      resourceId: resource || 'default',
      riskScore,
      country: location?.country || requestContext.location?.country,
      status: userProfile.status || 'ACTIVE',
      hour: new Date(requestContext.timestamp).getHours(),
      mfaVerified: false,
      tenantId: userProfile.tenantId || tenancy.DEFAULT_TENANT,
    });
    if (pdpResult.decision === 'forbid') {
      promMetrics.inc('ztiam_decisions_total', { decision: 'DENY', layer: 'policy_engine', reason: 'pdp_forbid' });
      await db.writeAuditLog({
        userId: username, deviceId, riskScore, decision: 'DENY',
        reason: pdpResult.reason, layer: `Policy Engine (PDP:${pdpResult.backend || 'local'})`,
      });
      return sendPublicAuth(res, {
        decision: 'DENY',
        reason: pdpResult.reason,
        layer: 'Policy Engine (PDP)',
      });
    }

    // Step 3: Policy engine threshold check
    const modelVersion = await getAssessmentModelVersion(ensemble);
    const targetResource = resource || 'default';

    if (riskScore >= config.riskThreshold) {
      req.log.warn({ username, riskScore }, 'Denied by policy engine: risk too high');
      // Do not call chaincode with untrusted path details in the public reason
      await persistObservedLogin(username, requestContext, riskScore, 'DENY');
      await db.writeAuditLog({ userId: username, deviceId, riskScore, decision: 'DENY', reason: 'Risk too high', layer: 'Policy Engine' });
      ingestObservedDecision(userProfile, requestContext, assessment, 'DENY', 'Risk too high', null);
      promMetrics.inc('ztiam_decisions_total', { decision: 'DENY', layer: 'policy_engine', reason: 'risk_too_high' });
      promMetrics.inc('ztiam_ml_ingest_total', { label: '1' });
      return sendPublicAuth(res, {
        decision: 'DENY',
        reason: 'Risk too high',
        reasonCode: 'RISK_DENIED',
        layer: 'Policy Engine',
      });
    }

    // Step 4: MFA step-up check before minting an access grant on-chain.
    const mfaData = await db.getMFASecret(username);
    const mfaEnabled = mfaData && mfaData.enabled;
    const stepUpRequired = mfaEnabled && mfa.requiresStepUp(riskScore, requiredPermission || 'read');
    const { proofPackage, zkProof } = createRiskProofPackage(riskScore);

    if (stepUpRequired) {
      const preflightResult = await blockchain.evaluateAccess(username, deviceId, riskScore, requiredPermission || 'read', {
        proofPackage,
        modelVersion,
        resource: targetResource,
        issueGrant: false,
      });
      if (preflightResult.decision !== 'ALLOW') {
        await persistObservedLogin(username, requestContext, riskScore, preflightResult.decision);
        await db.writeAuditLog({ txId: preflightResult.txId, userId: username, deviceId, riskScore, decision: preflightResult.decision, reason: preflightResult.reason, layer: preflightResult.layer });
        ingestObservedDecision(userProfile, requestContext, assessment, preflightResult.decision, preflightResult.reason, preflightResult.txId);
        promMetrics.inc('ztiam_decisions_total', { decision: preflightResult.decision, layer: 'chaincode' });
        promMetrics.inc('ztiam_ml_ingest_total', { label: preflightResult.decision === 'DENY' ? '1' : '0' });
        return sendPublicAuth(res, {
          decision: preflightResult.decision,
          reason: preflightResult.reason,
          txId: preflightResult.txId,
          layer: preflightResult.layer,
        });
      }

      if (!req.body.mfaCode) {
        const challengeId = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + config.mfaChallengeExpiry * 1000).toISOString();
        await db.storeMFAChallenge(challengeId, username, {
          deviceId, riskScore, requiredPermission: requiredPermission || 'read',
          resource: targetResource, breakdown, modelVersion,
        }, expiresAt);

        req.log.info({ username, riskScore, requiredPermission }, 'MFA step-up required');
        return sendPublicAuth(res, {
          decision: 'MFA_REQUIRED',
          reason: 'Step-up authentication required',
          reasonCode: 'MFA_REQUIRED',
          challengeId,
          layer: 'Policy Engine (MFA)',
        });
      }
    }

    if (stepUpRequired && req.body.mfaCode) {
      const verification = await mfa.verifyTOTP(username, req.body.mfaCode);
      if (!verification.valid) {
        return sendPublicAuth(res, {
          decision: 'DENY',
          reason: 'MFA verification failed',
          reasonCode: 'MFA_FAILED',
          layer: 'Policy Engine (MFA)',
        });
      }
      req.log.info({ username }, 'MFA step-up verified');
    }

    // Step 5: Blockchain smart contract authorization + access grant issuance
    const blockchainResult = await blockchain.evaluateAccess(username, deviceId, riskScore, requiredPermission || 'read', {
      proofPackage,
      modelVersion,
      resource: targetResource,
    });
    await persistAccessGrant(blockchainResult.accessGrant);

    if (blockchainResult.decision === 'ALLOW') {
      await resetFailedAttempts(username);

      // Step 6: Issue session tokens
      const accessToken = await generateAccessToken(username, userProfile.role, {
        tid: userProfile.tenantId || tenancy.DEFAULT_TENANT,
      });
      const refreshToken = await generateRefreshToken(username);

      // Step 7: Record login
      await persistObservedLogin(username, requestContext, riskScore, 'ALLOW');

      await db.writeAuditLog({ txId: blockchainResult.txId, userId: username, deviceId, riskScore, decision: 'ALLOW', reason: blockchainResult.reason, layer: blockchainResult.layer });
      auditMirror.mirrorAuditEntry({
        txId: blockchainResult.txId,
        userId: username,
        deviceId,
        decision: 'ALLOW',
        reason: blockchainResult.reason,
        entryHash: blockchainResult.entryHash,
        prevHash: blockchainResult.prevHash,
        timestamp: requestContext.timestamp,
      }).catch(() => {});

      ingestObservedDecision(userProfile, requestContext, assessment, 'ALLOW', blockchainResult.reason, blockchainResult.txId);
      promMetrics.inc('ztiam_decisions_total', { decision: 'ALLOW', layer: 'chaincode' });
      promMetrics.inc('ztiam_ml_ingest_total', { label: '0' });

      req.log.info({ username, txId: blockchainResult.txId }, 'Access granted');
      return sendPublicAuth(res, {
        decision: 'ALLOW',
        reason: blockchainResult.reason,
        txId: blockchainResult.txId,
        layer: blockchainResult.layer,
        accessToken,
        refreshToken,
        tokenExpiry: config.jwtAccessExpiry,
        mfaVerified: stepUpRequired ? true : undefined,
        zkProof,
        accessGrant: blockchainResult.accessGrant,
        deviceEnrolled: deviceGate.enrolled || undefined,
      });
    }

    // Blockchain denied
    await db.recordLoginHistory(username, deviceId, location?.country, location?.city, requestContext.timestamp, riskScore, blockchainResult.decision);
    await db.writeAuditLog({ txId: blockchainResult.txId, userId: username, deviceId, riskScore, decision: blockchainResult.decision, reason: blockchainResult.reason, layer: blockchainResult.layer });

    ingestObservedDecision(userProfile, requestContext, assessment, blockchainResult.decision, blockchainResult.reason, blockchainResult.txId);
    promMetrics.inc('ztiam_decisions_total', { decision: blockchainResult.decision, layer: 'chaincode' });
    promMetrics.inc('ztiam_ml_ingest_total', { label: blockchainResult.decision === 'DENY' ? '1' : '0' });

    req.log.info({ username, decision: blockchainResult.decision, reason: blockchainResult.reason }, 'Blockchain decision');
    return sendPublicAuth(res, {
      decision: blockchainResult.decision,
      reason: blockchainResult.reason,
      txId: blockchainResult.txId,
      layer: blockchainResult.layer,
    });
  } catch (err) {
    next(err);
  }
});

// ──────────────────────── Token Endpoints ────────────────────────

api.post('/verify-token', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ valid: false, reason: 'No token provided' });
  }
  try {
    const decoded = await kmsSigner.verifyJwt(authHeader.split(' ')[1], { issuer: config.jwtIssuer });
    if (decoded.type !== 'access') return res.status(401).json({ valid: false, reason: 'Invalid token type' });
    res.json({ valid: true, user: decoded.sub, role: decoded.role, expiresAt: new Date(decoded.exp * 1000).toISOString() });
  } catch {
    res.status(401).json({ valid: false, reason: 'Token expired or invalid' });
  }
});

api.post('/refresh-token', validate('refreshToken'), async (req, res) => {
  const { refreshToken } = req.body;
  // Look up status BEFORE checking validity so we can detect reuse of a
  // ROTATED/COMPROMISED token (RFC 6819 §5.2.2.3 family invalidation).
  const tokenInfo = await db.getRefreshTokenStatus(refreshToken);
  if (!tokenInfo) {
    return res.status(401).json({ error: 'Invalid or revoked refresh token' });
  }
  if (tokenInfo.status === 'ROTATED' || tokenInfo.status === 'COMPROMISED') {
    await db.markFamilyCompromised(tokenInfo.familyId, 'reuse_detected');
    req.log.warn({
      event: 'refresh_reuse_detected',
      userId: tokenInfo.userId,
      familyId: tokenInfo.familyId,
      priorStatus: tokenInfo.status,
    }, 'Refresh token reuse detected — family invalidated');
    return res.status(401).json({
      error: 'Token reuse detected',
      code: 'REFRESH_REUSE_DETECTED',
    });
  }
  if (tokenInfo.status !== 'ACTIVE') {
    return res.status(401).json({ error: 'Invalid or revoked refresh token' });
  }
  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET, { issuer: config.jwtIssuer });
    if (decoded.type !== 'refresh') return res.status(401).json({ error: 'Invalid token type' });
    const userProfile = await db.getUser(decoded.sub);
    if (!userProfile) return res.status(401).json({ error: 'User no longer exists' });
    // Rotate: mark old ROTATED, issue new in the same family with parent linkage.
    const familyId = await db.markRefreshTokenRotated(refreshToken);
    const newAccessToken = await generateAccessToken(decoded.sub, userProfile.role, {
      tid: userProfile.tenantId || tenancy.DEFAULT_TENANT,
    });
    const newRefreshToken = await generateRefreshToken(decoded.sub, {
      familyId: familyId || tokenInfo.familyId,
      parentTokenHash: refreshToken,
    });
    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken, tokenExpiry: config.jwtAccessExpiry });
  } catch {
    await db.revokeRefreshToken(refreshToken);
    res.status(401).json({ error: 'Refresh token expired' });
  }
});

api.post('/logout', validate('logout'), async (req, res) => {
  if (req.body.refreshToken) await db.revokeRefreshToken(req.body.refreshToken);
  res.json({ success: true, message: 'Logged out successfully' });
});

// ──────────────────────── OAuth 2.0 / OIDC ────────────────────────

api.get('/.well-known/openid-configuration', (req, res) => res.json(oauth.getDiscoveryDocument()));
api.get('/oauth/.well-known/jwks.json', (req, res) => res.json(oauth.getJwks()));

api.get('/oauth/authorize', async (req, res) => {
  const { response_type, client_id, redirect_uri, scope, state, nonce } = req.query;
  if (response_type !== 'code') return res.status(400).json({ error: 'unsupported_response_type' });
  const client = await db.getOAuthClient(client_id);
  if (!client) return res.status(400).json({ error: 'invalid_client' });
  if (!client.redirectUris.includes(redirect_uri)) return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid redirect_uri' });
  res.send(`
    <html><body style="font-family:sans-serif;max-width:400px;margin:60px auto;background:#0f172a;color:#e2e8f0;padding:40px;border-radius:12px">
      <h2>Authorize Application</h2>
      <p><strong>${client_id}</strong> requests access to your account.</p>
      <p>Scope: <code>${scope || 'openid'}</code></p>
      <form method="POST" action="${(req.baseUrl || '')}/oauth/authorize">
        <input type="hidden" name="client_id" value="${client_id}">
        <input type="hidden" name="redirect_uri" value="${redirect_uri}">
        <input type="hidden" name="scope" value="${scope || 'openid'}">
        <input type="hidden" name="state" value="${state || ''}">
        <input type="hidden" name="nonce" value="${nonce || ''}">
        <label>Username: <input name="username" required style="padding:8px;margin:4px 0 12px;display:block;width:100%"></label>
        <label>Password: <input name="password" type="password" required style="padding:8px;margin:4px 0 12px;display:block;width:100%"></label>
        <button type="submit" style="padding:10px 24px;background:#3b82f6;color:#fff;border:none;border-radius:6px;cursor:pointer">Authorize</button>
      </form>
    </body></html>
  `);
});

api.use('/oauth/authorize', express.urlencoded({ extended: false }));
api.post('/oauth/authorize', authLimiter, async (req, res) => {
  const { client_id, redirect_uri, scope, state, nonce, username, password } = req.body;
  const userProfile = await db.getUser(username);
  if (!userProfile) return res.status(401).send('Invalid credentials');
  const valid = await passwordPolicy.verifyPassword(password, userProfile.passwordHash);
  if (!valid) return res.status(401).send('Invalid credentials');
  const code = await oauth.createAuthorizationCode(username, client_id, redirect_uri, scope, nonce);
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);
  res.redirect(redirectUrl.toString());
});

api.post('/oauth/token', authLimiter, validate('oauthToken'), async (req, res) => {
  const { grant_type, code, client_id, client_secret, redirect_uri } = req.body;
  if (grant_type !== 'authorization_code') return res.status(400).json({ error: 'unsupported_grant_type' });
  const result = await oauth.exchangeCode(code, client_id, client_secret, redirect_uri);
  if (result.error) return res.status(400).json(result);
  res.json(result);
});

api.get('/oauth/userinfo', requireAuth, async (req, res) => {
  const user = await db.getUser(req.user.sub);
  if (!user) return res.status(404).json({ error: 'user_not_found' });
  res.json({ sub: req.user.sub, role: user.role, devices: user.registeredDevices.length, location: user.usualLocation });
});

// ──────────────────────── MFA ────────────────────────

/**
 * Resolve userId from Bearer access token (preferred for logged-in console)
 * or username+password body (legacy / unauthenticated enrollment).
 */
async function resolveUserIdFromAuthOrPassword(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const decoded = await kmsSigner.verifyJwt(authHeader.split(' ')[1], { issuer: config.jwtIssuer });
      if (decoded.type === 'access' && decoded.sub) return { userId: decoded.sub, via: 'session' };
    } catch {
      return { error: 'Token expired or invalid', status: 401 };
    }
  }
  const username = req.body?.username;
  const password = req.body?.password;
  if (username && password) {
    const userProfile = await db.getUser(username);
    if (!userProfile) return { error: 'User not found', status: 401 };
    const valid = await passwordPolicy.verifyPassword(password, userProfile.passwordHash);
    if (!valid) return { error: 'Invalid credentials', status: 401 };
    return { userId: username, via: 'password' };
  }
  return { error: 'Authentication required (session or username+password)', status: 401 };
}

api.post('/mfa/enroll', authLimiter, async (req, res, next) => {
  try {
    const resolved = await resolveUserIdFromAuthOrPassword(req);
    if (resolved.error) return res.status(resolved.status).json({ error: resolved.error });
    const enrollment = await mfa.enrollMFA(resolved.userId);
    // Normalize field names for the Security UI
    res.json({
      ...enrollment,
      otpauth_url: enrollment.otpauth,
      otpauthUrl: enrollment.otpauth,
      qrcode: enrollment.qrCodeDataUrl,
      qr_data_url: enrollment.qrCodeDataUrl,
    });
  } catch (err) { next(err); }
});

api.post('/mfa/verify', async (req, res, next) => {
  try {
    let userId = req.body?.username;
    if (req.headers.authorization?.startsWith('Bearer ')) {
      const resolved = await resolveUserIdFromAuthOrPassword(req);
      if (resolved.error) return res.status(resolved.status).json({ error: resolved.error });
      userId = resolved.userId;
    }
    if (!userId || !req.body?.code) {
      return res.status(400).json({ error: 'username (or session) and code required' });
    }
    res.json(await mfa.verifyTOTP(userId, req.body.code));
  } catch (err) { next(err); }
});

api.post('/mfa/challenge', validate('mfaChallenge'), async (req, res) => {
  const challenge = await db.getMFAChallenge(req.body.challengeId);
  if (!challenge) {
    return sendPublicAuth(res, {
      decision: 'DENY',
      reason: 'MFA verification failed',
      reasonCode: 'MFA_FAILED',
      layer: 'Policy Engine (MFA)',
    });
  }
  const verification = await mfa.verifyTOTP(challenge.user_id, req.body.code);
  if (!verification.valid) {
    return sendPublicAuth(res, {
      decision: 'DENY',
      reason: 'MFA verification failed',
      reasonCode: 'MFA_FAILED',
      layer: 'Policy Engine (MFA)',
    });
  }
  await db.deleteMFAChallenge(req.body.challengeId);
  let userProfile = await db.getUser(challenge.user_id);
  const ctx = challenge.context;

  // Enroll opaque device after MFA when challenge requested device binding
  if (ctx.enrollDevice || !deviceTrust.isDeviceRegistered(userProfile, ctx.deviceId)) {
    const gate = await deviceTrust.ensureDeviceTrusted(userProfile, ctx.deviceId, {
      riskScore: ctx.riskScore ?? 0,
      mfaVerified: true,
      forceEnroll: true,
    });
    if (!gate.ok) {
      return sendPublicAuth(res, {
        decision: 'DENY',
        reason: 'Untrusted device',
        reasonCode: 'UNTRUSTED_DEVICE',
        layer: 'Policy Engine (MFA)',
      });
    }
    if (gate.enrolled) userProfile = gate.userProfile;
  }

  const { proofPackage, zkProof } = createRiskProofPackage(ctx.riskScore);
  const blockchainResult = await blockchain.evaluateAccess(
    challenge.user_id,
    ctx.deviceId,
    ctx.riskScore,
    ctx.requiredPermission || 'read',
    {
      proofPackage,
      modelVersion: ctx.modelVersion || 'rules-ahp-v1',
      resource: ctx.resource || 'default',
    }
  );
  await persistAccessGrant(blockchainResult.accessGrant);
  if (blockchainResult.decision !== 'ALLOW') {
    return sendPublicAuth(res, {
      decision: blockchainResult.decision,
      reason: blockchainResult.reason,
      txId: blockchainResult.txId,
      layer: blockchainResult.layer,
    });
  }
  const accessToken = await generateAccessToken(challenge.user_id, userProfile.role, {
    tid: userProfile.tenantId || tenancy.DEFAULT_TENANT,
  });
  const refreshToken = await generateRefreshToken(challenge.user_id);
  return sendPublicAuth(res, {
    decision: 'ALLOW',
    reason: 'MFA step-up verified, all checks passed',
    txId: blockchainResult.txId,
    layer: blockchainResult.layer,
    accessToken,
    refreshToken,
    tokenExpiry: config.jwtAccessExpiry,
    mfaVerified: true,
    zkProof,
    accessGrant: blockchainResult.accessGrant,
  });
});

/** MFA status for the authenticated subject only (anti-enumeration). */
api.get('/mfa/status', requireAuth, async (req, res, next) => {
  try {
    const mfaData = await db.getMFASecret(req.user.sub);
    const on = !!(mfaData && mfaData.enabled);
    res.json({ enabled: on, enrolled: on, stepUpThreshold: config.mfaStepUpThreshold });
  } catch (err) { next(err); }
});

api.get('/mfa/status/:username', requireAuth, async (req, res, next) => {
  try {
    if (req.user.sub !== req.params.username && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const mfaData = await db.getMFASecret(req.params.username);
    const on = !!(mfaData && mfaData.enabled);
    res.json({ enabled: on, enrolled: on, stepUpThreshold: config.mfaStepUpThreshold });
  } catch (err) { next(err); }
});

/** Self-service: remove TOTP authenticator (session required). */
api.post('/mfa/disable', async (req, res, next) => {
  try {
    const resolved = await resolveUserIdFromAuthOrPassword(req);
    if (resolved.error) return res.status(resolved.status).json({ error: resolved.error });
    const result = await mfa.disableMFA(resolved.userId);
    await db.writeAuditLog({
      userId: resolved.userId,
      decision: 'MFA_DISABLED',
      reason: `via ${resolved.via}`,
      layer: 'Policy Engine (MFA)',
    }).catch(() => {});
    res.json(result);
  } catch (err) { next(err); }
});

// ──────────────────────── ZKP (Experimental — not a security boundary) ────────────────────────

api.post('/zkp/prove', requireAuth, validate('zkpProve'), (req, res) => {
  if (!config.zkpEnabled) {
    return res.status(503).json({ error: 'ZKP disabled', experimental: true });
  }
  const result = zkp.createZKPPackage(req.body.riskScore, req.body.threshold || config.riskThreshold);
  if (result.success) {
    result.metadata.experimental = true;
    result.metadata.securityBoundary = false;
  }
  res.json(result);
});

api.post('/zkp/verify', requireAuth, validate('zkpVerify'), (req, res) => {
  if (!config.zkpEnabled) {
    return res.status(503).json({ error: 'ZKP disabled', experimental: true });
  }
  const result = zkp.verifyRangeProof(req.body.proof);
  result.experimental = true;
  result.securityBoundary = false;
  res.json(result);
});

// ──────────────────────── Fabric-Style Policy Params + Access Grants ────────────────────────

api.get('/policy/public-params', async (req, res, next) => {
  try {
    const params = await blockchain.getPolicyPublicParams();
    await db.storePolicyPublicParams(params);
    res.json(params);
  } catch (err) { next(err); }
});

/**
 * Admin console alias for policy public parameters.
 * GET/POST /admin/policies — used by web-app/public/admin/policies.html
 */
async function loadPolicyParamsForAdmin() {
  let params = null;
  try {
    params = await blockchain.getPolicyPublicParams();
    if (params) await db.storePolicyPublicParams(params);
  } catch (err) {
    logger.warn({ err: err.message }, 'Fabric GetPolicyPublicParams failed — falling back to DB/config');
    params = await db.getActivePolicyPublicParams();
  }
  const base = params && typeof params === 'object' ? params : {};
  return {
    ...base,
    policyId: base.policyId || base.policy_id || 'zt-iam-policy-v1',
    policyVersion: base.policyVersion || base.policy_version || '1.0.0',
    riskThreshold: base.riskThreshold ?? config.riskThreshold,
    mfaStepUpThreshold: base.mfaStepUpThreshold ?? config.mfaStepUpThreshold,
    accessGrantTtlSeconds: base.accessGrantTtlSeconds ?? 900,
    zkpRequiredForAllow: base.zkpRequiredForAllow !== false && base.zkpRequiredForAllow !== 'false',
    zkpScheme: base.zkpScheme || 'PedersenBitRangeProof',
    activeModelVersion: base.activeModelVersion || null,
    roleSchemaVersion: base.roleSchemaVersion || null,
    authorizedRiskEngines: base.authorizedRiskEngines || [],
    authorizedAuditors: base.authorizedAuditors || [],
    updatedAt: base.updatedAt || base.lastUpdate || null,
    updateTxId: base.updateTxId || base.txId || null,
  };
}

api.get('/admin/policies', requireAuth, requireRole('admin'), async (_req, res, next) => {
  try {
    res.json(await loadPolicyParamsForAdmin());
  } catch (err) { next(err); }
});

api.post('/admin/policies', requireAuth, requireRole('admin'), validate('updatePolicyPublicParams'), async (req, res, next) => {
  try {
    // Keep in-process MFA threshold in sync for evaluate() when UI updates it
    if (typeof req.body.mfaStepUpThreshold === 'number') {
      config.mfaStepUpThreshold = req.body.mfaStepUpThreshold;
    }
    if (typeof req.body.riskThreshold === 'number') {
      config.riskThreshold = req.body.riskThreshold;
    }
    const result = await blockchain.updatePolicyPublicParams(req.body);
    const params = result.params || result;
    if (params && typeof params === 'object') {
      await db.storePolicyPublicParams(params);
    }
    res.json({
      ...result,
      txId: result.txId || result.updateTxId || params?.updateTxId,
      params: await loadPolicyParamsForAdmin(),
    });
  } catch (err) { next(err); }
});

api.post('/access-grants/verify', validate('verifyAccessGrant'), async (req, res, next) => {
  try {
    const { grantId, subject, resource, permission } = req.body;
    const result = await blockchain.verifyAccessGrant(grantId, subject, resource, permission);
    if (result.valid && result.grant) {
      await db.storeAccessGrant(result.grant);
    }
    res.json(result);
  } catch (err) { next(err); }
});

api.post('/admin/policy/public-params', requireAuth, requireRole('admin'), validate('updatePolicyPublicParams'), async (req, res, next) => {
  try {
    if (typeof req.body.mfaStepUpThreshold === 'number') {
      config.mfaStepUpThreshold = req.body.mfaStepUpThreshold;
    }
    if (typeof req.body.riskThreshold === 'number') {
      config.riskThreshold = req.body.riskThreshold;
    }
    const result = await blockchain.updatePolicyPublicParams(req.body);
    if (result.params) {
      await db.storePolicyPublicParams(result.params);
    }
    res.json(result);
  } catch (err) { next(err); }
});

api.post('/admin/risk-models', requireAuth, requireRole('admin'), validate('registerRiskModel'), async (req, res, next) => {
  try {
    const result = await blockchain.registerRiskModel(
      req.body.modelVersion,
      req.body.modelHash,
      req.body.modelType,
      req.body.approvedBy || req.user.sub,
      req.body.activate === true
    );
    if (req.body.activate) {
      const params = await blockchain.getPolicyPublicParams();
      await db.storePolicyPublicParams(params);
    }
    res.json(result);
  } catch (err) { next(err); }
});

api.post('/admin/access-grants/revoke', requireAuth, requireRole('admin'), validate('revokeAccessGrant'), async (req, res, next) => {
  try {
    const result = await blockchain.revokeAccessGrant(req.body.grantId, req.body.reason || `revoked by ${req.user.sub}`);
    await db.markAccessGrantRevoked(req.body.grantId);
    res.json(result);
  } catch (err) { next(err); }
});

// ──────────────────────── Anomaly Detection ────────────────────────

api.get('/anomaly/profile/:username', requireAuth, async (req, res, next) => {
  try {
    if (req.user.sub !== req.params.username && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    res.json(await anomalyDetector.getProfileSummary(req.params.username));
  } catch (err) { next(err); }
});

api.get('/ml/health', requireAuth, requireRole('admin'), async (req, res) => {
  res.json(await mlHealth());
});

// ──────────────────────── Admin ML lifecycle (BFF → ml-service) ────────────────────────
// SPA calls /api/admin/ml/*; web-app proxies to /v1/admin/ml/* on this engine.

async function sendMlProxy(res, result) {
  return res.status(result.status).json(result.body || {});
}

api.get('/admin/ml/info', requireAuth, requireRole('admin'), async (_req, res) => {
  return sendMlProxy(res, await mlModelInfo());
});

api.get('/admin/ml/comparison', requireAuth, requireRole('admin'), async (_req, res) => {
  return sendMlProxy(res, await mlModelComparison());
});

api.get('/admin/ml/drift', requireAuth, requireRole('admin'), async (_req, res) => {
  return sendMlProxy(res, await mlFeatureDrift());
});

api.post('/admin/ml/promote', requireAuth, requireRole('admin'), async (_req, res) => {
  return sendMlProxy(res, await mlPromoteCandidate());
});

api.post('/admin/ml/rollback', requireAuth, requireRole('admin'), async (_req, res) => {
  return sendMlProxy(res, await mlRollbackChampion());
});

api.post('/anomaly/detect', requireAuth, validate('anomalyDetect'), async (req, res, next) => {
  try {
    if (req.user.sub !== req.body.username && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const context = {
      username: req.body.username,
      deviceId: req.body.deviceId || 'unknown',
      timestamp: req.body.timestamp || new Date().toISOString(),
      location: req.body.location || { country: 'UNKNOWN', city: 'UNKNOWN' },
    };
    res.json(await anomalyDetector.detectAnomalies(req.body.username, context));
  } catch (err) { next(err); }
});

// ──────────────────────── WebAuthn ────────────────────────

// Passkey registration for logged-in users (Security console) or username+password.
api.post('/webauthn/register/options', authLimiter, async (req, res, next) => {
  try {
    const resolved = await resolveUserIdFromAuthOrPassword(req);
    if (resolved.error) return res.status(resolved.status).json({ error: resolved.error });
    res.json(await webauthn.getRegistrationOptions(resolved.userId));
  } catch (err) { next(err); }
});

api.post('/webauthn/register/verify', async (req, res, next) => {
  try {
    const resolved = await resolveUserIdFromAuthOrPassword(req);
    if (resolved.error) return res.status(resolved.status).json({ error: resolved.error });
    if (!req.body?.response) return res.status(400).json({ error: 'response required' });
    res.json(await webauthn.verifyRegistration(resolved.userId, req.body.response));
  } catch (err) { next(err); }
});

api.post('/webauthn/login/options', async (req, res, next) => {
  try {
    const options = await webauthn.getAuthenticationOptions(req.body.username);
    if (options.error) return res.status(400).json(options);
    res.json(options);
  } catch (err) { next(err); }
});

api.post('/webauthn/login/verify', async (req, res, next) => {
  try {
    const { username, response, deviceId, timestamp, location, requiredPermission, resource } = req.body;
    const result = await webauthn.verifyAuthentication(username, response);
    if (!result.verified) return res.json({ decision: 'DENY', reason: 'WebAuthn verification failed: ' + result.reason, layer: 'Policy Engine (WebAuthn)' });
    const userProfile = await db.getUser(username);
    const requestContext = buildRequestContext(
      username,
      deviceId || 'webauthn-device',
      timestamp,
      '0.0.0.0',
      location
    );
    const assessment = await assessRequestRisk(userProfile, requestContext, requiredPermission || 'read');
    const { riskScore, baseRiskScore, breakdown, anomalyResult, ensemble } = assessment;
    if (riskScore >= config.riskThreshold) {
      await persistObservedLogin(username, requestContext, riskScore, 'DENY');
      ingestObservedDecision(userProfile, requestContext, assessment, 'DENY', 'Risk too high');
      promMetrics.inc('ztiam_decisions_total', { decision: 'DENY', layer: 'policy_engine', reason: 'risk_too_high' });
      promMetrics.inc('ztiam_ml_ingest_total', { label: '1' });
      return res.json({
        decision: 'DENY',
        reason: `Risk score too high (${riskScore} >= ${config.riskThreshold})`,
        riskScore,
        baseRiskScore,
        breakdown,
        anomaly: anomalyResult.anomaly,
        ensemble,
        layer: 'Policy Engine',
      });
    }

    const { proofPackage, zkProof } = createRiskProofPackage(riskScore);
    const blockchainResult = await blockchain.evaluateAccess(username, deviceId || 'webauthn-device', riskScore, requiredPermission || 'read', {
      proofPackage,
      modelVersion: await getAssessmentModelVersion(ensemble),
      resource: resource || 'default',
    });
    await persistAccessGrant(blockchainResult.accessGrant);
    if (blockchainResult.decision === 'ALLOW') {
      await resetFailedAttempts(username);
      await persistObservedLogin(username, requestContext, riskScore, 'ALLOW');
      ingestObservedDecision(userProfile, requestContext, assessment, 'ALLOW', blockchainResult.reason, blockchainResult.txId);
      promMetrics.inc('ztiam_decisions_total', { decision: 'ALLOW', layer: 'chaincode' });
      promMetrics.inc('ztiam_ml_ingest_total', { label: '0' });
      const accessToken = await generateAccessToken(username, userProfile.role, {
        tid: userProfile.tenantId || tenancy.DEFAULT_TENANT,
      });
      const refreshToken = await generateRefreshToken(username);
      return res.json({
        decision: 'ALLOW',
        reason: 'WebAuthn passwordless authentication successful',
        riskScore,
        baseRiskScore,
        breakdown,
        anomaly: anomalyResult.anomaly,
        ensemble,
        txId: blockchainResult.txId,
        layer: 'WebAuthn + ' + blockchainResult.layer,
        accessToken,
        refreshToken,
        tokenExpiry: config.jwtAccessExpiry,
        authMethod: 'webauthn',
        zkProof,
        accessGrant: blockchainResult.accessGrant,
      });
    }
    await db.recordLoginHistory(username, requestContext.deviceId, requestContext.location?.country, requestContext.location?.city, requestContext.timestamp, riskScore, blockchainResult.decision);
    ingestObservedDecision(userProfile, requestContext, assessment, blockchainResult.decision, blockchainResult.reason, blockchainResult.txId);
    promMetrics.inc('ztiam_decisions_total', { decision: blockchainResult.decision, layer: 'chaincode' });
    promMetrics.inc('ztiam_ml_ingest_total', { label: blockchainResult.decision === 'DENY' ? '1' : '0' });
    res.json({
      decision: blockchainResult.decision,
      reason: blockchainResult.reason,
      riskScore,
      baseRiskScore,
      breakdown,
      anomaly: anomalyResult.anomaly,
      ensemble,
      txId: blockchainResult.txId,
      layer: blockchainResult.layer,
    });
  } catch (err) { next(err); }
});

api.get('/webauthn/status/:username', async (req, res) => {
  res.json({
    hasPasskeys: await webauthn.hasPasskeys(req.params.username),
    passkeyCount: await webauthn.getPasskeyCount(req.params.username),
  });
});

// ──────────────────────── W3C DID ────────────────────────

api.post('/did/create', authLimiter, validate('credentialAuth'), async (req, res, next) => {
  try {
    const userProfile = await db.getUser(req.body.username);
    if (!userProfile) return res.status(401).json({ error: 'User not found' });
    const valid = await passwordPolicy.verifyPassword(req.body.password, userProfile.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    res.json(await didResolver.createDID(req.body.username));
  } catch (err) { next(err); }
});

api.get('/did/resolve/:did(*)', async (req, res, next) => {
  try {
    const resolution = await didResolver.resolveDID(req.params.did);
    if (resolution.didResolutionMetadata.error) return res.status(404).json(resolution);
    res.json(resolution);
  } catch (err) { next(err); }
});

api.post('/did/credential/issue', authLimiter, validate('issueVC'), async (req, res, next) => {
  try {
    const userProfile = await db.getUser(req.body.username);
    if (!userProfile) return res.status(401).json({ error: 'User not found' });
    const valid = await passwordPolicy.verifyPassword(req.body.password, userProfile.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    res.json(await didResolver.issueCredential(req.body.issuerDid, req.body.subjectDid, req.body.types || [], req.body.claims || {}));
  } catch (err) { next(err); }
});

api.get('/did/credential/verify/:credentialId', async (req, res, next) => {
  try {
    res.json(await didResolver.verifyCredential(req.params.credentialId));
  } catch (err) { next(err); }
});
api.get('/did/list', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    res.json(await didResolver.listDIDs());
  } catch (err) { next(err); }
});

// ──────────────────────── Admin: User Management ────────────────────────

api.post('/admin/users', requireAuth, requireRole('admin'), validate('createUser'), async (req, res, next) => {
  try {
    const result = await userProvisioning.provisionUser({
      userId: req.body.userId,
      password: req.body.password,
      role: req.body.role || 'viewer',
      devices: req.body.devices || [],
      usualCountry: req.body.usualCountry,
      usualCity: req.body.usualCity,
      normalHoursStart: req.body.normalHoursStart,
      normalHoursEnd: req.body.normalHoursEnd,
      tenantId: req.body.tenantId || req.user?.tid || tenancy.DEFAULT_TENANT,
      email: req.body.email || null,
      phone: req.body.phone || null,
    });
    req.log.info({ userId: result.userId, fabric: result.fabric?.status }, 'User dual-written (Postgres + Fabric)');
    notifyUserAsync('USER_ONBOARDED', {
      userId: result.userId,
      email: req.body.email || null,
      phone: req.body.phone || null,
      actor: req.user.sub,
      role: req.body.role || 'viewer',
      tempPassword: req.body.password,
    });
    res.status(201).json({
      status: 'created',
      userId: result.userId,
      devices: result.devices,
      fabric: result.fabric,
      notified: true,
    });
  } catch (err) {
    if (err.code === 'EXISTS' || err.code === '23505' || (err.message && err.message.includes('UNIQUE'))) {
      return res.status(409).json({ error: 'User already exists' });
    }
    if (err.code === 'PASSWORD_POLICY') {
      return res.status(400).json({ error: err.message, details: err.details });
    }
    if (err.code === 'FABRIC_PROVISION_FAILED') {
      return res.status(502).json({ error: err.message, code: err.code });
    }
    next(err);
  }
});

/** Admin: register a device for any user (Postgres + Fabric). */
api.post('/admin/users/:userId/devices', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const deviceId = req.body?.deviceId;
    if (!deviceId || String(deviceId).length > 100) {
      return res.status(400).json({ error: 'deviceId required (max 100 chars)' });
    }
    const target = await db.getUser(req.params.userId);
    if (!target) return res.status(404).json({ error: 'User not found' });
    const result = await userProvisioning.provisionDevice(req.params.userId, String(deviceId), {
      label: req.body?.label,
      role: target.role,
    });
    res.status(201).json({ registered: true, ...result });
  } catch (err) {
    if (err.code === 'FABRIC_DEVICE_FAILED') {
      return res.status(502).json({ error: err.message, code: err.code });
    }
    next(err);
  }
});

/** Admin: push an existing Postgres user (and devices) onto Fabric. */
api.post('/admin/users/:userId/sync-fabric', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const fabric = await userProvisioning.syncUserToFabric(req.params.userId);
    res.json({ synced: true, fabric });
  } catch (err) {
    if (err.code === 'NOT_FOUND') return res.status(404).json({ error: 'User not found' });
    next(err);
  }
});

api.get('/admin/users', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const users = await db.getAdminUserDirectory();
    res.json({ users });
  } catch (err) { next(err); }
});

api.get('/admin/overview', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const overview = await db.getAdminOverview();
    const ml = await mlHealth();
    res.json({
      ...overview,
      fabric: { mode: config.fabricFailureMode || 'fail_closed' },
      ml: { enabled: ml.enabled !== false, ok: ml.ok, body: ml.body || null },
      riskThreshold: config.riskThreshold,
      deviceEnrollMode: config.deviceEnrollMode,
    });
  } catch (err) { next(err); }
});

api.get('/admin/users/:userId', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const user = await db.getUser(req.params.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const devices = await db.getUserDevices(req.params.userId);
    const sessions = await db.listUserSessions(req.params.userId);
    let fabricUser = null;
    try { fabricUser = await blockchain.getUser(req.params.userId); } catch { /* optional */ }
    res.json({
      userId: user.userId,
      username: user.userId,
      role: user.role,
      status: user.status,
      email: user.email,
      phone: user.phone,
      usualLocation: user.usualLocation,
      normalHours: user.normalHours,
      tenantId: user.tenantId,
      createdAt: user.createdAt,
      devices: devices.map((d) => ({
        deviceId: d.device_id,
        label: d.label,
        registeredAt: d.registered_at instanceof Date ? d.registered_at.toISOString() : d.registered_at,
      })),
      sessions: (sessions || []).slice(0, 20),
      fabric: fabricUser,
    });
  } catch (err) { next(err); }
});

/** Suspend or re-activate (Postgres + Fabric best-effort). */
api.patch('/admin/users/:userId/status', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const status = String(req.body?.status || '').toUpperCase();
    if (!['ACTIVE', 'SUSPENDED'].includes(status)) {
      return res.status(400).json({ error: 'status must be ACTIVE or SUSPENDED' });
    }
    const target = await db.getUser(req.params.userId);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.status === 'DELETED') {
      return res.status(400).json({ error: 'Deleted accounts cannot be reactivated this way' });
    }
    if (req.params.userId === req.user.sub && status === 'SUSPENDED') {
      return res.status(400).json({ error: 'Cannot suspend your own account' });
    }
    await db.setUserStatus(req.params.userId, status);
    if (status === 'SUSPENDED') {
      await db.revokeAllUserTokens(req.params.userId);
    }
    let fabric = null;
    try {
      fabric = await blockchain.updateUserStatus(req.params.userId, status);
    } catch (fabricErr) {
      req.log.warn({ err: fabricErr.message, userId: req.params.userId }, 'Fabric status update failed');
    }
    await db.writeAuditLog({
      userId: req.params.userId,
      decision: status === 'SUSPENDED' ? 'USER_SUSPENDED' : 'USER_ACTIVATED',
      reason: `by ${req.user.sub}`,
      layer: 'Admin Console',
    });
    notifyUserAsync(status === 'SUSPENDED' ? 'USER_SUSPENDED' : 'USER_ACTIVATED', {
      userId: req.params.userId,
      email: target.email,
      phone: target.phone,
      actor: req.user.sub,
    });
    res.json({ userId: req.params.userId, status, fabric, notified: true });
  } catch (err) { next(err); }
});

/** Evict: soft-delete / redact PII (GDPR-style) + Fabric SUSPENDED + revoke sessions. */
api.post('/admin/users/:userId/evict', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const userId = req.params.userId;
    if (userId === req.user.sub) {
      return res.status(400).json({ error: 'Cannot evict your own account' });
    }
    const target = await db.getUser(userId);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.status === 'DELETED') {
      return res.status(409).json({ error: 'User already deleted' });
    }
    // Capture contact before redaction
    const email = target.email;
    const phone = target.phone;
    const redactionId = crypto.randomUUID();
    await db.eraseUserAccount(userId, redactionId);
    let fabric = null;
    try {
      fabric = await blockchain.updateUserStatus(userId, 'SUSPENDED');
    } catch (fabricErr) {
      req.log.warn({ err: fabricErr.message, userId }, 'Fabric suspend on evict failed');
    }
    await db.writeAuditLog({
      userId,
      decision: 'USER_EVICTED',
      reason: `redactionId=${redactionId} by ${req.user.sub}`,
      layer: 'Admin Console',
    });
    notifyUserAsync('USER_EVICTED', {
      userId,
      email,
      phone,
      actor: req.user.sub,
    });
    res.json({ evicted: true, userId, redactionId, fabric, notified: true });
  } catch (err) { next(err); }
});

api.post('/admin/users/:userId/revoke-sessions', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const target = await db.getUser(req.params.userId);
    if (!target) return res.status(404).json({ error: 'User not found' });
    await db.revokeAllUserTokens(req.params.userId);
    await db.writeAuditLog({
      userId: req.params.userId,
      decision: 'SESSIONS_REVOKED',
      reason: `by ${req.user.sub}`,
      layer: 'Admin Console',
    });
    notifyUserAsync('SESSIONS_REVOKED', {
      userId: req.params.userId,
      email: target.email,
      phone: target.phone,
      actor: req.user.sub,
    });
    res.json({ revoked: true, userId: req.params.userId, notified: true });
  } catch (err) { next(err); }
});

/** Admin sets a temporary password (user should change after next login). */
api.post('/admin/users/:userId/reset-password', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const newPassword = req.body?.newPassword || req.body?.password;
    if (!newPassword || String(newPassword).length < 12) {
      return res.status(400).json({ error: 'newPassword required (min 12 characters)' });
    }
    const target = await db.getUser(req.params.userId);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.status === 'DELETED') {
      return res.status(400).json({ error: 'Cannot reset password for deleted user' });
    }
    const policy = passwordPolicy.validatePassword(String(newPassword), { username: req.params.userId });
    if (!policy.ok) {
      return res.status(400).json({ error: 'Password policy violation', details: policy.errors });
    }
    const hash = await passwordPolicy.hashPassword(String(newPassword));
    await db.updateUserPassword(req.params.userId, hash);
    await db.revokeAllUserTokens(req.params.userId);
    await db.writeAuditLog({
      userId: req.params.userId,
      decision: 'PASSWORD_RESET_ADMIN',
      reason: `by ${req.user.sub}`,
      layer: 'Admin Console',
    });
    notifyUserAsync('PASSWORD_RESET_ADMIN', {
      userId: req.params.userId,
      email: target.email,
      phone: target.phone,
      actor: req.user.sub,
      tempPassword: String(newPassword),
    });
    res.json({ reset: true, userId: req.params.userId, sessionsRevoked: true, notified: true });
  } catch (err) { next(err); }
});

api.get('/admin/notifications', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const rows = await db.listNotifications({
      userId: req.query.userId || undefined,
      limit: req.query.limit,
    });
    res.json({
      notifications: rows.map((r) => ({
        id: r.id,
        userId: r.user_id,
        event: r.event,
        actor: r.actor,
        subject: r.subject,
        channels: r.channels,
        createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at,
      })),
    });
  } catch (err) { next(err); }
});

api.delete('/admin/users/:userId/devices/:deviceId', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const removed = await db.deleteUserDevice(req.params.userId, req.params.deviceId);
    if (!removed) return res.status(404).json({ error: 'Device not found' });
    await db.writeAuditLog({
      userId: req.params.userId,
      deviceId: req.params.deviceId,
      decision: 'DEVICE_REVOKED_ADMIN',
      reason: `by ${req.user.sub}`,
      layer: 'Admin Console',
    });
    res.json({ removed: true, deviceId: req.params.deviceId });
  } catch (err) { next(err); }
});

api.get('/admin/audit', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { userId, decision, limit, offset } = req.query;
    const rows = await db.queryAuditLog({
      userId,
      decision,
      limit: parseInt(limit || '100', 10),
      offset: parseInt(offset || '0', 10),
    });
    // Normalize snake_case DB rows for the admin console UI
    const entries = rows.map((r) => {
      const created = r.created_at instanceof Date ? r.created_at.toISOString() : r.created_at;
      return {
        id: r.id,
        auditId: r.tx_id || (r.id != null ? String(r.id) : null),
        txId: r.tx_id || null,
        userId: r.user_id || null,
        user: r.user_id || null,
        deviceId: r.device_id || null,
        riskScore: r.risk_score != null ? Number(r.risk_score) : null,
        decision: r.decision,
        reason: r.reason || null,
        layer: r.layer || null,
        metadata: r.metadata || null,
        timestamp: created,
        createdAt: created,
        resource: (r.metadata && (r.metadata.resource || r.metadata.resourceId)) || 'default',
      };
    });
    res.json({ entries, total: entries.length });
  } catch (err) { next(err); }
});

// ──────────────────────── Analyst feedback (Tier B.6) ────────────────────────

api.post(
  '/audit/:auditId/feedback',
  requireAuth,
  requireRole('admin'),
  validate('auditFeedback'),
  async (req, res, next) => {
    try {
      const { auditId } = req.params;
      if (!auditId || auditId.length > 200) {
        return res.status(400).json({ error: 'Invalid auditId' });
      }
      const recorded = await db.recordAuditFeedback({
        auditId,
        label: req.body.label,
        reviewer: req.user.sub,
        notes: req.body.notes,
      });
      // Best-effort relabel of the underlying ML training sample. A 404 from the
      // ML side is fine — the sample may have been pruned by retraining.
      let mlRelabel = null;
      try {
        mlRelabel = await relabelMlSample({
          auditId,
          label: req.body.label,
          reviewer: req.user.sub,
        });
      } catch (err) {
        req.log.warn({ err: err.message }, 'ML relabel call threw');
      }
      req.log.info({ auditId, label: req.body.label, reviewer: req.user.sub }, 'Audit feedback recorded');
      res.status(201).json({ feedback: recorded, mlRelabel });
    } catch (err) {
      next(err);
    }
  }
);

api.get(
  '/audit/:auditId/feedback',
  requireAuth,
  requireRole('admin'),
  async (req, res, next) => {
    try {
      const rows = await db.getAuditFeedback(req.params.auditId);
      res.json({ auditId: req.params.auditId, feedback: rows });
    } catch (err) {
      next(err);
    }
  }
);

// ──────────────────────── Audit Log (Blockchain) ────────────────────────

api.get('/audit-log', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const logs = await blockchain.getAuditLog();
    res.json(logs);
  } catch (err) { next(err); }
});

// ──────────────────────── Self-service (/me/*) ────────────────────────

api.use('/me', meRoutes);

// ──────────────────────── Federation (OIDC social + SAML) ────────────────────────

api.get('/federation/providers', (_req, res) => {
  res.json({
    oidc: federation.listProviders(),
    saml: { configured: saml.isConfigured() },
  });
});

api.get('/federation/:provider/start', authLimiter, (req, res) => {
  try {
    const provider = req.params.provider;
    if (provider === 'saml') {
      const { redirectUrl } = saml.createAuthnRequest({
        tenantId: req.query.tenant || tenancy.DEFAULT_TENANT,
      });
      return res.redirect(302, redirectUrl);
    }
    const { url } = federation.startAuth(provider, {
      tenantId: req.query.tenant || tenancy.DEFAULT_TENANT,
      redirectAfter: req.query.redirect || null,
    });
    res.redirect(302, url);
  } catch (err) {
    const code = err.code === 'FEDERATION_NOT_CONFIGURED' || err.code === 'SAML_NOT_CONFIGURED' ? 503 : 400;
    res.status(code).json({ error: err.message, code: err.code });
  }
});

api.get('/federation/:provider/callback', authLimiter, async (req, res, next) => {
  try {
    const provider = req.params.provider;
    if (provider === 'saml') {
      return res.status(400).json({ error: 'Use POST ACS for SAML', path: '/v1/federation/saml/acs' });
    }
    const { code, state, error, error_description: errDesc } = req.query;
    if (error) {
      return res.status(401).json({ error: errDesc || error || 'IdP error' });
    }
    const result = await federation.handleCallback(provider, { code, state });
    const accessToken = await generateAccessToken(result.userId, result.role, { tid: result.tenantId });
    const refreshToken = await generateRefreshToken(result.userId);
    // Browser-friendly: redirect to web app with tokens in fragment (or JSON for XHR)
    if (req.query.format === 'json' || req.headers.accept?.includes('application/json')) {
      return res.json({
        decision: 'ALLOW',
        accessToken,
        refreshToken,
        userId: result.userId,
        tenantId: result.tenantId,
        provider: result.provider,
        email: result.email,
      });
    }
    const web = process.env.WEB_APP_URL || 'http://localhost:3000';
    const q = new URLSearchParams({
      accessToken,
      refreshToken,
      provider: result.provider,
      userId: result.userId,
    });
    res.redirect(302, `${web}/oauth/callback?${q.toString()}`);
  } catch (err) {
    next(err);
  }
});

api.post('/federation/saml/acs', authLimiter, express.urlencoded({ extended: false }), async (req, res, next) => {
  try {
    const result = await saml.handleAcs({
      samlResponse: req.body.SAMLResponse || req.body.samlResponse,
      relayState: req.body.RelayState || req.body.relayState,
    });
    const accessToken = await generateAccessToken(result.userId, result.role, { tid: result.tenantId });
    const refreshToken = await generateRefreshToken(result.userId);
    const web = process.env.WEB_APP_URL || 'http://localhost:3000';
    const q = new URLSearchParams({
      accessToken,
      refreshToken,
      provider: 'saml',
      userId: result.userId,
    });
    res.redirect(302, `${web}/oauth/callback?${q.toString()}`);
  } catch (err) {
    next(err);
  }
});

api.get('/federation/saml/metadata', (_req, res) => {
  res.type('application/xml').send(saml.metadataXml());
});

// ──────────────────────── Tenants (multi-tenancy) ────────────────────────

api.get('/admin/tenants', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    res.json({ tenants: await db.listTenants(), plans: tenancy.PLAN_LIMITS });
  } catch (err) { next(err); }
});

api.post('/admin/tenants', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { name, slug, plan, billingEmail, cmkArn, settings } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name required' });
    const t = await tenancy.createTenant({ name, slug, plan, billingEmail, cmkArn, settings });
    res.status(201).json({ tenant: t });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Tenant slug exists' });
    next(err);
  }
});

api.get('/admin/tenants/:tenantId', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const t = await db.getTenant(req.params.tenantId);
    if (!t) return res.status(404).json({ error: 'Not found' });
    const users = await db.listUsersByTenant(req.params.tenantId);
    const limits = tenancy.getPlanLimits(t.plan);
    res.json({ tenant: t, users, limits });
  } catch (err) { next(err); }
});

api.patch('/admin/tenants/:tenantId', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const t = await db.updateTenant(req.params.tenantId, req.body || {});
    if (!t) return res.status(404).json({ error: 'Not found' });
    res.json({ tenant: t });
  } catch (err) { next(err); }
});

api.post('/admin/tenants/:tenantId/billing/events', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    await db.recordBillingEvent(
      req.params.tenantId,
      req.body?.eventType || 'manual',
      req.body?.amountCents,
      req.body?.metadata
    );
    res.status(201).json({ recorded: true });
  } catch (err) { next(err); }
});

// ──────────────────────── Stripe billing ────────────────────────

api.get('/billing/catalog', (_req, res) => {
  res.json(billing.getCatalog());
});

api.get('/admin/billing/:tenantId', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const summary = await billing.getBillingSummary(req.params.tenantId);
    if (!summary) return res.status(404).json({ error: 'Tenant not found' });
    res.json(summary);
  } catch (err) { next(err); }
});

api.post('/admin/billing/:tenantId/checkout', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const plan = req.body?.plan || 'team';
    const result = await billing.createCheckoutSession(req.params.tenantId, plan, {
      successUrl: req.body?.successUrl,
      cancelUrl: req.body?.cancelUrl,
      email: req.body?.email,
    });
    res.json(result);
  } catch (err) {
    if (err.code === 'STRIPE_NOT_CONFIGURED' || err.code === 'PRICE_NOT_CONFIGURED') {
      return res.status(503).json({ error: err.message, code: err.code });
    }
    next(err);
  }
});

api.post('/admin/billing/:tenantId/portal', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const result = await billing.createPortalSession(req.params.tenantId, {
      returnUrl: req.body?.returnUrl,
    });
    res.json(result);
  } catch (err) {
    if (err.code === 'STRIPE_NOT_CONFIGURED' || err.code === 'NO_CUSTOMER') {
      return res.status(err.code === 'NO_CUSTOMER' ? 400 : 503).json({ error: err.message, code: err.code });
    }
    next(err);
  }
});

api.get('/admin/billing/:tenantId/invoices', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    res.json(await billing.listInvoices(req.params.tenantId, {
      limit: parseInt(req.query.limit || '12', 10),
    }));
  } catch (err) { next(err); }
});

// Stripe webhooks need raw body — registered on app before json parser would break.
// We accept JSON here when Stripe CLI sends parsed; production should use express.raw on this path.
api.post('/billing/webhooks/stripe', async (req, res) => {
  try {
    const sig = req.headers['stripe-signature'];
    const raw = req.rawBody || JSON.stringify(req.body);
    if (process.env.STRIPE_WEBHOOK_SECRET) {
      const ok = billing.verifyWebhookSignature(raw, sig);
      if (!ok) return res.status(400).json({ error: 'Invalid signature' });
    }
    const event = req.body?.type ? req.body : JSON.parse(typeof raw === 'string' ? raw : raw.toString());
    await billing.handleWebhookEvent(event);
    res.json({ received: true });
  } catch (err) {
    req.log?.error?.({ err: err.message }, 'Stripe webhook failed');
    res.status(400).json({ error: err.message });
  }
});

api.get('/admin/pdp/status', requireAuth, requireRole('admin'), (_req, res) => {
  res.json(externalPdp.status());
});

// ──────────────────────── Password reset (anti-enumeration) ────────────────────────

api.post('/password-reset/request', authLimiter, validate('requestPasswordReset'), async (req, res, next) => {
  try {
    const { username } = req.body;
    // Always return the same response to prevent account enumeration
    const generic = {
      accepted: true,
      message: 'If the account exists, a password reset token has been issued',
    };
    const user = await db.getUser(username);
    if (!user || user.status !== 'ACTIVE') {
      return res.json(generic);
    }
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    await db.storePasswordResetToken(tokenHash, username, expiresAt);
    // In production wire this to email/SMS. Dev/test returns token when not production.
    if (config.nodeEnv !== 'production') {
      generic.devToken = rawToken;
      generic.expiresAt = expiresAt;
    }
    req.log.info({ username }, 'Password reset requested');
    res.json(generic);
  } catch (err) { next(err); }
});

api.post('/password-reset/complete', authLimiter, validate('completePasswordReset'), async (req, res, next) => {
  try {
    const { token, newPassword } = req.body;
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const row = await db.consumePasswordResetToken(tokenHash);
    if (!row) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    const policy = passwordPolicy.validatePassword(newPassword, { username: row.user_id });
    if (!policy.ok) {
      return res.status(400).json({ error: 'Password policy violation', details: policy.errors });
    }
    const hash = await passwordPolicy.hashPassword(newPassword);
    await db.updateUserPassword(row.user_id, hash);
    await db.revokeAllUserTokens(row.user_id);
    await accountLockout.resetFailedAttempts(row.user_id);
    await db.writeAuditLog({
      userId: row.user_id,
      decision: 'PASSWORD_RESET',
      reason: 'Password reset completed',
      layer: 'Self-service',
    });
    res.json({ reset: true });
  } catch (err) { next(err); }
});

// ──────────────────────── ABAC admin ────────────────────────

api.get('/admin/abac/policies', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const policies = await db.listAbacPolicies({});
    res.json({ policies, builtin: abac.BUILTIN });
  } catch (err) { next(err); }
});

api.post('/admin/abac/policies', requireAuth, requireRole('admin'), validate('abacPolicy'), async (req, res, next) => {
  try {
    const doc = {
      id: req.body.policyId,
      effect: req.body.effect,
      principal: req.body.principal || {},
      action: req.body.action || [],
      resource: req.body.resource || {},
      when: req.body.when || {},
      description: req.body.description,
    };
    await db.upsertAbacPolicy(req.body.policyId, doc, req.body.description, req.user.sub);
    res.status(201).json({ stored: true, policy: doc });
  } catch (err) { next(err); }
});

api.delete('/admin/abac/policies/:policyId', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const ok = await db.deleteAbacPolicy(req.params.policyId);
    if (!ok) return res.status(404).json({ error: 'Policy not found' });
    res.json({ deleted: true });
  } catch (err) { next(err); }
});

api.post('/admin/abac/evaluate', requireAuth, requireRole('admin'), validate('abacEvaluate'), async (req, res, next) => {
  try {
    const result = await externalPdp.evaluate({
      ...req.body,
      hour: new Date().getHours(),
      tenantId: req.body.tenantId || tenancy.DEFAULT_TENANT,
    });
    res.json(result);
  } catch (err) { next(err); }
});

// ──────────────────────── DID list (admin only) ────────────────────────

// ──────────────────────── Error Handler ────────────────────────

app.use(api);
app.use('/v1', api);
// SCIM 2.0 provisioning (outside versioned api router for standard path)
app.use('/scim/v2', scimRouter);
app.use('/v1/scim/v2', scimRouter);
app.use(errorHandler);

// ──────────────────────── Startup ────────────────────────

async function start() {
  await db.init();
  await db._prepareStatements();

  await initKeys();
  await oauth.initKeys();

  await db.seedOAuthClient();

  // SEED_DEMO=true seeds alice/bob. Allowed even when NODE_ENV=production for local
  // compose demos; never enable in real production deployments.
  if (config.seedDemo) {
    if (config.nodeEnv === 'production') {
      logger.warn('SEED_DEMO=true in production mode — demo users will be created (local/dev only)');
    }
    const seeded = await db.seedDemoData();
    if (seeded) {
      logger.info('Demo data seeded (alice, bob)');
      await mfa.seedDemoSecrets();
      didResolver.seedDemoDIDs().catch((err) => {
        logger.error({ err: err.message }, 'Failed to seed demo DIDs on Fabric');
      });
      await anomalyDetector.seedDemoProfiles();
    }
  }

  blockchain.getPolicyPublicParams()
    .then(async (params) => {
      await db.storePolicyPublicParams(params);
      logger.info({ policyId: params.policyId, policyVersion: params.policyVersion }, 'Policy public params synced from Fabric');
    })
    .catch((err) => {
      logger.warn({ err: err.message }, 'Policy public params sync skipped');
    });

  const cleanupTimer = setInterval(() => {
    db.runCleanupJobs()
      .then((cleaned) => logger.debug(cleaned, 'Cleanup job completed'))
      .catch((err) => logger.warn({ err: err.message }, 'Cleanup job failed'));
  }, config.cleanupInterval);
  cleanupTimer.unref();

  /** @returns {Promise<import('net').Server>} */
  const listenServer = () => new Promise((resolve, reject) => {
    if (config.tlsEnabled) {
      const fs = require('fs');
      const https = require('https');
      const tlsOpts = {
        key: fs.readFileSync(config.tlsKeyPath),
        cert: fs.readFileSync(config.tlsCertPath),
        ca: fs.readFileSync(config.tlsClientCaPath),
        requestCert: true,
        rejectUnauthorized: false,
        minVersion: 'TLSv1.2',
      };
      const server = https.createServer(tlsOpts, app).listen(config.port, () => resolve(server));
      server.on('error', reject);
      return;
    }
    const server = app.listen(config.port, () => resolve(server));
    server.on('error', reject);
  });

  const server = await listenServer();
  logger.info({
    port: config.port,
    tls: !!config.tlsEnabled,
    blockchain: 'Hyperledger Fabric',
    riskThreshold: config.riskThreshold,
    mfaStepUp: config.mfaStepUpThreshold,
    zkp: config.zkpEnabled ? 'enabled (experimental)' : 'disabled',
    anomalyWeight: config.anomalyWeight,
  }, config.tlsEnabled ? `Policy Engine HTTPS on port ${config.port}` : `Policy Engine HTTP on port ${config.port}`);

  const shutdown = (signal) => {
    logger.info({ signal }, 'Shutting down gracefully');
    clearInterval(cleanupTimer);
    try {
      blockchain.closeGrpcClients();
    } catch {
      /* ignore */
    }
    try {
      require('./tracing').shutdownTracing();
    } catch {
      /* ignore */
    }
    server.close(async () => {
      try {
        await db.close();
      } finally {
        logger.info('Server closed');
        process.exit(0);
      }
    });
    setTimeout(() => process.exit(1), 5000);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  return server;
}

if (require.main === module) {
  start().catch((err) => {
    logger.error({ err }, 'Failed to start policy engine');
    process.exit(1);
  });
}

module.exports = { app, start };