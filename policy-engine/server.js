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
const oauth = require('./oauth');
const mfa = require('./mfa');
const didResolver = require('./didResolver');
const webauthn = require('./webauthn');
const anomalyDetector = require('./anomalyDetector');
const { scoreWithML, mlHealth, ingestSample } = require('./mlRiskScorer');
const { computeEnsembleRisk } = require('./riskScorerEnsemble');
const zkp = require('./zkpVerifier');
const promMetrics = require('./metrics');

const blockchain = require('./fabricClient');

const app = express();

// ──────────────────────── Global Middleware ────────────────────────

app.use(securityHeaders);
app.use(express.json({ limit: '100kb' }));

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

let JWT_SECRET, JWT_REFRESH_SECRET;

async function initKeys() {
  let jwtKey = await db.getActiveSigningKey('jwt');
  if (!jwtKey) {
    const secret = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
    await db.storeSigningKey(`jwt-${Date.now()}`, 'jwt', secret, null, 'HS256');
    jwtKey = await db.getActiveSigningKey('jwt');
  }
  JWT_SECRET = jwtKey.private_key;

  let refreshKey = await db.getActiveSigningKey('jwt_refresh');
  if (!refreshKey) {
    const secret = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
    await db.storeSigningKey(`jwt-refresh-${Date.now()}`, 'jwt_refresh', secret, null, 'HS256');
    refreshKey = await db.getActiveSigningKey('jwt_refresh');
  }
  JWT_REFRESH_SECRET = refreshKey.private_key;
}

function generateAccessToken(username, role) {
  return jwt.sign(
    { sub: username, role, type: 'access' },
    JWT_SECRET,
    { expiresIn: config.jwtAccessExpiry, issuer: config.jwtIssuer }
  );
}

async function generateRefreshToken(username) {
  const token = jwt.sign(
    { sub: username, type: 'refresh', jti: crypto.randomUUID() },
    JWT_REFRESH_SECRET,
    { expiresIn: config.jwtRefreshExpiry, issuer: config.jwtIssuer }
  );
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  await db.storeRefreshToken(token, username, expiresAt);
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
  const { score: baseRiskScore, breakdown } = computeRiskScore(userProfile, requestContext);
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

function ingestObservedDecision(userProfile, requestContext, assessment, decision, reason) {
  ingestSample(userProfile, requestContext, {
    ...assessment.mlOpts,
    decision,
    reason,
  });
}

async function getAssessmentModelVersion(ensemble) {
  const params = await db.getActivePolicyPublicParams();
  return ensemble.mlModelVersion || params?.activeModelVersion || 'rules-ahp-v1';
}

function createRiskProofPackage(riskScore) {
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
      experimental: config.zkpExperimental,
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
    // Step 1: Credential verification from database
    const userProfile = await db.getUser(username);
    if (!userProfile) {
      incrementFailedAttempts(username);
      req.log.warn({ username }, 'User not found');
      await db.writeAuditLog({ userId: username, deviceId, decision: 'DENY', reason: 'User not found', layer: 'Policy Engine' });
      promMetrics.inc('ztiam_decisions_total', { decision: 'DENY', layer: 'policy_engine', reason: 'user_not_found' });
      return res.json({ decision: 'DENY', reason: 'Invalid credentials - user not found', layer: 'Policy Engine' });
    }

    const passwordValid = await bcrypt.compare(password, userProfile.passwordHash);
    if (!passwordValid) {
      const attempts = incrementFailedAttempts(username);
      req.log.warn({ username, attempts }, 'Invalid password');
      await db.writeAuditLog({ userId: username, deviceId, decision: 'DENY', reason: 'Wrong password', layer: 'Policy Engine' });
      promMetrics.inc('ztiam_decisions_total', { decision: 'DENY', layer: 'policy_engine', reason: 'wrong_password' });
      return res.json({ decision: 'DENY', reason: 'Invalid credentials - wrong password', failedAttempts: attempts, layer: 'Policy Engine' });
    }

    // Step 2: Compute contextual + anomaly + ML ensemble risk
    const requestContext = buildRequestContext(username, deviceId, timestamp, ip, location);
    const assessment = await assessRequestRisk(userProfile, requestContext, requiredPermission || 'read');
    const { baseRiskScore, breakdown, anomalyResult, ensemble, profile, riskScore } = assessment;

    req.log.info({
      username,
      baseRiskScore,
      riskScore,
      ensemble: ensemble.components,
      weights: ensemble.weights,
      mlAvailable: ensemble.mlAvailable,
      breakdown,
    }, 'Risk score computed');

    // Step 3: Policy engine threshold check
    const modelVersion = await getAssessmentModelVersion(ensemble);
    const targetResource = resource || 'default';

    if (riskScore >= config.riskThreshold) {
      req.log.warn({ username, riskScore }, 'Denied by policy engine: risk too high');
      const blockchainResult = await blockchain.evaluateAccess(username, deviceId, riskScore, requiredPermission || 'read', {
        modelVersion,
        resource: targetResource,
      });
      await persistObservedLogin(username, requestContext, riskScore, 'DENY');
      await db.writeAuditLog({ txId: blockchainResult.txId, userId: username, deviceId, riskScore, decision: 'DENY', reason: 'Risk too high', layer: 'Policy Engine' });
      ingestObservedDecision(userProfile, requestContext, assessment, 'DENY', 'Risk too high');
      promMetrics.inc('ztiam_decisions_total', { decision: 'DENY', layer: 'policy_engine', reason: 'risk_too_high' });
      promMetrics.inc('ztiam_ml_ingest_total', { label: '1' });
      return res.json({
        decision: 'DENY', reason: `Risk score too high (${riskScore} >= ${config.riskThreshold})`,
        riskScore, baseRiskScore, breakdown, anomaly: anomalyResult.anomaly, ensemble,
        layer: 'Policy Engine', txId: blockchainResult.txId,
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
        ingestObservedDecision(userProfile, requestContext, assessment, preflightResult.decision, preflightResult.reason);
        promMetrics.inc('ztiam_decisions_total', { decision: preflightResult.decision, layer: 'chaincode' });
        promMetrics.inc('ztiam_ml_ingest_total', { label: preflightResult.decision === 'DENY' ? '1' : '0' });
        return res.json({
          decision: preflightResult.decision,
          reason: preflightResult.reason,
          riskScore,
          baseRiskScore,
          breakdown,
          anomaly: anomalyResult.anomaly,
          ensemble,
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
        return res.json({
          decision: 'MFA_REQUIRED',
          reason: `Step-up authentication required (risk=${riskScore}, operation=${requiredPermission || 'read'})`,
          riskScore, breakdown, challengeId, layer: 'Policy Engine (MFA)',
        });
      }
    }

    if (stepUpRequired && req.body.mfaCode) {
      const verification = await mfa.verifyTOTP(username, req.body.mfaCode);
      if (!verification.valid) {
        return res.json({ decision: 'DENY', reason: 'MFA verification failed: ' + verification.reason, riskScore, breakdown, layer: 'Policy Engine (MFA)' });
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
      resetFailedAttempts(username);

      // Step 6: Issue session tokens
      const accessToken = generateAccessToken(username, userProfile.role);
      const refreshToken = await generateRefreshToken(username);

      // Step 7: Record login
      await persistObservedLogin(username, requestContext, riskScore, 'ALLOW');

      await db.writeAuditLog({ txId: blockchainResult.txId, userId: username, deviceId, riskScore, decision: 'ALLOW', reason: blockchainResult.reason, layer: blockchainResult.layer });

      ingestObservedDecision(userProfile, requestContext, assessment, 'ALLOW', blockchainResult.reason);
      promMetrics.inc('ztiam_decisions_total', { decision: 'ALLOW', layer: 'chaincode' });
      promMetrics.inc('ztiam_ml_ingest_total', { label: '0' });

      req.log.info({ username, txId: blockchainResult.txId }, 'Access granted');
      return res.json({
        decision: 'ALLOW', reason: blockchainResult.reason,
        riskScore, baseRiskScore, breakdown, anomaly: anomalyResult.anomaly, ensemble,
        txId: blockchainResult.txId, layer: blockchainResult.layer,
        accessToken, refreshToken, tokenExpiry: config.jwtAccessExpiry,
        mfaVerified: stepUpRequired ? true : undefined,
        zkProof,
        accessGrant: blockchainResult.accessGrant,
      });
    }

    // Blockchain denied
    await db.recordLoginHistory(username, deviceId, location?.country, location?.city, requestContext.timestamp, riskScore, blockchainResult.decision);
    await db.writeAuditLog({ txId: blockchainResult.txId, userId: username, deviceId, riskScore, decision: blockchainResult.decision, reason: blockchainResult.reason, layer: blockchainResult.layer });

    ingestObservedDecision(userProfile, requestContext, assessment, blockchainResult.decision, blockchainResult.reason);
    promMetrics.inc('ztiam_decisions_total', { decision: blockchainResult.decision, layer: 'chaincode' });
    promMetrics.inc('ztiam_ml_ingest_total', { label: blockchainResult.decision === 'DENY' ? '1' : '0' });

    req.log.info({ username, decision: blockchainResult.decision, reason: blockchainResult.reason }, 'Blockchain decision');
    res.json({
      decision: blockchainResult.decision, reason: blockchainResult.reason,
      riskScore, baseRiskScore, breakdown, anomaly: anomalyResult.anomaly, ensemble,
      txId: blockchainResult.txId, layer: blockchainResult.layer,
    });
  } catch (err) {
    next(err);
  }
});

// ──────────────────────── Token Endpoints ────────────────────────

api.post('/verify-token', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ valid: false, reason: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET, { issuer: config.jwtIssuer });
    if (decoded.type !== 'access') return res.status(401).json({ valid: false, reason: 'Invalid token type' });
    res.json({ valid: true, user: decoded.sub, role: decoded.role, expiresAt: new Date(decoded.exp * 1000).toISOString() });
  } catch {
    res.status(401).json({ valid: false, reason: 'Token expired or invalid' });
  }
});

api.post('/refresh-token', validate('refreshToken'), async (req, res) => {
  const { refreshToken } = req.body;
  if (!await db.isRefreshTokenValid(refreshToken)) {
    return res.status(401).json({ error: 'Invalid or revoked refresh token' });
  }
  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET, { issuer: config.jwtIssuer });
    if (decoded.type !== 'refresh') return res.status(401).json({ error: 'Invalid token type' });
    const userProfile = await db.getUser(decoded.sub);
    if (!userProfile) return res.status(401).json({ error: 'User no longer exists' });
    // Rotate: revoke old, issue new
    await db.revokeRefreshToken(refreshToken);
    const newAccessToken = generateAccessToken(decoded.sub, userProfile.role);
    const newRefreshToken = await generateRefreshToken(decoded.sub);
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
  const valid = await bcrypt.compare(password, userProfile.passwordHash);
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

api.post('/mfa/enroll', authLimiter, validate('credentialAuth'), async (req, res) => {
  const userProfile = await db.getUser(req.body.username);
  if (!userProfile) return res.status(401).json({ error: 'User not found' });
  const valid = await bcrypt.compare(req.body.password, userProfile.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const enrollment = await mfa.enrollMFA(req.body.username);
  res.json(enrollment);
});

api.post('/mfa/verify', validate('mfaVerify'), async (req, res) => {
  res.json(await mfa.verifyTOTP(req.body.username, req.body.code));
});

api.post('/mfa/challenge', validate('mfaChallenge'), async (req, res) => {
  const challenge = await db.getMFAChallenge(req.body.challengeId);
  if (!challenge) return res.json({ decision: 'DENY', reason: 'MFA challenge failed: Challenge not found or expired', layer: 'Policy Engine (MFA)' });
  const verification = await mfa.verifyTOTP(challenge.user_id, req.body.code);
  if (!verification.valid) return res.json({ decision: 'DENY', reason: 'MFA challenge failed: ' + verification.reason, layer: 'Policy Engine (MFA)' });
  await db.deleteMFAChallenge(req.body.challengeId);
  const userProfile = await db.getUser(challenge.user_id);
  const ctx = challenge.context;
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
    return res.json({
      decision: blockchainResult.decision,
      reason: blockchainResult.reason,
      riskScore: ctx.riskScore,
      breakdown: ctx.breakdown,
      txId: blockchainResult.txId,
      layer: blockchainResult.layer,
    });
  }
  const accessToken = generateAccessToken(challenge.user_id, userProfile.role);
  const refreshToken = await generateRefreshToken(challenge.user_id);
  res.json({
    decision: 'ALLOW',
    reason: 'MFA step-up verified, all checks passed',
    riskScore: ctx.riskScore,
    breakdown: ctx.breakdown,
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

api.get('/mfa/status/:username', async (req, res) => {
  const mfaData = await db.getMFASecret(req.params.username);
  res.json({ enabled: !!(mfaData && mfaData.enabled), stepUpThreshold: config.mfaStepUpThreshold });
});

// ──────────────────────── ZKP (Experimental) ────────────────────────

api.post('/zkp/prove', validate('zkpProve'), (req, res) => {
  const result = zkp.createZKPPackage(req.body.riskScore, req.body.threshold || config.riskThreshold);
  if (result.success) result.metadata.experimental = config.zkpExperimental;
  res.json(result);
});

api.post('/zkp/verify', validate('zkpVerify'), (req, res) => {
  const result = zkp.verifyRangeProof(req.body.proof);
  if (result.valid) result.experimental = config.zkpExperimental;
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

api.get('/anomaly/profile/:username', async (req, res) => {
  res.json(await anomalyDetector.getProfileSummary(req.params.username));
});

api.get('/ml/health', async (req, res) => {
  res.json(await mlHealth());
});

api.post('/anomaly/detect', validate('anomalyDetect'), async (req, res) => {
  const context = { username: req.body.username, deviceId: req.body.deviceId || 'unknown', timestamp: req.body.timestamp || new Date().toISOString(), location: req.body.location || { country: 'UNKNOWN', city: 'UNKNOWN' } };
  res.json(await anomalyDetector.detectAnomalies(req.body.username, context));
});

// ──────────────────────── WebAuthn ────────────────────────

api.post('/webauthn/register/options', authLimiter, validate('credentialAuth'), async (req, res, next) => {
  try {
    const userProfile = await db.getUser(req.body.username);
    if (!userProfile) return res.status(401).json({ error: 'User not found' });
    const valid = await bcrypt.compare(req.body.password, userProfile.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    res.json(await webauthn.getRegistrationOptions(req.body.username));
  } catch (err) { next(err); }
});

api.post('/webauthn/register/verify', async (req, res, next) => {
  try { res.json(await webauthn.verifyRegistration(req.body.username, req.body.response)); } catch (err) { next(err); }
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
      resetFailedAttempts(username);
      await persistObservedLogin(username, requestContext, riskScore, 'ALLOW');
      ingestObservedDecision(userProfile, requestContext, assessment, 'ALLOW', blockchainResult.reason);
      promMetrics.inc('ztiam_decisions_total', { decision: 'ALLOW', layer: 'chaincode' });
      promMetrics.inc('ztiam_ml_ingest_total', { label: '0' });
      const accessToken = generateAccessToken(username, userProfile.role);
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
    ingestObservedDecision(userProfile, requestContext, assessment, blockchainResult.decision, blockchainResult.reason);
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
    const valid = await bcrypt.compare(req.body.password, userProfile.passwordHash);
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
    const valid = await bcrypt.compare(req.body.password, userProfile.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    res.json(await didResolver.issueCredential(req.body.issuerDid, req.body.subjectDid, req.body.types || [], req.body.claims || {}));
  } catch (err) { next(err); }
});

api.get('/did/credential/verify/:credentialId', async (req, res, next) => {
  try {
    res.json(await didResolver.verifyCredential(req.params.credentialId));
  } catch (err) { next(err); }
});
api.get('/did/list', async (req, res) => {
  res.json(await didResolver.listDIDs());
});

// ──────────────────────── Admin: User Management ────────────────────────

api.post('/admin/users', requireAuth, requireRole('admin'), validate('createUser'), async (req, res, next) => {
  try {
    await db.createUser(req.body);
    req.log.info({ userId: req.body.userId }, 'User created by admin');
    res.status(201).json({ status: 'created', userId: req.body.userId });
  } catch (err) {
    if (err.code === '23505' || err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'User already exists' });
    }
    next(err);
  }
});

api.get('/admin/users', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    res.json(await db.getAllUsers());
  } catch (err) { next(err); }
});

api.get('/admin/audit', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { userId, decision, limit, offset } = req.query;
    res.json(await db.queryAuditLog({
      userId,
      decision,
      limit: parseInt(limit || '100', 10),
      offset: parseInt(offset || '0', 10),
    }));
  } catch (err) { next(err); }
});

// ──────────────────────── Audit Log (Blockchain) ────────────────────────

api.get('/audit-log', async (req, res, next) => {
  try {
    const logs = await blockchain.getAuditLog();
    res.json(logs);
  } catch (err) { next(err); }
});

// ──────────────────────── Error Handler ────────────────────────

app.use(api);
app.use('/v1', api);
app.use(errorHandler);

// ──────────────────────── Startup ────────────────────────

async function start() {
  await db.init();
  await db._prepareStatements();

  await initKeys();
  await oauth.initKeys();

  await db.seedOAuthClient();

  if (config.seedDemo && config.nodeEnv !== 'production') {
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