'use strict';

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
const { scoreWithML, mlHealth } = require('./mlRiskScorer');
const { computeEnsembleRisk } = require('./riskScorerEnsemble');
const zkp = require('./zkpVerifier');

const blockchain = config.useMock
  ? require('./mockBlockchain')
  : require('./fabricClient');

const app = express();

// ──────────────────────── Global Middleware ────────────────────────

app.use(securityHeaders);
app.use(express.json({ limit: '100kb' }));
app.use(requestLogger);
app.use(globalLimiter);
app.disable('x-powered-by');

// ──────────────────────── Key Management ────────────────────────

let JWT_SECRET, JWT_REFRESH_SECRET;

function initKeys() {
  // JWT signing key
  let jwtKey = db.getActiveSigningKey('jwt');
  if (!jwtKey) {
    const secret = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
    db.storeSigningKey('jwt-' + Date.now(), 'jwt', secret, null, 'HS256');
    jwtKey = db.getActiveSigningKey('jwt');
  }
  JWT_SECRET = jwtKey.private_key;

  // JWT refresh signing key
  let refreshKey = db.getActiveSigningKey('jwt_refresh');
  if (!refreshKey) {
    const secret = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
    db.storeSigningKey('jwt-refresh-' + Date.now(), 'jwt_refresh', secret, null, 'HS256');
    refreshKey = db.getActiveSigningKey('jwt_refresh');
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

function generateRefreshToken(username) {
  const token = jwt.sign(
    { sub: username, type: 'refresh', jti: crypto.randomUUID() },
    JWT_REFRESH_SECRET,
    { expiresIn: config.jwtRefreshExpiry, issuer: config.jwtIssuer }
  );
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  db.storeRefreshToken(token, username, expiresAt);
  return token;
}

// ──────────────────────── Health Check ────────────────────────

app.get('/health', (req, res) => {
  const dbOk = !!db.getDb();
  res.status(dbOk ? 200 : 503).json({
    status: dbOk ? 'healthy' : 'degraded',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    blockchain: config.useMock ? 'mock' : 'fabric',
    database: dbOk ? 'connected' : 'disconnected',
  });
});

// ──────────────────────── Core Authentication ────────────────────────

app.post('/evaluate', authLimiter, validate('evaluate'), async (req, res, next) => {
  const { username, password, deviceId, timestamp, ip, location, requiredPermission } = req.body;

  req.log.info({ username, deviceId, location }, 'Access request received');

  try {
    // Step 1: Credential verification from database
    const userProfile = db.getUser(username);
    if (!userProfile) {
      incrementFailedAttempts(username);
      req.log.warn({ username }, 'User not found');
      db.writeAuditLog({ userId: username, deviceId, decision: 'DENY', reason: 'User not found', layer: 'Policy Engine' });
      return res.json({ decision: 'DENY', reason: 'Invalid credentials - user not found', layer: 'Policy Engine' });
    }

    const passwordValid = await bcrypt.compare(password, userProfile.passwordHash);
    if (!passwordValid) {
      const attempts = incrementFailedAttempts(username);
      req.log.warn({ username, attempts }, 'Invalid password');
      db.writeAuditLog({ userId: username, deviceId, decision: 'DENY', reason: 'Wrong password', layer: 'Policy Engine' });
      return res.json({ decision: 'DENY', reason: 'Invalid credentials - wrong password', failedAttempts: attempts, layer: 'Policy Engine' });
    }

    // Step 2: Compute contextual risk score
    const requestContext = {
      username,
      deviceId,
      timestamp: timestamp || new Date().toISOString(),
      ip: ip || '0.0.0.0',
      location: location || { country: 'UNKNOWN', city: 'UNKNOWN' },
    };

    const { score: baseRiskScore, breakdown } = computeRiskScore(userProfile, requestContext);

    // Step 2b: behavioral anomaly detection (still needed for explanations + recordLogin downstream)
    const anomaly = anomalyDetector.detectAnomalies(username, requestContext);
    const anomalyScore = anomaly.combined;

    // Step 2c: ML sidecar — RandomForest data-driven score
    const profile = anomalyDetector.getProfileSummary(username);
    const mlResult = await scoreWithML(userProfile, requestContext, {
      requiredPermission: requiredPermission || 'read',
      failedAttempts: Math.round((breakdown.a_score || 0) * 5),
      knownLocations: profile.knownLocations,
      knownDevices: profile.knownDevices,
      loginHoursMean: profile.loginHours.mean,
      loginHoursStd: profile.loginHours.std,
      profileSamples: profile.loginHours.samples,
      lastLogin: profile.lastLogin,
    });

    // Step 2d: ensemble blend
    const ensemble = computeEnsembleRisk({ ahpScore: baseRiskScore, mlResult, anomalyScore });
    const riskScore = ensemble.ensembleScore;

    // Preserve legacy shape expected by the /evaluate response + downstream code
    const anomalyResult = {
      originalRiskScore: baseRiskScore,
      adjustedRiskScore: riskScore,
      anomalyAdjustment: Math.round((riskScore - baseRiskScore) * 100) / 100,
      anomaly,
    };

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
    if (riskScore >= config.riskThreshold) {
      req.log.warn({ username, riskScore }, 'Denied by policy engine: risk too high');
      const blockchainResult = await blockchain.evaluateAccess(username, deviceId, riskScore, requiredPermission || 'read');
      anomalyDetector.recordLogin(username, requestContext);
      db.recordLoginHistory(username, deviceId, location?.country, location?.city, requestContext.timestamp, riskScore, 'DENY');
      db.writeAuditLog({ txId: blockchainResult.txId, userId: username, deviceId, riskScore, decision: 'DENY', reason: 'Risk too high', layer: 'Policy Engine' });
      return res.json({
        decision: 'DENY', reason: `Risk score too high (${riskScore} >= ${config.riskThreshold})`,
        riskScore, baseRiskScore, breakdown, anomaly: anomalyResult.anomaly, ensemble,
        layer: 'Policy Engine', txId: blockchainResult.txId,
      });
    }

    // Step 4: Blockchain smart contract authorization
    const blockchainResult = await blockchain.evaluateAccess(username, deviceId, riskScore, requiredPermission || 'read');

    if (blockchainResult.decision === 'ALLOW') {
      resetFailedAttempts(username);

      // Step 5: MFA step-up check
      const mfaData = db.getMFASecret(username);
      const mfaEnabled = mfaData && mfaData.enabled;
      const stepUpRequired = mfaEnabled && mfa.requiresStepUp(riskScore, requiredPermission || 'read');

      if (stepUpRequired && !req.body.mfaCode) {
        const challengeId = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + config.mfaChallengeExpiry * 1000).toISOString();
        db.storeMFAChallenge(challengeId, username, {
          deviceId, riskScore, requiredPermission: requiredPermission || 'read',
          breakdown, txId: blockchainResult.txId, layer: blockchainResult.layer,
        }, expiresAt);

        req.log.info({ username, riskScore, requiredPermission }, 'MFA step-up required');
        return res.json({
          decision: 'MFA_REQUIRED',
          reason: `Step-up authentication required (risk=${riskScore}, operation=${requiredPermission || 'read'})`,
          riskScore, breakdown, challengeId, layer: 'Policy Engine (MFA)',
        });
      }

      if (stepUpRequired && req.body.mfaCode) {
        const verification = mfa.verifyTOTP(username, req.body.mfaCode);
        if (!verification.valid) {
          return res.json({ decision: 'DENY', reason: 'MFA verification failed: ' + verification.reason, riskScore, breakdown, layer: 'Policy Engine (MFA)' });
        }
        req.log.info({ username }, 'MFA step-up verified');
      }

      // Step 6: Issue tokens
      const accessToken = generateAccessToken(username, userProfile.role);
      const refreshToken = generateRefreshToken(username);

      // Step 7: Record login + generate ZKP
      anomalyDetector.recordLogin(username, requestContext);
      db.recordLoginHistory(username, deviceId, location?.country, location?.city, requestContext.timestamp, riskScore, 'ALLOW');

      let zkProof;
      if (config.zkpEnabled) {
        const zkpPackage = zkp.createZKPPackage(riskScore, config.riskThreshold);
        if (zkpPackage.success) {
          zkProof = {
            proofId: zkpPackage.rangeProof.proofId,
            property: zkpPackage.metadata.property,
            scheme: zkpPackage.metadata.scheme,
            experimental: config.zkpExperimental,
          };
        }
      }

      db.writeAuditLog({ txId: blockchainResult.txId, userId: username, deviceId, riskScore, decision: 'ALLOW', reason: blockchainResult.reason, layer: blockchainResult.layer });

      req.log.info({ username, txId: blockchainResult.txId }, 'Access granted');
      return res.json({
        decision: 'ALLOW', reason: blockchainResult.reason,
        riskScore, baseRiskScore, breakdown, anomaly: anomalyResult.anomaly, ensemble,
        txId: blockchainResult.txId, layer: blockchainResult.layer,
        accessToken, refreshToken, tokenExpiry: config.jwtAccessExpiry,
        mfaVerified: stepUpRequired ? true : undefined, zkProof,
      });
    }

    // Blockchain denied
    db.recordLoginHistory(username, deviceId, location?.country, location?.city, requestContext.timestamp, riskScore, blockchainResult.decision);
    db.writeAuditLog({ txId: blockchainResult.txId, userId: username, deviceId, riskScore, decision: blockchainResult.decision, reason: blockchainResult.reason, layer: blockchainResult.layer });

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

app.post('/verify-token', (req, res) => {
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

app.post('/refresh-token', validate('refreshToken'), (req, res) => {
  const { refreshToken } = req.body;
  if (!db.isRefreshTokenValid(refreshToken)) {
    return res.status(401).json({ error: 'Invalid or revoked refresh token' });
  }
  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET, { issuer: config.jwtIssuer });
    if (decoded.type !== 'refresh') return res.status(401).json({ error: 'Invalid token type' });
    const userProfile = db.getUser(decoded.sub);
    if (!userProfile) return res.status(401).json({ error: 'User no longer exists' });
    // Rotate: revoke old, issue new
    db.revokeRefreshToken(refreshToken);
    const newAccessToken = generateAccessToken(decoded.sub, userProfile.role);
    const newRefreshToken = generateRefreshToken(decoded.sub);
    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken, tokenExpiry: config.jwtAccessExpiry });
  } catch {
    db.revokeRefreshToken(refreshToken);
    res.status(401).json({ error: 'Refresh token expired' });
  }
});

app.post('/logout', validate('logout'), (req, res) => {
  if (req.body.refreshToken) db.revokeRefreshToken(req.body.refreshToken);
  res.json({ success: true, message: 'Logged out successfully' });
});

// ──────────────────────── OAuth 2.0 / OIDC ────────────────────────

app.get('/.well-known/openid-configuration', (req, res) => res.json(oauth.getDiscoveryDocument()));
app.get('/oauth/.well-known/jwks.json', (req, res) => res.json(oauth.getJwks()));

app.get('/oauth/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, scope, state, nonce } = req.query;
  if (response_type !== 'code') return res.status(400).json({ error: 'unsupported_response_type' });
  const client = db.getOAuthClient(client_id);
  if (!client) return res.status(400).json({ error: 'invalid_client' });
  if (!client.redirectUris.includes(redirect_uri)) return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid redirect_uri' });
  res.send(`
    <html><body style="font-family:sans-serif;max-width:400px;margin:60px auto;background:#0f172a;color:#e2e8f0;padding:40px;border-radius:12px">
      <h2>Authorize Application</h2>
      <p><strong>${client_id}</strong> requests access to your account.</p>
      <p>Scope: <code>${scope || 'openid'}</code></p>
      <form method="POST" action="/oauth/authorize">
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

app.use('/oauth/authorize', express.urlencoded({ extended: false }));
app.post('/oauth/authorize', authLimiter, async (req, res) => {
  const { client_id, redirect_uri, scope, state, nonce, username, password } = req.body;
  const userProfile = db.getUser(username);
  if (!userProfile) return res.status(401).send('Invalid credentials');
  const valid = await bcrypt.compare(password, userProfile.passwordHash);
  if (!valid) return res.status(401).send('Invalid credentials');
  const code = oauth.createAuthorizationCode(username, client_id, redirect_uri, scope, nonce);
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);
  res.redirect(redirectUrl.toString());
});

app.post('/oauth/token', authLimiter, validate('oauthToken'), (req, res) => {
  const { grant_type, code, client_id, client_secret, redirect_uri } = req.body;
  if (grant_type !== 'authorization_code') return res.status(400).json({ error: 'unsupported_grant_type' });
  const result = oauth.exchangeCode(code, client_id, client_secret, redirect_uri);
  if (result.error) return res.status(400).json(result);
  res.json(result);
});

app.get('/oauth/userinfo', requireAuth, (req, res) => {
  const user = db.getUser(req.user.sub);
  if (!user) return res.status(404).json({ error: 'user_not_found' });
  res.json({ sub: req.user.sub, role: user.role, devices: user.registeredDevices.length, location: user.usualLocation });
});

// ──────────────────────── MFA ────────────────────────

app.post('/mfa/enroll', authLimiter, validate('credentialAuth'), async (req, res) => {
  const userProfile = db.getUser(req.body.username);
  if (!userProfile) return res.status(401).json({ error: 'User not found' });
  const valid = await bcrypt.compare(req.body.password, userProfile.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const enrollment = await mfa.enrollMFA(req.body.username);
  res.json(enrollment);
});

app.post('/mfa/verify', validate('mfaVerify'), (req, res) => {
  res.json(mfa.verifyTOTP(req.body.username, req.body.code));
});

app.post('/mfa/challenge', validate('mfaChallenge'), async (req, res) => {
  const challenge = db.getMFAChallenge(req.body.challengeId);
  if (!challenge) return res.json({ decision: 'DENY', reason: 'MFA challenge failed: Challenge not found or expired', layer: 'Policy Engine (MFA)' });
  const verification = mfa.verifyTOTP(challenge.user_id, req.body.code);
  if (!verification.valid) return res.json({ decision: 'DENY', reason: 'MFA challenge failed: ' + verification.reason, layer: 'Policy Engine (MFA)' });
  db.deleteMFAChallenge(req.body.challengeId);
  const userProfile = db.getUser(challenge.user_id);
  const accessToken = generateAccessToken(challenge.user_id, userProfile.role);
  const refreshToken = generateRefreshToken(challenge.user_id);
  const ctx = challenge.context;
  res.json({ decision: 'ALLOW', reason: 'MFA step-up verified, all checks passed', riskScore: ctx.riskScore, breakdown: ctx.breakdown, txId: ctx.txId, layer: ctx.layer, accessToken, refreshToken, tokenExpiry: config.jwtAccessExpiry, mfaVerified: true });
});

app.get('/mfa/status/:username', (req, res) => {
  const mfaData = db.getMFASecret(req.params.username);
  res.json({ enabled: !!(mfaData && mfaData.enabled), stepUpThreshold: config.mfaStepUpThreshold });
});

// ──────────────────────── ZKP (Experimental) ────────────────────────

app.post('/zkp/prove', validate('zkpProve'), (req, res) => {
  const result = zkp.createZKPPackage(req.body.riskScore, req.body.threshold || config.riskThreshold);
  if (result.success) result.metadata.experimental = config.zkpExperimental;
  res.json(result);
});

app.post('/zkp/verify', validate('zkpVerify'), (req, res) => {
  const result = zkp.verifyRangeProof(req.body.proof);
  if (result.valid) result.experimental = config.zkpExperimental;
  res.json(result);
});

// ──────────────────────── Anomaly Detection ────────────────────────

app.get('/anomaly/profile/:username', (req, res) => res.json(anomalyDetector.getProfileSummary(req.params.username)));

app.get('/ml/health', async (req, res) => {
  res.json(await mlHealth());
});

app.post('/anomaly/detect', validate('anomalyDetect'), (req, res) => {
  const context = { username: req.body.username, deviceId: req.body.deviceId || 'unknown', timestamp: req.body.timestamp || new Date().toISOString(), location: req.body.location || { country: 'UNKNOWN', city: 'UNKNOWN' } };
  res.json(anomalyDetector.detectAnomalies(req.body.username, context));
});

// ──────────────────────── WebAuthn ────────────────────────

app.post('/webauthn/register/options', authLimiter, validate('credentialAuth'), async (req, res, next) => {
  try {
    const userProfile = db.getUser(req.body.username);
    if (!userProfile) return res.status(401).json({ error: 'User not found' });
    const valid = await bcrypt.compare(req.body.password, userProfile.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    res.json(await webauthn.getRegistrationOptions(req.body.username));
  } catch (err) { next(err); }
});

app.post('/webauthn/register/verify', async (req, res, next) => {
  try { res.json(await webauthn.verifyRegistration(req.body.username, req.body.response)); } catch (err) { next(err); }
});

app.post('/webauthn/login/options', async (req, res, next) => {
  try {
    const options = await webauthn.getAuthenticationOptions(req.body.username);
    if (options.error) return res.status(400).json(options);
    res.json(options);
  } catch (err) { next(err); }
});

app.post('/webauthn/login/verify', async (req, res, next) => {
  try {
    const { username, response, deviceId, timestamp, location, requiredPermission } = req.body;
    const result = await webauthn.verifyAuthentication(username, response);
    if (!result.verified) return res.json({ decision: 'DENY', reason: 'WebAuthn verification failed: ' + result.reason, layer: 'Policy Engine (WebAuthn)' });
    const userProfile = db.getUser(username);
    const requestContext = { username, deviceId: deviceId || 'webauthn-device', timestamp: timestamp || new Date().toISOString(), ip: '0.0.0.0', location: location || { country: 'UNKNOWN', city: 'UNKNOWN' } };
    const { score: riskScore, breakdown } = computeRiskScore(userProfile, requestContext);
    if (riskScore >= config.riskThreshold) return res.json({ decision: 'DENY', reason: `Risk score too high (${riskScore} >= ${config.riskThreshold})`, riskScore, breakdown, layer: 'Policy Engine' });
    const blockchainResult = await blockchain.evaluateAccess(username, deviceId || 'webauthn-device', riskScore, requiredPermission || 'read');
    if (blockchainResult.decision === 'ALLOW') {
      const accessToken = generateAccessToken(username, userProfile.role);
      const refreshToken = generateRefreshToken(username);
      return res.json({ decision: 'ALLOW', reason: 'WebAuthn passwordless authentication successful', riskScore, breakdown, txId: blockchainResult.txId, layer: 'WebAuthn + ' + blockchainResult.layer, accessToken, refreshToken, tokenExpiry: config.jwtAccessExpiry, authMethod: 'webauthn' });
    }
    res.json({ decision: blockchainResult.decision, reason: blockchainResult.reason, riskScore, breakdown, txId: blockchainResult.txId, layer: blockchainResult.layer });
  } catch (err) { next(err); }
});

app.get('/webauthn/status/:username', (req, res) => {
  res.json({ hasPasskeys: webauthn.hasPasskeys(req.params.username), passkeyCount: webauthn.getPasskeyCount(req.params.username) });
});

// ──────────────────────── W3C DID ────────────────────────

app.post('/did/create', authLimiter, validate('credentialAuth'), async (req, res) => {
  const userProfile = db.getUser(req.body.username);
  if (!userProfile) return res.status(401).json({ error: 'User not found' });
  const valid = await bcrypt.compare(req.body.password, userProfile.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  res.json(didResolver.createDID(req.body.username));
});

app.get('/did/resolve/:did(*)', (req, res) => {
  const resolution = didResolver.resolveDID(req.params.did);
  if (resolution.didResolutionMetadata.error) return res.status(404).json(resolution);
  res.json(resolution);
});

app.post('/did/credential/issue', authLimiter, validate('issueVC'), async (req, res) => {
  const userProfile = db.getUser(req.body.username);
  if (!userProfile) return res.status(401).json({ error: 'User not found' });
  const valid = await bcrypt.compare(req.body.password, userProfile.passwordHash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  res.json(didResolver.issueCredential(req.body.issuerDid, req.body.subjectDid, req.body.types || [], req.body.claims || {}));
});

app.get('/did/credential/verify/:credentialId', (req, res) => res.json(didResolver.verifyCredential(req.params.credentialId)));
app.get('/did/list', (req, res) => {
  res.json(didResolver.listDIDs());
});

// ──────────────────────── Admin: User Management ────────────────────────

app.post('/admin/users', requireAuth, requireRole('admin'), validate('createUser'), (req, res) => {
  try {
    db.createUser(req.body);
    req.log.info({ userId: req.body.userId }, 'User created by admin');
    res.status(201).json({ status: 'created', userId: req.body.userId });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'User already exists' });
    throw err;
  }
});

app.get('/admin/users', requireAuth, requireRole('admin'), (req, res) => {
  res.json(db.getAllUsers());
});

app.get('/admin/audit', requireAuth, requireRole('admin'), (req, res) => {
  const { userId, decision, limit, offset } = req.query;
  res.json(db.queryAuditLog({ userId, decision, limit: parseInt(limit || '100'), offset: parseInt(offset || '0') }));
});

// ──────────────────────── Audit Log (Blockchain) ────────────────────────

app.get('/audit-log', async (req, res, next) => {
  try {
    const logs = await blockchain.getAuditLog();
    res.json(logs);
  } catch (err) { next(err); }
});

// ──────────────────────── Error Handler ────────────────────────

app.use(errorHandler);

// ──────────────────────── Startup ────────────────────────

function start() {
  // Initialize database
  db.init();
  db._prepareStatements();

  // Initialize signing keys (JWT + OAuth RSA)
  initKeys();
  oauth.initKeys();

  // Seed default OAuth client (idempotent, uses config values)
  db.seedOAuthClient();

  // Seed demo data only when explicitly requested (SEED_DEMO=true)
  if (config.seedDemo && config.nodeEnv !== 'production') {
    const seeded = db.seedDemoData();
    if (seeded) {
      logger.info('Demo data seeded (alice, bob)');
      mfa.seedDemoSecrets();
      didResolver.seedDemoDIDs();
      anomalyDetector.seedDemoProfiles();
    }
  }

  // Periodic cleanup job
  const cleanupTimer = setInterval(() => {
    const cleaned = db.runCleanupJobs();
    logger.debug(cleaned, 'Cleanup job completed');
  }, config.cleanupInterval);
  cleanupTimer.unref();

  const server = app.listen(config.port, () => {
    logger.info({
      port: config.port,
      blockchain: config.useMock ? 'MOCK' : 'Hyperledger Fabric',
      riskThreshold: config.riskThreshold,
      mfaStepUp: config.mfaStepUpThreshold,
      zkp: config.zkpEnabled ? 'enabled (experimental)' : 'disabled',
      anomalyWeight: config.anomalyWeight,
    }, `Policy Engine running on http://localhost:${config.port}`);
  });

  // Graceful shutdown
  const shutdown = (signal) => {
    logger.info({ signal }, 'Shutting down gracefully');
    clearInterval(cleanupTimer);
    server.close(() => {
      db.close();
      logger.info('Server closed');
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 5000);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  return server;
}

// Start unless imported as module (for testing)
if (require.main === module) {
  start();
}

module.exports = { app, start };
