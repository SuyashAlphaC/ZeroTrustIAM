const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { computeRiskScore, incrementFailedAttempts, resetFailedAttempts } = require('./riskScorer');
const oauth = require('./oauth');
const mfa = require('./mfa');
const didResolver = require('./didResolver');
const webauthn = require('./webauthn');
const anomalyDetector = require('./anomalyDetector');
const zkp = require('./zkpVerifier');

// Toggle between mock and real blockchain via USE_MOCK env var
const USE_MOCK = process.env.USE_MOCK === 'true';
const blockchain = USE_MOCK
  ? require('./mockBlockchain')
  : require('./fabricClient');

const app = express();
const PORT = 4000;
const RISK_THRESHOLD = 0.6;

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';

// In-memory refresh token store (in production, use Redis or a database)
const refreshTokens = new Set();

// Identity store with bcrypt-hashed passwords (cost factor 12)
const identityStore = {
  alice: {
    passwordHash: '$2b$12$EOGcMVN8FRmorMl9S/HvZO6ySwzXLWiyd.AKjSBCksUUiNjjAdyn6', // pass123
    role: 'admin',
    registeredDevices: ['dev-001'],
    usualLocation: { country: 'IN', city: 'Gwalior' },
    normalHours: [8, 18],
  },
  bob: {
    passwordHash: '$2b$12$aRTJONK0x0KNmoqWc3.POutsYXGReWVCljq1Srbys8P3fsA4Gsd/W', // bob456
    role: 'viewer',
    registeredDevices: ['dev-002'],
    usualLocation: { country: 'IN', city: 'Delhi' },
    normalHours: [9, 17],
  },
};

// Generate JWT access token
function generateAccessToken(username, role) {
  return jwt.sign(
    { sub: username, role, type: 'access' },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY, issuer: 'zt-iam-policy-engine' }
  );
}

// Generate JWT refresh token
function generateRefreshToken(username) {
  const token = jwt.sign(
    { sub: username, type: 'refresh', jti: crypto.randomUUID() },
    JWT_REFRESH_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRY, issuer: 'zt-iam-policy-engine' }
  );
  refreshTokens.add(token);
  return token;
}

app.use(express.json());

app.post('/evaluate', async (req, res) => {
  const { username, password, deviceId, timestamp, ip, location, requiredPermission } = req.body;

  console.log(`\n--- Access Request ---`);
  console.log(`User: ${username} | Device: ${deviceId} | Location: ${location?.country}/${location?.city}`);

  // Step 1: Credential verification
  const userProfile = identityStore[username];
  if (!userProfile) {
    incrementFailedAttempts(username);
    return res.json({
      decision: 'DENY',
      reason: 'Invalid credentials - user not found',
      layer: 'Policy Engine',
    });
  }

  // Verify password against bcrypt hash
  const passwordValid = await bcrypt.compare(password, userProfile.passwordHash);
  if (!passwordValid) {
    const attempts = incrementFailedAttempts(username);
    console.log(`Invalid password. Failed attempts: ${attempts}`);
    return res.json({
      decision: 'DENY',
      reason: 'Invalid credentials - wrong password',
      failedAttempts: attempts,
      layer: 'Policy Engine',
    });
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

  // Step 2b: ML anomaly detection adjustment
  const anomalyResult = anomalyDetector.adjustRiskScore(baseRiskScore, username, requestContext);
  const riskScore = anomalyResult.adjustedRiskScore;

  console.log(`Risk Score: ${baseRiskScore} -> ${riskScore} (anomaly adj: +${anomalyResult.anomalyAdjustment}) | Breakdown:`, breakdown);
  if (anomalyResult.anomaly.anomalyDetected) {
    console.log(`  Anomaly detected:`, anomalyResult.anomaly.scores);
  }

  try {
    // Step 3: Policy engine threshold check
    if (riskScore >= RISK_THRESHOLD) {
      console.log(`DENIED by Policy Engine (risk ${riskScore} >= ${RISK_THRESHOLD})`);
      const blockchainResult = await blockchain.evaluateAccess(
        username, deviceId, riskScore, requiredPermission || 'read'
      );
      // Record failed login for anomaly learning
      anomalyDetector.recordLogin(username, requestContext);
      return res.json({
        decision: 'DENY',
        reason: `Risk score too high (${riskScore} >= ${RISK_THRESHOLD})`,
        riskScore,
        baseRiskScore,
        breakdown,
        anomaly: anomalyResult.anomaly,
        layer: 'Policy Engine',
        txId: blockchainResult.txId,
      });
    }

    // Step 4: Submit to blockchain smart contract for authorization
    const blockchainResult = await blockchain.evaluateAccess(
      username, deviceId, riskScore, requiredPermission || 'read'
    );

    // On successful authentication, check MFA step-up then issue JWT tokens
    if (blockchainResult.decision === 'ALLOW') {
      resetFailedAttempts(username);

      // Check if MFA step-up is required
      const stepUpRequired = mfa.isMFAEnabled(username) &&
        mfa.requiresStepUp(riskScore, requiredPermission || 'read');

      if (stepUpRequired && !req.body.mfaCode) {
        // Create MFA challenge
        const challengeId = mfa.createChallenge(username, {
          deviceId, riskScore, requiredPermission: requiredPermission || 'read',
          breakdown, txId: blockchainResult.txId, layer: blockchainResult.layer,
        });

        console.log(`MFA step-up required for ${username} (risk=${riskScore}, perm=${requiredPermission})`);

        return res.json({
          decision: 'MFA_REQUIRED',
          reason: `Step-up authentication required (risk=${riskScore}, operation=${requiredPermission || 'read'})`,
          riskScore,
          breakdown,
          challengeId,
          layer: 'Policy Engine (MFA)',
        });
      }

      // If MFA code provided, verify it
      if (stepUpRequired && req.body.mfaCode) {
        const verification = mfa.verifyTOTP(username, req.body.mfaCode);
        if (!verification.valid) {
          return res.json({
            decision: 'DENY',
            reason: 'MFA verification failed: ' + verification.reason,
            riskScore,
            breakdown,
            layer: 'Policy Engine (MFA)',
          });
        }
        console.log(`MFA step-up verified for ${username}`);
      }

      const accessToken = generateAccessToken(username, userProfile.role);
      const refreshToken = generateRefreshToken(username);

      // Record successful login for anomaly learning
      anomalyDetector.recordLogin(username, requestContext);

      // Generate ZKP proof that risk score is below threshold
      const zkpPackage = zkp.createZKPPackage(riskScore, RISK_THRESHOLD);

      console.log(`Blockchain decision: ALLOW - ${blockchainResult.reason} | JWT issued | ZKP: ${zkpPackage.success}`);

      return res.json({
        decision: blockchainResult.decision,
        reason: blockchainResult.reason,
        riskScore,
        baseRiskScore,
        breakdown,
        anomaly: anomalyResult.anomaly,
        txId: blockchainResult.txId,
        layer: blockchainResult.layer,
        accessToken,
        refreshToken,
        tokenExpiry: ACCESS_TOKEN_EXPIRY,
        mfaVerified: stepUpRequired ? true : undefined,
        zkProof: zkpPackage.success ? {
          proofId: zkpPackage.rangeProof.proofId,
          property: zkpPackage.metadata.property,
          scheme: zkpPackage.metadata.scheme,
        } : undefined,
      });
    }

    console.log(`Blockchain decision: ${blockchainResult.decision} - ${blockchainResult.reason}`);

    res.json({
      decision: blockchainResult.decision,
      reason: blockchainResult.reason,
      riskScore,
      baseRiskScore,
      breakdown,
      anomaly: anomalyResult.anomaly,
      txId: blockchainResult.txId,
      layer: blockchainResult.layer,
    });
  } catch (err) {
    console.error('Blockchain error:', err.message);
    res.status(500).json({
      decision: 'DENY',
      reason: 'Blockchain service error: ' + err.message,
      riskScore,
      breakdown,
      layer: 'Policy Engine (error)',
    });
  }
});

// Verify JWT access token
app.post('/verify-token', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ valid: false, reason: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { issuer: 'zt-iam-policy-engine' });
    if (decoded.type !== 'access') {
      return res.status(401).json({ valid: false, reason: 'Invalid token type' });
    }
    res.json({
      valid: true,
      user: decoded.sub,
      role: decoded.role,
      expiresAt: new Date(decoded.exp * 1000).toISOString(),
    });
  } catch (err) {
    res.status(401).json({ valid: false, reason: 'Token expired or invalid' });
  }
});

// Refresh access token using refresh token
app.post('/refresh-token', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken || !refreshTokens.has(refreshToken)) {
    return res.status(401).json({ error: 'Invalid or revoked refresh token' });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET, { issuer: 'zt-iam-policy-engine' });
    if (decoded.type !== 'refresh') {
      return res.status(401).json({ error: 'Invalid token type' });
    }

    const userProfile = identityStore[decoded.sub];
    if (!userProfile) {
      return res.status(401).json({ error: 'User no longer exists' });
    }

    const newAccessToken = generateAccessToken(decoded.sub, userProfile.role);
    res.json({
      accessToken: newAccessToken,
      tokenExpiry: ACCESS_TOKEN_EXPIRY,
    });
  } catch (err) {
    refreshTokens.delete(refreshToken);
    res.status(401).json({ error: 'Refresh token expired' });
  }
});

// Revoke refresh token (logout)
app.post('/logout', (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    refreshTokens.delete(refreshToken);
  }
  res.json({ success: true, message: 'Logged out successfully' });
});

// --- OAuth 2.0 / OIDC Endpoints ---

// OIDC Discovery
app.get('/.well-known/openid-configuration', (req, res) => {
  res.json(oauth.getDiscoveryDocument());
});

// JWKS endpoint
app.get('/oauth/.well-known/jwks.json', (req, res) => {
  res.json(oauth.getJwks());
});

// OAuth Authorization endpoint
app.get('/oauth/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, scope, state, nonce } = req.query;

  if (response_type !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type' });
  }

  const client = oauth.registeredClients.get(client_id);
  if (!client) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown client_id' });
  }

  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid redirect_uri' });
  }

  // Return a simple consent form (in production, this would be a proper UI)
  res.send(`
    <html><body style="font-family:sans-serif;max-width:400px;margin:60px auto;background:#0f172a;color:#e2e8f0;padding:40px;border-radius:12px">
      <h2>Authorize Application</h2>
      <p><strong>${client_id}</strong> is requesting access to your account.</p>
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

// Process authorization (form submit)
app.use('/oauth/authorize', express.urlencoded({ extended: false }));
app.post('/oauth/authorize', async (req, res) => {
  const { client_id, redirect_uri, scope, state, nonce, username, password } = req.body;

  // Validate credentials
  const userProfile = identityStore[username];
  if (!userProfile) {
    return res.status(401).send('Invalid credentials');
  }

  const passwordValid = await bcrypt.compare(password, userProfile.passwordHash);
  if (!passwordValid) {
    return res.status(401).send('Invalid credentials');
  }

  // Generate authorization code
  const code = oauth.createAuthorizationCode(username, client_id, redirect_uri, scope, nonce);

  // Redirect back with code
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);

  res.redirect(redirectUrl.toString());
});

// OAuth Token endpoint
app.post('/oauth/token', (req, res) => {
  const { grant_type, code, client_id, client_secret, redirect_uri } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  const result = oauth.exchangeCode(code, client_id, client_secret, redirect_uri);
  if (result.error) {
    return res.status(400).json(result);
  }

  res.json(result);
});

// OIDC UserInfo endpoint
app.get('/oauth/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const token = authHeader.split(' ')[1];
  const verification = oauth.verifyAccessToken(token);
  if (!verification.valid) {
    return res.status(401).json({ error: 'invalid_token', error_description: verification.reason });
  }

  const user = identityStore[verification.claims.sub];
  if (!user) {
    return res.status(404).json({ error: 'user_not_found' });
  }

  res.json({
    sub: verification.claims.sub,
    role: user.role,
    devices: user.registeredDevices.length,
    location: user.usualLocation,
  });
});

// --- MFA Endpoints ---

// Enroll user in TOTP MFA
app.post('/mfa/enroll', async (req, res) => {
  const { username, password } = req.body;

  const userProfile = identityStore[username];
  if (!userProfile) {
    return res.status(401).json({ error: 'User not found' });
  }

  const passwordValid = await bcrypt.compare(password, userProfile.passwordHash);
  if (!passwordValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const enrollment = await mfa.enrollMFA(username);
  res.json(enrollment);
});

// Verify TOTP code (standalone)
app.post('/mfa/verify', (req, res) => {
  const { username, code } = req.body;
  const result = mfa.verifyTOTP(username, code);
  res.json(result);
});

// Complete an MFA challenge (step-up flow)
app.post('/mfa/challenge', async (req, res) => {
  const { challengeId, code } = req.body;

  const result = mfa.completeChallenge(challengeId, code);
  if (!result.valid) {
    return res.json({
      decision: 'DENY',
      reason: 'MFA challenge failed: ' + result.reason,
      layer: 'Policy Engine (MFA)',
    });
  }

  // MFA passed - issue tokens
  const { context } = result;
  const userProfile = identityStore[context.userId];
  const accessToken = generateAccessToken(context.userId, userProfile.role);
  const refreshToken = generateRefreshToken(context.userId);

  res.json({
    decision: 'ALLOW',
    reason: 'MFA step-up verified, all checks passed',
    riskScore: context.riskScore,
    breakdown: context.breakdown,
    txId: context.txId,
    layer: context.layer,
    accessToken,
    refreshToken,
    tokenExpiry: ACCESS_TOKEN_EXPIRY,
    mfaVerified: true,
  });
});

// Check MFA status for a user
app.get('/mfa/status/:username', (req, res) => {
  res.json({
    enabled: mfa.isMFAEnabled(req.params.username),
    stepUpThreshold: mfa.STEP_UP_THRESHOLD,
  });
});

// --- Zero-Knowledge Proof Endpoints ---

// Create a ZKP that risk score is below threshold
app.post('/zkp/prove', (req, res) => {
  const { riskScore, threshold } = req.body;
  const t = threshold || RISK_THRESHOLD;
  const result = zkp.createZKPPackage(riskScore, t);
  res.json(result);
});

// Verify a ZKP range proof
app.post('/zkp/verify', (req, res) => {
  const { proof } = req.body;
  const result = zkp.verifyRangeProof(proof);
  res.json(result);
});

// --- Anomaly Detection Endpoints ---

// Get behavioral profile for a user
app.get('/anomaly/profile/:username', (req, res) => {
  res.json(anomalyDetector.getProfileSummary(req.params.username));
});

// Detect anomalies for a given context (diagnostic)
app.post('/anomaly/detect', (req, res) => {
  const { username, deviceId, timestamp, location } = req.body;
  const context = {
    username,
    deviceId: deviceId || 'unknown',
    timestamp: timestamp || new Date().toISOString(),
    location: location || { country: 'UNKNOWN', city: 'UNKNOWN' },
  };
  const result = anomalyDetector.detectAnomalies(username, context);
  res.json(result);
});

// --- WebAuthn/FIDO2 Endpoints ---

// Get registration options (begin passkey enrollment)
app.post('/webauthn/register/options', async (req, res) => {
  const { username, password } = req.body;

  const userProfile = identityStore[username];
  if (!userProfile) {
    return res.status(401).json({ error: 'User not found' });
  }

  const passwordValid = await bcrypt.compare(password, userProfile.passwordHash);
  if (!passwordValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  try {
    const options = await webauthn.getRegistrationOptions(username);
    res.json(options);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Verify registration response (complete passkey enrollment)
app.post('/webauthn/register/verify', async (req, res) => {
  const { username, response } = req.body;

  try {
    const result = await webauthn.verifyRegistration(username, response);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get authentication options (begin passwordless login)
app.post('/webauthn/login/options', async (req, res) => {
  const { username } = req.body;

  try {
    const options = await webauthn.getAuthenticationOptions(username);
    if (options.error) {
      return res.status(400).json(options);
    }
    res.json(options);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Verify authentication response (complete passwordless login)
app.post('/webauthn/login/verify', async (req, res) => {
  const { username, response, deviceId, timestamp, location, requiredPermission } = req.body;

  try {
    const result = await webauthn.verifyAuthentication(username, response);

    if (!result.verified) {
      return res.json({
        decision: 'DENY',
        reason: 'WebAuthn verification failed: ' + result.reason,
        layer: 'Policy Engine (WebAuthn)',
      });
    }

    // WebAuthn verified - proceed with risk scoring and blockchain check
    const userProfile = identityStore[username];
    const requestContext = {
      username,
      deviceId: deviceId || 'webauthn-device',
      timestamp: timestamp || new Date().toISOString(),
      ip: '0.0.0.0',
      location: location || { country: 'UNKNOWN', city: 'UNKNOWN' },
    };

    const { score: riskScore, breakdown } = computeRiskScore(userProfile, requestContext);

    if (riskScore >= RISK_THRESHOLD) {
      return res.json({
        decision: 'DENY',
        reason: `Risk score too high (${riskScore} >= ${RISK_THRESHOLD})`,
        riskScore,
        breakdown,
        layer: 'Policy Engine',
      });
    }

    const blockchainResult = await blockchain.evaluateAccess(
      username, deviceId || 'webauthn-device', riskScore, requiredPermission || 'read'
    );

    if (blockchainResult.decision === 'ALLOW') {
      const accessToken = generateAccessToken(username, userProfile.role);
      const refreshToken = generateRefreshToken(username);

      return res.json({
        decision: 'ALLOW',
        reason: 'WebAuthn passwordless authentication successful',
        riskScore,
        breakdown,
        txId: blockchainResult.txId,
        layer: 'WebAuthn + ' + blockchainResult.layer,
        accessToken,
        refreshToken,
        tokenExpiry: ACCESS_TOKEN_EXPIRY,
        authMethod: 'webauthn',
      });
    }

    res.json({
      decision: blockchainResult.decision,
      reason: blockchainResult.reason,
      riskScore,
      breakdown,
      txId: blockchainResult.txId,
      layer: blockchainResult.layer,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Check WebAuthn status for a user
app.get('/webauthn/status/:username', (req, res) => {
  res.json({
    hasPasskeys: webauthn.hasPasskeys(req.params.username),
    passkeyCount: webauthn.getPasskeyCount(req.params.username),
  });
});

// --- W3C DID Endpoints ---

// Create a DID for a user
app.post('/did/create', async (req, res) => {
  const { username, password } = req.body;

  const userProfile = identityStore[username];
  if (!userProfile) {
    return res.status(401).json({ error: 'User not found' });
  }

  const passwordValid = await bcrypt.compare(password, userProfile.passwordHash);
  if (!passwordValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const result = didResolver.createDID(username);
  res.json(result);
});

// Resolve a DID document
app.get('/did/resolve/:did(*)', (req, res) => {
  const did = req.params.did;
  const resolution = didResolver.resolveDID(did);
  if (resolution.didResolutionMetadata.error) {
    return res.status(404).json(resolution);
  }
  res.json(resolution);
});

// Issue a Verifiable Credential
app.post('/did/credential/issue', async (req, res) => {
  const { issuerDid, subjectDid, types, claims, username, password } = req.body;

  // Authenticate the issuer
  const userProfile = identityStore[username];
  if (!userProfile) {
    return res.status(401).json({ error: 'User not found' });
  }

  const passwordValid = await bcrypt.compare(password, userProfile.passwordHash);
  if (!passwordValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const credential = didResolver.issueCredential(issuerDid, subjectDid, types || [], claims || {});
  res.json(credential);
});

// Verify a Verifiable Credential
app.get('/did/credential/verify/:credentialId', (req, res) => {
  const result = didResolver.verifyCredential(req.params.credentialId);
  res.json(result);
});

// List all DIDs
app.get('/did/list', (req, res) => {
  const dids = [];
  for (const [did, entry] of didResolver.didStore) {
    dids.push({
      did,
      created: entry.document.created,
      deactivated: !!entry.document.deactivated,
    });
  }
  res.json(dids);
});

// Audit log endpoint
app.get('/audit-log', async (req, res) => {
  try {
    const logs = await blockchain.getAuditLog();
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  // Seed demo data
  const mfaKeys = mfa.seedDemoSecrets();
  const dids = didResolver.seedDemoDIDs();
  anomalyDetector.seedDemoProfiles();
  console.log(`Policy Engine running on http://localhost:${PORT}`);
  console.log(`Blockchain mode: ${USE_MOCK ? 'MOCK' : 'Hyperledger Fabric'}`);
  console.log(`Risk threshold: ${RISK_THRESHOLD}`);
  console.log(`Password storage: bcrypt (cost factor 12)`);
  console.log(`JWT access token expiry: ${ACCESS_TOKEN_EXPIRY}`);
  console.log(`MFA: TOTP enabled (step-up threshold: ${mfa.STEP_UP_THRESHOLD})`);
  console.log(`MFA secrets (demo only): alice=${mfaKeys.alice}, bob=${mfaKeys.bob}`);
  console.log(`DIDs: alice=${dids.alice}, bob=${dids.bob}`);
  console.log(`Anomaly detection: enabled (weight=${anomalyDetector.ANOMALY_WEIGHT})`);
  console.log(`Registered users: ${Object.keys(identityStore).join(', ')}`);
});
