const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

// OAuth 2.0 / OIDC configuration
const ISSUER = 'http://localhost:4000';
const AUTHORIZATION_ENDPOINT = `${ISSUER}/oauth/authorize`;
const TOKEN_ENDPOINT = `${ISSUER}/oauth/token`;
const USERINFO_ENDPOINT = `${ISSUER}/oauth/userinfo`;
const JWKS_URI = `${ISSUER}/oauth/.well-known/jwks.json`;

// RSA key pair for signing ID tokens (generated at startup)
let rsaPrivateKey, rsaPublicKey, rsaJwk;

function initKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  rsaPrivateKey = privateKey;
  rsaPublicKey = publicKey;

  // Export public key as JWK for JWKS endpoint
  const pubKeyObj = crypto.createPublicKey(rsaPublicKey);
  const jwkExport = pubKeyObj.export({ format: 'jwk' });
  rsaJwk = {
    ...jwkExport,
    kid: 'zt-iam-key-1',
    use: 'sig',
    alg: 'RS256',
  };
}

initKeys();

// In-memory stores
const authorizationCodes = new Map(); // code -> { userId, clientId, redirectUri, scope, nonce, expiresAt }
const registeredClients = new Map();

// Register default client (the web app itself)
registeredClients.set('zt-iam-web', {
  clientId: 'zt-iam-web',
  clientSecret: 'zt-iam-web-secret-2026',
  redirectUris: ['http://localhost:3000/oauth/callback'],
  grantTypes: ['authorization_code', 'refresh_token'],
  scope: 'openid profile email',
});

// Generate an authorization code
function createAuthorizationCode(userId, clientId, redirectUri, scope, nonce) {
  const code = crypto.randomBytes(32).toString('hex');
  authorizationCodes.set(code, {
    userId,
    clientId,
    redirectUri,
    scope: scope || 'openid',
    nonce: nonce || null,
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
  });
  return code;
}

// Exchange authorization code for tokens
function exchangeCode(code, clientId, clientSecret, redirectUri) {
  const codeData = authorizationCodes.get(code);
  if (!codeData) {
    return { error: 'invalid_grant', error_description: 'Authorization code not found or expired' };
  }

  // Verify code hasn't expired
  if (Date.now() > codeData.expiresAt) {
    authorizationCodes.delete(code);
    return { error: 'invalid_grant', error_description: 'Authorization code expired' };
  }

  // Verify client
  const client = registeredClients.get(clientId);
  if (!client || client.clientSecret !== clientSecret) {
    return { error: 'invalid_client', error_description: 'Invalid client credentials' };
  }

  // Verify redirect URI matches
  if (codeData.redirectUri !== redirectUri) {
    return { error: 'invalid_grant', error_description: 'Redirect URI mismatch' };
  }

  // Code is single-use
  authorizationCodes.delete(code);

  const scopes = codeData.scope.split(' ');
  const now = Math.floor(Date.now() / 1000);

  // Build access token (opaque JWT)
  const accessToken = jwt.sign(
    {
      sub: codeData.userId,
      iss: ISSUER,
      aud: clientId,
      scope: codeData.scope,
      type: 'access',
    },
    rsaPrivateKey,
    { algorithm: 'RS256', expiresIn: '15m', keyid: 'zt-iam-key-1' }
  );

  const response = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 900,
    scope: codeData.scope,
  };

  // If openid scope requested, include ID token
  if (scopes.includes('openid')) {
    const idTokenPayload = {
      sub: codeData.userId,
      iss: ISSUER,
      aud: clientId,
      iat: now,
      exp: now + 3600,
      auth_time: now,
    };
    if (codeData.nonce) {
      idTokenPayload.nonce = codeData.nonce;
    }

    const idToken = jwt.sign(idTokenPayload, rsaPrivateKey, {
      algorithm: 'RS256',
      keyid: 'zt-iam-key-1',
    });
    response.id_token = idToken;
  }

  // Issue refresh token
  const refreshToken = jwt.sign(
    { sub: codeData.userId, type: 'refresh', jti: uuidv4() },
    rsaPrivateKey,
    { algorithm: 'RS256', expiresIn: '7d', keyid: 'zt-iam-key-1' }
  );
  response.refresh_token = refreshToken;

  return response;
}

// Verify an access token and return claims
function verifyAccessToken(token) {
  try {
    const decoded = jwt.verify(token, rsaPublicKey, { algorithms: ['RS256'], issuer: ISSUER });
    if (decoded.type !== 'access') {
      return { valid: false, reason: 'Not an access token' };
    }
    return { valid: true, claims: decoded };
  } catch (err) {
    return { valid: false, reason: err.message };
  }
}

// Get OIDC discovery document
function getDiscoveryDocument() {
  return {
    issuer: ISSUER,
    authorization_endpoint: AUTHORIZATION_ENDPOINT,
    token_endpoint: TOKEN_ENDPOINT,
    userinfo_endpoint: USERINFO_ENDPOINT,
    jwks_uri: JWKS_URI,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
  };
}

// Get JWKS
function getJwks() {
  return { keys: [rsaJwk] };
}

module.exports = {
  createAuthorizationCode,
  exchangeCode,
  verifyAccessToken,
  getDiscoveryDocument,
  getJwks,
  registeredClients,
  ISSUER,
};
