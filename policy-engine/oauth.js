'use strict';

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('./config');
const db = require('./database');

/**
 * OAuth 2.0 / OIDC module — fully database-backed.
 * RSA keys persisted in signing_keys table.
 * Auth codes and clients stored in database, not in-memory Maps.
 */

let rsaPrivateKey, rsaPublicKey, rsaJwk;

/**
 * Initialize or restore RSA key pair from database.
 * On first run, generates a new pair and persists it.
 * On subsequent runs, loads the existing key from the database.
 */
function initKeys() {
  let oauthKey = db.getActiveSigningKey('oauth_rsa');
  if (!oauthKey) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    db.storeSigningKey('oauth-rsa-' + Date.now(), 'oauth_rsa', privateKey, publicKey, 'RS256');
    oauthKey = db.getActiveSigningKey('oauth_rsa');
  }
  rsaPrivateKey = oauthKey.private_key;
  rsaPublicKey = oauthKey.public_key;

  const pubKeyObj = crypto.createPublicKey(rsaPublicKey);
  const jwkExport = pubKeyObj.export({ format: 'jwk' });
  rsaJwk = { ...jwkExport, kid: oauthKey.key_id, use: 'sig', alg: 'RS256' };
}

/**
 * Generate an authorization code and store it in the database.
 */
function createAuthorizationCode(userId, clientId, redirectUri, scope, nonce) {
  const code = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + config.oauthCodeExpiry * 1000).toISOString();
  db.storeOAuthCode(code, userId, clientId, redirectUri, scope || 'openid', nonce, expiresAt);
  return code;
}

/**
 * Exchange an authorization code for tokens.
 * Reads the code and client from the database.
 */
function exchangeCode(code, clientId, clientSecret, redirectUri) {
  const codeData = db.consumeOAuthCode(code);
  if (!codeData) {
    return { error: 'invalid_grant', error_description: 'Authorization code not found or expired' };
  }

  const client = db.getOAuthClient(clientId);
  if (!client || client.clientSecret !== clientSecret) {
    return { error: 'invalid_client', error_description: 'Invalid client credentials' };
  }

  if (codeData.redirect_uri !== redirectUri) {
    return { error: 'invalid_grant', error_description: 'Redirect URI mismatch' };
  }

  const scopes = codeData.scope.split(' ');
  const now = Math.floor(Date.now() / 1000);
  const issuer = config.oauthIssuer;

  const accessToken = jwt.sign(
    { sub: codeData.user_id, iss: issuer, aud: clientId, scope: codeData.scope, type: 'access' },
    rsaPrivateKey,
    { algorithm: 'RS256', expiresIn: '15m', keyid: rsaJwk.kid }
  );

  const response = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 900,
    scope: codeData.scope,
  };

  if (scopes.includes('openid')) {
    const idTokenPayload = {
      sub: codeData.user_id, iss: issuer, aud: clientId,
      iat: now, exp: now + 3600, auth_time: now,
    };
    if (codeData.nonce) idTokenPayload.nonce = codeData.nonce;
    response.id_token = jwt.sign(idTokenPayload, rsaPrivateKey, {
      algorithm: 'RS256', keyid: rsaJwk.kid,
    });
  }

  response.refresh_token = jwt.sign(
    { sub: codeData.user_id, type: 'refresh', jti: crypto.randomUUID() },
    rsaPrivateKey,
    { algorithm: 'RS256', expiresIn: '7d', keyid: rsaJwk.kid }
  );

  return response;
}

/**
 * Verify an OAuth access token.
 */
function verifyAccessToken(token) {
  try {
    const decoded = jwt.verify(token, rsaPublicKey, {
      algorithms: ['RS256'],
      issuer: config.oauthIssuer,
    });
    if (decoded.type !== 'access') return { valid: false, reason: 'Not an access token' };
    return { valid: true, claims: decoded };
  } catch (err) {
    return { valid: false, reason: err.message };
  }
}

/**
 * OIDC discovery document.
 */
function getDiscoveryDocument() {
  const issuer = config.oauthIssuer;
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    jwks_uri: `${issuer}/oauth/.well-known/jwks.json`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
  };
}

function getJwks() {
  return { keys: [rsaJwk] };
}

module.exports = {
  initKeys,
  createAuthorizationCode,
  exchangeCode,
  verifyAccessToken,
  getDiscoveryDocument,
  getJwks,
};
