'use strict';

/**
 * Social / enterprise OIDC federation (Authorization Code + PKCE).
 *
 * Built-in providers:
 *   - google
 *   - entra  (Microsoft Entra ID / Azure AD)
 *   - okta
 *   - generic (any OIDC discovery document)
 *
 * Flow:
 *   GET  /federation/:provider/start  → redirect to IdP
 *   GET  /federation/:provider/callback → exchange code, upsert user, mint JWT
 *
 * Config via env (per provider) or tenants.settings.federation.
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const config = require('./config');
const db = require('./database');
const { logger } = require('./logger');
const tenancy = require('./tenancy');

/** In-memory PKCE/state store (production: Redis). */
const pending = new Map();
const STATE_TTL_MS = 10 * 60 * 1000;

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function sha256b64url(s) {
  return b64url(crypto.createHash('sha256').update(s).digest());
}

/**
 * Provider presets. Override client_id/secret via env.
 */
function providerConfig(name) {
  const n = String(name || '').toLowerCase();
  const base = {
    google: {
      issuer: 'https://accounts.google.com',
      authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
      token_endpoint: 'https://oauth2.googleapis.com/token',
      jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
      userinfo_endpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
      scopes: 'openid email profile',
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    },
    entra: {
      // tenant can be 'common', 'organizations', or a GUID
      tenant: process.env.ENTRA_TENANT_ID || 'common',
      get issuer() {
        return `https://login.microsoftonline.com/${this.tenant}/v2.0`;
      },
      get authorization_endpoint() {
        return `https://login.microsoftonline.com/${this.tenant}/oauth2/v2.0/authorize`;
      },
      get token_endpoint() {
        return `https://login.microsoftonline.com/${this.tenant}/oauth2/v2.0/token`;
      },
      get jwks_uri() {
        return `https://login.microsoftonline.com/${this.tenant}/discovery/v2.0/keys`;
      },
      scopes: 'openid email profile offline_access',
      clientId: process.env.ENTRA_CLIENT_ID || '',
      clientSecret: process.env.ENTRA_CLIENT_SECRET || '',
    },
    okta: {
      domain: process.env.OKTA_DOMAIN || '', // e.g. dev-xxx.okta.com
      get issuer() {
        return process.env.OKTA_ISSUER || (this.domain ? `https://${this.domain}` : '');
      },
      get authorization_endpoint() {
        return `${this.issuer}/oauth2/v1/authorize`;
      },
      get token_endpoint() {
        return `${this.issuer}/oauth2/v1/token`;
      },
      get jwks_uri() {
        return `${this.issuer}/oauth2/v1/keys`;
      },
      scopes: 'openid email profile offline_access',
      clientId: process.env.OKTA_CLIENT_ID || '',
      clientSecret: process.env.OKTA_CLIENT_SECRET || '',
    },
  };
  if (n === 'generic') {
    return {
      issuer: process.env.OIDC_ISSUER || '',
      authorization_endpoint: process.env.OIDC_AUTH_URL || '',
      token_endpoint: process.env.OIDC_TOKEN_URL || '',
      jwks_uri: process.env.OIDC_JWKS_URL || '',
      scopes: process.env.OIDC_SCOPES || 'openid email profile',
      clientId: process.env.OIDC_CLIENT_ID || '',
      clientSecret: process.env.OIDC_CLIENT_SECRET || '',
    };
  }
  return base[n] || null;
}

function callbackUrl(provider) {
  const root = process.env.FEDERATION_CALLBACK_BASE
    || config.oauthIssuer
    || `http://localhost:${config.port}`;
  return `${root.replace(/\/$/, '')}/v1/federation/${provider}/callback`;
}

/**
 * @returns {{ url: string, state: string }}
 */
function startAuth(provider, { tenantId, redirectAfter } = {}) {
  const p = providerConfig(provider);
  if (!p || !p.clientId) {
    const err = new Error(`Federation provider "${provider}" is not configured`);
    err.code = 'FEDERATION_NOT_CONFIGURED';
    throw err;
  }
  const state = b64url(crypto.randomBytes(24));
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = sha256b64url(verifier);
  pending.set(state, {
    provider,
    verifier,
    tenantId: tenantId || tenancy.DEFAULT_TENANT,
    redirectAfter: redirectAfter || null,
    exp: Date.now() + STATE_TTL_MS,
  });
  // prune
  for (const [k, v] of pending) {
    if (v.exp < Date.now()) pending.delete(k);
  }

  const params = new URLSearchParams({
    client_id: p.clientId,
    response_type: 'code',
    scope: p.scopes,
    redirect_uri: callbackUrl(provider),
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    access_type: 'offline',
    prompt: 'select_account',
  });
  // Entra needs response_mode
  if (provider === 'entra') params.set('response_mode', 'query');

  return {
    url: `${p.authorization_endpoint}?${params.toString()}`,
    state,
  };
}

async function fetchJson(url, opts = {}) {
  const res = await fetch(url, opts);
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = { raw: text }; }
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status} from ${url}`);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

/** Minimal JWKS cache */
const jwksCache = new Map();

async function getJwks(uri) {
  const hit = jwksCache.get(uri);
  if (hit && hit.exp > Date.now()) return hit.keys;
  const body = await fetchJson(uri);
  jwksCache.set(uri, { keys: body.keys || [], exp: Date.now() + 3600_000 });
  return body.keys || [];
}

function jwkToPem(jwk) {
  // Use jose-less RSA public key import via Node crypto
  if (jwk.kty !== 'RSA') throw new Error('Only RSA JWKs supported for federation');
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

async function verifyIdToken(idToken, provider) {
  const p = providerConfig(provider);
  const decoded = jwt.decode(idToken, { complete: true });
  if (!decoded) throw new Error('Invalid id_token');
  const kid = decoded.header.kid;
  const keys = await getJwks(p.jwks_uri);
  const jwk = keys.find((k) => k.kid === kid) || keys[0];
  if (!jwk) throw new Error('No JWKS key for id_token');
  const pub = jwkToPem(jwk);
  const payload = jwt.verify(idToken, pub, {
    algorithms: ['RS256', 'RS384', 'RS512'],
    audience: p.clientId,
  });
  // issuer check (entra uses sts.windows.net variants — loose match)
  if (p.issuer && payload.iss) {
    const ok = payload.iss === p.issuer
      || payload.iss.startsWith(p.issuer)
      || (provider === 'entra' && /login\.microsoftonline\.com|sts\.windows\.net/.test(payload.iss));
    if (!ok) throw new Error(`Issuer mismatch: ${payload.iss}`);
  }
  return payload;
}

/**
 * Complete OIDC code exchange and provision local user.
 * @returns {Promise<{ userId, email, tenantId, claims }>}
 */
async function handleCallback(provider, { code, state }) {
  const st = pending.get(state);
  pending.delete(state);
  if (!st || st.exp < Date.now() || st.provider !== provider) {
    const err = new Error('Invalid or expired OAuth state');
    err.code = 'INVALID_STATE';
    throw err;
  }
  const p = providerConfig(provider);
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: callbackUrl(provider),
    client_id: p.clientId,
    client_secret: p.clientSecret,
    code_verifier: st.verifier,
  });
  const tokenSet = await fetchJson(p.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  let claims = {};
  if (tokenSet.id_token) {
    claims = await verifyIdToken(tokenSet.id_token, provider);
  } else if (tokenSet.access_token && p.userinfo_endpoint) {
    claims = await fetchJson(p.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${tokenSet.access_token}` },
    });
  }

  const email = claims.email || claims.preferred_username || claims.upn || '';
  const sub = claims.sub || email;
  if (!sub) throw new Error('IdP did not return subject');

  const tenantId = st.tenantId || tenancy.DEFAULT_TENANT;
  // Stable local user id: fed_<provider>_<hash>
  const userId = `fed_${provider}_${crypto.createHash('sha256').update(`${provider}:${sub}`).digest('hex').slice(0, 16)}`;

  let user = await db.getUser(userId);
  if (!user) {
    // Random unusable password — login is federation-only; dual-write to Fabric
    const randomPass = crypto.randomBytes(32).toString('base64url') + 'Aa1!';
    const userProvisioning = require('./userProvisioning');
    await userProvisioning.provisionUser({
      userId,
      password: randomPass,
      role: 'viewer',
      usualCountry: 'UNKNOWN',
      usualCity: 'UNKNOWN',
      tenantId,
      devices: [],
      skipPasswordPolicy: true,
    });
    await db.linkFederatedIdentity({
      userId,
      provider,
      subject: String(sub),
      email: email || null,
      claims,
      tenantId,
    });
    user = await db.getUser(userId);
  } else {
    // Keep Fabric registry in sync (role/status/devices)
    try {
      await require('./userProvisioning').syncUserToFabric(userId);
    } catch (syncErr) {
      logger.warn({ err: syncErr.message, userId }, 'Federation Fabric sync skipped');
    }
    await db.linkFederatedIdentity({
      userId,
      provider,
      subject: String(sub),
      email: email || null,
      claims,
      tenantId,
    });
  }

  logger.info({ userId, provider, tenantId, email }, 'Federation login success');
  return {
    userId: user.userId,
    role: user.role,
    email,
    tenantId,
    claims,
    redirectAfter: st.redirectAfter,
    provider,
  };
}

function listProviders() {
  return ['google', 'entra', 'okta', 'generic'].map((name) => {
    const p = providerConfig(name);
    return {
      name,
      configured: !!(p && p.clientId && (p.authorization_endpoint || p.issuer)),
      scopes: p?.scopes,
    };
  });
}

module.exports = {
  providerConfig,
  startAuth,
  handleCallback,
  listProviders,
  callbackUrl,
  verifyIdToken,
};
