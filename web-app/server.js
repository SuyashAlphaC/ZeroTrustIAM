const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');

const app = express();
const PORT = process.env.WEB_PORT || process.env.PORT || 3000;
/** Issuer/policy base URL reachable from the user's browser (OAuth redirects). */
const POLICY_ENGINE_PUBLIC_URL = process.env.POLICY_ENGINE_URL || 'http://localhost:4000';
/** Base URL used by this server's outbound calls to the policy-engine (often the Docker network host). */
const POLICY_ENGINE_INTERNAL_URL = process.env.POLICY_ENGINE_INTERNAL_URL || POLICY_ENGINE_PUBLIC_URL;

let policyHttpsAgent;
function outboundPolicyAgentOptions() {
  if (!String(POLICY_ENGINE_INTERNAL_URL).startsWith('https://')) return {};
  const ca = process.env.POLICY_ENGINE_TLS_CA_PATH;
  const cert = process.env.POLICY_ENGINE_MTLS_CERT_PATH;
  const key = process.env.POLICY_ENGINE_MTLS_KEY_PATH;
  if (!ca || !cert || !key) {
    throw new Error(
      'POLICY_ENGINE_INTERNAL_URL uses https:// but POLICY_ENGINE_TLS_CA_PATH, POLICY_ENGINE_MTLS_CERT_PATH, and POLICY_ENGINE_MTLS_KEY_PATH must all be set'
    );
  }
  if (!policyHttpsAgent) {
    policyHttpsAgent = new https.Agent({
      ca: fs.readFileSync(ca),
      cert: fs.readFileSync(cert),
      key: fs.readFileSync(key),
      minVersion: 'TLSv1.2',
      keepAlive: true,
    });
  }
  return { agent: policyHttpsAgent };
}

async function policyFetch(pathOrUrl, opts = {}) {
  const url = /^https?:\/\//i.test(pathOrUrl) ? pathOrUrl : `${POLICY_ENGINE_INTERNAL_URL}${pathOrUrl}`;
  const agentOpts = outboundPolicyAgentOptions();
  return fetch(url, { ...agentOpts, ...opts });
}

const OAUTH_CALLBACK_URL = process.env.OAUTH_CALLBACK_URL || `http://localhost:${PORT}/oauth/callback`;
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || 'zt-iam-web';
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || process.env.OAUTH_DEFAULT_CLIENT_SECRET || 'change-me-in-production';

if ((process.env.NODE_ENV || '').toLowerCase() === 'production') {
  app.set('trust proxy', Number(process.env.WEB_TRUST_PROXY_HOPS || 1));
}

const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const Tokens = require('csrf');

const csrfProtect = new Tokens();

app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: false,
}));
app.use(cookieParser());
app.use(rateLimit({
  windowMs: parseInt(process.env.WEB_RATE_LIMIT_WINDOW_MS || '60000', 10),
  max: parseInt(process.env.WEB_RATE_LIMIT_MAX || '200', 10),
  standardHeaders: true,
  legacyHeaders: false,
}));

app.get('/api/csrf-token', (req, res) => {
  const secret = csrfProtect.secretSync();
  res.cookie('_csrf', secret, {
    httpOnly: true,
    sameSite: 'strict',
    path: '/',
    secure: process.env.WEB_CSRF_SECURE === 'true'
      || (process.env.NODE_ENV || '').toLowerCase() === 'production',
  });
  res.json({ csrfToken: csrfProtect.create(secret) });
});

const CSRF_EXEMPT_PREFIXES = new Set([
  '/csrf-token',
]);

app.use('/api', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  let sub = req.originalUrl.replace(/^\/api/, '') || '/';
  sub = sub.split('?')[0];
  for (const prefix of CSRF_EXEMPT_PREFIXES) {
    if (sub === prefix || sub.startsWith(`${prefix}/`)) return next();
  }
  const secret = req.cookies._csrf;
  const token = req.headers['x-csrf-token'];
  if (!secret || !token || !csrfProtect.verify(secret, token)) {
    return res.status(403).json({ error: 'Invalid CSRF token', code: 'CSRF_REJECTED' });
  }
  return next();
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ──────────────────── Cookie-Based Session Helpers ────────────────────

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  path: '/',
  maxAge: 15 * 60 * 1000, // 15 minutes
};

const REFRESH_COOKIE_OPTIONS = {
  ...COOKIE_OPTIONS,
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  path: '/api/refresh-token', // only sent to refresh endpoint
};

function setTokenCookies(res, accessToken, refreshToken) {
  res.cookie('zt_access', accessToken, COOKIE_OPTIONS);
  if (refreshToken) {
    res.cookie('zt_refresh', refreshToken, REFRESH_COOKIE_OPTIONS);
  }
}

function clearTokenCookies(res) {
  res.clearCookie('zt_access', { path: '/' });
  res.clearCookie('zt_refresh', { path: '/api/refresh-token' });
}

// Simple cookie parser
app.use((req, res, next) => {
  req.cookies = {};
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    cookieHeader.split(';').forEach(cookie => {
      const [name, ...rest] = cookie.trim().split('=');
      req.cookies[name] = decodeURIComponent(rest.join('='));
    });
  }
  next();
});

// ──────────────────── Proxy: Login ────────────────────

app.post('/api/login', async (req, res) => {
  try {
    const response = await policyFetch('/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });
    const result = await response.json();

    // Set tokens as HttpOnly cookies instead of sending in body
    if (result.accessToken) {
      setTokenCookies(res, result.accessToken, result.refreshToken);
      // Send a sanitized response without raw tokens
      const { accessToken, refreshToken, ...safeResult } = result;
      return res.json({ ...safeResult, tokenSet: true });
    }

    res.json(result);
  } catch (err) {
    console.error('Policy engine error:', err.message);
    res.status(502).json({ decision: 'DENY', reason: 'Policy engine unavailable' });
  }
});

// ──────────────────── Proxy: Token Verification ────────────────────

app.post('/api/verify-token', async (req, res) => {
  const token = req.cookies?.zt_access;
  if (!token) return res.status(401).json({ valid: false, reason: 'No session' });

  try {
    const response = await policyFetch('/verify-token', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const result = await response.json();
    res.status(response.status).json(result);
  } catch (err) {
    res.status(502).json({ valid: false, reason: 'Policy engine unavailable' });
  }
});

// ──────────────────── Proxy: Token Refresh ────────────────────

app.post('/api/refresh-token', async (req, res) => {
  const refreshToken = req.cookies?.zt_refresh;
  if (!refreshToken) return res.status(401).json({ error: 'No refresh token' });

  try {
    const response = await policyFetch('/refresh-token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    });
    const result = await response.json();
    if (response.ok && result.accessToken) {
      setTokenCookies(res, result.accessToken, result.refreshToken);
      return res.json({ refreshed: true, tokenExpiry: result.tokenExpiry });
    }
    res.status(response.status).json(result);
  } catch (err) {
    res.status(502).json({ error: 'Policy engine unavailable' });
  }
});

// ──────────────────── Proxy: Logout ────────────────────

app.post('/api/logout', async (req, res) => {
  const refreshToken = req.cookies?.zt_refresh;
  try {
    await policyFetch('/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    });
  } catch { /* ignore */ }
  clearTokenCookies(res);
  res.json({ success: true, message: 'Logged out successfully' });
});

// ──────────────────── Proxy: WebAuthn ────────────────────

const webauthnPaths = [
  '/webauthn/register/options',
  '/webauthn/register/verify',
  '/webauthn/login/options',
  '/webauthn/login/verify',
];
for (const wpath of webauthnPaths) {
  app.post(`/api${wpath}`, async (req, res) => {
    try {
      const response = await policyFetch(wpath, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req.body),
      });
      const result = await response.json();
      if (result.accessToken) {
        setTokenCookies(res, result.accessToken, result.refreshToken);
        const { accessToken, refreshToken, ...safe } = result;
        return res.status(response.status).json({ ...safe, tokenSet: true });
      }
      res.status(response.status).json(result);
    } catch (err) {
      res.status(502).json({ error: 'Policy engine unavailable' });
    }
  });
}

app.get('/api/webauthn/status/:username', async (req, res) => {
  try {
    const response = await policyFetch(`/webauthn/status/${req.params.username}`);
    res.json(await response.json());
  } catch (err) {
    res.status(502).json({ error: 'Policy engine unavailable' });
  }
});

// ──────────────────── Proxy: MFA ────────────────────

app.post('/api/mfa/enroll', async (req, res) => {
  try {
    const response = await policyFetch('/mfa/enroll', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });
    res.status(response.status).json(await response.json());
  } catch (err) {
    res.status(502).json({ error: 'Policy engine unavailable' });
  }
});

app.post('/api/mfa/challenge', async (req, res) => {
  try {
    const response = await policyFetch('/mfa/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });
    const result = await response.json();
    if (result.accessToken) {
      setTokenCookies(res, result.accessToken, result.refreshToken);
      const { accessToken, refreshToken, ...safe } = result;
      return res.status(response.status).json({ ...safe, tokenSet: true });
    }
    res.status(response.status).json(result);
  } catch (err) {
    res.status(502).json({ error: 'Policy engine unavailable' });
  }
});

app.get('/api/mfa/status/:username', async (req, res) => {
  try {
    const response = await policyFetch(`/mfa/status/${req.params.username}`);
    res.json(await response.json());
  } catch (err) {
    res.status(502).json({ error: 'Policy engine unavailable' });
  }
});

// ──────────────────── OAuth 2.0 ────────────────────

app.get('/oauth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.status(400).send(`OAuth Error: ${error}`);
  if (!code) return res.status(400).send('No authorization code received');

  try {
    const tokenRes = await policyFetch('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        client_id: OAUTH_CLIENT_ID,
        client_secret: OAUTH_CLIENT_SECRET,
        redirect_uri: OAUTH_CALLBACK_URL,
      }),
    });
    const tokens = await tokenRes.json();
    if (tokens.error) return res.status(400).json(tokens);

    if (tokens.access_token) {
      setTokenCookies(res, tokens.access_token, tokens.refresh_token);
    }
    res.redirect('/');
  } catch (err) {
    res.status(502).send('Token exchange failed: ' + err.message);
  }
});

app.get('/oauth/login', (req, res) => {
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();
  const authUrl = `${POLICY_ENGINE_PUBLIC_URL}/oauth/authorize?response_type=code&client_id=${OAUTH_CLIENT_ID}&redirect_uri=${encodeURIComponent(OAUTH_CALLBACK_URL)}&scope=openid%20profile&state=${state}&nonce=${nonce}`;
  res.redirect(authUrl);
});

// ──────────────────── Health Check ────────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', uptime: process.uptime() });
});

app.listen(PORT, () => {
  console.log(`Web App running on http://localhost:${PORT}`);
});
