'use strict';

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
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

function upstreamTimeoutSignal(ms) {
  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
    return AbortSignal.timeout(ms);
  }
  const ac = new AbortController();
  setTimeout(() => ac.abort(new Error('POLICY_FETCH_TIMEOUT')), ms);
  return ac.signal;
}

async function policyFetch(pathOrUrl, opts = {}) {
  const resolved = /^https?:\/\//i.test(pathOrUrl) ? pathOrUrl : `${POLICY_ENGINE_INTERNAL_URL}${pathOrUrl}`;
  let urlObj;
  try {
    urlObj = new URL(resolved);
  } catch (e) {
    throw new Error(`Invalid POLICY_ENGINE URL: ${resolved}`);
  }

  const useHttps = urlObj.protocol === 'https:';
  const lib = useHttps ? https : http;
  const ms = parseInt(process.env.POLICY_FETCH_TIMEOUT_MS || '60000', 10);
  const agentOpts = useHttps ? outboundPolicyAgentOptions() : {};
  const signal = opts.signal ?? upstreamTimeoutSignal(ms);

  /** @type {import('http').RequestOptions} */
  const reqOpts = {
    hostname: urlObj.hostname,
    port: urlObj.port || (useHttps ? 443 : 80),
    path: `${urlObj.pathname}${urlObj.search}`,
    method: opts.method || 'GET',
    headers: { ...(opts.headers || {}) },
    agent: agentOpts.agent,
  };

  let bodySent = '';
  if (opts.body !== undefined && opts.body !== null) {
    bodySent = typeof opts.body === 'string' ? opts.body : String(opts.body);
    reqOpts.headers['Content-Length'] = Buffer.byteLength(bodySent, 'utf8');
    if (!reqOpts.headers['Content-Type']) reqOpts.headers['Content-Type'] = 'application/json';
  }

  return await new Promise((resolve, reject) => {
    let settled = false;
    /** @type {import('http').ClientRequest} */
    let req;

    function settle(err, val) {
      if (settled) return;
      settled = true;
      if (signal) signal.removeEventListener('abort', onAbort);
      if (err) reject(err);
      else resolve(val);
    }

    function onAbort() {
      if (req) req.destroy();
      settle(new Error('POLICY_FETCH_ABORT'));
    }

    if (signal) {
      if (signal.aborted) {
        settle(new Error('POLICY_FETCH_ABORT'));
        return;
      }
      signal.addEventListener('abort', onAbort, { once: true });
    }

    req = lib.request(reqOpts, (incoming) => {
      const chunks = [];
      incoming.on('data', (c) => chunks.push(c));
      incoming.on('end', () => {
        const buf = Buffer.concat(chunks);
        const headers = incoming.headers || {};
        settle(null, {
          ok: incoming.statusCode >= 200 && incoming.statusCode < 300,
          status: incoming.statusCode,
          headers: {
            ...headers,
            get(name) {
              const key = String(name).toLowerCase();
              const v = headers[key];
              return Array.isArray(v) ? v[0] : (v || null);
            },
          },
          /** @returns {Promise<any>} */
          async json() {
            if (!buf.length) return {};
            return JSON.parse(buf.toString('utf8'));
          },
          async text() {
            return buf.toString('utf8');
          },
          async arrayBuffer() {
            return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
          },
        });
      });
    });

    req.on('error', (e) => settle(e));

    req.setTimeout(ms, () => {
      req.destroy();
      settle(Object.assign(new Error('POLICY_FETCH_TIMEOUT'), { name: 'TimeoutError' }));
    });

    if (bodySent) req.write(bodySent, 'utf8');
    req.end();
  });
}

function cookieSecureFlag() {
  return (
    process.env.WEB_CSRF_SECURE === 'true'
    || (process.env.NODE_ENV || '').toLowerCase() === 'production'
  );
}

function cookieSameSiteForSessionAndCsrf() {
  return process.env.WEB_CSRF_SECURE === 'true' ? 'lax' : 'strict';
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
    sameSite: cookieSameSiteForSessionAndCsrf(),
    path: '/',
    secure: cookieSecureFlag(),
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
  secure: cookieSecureFlag(),
  sameSite: cookieSameSiteForSessionAndCsrf(),
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

    return res.status(response.status).json(result);
  } catch (err) {
    const name = err && err.name;
    if (
      err && (
        String(err.message).includes('POLICY_FETCH_TIMEOUT')
        || name === 'TimeoutError'
        || err.message === 'POLICY_FETCH_ABORT'
        || name === 'AbortError'
      )
    ) {
      return res.status(504).json({ decision: 'DENY', reason: 'Policy engine timeout' });
    }
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

// ──────────────────── Proxy: WebAuthn / MFA (session cookie → Bearer) ────────────────────

function authHeadersFromRequest(req, extra = {}) {
  const headers = { 'Content-Type': 'application/json', ...extra };
  if (req.headers.authorization) {
    headers.Authorization = req.headers.authorization;
  } else if (req.cookies?.zt_access) {
    headers.Authorization = `Bearer ${req.cookies.zt_access}`;
  }
  return headers;
}

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
        headers: authHeadersFromRequest(req),
        body: JSON.stringify(req.body || {}),
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
    const response = await policyFetch(`/webauthn/status/${req.params.username}`, {
      headers: authHeadersFromRequest(req),
    });
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
      headers: authHeadersFromRequest(req),
      body: JSON.stringify(req.body || {}),
    });
    res.status(response.status).json(await response.json());
  } catch (err) {
    res.status(502).json({ error: 'Policy engine unavailable' });
  }
});

app.post('/api/mfa/verify', async (req, res) => {
  try {
    const response = await policyFetch('/mfa/verify', {
      method: 'POST',
      headers: authHeadersFromRequest(req),
      body: JSON.stringify(req.body || {}),
    });
    res.status(response.status).json(await response.json());
  } catch (err) {
    res.status(502).json({ error: 'Policy engine unavailable' });
  }
});

app.post('/api/mfa/disable', async (req, res) => {
  try {
    const response = await policyFetch('/mfa/disable', {
      method: 'POST',
      headers: authHeadersFromRequest(req),
      body: JSON.stringify(req.body || {}),
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
      headers: authHeadersFromRequest(req),
      body: JSON.stringify(req.body || {}),
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
    const response = await policyFetch(`/mfa/status/${req.params.username}`, {
      headers: authHeadersFromRequest(req),
    });
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

// ──────────────────── HTML page routes (admin + me) ────────────────────
// These serve the static SPA-style pages from /public. The pages do their
// own role check client-side via /js/auth.js — server-side auth happens at
// the /api/* proxy below, where the bearer token is required.

const ADMIN_PAGES = ['overview', 'policies', 'audit', 'models', 'users'];
for (const page of ADMIN_PAGES) {
  app.get(`/admin/${page}`, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', `${page}.html`));
  });
}
// Dedicated operator console (HTML admin pages). Legacy React build remains at /admin-console.
app.get('/admin', (_req, res) => res.redirect('/admin/overview'));

// Modern React admin console (Vite build output under public/admin-console)
app.use('/admin-console', express.static(path.join(__dirname, 'public', 'admin-console'), {
  fallthrough: true,
  index: 'index.html',
}));
app.get('/admin-console/*', (req, res, next) => {
  const index = path.join(__dirname, 'public', 'admin-console', 'index.html');
  if (require('fs').existsSync(index)) return res.sendFile(index);
  // Dev fallback: point operators at Vite
  res.status(503).send(
    'Admin console not built. Run: cd admin-console && npm install && npm run build'
  );
});

const ME_PAGES = ['security', 'devices', 'sessions', 'data'];
for (const page of ME_PAGES) {
  app.get(`/me/${page}`, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'me', `${page}.html`));
  });
}
app.get('/me', (_req, res) => res.redirect('/me/security'));

// ──────────────────── Generic /api/admin and /api/me proxy ────────────────────
// Forwards to the policy-engine under /v1/admin/* and /v1/me/*. The bearer
// token from the browser's session is forwarded as Authorization. CSRF
// protection above already gates non-GET requests.

/** Prefer browser Authorization; else promote HttpOnly zt_access cookie to Bearer. */
function bearerFromRequest(req) {
  if (req.headers.authorization) return req.headers.authorization;
  const cookieTok = req.cookies?.zt_access;
  if (cookieTok) return `Bearer ${cookieTok}`;
  return null;
}

async function proxyToPolicyEngine(req, res) {
  const sub = req.originalUrl.replace(/^\/api/, '');
  const target = `/v1${sub}`;
  const auth = bearerFromRequest(req);
  const headers = {};
  if (auth) headers.Authorization = auth;
  const opts = { method: req.method, headers };
  if (!['GET', 'HEAD'].includes(req.method) && req.body && Object.keys(req.body).length) {
    opts.body = JSON.stringify(req.body);
    headers['Content-Type'] = 'application/json';
  }
  try {
    const upstream = await policyFetch(target, opts);
    const ct = (upstream.headers && (upstream.headers.get?.('content-type') || upstream.headers['content-type'])) || '';
    // GDPR export and similar: stream raw body when not JSON or when Content-Disposition is attachment
    const disp = upstream.headers?.get?.('content-disposition') || upstream.headers?.['content-disposition'] || '';
    if (disp.includes('attachment') || (ct && !String(ct).includes('json'))) {
      const buf = Buffer.from(await upstream.arrayBuffer());
      if (ct) res.setHeader('Content-Type', ct);
      if (disp) res.setHeader('Content-Disposition', disp);
      return res.status(upstream.status).send(buf);
    }
    let body = {};
    try { body = await upstream.json(); } catch { body = {}; }
    res.status(upstream.status).json(body);
  } catch (err) {
    if (err.message === 'POLICY_FETCH_TIMEOUT') {
      return res.status(504).json({ error: 'Upstream timeout' });
    }
    return res.status(502).json({ error: 'Upstream unavailable', detail: err.message });
  }
}

app.all('/api/admin/*', proxyToPolicyEngine);
app.all('/api/me/*',    proxyToPolicyEngine);
// Proxy /v1/* for admin-console SPA direct API calls
app.all('/v1/*', async (req, res) => {
  const target = req.originalUrl;
  const auth = bearerFromRequest(req);
  const headers = {};
  if (auth) headers.Authorization = auth;
  const opts = { method: req.method, headers };
  if (!['GET', 'HEAD'].includes(req.method) && req.body && Object.keys(req.body).length) {
    opts.body = JSON.stringify(req.body);
    headers['Content-Type'] = 'application/json';
  }
  try {
    const upstream = await policyFetch(target, opts);
    let body = {};
    try { body = await upstream.json(); } catch { body = {}; }
    res.status(upstream.status).json(body);
  } catch (err) {
    res.status(502).json({ error: 'Upstream unavailable', detail: err.message });
  }
});

// ──────────────────── Health Check ────────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', uptime: process.uptime() });
});

module.exports = { app, policyFetch, outboundPolicyAgentOptions };

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Web App running on http://localhost:${PORT}`);
  });
}
