const express = require('express');
const path = require('path');

const app = express();
const PORT = 3000;
const POLICY_ENGINE_URL = 'http://localhost:4000';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Proxy login to policy engine
app.post('/api/login', async (req, res) => {
  try {
    const response = await fetch(`${POLICY_ENGINE_URL}/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });

    const result = await response.json();
    res.json(result);
  } catch (err) {
    console.error('Policy engine error:', err.message);
    res.status(502).json({
      decision: 'DENY',
      reason: 'Policy engine unavailable',
    });
  }
});

// Proxy token verification
app.post('/api/verify-token', async (req, res) => {
  try {
    const response = await fetch(`${POLICY_ENGINE_URL}/verify-token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': req.headers.authorization || '',
      },
    });
    const result = await response.json();
    res.status(response.status).json(result);
  } catch (err) {
    res.status(502).json({ valid: false, reason: 'Policy engine unavailable' });
  }
});

// Proxy token refresh
app.post('/api/refresh-token', async (req, res) => {
  try {
    const response = await fetch(`${POLICY_ENGINE_URL}/refresh-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });
    const result = await response.json();
    res.status(response.status).json(result);
  } catch (err) {
    res.status(502).json({ error: 'Policy engine unavailable' });
  }
});

// Proxy logout
app.post('/api/logout', async (req, res) => {
  try {
    const response = await fetch(`${POLICY_ENGINE_URL}/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });
    const result = await response.json();
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: 'Policy engine unavailable' });
  }
});

// Proxy WebAuthn endpoints
const webauthnPaths = [
  '/webauthn/register/options',
  '/webauthn/register/verify',
  '/webauthn/login/options',
  '/webauthn/login/verify',
];
for (const path of webauthnPaths) {
  app.post(`/api${path}`, async (req, res) => {
    try {
      const response = await fetch(`${POLICY_ENGINE_URL}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req.body),
      });
      const result = await response.json();
      res.status(response.status).json(result);
    } catch (err) {
      res.status(502).json({ error: 'Policy engine unavailable' });
    }
  });
}

app.get('/api/webauthn/status/:username', async (req, res) => {
  try {
    const response = await fetch(`${POLICY_ENGINE_URL}/webauthn/status/${req.params.username}`);
    const result = await response.json();
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: 'Policy engine unavailable' });
  }
});

// Proxy MFA endpoints
app.post('/api/mfa/enroll', async (req, res) => {
  try {
    const response = await fetch(`${POLICY_ENGINE_URL}/mfa/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });
    const result = await response.json();
    res.status(response.status).json(result);
  } catch (err) {
    res.status(502).json({ error: 'Policy engine unavailable' });
  }
});

app.post('/api/mfa/challenge', async (req, res) => {
  try {
    const response = await fetch(`${POLICY_ENGINE_URL}/mfa/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });
    const result = await response.json();
    res.status(response.status).json(result);
  } catch (err) {
    res.status(502).json({ error: 'Policy engine unavailable' });
  }
});

app.get('/api/mfa/status/:username', async (req, res) => {
  try {
    const response = await fetch(`${POLICY_ENGINE_URL}/mfa/status/${req.params.username}`);
    const result = await response.json();
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: 'Policy engine unavailable' });
  }
});

// OAuth 2.0 callback handler
app.get('/oauth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send(`OAuth Error: ${error}`);
  }

  if (!code) {
    return res.status(400).send('No authorization code received');
  }

  try {
    // Exchange code for tokens
    const tokenRes = await fetch(`${POLICY_ENGINE_URL}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        client_id: 'zt-iam-web',
        client_secret: 'zt-iam-web-secret-2026',
        redirect_uri: 'http://localhost:3000/oauth/callback',
      }),
    });

    const tokens = await tokenRes.json();
    if (tokens.error) {
      return res.status(400).json(tokens);
    }

    // Return tokens to browser via a page that stores them
    res.send(`
      <html><body>
        <script>
          sessionStorage.setItem('zt-iam-access-token', '${tokens.access_token}');
          ${tokens.refresh_token ? `sessionStorage.setItem('zt-iam-refresh-token', '${tokens.refresh_token}');` : ''}
          window.location.href = '/';
        </script>
        <p>Authenticating...</p>
      </body></html>
    `);
  } catch (err) {
    res.status(502).send('Token exchange failed: ' + err.message);
  }
});

// Initiate OAuth login
app.get('/oauth/login', (req, res) => {
  const state = require('crypto').randomUUID();
  const nonce = require('crypto').randomUUID();
  const authUrl = `${POLICY_ENGINE_URL}/oauth/authorize?response_type=code&client_id=zt-iam-web&redirect_uri=${encodeURIComponent('http://localhost:3000/oauth/callback')}&scope=openid%20profile&state=${state}&nonce=${nonce}`;
  res.redirect(authUrl);
});

app.listen(PORT, () => {
  console.log(`Web App running on http://localhost:${PORT}`);
});
