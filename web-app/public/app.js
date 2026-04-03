// Generate or retrieve a persistent device ID (simulates device fingerprinting)
function getDeviceId() {
  let deviceId = localStorage.getItem('zt-iam-device-id');
  if (!deviceId) {
    deviceId = 'dev-' + crypto.randomUUID();
    localStorage.setItem('zt-iam-device-id', deviceId);
  }
  return deviceId;
}

// JWT token management
function getAccessToken() {
  return sessionStorage.getItem('zt-iam-access-token');
}

function getRefreshToken() {
  return sessionStorage.getItem('zt-iam-refresh-token');
}

function storeTokens(accessToken, refreshToken) {
  sessionStorage.setItem('zt-iam-access-token', accessToken);
  if (refreshToken) {
    sessionStorage.setItem('zt-iam-refresh-token', refreshToken);
  }
}

function clearTokens() {
  sessionStorage.removeItem('zt-iam-access-token');
  sessionStorage.removeItem('zt-iam-refresh-token');
}

// Display device ID on page
const deviceId = getDeviceId();
document.getElementById('deviceIdDisplay').textContent = deviceId;

// Check for existing session on page load
checkSession();

async function checkSession() {
  const token = getAccessToken();
  if (!token) return;

  try {
    const res = await fetch('/api/verify-token', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const result = await res.json();
    if (result.valid) {
      showSession(result);
    } else {
      // Try refresh
      const refreshed = await tryRefreshToken();
      if (!refreshed) clearTokens();
    }
  } catch {
    clearTokens();
  }
}

async function tryRefreshToken() {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;

  try {
    const res = await fetch('/api/refresh-token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    });
    if (!res.ok) return false;
    const result = await res.json();
    storeTokens(result.accessToken, null);
    await checkSession();
    return true;
  } catch {
    return false;
  }
}

function showSession(sessionInfo) {
  const panel = document.getElementById('sessionPanel');
  const details = document.getElementById('sessionDetails');
  panel.classList.remove('hidden');

  let html = '';
  const addRow = (label, value) => {
    html += `<div class="detail-row">
      <span class="detail-label">${label}</span>
      <span class="detail-value">${value}</span>
    </div>`;
  };

  addRow('User', sessionInfo.user);
  addRow('Role', sessionInfo.role);
  addRow('Token Expires', new Date(sessionInfo.expiresAt).toLocaleString());
  details.innerHTML = html;
}

// Handle logout
document.getElementById('logoutBtn').addEventListener('click', async () => {
  const refreshToken = getRefreshToken();
  try {
    await fetch('/api/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    });
  } catch { /* ignore */ }
  clearTokens();
  document.getElementById('sessionPanel').classList.add('hidden');
});

// Handle login form submission
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const submitBtn = document.getElementById('submitBtn');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Evaluating...';

  const payload = {
    username: document.getElementById('username').value,
    password: document.getElementById('password').value,
    deviceId: deviceId,
    timestamp: new Date().toISOString(),
    ip: '192.168.1.100',
    location: {
      country: document.getElementById('locationCountry').value || 'IN',
      city: document.getElementById('locationCity').value || 'Gwalior',
    },
    requiredPermission: document.getElementById('resource').value,
  };

  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const result = await response.json();

    // Handle MFA step-up requirement
    if (result.decision === 'MFA_REQUIRED') {
      showMFAChallenge(result);
      return;
    }

    // Store JWT tokens if authentication succeeded
    if (result.accessToken) {
      storeTokens(result.accessToken, result.refreshToken);
      checkSession();
    }

    displayResult(result);
  } catch (err) {
    displayResult({
      decision: 'DENY',
      reason: 'Network error: ' + err.message,
    });
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Authenticate';
  }
});

function displayResult(result) {
  const resultDiv = document.getElementById('result');
  const banner = document.getElementById('resultBanner');
  const details = document.getElementById('resultDetails');

  resultDiv.classList.remove('hidden');

  const isAllowed = result.decision === 'ALLOW';
  banner.className = 'result-banner ' + (isAllowed ? 'allow' : 'deny');
  banner.textContent = isAllowed ? 'ACCESS GRANTED' : 'ACCESS DENIED';

  let detailsHTML = '';

  const addRow = (label, value) => {
    detailsHTML += `<div class="detail-row">
      <span class="detail-label">${label}</span>
      <span class="detail-value">${value}</span>
    </div>`;
  };

  addRow('Decision', result.decision);
  addRow('Reason', result.reason);

  if (result.riskScore !== undefined) {
    addRow('Risk Score', result.riskScore.toFixed(2));
  }

  if (result.breakdown) {
    addRow('Device Score', result.breakdown.d_score);
    addRow('Location Score', result.breakdown.l_score);
    addRow('Time Score', result.breakdown.t_score);
    addRow('Attempt Score', result.breakdown.a_score);
  }

  if (result.txId) {
    addRow('Transaction ID', result.txId);
  }

  if (result.layer) {
    addRow('Decided By', result.layer);
  }

  if (result.accessToken) {
    addRow('JWT Token', 'Issued (stored in session)');
    addRow('Token Expiry', result.tokenExpiry);
  }

  if (result.mfaVerified) {
    addRow('MFA', 'Verified');
  }

  details.innerHTML = detailsHTML;
}

// MFA challenge handling
let pendingChallengeId = null;

function showMFAChallenge(result) {
  pendingChallengeId = result.challengeId;
  const mfaPanel = document.getElementById('mfaPanel');
  const mfaReason = document.getElementById('mfaReason');
  mfaPanel.classList.remove('hidden');
  mfaReason.textContent = result.reason;
  document.getElementById('mfaCode').focus();
}

document.getElementById('mfaSubmitBtn').addEventListener('click', async () => {
  if (!pendingChallengeId) return;

  const code = document.getElementById('mfaCode').value.trim();
  if (code.length !== 6) {
    alert('Please enter a 6-digit TOTP code');
    return;
  }

  const btn = document.getElementById('mfaSubmitBtn');
  btn.disabled = true;
  btn.textContent = 'Verifying...';

  try {
    const response = await fetch('/api/mfa/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: pendingChallengeId, code }),
    });
    const result = await response.json();

    if (result.accessToken) {
      storeTokens(result.accessToken, result.refreshToken);
      checkSession();
    }

    displayResult(result);
    document.getElementById('mfaPanel').classList.add('hidden');
    document.getElementById('mfaCode').value = '';
    pendingChallengeId = null;
  } catch (err) {
    displayResult({ decision: 'DENY', reason: 'MFA verification error: ' + err.message });
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify MFA';
  }
});
