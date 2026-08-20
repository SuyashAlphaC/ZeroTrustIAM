// ZeroTrustIAM login client — opaque device binding + safe decision display.
// Device credentials are never shown as editable form fields.
// Risk scores must never be rendered (server also redacts them).

const DEVICE_STORAGE_KEY = 'zt-iam-device-credential';

/**
 * Stable opaque device credential for this browser profile.
 * crypto.randomUUID when available; never a demo hardcode, never user-editable.
 */
function getDeviceCredential() {
  try {
    let id = localStorage.getItem(DEVICE_STORAGE_KEY);
    // Migrate away from legacy hardcoded demo key if present as sole value
    if (id === 'dev-001' || id === 'dev-002') {
      id = null;
      localStorage.removeItem(DEVICE_STORAGE_KEY);
      localStorage.removeItem('zt-iam-device-id');
    }
    // Legacy key migration (opaque values only)
    if (!id) {
      const legacy = localStorage.getItem('zt-iam-device-id');
      if (legacy && legacy !== 'dev-001' && legacy !== 'dev-002' && legacy.length >= 6) {
        id = legacy;
        localStorage.setItem(DEVICE_STORAGE_KEY, id);
        localStorage.removeItem('zt-iam-device-id');
      }
    }
    if (!id) {
      id = (typeof crypto !== 'undefined' && crypto.randomUUID)
        ? crypto.randomUUID()
        : ('d_' + Math.random().toString(36).slice(2) + Date.now().toString(36));
      localStorage.setItem(DEVICE_STORAGE_KEY, id);
    }
    return id;
  } catch {
    // Private mode fallback (session-only)
    if (!window.__ztDeviceCred) {
      window.__ztDeviceCred = (typeof crypto !== 'undefined' && crypto.randomUUID)
        ? crypto.randomUUID()
        : ('d_' + Math.random().toString(36).slice(2));
    }
    return window.__ztDeviceCred;
  }
}

let csrfTokenMemo = null;

async function getCsrfToken() {
  if (csrfTokenMemo) return csrfTokenMemo;
  const r = await fetch('/api/csrf-token', { credentials: 'same-origin' });
  if (!r.ok) throw new Error('CSRF bootstrap failed');
  const d = await r.json();
  csrfTokenMemo = d.csrfToken;
  return csrfTokenMemo;
}

async function apiPostEmpty(url) {
  const csrf = await getCsrfToken();
  return fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'X-CSRF-Token': csrf },
  });
}

async function apiPostJson(url, obj) {
  const csrf = await getCsrfToken();
  return fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: JSON.stringify(obj),
  });
}

// Check for existing session on page load (tokens are now in HttpOnly cookies)
checkSession();

async function checkSession() {
  try {
    const res = await apiPostEmpty('/api/verify-token');
    const result = await res.json();
    if (result.valid) {
      showSession(result);
    } else {
      const refreshed = await tryRefreshToken();
      if (!refreshed) hideSession();
    }
  } catch {
    hideSession();
  }
}

async function tryRefreshToken() {
  try {
    const res = await apiPostJson('/api/refresh-token', {});
    if (!res.ok) return false;
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
      <span class="detail-value">${escapeHtml(value)}</span>
    </div>`;
  };

  addRow('User', sessionInfo.user);
  addRow('Role', sessionInfo.role);
  addRow('Token Expires', new Date(sessionInfo.expiresAt).toLocaleString());
  addRow('Session', 'Secured (HttpOnly cookie)');
  details.innerHTML = html;
}

function hideSession() {
  document.getElementById('sessionPanel').classList.add('hidden');
}

function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

document.getElementById('logoutBtn').addEventListener('click', async () => {
  try {
    await apiPostJson('/api/logout', {});
  } catch { /* ignore */ }
  hideSession();
});

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const submitBtn = document.getElementById('submitBtn');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Evaluating...';

  const payload = {
    username: document.getElementById('username').value,
    password: document.getElementById('password').value,
    deviceId: getDeviceCredential(),
    timestamp: new Date().toISOString(),
    location: {
      country: document.getElementById('locationCountry').value || 'IN',
      city: document.getElementById('locationCity').value || 'Gwalior',
    },
    requiredPermission: document.getElementById('resource').value,
  };

  try {
    const response = await apiPostJson('/api/login', payload);
    const result = await response.json();

    if (result.decision === 'MFA_REQUIRED') {
      showMFAChallenge(result);
      return;
    }

    if (result.tokenSet) {
      checkSession();
    }

    displayResult(result);
  } catch (err) {
    displayResult({ decision: 'DENY', userMessage: 'Network error. Try again.', reason: 'Network error' });
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Authenticate';
  }
});

/**
 * Show decision only — never risk scores, breakdowns, or thresholds.
 */
function displayResult(result) {
  const resultDiv = document.getElementById('result');
  const banner = document.getElementById('resultBanner');
  const details = document.getElementById('resultDetails');

  resultDiv.classList.remove('hidden');

  const decision = result.decision || 'DENY';
  const isAllowed = decision === 'ALLOW';
  const isMfa = decision === 'MFA_REQUIRED';
  banner.className = 'result-banner ' + (isAllowed ? 'allow' : isMfa ? 'deny' : 'deny');
  banner.textContent = isAllowed
    ? 'ACCESS GRANTED'
    : isMfa
      ? 'VERIFICATION REQUIRED'
      : 'ACCESS DENIED';

  let detailsHTML = '';
  const addRow = (label, value) => {
    if (value == null || value === '') return;
    detailsHTML += `<div class="detail-row">
      <span class="detail-label">${escapeHtml(label)}</span>
      <span class="detail-value">${escapeHtml(value)}</span>
    </div>`;
  };

  addRow('Status', decision);
  addRow('Message', result.userMessage || result.reason || '—');
  if (result.reasonCode) addRow('Code', result.reasonCode);
  if (result.txId) addRow('Audit reference', result.txId);
  if (result.tokenSet || result.accessToken) addRow('Session', 'Established (HttpOnly cookie)');
  if (result.mfaVerified) addRow('MFA', 'Verified');
  if (result.deviceEnrolled) addRow('Device', 'Registered for this browser');

  // Defense-in-depth: never render risk fields even if a misconfigured server leaks them
  details.innerHTML = detailsHTML;
}

let pendingChallengeId = null;

function showMFAChallenge(result) {
  pendingChallengeId = result.challengeId;
  const mfaPanel = document.getElementById('mfaPanel');
  const mfaReason = document.getElementById('mfaReason');
  mfaPanel.classList.remove('hidden');
  mfaReason.textContent = result.userMessage || result.reason || 'Additional verification required.';
  document.getElementById('mfaCode').focus();
  displayResult(result);
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
    const response = await apiPostJson('/api/mfa/challenge', { challengeId: pendingChallengeId, code });
    const result = await response.json();

    if (result.tokenSet || result.accessToken) {
      checkSession();
    }

    displayResult(result);
    document.getElementById('mfaPanel').classList.add('hidden');
    document.getElementById('mfaCode').value = '';
    pendingChallengeId = null;
  } catch (err) {
    displayResult({ decision: 'DENY', userMessage: 'Verification failed. Try again.', reason: 'MFA verification failed' });
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify MFA';
  }
});
