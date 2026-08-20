// ZeroTrustIAM — auth helpers. Role-gating + cookie-backed session restore.
import { getSession, setSession, clearSession, post } from './api.js';

// Re-export so pages/ui can import session helpers from one place.
export { getSession, setSession, clearSession };

/**
 * Ensure the user is signed in. Login sets HttpOnly cookies (zt_access) and
 * does not put the JWT in sessionStorage, so we restore a lightweight session
 * via POST /api/verify-token when sessionStorage is empty.
 */
export async function requireAuth() {
  let s = getSession();
  // Bearer in sessionStorage (legacy / tests) or cookie-backed metadata after verify
  if (s && (s.accessToken || s.valid)) {
    return s;
  }

  try {
    const result = await post('/api/verify-token', {});
    if (result?.valid) {
      s = {
        username: result.user,
        user: { username: result.user, role: result.role },
        role: result.role,
        valid: true,
        expiresAt: result.expiresAt,
        // accessToken stays HttpOnly — proxy injects Authorization from cookie
      };
      setSession(s);
      return s;
    }
  } catch {
    /* api.js already redirects on 401 for most paths */
  }

  clearSession();
  location.href = '/?next=' + encodeURIComponent(location.pathname);
  throw new Error('redirect');
}

export async function requireRole(role) {
  const s = await requireAuth();
  if (!hasRole(s, role)) {
    location.href = '/me/security?denied=role';
    throw new Error('redirect');
  }
  return s;
}

export function hasRole(session, role) {
  if (!session) return false;
  const r = session.role || session.user?.role;
  if (Array.isArray(r)) return r.includes(role);
  return r === role || r === 'admin'; // admin includes everything
}

export async function logout() {
  try { await post('/api/logout', {}); } catch { /* ignore */ }
  clearSession();
  location.href = '/';
}

// Live time updater for status footer.
export function startStatusTicker() {
  const el = document.querySelector('[data-live-time]');
  if (!el) return;
  const tick = () => {
    const d = new Date();
    el.textContent = d.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
  };
  tick();
  setInterval(tick, 1000);
}
