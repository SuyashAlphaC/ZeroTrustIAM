// ZeroTrustIAM — auth helpers. Role-gating + session refresh.
import { getSession, clearSession, post } from './api.js';

export function requireAuth() {
  const s = getSession();
  if (!s?.accessToken) {
    location.href = '/?next=' + encodeURIComponent(location.pathname);
    throw new Error('redirect');
  }
  return s;
}

export function requireRole(role) {
  const s = requireAuth();
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
