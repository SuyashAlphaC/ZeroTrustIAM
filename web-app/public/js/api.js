// ZeroTrustIAM — API client. Handles CSRF, session bearer, error normalization.
const STORAGE_KEY = 'ztiam_session';
let csrfToken = null;
let csrfPromise = null;

export function getSession() {
  try { return JSON.parse(sessionStorage.getItem(STORAGE_KEY) || 'null'); }
  catch { return null; }
}
export function setSession(s) { sessionStorage.setItem(STORAGE_KEY, JSON.stringify(s)); }
export function clearSession() { sessionStorage.removeItem(STORAGE_KEY); }

async function ensureCsrf() {
  if (csrfToken) return csrfToken;
  if (!csrfPromise) {
    csrfPromise = fetch('/api/csrf-token', { credentials: 'same-origin' })
      .then((r) => r.json())
      .then((j) => { csrfToken = j.csrfToken; return csrfToken; })
      .catch(() => { csrfPromise = null; throw new Error('Failed to fetch CSRF token'); });
  }
  return csrfPromise;
}

export async function api(path, opts = {}) {
  const method = (opts.method || 'GET').toUpperCase();
  const headers = { 'Accept': 'application/json', ...(opts.headers || {}) };
  if (method !== 'GET' && method !== 'HEAD') {
    headers['X-CSRF-Token'] = await ensureCsrf();
    if (opts.body && typeof opts.body !== 'string') {
      headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
  }
  const session = getSession();
  if (session?.accessToken) headers['Authorization'] = `Bearer ${session.accessToken}`;

  const res = await fetch(path, {
    method, headers, body: opts.body, credentials: 'same-origin',
    signal: opts.signal,
  });

  let data = null;
  const ct = res.headers.get('content-type') || '';

  // Blob downloads must be read as binary first (even when Content-Type is application/json).
  if (opts.expect === 'blob') {
    if (!res.ok) {
      // Prefer JSON error body when present
      let errBody = null;
      try {
        const text = await res.text();
        try { errBody = JSON.parse(text); } catch { errBody = { message: text }; }
      } catch { /* ignore */ }
      const err = new Error(errBody?.error || errBody?.message || `HTTP ${res.status}`);
      err.status = res.status;
      err.data = errBody;
      if (res.status === 401) {
        clearSession();
        if (!path.includes('/login') && !path.includes('/refresh')) {
          location.href = '/?next=' + encodeURIComponent(location.pathname);
        }
      }
      throw err;
    }
    return res.blob();
  }

  if (ct.includes('application/json')) {
    try { data = await res.json(); } catch { data = null; }
  } else {
    data = await res.text();
  }

  if (!res.ok) {
    const err = new Error(data?.error || data?.message || `HTTP ${res.status}`);
    err.status = res.status; err.data = data;
    if (res.status === 401) {
      clearSession();
      if (!path.includes('/login') && !path.includes('/refresh')) {
        location.href = '/?next=' + encodeURIComponent(location.pathname);
      }
    }
    throw err;
  }
  return data;
}

export const get   = (p, opts) => api(p, { ...opts, method: 'GET' });
export const post  = (p, body, opts) => api(p, { ...opts, method: 'POST', body });
export const del   = (p, opts = {}) => api(p, { ...opts, method: 'DELETE' });
export const put   = (p, body, opts) => api(p, { ...opts, method: 'PUT', body });
export const patch = (p, body, opts) => api(p, { ...opts, method: 'PATCH', body });
