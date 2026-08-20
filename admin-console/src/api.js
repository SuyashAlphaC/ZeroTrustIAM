const API = import.meta.env.VITE_API_BASE || '';

function token() {
  try {
    return JSON.parse(sessionStorage.getItem('ztiam_admin') || '{}').accessToken;
  } catch {
    return null;
  }
}

export async function api(path, opts = {}) {
  const headers = {
    Accept: 'application/json',
    ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
    ...(opts.headers || {}),
  };
  const t = token();
  if (t) headers.Authorization = `Bearer ${t}`;
  const res = await fetch(`${API}${path}`, {
    ...opts,
    headers,
    body: opts.body && typeof opts.body !== 'string' ? JSON.stringify(opts.body) : opts.body,
  });
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json().catch(() => ({})) : await res.text();
  if (!res.ok) {
    const err = new Error(data?.error || data?.message || `HTTP ${res.status}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

export const get = (p) => api(p);
export const post = (p, body) => api(p, { method: 'POST', body });
export const patch = (p, body) => api(p, { method: 'PATCH', body });
export const del = (p) => api(p, { method: 'DELETE' });

export async function login(username, password) {
  const data = await post('/v1/evaluate', {
    username,
    password,
    deviceId: `admin-console-${navigator.userAgent.slice(0, 24)}`,
    location: { country: 'XX', city: 'Admin' },
    requiredPermission: 'read',
  });
  if (data.decision !== 'ALLOW' || !data.accessToken) {
    throw new Error(data.reason || 'Login denied');
  }
  sessionStorage.setItem(
    'ztiam_admin',
    JSON.stringify({
      accessToken: data.accessToken,
      refreshToken: data.refreshToken,
      username,
    })
  );
  return data;
}

export function logout() {
  sessionStorage.removeItem('ztiam_admin');
}

export function session() {
  try {
    return JSON.parse(sessionStorage.getItem('ztiam_admin') || 'null');
  } catch {
    return null;
  }
}
