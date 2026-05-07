// ZeroTrustIAM — UI primitives. Layout, modals, toasts, sparklines.
import { hasRole, getSession, logout, startStatusTicker } from './auth.js';

const ICONS = {
  policies: '<path d="M3 6h10M3 10h10M3 2h10" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>',
  audit:    '<path d="M2 3h12v10H2zM5 6h6M5 9h4" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round"/>',
  models:   '<circle cx="8" cy="8" r="3" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M8 1v3M8 12v3M1 8h3M12 8h3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>',
  users:    '<circle cx="8" cy="6" r="3" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M2 14c0-3 3-5 6-5s6 2 6 5" stroke="currentColor" stroke-width="1.4" fill="none"/>',
  devices:  '<rect x="2" y="3" width="12" height="9" rx="1" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M5 14h6" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>',
  security: '<path d="M8 1L2 4v4c0 4 6 7 6 7s6-3 6-7V4z" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M5 8l2 2 4-4" stroke="currentColor" stroke-width="1.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
  sessions: '<rect x="2" y="2" width="12" height="12" rx="1" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M2 6h12M5 9h6" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>',
  data:     '<ellipse cx="8" cy="3.5" rx="5" ry="1.5" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M3 3.5v9c0 .8 2.2 1.5 5 1.5s5-.7 5-1.5v-9M3 8c0 .8 2.2 1.5 5 1.5s5-.7 5-1.5" stroke="currentColor" stroke-width="1.4" fill="none"/>',
  copy:     '<rect x="3" y="3" width="7" height="9" rx="1" stroke="currentColor" stroke-width="1.4" fill="none"/><path d="M6 3V1h7v9h-2" stroke="currentColor" stroke-width="1.4" fill="none"/>',
  check:    '<path d="M3 8l3 3 7-7" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
};
const icon = (k) => `<svg class="nav-icon" viewBox="0 0 16 16">${ICONS[k] || ''}</svg>`;

const ADMIN_NAV = [
  { href: '/admin/policies', label: 'Policies', icon: 'policies' },
  { href: '/admin/audit',    label: 'Audit Log', icon: 'audit' },
  { href: '/admin/models',   label: 'ML Models', icon: 'models' },
  { href: '/admin/users',    label: 'Users',     icon: 'users' },
];
const USER_NAV = [
  { href: '/me/security', label: 'Security',  icon: 'security' },
  { href: '/me/devices',  label: 'Devices',   icon: 'devices' },
  { href: '/me/sessions', label: 'Sessions',  icon: 'sessions' },
  { href: '/me/data',     label: 'My Data',   icon: 'data' },
];

export function renderShell({ section = 'me', currentPath = '' } = {}) {
  const session = getSession();
  const username = session?.username || session?.user?.username || 'unknown';
  const isAdmin = hasRole(session, 'admin');
  const initials = username.slice(0, 2).toUpperCase();

  const adminLinks = isAdmin
    ? ADMIN_NAV.map((n) => navLink(n, currentPath)).join('')
    : '';
  const userLinks = USER_NAV.map((n) => navLink(n, currentPath)).join('');

  const adminSection = isAdmin ? `
    <div class="nav-section">Governance</div>
    ${adminLinks}` : '';

  const html = `
    <aside class="shell-sidebar">
      <div class="brand">
        <div class="brand-mark">ZeroTrust</div>
        <div class="brand-tag">Identity · Access · Audit</div>
      </div>
      <nav class="nav">
        ${adminSection}
        <div class="nav-section">Account</div>
        ${userLinks}
      </nav>
      <div class="sidebar-foot">
        <button class="user-chip" id="user-chip" type="button" aria-label="Sign out">
          <span class="user-avatar">${initials}</span>
          <span class="flex flex-col gap-1" style="line-height:1.2">
            <span style="color:var(--fg-0);font-size:12px">${escape(username)}</span>
            <span style="color:var(--fg-3);font-size:10px;text-transform:uppercase;letter-spacing:0.08em">${escape(session?.role || 'user')}</span>
          </span>
        </button>
      </div>
    </aside>
    <main class="shell-main" id="main"></main>
    <footer class="shell-footer">
      <div class="status-cluster">
        <span class="status-dot"></span>
        <span class="text">policy-engine · operational</span>
      </div>
      <div class="flex gap-4 items-center">
        <span data-live-time>—</span>
        <span style="color:var(--fg-3)">v1.0.0</span>
      </div>
    </footer>
    <div id="toast-stack" class="toast-stack" aria-live="polite"></div>
  `;
  document.body.classList.add('shell-body');
  const root = document.createElement('div');
  root.className = 'shell';
  root.innerHTML = html;
  document.body.appendChild(root);

  document.getElementById('user-chip').addEventListener('click', logout);
  startStatusTicker();
  return document.getElementById('main');
}

function navLink(n, currentPath) {
  const active = currentPath.startsWith(n.href) ? ' active' : '';
  return `<a class="nav-link${active}" href="${n.href}">${icon(n.icon)}<span>${n.label}</span></a>`;
}

// ─── Toasts ────────────────────────────────────────────────────────────
export function toast(message, type = 'info', timeout = 3500) {
  const stack = document.getElementById('toast-stack');
  if (!stack) { console.log('[toast]', type, message); return; }
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span style="flex:1">${escape(message)}</span>`;
  stack.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0'; t.style.transform = 'translateY(8px)';
    t.style.transition = 'opacity 0.2s, transform 0.2s';
    setTimeout(() => t.remove(), 220);
  }, timeout);
}

// ─── Modals ────────────────────────────────────────────────────────────
export function confirm({ title, body, danger = false, confirmLabel = 'Confirm', cancelLabel = 'Cancel' }) {
  return new Promise((resolve) => {
    const back = document.createElement('div');
    back.className = 'modal-backdrop';
    back.innerHTML = `
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
        <div class="modal-head"><h2 class="t-h2" id="modal-title">${escape(title)}</h2></div>
        <div class="modal-body">${body}</div>
        <div class="modal-foot">
          <button class="btn btn-ghost" data-act="cancel">${escape(cancelLabel)}</button>
          <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-act="confirm">${escape(confirmLabel)}</button>
        </div>
      </div>`;
    document.body.appendChild(back);
    const close = (v) => { back.remove(); resolve(v); };
    back.querySelector('[data-act=confirm]').addEventListener('click', () => close(true));
    back.querySelector('[data-act=cancel]').addEventListener('click', () => close(false));
    back.addEventListener('click', (e) => { if (e.target === back) close(false); });
    setTimeout(() => back.querySelector('[data-act=cancel]').focus(), 50);
  });
}

// ─── Sparkline ─────────────────────────────────────────────────────────
export function sparkline(values, { width = 64, height = 22, threshold = null } = {}) {
  if (!values?.length) return '<span class="t-mono text-fg-2">—</span>';
  const min = Math.min(...values, 0);
  const max = Math.max(...values, 1);
  const range = max - min || 1;
  const step = width / (values.length - 1 || 1);
  const pts = values.map((v, i) => [i * step, height - ((v - min) / range) * (height - 2) - 1]);
  const line = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  const fill = `${line} L${width} ${height} L0 ${height} Z`;
  const last = values[values.length - 1];
  const lx = pts[pts.length - 1][0]; const ly = pts[pts.length - 1][1];
  const color = threshold != null && last >= threshold ? 'var(--deny)' : 'var(--accent)';
  return `<svg class="spark" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" aria-hidden="true">
    <path class="fill" d="${fill}" style="fill:${color};opacity:0.12"/>
    <path class="line" d="${line}" style="stroke:${color}"/>
    <circle cx="${lx.toFixed(1)}" cy="${ly.toFixed(1)}" r="2" fill="${color}"/>
  </svg>`;
}

// ─── Risk gauge ────────────────────────────────────────────────────────
export function riskGauge(score) {
  const v = Math.max(0, Math.min(1, Number(score) || 0));
  const pct = (v * 100).toFixed(0);
  const cls = v >= 0.6 ? 'high' : v >= 0.3 ? 'med' : '';
  return `<span class="gauge ${cls}">
    <span class="gauge-bar"><span class="gauge-fill" style="right:${(100 - v * 100).toFixed(1)}%"></span></span>
    <span class="gauge-num">${v.toFixed(2)}</span>
  </span>`;
}

// ─── Decision pill ─────────────────────────────────────────────────────
export function decisionPill(d) {
  const cls = ({ ALLOW: 'allow', STEP_UP: 'stepup', DENY: 'deny' })[d] || 'muted';
  return `<span class="pill ${cls}">${escape(d || 'unknown')}</span>`;
}

// ─── Hash w/ copy ──────────────────────────────────────────────────────
export function hashCopy(value, { length = 12 } = {}) {
  if (!value) return '<span class="t-mono text-fg-2">—</span>';
  const short = value.length > length ? value.slice(0, length) + '…' : value;
  return `<span class="hash" data-copy="${escape(value)}" role="button" tabindex="0">
    <span>${escape(short)}</span>
    <svg class="hash-icon" viewBox="0 0 16 16">${ICONS.copy}</svg>
  </span>`;
}

// Delegate copy clicks at document level (works for dynamically-added .hash elements)
document.addEventListener('click', async (e) => {
  const h = e.target.closest('.hash[data-copy]');
  if (!h) return;
  try {
    await navigator.clipboard.writeText(h.dataset.copy);
    h.classList.add('copied');
    setTimeout(() => h.classList.remove('copied'), 900);
  } catch { /* clipboard blocked */ }
});

// ─── Helpers ───────────────────────────────────────────────────────────
export function escape(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

export function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  return d.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
}
export function fmtRelative(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  const s = (Date.now() - d.getTime()) / 1000;
  if (s < 60) return Math.floor(s) + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

export function pageHead({ crumb, title, description, actions = '' }) {
  return `
    <div class="page-head">
      <div class="page-head-title">
        ${crumb ? `<div class="crumb">${escape(crumb)}</div>` : ''}
        <h1 class="t-h1">${title}</h1>
        ${description ? `<p class="t-body">${description}</p>` : ''}
      </div>
      <div class="page-head-actions">${actions}</div>
    </div>`;
}
