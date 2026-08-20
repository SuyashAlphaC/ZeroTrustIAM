import React, { useEffect, useState } from 'react';
import { Routes, Route, NavLink, Navigate, useNavigate } from 'react-router-dom';
import { login, logout, session, get, post, patch } from './api';

function Shell({ children, user }) {
  const nav = useNavigate();
  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <span className="logo">ZT</span>
          <div>
            <div className="brand-title">ZeroTrustIAM</div>
            <div className="brand-sub">Admin Console</div>
          </div>
        </div>
        <nav>
          <NavLink to="/" end>Dashboard</NavLink>
          <NavLink to="/users">Users</NavLink>
          <NavLink to="/tenants">Tenants</NavLink>
          <NavLink to="/billing">Billing</NavLink>
          <NavLink to="/policies">ABAC / PDP</NavLink>
          <NavLink to="/audit">Audit</NavLink>
          <NavLink to="/federation">Federation</NavLink>
          <NavLink to="/models">Risk models</NavLink>
        </nav>
        <div className="sidebar-foot">
          <div className="muted mono">{user}</div>
          <button className="btn ghost" type="button" onClick={() => { logout(); nav('/login'); }}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}

function Login() {
  const nav = useNavigate();
  const [username, setU] = useState('alice');
  const [password, setP] = useState('pass123');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    setBusy(true);
    setErr('');
    try {
      await login(username, password);
      nav('/');
    } catch (ex) {
      setErr(ex.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <form className="card login-card" onSubmit={onSubmit}>
        <h1>Admin sign-in</h1>
        <p className="muted">Authenticate against the policy engine. Admin role required for management APIs.</p>
        {err && <div className="alert">{err}</div>}
        <label>
          Username
          <input value={username} onChange={(e) => setU(e.target.value)} autoComplete="username" />
        </label>
        <label>
          Password
          <input type="password" value={password} onChange={(e) => setP(e.target.value)} autoComplete="current-password" />
        </label>
        <button className="btn primary" disabled={busy} type="submit">
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        <div className="fed-links">
          <a href="/v1/federation/google/start">Google</a>
          <a href="/v1/federation/entra/start">Entra ID</a>
          <a href="/v1/federation/okta/start">Okta</a>
          <a href="/v1/federation/saml/start">SAML</a>
        </div>
      </form>
    </div>
  );
}

function Dashboard() {
  const [health, setHealth] = useState(null);
  const [pdp, setPdp] = useState(null);
  useEffect(() => {
    get('/v1/health').then(setHealth).catch(() => setHealth({ status: 'unreachable' }));
    get('/v1/admin/pdp/status').then(setPdp).catch(() => setPdp(null));
  }, []);
  return (
    <div>
      <header className="page-head">
        <h1>Control plane</h1>
        <p className="muted">Live status of identity, PDP, and ledger-adjacent services.</p>
      </header>
      <div className="grid-3">
        <div className="card">
          <h3>Policy engine</h3>
          <div className={`pill ${health?.status === 'healthy' ? 'ok' : 'warn'}`}>
            {health?.status || '…'}
          </div>
          <dl className="kv">
            <div><dt>Version</dt><dd>{health?.version || '—'}</dd></div>
            <div><dt>Database</dt><dd>{health?.database || '—'}</dd></div>
            <div><dt>Blockchain</dt><dd>{health?.blockchain || '—'}</dd></div>
          </dl>
        </div>
        <div className="card">
          <h3>External PDP</h3>
          <div className="pill ok">{pdp?.backend || 'local'}</div>
          <dl className="kv">
            <div><dt>OPA</dt><dd>{pdp?.opa?.configured ? 'configured' : 'off'}</dd></div>
            <div><dt>Cedar</dt><dd>{pdp?.cedar?.configured ? 'configured' : 'off'}</dd></div>
            <div><dt>Fail mode</dt><dd className="mono">{pdp?.failureMode || '—'}</dd></div>
          </dl>
        </div>
        <div className="card">
          <h3>Quick links</h3>
          <ul className="list">
            <li><a href="/admin-console/tenants">Tenant isolation & CMK</a></li>
            <li><a href="/admin-console/federation">OIDC / SAML providers</a></li>
            <li><a href="/docs/SLO_AND_FAILURE_MODES.md">SLO & failure modes</a></li>
          </ul>
        </div>
      </div>
    </div>
  );
}

function Users() {
  const [users, setUsers] = useState([]);
  const [err, setErr] = useState('');
  useEffect(() => {
    get('/v1/admin/users')
      .then((d) => setUsers(Array.isArray(d) ? d : d.users || []))
      .catch((e) => setErr(e.message));
  }, []);
  return (
    <div>
      <header className="page-head"><h1>Users</h1></header>
      {err && <div className="alert">{err}</div>}
      <div className="card table-wrap">
        <table>
          <thead>
            <tr><th>User</th><th>Role</th><th>Status</th><th>Tenant</th><th>Created</th></tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.user_id || u.userId}>
                <td className="mono">{u.user_id || u.userId}</td>
                <td>{u.role}</td>
                <td><span className={`pill ${u.status === 'ACTIVE' ? 'ok' : 'warn'}`}>{u.status}</span></td>
                <td className="mono">{u.tenant_id || u.tenantId || 'default'}</td>
                <td className="muted">{u.created_at || u.createdAt || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Tenants() {
  const [tenants, setTenants] = useState([]);
  const [name, setName] = useState('');
  const [plan, setPlan] = useState('team');
  const [msg, setMsg] = useState('');
  async function load() {
    const d = await get('/v1/admin/tenants');
    setTenants(d.tenants || []);
  }
  useEffect(() => { load().catch((e) => setMsg(e.message)); }, []);
  async function create(e) {
    e.preventDefault();
    try {
      await post('/v1/admin/tenants', { name, plan });
      setName('');
      setMsg('Tenant created');
      await load();
    } catch (ex) {
      setMsg(ex.message);
    }
  }
  return (
    <div>
      <header className="page-head">
        <h1>Tenants</h1>
        <p className="muted">Org isolation, plan limits, and customer-managed keys (CMK).</p>
      </header>
      {msg && <div className="alert info">{msg}</div>}
      <form className="card form-row" onSubmit={create}>
        <input placeholder="Organization name" value={name} onChange={(e) => setName(e.target.value)} required />
        <select value={plan} onChange={(e) => setPlan(e.target.value)}>
          <option value="free">free</option>
          <option value="team">team</option>
          <option value="business">business</option>
          <option value="enterprise">enterprise</option>
        </select>
        <button className="btn primary" type="submit">Create tenant</button>
      </form>
      <div className="card table-wrap">
        <table>
          <thead>
            <tr><th>ID</th><th>Name</th><th>Slug</th><th>Plan</th><th>CMK</th><th>Status</th></tr>
          </thead>
          <tbody>
            {tenants.map((t) => (
              <tr key={t.tenant_id}>
                <td className="mono">{t.tenant_id}</td>
                <td>{t.name}</td>
                <td className="mono">{t.slug}</td>
                <td>{t.plan}</td>
                <td className="mono muted">{t.cmk_arn || t.cmk_key_id || '—'}</td>
                <td>{t.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Policies() {
  const [pdp, setPdp] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [evalResult, setEval] = useState(null);
  useEffect(() => {
    get('/v1/admin/pdp/status').then(setPdp).catch(() => {});
    get('/v1/admin/abac/policies').then((d) => setPolicies(d.policies || [])).catch(() => {});
  }, []);
  async function runEval(e) {
    e.preventDefault();
    const fd = new FormData(e.target);
    const body = {
      userId: fd.get('userId'),
      role: fd.get('role'),
      action: fd.get('action'),
      riskScore: parseFloat(fd.get('riskScore') || '0'),
      status: 'ACTIVE',
    };
    const r = await post('/v1/admin/abac/evaluate', body);
    setEval(r);
  }
  return (
    <div>
      <header className="page-head">
        <h1>ABAC & external PDP</h1>
        <p className="muted">OPA / Cedar when configured; local ABAC always as defense-in-depth.</p>
      </header>
      <div className="grid-2">
        <div className="card">
          <h3>PDP status</h3>
          <pre className="code">{JSON.stringify(pdp, null, 2)}</pre>
        </div>
        <div className="card">
          <h3>Evaluate</h3>
          <form onSubmit={runEval} className="stack">
            <input name="userId" defaultValue="alice" placeholder="userId" />
            <input name="role" defaultValue="viewer" placeholder="role" />
            <select name="action" defaultValue="read">
              <option>read</option><option>write</option><option>delete</option><option>manage</option>
            </select>
            <input name="riskScore" defaultValue="0.2" />
            <button className="btn primary" type="submit">Evaluate</button>
          </form>
          {evalResult && <pre className="code">{JSON.stringify(evalResult, null, 2)}</pre>}
        </div>
      </div>
      <div className="card">
        <h3>Stored ABAC policies ({policies.length})</h3>
        <pre className="code">{JSON.stringify(policies, null, 2)}</pre>
      </div>
    </div>
  );
}

function Audit() {
  const [rows, setRows] = useState([]);
  useEffect(() => {
    get('/v1/admin/audit?limit=50')
      .then((d) => setRows(Array.isArray(d) ? d : d.entries || []))
      .catch(() => setRows([]));
  }, []);
  return (
    <div>
      <header className="page-head"><h1>Audit log</h1></header>
      <div className="card table-wrap">
        <table>
          <thead>
            <tr><th>Time</th><th>User</th><th>Decision</th><th>Reason</th><th>Layer</th></tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={r.id || i}>
                <td className="muted">{r.created_at || r.createdAt}</td>
                <td className="mono">{r.user_id || r.userId}</td>
                <td><span className={`pill ${r.decision === 'ALLOW' ? 'ok' : 'warn'}`}>{r.decision}</span></td>
                <td>{r.reason}</td>
                <td className="muted">{r.layer}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Federation() {
  const [prov, setProv] = useState(null);
  useEffect(() => {
    get('/v1/federation/providers').then(setProv).catch(() => setProv(null));
  }, []);
  return (
    <div>
      <header className="page-head">
        <h1>Federation</h1>
        <p className="muted">Google, Entra ID, Okta (OIDC) and enterprise SAML.</p>
      </header>
      <div className="card">
        <pre className="code">{JSON.stringify(prov, null, 2)}</pre>
        <div className="fed-links" style={{ marginTop: 16 }}>
          <a className="btn" href="/v1/federation/google/start">Start Google</a>
          <a className="btn" href="/v1/federation/entra/start">Start Entra</a>
          <a className="btn" href="/v1/federation/okta/start">Start Okta</a>
          <a className="btn" href="/v1/federation/saml/start">Start SAML</a>
          <a className="btn ghost" href="/v1/federation/saml/metadata">SAML metadata</a>
        </div>
      </div>
    </div>
  );
}

function Models() {
  return (
    <div>
      <header className="page-head">
        <h1>Risk models</h1>
        <p className="muted">Register model hashes on Fabric via <code>POST /v1/admin/risk-models</code>.</p>
      </header>
      <div className="card">
        <p>Use the API or CI pipeline to register <code>modelVersion</code> + <code>modelHash</code> after offline evaluation. Promotion is gated by admin role.</p>
      </div>
    </div>
  );
}

function formatMoney(cents, currency = 'usd') {
  if (cents == null) return '—';
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency.toUpperCase(),
  }).format(cents / 100);
}

function Billing() {
  const [tenantId, setTenantId] = useState('default');
  const [tenants, setTenants] = useState([]);
  const [catalog, setCatalog] = useState(null);
  const [summary, setSummary] = useState(null);
  const [invoices, setInvoices] = useState([]);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(null);

  async function load(tid = tenantId) {
    setErr('');
    try {
      const [cat, sum, inv, t] = await Promise.all([
        get('/v1/billing/catalog'),
        get(`/v1/admin/billing/${tid}`),
        get(`/v1/admin/billing/${tid}/invoices`).catch(() => ({ invoices: [] })),
        get('/v1/admin/tenants').catch(() => ({ tenants: [] })),
      ]);
      setCatalog(cat);
      setSummary(sum);
      setInvoices(inv.invoices || []);
      setTenants(t.tenants || []);
    } catch (e) {
      setErr(e.message);
    }
  }

  useEffect(() => { load(); }, []);

  async function checkout(plan) {
    setBusy(plan);
    setMsg('');
    setErr('');
    try {
      const r = await post(`/v1/admin/billing/${tenantId}/checkout`, { plan });
      if (r.url) {
        window.location.href = r.url;
        return;
      }
      setMsg(r.mode === 'free' ? 'Switched to Free plan' : 'Checkout created');
      await load();
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(null);
    }
  }

  async function openPortal() {
    setBusy('portal');
    setErr('');
    try {
      const r = await post(`/v1/admin/billing/${tenantId}/portal`, {});
      if (r.url) window.location.href = r.url;
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(null);
    }
  }

  const usage = summary?.usage;

  return (
    <div>
      <header className="page-head">
        <h1>Billing</h1>
        <p className="muted">Stripe subscriptions, invoices, usage meters, and plan upgrades.</p>
      </header>

      {(msg || err) && (
        <div className={`alert ${err ? '' : 'info'}`} style={{ marginBottom: 16 }}>
          {err || msg}
        </div>
      )}

      <div className="card form-row" style={{ marginBottom: 16 }}>
        <label className="muted" style={{ flex: 1 }}>
          Tenant
          <select
            value={tenantId}
            onChange={(e) => {
              setTenantId(e.target.value);
              load(e.target.value);
            }}
            style={{ width: '100%', marginTop: 6 }}
          >
            <option value="default">default</option>
            {tenants.filter((t) => t.tenant_id !== 'default').map((t) => (
              <option key={t.tenant_id} value={t.tenant_id}>{t.name} ({t.slug})</option>
            ))}
          </select>
        </label>
        <button className="btn" type="button" onClick={() => load()}>Refresh</button>
        <button className="btn primary" type="button" disabled={busy === 'portal'} onClick={openPortal}>
          {busy === 'portal' ? 'Opening…' : 'Customer portal'}
        </button>
      </div>

      <div className="grid-3" style={{ marginBottom: 16 }}>
        <div className="card">
          <h3>Current plan</h3>
          <div className="pill ok" style={{ textTransform: 'capitalize', marginTop: 8 }}>
            {summary?.plan || '—'}
          </div>
          <dl className="kv">
            <div><dt>Status</dt><dd>{summary?.status || '—'}</dd></div>
            <div><dt>Period end</dt><dd className="mono">{summary?.currentPeriodEnd || summary?.subscription?.currentPeriodEnd || '—'}</dd></div>
            <div><dt>Stripe</dt><dd>{summary?.stripeConfigured ? 'connected' : 'not configured'}</dd></div>
          </dl>
        </div>
        <div className="card">
          <h3>Seat usage</h3>
          <div style={{ marginTop: 12 }}>
            <div className="muted" style={{ marginBottom: 6 }}>
              {usage?.users ?? 0} / {usage?.usersLimit ?? '—'} users
            </div>
            <div style={{ height: 8, background: 'var(--bg)', borderRadius: 99, overflow: 'hidden' }}>
              <div style={{
                width: `${usage?.usersPct || 0}%`,
                height: '100%',
                background: 'linear-gradient(90deg, var(--accent), var(--accent-2))',
              }}
              />
            </div>
          </div>
          <dl className="kv">
            <div><dt>SCIM</dt><dd>{summary?.features?.scim ? 'included' : '—'}</dd></div>
            <div><dt>SAML</dt><dd>{summary?.features?.saml ? 'included' : '—'}</dd></div>
            <div><dt>CMK</dt><dd>{summary?.features?.cmk ? 'included' : '—'}</dd></div>
          </dl>
        </div>
        <div className="card">
          <h3>Subscription</h3>
          <dl className="kv">
            <div><dt>Customer</dt><dd className="mono" style={{ maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis' }}>{summary?.stripeCustomerId || '—'}</dd></div>
            <div><dt>Sub ID</dt><dd className="mono" style={{ maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis' }}>{summary?.stripeSubscriptionId || '—'}</dd></div>
            <div><dt>Cancel at period end</dt><dd>{summary?.cancelAtPeriodEnd || summary?.subscription?.cancelAtPeriodEnd ? 'yes' : 'no'}</dd></div>
          </dl>
        </div>
      </div>

      <h2 style={{ fontSize: 18, margin: '24px 0 12px' }}>Plans</h2>
      <div className="grid-3" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        {(catalog?.plans || []).map((p) => (
          <div
            key={p.id}
            className="card"
            style={{
              borderColor: p.highlighted ? 'var(--accent)' : undefined,
              position: 'relative',
            }}
          >
            {p.highlighted && (
              <div className="pill ok" style={{ position: 'absolute', top: 12, right: 12 }}>Popular</div>
            )}
            <h3 style={{ marginTop: 0 }}>{p.name}</h3>
            <div style={{ fontSize: 28, fontWeight: 700, margin: '8px 0' }}>
              {p.priceMonthly == null ? 'Custom' : p.priceMonthly === 0 ? '$0' : `$${p.priceMonthly}`}
              {p.priceMonthly != null && <span className="muted" style={{ fontSize: 14, fontWeight: 400 }}>/mo</span>}
            </div>
            <p className="muted" style={{ minHeight: 40 }}>{p.description}</p>
            <ul className="list" style={{ marginBottom: 16 }}>
              {p.features.map((f) => <li key={f}>{f}</li>)}
            </ul>
            {p.contactSales ? (
              <a className="btn" href="mailto:sales@example.com">Contact sales</a>
            ) : (
              <button
                className={`btn ${summary?.plan === p.id ? 'ghost' : 'primary'}`}
                type="button"
                disabled={busy === p.id || summary?.plan === p.id}
                onClick={() => checkout(p.id)}
              >
                {summary?.plan === p.id ? 'Current plan' : busy === p.id ? 'Redirecting…' : p.id === 'free' ? 'Downgrade' : 'Upgrade'}
              </button>
            )}
          </div>
        ))}
      </div>

      <h2 style={{ fontSize: 18, margin: '28px 0 12px' }}>Invoices</h2>
      <div className="card table-wrap">
        <table>
          <thead>
            <tr>
              <th>Number</th>
              <th>Status</th>
              <th>Amount</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {invoices.length === 0 && (
              <tr><td colSpan={5} className="muted">No invoices yet</td></tr>
            )}
            {invoices.map((inv) => (
              <tr key={inv.id}>
                <td className="mono">{inv.number || inv.id}</td>
                <td><span className={`pill ${inv.status === 'paid' ? 'ok' : 'warn'}`}>{inv.status}</span></td>
                <td>{formatMoney(inv.amountPaid ?? inv.amountDue, inv.currency)}</td>
                <td className="muted">{inv.created ? new Date(inv.created * 1000).toLocaleDateString() : '—'}</td>
                <td>
                  {inv.hostedInvoiceUrl && (
                    <a href={inv.hostedInvoiceUrl} target="_blank" rel="noreferrer">View</a>
                  )}
                  {inv.invoicePdf && (
                    <>
                      {' · '}
                      <a href={inv.invoicePdf} target="_blank" rel="noreferrer">PDF</a>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {summary?.recentEvents?.length > 0 && (
        <>
          <h2 style={{ fontSize: 18, margin: '28px 0 12px' }}>Billing events</h2>
          <div className="card table-wrap">
            <table>
              <thead>
                <tr><th>When</th><th>Event</th><th>Amount</th></tr>
              </thead>
              <tbody>
                {summary.recentEvents.map((ev) => (
                  <tr key={ev.id}>
                    <td className="muted">{ev.created_at}</td>
                    <td className="mono">{ev.event_type}</td>
                    <td>{ev.amount_cents != null ? formatMoney(ev.amount_cents) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

function RequireAuth({ children }) {
  const s = session();
  if (!s?.accessToken) return <Navigate to="/login" replace />;
  return <Shell user={s.username}>{children}</Shell>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<RequireAuth><Dashboard /></RequireAuth>} />
      <Route path="/users" element={<RequireAuth><Users /></RequireAuth>} />
      <Route path="/tenants" element={<RequireAuth><Tenants /></RequireAuth>} />
      <Route path="/billing" element={<RequireAuth><Billing /></RequireAuth>} />
      <Route path="/policies" element={<RequireAuth><Policies /></RequireAuth>} />
      <Route path="/audit" element={<RequireAuth><Audit /></RequireAuth>} />
      <Route path="/federation" element={<RequireAuth><Federation /></RequireAuth>} />
      <Route path="/models" element={<RequireAuth><Models /></RequireAuth>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
