'use strict';

/**
 * External Policy Decision Point (PDP) clients:
 *   - OPA (Open Policy Agent) — HTTP Data / Compile API
 *   - Cedar (Amazon Verified Permissions style or cedar-agent HTTP)
 *
 * When enabled, evaluate() is consulted in addition to in-process ABAC.
 * Fail mode: PDP_FAILURE_MODE=fail_closed|fail_open|degrade (default degrade → local ABAC only)
 */

const config = require('./config');
const abac = require('./abac');
const { logger } = require('./logger');

const OPA_URL = (process.env.OPA_URL || '').replace(/\/$/, '');
const OPA_PATH = process.env.OPA_POLICY_PATH || '/v1/data/ztiam/authz/allow';
const CEDAR_URL = (process.env.CEDAR_PDP_URL || '').replace(/\/$/, '');
// local | opa | cedar | avp | both | all
const PDP_BACKEND = (process.env.PDP_BACKEND || 'local').toLowerCase();
const FAILURE_MODE = (process.env.PDP_FAILURE_MODE || 'degrade').toLowerCase();
const TIMEOUT_MS = parseInt(process.env.PDP_TIMEOUT_MS || '500', 10);
const avp = require('./amazonVerifiedPermissions');

async function fetchWithTimeout(url, opts = {}) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...opts, signal: ac.signal });
    const text = await res.text();
    let body;
    try { body = JSON.parse(text); } catch { body = { raw: text }; }
    return { ok: res.ok, status: res.status, body };
  } finally {
    clearTimeout(t);
  }
}

/**
 * Map internal context → OPA input document.
 */
function toOpaInput(ctx) {
  return {
    input: {
      user: {
        id: ctx.userId,
        role: ctx.role,
        tenant: ctx.tenantId,
        status: ctx.status || 'ACTIVE',
      },
      action: ctx.action,
      resource: {
        id: ctx.resourceId || ctx.resource || 'default',
        type: ctx.resourceType || 'app',
      },
      context: {
        risk_score: ctx.riskScore,
        country: ctx.country,
        mfa_verified: !!ctx.mfaVerified,
        hour: ctx.hour,
      },
    },
  };
}

/**
 * OPA decision: expect { result: true/false } or { result: { allow: bool, reasons: [] } }
 */
async function evaluateOpa(ctx) {
  if (!OPA_URL) throw new Error('OPA_URL not configured');
  const { ok, status, body } = await fetchWithTimeout(`${OPA_URL}${OPA_PATH}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(toOpaInput(ctx)),
  });
  if (!ok) throw new Error(`OPA HTTP ${status}`);
  const result = body.result;
  if (typeof result === 'boolean') {
    return {
      decision: result ? 'permit' : 'forbid',
      reason: result ? 'OPA allow' : 'OPA deny',
      backend: 'opa',
      raw: body,
    };
  }
  if (result && typeof result === 'object') {
    const allow = result.allow === true || result.decision === 'allow' || result.permit === true;
    return {
      decision: allow ? 'permit' : 'forbid',
      reason: result.reason || result.reasons?.join?.('; ') || (allow ? 'OPA allow' : 'OPA deny'),
      backend: 'opa',
      raw: body,
    };
  }
  return { decision: 'forbid', reason: 'OPA empty result', backend: 'opa', raw: body };
}

/**
 * Cedar HTTP agent: POST /v1/is_authorized
 * Body: { principal, action, resource, context }
 */
async function evaluateCedar(ctx) {
  if (!CEDAR_URL) throw new Error('CEDAR_PDP_URL not configured');
  const payload = {
    principal: `User::"${ctx.userId}"`,
    action: `Action::"${ctx.action}"`,
    resource: `Resource::"${ctx.resourceId || ctx.resource || 'default'}"`,
    context: {
      riskScore: ctx.riskScore ?? 0,
      country: ctx.country || '',
      mfaVerified: !!ctx.mfaVerified,
      role: ctx.role || '',
      tenantId: ctx.tenantId || '',
      status: ctx.status || 'ACTIVE',
    },
  };
  const { ok, status, body } = await fetchWithTimeout(`${CEDAR_URL}/v1/is_authorized`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!ok) throw new Error(`Cedar HTTP ${status}`);
  const decision = (body.decision || body.result || '').toString().toLowerCase();
  const allow = decision === 'allow' || decision === 'permit' || body.allowed === true;
  return {
    decision: allow ? 'permit' : 'forbid',
    reason: body.diagnostics?.reason || body.reason || (allow ? 'Cedar allow' : 'Cedar deny'),
    backend: 'cedar',
    raw: body,
  };
}

/**
 * Unified evaluate: external PDP first (if configured), else local ABAC.
 * Forbid from any layer wins.
 *
 * @param {object} ctx
 * @returns {Promise<{ decision: 'permit'|'forbid', reason: string, layers: object[] }>}
 */
function resolveBackends() {
  switch (PDP_BACKEND) {
    case 'all':
      return ['opa', 'cedar', 'avp'];
    case 'both':
      return ['opa', 'cedar'];
    case 'opa':
      return ['opa'];
    case 'cedar':
      return ['cedar'];
    case 'avp':
      return ['avp'];
    case 'local':
    default:
      return [];
  }
}

async function evaluateBackend(b, ctx) {
  if (b === 'opa') return evaluateOpa(ctx);
  if (b === 'cedar') return evaluateCedar(ctx);
  if (b === 'avp') return avp.evaluate(ctx);
  throw new Error(`Unknown PDP backend ${b}`);
}

async function evaluate(ctx) {
  const layers = [];
  const backends = resolveBackends();

  for (const b of backends) {
    try {
      const r = await evaluateBackend(b, ctx);
      layers.push(r);
      if (r.decision === 'forbid') {
        return { decision: 'forbid', reason: r.reason, layers, backend: b };
      }
    } catch (err) {
      logger.warn({ err: err.message, backend: b }, 'External PDP error');
      if (FAILURE_MODE === 'fail_closed') {
        return {
          decision: 'forbid',
          reason: `PDP unavailable (${b}): fail-closed`,
          layers,
          backend: b,
          degraded: true,
        };
      }
      if (FAILURE_MODE === 'fail_open') {
        layers.push({ decision: 'permit', reason: `PDP ${b} error fail-open`, backend: b, error: err.message });
        continue;
      }
      // degrade: continue to local
      layers.push({ decision: 'degraded', reason: err.message, backend: b });
    }
  }

  // Local ABAC always runs (defense in depth) unless pure external and all permitted
  const local = await abac.evaluate(ctx);
  layers.push({ ...local, backend: 'local_abac' });
  if (local.decision === 'forbid') {
    return { decision: 'forbid', reason: local.reason, layers, backend: 'local_abac' };
  }

  // If external backends ran and all permitted, permit
  if (backends.length && layers.some((l) => ['opa', 'cedar', 'avp'].includes(l.backend))) {
    const forbids = layers.filter((l) => l.decision === 'forbid');
    if (forbids.length) {
      return { decision: 'forbid', reason: forbids[0].reason, layers };
    }
  }

  return {
    decision: 'permit',
    reason: local.reason || 'permit',
    layers,
    backend: backends[0] || 'local_abac',
  };
}

function status() {
  return {
    backend: PDP_BACKEND,
    failureMode: FAILURE_MODE,
    opa: { configured: !!OPA_URL, url: OPA_URL || null, path: OPA_PATH },
    cedar: { configured: !!CEDAR_URL, url: CEDAR_URL || null },
    avp: avp.status(),
    timeoutMs: TIMEOUT_MS,
  };
}

module.exports = {
  evaluate,
  evaluateOpa,
  evaluateCedar,
  status,
  toOpaInput,
};
