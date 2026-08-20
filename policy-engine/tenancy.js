'use strict';

/**
 * Multi-tenancy: org isolation, plan/billing metadata, per-tenant CMK.
 *
 * Tenants own users, devices, and policies. Requests carry tenant context via:
 *   - JWT claim `tid` / `tenant_id`
 *   - Header `X-Tenant-Id` (admin/service only when impersonating)
 *   - Host subdomain mapping (optional TENANT_HOST_MAP_JSON)
 */

const crypto = require('crypto');
const db = require('./database');
const { logger } = require('./logger');
const config = require('./config');

const DEFAULT_TENANT = process.env.DEFAULT_TENANT_ID || 'default';

/**
 * Resolve tenant id from request.
 * @param {import('express').Request} req
 * @returns {string|null}
 */
function resolveTenantId(req) {
  // Platform / tenant admins may impersonate via header
  const hdr = req.headers['x-tenant-id'];
  if (hdr && typeof hdr === 'string' && (req.user?.role === 'admin' || req.user?.role === 'platform_admin')) {
    return hdr.trim();
  }
  if (req.user?.tid) return req.user.tid;
  if (req.user?.tenant_id) return req.user.tenant_id;
  // Subdomain: acme.iam.example.com → acme
  const host = (req.headers.host || '').split(':')[0];
  const mapRaw = process.env.TENANT_HOST_MAP_JSON;
  if (mapRaw) {
    try {
      const map = JSON.parse(mapRaw);
      if (map[host]) return map[host];
    } catch {
      /* ignore */
    }
  }
  const base = process.env.TENANT_BASE_DOMAIN; // e.g. iam.example.com
  if (base && host.endsWith(`.${base}`)) {
    const sub = host.slice(0, -(base.length + 1));
    if (sub && !sub.includes('.')) return sub;
  }
  return DEFAULT_TENANT;
}

/**
 * Express middleware: attach req.tenantId and load tenant row when available.
 */
function tenantMiddleware() {
  return async (req, res, next) => {
    try {
      const tid = resolveTenantId(req) || DEFAULT_TENANT;
      req.tenantId = tid;
      try {
        req.tenant = await db.getTenant(tid);
      } catch {
        req.tenant = null;
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Ensure the authenticated user belongs to the request tenant (unless platform admin).
 */
function requireTenantAccess(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Authentication required' });
  if (req.user.role === 'platform_admin' || req.user.role === 'admin' && req.user.tid === '*') {
    return next();
  }
  const userTid = req.user.tid || req.user.tenant_id || DEFAULT_TENANT;
  if (req.tenantId && userTid !== req.tenantId && userTid !== '*') {
    return res.status(403).json({ error: 'Tenant isolation violation', code: 'TENANT_MISMATCH' });
  }
  next();
}

/**
 * @param {object} opts
 * @param {string} opts.name
 * @param {string} [opts.slug]
 * @param {string} [opts.plan]
 * @param {string} [opts.billingEmail]
 * @param {string} [opts.cmkArn]
 */
async function createTenant(opts) {
  const tenantId = opts.tenantId || crypto.randomUUID();
  const slug = (opts.slug || opts.name || tenantId)
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 63);
  await db.createTenant({
    tenantId,
    name: opts.name,
    slug,
    plan: opts.plan || 'free',
    billingEmail: opts.billingEmail || null,
    cmkArn: opts.cmkArn || null,
    settings: opts.settings || {},
  });
  logger.info({ tenantId, slug, plan: opts.plan || 'free' }, 'Tenant created');
  return db.getTenant(tenantId);
}

/**
 * Billing plan limits (soft enforcement).
 */
const PLAN_LIMITS = {
  free: { users: 25, mfaRequired: false, scim: false, saml: false, cmk: false },
  team: { users: 250, mfaRequired: true, scim: true, saml: false, cmk: false },
  business: { users: 5000, mfaRequired: true, scim: true, saml: true, cmk: true },
  enterprise: { users: 1000000, mfaRequired: true, scim: true, saml: true, cmk: true },
};

function getPlanLimits(plan) {
  return PLAN_LIMITS[plan] || PLAN_LIMITS.free;
}

/**
 * Resolve CMK for a tenant (AWS KMS key ARN/id) for envelope encryption.
 * @param {string} tenantId
 * @returns {Promise<{ keyId: string|null, arn: string|null }>}
 */
async function getTenantCmk(tenantId) {
  const t = await db.getTenant(tenantId);
  if (!t) return { keyId: null, arn: null };
  return {
    keyId: t.cmk_key_id || t.cmk_arn || null,
    arn: t.cmk_arn || null,
  };
}

/**
 * Attach tenant claim to access token payload.
 */
function withTenantClaims(payload, tenantId, extra = {}) {
  return {
    ...payload,
    tid: tenantId || DEFAULT_TENANT,
    ...extra,
  };
}

module.exports = {
  DEFAULT_TENANT,
  resolveTenantId,
  tenantMiddleware,
  requireTenantAccess,
  createTenant,
  getPlanLimits,
  getTenantCmk,
  withTenantClaims,
  PLAN_LIMITS,
};
