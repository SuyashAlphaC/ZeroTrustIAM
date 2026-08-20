'use strict';

/**
 * Lightweight ABAC policy evaluator (Cedar/Rego-inspired, in-process).
 *
 * Policy document shape:
 * {
 *   "id": "deny-foreign-delete",
 *   "effect": "permit" | "forbid",
 *   "principal": { "roles": ["editor"], "users": [] },   // empty = any
 *   "action": ["delete", "manage"],                      // empty = any
 *   "resource": { "ids": ["*"], "types": [] },
 *   "when": {
 *     "maxRisk": 0.5,           // permit only if risk <= maxRisk; forbid if risk > maxRisk
 *     "countries": ["IN", "US"],
 *     "requireMfa": true,
 *     "hours": [9, 17],
 *     "statusIn": ["SUSPENDED", "DELETED"]
 *   }
 * }
 *
 * Evaluation order: all matching `forbid` policies win over `permit`.
 * If no policy matches, default is permit (caller still enforces RBAC/risk).
 */

const db = require('./database');
const { logger } = require('./logger');

/** Built-in default policies (always active unless overridden). */
const BUILTIN = [
  {
    id: 'builtin-forbid-suspended',
    effect: 'forbid',
    principal: {},
    action: [],
    resource: {},
    when: { statusIn: ['SUSPENDED', 'DELETED', 'DISABLED'] },
    description: 'Suspended or deleted users cannot access any resource',
  },
  {
    id: 'builtin-forbid-high-risk-manage',
    effect: 'forbid',
    principal: {},
    action: ['manage', 'delete'],
    resource: {},
    when: { maxRisk: 0.45 },
    description: 'High-risk sessions cannot perform manage/delete',
  },
];

function matchList(list, value) {
  if (!list || list.length === 0) return true;
  if (list.includes('*')) return true;
  return list.map(String).includes(String(value));
}

function hourInRange(hour, range) {
  if (!range || range.length < 2) return true;
  const [start, end] = range;
  if (start <= end) return hour >= start && hour < end;
  return hour >= start || hour < end;
}

/**
 * @param {object} policy
 * @param {object} ctx
 * @returns {boolean} true if this policy applies to the request
 */
function matches(policy, ctx) {
  const p = policy.principal || {};
  if (p.roles?.length && !matchList(p.roles, ctx.role)) return false;
  if (p.users?.length && !matchList(p.users, ctx.userId)) return false;

  if (policy.action?.length && !matchList(policy.action, ctx.action)) return false;

  const r = policy.resource || {};
  if (r.ids?.length && !matchList(r.ids, ctx.resourceId || ctx.resource)) return false;
  if (r.types?.length && !matchList(r.types, ctx.resourceType)) return false;

  const w = policy.when || {};

  // statusIn: policy applies only when status is in the list
  if (w.statusIn?.length) {
    if (!ctx.status || !w.statusIn.includes(ctx.status)) return false;
  }

  // maxRisk:
  //   forbid → applies when riskScore > maxRisk
  //   permit → applies when riskScore <= maxRisk
  if (w.maxRisk !== undefined && ctx.riskScore !== undefined) {
    if (policy.effect === 'forbid') {
      if (!(ctx.riskScore > w.maxRisk)) return false;
    } else if (policy.effect === 'permit') {
      if (ctx.riskScore > w.maxRisk) return false;
    }
  }

  // countries: permit only from listed countries; forbid when in listed countries
  if (w.countries?.length && ctx.country) {
    const inList = matchList(w.countries, ctx.country);
    if (policy.effect === 'permit' && !inList) return false;
    if (policy.effect === 'forbid' && !inList) return false;
  }

  // requireMfa: permit only when mfaVerified; forbid when mfa missing
  if (w.requireMfa) {
    if (policy.effect === 'permit' && !ctx.mfaVerified) return false;
    if (policy.effect === 'forbid' && ctx.mfaVerified) return false;
  }

  if (w.hours && ctx.hour !== undefined) {
    const inHours = hourInRange(ctx.hour, w.hours);
    if (policy.effect === 'permit' && !inHours) return false;
    if (policy.effect === 'forbid' && inHours) return false;
  }

  return true;
}

/**
 * @param {object} ctx
 * @returns {Promise<{ decision: 'permit'|'forbid', matched: object[], reason: string }>}
 */
async function evaluate(ctx) {
  let stored = [];
  try {
    stored = await db.listAbacPolicies({ activeOnly: true });
  } catch (err) {
    logger.debug({ err: err.message }, 'abac: list policies failed, using builtins');
  }

  const policies = [
    ...BUILTIN,
    ...stored.map((row) => {
      const doc = typeof row.policy_json === 'object'
        ? row.policy_json
        : JSON.parse(row.policy_json || '{}');
      return { ...doc, id: row.policy_id || doc.id };
    }),
  ];

  const matched = [];
  for (const policy of policies) {
    try {
      if (matches(policy, ctx)) matched.push(policy);
    } catch (err) {
      logger.warn({ err: err.message, policyId: policy.id }, 'abac: policy match error');
    }
  }

  const forbids = matched.filter((p) => p.effect === 'forbid');
  if (forbids.length > 0) {
    return {
      decision: 'forbid',
      matched: forbids,
      reason: `ABAC forbid: ${forbids.map((p) => p.id).join(', ')}`,
    };
  }

  const permits = matched.filter((p) => p.effect === 'permit');
  if (permits.length > 0) {
    return {
      decision: 'permit',
      matched: permits,
      reason: `ABAC permit: ${permits.map((p) => p.id).join(', ')}`,
    };
  }

  return { decision: 'permit', matched: [], reason: 'ABAC default permit' };
}

module.exports = {
  evaluate,
  matches,
  BUILTIN,
};
