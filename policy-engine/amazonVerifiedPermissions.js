'use strict';

/**
 * Amazon Verified Permissions (AVP) — managed Cedar PDP.
 *
 * Env:
 *   AVP_POLICY_STORE_ID     ps-xxxxxxxx
 *   AWS_REGION              us-east-1
 *   AVP_PRINCIPAL_TYPE      User          (entity type)
 *   AVP_RESOURCE_TYPE       Resource
 *   AVP_ACTION_TYPE         Action        (namespace prefix)
 *   AVP_ENABLED             true|false    (also selected via PDP_BACKEND=avp)
 *
 * Uses IsAuthorized API. Falls back gracefully if SDK/credentials missing.
 */

const { logger } = require('./logger');

function isConfigured() {
  return !!(
    process.env.AVP_POLICY_STORE_ID
    && (process.env.AVP_ENABLED === 'true' || process.env.PDP_BACKEND === 'avp'
      || (process.env.PDP_BACKEND || '').includes('avp'))
  );
}

function entityId(entityType, id) {
  return {
    entityType: entityType.startsWith('ztiam::') ? entityType : `ztiam::${entityType}`,
    entityId: String(id),
  };
}

/**
 * Map ZeroTrustIAM context → AVP IsAuthorized request.
 */
function toIsAuthorizedInput(ctx) {
  const principalType = process.env.AVP_PRINCIPAL_TYPE || 'User';
  const resourceType = process.env.AVP_RESOURCE_TYPE || 'Resource';
  const actionType = process.env.AVP_ACTION_TYPE || 'Action';
  const resourceId = ctx.resourceId || ctx.resource || 'default';

  return {
    policyStoreId: process.env.AVP_POLICY_STORE_ID,
    principal: entityId(principalType, ctx.userId),
    action: {
      actionType: actionType.startsWith('ztiam::') ? actionType : `ztiam::${actionType}`,
      actionId: String(ctx.action || 'read'),
    },
    resource: entityId(resourceType, resourceId),
    context: {
      contextMap: {
        riskScore: { decimal: String(ctx.riskScore ?? 0) },
        // AVP context values are typed
        country: { string: String(ctx.country || '') },
        role: { string: String(ctx.role || '') },
        tenantId: { string: String(ctx.tenantId || 'default') },
        status: { string: String(ctx.status || 'ACTIVE') },
        mfaVerified: { boolean: !!ctx.mfaVerified },
        hour: { long: Number(ctx.hour ?? 0) },
      },
    },
  };
}

/**
 * Call AVP IsAuthorized.
 * @returns {Promise<{ decision: 'permit'|'forbid', reason: string, backend: 'avp', raw?: object }>}
 */
async function evaluate(ctx) {
  if (!process.env.AVP_POLICY_STORE_ID) {
    throw new Error('AVP_POLICY_STORE_ID is not configured');
  }

  // eslint-disable-next-line global-require
  const {
    VerifiedPermissionsClient,
    IsAuthorizedCommand,
  } = require('@aws-sdk/client-verifiedpermissions');

  const region = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1';
  const client = new VerifiedPermissionsClient({ region });
  const input = toIsAuthorizedInput(ctx);

  const out = await client.send(new IsAuthorizedCommand(input));
  const decision = (out.decision || '').toUpperCase();
  const allow = decision === 'ALLOW';

  // Collect determining policies for audit
  const determining = (out.determiningPolicies || [])
    .map((p) => p.policyId)
    .filter(Boolean);

  const errors = (out.errors || []).map((e) => e.errorDescription || e.errorCode).filter(Boolean);

  return {
    decision: allow ? 'permit' : 'forbid',
    reason: allow
      ? `AVP ALLOW (${determining.join(',') || 'no-determining-policy'})`
      : `AVP DENY (${errors.join('; ') || determining.join(',') || 'implicit deny'})`,
    backend: 'avp',
    raw: {
      decision: out.decision,
      determiningPolicies: determining,
      errors,
    },
  };
}

/**
 * Batch authorize helper (optional bulk path).
 */
async function evaluateBatch(requests) {
  const results = [];
  for (const ctx of requests) {
    try {
      results.push(await evaluate(ctx));
    } catch (err) {
      results.push({
        decision: 'forbid',
        reason: err.message,
        backend: 'avp',
        error: true,
      });
    }
  }
  return results;
}

/**
 * Create / update schema notes for operators (documentation helper).
 */
function schemaHint() {
  return {
    namespace: 'ztiam',
    entityTypes: ['User', 'Resource'],
    actions: ['read', 'write', 'delete', 'manage'],
    contextAttributes: {
      riskScore: 'Decimal',
      country: 'String',
      role: 'String',
      tenantId: 'String',
      status: 'String',
      mfaVerified: 'Boolean',
      hour: 'Long',
    },
    samplePolicy: `
permit (
  principal,
  action == ztiam::Action::"read",
  resource
) when {
  context.status == "ACTIVE" &&
  context.riskScore < decimal("0.6")
};
`.trim(),
  };
}

function status() {
  return {
    configured: !!(process.env.AVP_POLICY_STORE_ID),
    enabled: isConfigured(),
    policyStoreId: process.env.AVP_POLICY_STORE_ID || null,
    region: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1',
    schema: schemaHint(),
  };
}

module.exports = {
  isConfigured,
  evaluate,
  evaluateBatch,
  toIsAuthorizedInput,
  schemaHint,
  status,
};
