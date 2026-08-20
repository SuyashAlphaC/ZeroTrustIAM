'use strict';

const avp = require('../../amazonVerifiedPermissions');

describe('amazonVerifiedPermissions', () => {
  it('maps context to IsAuthorized input', () => {
    process.env.AVP_POLICY_STORE_ID = 'ps-test';
    const input = avp.toIsAuthorizedInput({
      userId: 'alice',
      action: 'read',
      resourceId: 'orders',
      riskScore: 0.2,
      country: 'US',
      role: 'viewer',
      tenantId: 'default',
      status: 'ACTIVE',
      mfaVerified: true,
      hour: 10,
    });
    expect(input.policyStoreId).toBe('ps-test');
    expect(input.principal.entityId).toBe('alice');
    expect(input.action.actionId).toBe('read');
    expect(input.resource.entityId).toBe('orders');
    expect(input.context.contextMap.mfaVerified.boolean).toBe(true);
    expect(input.context.contextMap.riskScore.decimal).toBe('0.2');
  });

  it('status reports schema hint', () => {
    const s = avp.status();
    expect(s.schema.actions).toContain('read');
    expect(s.schema.samplePolicy).toContain('permit');
  });
});
