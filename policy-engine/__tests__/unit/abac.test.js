'use strict';

const abac = require('../../abac');

describe('abac', () => {
  it('forbids suspended users via builtin', async () => {
    const r = await abac.evaluate({
      userId: 'bob',
      role: 'viewer',
      action: 'read',
      status: 'SUSPENDED',
      riskScore: 0,
    });
    expect(r.decision).toBe('forbid');
  });

  it('forbids high-risk manage', async () => {
    const r = await abac.evaluate({
      userId: 'bob',
      role: 'editor',
      action: 'manage',
      status: 'ACTIVE',
      riskScore: 0.7,
    });
    expect(r.decision).toBe('forbid');
  });

  it('permits low-risk read by default', async () => {
    const r = await abac.evaluate({
      userId: 'alice',
      role: 'viewer',
      action: 'read',
      status: 'ACTIVE',
      riskScore: 0.1,
    });
    expect(r.decision).toBe('permit');
  });

  it('matches custom forbid policy shape', () => {
    const policy = {
      id: 'test',
      effect: 'forbid',
      action: ['delete'],
      when: { maxRisk: 0.2 },
    };
    expect(abac.matches(policy, { action: 'delete', riskScore: 0.5 })).toBe(true);
    expect(abac.matches(policy, { action: 'delete', riskScore: 0.1 })).toBe(false);
  });
});
