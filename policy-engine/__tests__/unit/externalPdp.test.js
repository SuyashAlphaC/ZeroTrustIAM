'use strict';

process.env.PDP_BACKEND = 'local';
process.env.OPA_URL = '';
process.env.CEDAR_PDP_URL = '';

const pdp = require('../../externalPdp');

describe('externalPdp (local backend)', () => {
  it('forbids suspended via local ABAC layer', async () => {
    const r = await pdp.evaluate({
      userId: 'bob',
      role: 'viewer',
      action: 'read',
      status: 'SUSPENDED',
      riskScore: 0,
    });
    expect(r.decision).toBe('forbid');
  });

  it('permits low-risk read', async () => {
    const r = await pdp.evaluate({
      userId: 'alice',
      role: 'viewer',
      action: 'read',
      status: 'ACTIVE',
      riskScore: 0.1,
    });
    expect(r.decision).toBe('permit');
  });

  it('exposes status', () => {
    const s = pdp.status();
    expect(s.backend).toBeDefined();
    expect(s.opa).toBeDefined();
  });
});
