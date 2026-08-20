'use strict';

const tenancy = require('../../tenancy');

describe('tenancy', () => {
  it('resolves default tenant', () => {
    const req = { headers: {}, user: {} };
    expect(tenancy.resolveTenantId(req)).toBe(tenancy.DEFAULT_TENANT);
  });

  it('prefers JWT tid', () => {
    const req = { headers: {}, user: { tid: 'acme' } };
    expect(tenancy.resolveTenantId(req)).toBe('acme');
  });

  it('allows admin X-Tenant-Id override', () => {
    const req = {
      headers: { 'x-tenant-id': 'other' },
      user: { role: 'admin', tid: 'default' },
    };
    expect(tenancy.resolveTenantId(req)).toBe('other');
  });

  it('returns plan limits', () => {
    expect(tenancy.getPlanLimits('enterprise').scim).toBe(true);
    expect(tenancy.getPlanLimits('free').users).toBe(25);
  });

  it('withTenantClaims injects tid', () => {
    const p = tenancy.withTenantClaims({ sub: 'a', type: 'access' }, 't1');
    expect(p.tid).toBe('t1');
  });
});
