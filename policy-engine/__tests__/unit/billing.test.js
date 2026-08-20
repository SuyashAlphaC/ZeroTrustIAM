'use strict';

const billing = require('../../billing');

describe('billing catalog', () => {
  it('returns plan catalog', () => {
    const c = billing.getCatalog();
    expect(c.plans.length).toBeGreaterThanOrEqual(4);
    expect(c.plans.map((p) => p.id)).toEqual(
      expect.arrayContaining(['free', 'team', 'business', 'enterprise'])
    );
  });

  it('verifyWebhookSignature rejects bad sig when secret set', () => {
    process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test';
    process.env.NODE_ENV = 'test';
    const ok = billing.verifyWebhookSignature('{}', 't=1,v1=deadbeef');
    expect(ok).toBe(false);
    delete process.env.STRIPE_WEBHOOK_SECRET;
  });
});
