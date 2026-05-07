// Policy public params, MSP-gated updates, and risk model registry behaviours.
'use strict';

const IAMContract = require('../lib/iamContract');
const { MockContext } = require('./mockContext');

describe('PolicyPublicParams and risk models', () => {
  test('GetPolicyPublicParams returns defaults when state empty', async () => {
    const ctx = new MockContext({ store: new Map() });
    const c = new IAMContract('IAMContract');
    const raw = await c.GetPolicyPublicParams(ctx);
    const params = JSON.parse(raw);
    expect(params.policyId).toBe('zt-iam-policy-v1');
    expect(params.riskThreshold).toBe(0.6);
  });

  test('UpdatePolicyPublicParams rejects non Org1MSP', async () => {
    const ctx = new MockContext({ store: new Map(), mspId: 'Org2MSP' });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);
    await expect(
      c.UpdatePolicyPublicParams(ctx, JSON.stringify({ riskThreshold: 0.5 }))
    ).rejects.toThrow(/unauthorized/);
  });

  test('Org1MSP update persists across reads', async () => {
    const ctx = new MockContext({ store: new Map(), mspId: 'Org1MSP' });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);
    await c.UpdatePolicyPublicParams(
      ctx,
      JSON.stringify({ riskThreshold: 0.55, accessGrantTtlSeconds: 1200 })
    );
    const after = JSON.parse(await c.GetPolicyPublicParams(ctx));
    expect(after.riskThreshold).toBe(0.55);
    expect(after.accessGrantTtlSeconds).toBe(1200);
  });

  test('RegisterRiskModel and GetRiskModel round-trip metadata', async () => {
    const ctx = new MockContext({ txId: 'rm-tx', store: new Map() });
    ctx.stub.setTxId('rm-tx');

    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);

    await c.RegisterRiskModel(ctx, 'v-test-001', 'hash-abc', 'RF', 'admin', 'false');
    const got = JSON.parse(await c.GetRiskModel(ctx, 'v-test-001'));
    expect(got.modelHash).toBe('hash-abc');
    expect(got.modelVersion).toBe('v-test-001');
  });
});
