'use strict';

const crypto = require('crypto');

const IAMContract = require('../lib/iamContract');
const { MockContext } = require('./mockContext');
const zkpVerifier = require('../../policy-engine/zkpVerifier');

let rbSeed = 0;
function buildPkg() {
  rbSeed += 1;
  jest.spyOn(crypto, 'randomBytes').mockImplementation((n) => {
    const buf = Buffer.alloc(n);
    for (let i = 0; i < n; i++) buf[i] = (rbSeed + i * 53) & 0xff;
    return buf;
  });
  const pkg = zkpVerifier.createZKPPackage(0.2, 0.6);
  crypto.randomBytes.mockRestore();
  if (!pkg.success) throw new Error('proof generation failed');
  return pkg;
}

function makeProofJson(pkg, overrides = {}) {
  const metadata = { ...pkg.metadata, ...overrides };
  return JSON.stringify({ commitment: pkg.commitment, rangeProof: pkg.rangeProof, metadata });
}

async function evaluate(c, ctx, proofJson, txId) {
  ctx.stub.setTxId(txId);
  return c.EvaluateAccess(ctx, 'alice', 'dev-001', '0.05', 'read', proofJson, '', 'default', 'true');
}

describe('Replay protection (nonce + freshness)', () => {
  const baseMs = Date.parse('2026-05-07T12:00:00.000Z');

  test('fresh proof with valid nonce is allowed', async () => {
    const ctx = new MockContext({ store: new Map(), timestampMs: baseMs });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);
    const pkg = buildPkg();
    const proofJson = makeProofJson(pkg, { timestamp: new Date(baseMs).toISOString() });
    const res = JSON.parse(await evaluate(c, ctx, proofJson, 'tx-fresh'));
    expect(res.decision).toBe('ALLOW');
  });

  test('replay of same nonce is denied', async () => {
    const ctx = new MockContext({ store: new Map(), timestampMs: baseMs });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);
    const pkg = buildPkg();
    const proofJson = makeProofJson(pkg, { timestamp: new Date(baseMs).toISOString() });
    const first = JSON.parse(await evaluate(c, ctx, proofJson, 'tx-1'));
    expect(first.decision).toBe('ALLOW');
    const second = JSON.parse(await evaluate(c, ctx, proofJson, 'tx-2'));
    expect(second.decision).toBe('DENY');
    expect(second.reason).toBe('nonce_replay');
  });

  test('proof timestamp 10 minutes old is denied', async () => {
    const ctx = new MockContext({ store: new Map(), timestampMs: baseMs });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);
    const pkg = buildPkg();
    const proofJson = makeProofJson(pkg, { timestamp: new Date(baseMs - 600000).toISOString() });
    const res = JSON.parse(await evaluate(c, ctx, proofJson, 'tx-old'));
    expect(res.decision).toBe('DENY');
    expect(res.reason).toBe('proof_too_old');
  });

  test('proof timestamp 2 minutes in future is denied', async () => {
    const ctx = new MockContext({ store: new Map(), timestampMs: baseMs });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);
    const pkg = buildPkg();
    const proofJson = makeProofJson(pkg, { timestamp: new Date(baseMs + 120000).toISOString() });
    const res = JSON.parse(await evaluate(c, ctx, proofJson, 'tx-future'));
    expect(res.decision).toBe('DENY');
    expect(res.reason).toBe('proof_in_future');
  });

  test('same nonce for different users both allowed (per-user scope)', async () => {
    const ctx = new MockContext({ store: new Map(), timestampMs: baseMs });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);
    await ctx.stub.putState(
      'UserRegistry:bob',
      Buffer.from(JSON.stringify({ userId: 'bob', role: 'admin', registeredDevices: ['dev-001'], status: 'ACTIVE' }))
    );
    const pkg = buildPkg();
    const sharedNonce = 'aabbccddeeff0011';
    const proofJson = makeProofJson(pkg, {
      nonce: sharedNonce,
      timestamp: new Date(baseMs).toISOString(),
    });

    ctx.stub.setTxId('tx-alice');
    const aliceRes = JSON.parse(
      await c.EvaluateAccess(ctx, 'alice', 'dev-001', '0.05', 'read', proofJson, '', 'default', 'true')
    );
    expect(aliceRes.decision).toBe('ALLOW');

    ctx.stub.setTxId('tx-bob');
    const bobRes = JSON.parse(
      await c.EvaluateAccess(ctx, 'bob', 'dev-001', '0.05', 'read', proofJson, '', 'default', 'true')
    );
    expect(bobRes.decision).toBe('ALLOW');
  });

  test('CleanupExpiredNonces removes expired entries', async () => {
    const ctx = new MockContext({ store: new Map(), timestampMs: baseMs });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);

    const expiredKey = ctx.stub.createCompositeKey('Nonce', ['alice', 'default', '1111111111111111']);
    const liveKey = ctx.stub.createCompositeKey('Nonce', ['alice', 'default', '2222222222222222']);
    await ctx.stub.putState(expiredKey, Buffer.from(JSON.stringify({ expiresAt: baseMs - 1000 })));
    await ctx.stub.putState(liveKey, Buffer.from(JSON.stringify({ expiresAt: baseMs + 600000 })));

    const res = JSON.parse(await c.CleanupExpiredNonces(ctx));
    expect(res.removed).toBe(1);
    const expiredAfter = await ctx.stub.getState(expiredKey);
    expect(expiredAfter.length).toBe(0);
    const liveAfter = await ctx.stub.getState(liveKey);
    expect(liveAfter.length).toBeGreaterThan(0);
  });
});
