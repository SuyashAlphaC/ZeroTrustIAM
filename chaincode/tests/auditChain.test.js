// Tamper-evident audit hash chain: per-entry SHA256 link + chain verification.
'use strict';

const crypto = require('crypto');

const IAMContract = require('../lib/iamContract');
const { MockContext } = require('./mockContext');

const zkpVerifier = require('../../policy-engine/zkpVerifier');

let rbSeed = 0;
function deterministicProofPkg() {
  rbSeed += 1;
  jest.spyOn(crypto, 'randomBytes').mockImplementation((n) => {
    const buf = Buffer.alloc(n);
    for (let i = 0; i < n; i++) buf[i] = (rbSeed + i * 41) & 0xff;
    return buf;
  });
  const pkg = zkpVerifier.createZKPPackage(0.2, 0.6);
  crypto.randomBytes.mockRestore();
  if (!pkg.success) throw new Error('proof generation failed');
  return pkg;
}

async function evalAccess(c, ctx, txId, opts = {}) {
  ctx.stub.setTxId(txId);
  const pkg = opts.usePkg !== false ? deterministicProofPkg() : null;
  const proofJson = pkg ? JSON.stringify({ commitment: pkg.commitment, rangeProof: pkg.rangeProof }) : '';
  return c.EvaluateAccess(
    ctx,
    opts.userId || 'alice',
    opts.deviceId || 'dev-001',
    String(opts.riskScore ?? 0.05),
    opts.permission || 'read',
    proofJson,
    '',
    opts.resource || 'default',
    'true',
  );
}

describe('Audit hash chain', () => {
  beforeEach(() => {
    rbSeed += 71;
  });

  test('first entry uses prevHash=GENESIS and stores entryHash', async () => {
    const ctx = new MockContext({ store: new Map() });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);

    await evalAccess(c, ctx, 'chain-tx-1');

    const entry = JSON.parse((await ctx.stub.getState('AuditLog:chain-tx-1')).toString());
    expect(entry.prevHash).toBe('GENESIS');
    expect(typeof entry.entryHash).toBe('string');
    expect(entry.entryHash).toMatch(/^[0-9a-f]{64}$/);

    const head = await c.GetAuditChainHead(ctx);
    expect(head).toBe(entry.entryHash);
  });

  test('subsequent entry links to previous entryHash', async () => {
    const ctx = new MockContext({ store: new Map() });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);

    await evalAccess(c, ctx, 'chain-tx-a');
    const first = JSON.parse((await ctx.stub.getState('AuditLog:chain-tx-a')).toString());

    await evalAccess(c, ctx, 'chain-tx-b');
    const second = JSON.parse((await ctx.stub.getState('AuditLog:chain-tx-b')).toString());

    expect(second.prevHash).toBe(first.entryHash);
    expect(second.entryHash).not.toBe(first.entryHash);

    const head = await c.GetAuditChainHead(ctx);
    expect(head).toBe(second.entryHash);
  });

  test('VerifyAuditChain returns valid=true on a clean ledger', async () => {
    const ctx = new MockContext({ store: new Map() });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);

    await evalAccess(c, ctx, 'verify-tx-1');
    await evalAccess(c, ctx, 'verify-tx-2');
    await evalAccess(c, ctx, 'verify-tx-3');

    const result = JSON.parse(await c.VerifyAuditChain(ctx, '', ''));
    expect(result.valid).toBe(true);
    expect(result.brokenAt).toBeNull();
    expect(result.totalChecked).toBe(3);
  });

  test('VerifyAuditChain detects tampered entry and reports brokenAt', async () => {
    const ctx = new MockContext({ store: new Map() });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);

    await evalAccess(c, ctx, 'tamper-tx-1');
    await evalAccess(c, ctx, 'tamper-tx-2');
    await evalAccess(c, ctx, 'tamper-tx-3');

    // Tamper with the middle entry's decision in mock world state.
    const tamperedKey = 'AuditLog:tamper-tx-2';
    const original = JSON.parse((await ctx.stub.getState(tamperedKey)).toString());
    original.decision = 'DENY'; // hash will no longer match
    await ctx.stub.putState(tamperedKey, Buffer.from(JSON.stringify(original)));

    const result = JSON.parse(await c.VerifyAuditChain(ctx, '', ''));
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe('tamper-tx-2');
  });
});
