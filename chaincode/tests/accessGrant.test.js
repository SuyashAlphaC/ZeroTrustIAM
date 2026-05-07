// Access grant issuance, expiry, revocation, and audit fields on ALLOW/DENY paths.
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

describe('AccessGrant + audit logging', () => {
  beforeEach(() => {
    rbSeed += 99;
  });

  test('ALLOW with grant writes AccessGrant and correct expiresAt TTL', async () => {
    const issuedAt = Date.parse('2026-06-01T10:00:00.000Z');
    const ctx = new MockContext({ txId: 'grant-ttl-tx', store: new Map() });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);

    const pkg = deterministicProofPkg();
    const proofJson = JSON.stringify({ commitment: pkg.commitment, rangeProof: pkg.rangeProof });

    jest.useFakeTimers({ advanceTimers: true });
    jest.setSystemTime(issuedAt);

    const resStr = await c.EvaluateAccess(
      ctx,
      'alice',
      'dev-001',
      '0.05',
      'read',
      proofJson,
      '',
      'default',
      'true'
    );

    jest.useRealTimers();

    const res = JSON.parse(resStr);
    expect(res.decision).toBe('ALLOW');
    const grantId = res.accessGrant.grantId;

    const raw = await ctx.stub.getState(`AccessGrant:${grantId}`);
    const grant = JSON.parse(raw.toString());
    expect(Date.parse(grant.expiresAt) - issuedAt).toBe(900 * 1000);
  });

  test('VerifyAccessGrant valid before expiry, expired after advancing clock', async () => {
    const t0 = Date.parse('2026-06-05T08:00:00.000Z');
    const ctx = new MockContext({ txId: 'expiry-tx', store: new Map() });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);

    const pkg = deterministicProofPkg();
    const proofJson = JSON.stringify({ commitment: pkg.commitment, rangeProof: pkg.rangeProof });

    jest.useFakeTimers({ advanceTimers: true });
    jest.setSystemTime(t0);
    await c.EvaluateAccess(
      ctx,
      'alice',
      'dev-001',
      '0.05',
      'read',
      proofJson,
      '',
      'default',
      'true'
    );

    const audit = JSON.parse((await ctx.stub.getState('AuditLog:expiry-tx')).toString());
    const grantId = audit.accessGrantId;

    jest.setSystemTime(t0 + 60 * 1000);
    let v = JSON.parse(await c.VerifyAccessGrant(ctx, grantId, 'alice', 'default', 'read'));
    expect(v.valid).toBe(true);

    jest.setSystemTime(t0 + 900 * 1000 + 1);
    v = JSON.parse(await c.VerifyAccessGrant(ctx, grantId, 'alice', 'default', 'read'));
    expect(v.valid).toBe(false);
    expect(String(v.reason).toLowerCase()).toContain('expired');

    jest.useRealTimers();
  });

  test('RevokeAccessGrant yields revoked verification', async () => {
    const t0 = Date.parse('2026-06-07T09:00:00.000Z');
    const ctx = new MockContext({ txId: 'revoke-tx', store: new Map() });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);

    const pkg = deterministicProofPkg();
    const proofJson = JSON.stringify({ commitment: pkg.commitment, rangeProof: pkg.rangeProof });
    jest.useFakeTimers({ advanceTimers: true });
    jest.setSystemTime(t0);
    await c.EvaluateAccess(
      ctx,
      'alice',
      'dev-001',
      '0.05',
      'read',
      proofJson,
      '',
      'default',
      'true'
    );

    const audit = JSON.parse((await ctx.stub.getState('AuditLog:revoke-tx')).toString());
    const grantId = audit.accessGrantId;

    await c.RevokeAccessGrant(ctx, grantId, 'test-revoke');
    jest.setSystemTime(t0 + 1000);
    const v = JSON.parse(await c.VerifyAccessGrant(ctx, grantId, 'alice', 'default', 'read'));
    expect(v.valid).toBe(false);
    expect(String(v.reason).toLowerCase()).toContain('revoked');

    jest.useRealTimers();
  });

  test('audit with proof hides numeric riskScore and sets proof metadata', async () => {
    const ctx = new MockContext({ txId: 'audit-proof-tx', store: new Map() });
    ctx.stub.setTxId('audit-proof-tx');
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);

    const pkg = deterministicProofPkg();
    const proofJson = JSON.stringify({ commitment: pkg.commitment, rangeProof: pkg.rangeProof });
    await c.EvaluateAccess(
      ctx,
      'alice',
      'dev-001',
      '0.33',
      'read',
      proofJson,
      '',
      'default',
      'true'
    );

    const entry = JSON.parse((await ctx.stub.getState('AuditLog:audit-proof-tx')).toString());
    expect(Object.prototype.hasOwnProperty.call(entry, 'riskScore')).toBe(false);
    expect(entry.riskProof && entry.riskProof.proofHash).toBeTruthy();
  });

  test('audit without proof records numeric riskScore', async () => {
    const ctx = new MockContext({ txId: 'no-proof-tx', store: new Map() });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);

    const merged = JSON.parse((await ctx.stub.getState('PolicyPublicParams:active')).toString());
    merged.zkpRequiredForAllow = false;
    merged.riskThreshold = 0.9;
    await ctx.stub.putState('PolicyPublicParams:active', Buffer.from(JSON.stringify(merged)));

    ctx.stub.setTxId('no-proof-tx');
    await c.EvaluateAccess(ctx, 'alice', 'dev-001', '0.2', 'read', '', '', 'default', 'true');

    const entry = JSON.parse((await ctx.stub.getState('AuditLog:no-proof-tx')).toString());
    expect(entry.riskScore).toBeCloseTo(0.2);
    expect(entry.riskScoreRedacted).toBe(false);
  });
});
