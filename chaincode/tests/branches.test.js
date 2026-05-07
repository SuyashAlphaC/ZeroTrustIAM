// DENY paths, DID/VC flows, and parsers to raise iamContract.js coverage.
'use strict';

const IAMContract = require('../lib/iamContract');
const { MockContext } = require('./mockContext');

describe('iamContract branch coverage', () => {
  let ctx;
  let c;

  beforeEach(async () => {
    ctx = new MockContext({ store: new Map(), txId: 'branch-tx' });
    c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);
  });

  test('_parseOptionalJson trims and handles objects', () => {
    expect(c._parseOptionalJson('')).toBeNull();
    expect(c._parseOptionalJson('   ')).toBeNull();
    expect(c._parseOptionalJson(null)).toBeNull();
    expect(c._parseOptionalJson({ a: 1 })).toEqual({ a: 1 });
  });

  test('EvaluateAccess DENY — user not found', async () => {
    ctx.stub.setTxId('nx');
    const out = JSON.parse(
      await c.EvaluateAccess(ctx, 'nope', 'dev-001', '0.1', 'read', '', '', 'default', 'true')
    );
    expect(out.decision).toBe('DENY');
  });

  test('EvaluateAccess DENY — inactive account', async () => {
    await c.UpdateUserStatus(ctx, 'alice', 'SUSPENDED');
    ctx.stub.setTxId('in');
    const out = JSON.parse(
      await c.EvaluateAccess(ctx, 'alice', 'dev-001', '0.1', 'read', '', '', 'default', 'true')
    );
    expect(out.decision).toBe('DENY');
  });

  test('EvaluateAccess DENY — unknown device', async () => {
    await c.UpdateUserStatus(ctx, 'alice', 'ACTIVE');
    ctx.stub.setTxId('dev');
    const out = JSON.parse(
      await c.EvaluateAccess(ctx, 'alice', 'bad-dev', '0.1', 'read', '', '', 'default', 'true')
    );
    expect(out.decision).toBe('DENY');
  });

  test('EvaluateAccess DENY — numeric risk without proof', async () => {
    const merged = JSON.parse((await ctx.stub.getState('PolicyPublicParams:active')).toString());
    merged.zkpRequiredForAllow = false;
    merged.riskThreshold = 0.2;
    await ctx.stub.putState('PolicyPublicParams:active', Buffer.from(JSON.stringify(merged)));
    ctx.stub.setTxId('risk');
    const out = JSON.parse(
      await c.EvaluateAccess(ctx, 'alice', 'dev-001', '0.95', 'read', '', '', 'default', 'true')
    );
    expect(out.decision).toBe('DENY');
  });

  test('EvaluateAccess DENY — proof required but missing range proof', async () => {
    ctx.stub.setTxId('badp');
    const out = JSON.parse(
      await c.EvaluateAccess(
        ctx,
        'alice',
        'dev-001',
        '0.05',
        'read',
        '{}',
        '',
        'default',
        'true'
      )
    );
    expect(out.decision).toBe('DENY');
  });

  test('EvaluateAccess DENY — insufficient role permission', async () => {
    const merged = JSON.parse((await ctx.stub.getState('PolicyPublicParams:active')).toString());
    merged.zkpRequiredForAllow = false;
    merged.riskThreshold = 0.9;
    await ctx.stub.putState('PolicyPublicParams:active', Buffer.from(JSON.stringify(merged)));
    ctx.stub.setTxId('rbac');
    const out = JSON.parse(
      await c.EvaluateAccess(ctx, 'bob', 'dev-002', '0.1', 'delete', '', '', 'default', 'true')
    );
    expect(out.decision).toBe('DENY');
  });

  test('EvaluateAccess DENY — missing RolePermissions simulation', async () => {
    const merged = JSON.parse((await ctx.stub.getState('PolicyPublicParams:active')).toString());
    merged.zkpRequiredForAllow = false;
    merged.riskThreshold = 0.9;
    await ctx.stub.putState('PolicyPublicParams:active', Buffer.from(JSON.stringify(merged)));
    await ctx.stub.deleteState('RolePermissions:admin');
    ctx.stub.setTxId('norole');
    const out = JSON.parse(
      await c.EvaluateAccess(ctx, 'alice', 'dev-001', '0.1', 'read', '', '', 'default', 'true')
    );
    expect(out.decision).toBe('DENY');
  });

  test('RegisterDevice and GetUser', async () => {
    await c.RegisterDevice(ctx, 'alice', 'dev-extra');
    const u = await c.GetUser(ctx, 'alice');
    expect(JSON.parse(u).registeredDevices).toContain('dev-extra');
  });

  test('GetAuditLog and GetAllAuditLogs', async () => {
    const merged = JSON.parse((await ctx.stub.getState('PolicyPublicParams:active')).toString());
    merged.zkpRequiredForAllow = false;
    merged.riskThreshold = 0.9;
    await ctx.stub.putState('PolicyPublicParams:active', Buffer.from(JSON.stringify(merged)));
    ctx.stub.setTxId('alog');
    await c.EvaluateAccess(ctx, 'alice', 'dev-001', '0.1', 'read', '', '', 'default', 'true');
    const one = await c.GetAuditLog(ctx, 'alog');
    expect(JSON.parse(one).txId).toBe('alog');
    const all = JSON.parse(await c.GetAllAuditLogs(ctx));
    expect(Array.isArray(all)).toBe(true);
    expect(all.length).toBeGreaterThan(0);
  });

  test('RegisterDevice idempotent', async () => {
    const first = JSON.parse(await c.RegisterDevice(ctx, 'alice', 'dev-dup'));
    const second = JSON.parse(await c.RegisterDevice(ctx, 'alice', 'dev-dup'));
    expect(first.status).toMatch(/registered/i);
    expect(second.status).toMatch(/already/i);
  });

  test('ResolveDID / DeactivateDID not found', async () => {
    await expect(c.ResolveDID(ctx, 'did:fabric:iam:ghost')).rejects.toThrow(/not found/);
    await expect(c.DeactivateDID(ctx, 'did:fabric:iam:ghost')).rejects.toThrow(/not found/);
  });

  test('DID + VC lifecycle with issuer deactivation', async () => {
    const jwk = JSON.stringify({ kty: 'EC', crv: 'P-256', x: 'test', y: 'test' });
    ctx.stub.setTxId('did1');
    await c.CreateDID(ctx, 'alice', jwk, 'JsonWebKey2020');
    const did = 'did:fabric:iam:alice';
    const resolved = JSON.parse(await c.ResolveDID(ctx, did));
    expect(resolved.didDocument.id).toBe(did);

    ctx.stub.setTxId('did2');
    await c.UpdateDID(ctx, did, JSON.stringify({ kty: 'EC', crv: 'P-256', x: 'x2', y: 'y2' }));

    ctx.stub.setTxId('vc1');
    await c.IssueVerifiableCredential(
      ctx,
      'cred-1',
      did,
      'did:fabric:iam:bob',
      JSON.stringify(['RoleCredential']),
      JSON.stringify({ role: 'viewer' })
    );
    const ver = JSON.parse(await c.VerifyCredential(ctx, 'cred-1'));
    expect(ver.verified).toBe(true);

    ctx.stub.setTxId('dd');
    await c.DeactivateDID(ctx, did);
    const ver2 = JSON.parse(await c.VerifyCredential(ctx, 'cred-1'));
    expect(ver2.verified).toBe(false);
  });

  test('CreateDID duplicate rejected', async () => {
    const jwk = JSON.stringify({ kty: 'EC', crv: 'P-256', x: 'z', y: 'z' });
    ctx.stub.setTxId('d1');
    await c.CreateDID(ctx, 'alice', jwk, 'JsonWebKey2020');
    ctx.stub.setTxId('d2');
    await expect(c.CreateDID(ctx, 'alice', jwk, 'JsonWebKey2020')).rejects.toThrow(/already exists/);
  });

  test('VerifyCredential issuer DID missing', async () => {
    ctx.stub.setTxId('vc2');
    await c.IssueVerifiableCredential(
      ctx,
      'cred-orphan',
      'did:fabric:iam:missingissuer',
      'did:fabric:iam:bob',
      JSON.stringify(['RoleCredential']),
      JSON.stringify({ role: 'viewer' })
    );
    const v = JSON.parse(await c.VerifyCredential(ctx, 'cred-orphan'));
    expect(v.verified).toBe(false);
    expect(String(v.reason)).toMatch(/Issuer/i);
  });

  test('VerifyCredential missing VC', async () => {
    const v = JSON.parse(await c.VerifyCredential(ctx, 'missing-cred'));
    expect(v.verified).toBe(false);
  });

  test('UpdatePolicyPublicParams invalid threshold', async () => {
    await expect(c.UpdatePolicyPublicParams(ctx, JSON.stringify({ riskThreshold: 0 }))).rejects.toThrow(
      /riskThreshold/
    );
  });

  test('RegisterRiskModel activate updates active model', async () => {
    await c.RegisterRiskModel(ctx, 'm-active', 'h2', 'RF', 'admin', 'true');
    const p = JSON.parse(await c.GetPolicyPublicParams(ctx));
    expect(p.activeModelVersion).toBe('m-active');
  });

  test('GetRiskModel throws when missing', async () => {
    await expect(c.GetRiskModel(ctx, 'nope')).rejects.toThrow(/not found/);
  });
});
