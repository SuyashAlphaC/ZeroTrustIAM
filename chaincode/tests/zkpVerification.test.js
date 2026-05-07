// Tests for Pedersen range proofs using policy-engine prover vs chaincode verifier.
'use strict';

const crypto = require('crypto');

const IAMContract = require('../lib/iamContract');
const { MockContext } = require('./mockContext');

const zkpVerifier = require('../../policy-engine/zkpVerifier');

let rbCounter = 0;
function mockRandomBytes() {
  jest.spyOn(crypto, 'randomBytes').mockImplementation((n) => {
    rbCounter += 1;
    const buf = Buffer.alloc(n);
    for (let i = 0; i < n; i++) buf[i] = (rbCounter + i * 17) & 0xff;
    return buf;
  });
}

function buildValidProof() {
  mockRandomBytes();
  const pkg = zkpVerifier.createZKPPackage(0.45, 0.6);
  crypto.randomBytes.mockRestore();
  expect(pkg.success).toBe(true);
  return pkg;
}

describe('ZKP verification (chaincode)', () => {
  const contract = new IAMContract('IAMContract');

  test('_validateRiskProof accepts valid proof from zkpVerifier', () => {
    const pkg = buildValidProof();
    const params = {
      riskThreshold: 0.6,
      zkpScheme: 'PedersenBitRangeProof',
    };
    const res = contract._validateRiskProof(
      { commitment: pkg.commitment, rangeProof: pkg.rangeProof },
      params
    );
    expect(res.valid).toBe(true);
  });

  test('tampered commitment fails', () => {
    const pkg = buildValidProof();
    const proof = JSON.parse(JSON.stringify(pkg.rangeProof));
    proof.valueCommitment = `${proof.valueCommitment.slice(0, -1)}0`;
    const params = { riskThreshold: 0.6, zkpScheme: 'PedersenBitRangeProof' };
    expect(
      contract._validateRiskProof({ commitment: pkg.commitment, rangeProof: proof }, params).valid
    ).toBe(false);
  });

  test('tampered bit OR proof fails', () => {
    const pkg = buildValidProof();
    const proof = JSON.parse(JSON.stringify(pkg.rangeProof));
    proof.valueBits[0].proof.e0 = '01'.padStart(64, '0');
    const params = { riskThreshold: 0.6, zkpScheme: 'PedersenBitRangeProof' };
    expect(
      contract._validateRiskProof({ commitment: pkg.commitment, rangeProof: proof }, params).valid
    ).toBe(false);
  });

  test('tampered link proof fails', () => {
    const pkg = buildValidProof();
    const proof = JSON.parse(JSON.stringify(pkg.rangeProof));
    proof.linkProof.response = '02'.padStart(64, '0');
    const params = { riskThreshold: 0.6, zkpScheme: 'PedersenBitRangeProof' };
    expect(
      contract._validateRiskProof({ commitment: pkg.commitment, rangeProof: proof }, params).valid
    ).toBe(false);
  });

  test('edge value 0 is in range', () => {
    mockRandomBytes();
    const pkg = zkpVerifier.createZKPPackage(0, 0.6);
    crypto.randomBytes.mockRestore();
    expect(pkg.success).toBe(true);
    const params = { riskThreshold: 0.6, zkpScheme: 'PedersenBitRangeProof' };
    expect(
      contract._validateRiskProof({ commitment: pkg.commitment, rangeProof: pkg.rangeProof }, params)
        .valid
    ).toBe(true);
  });

  test('value === threshold - epsilon is in range', () => {
    mockRandomBytes();
    const pkg = zkpVerifier.createZKPPackage(0.599, 0.6);
    crypto.randomBytes.mockRestore();
    expect(pkg.success).toBe(true);
    const params = { riskThreshold: 0.6, zkpScheme: 'PedersenBitRangeProof' };
    expect(
      contract._validateRiskProof({ commitment: pkg.commitment, rangeProof: pkg.rangeProof }, params)
        .valid
    ).toBe(true);
  });

  test('value === threshold cannot be proven in range', () => {
    mockRandomBytes();
    const pkg = zkpVerifier.createZKPPackage(0.6, 0.6);
    crypto.randomBytes.mockRestore();
    expect(pkg.success).toBe(false);
  });

  test('replay: same txId overwrites audit — no extra world-state keys', async () => {
    const store = new Map();
    const ctx = new MockContext({ store, txId: 'replay-tx' });
    const c = new IAMContract('IAMContract');
    await c.InitLedger(ctx);

    const pkg = buildValidProof();
    const proofJson = JSON.stringify({ commitment: pkg.commitment, rangeProof: pkg.rangeProof });

    jest.useFakeTimers({ now: new Date('2026-05-01T12:00:00.000Z') });
    const before = ctx.stub.worldStateKeyCount();

    await c.EvaluateAccess(
      ctx,
      'alice',
      'dev-001',
      '0.1',
      'read',
      proofJson,
      '',
      'default',
      'true'
    );
    const mid = ctx.stub.worldStateKeyCount();
    expect(mid).toBeGreaterThan(before);

    await c.EvaluateAccess(
      ctx,
      'alice',
      'dev-001',
      '0.1',
      'read',
      proofJson,
      '',
      'default',
      'true'
    );
    const after = ctx.stub.worldStateKeyCount();
    expect(after).toBe(mid);

    jest.useRealTimers();
  });
});
