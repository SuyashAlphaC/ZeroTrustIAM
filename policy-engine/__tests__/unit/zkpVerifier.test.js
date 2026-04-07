'use strict';

const { commit, createRangeProof, verifyRangeProof, createZKPPackage, randomBlindingFactor, PARAMS } = require('../../zkpVerifier');

describe('zkpVerifier', () => {
  describe('randomBlindingFactor', () => {
    it('generates a BigInt blinding factor', () => {
      const r = randomBlindingFactor();
      expect(typeof r).toBe('bigint');
      expect(r).toBeGreaterThan(BigInt(0));
      expect(r).toBeLessThan(PARAMS.p);
    });

    it('generates unique values', () => {
      const a = randomBlindingFactor();
      const b = randomBlindingFactor();
      expect(a).not.toBe(b);
    });
  });

  describe('commit', () => {
    it('creates a Pedersen commitment', () => {
      const r = randomBlindingFactor();
      const c = commit(0.5, r);
      expect(typeof c).toBe('bigint');
      expect(c).toBeGreaterThan(BigInt(0));
    });

    it('produces different commitments for different values', () => {
      const r = randomBlindingFactor();
      const c1 = commit(0.3, r);
      const c2 = commit(0.7, r);
      expect(c1).not.toBe(c2);
    });

    it('produces different commitments for different blinding factors', () => {
      const r1 = randomBlindingFactor();
      const r2 = randomBlindingFactor();
      const c1 = commit(0.5, r1);
      const c2 = commit(0.5, r2);
      expect(c1).not.toBe(c2);
    });
  });

  describe('createRangeProof', () => {
    it('creates a valid proof when value < threshold', () => {
      const r = randomBlindingFactor();
      const proof = createRangeProof(0.3, 0.6, r);
      expect(proof).not.toBeNull();
      expect(proof.proofType).toBe('PedersenRangeProof');
      expect(proof.threshold).toBe(600);
      expect(proof.proofId).toBeDefined();
    });

    it('returns null when value >= threshold', () => {
      const r = randomBlindingFactor();
      const proof = createRangeProof(0.7, 0.6, r);
      expect(proof).toBeNull();
    });

    it('returns null when value equals threshold', () => {
      const r = randomBlindingFactor();
      const proof = createRangeProof(0.6, 0.6, r);
      expect(proof).toBeNull();
    });
  });

  describe('verifyRangeProof', () => {
    it('verifies a valid proof', () => {
      const r = randomBlindingFactor();
      const proof = createRangeProof(0.25, 0.6, r);
      const result = verifyRangeProof(proof);
      expect(result.valid).toBe(true);
      expect(result.threshold).toBe(0.6);
      expect(result.proofId).toBe(proof.proofId);
    });

    it('rejects null proof', () => {
      const result = verifyRangeProof(null);
      expect(result.valid).toBe(false);
    });

    it('rejects wrong proof type', () => {
      const result = verifyRangeProof({ proofType: 'FakeProof' });
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Invalid proof type');
    });

    it('rejects tampered proof (modified challenge)', () => {
      const r = randomBlindingFactor();
      const proof = createRangeProof(0.3, 0.6, r);
      proof.challenge = '12345';
      const result = verifyRangeProof(proof);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Challenge verification failed');
    });
  });

  describe('createZKPPackage', () => {
    it('creates a complete package for valid risk score', () => {
      const pkg = createZKPPackage(0.2, 0.6);
      expect(pkg.success).toBe(true);
      expect(pkg.commitment).toBeDefined();
      expect(pkg.rangeProof).toBeDefined();
      expect(pkg.metadata.scheme).toContain('Pedersen');
      expect(pkg.metadata.property).toBe('risk_score < 0.6');
    });

    it('fails for risk score above threshold', () => {
      const pkg = createZKPPackage(0.8, 0.6);
      expect(pkg.success).toBe(false);
      expect(pkg.reason).toContain('not below threshold');
    });

    it('creates verifiable end-to-end proof', () => {
      const pkg = createZKPPackage(0.15, 0.6);
      expect(pkg.success).toBe(true);
      const verification = verifyRangeProof(pkg.rangeProof);
      expect(verification.valid).toBe(true);
    });
  });
});
