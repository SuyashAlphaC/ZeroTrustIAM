'use strict';

const blockchain = require('../../mockBlockchain');

describe('mockBlockchain', () => {
  describe('evaluateAccess', () => {
    it('allows active user with registered device and valid permission', async () => {
      const result = await blockchain.evaluateAccess('alice', 'dev-001', 0.2, 'read');
      expect(result.decision).toBe('ALLOW');
      expect(result.txId).toMatch(/^mock-/);
      expect(result.layer).toContain('Smart Contract');
    });

    it('denies unregistered device', async () => {
      const result = await blockchain.evaluateAccess('alice', 'unknown-dev', 0.2, 'read');
      expect(result.decision).toBe('DENY');
      expect(result.reason).toContain('Unregistered device');
    });

    it('denies insufficient permissions (viewer trying delete)', async () => {
      const result = await blockchain.evaluateAccess('bob', 'dev-002', 0.1, 'delete');
      expect(result.decision).toBe('DENY');
      expect(result.reason).toContain('Insufficient permissions');
    });

    it('denies unknown user', async () => {
      const result = await blockchain.evaluateAccess('hacker', 'dev-x', 0.1, 'read');
      expect(result.decision).toBe('DENY');
    });
  });

  describe('getAuditLog', () => {
    it('returns audit log entries', async () => {
      // Previous evaluateAccess calls should have generated entries
      const logs = await blockchain.getAuditLog();
      expect(Array.isArray(logs)).toBe(true);
      expect(logs.length).toBeGreaterThan(0);
      expect(logs[0]).toHaveProperty('txId');
      expect(logs[0]).toHaveProperty('decision');
    });
  });
});
