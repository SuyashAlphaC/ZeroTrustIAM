'use strict';

const { computeRiskScore, incrementFailedAttempts, resetFailedAttempts, getFailedAttempts } = require('../../riskScorer');

describe('riskScorer', () => {
  const aliceProfile = {
    registeredDevices: ['dev-001'],
    usualLocation: { country: 'IN', city: 'Gwalior' },
    normalHours: [8, 18],
  };

  beforeEach(() => {
    resetFailedAttempts('alice');
    resetFailedAttempts('bob');
  });

  describe('computeRiskScore', () => {
    it('returns 0 for a fully trusted context', () => {
      const ctx = {
        username: 'alice',
        deviceId: 'dev-001',
        timestamp: '2026-04-02T10:00:00Z', // 3:30 PM IST = within 8-18
        location: { country: 'IN', city: 'Gwalior' },
      };
      const { score, breakdown } = computeRiskScore(aliceProfile, ctx);
      expect(score).toBe(0);
      expect(breakdown.d_score).toBe(0);
      expect(breakdown.l_score).toBe(0);
      expect(breakdown.t_score).toBe(0);
      expect(breakdown.a_score).toBe(0);
    });

    it('assigns d_score=1 for unknown device', () => {
      const ctx = {
        username: 'alice',
        deviceId: 'attacker-laptop',
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'IN', city: 'Gwalior' },
      };
      const { score, breakdown } = computeRiskScore(aliceProfile, ctx);
      expect(breakdown.d_score).toBe(1);
      expect(score).toBe(0.4); // 0.40 * 1
    });

    it('assigns l_score=1 for foreign country', () => {
      const ctx = {
        username: 'alice',
        deviceId: 'dev-001',
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'RU', city: 'Moscow' },
      };
      const { breakdown } = computeRiskScore(aliceProfile, ctx);
      expect(breakdown.l_score).toBe(1);
    });

    it('assigns l_score=0.5 for same country different city', () => {
      const ctx = {
        username: 'alice',
        deviceId: 'dev-001',
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'IN', city: 'Delhi' },
      };
      const { breakdown } = computeRiskScore(aliceProfile, ctx);
      expect(breakdown.l_score).toBe(0.5);
    });

    it('assigns t_score=1 for off-hours login', () => {
      // 20:00 UTC = 1:30 AM IST (next day), outside 8-18
      const ctx = {
        username: 'alice',
        deviceId: 'dev-001',
        timestamp: '2026-04-02T20:00:00Z',
        location: { country: 'IN', city: 'Gwalior' },
      };
      const { breakdown } = computeRiskScore(aliceProfile, ctx);
      expect(breakdown.t_score).toBe(1);
    });

    it('computes cumulative risk correctly', () => {
      // Unknown device + foreign country + off-hours
      const ctx = {
        username: 'alice',
        deviceId: 'hacker-dev',
        timestamp: '2026-04-02T20:00:00Z',
        location: { country: 'CN', city: 'Beijing' },
      };
      const { score } = computeRiskScore(aliceProfile, ctx);
      // R = 0.40*1 + 0.30*1 + 0.20*1 + 0.10*0 = 0.90
      expect(score).toBe(0.9);
    });
  });

  describe('failedAttempts', () => {
    it('increments and tracks failed attempts', () => {
      expect(getFailedAttempts('alice')).toBe(0);
      incrementFailedAttempts('alice');
      incrementFailedAttempts('alice');
      expect(getFailedAttempts('alice')).toBe(2);
    });

    it('resets failed attempts', () => {
      incrementFailedAttempts('alice');
      incrementFailedAttempts('alice');
      resetFailedAttempts('alice');
      expect(getFailedAttempts('alice')).toBe(0);
    });

    it('caps a_score at 1.0', () => {
      for (let i = 0; i < 10; i++) incrementFailedAttempts('alice');
      const ctx = {
        username: 'alice',
        deviceId: 'dev-001',
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'IN', city: 'Gwalior' },
      };
      const { breakdown } = computeRiskScore(aliceProfile, ctx);
      expect(breakdown.a_score).toBe(1);
    });

    it('computes a_score proportionally', () => {
      incrementFailedAttempts('alice');
      incrementFailedAttempts('alice');
      const ctx = {
        username: 'alice',
        deviceId: 'dev-001',
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'IN', city: 'Gwalior' },
      };
      const { breakdown } = computeRiskScore(aliceProfile, ctx);
      expect(breakdown.a_score).toBeCloseTo(0.4); // 2/5
    });
  });
});
