'use strict';

const { computeRiskScore, incrementFailedAttempts, resetFailedAttempts, getFailedAttempts } = require('../../riskScorer');

describe('riskScorer', () => {
  const aliceProfile = {
    registeredDevices: ['dev-001'],
    usualLocation: { country: 'IN', city: 'Gwalior' },
    normalHours: [8, 18],
  };

  beforeEach(async () => {
    await resetFailedAttempts('alice');
    await resetFailedAttempts('bob');
  });

  describe('computeRiskScore', () => {
    it('returns 0 for a fully trusted context', async () => {
      const ctx = {
        username: 'alice',
        deviceId: 'dev-001',
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'IN', city: 'Gwalior' },
      };
      const { score, breakdown } = await computeRiskScore(aliceProfile, ctx);
      expect(score).toBe(0);
      expect(breakdown.d_score).toBe(0);
      expect(breakdown.l_score).toBe(0);
      expect(breakdown.t_score).toBe(0);
      expect(breakdown.a_score).toBe(0);
    });

    it('assigns d_score=1 for unknown device', async () => {
      const ctx = {
        username: 'alice',
        deviceId: 'attacker-laptop',
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'IN', city: 'Gwalior' },
      };
      const { score, breakdown } = await computeRiskScore(aliceProfile, ctx);
      expect(breakdown.d_score).toBe(1);
      expect(score).toBe(0.4);
    });

    it('assigns l_score=1 for foreign country', async () => {
      const ctx = {
        username: 'alice',
        deviceId: 'dev-001',
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'RU', city: 'Moscow' },
      };
      const { breakdown } = await computeRiskScore(aliceProfile, ctx);
      expect(breakdown.l_score).toBe(1);
    });

    it('assigns l_score=0.5 for same country different city', async () => {
      const ctx = {
        username: 'alice',
        deviceId: 'dev-001',
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'IN', city: 'Delhi' },
      };
      const { breakdown } = await computeRiskScore(aliceProfile, ctx);
      expect(breakdown.l_score).toBe(0.5);
    });

    it('assigns t_score=1 for off-hours login', async () => {
      const ctx = {
        username: 'alice',
        deviceId: 'dev-001',
        timestamp: '2026-04-02T20:00:00Z',
        location: { country: 'IN', city: 'Gwalior' },
      };
      const { breakdown } = await computeRiskScore(aliceProfile, ctx);
      expect(breakdown.t_score).toBe(1);
    });

    it('computes cumulative risk correctly', async () => {
      const ctx = {
        username: 'alice',
        deviceId: 'hacker-dev',
        timestamp: '2026-04-02T20:00:00Z',
        location: { country: 'CN', city: 'Beijing' },
      };
      const { score } = await computeRiskScore(aliceProfile, ctx);
      expect(score).toBe(0.9);
    });
  });

  describe('failedAttempts', () => {
    it('increments and tracks failed attempts', async () => {
      expect(await getFailedAttempts('alice')).toBe(0);
      await incrementFailedAttempts('alice');
      await incrementFailedAttempts('alice');
      expect(await getFailedAttempts('alice')).toBe(2);
    });

    it('resets failed attempts', async () => {
      await incrementFailedAttempts('alice');
      await incrementFailedAttempts('alice');
      await resetFailedAttempts('alice');
      expect(await getFailedAttempts('alice')).toBe(0);
    });

    it('caps a_score at 1.0', async () => {
      for (let i = 0; i < 10; i++) await incrementFailedAttempts('alice');
      const ctx = {
        username: 'alice',
        deviceId: 'dev-001',
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'IN', city: 'Gwalior' },
      };
      const { breakdown } = await computeRiskScore(aliceProfile, ctx);
      expect(breakdown.a_score).toBe(1);
    });

    it('computes a_score proportionally', async () => {
      await incrementFailedAttempts('alice');
      await incrementFailedAttempts('alice');
      const ctx = {
        username: 'alice',
        deviceId: 'dev-001',
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'IN', city: 'Gwalior' },
      };
      const { breakdown } = await computeRiskScore(aliceProfile, ctx);
      expect(breakdown.a_score).toBeCloseTo(0.4);
    });
  });
});
