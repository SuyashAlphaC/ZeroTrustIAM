'use strict';

describe('accountLockout (local fallback)', () => {
  let lockout;
  const user = `lockuser_${Date.now()}`;

  beforeAll(() => {
    process.env.REDIS_ENABLED = 'false';
    process.env.DECISION_CACHE_ENABLED = 'false';
    process.env.LOCKOUT_MAX_ATTEMPTS = '3';
    process.env.LOCKOUT_DURATION_SECONDS = '60';
    jest.resetModules();
    lockout = require('../../accountLockout');
  });

  afterEach(async () => {
    await lockout.resetFailedAttempts(user);
  });

  it('locks after max attempts', async () => {
    await lockout.incrementFailedAttempts(user);
    await lockout.incrementFailedAttempts(user);
    expect((await lockout.isLocked(user)).locked).toBe(false);
    await lockout.incrementFailedAttempts(user);
    const status = await lockout.isLocked(user);
    expect(status.locked).toBe(true);
    expect(status.remainingSeconds).toBeGreaterThan(0);
  });

  it('clears lock on reset', async () => {
    for (let i = 0; i < 5; i++) await lockout.incrementFailedAttempts(user);
    await lockout.resetFailedAttempts(user);
    expect((await lockout.isLocked(user)).locked).toBe(false);
    expect(await lockout.getFailedAttempts(user)).toBe(0);
  });
});
