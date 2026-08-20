'use strict';

const {
  validatePassword,
  hashPassword,
  verifyPassword,
} = require('../../passwordPolicy');

describe('passwordPolicy', () => {
  it('rejects short passwords', () => {
    const r = validatePassword('Short1');
    expect(r.ok).toBe(false);
    expect(r.errors.some((e) => e.includes('at least'))).toBe(true);
  });

  it('rejects passwords containing username', () => {
    const r = validatePassword('AliceSecure99', { username: 'alice' });
    expect(r.ok).toBe(false);
  });

  it('accepts a strong password', () => {
    const r = validatePassword('CorrectHorseBattery99');
    expect(r.ok).toBe(true);
  });

  it('hashes and verifies with bcrypt', async () => {
    const hash = await hashPassword('CorrectHorseBattery99');
    expect(hash.startsWith('$2')).toBe(true);
    expect(await verifyPassword('CorrectHorseBattery99', hash)).toBe(true);
    expect(await verifyPassword('wrong-password-xx', hash)).toBe(false);
  });
});
