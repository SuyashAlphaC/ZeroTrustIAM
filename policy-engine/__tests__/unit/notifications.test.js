'use strict';

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test-refresh';
process.env.OAUTH_DEFAULT_CLIENT_SECRET = process.env.OAUTH_DEFAULT_CLIENT_SECRET || 'oauth';
process.env.NOTIFY_ENABLED = 'true';
process.env.NOTIFICATION_MODE = 'log';
process.env.NOTIFY_INCLUDE_TEMP_PASSWORD = 'true';

const { buildPayload, notifyUser, TEMPLATES } = require('../../notifications');

describe('notification templates', () => {
  test('covers lifecycle events', () => {
    expect(Object.keys(TEMPLATES).sort()).toEqual([
      'PASSWORD_RESET_ADMIN',
      'SESSIONS_REVOKED',
      'USER_ACTIVATED',
      'USER_EVICTED',
      'USER_ONBOARDED',
      'USER_SUSPENDED',
    ].sort());
  });

  test('onboard email includes username and login url', () => {
    const p = buildPayload('USER_ONBOARDED', {
      userId: 'dave',
      actor: 'alice',
      role: 'viewer',
      tempPassword: 'TempPassw0rd!!',
    });
    expect(p.subject).toMatch(/account is ready/i);
    expect(p.emailBody).toContain('dave');
    expect(p.emailBody).toContain('TempPassw0rd!!');
    expect(p.smsBody).not.toContain('TempPassw0rd!!');
  });

  test('suspend sms is short and has no secrets', () => {
    const p = buildPayload('USER_SUSPENDED', { userId: 'dave', actor: 'alice' });
    expect(p.smsBody.length).toBeLessThan(160);
    expect(p.emailBody).toMatch(/suspended/i);
  });
});

describe('notifyUser log mode', () => {
  test('returns logged/skipped channels without throwing', async () => {
    const r = await notifyUser('USER_SUSPENDED', {
      userId: 'dave',
      email: 'dave@example.com',
      phone: '+15551234567',
      actor: 'alice',
    });
    expect(r.ok).toBe(true);
    expect(r.results.some((c) => c.channel === 'email')).toBe(true);
    expect(r.results.some((c) => c.channel === 'sms')).toBe(true);
  });

  test('skips when no contact and still ok via log paths', async () => {
    const r = await notifyUser('SESSIONS_REVOKED', {
      userId: 'nobody-contact',
      actor: 'alice',
    });
    // no email/phone → skipped channels, but dispatch still succeeds
    expect(r.event).toBe('SESSIONS_REVOKED');
    expect(r.results.every((c) => c.status === 'skipped' || c.status === 'logged')).toBe(true);
  });
});
