'use strict';

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test-refresh-secret';
process.env.OAUTH_DEFAULT_CLIENT_SECRET = process.env.OAUTH_DEFAULT_CLIENT_SECRET || 'test-oauth-secret';
process.env.ML_SERVICE_URL = 'http://ml-mock.invalid';
process.env.ML_SERVICE_TIMEOUT_MS = '200';
process.env.ML_SERVICE_ENABLED = 'true';

const { scoreWithML, toRiskRequest } = require('../../mlRiskScorer');

const userProfile = {
  registeredDevices: ['dev-001'],
  usualLocation: { country: 'IN', city: 'Gwalior' },
  normalHours: [9, 18],
};
const ctx = {
  username: 'alice',
  deviceId: 'dev-001',
  timestamp: '2026-04-11T10:00:00Z',
  ip: '192.168.1.10',
  location: { country: 'IN', city: 'Gwalior' },
};

describe('toRiskRequest', () => {
  test('produces snake_case payload with defaults', () => {
    const body = toRiskRequest(userProfile, ctx, { requiredPermission: 'admin', failedAttempts: 2 });
    expect(body.username).toBe('alice');
    expect(body.user_profile.registered_devices).toEqual(['dev-001']);
    expect(body.request_context.device_id).toBe('dev-001');
    expect(body.request_context.required_permission).toBe('admin');
    expect(body.request_context.failed_attempts).toBe(2);
  });
});

describe('scoreWithML', () => {
  const origFetch = global.fetch;
  afterEach(() => { global.fetch = origFetch; });

  test('returns available=true on 200 response', async () => {
    global.fetch = jest.fn(async () => ({
      ok: true,
      json: async () => ({ risk_score: 0.82, model_version: '1.0.0', explanation: [{ feature: 'x' }] }),
    }));
    const r = await scoreWithML(userProfile, ctx);
    expect(r.available).toBe(true);
    expect(r.score).toBe(0.82);
    expect(r.modelVersion).toBe('1.0.0');
  });

  test('returns available=false on non-OK', async () => {
    global.fetch = jest.fn(async () => ({ ok: false, status: 500, text: async () => 'boom' }));
    const r = await scoreWithML(userProfile, ctx);
    expect(r.available).toBe(false);
    expect(r.error).toBe('http_500');
  });

  test('returns available=false on network error', async () => {
    global.fetch = jest.fn(async () => { throw new Error('ECONNREFUSED'); });
    const r = await scoreWithML(userProfile, ctx);
    expect(r.available).toBe(false);
    expect(r.error).toMatch(/ECONNREFUSED/);
  });
});
