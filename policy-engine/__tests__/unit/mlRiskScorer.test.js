'use strict';

const http = require('http');

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test-refresh-secret';
process.env.OAUTH_DEFAULT_CLIENT_SECRET = process.env.OAUTH_DEFAULT_CLIENT_SECRET || 'test-oauth-secret';
process.env.ML_SERVICE_TIMEOUT_MS = '200';
process.env.ML_SERVICE_ENABLED = 'true';
process.env.ML_SERVICE_TOKEN = 'test-ml-token';

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
    const { toRiskRequest } = require('../../mlRiskScorer');
    const body = toRiskRequest(userProfile, ctx, { requiredPermission: 'admin', failedAttempts: 2 });
    expect(body.username).toBe('alice');
    expect(body.user_profile.registered_devices).toEqual(['dev-001']);
    expect(body.request_context.device_id).toBe('dev-001');
    expect(body.request_context.required_permission).toBe('admin');
    expect(body.request_context.failed_attempts).toBe(2);
  });
});

describe('scoreWithML', () => {
  let server;
  let baseUrl;

  async function startServer(handler) {
    await new Promise((resolve) => {
      server = http.createServer(handler);
      server.listen(0, '127.0.0.1', resolve);
    });
    const { port } = server.address();
    baseUrl = `http://127.0.0.1:${port}`;
    process.env.ML_SERVICE_URL = baseUrl;
    jest.resetModules();
  }

  afterEach(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
      server = null;
    }
  });

  test('returns available=true on 200 response', async () => {
    await startServer((req, res) => {
      expect(req.headers['x-ml-service-token']).toBe('test-ml-token');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        risk_score: 0.82,
        model_version: '1.0.0',
        explanation: [{ feature: 'x' }],
      }));
    });

    const { scoreWithML } = require('../../mlRiskScorer');
    const r = await scoreWithML(userProfile, ctx);
    expect(r.available).toBe(true);
    expect(r.score).toBe(0.82);
    expect(r.modelVersion).toBe('1.0.0');
  });

  test('returns available=false on non-OK', async () => {
    await startServer((req, res) => {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end('boom');
    });

    const { scoreWithML } = require('../../mlRiskScorer');
    const r = await scoreWithML(userProfile, ctx);
    expect(r.available).toBe(false);
    expect(r.error).toBe('http_500');
  });

  test('returns available=false on network error', async () => {
    process.env.ML_SERVICE_URL = 'http://127.0.0.1:1';
    jest.resetModules();
    const { scoreWithML } = require('../../mlRiskScorer');
    const r = await scoreWithML(userProfile, ctx);
    expect(r.available).toBe(false);
    expect(r.error).toBeTruthy();
  });
});
