'use strict';

process.env.TEST_DATABASE_URL = process.env.TEST_DATABASE_URL
  || 'postgresql://ztiam:testpassword@127.0.0.1:5432/ztiam_test';
process.env.SEED_DEMO = 'true';
process.env.PORT = '0';
process.env.NODE_ENV = 'test';
process.env.RATE_LIMIT_MAX = '200';
process.env.RATE_LIMIT_AUTH_MAX = '200';
process.env.LOG_LEVEL = 'silent';
process.env.ML_SERVICE_ENABLED = 'false';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-integration';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test-refresh-integration';
process.env.OAUTH_DEFAULT_CLIENT_SECRET = process.env.OAUTH_DEFAULT_CLIENT_SECRET || 'test-oauth-client';
process.env.REDIS_ENABLED = 'false';
process.env.ZKP_ENABLED = 'false';

const request = require('supertest');
const { app, start } = require('../../server');
const db = require('../../database');

let server;
let accessToken;

beforeAll(async () => {
  await db.init();
  await db.truncateTestData();
  await db._prepareStatements();
  server = await start();
  await new Promise((resolve) => {
    if (server.listening) return resolve();
    server.on('listening', resolve);
  });

  const login = await request(app)
    .post('/evaluate')
    .send({
      username: 'alice',
      password: 'pass123',
      deviceId: 'dev-001',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Gwalior' },
      requiredPermission: 'read',
    });
  expect(login.body.decision).toBe('ALLOW');
  accessToken = login.body.accessToken;
});

afterAll(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  await db.close();
});

describe('Self-service /me routes', () => {
  it('GET /v1/me/profile returns the subject', async () => {
    const res = await request(app)
      .get('/v1/me/profile')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(res.body.userId).toBe('alice');
  });

  it('GET /v1/me/devices lists registered devices', async () => {
    const res = await request(app)
      .get('/v1/me/devices')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.devices)).toBe(true);
    expect(res.body.devices.length).toBeGreaterThan(0);
  });

  it('GET /v1/me/sessions lists sessions', async () => {
    const res = await request(app)
      .get('/v1/me/sessions')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.sessions)).toBe(true);
  });

  it('GET /v1/me/login-history returns history', async () => {
    const res = await request(app)
      .get('/v1/me/login-history?limit=10')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.history)).toBe(true);
  });

  it('GET /v1/me/export returns GDPR archive', async () => {
    const res = await request(app)
      .get('/v1/me/export')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-disposition']).toMatch(/attachment/);
    const body = typeof res.body === 'object' && !Buffer.isBuffer(res.body)
      ? res.body
      : JSON.parse(res.text);
    expect(body.subject).toBe('alice');
    expect(body.profile).toBeDefined();
  });

  it('rejects unauthenticated /me requests', async () => {
    const res = await request(app).get('/v1/me/profile');
    expect(res.status).toBe(401);
  });

  it('rejects weak password change', async () => {
    const res = await request(app)
      .post('/v1/me/change-password')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ currentPassword: 'pass123', newPassword: 'short' });
    expect(res.status).toBe(400);
  });
});

describe('Credential anti-enumeration', () => {
  it('returns generic deny for wrong password', async () => {
    const res = await request(app)
      .post('/evaluate')
      .send({
        username: 'alice',
        password: 'wrongpassword',
        deviceId: 'dev-001',
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'IN', city: 'Gwalior' },
      });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('DENY');
    expect(res.body.reason).toBe('Invalid credentials');
  });

  it('returns generic deny for unknown user', async () => {
    const res = await request(app)
      .post('/evaluate')
      .send({
        username: 'nosuchuser',
        password: 'whatever',
        deviceId: 'dev-x',
      });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('DENY');
    expect(res.body.reason).toBe('Invalid credentials');
  });
});
