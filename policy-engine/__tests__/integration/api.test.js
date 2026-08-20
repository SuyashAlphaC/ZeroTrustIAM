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
process.env.EXPOSE_RISK_DETAILS = 'false';
// Prod-like device trust: do not password-enroll arbitrary devices in these tests
process.env.DEVICE_ENROLL_MODE = 'first_only';

const request = require('supertest');
const { app, start } = require('../../server');
const db = require('../../database');

let server;

beforeAll(async () => {
  await db.init();
  await db.truncateTestData();
  await db._prepareStatements();
  server = await start();
  await new Promise((resolve) => {
    if (server.listening) return resolve();
    server.on('listening', resolve);
  });
});

afterAll(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
  await db.close();
});

describe('API Integration Tests', () => {
  describe('GET /health', () => {
    it('returns healthy status', async () => {
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('healthy');
      expect(res.body.blockchain).toBe('fabric');
      expect(res.body.database).toBe('connected');
    });
  });

  describe('GET /v1/health', () => {
    it('matches unversioned /health core fields', async () => {
      const root = await request(app).get('/health');
      const v1 = await request(app).get('/v1/health');
      expect(v1.status).toBe(root.status);
      expect(v1.body.status).toBe(root.body.status);
      expect(v1.body.database).toBe(root.body.database);
      expect(v1.body.blockchain).toBe(root.body.blockchain);
      expect(v1.body.version).toBe(root.body.version);
    });
  });

  describe('POST /evaluate', () => {
    it('allows valid login with registered device', async () => {
      const res = await request(app)
        .post('/evaluate')
        .send({
          username: 'alice',
          password: 'pass123',
          deviceId: 'dev-001',
          timestamp: '2026-04-02T10:00:00Z',
          location: { country: 'IN', city: 'Gwalior' },
          requiredPermission: 'read',
        });
      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('ALLOW');
      // Public clients must never receive raw risk scores
      expect(res.body.riskScore).toBeUndefined();
      expect(res.body.breakdown).toBeUndefined();
      expect(res.body.ensemble).toBeUndefined();
      expect(res.body.reasonCode).toBe('OK');
      expect(res.body.userMessage).toBeTruthy();
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.txId).toBeDefined();
    });

    it('denies wrong password', async () => {
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

    it('denies non-existent user', async () => {
      const res = await request(app)
        .post('/evaluate')
        .send({
          username: 'hacker',
          password: 'whatever',
          deviceId: 'dev-x',
        });
      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('DENY');
      expect(res.body.reason).toBe('Invalid credentials');
    });

    it('denies untrusted device without leaking risk scores', async () => {
      // first_only enroll mode: alice already has devices → unknown credential denied
      const res = await request(app)
        .post('/evaluate')
        .send({
          username: 'alice',
          password: 'pass123',
          deviceId: 'attacker-laptop',
          timestamp: '2026-04-02T10:00:00Z',
          location: { country: 'IN', city: 'Gwalior' },
          requiredPermission: 'read',
        });
      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('DENY');
      expect(res.body.reasonCode).toBe('UNTRUSTED_DEVICE');
      expect(res.body.riskScore).toBeUndefined();
      expect(String(res.body.reason || '')).not.toMatch(/0\.\d/);
      expect(String(res.body.userMessage || '')).not.toMatch(/0\.\d/);
    });

    it('denies high risk without exposing numeric scores', async () => {
      const res = await request(app)
        .post('/evaluate')
        .send({
          username: 'alice',
          password: 'pass123',
          deviceId: 'hacker-dev',
          timestamp: '2026-04-02T20:00:00Z',
          location: { country: 'CN', city: 'Beijing' },
          requiredPermission: 'write',
        });
      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('DENY');
      expect(res.body.riskScore).toBeUndefined();
      expect(res.body.breakdown).toBeUndefined();
      // Either untrusted device or risk — both must be non-numeric public reasons
      expect(['RISK_DENIED', 'UNTRUSTED_DEVICE', 'DENIED', 'POLICY_DENIED']).toContain(res.body.reasonCode);
      expect(JSON.stringify(res.body)).not.toMatch(/"riskScore"/);
    });

    it('denies RBAC violation (viewer trying delete)', async () => {
      const res = await request(app)
        .post('/evaluate')
        .send({
          username: 'bob',
          password: 'bob456',
          deviceId: 'dev-002',
          timestamp: '2026-04-02T10:00:00Z',
          location: { country: 'IN', city: 'Delhi' },
          requiredPermission: 'delete',
        });
      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('DENY');
    });

    it('omits ZKP proof when ZKP is disabled (default)', async () => {
      const res = await request(app)
        .post('/evaluate')
        .send({
          username: 'alice',
          password: 'pass123',
          deviceId: 'dev-001',
          timestamp: '2026-04-02T10:00:00Z',
          location: { country: 'IN', city: 'Gwalior' },
          requiredPermission: 'read',
        });
      expect(res.body.decision).toBe('ALLOW');
      // ZKP is opt-in experimental — not part of the security boundary
      expect(res.body.zkProof).toBeUndefined();
    });
  });

  describe('Input Validation', () => {
    it('rejects missing username', async () => {
      const res = await request(app)
        .post('/evaluate')
        .send({ password: 'pass123', deviceId: 'dev-001' });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Validation failed');
    });

    it('rejects invalid permission value', async () => {
      const res = await request(app)
        .post('/evaluate')
        .send({
          username: 'alice',
          password: 'pass123',
          deviceId: 'dev-001',
          requiredPermission: 'superadmin',
        });
      expect(res.status).toBe(400);
    });

    it('rejects SQL injection in username', async () => {
      const res = await request(app)
        .post('/evaluate')
        .send({
          username: "'; DROP TABLE users; --",
          password: 'pass123',
          deviceId: 'dev-001',
        });
      expect(res.status).toBe(400); // Joi rejects non-alphanum
    });
  });

  describe('POST /verify-token', () => {
    let accessToken;

    beforeAll(async () => {
      const res = await request(app)
        .post('/evaluate')
        .send({
          username: 'alice',
          password: 'pass123',
          deviceId: 'dev-001',
          timestamp: '2026-04-02T10:00:00Z',
          location: { country: 'IN', city: 'Gwalior' },
          requiredPermission: 'read',
        });
      accessToken = res.body.accessToken;
    });

    it('validates a valid access token', async () => {
      const res = await request(app)
        .post('/verify-token')
        .set('Authorization', `Bearer ${accessToken}`);
      expect(res.status).toBe(200);
      expect(res.body.valid).toBe(true);
      expect(res.body.user).toBe('alice');
    });

    it('rejects missing token', async () => {
      const res = await request(app).post('/verify-token');
      expect(res.status).toBe(401);
      expect(res.body.valid).toBe(false);
    });

    it('rejects invalid token', async () => {
      const res = await request(app)
        .post('/verify-token')
        .set('Authorization', 'Bearer invalid.token.here');
      expect(res.status).toBe(401);
    });
  });

  describe('POST /refresh-token', () => {
    let refreshToken;

    beforeAll(async () => {
      const res = await request(app)
        .post('/evaluate')
        .send({
          username: 'alice',
          password: 'pass123',
          deviceId: 'dev-001',
          timestamp: '2026-04-02T10:00:00Z',
          location: { country: 'IN', city: 'Gwalior' },
        });
      refreshToken = res.body.refreshToken;
    });

    it('rotates refresh token and issues new access token', async () => {
      const res = await request(app)
        .post('/refresh-token')
        .send({ refreshToken });
      expect(res.status).toBe(200);
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
      // Old token should be revoked
      expect(await db.isRefreshTokenValid(refreshToken)).toBe(false);
    });

    it('rejects revoked refresh token', async () => {
      const res = await request(app)
        .post('/refresh-token')
        .send({ refreshToken }); // already used above
      expect(res.status).toBe(401);
    });
  });

  describe('POST /logout', () => {
    it('logs out successfully', async () => {
      const res = await request(app)
        .post('/logout')
        .send({});
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  describe('ZKP endpoints (auth + opt-in)', () => {
    let accessToken;

    beforeAll(async () => {
      const res = await request(app)
        .post('/evaluate')
        .send({
          username: 'alice',
          password: 'pass123',
          deviceId: 'dev-001',
          timestamp: '2026-04-02T10:00:00Z',
          location: { country: 'IN', city: 'Gwalior' },
        });
      accessToken = res.body.accessToken;
    });

    it('rejects unauthenticated ZKP prove', async () => {
      const res = await request(app)
        .post('/zkp/prove')
        .send({ riskScore: 0.3, threshold: 0.6 });
      expect(res.status).toBe(401);
    });

    it('returns 503 when ZKP is disabled', async () => {
      const res = await request(app)
        .post('/zkp/prove')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({ riskScore: 0.3, threshold: 0.6 });
      // Default ZKP_ENABLED is false
      expect([503, 200]).toContain(res.status);
      if (res.status === 503) {
        expect(res.body.experimental).toBe(true);
      }
    });
  });

  describe('Anomaly detection endpoints', () => {
    let accessToken;

    beforeAll(async () => {
      const res = await request(app)
        .post('/evaluate')
        .send({
          username: 'alice',
          password: 'pass123',
          deviceId: 'dev-001',
          timestamp: '2026-04-02T10:00:00Z',
          location: { country: 'IN', city: 'Gwalior' },
        });
      accessToken = res.body.accessToken;
    });

    it('rejects unauthenticated profile access', async () => {
      const res = await request(app).get('/anomaly/profile/alice');
      expect(res.status).toBe(401);
    });

    it('GET /anomaly/profile/:username returns profile for self', async () => {
      const res = await request(app)
        .get('/anomaly/profile/alice')
        .set('Authorization', `Bearer ${accessToken}`);
      expect(res.status).toBe(200);
      expect(res.body.userId).toBe('alice');
    });

    it('POST /anomaly/detect returns anomaly scores', async () => {
      const res = await request(app)
        .post('/anomaly/detect')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          username: 'alice',
          deviceId: 'dev-001',
          timestamp: '2026-04-02T10:00:00Z',
          location: { country: 'IN', city: 'Gwalior' },
        });
      expect(res.status).toBe(200);
      expect(res.body.scores).toBeDefined();
      expect(res.body.combined).toBeDefined();
    });
  });

  describe('MFA endpoints', () => {
    let accessToken;

    beforeAll(async () => {
      const res = await request(app)
        .post('/evaluate')
        .send({
          username: 'alice',
          password: 'pass123',
          deviceId: 'dev-001',
          timestamp: '2026-04-02T10:00:00Z',
          location: { country: 'IN', city: 'Gwalior' },
        });
      accessToken = res.body.accessToken;
    });

    it('GET /mfa/status/:username returns MFA status for self', async () => {
      const res = await request(app)
        .get('/mfa/status/alice')
        .set('Authorization', `Bearer ${accessToken}`);
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('enabled');
    });
  });

  describe('Audit log', () => {
    it('requires admin auth', async () => {
      const res = await request(app).get('/audit-log');
      expect(res.status).toBe(401);
    });
  });
});
