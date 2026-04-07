'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');

// Setup test database before requiring any app modules
const TEST_DB_DIR = path.join(os.tmpdir(), `zt-iam-api-test-${Date.now()}`);
process.env.DB_PATH = path.join(TEST_DB_DIR, 'test.db');
process.env.USE_MOCK = 'true';
process.env.SEED_DEMO = 'true';
process.env.PORT = '0'; // random available port
process.env.RATE_LIMIT_MAX = '200';
process.env.RATE_LIMIT_AUTH_MAX = '200';
process.env.LOG_LEVEL = 'silent';

const request = require('supertest');
const { app, start } = require('../../server');
const db = require('../../database');

let server;

beforeAll(async () => {
  server = start();
  // Wait for server to be ready
  await new Promise(resolve => {
    if (server.listening) return resolve();
    server.on('listening', resolve);
  });
});

afterAll(async () => {
  if (server) {
    await new Promise(resolve => server.close(resolve));
  }
  db.close();
  try {
    fs.rmSync(TEST_DB_DIR, { recursive: true, force: true });
  } catch { /* ignore */ }
});

describe('API Integration Tests', () => {
  describe('GET /health', () => {
    it('returns healthy status', async () => {
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('healthy');
      expect(res.body.blockchain).toBe('mock');
      expect(res.body.database).toBe('connected');
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
      expect(res.body.riskScore).toBeDefined();
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
      expect(res.body.reason).toContain('wrong password');
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
      expect(res.body.reason).toContain('user not found');
    });

    it('denies unregistered device via smart contract', async () => {
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
      expect(res.body.reason).toContain('Unregistered device');
    });

    it('denies high risk score (cumulative risk)', async () => {
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
      expect(res.body.riskScore).toBeGreaterThanOrEqual(0.6);
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

    it('returns ZKP proof on successful login', async () => {
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
      expect(res.body.zkProof).toBeDefined();
      expect(res.body.zkProof.proofId).toBeDefined();
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
      expect(db.isRefreshTokenValid(refreshToken)).toBe(false);
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

  describe('ZKP endpoints', () => {
    it('POST /zkp/prove creates a proof', async () => {
      const res = await request(app)
        .post('/zkp/prove')
        .send({ riskScore: 0.3, threshold: 0.6 });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.rangeProof).toBeDefined();
    });

    it('POST /zkp/prove fails when risk >= threshold', async () => {
      const res = await request(app)
        .post('/zkp/prove')
        .send({ riskScore: 0.8, threshold: 0.6 });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(false);
    });

    it('POST /zkp/verify validates a proof', async () => {
      const proveRes = await request(app)
        .post('/zkp/prove')
        .send({ riskScore: 0.2, threshold: 0.6 });
      const res = await request(app)
        .post('/zkp/verify')
        .send({ proof: proveRes.body.rangeProof });
      expect(res.status).toBe(200);
      expect(res.body.valid).toBe(true);
    });
  });

  describe('Anomaly detection endpoints', () => {
    it('GET /anomaly/profile/:username returns profile', async () => {
      const res = await request(app).get('/anomaly/profile/alice');
      expect(res.status).toBe(200);
      expect(res.body.userId).toBe('alice');
    });

    it('POST /anomaly/detect returns anomaly scores', async () => {
      const res = await request(app)
        .post('/anomaly/detect')
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
    it('GET /mfa/status/:username returns MFA status', async () => {
      const res = await request(app).get('/mfa/status/alice');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('enabled');
    });
  });

  describe('Audit log', () => {
    it('GET /audit-log returns blockchain audit entries', async () => {
      const res = await request(app).get('/audit-log');
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
    });
  });
});
