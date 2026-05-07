'use strict';

process.env.TEST_DATABASE_URL = process.env.TEST_DATABASE_URL
  || 'postgresql://ztiam:testpassword@127.0.0.1:5433/ztiam_test';
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

const request = require('supertest');
const { app, start } = require('../../server');
const db = require('../../database');

let server;

async function loginForRefreshToken() {
  const res = await request(app)
    .post('/evaluate')
    .send({
      username: 'alice',
      password: 'pass123',
      deviceId: 'dev-001',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Gwalior' },
    });
  expect(res.status).toBe(200);
  expect(res.body.refreshToken).toBeDefined();
  return res.body.refreshToken;
}

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
  if (server) await new Promise((resolve) => server.close(resolve));
  await db.close();
});

describe('Refresh token reuse detection', () => {
  test('happy path: refresh once → old token marked ROTATED, new token ACTIVE in same family', async () => {
    const original = await loginForRefreshToken();

    const before = await db.getRefreshTokenStatus(original);
    expect(before.status).toBe('ACTIVE');
    const familyId = before.familyId;
    expect(familyId).toBeTruthy();

    const refreshRes = await request(app)
      .post('/refresh-token')
      .send({ refreshToken: original });
    expect(refreshRes.status).toBe(200);
    const newToken = refreshRes.body.refreshToken;
    expect(newToken).toBeDefined();
    expect(newToken).not.toBe(original);

    const oldStatus = await db.getRefreshTokenStatus(original);
    expect(oldStatus.status).toBe('ROTATED');
    const newStatus = await db.getRefreshTokenStatus(newToken);
    expect(newStatus.status).toBe('ACTIVE');
    expect(newStatus.familyId).toBe(familyId);
  });

  test('replaying a rotated token compromises the entire family', async () => {
    const original = await loginForRefreshToken();
    const ok = await request(app)
      .post('/refresh-token')
      .send({ refreshToken: original });
    expect(ok.status).toBe(200);
    const newToken = ok.body.refreshToken;

    // Reuse the now-rotated original token: must trip reuse detection.
    const reuse = await request(app)
      .post('/refresh-token')
      .send({ refreshToken: original });
    expect(reuse.status).toBe(401);
    expect(reuse.body.code).toBe('REFRESH_REUSE_DETECTED');

    const familyId = (await db.getRefreshTokenStatus(original)).familyId;
    const compromisedRows = await db.getDb().query(
      "SELECT status FROM refresh_tokens WHERE family_id = $1",
      [familyId]
    );
    expect(compromisedRows.rows.length).toBeGreaterThanOrEqual(2);
    for (const row of compromisedRows.rows) {
      expect(row.status).toBe('COMPROMISED');
    }

    // The previously-valid newToken in the same family is now also unusable.
    const followUp = await request(app)
      .post('/refresh-token')
      .send({ refreshToken: newToken });
    expect(followUp.status).toBe(401);
    expect(followUp.body.code).toBe('REFRESH_REUSE_DETECTED');
  });
});
