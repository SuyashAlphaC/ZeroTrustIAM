'use strict';

/**
 * Validates CSRF token endpoints and guarded POST behaviour for login proxy.
 */

const request = require('supertest');
const nock = require('nock');

let appFactory;
beforeEach(() => {
  process.env.NODE_ENV = 'test';
  process.env.POLICY_ENGINE_INTERNAL_URL = 'http://127.0.0.1:40199';
  process.env.WEB_CSRF_SECURE = 'false';
  jest.resetModules();
  appFactory = require('../server.js');
});

afterEach(() => {
  nock.cleanAll();
  nock.enableNetConnect();
});

function cookieHeader(setCookie) {
  if (!Array.isArray(setCookie)) return '';
  return setCookie.map((c) => c.split(';')[0]).join('; ');
}

describe('CSRF middleware', () => {
  test('GET /api/csrf-token returns token and sets HttpOnly _csrf cookie', async () => {
    const app = appFactory.app;
    const res = await request(app).get('/api/csrf-token').expect(200);
    expect(res.body.csrfToken).toMatch(/^[A-Za-z0-9_-]{20,}$/);
    const setCookie = res.headers['set-cookie'];
    expect(setCookie.some((line) => /_csrf=/.test(line) && line.toLowerCase().includes('httponly'))).toBe(
      true
    );
  });

  test('POST /api/login missing X-CSRF-Token -> 403', async () => {
    const app = appFactory.app;
    const { body, headers } = await request(app).get('/api/csrf-token').expect(200);
    const cookie = cookieHeader(headers['set-cookie']);

    await request(app)
      .post('/api/login')
      .set('Cookie', cookie)
      .set('Content-Type', 'application/json')
      .send({ username: 'alice', password: 'x', deviceId: 'd' })
      .expect(403);
  });

  test('POST /api/login mismatched CSRF header -> 403', async () => {
    const app = appFactory.app;
    const { headers } = await request(app).get('/api/csrf-token').expect(200);
    const cookie = cookieHeader(headers['set-cookie']);

    await request(app)
      .post('/api/login')
      .set('Cookie', cookie)
      .set('X-CSRF-Token', 'wrong')
      .set('Content-Type', 'application/json')
      .send({ username: 'alice', password: 'x', deviceId: 'd' })
      .expect(403);
  });

  test('POST /api/login valid CSRF proxies to policy-engine', async () => {
    const app = appFactory.app;

    const scope = nock('http://127.0.0.1:40199').post('/evaluate').reply(200, {
      decision: 'ALLOW',
      accessToken: 'atok',
      refreshToken: 'rtok',
      txId: 't',
    });

    const { body, headers } = await request(app).get('/api/csrf-token').expect(200);
    const cookie = cookieHeader(headers['set-cookie']);

    const login = await request(app)
      .post('/api/login')
      .set('Cookie', cookie)
      .set('X-CSRF-Token', body.csrfToken)
      .set('Content-Type', 'application/json')
      .send({
        username: 'alice',
        password: 'x',
        deviceId: 'dev',
        timestamp: '2026-06-06T08:08:08.000Z',
      })
      .expect(200);

    expect(login.body.decision).toBe('ALLOW');
    expect(login.body.tokenSet).toBe(true);
    expect(login.body.accessToken).toBeUndefined();
    expect(scope.isDone()).toBe(true);
  });
});
