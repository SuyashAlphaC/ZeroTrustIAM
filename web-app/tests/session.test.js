'use strict';

/**
 * Validates HttpOnly cookie session behaviour and logout refresh invalidation forwarding.
 */

const request = require('supertest');
const nock = require('nock');

function loadApp(url, secure) {
  jest.resetModules();
  process.env.NODE_ENV = 'test';
  process.env.POLICY_ENGINE_INTERNAL_URL = url;
  if (secure) process.env.WEB_CSRF_SECURE = 'true';
  else delete process.env.WEB_CSRF_SECURE;
  return require('../server.js');
}

async function csrfPair(app) {
  const { body, headers } = await request(app).get('/api/csrf-token').expect(200);
  const cookie = headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');
  return { cookie, token: body.csrfToken };
}

afterEach(() => {
  nock.cleanAll();
  delete process.env.WEB_CSRF_SECURE;
});

describe('Session cookies', () => {
  test('login persists HttpOnly zt_access cookie and omits token from JSON', async () => {
    const base = 'http://127.0.0.1:40210';
    const { app } = loadApp(base, false);

    nock(base).post('/evaluate').reply(200, {
      decision: 'ALLOW',
      accessToken: 'acctoken',
      refreshToken: 'refresh',
    });

    const g = await csrfPair(app);
    const res = await request(app)
      .post('/api/login')
      .set('Cookie', g.cookie)
      .set('X-CSRF-Token', g.token)
      .set('Content-Type', 'application/json')
      .send({ u: 1 })
      .expect(200);

    expect(res.body.accessToken).toBeUndefined();
    expect(res.body.tokenSet).toBe(true);
    expect(res.headers['set-cookie'].some((c) => c.startsWith('zt_access=acctoken'))).toBe(true);
    expect(res.headers['set-cookie'].some((c) => /httponly/i.test(c))).toBe(true);

    const vt = nock(base)
      .matchHeader('authorization', /^Bearer acctoken$/)
      .post('/verify-token')
      .reply(200, { ok: true });
    const g2 = await csrfPair(app);
    await request(app)
      .post('/api/verify-token')
      .set('Cookie', `${g2.cookie}; zt_access=acctoken`)
      .set('X-CSRF-Token', g2.token)
      .expect(200);
    expect(vt.isDone()).toBe(true);
  });

  test('logout POST forwards refresh token payload to policy-engine', async () => {
    const base = 'http://127.0.0.1:40211';
    const { app } = loadApp(base, false);

    const scope = nock(base)
      .post('/logout', (body) => body.refreshToken === 'myrf')
      .reply(200, { ok: true });

    const g = await csrfPair(app);
    const res = await request(app)
      .post('/api/logout')
      .set('Cookie', `${g.cookie}; zt_refresh=myrf`)
      .set('X-CSRF-Token', g.token)
      .send({})
      .expect(200);

    expect(res.body.success).toBe(true);
    expect(scope.isDone()).toBe(true);
  });

  test('WEB_CSRF_SECURE=true yields SameSite=Lax and Secure cookies', async () => {
    const base = 'http://127.0.0.1:40212';
    const { app } = loadApp(base, true);

    nock(base).post('/evaluate').reply(200, {
      decision: 'ALLOW',
      accessToken: 'a',
      refreshToken: 'b',
    });

    const gt = await request(app).get('/api/csrf-token').expect(200);
    const csrfHdr = (gt.headers['set-cookie'] || []).join('|');
    expect(csrfHdr.toLowerCase()).toMatch(/samesite=lax/);
    expect(csrfHdr.toLowerCase()).toMatch(/secure/);

    const g = await csrfPair(app);
    const res = await request(app)
      .post('/api/login')
      .set('Cookie', g.cookie)
      .set('X-CSRF-Token', g.token)
      .set('Content-Type', 'application/json')
      .send({ k: true })
      .expect(200);

    const sess = (res.headers['set-cookie'] || []).join('|').toLowerCase();
    expect(sess).toMatch(/samesite=lax/);
    expect(sess).toMatch(/secure/);
  });
});
