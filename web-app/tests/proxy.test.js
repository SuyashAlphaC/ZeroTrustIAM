'use strict';

/**
 * Validates policy-engine forwarding, status propagation, mTLS agents, and timeout -> 504.
 */

const fs = require('fs');
const request = require('supertest');
const nock = require('nock');

function loadApp(url) {
  jest.resetModules();
  process.env.NODE_ENV = 'test';
  process.env.WEB_CSRF_SECURE = 'false';
  process.env.POLICY_ENGINE_INTERNAL_URL = url;
  return require('../server.js');
}

async function csrfPair(app) {
  const { body, headers } = await request(app).get('/api/csrf-token').expect(200);
  const cookie = headers['set-cookie'].map((c) => c.split(';')[0]).join('; ');
  return { cookie, token: body.csrfToken };
}

afterEach(() => {
  nock.cleanAll();
  delete process.env.POLICY_FETCH_TIMEOUT_MS;
});

describe('Policy-engine proxy', () => {
  test('forwards verify-token and attaches Authorization from session cookie', async () => {
    const base = 'http://127.0.0.1:40201';
    const { app } = loadApp(base);

    const scope = nock(base)
      .matchHeader('authorization', /^Bearer sess-token$/)
      .post('/verify-token')
      .reply(200, { valid: true });

    const { cookie, token } = await csrfPair(app);
    await request(app)
      .post('/api/verify-token')
      .set('Cookie', `${cookie}; zt_access=sess-token`)
      .set('X-CSRF-Token', token)
      .expect(200);

    expect(scope.isDone()).toBe(true);
  });

  test('proxyToPolicyEngine promotes zt_access cookie to Authorization Bearer', async () => {
    const base = 'http://127.0.0.1:40204';
    const { app } = loadApp(base);

    const scope = nock(base)
      .matchHeader('authorization', /^Bearer cookie-jwt$/)
      .get('/v1/me/devices')
      .reply(200, { devices: [] });

    const { cookie } = await csrfPair(app);
    await request(app)
      .get('/api/me/devices')
      .set('Cookie', `${cookie}; zt_access=cookie-jwt`)
      .expect(200);

    expect(scope.isDone()).toBe(true);
  });

  test('propagates downstream HTTP status codes for login', async () => {
    const base = 'http://127.0.0.1:40202';
    const { app } = loadApp(base);

    nock(base).post('/evaluate').reply(401, { deny: true });
    const g1 = await csrfPair(app);
    await request(app)
      .post('/api/login')
      .set('Cookie', g1.cookie)
      .set('X-CSRF-Token', g1.token)
      .set('Content-Type', 'application/json')
      .send({ body: 'x' })
      .expect(401);

    nock(base).post('/evaluate').reply(500, { deny: true });
    const g2 = await csrfPair(app);
    await request(app)
      .post('/api/login')
      .set('Cookie', g2.cookie)
      .set('X-CSRF-Token', g2.token)
      .set('Content-Type', 'application/json')
      .send({ body: 'x' })
      .expect(500);
  });

  test('https internal URL loads mTLS certificate material via readFileSync', () => {
    const base = 'https://mtls.pe.test';
    process.env.POLICY_ENGINE_INTERNAL_URL = base;
    process.env.POLICY_ENGINE_TLS_CA_PATH = '/tmp/ca.pem';
    process.env.POLICY_ENGINE_MTLS_CERT_PATH = '/tmp/c.pem';
    process.env.POLICY_ENGINE_MTLS_KEY_PATH = '/tmp/k.pem';
    jest.resetModules();
    const { outboundPolicyAgentOptions } = require('../server.js');
    jest.spyOn(fs, 'readFileSync').mockReturnValue(Buffer.from('x'));

    const opts = outboundPolicyAgentOptions();
    expect(opts.agent).toBeDefined();
    expect(fs.readFileSync).toHaveBeenCalledTimes(3);

    jest.restoreAllMocks();
    delete process.env.POLICY_ENGINE_TLS_CA_PATH;
    delete process.env.POLICY_ENGINE_MTLS_CERT_PATH;
    delete process.env.POLICY_ENGINE_MTLS_KEY_PATH;
  });

  test('slow upstream causes 504 response', async () => {
    const base = 'http://127.0.0.1:40203';
    process.env.POLICY_FETCH_TIMEOUT_MS = '1500';
    const { app } = loadApp(base);

    nock(base).post('/evaluate').delayConnection(4000).reply(200, {});

    const g = await csrfPair(app);
    await request(app)
      .post('/api/login')
      .set('Cookie', g.cookie)
      .set('X-CSRF-Token', g.token)
      .set('Content-Type', 'application/json')
      .send({ x: 1 })
      .expect(504);
  }, 30000);
});
