'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { createPep, PepClient } = require('../index');

function makeRs256Token(payload, { kid = 'test' } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.sign('RSA-SHA256', Buffer.from(`${header}.${body}`), privateKey).toString('base64url');
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = kid;
  jwk.use = 'sig';
  jwk.alg = 'RS256';
  return { token: `${header}.${body}.${sig}`, jwk };
}

describe('PepClient', () => {
  it('requires issuerUrl', () => {
    assert.throws(() => createPep({}), /issuerUrl/);
  });

  it('verifies a valid access token via JWKS', async () => {
    const now = Math.floor(Date.now() / 1000);
    const { token, jwk } = makeRs256Token({
      sub: 'alice', role: 'viewer', type: 'access', tid: 'default',
      iat: now, exp: now + 600, iss: 'test-iss',
    });
    const pep = createPep({
      issuerUrl: 'http://jwks.test',
      fetchImpl: async (url) => {
        if (String(url).includes('jwks')) {
          return { ok: true, json: async () => ({ keys: [jwk] }) };
        }
        throw new Error('unexpected ' + url);
      },
    });
    const claims = await pep.verifyAccessToken(token, { issuer: 'test-iss' });
    assert.equal(claims.sub, 'alice');
    assert.equal(claims.tid, 'default');
  });

  it('rejects expired tokens', async () => {
    const now = Math.floor(Date.now() / 1000);
    const { token, jwk } = makeRs256Token({
      sub: 'alice', type: 'access', iat: now - 1000, exp: now - 10,
    });
    const pep = createPep({
      issuerUrl: 'http://jwks.test',
      fetchImpl: async () => ({ ok: true, json: async () => ({ keys: [jwk] }) }),
    });
    await assert.rejects(() => pep.verifyAccessToken(token), /expired/);
  });
});
