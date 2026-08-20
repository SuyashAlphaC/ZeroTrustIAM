'use strict';

/**
 * @ztiam/pep-sdk — Policy Enforcement Point client
 *
 * Use at API gateways, microservices, or edge proxies to:
 *   1. Verify access JWTs (JWKS from policy-engine)
 *   2. Optionally re-check access grants on Fabric via policy-engine
 *   3. Enforce required permissions / roles / tenant isolation
 *
 * Framework adapters: express, generic Node (fetch), Envoy ext_authz JSON.
 */

const crypto = require('crypto');

/**
 * @typedef {object} PepOptions
 * @property {string} issuerUrl - Policy engine base URL (e.g. https://iam.example.com)
 * @property {string} [jwksPath='/oauth/.well-known/jwks.json']
 * @property {string} [verifyGrantPath='/v1/access-grants/verify']
 * @property {number} [jwksTtlMs=300000]
 * @property {string[]} [algorithms=['RS256']]
 * @property {boolean} [requireTenant=false]
 * @property {function} [fetchImpl]
 */

class PepClient {
  /**
   * @param {PepOptions} opts
   */
  constructor(opts) {
    if (!opts?.issuerUrl) throw new Error('issuerUrl is required');
    this.issuerUrl = opts.issuerUrl.replace(/\/$/, '');
    this.jwksPath = opts.jwksPath || '/oauth/.well-known/jwks.json';
    this.verifyGrantPath = opts.verifyGrantPath || '/v1/access-grants/verify';
    this.jwksTtlMs = opts.jwksTtlMs ?? 300_000;
    this.algorithms = opts.algorithms || ['RS256'];
    this.requireTenant = !!opts.requireTenant;
    this.fetchImpl = opts.fetchImpl || ((...a) => globalThis.fetch(...a));
    this._jwks = null;
    this._jwksExp = 0;
  }

  async _loadJwks(force = false) {
    if (!force && this._jwks && this._jwksExp > Date.now()) return this._jwks;
    const res = await this.fetchImpl(`${this.issuerUrl}${this.jwksPath}`);
    if (!res.ok) throw new Error(`JWKS fetch failed: HTTP ${res.status}`);
    const body = await res.json();
    this._jwks = body.keys || [];
    this._jwksExp = Date.now() + this.jwksTtlMs;
    return this._jwks;
  }

  _b64urlJson(obj) {
    return Buffer.from(JSON.stringify(obj)).toString('base64url');
  }

  /**
   * Verify RS256 JWT using JWKS.
   * @param {string} token
   * @param {{ audience?: string, issuer?: string }} [opts]
   */
  async verifyAccessToken(token, opts = {}) {
    if (!token || typeof token !== 'string') throw new Error('token required');
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('malformed JWT');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (header.alg && !this.algorithms.includes(header.alg)) {
      throw new Error(`unsupported alg ${header.alg}`);
    }
    const keys = await this._loadJwks();
    const jwk = keys.find((k) => k.kid === header.kid) || keys[0];
    if (!jwk) throw new Error('no JWKS key');
    const keyObject = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const ok = crypto.verify(
      'RSA-SHA256',
      Buffer.from(`${parts[0]}.${parts[1]}`),
      keyObject,
      Buffer.from(parts[2], 'base64url')
    );
    if (!ok) throw new Error('invalid signature');
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) throw new Error('token expired');
    if (payload.nbf && payload.nbf > now) throw new Error('token not yet valid');
    if (opts.issuer && payload.iss !== opts.issuer) throw new Error('issuer mismatch');
    if (opts.audience) {
      const aud = payload.aud;
      const okAud = Array.isArray(aud) ? aud.includes(opts.audience) : aud === opts.audience;
      if (!okAud) throw new Error('audience mismatch');
    }
    if (payload.type && payload.type !== 'access') throw new Error('not an access token');
    return payload;
  }

  /**
   * Ask policy-engine to verify an on-chain / mirrored access grant.
   */
  async verifyAccessGrant({ grantId, subject, resource, permission, bearerToken }) {
    const res = await this.fetchImpl(`${this.issuerUrl}${this.verifyGrantPath}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(bearerToken ? { Authorization: `Bearer ${bearerToken}` } : {}),
      },
      body: JSON.stringify({ grantId, subject, resource, permission }),
    });
    const body = await res.json().catch(() => ({}));
    return { httpStatus: res.status, ...body };
  }

  /**
   * Express middleware factory.
   * @param {{ roles?: string[], permission?: string, tenantHeader?: string }} [gate]
   */
  express(gate = {}) {
    const client = this;
    return async function pepMiddleware(req, res, next) {
      try {
        const hdr = req.headers.authorization || '';
        if (!hdr.startsWith('Bearer ')) {
          return res.status(401).json({ error: 'missing bearer token', code: 'PEP_NO_TOKEN' });
        }
        const token = hdr.slice(7);
        const claims = await client.verifyAccessToken(token, {
          issuer: gate.issuer,
          audience: gate.audience,
        });
        if (gate.roles?.length && !gate.roles.includes(claims.role)) {
          return res.status(403).json({ error: 'insufficient role', code: 'PEP_ROLE' });
        }
        if (client.requireTenant || gate.requireTenant) {
          const tid = claims.tid || claims.tenant_id;
          const hdrTid = req.headers['x-tenant-id'];
          if (hdrTid && tid && hdrTid !== tid && claims.role !== 'platform_admin') {
            return res.status(403).json({ error: 'tenant mismatch', code: 'PEP_TENANT' });
          }
        }
        req.user = claims;
        req.pep = { token, claims };
        next();
      } catch (err) {
        return res.status(401).json({ error: err.message || 'unauthorized', code: 'PEP_DENIED' });
      }
    };
  }

  /**
   * Envoy ext_authz compatible check from decoded request attributes.
   * @param {{ headers: Record<string,string>, path?: string }} req
   */
  async envoyCheck(req) {
    try {
      const auth = req.headers?.authorization || req.headers?.Authorization || '';
      if (!auth.startsWith('Bearer ')) {
        return { status: { code: 16 }, denied_response: { status: { code: 401 }, body: 'missing token' } };
      }
      const claims = await this.verifyAccessToken(auth.slice(7));
      return {
        status: { code: 0 },
        ok_response: {
          headers: [
            { header: { key: 'x-ztiam-sub', value: claims.sub || '' } },
            { header: { key: 'x-ztiam-role', value: claims.role || '' } },
            { header: { key: 'x-ztiam-tid', value: claims.tid || claims.tenant_id || '' } },
          ],
        },
      };
    } catch (err) {
      return {
        status: { code: 7 },
        denied_response: { status: { code: 401 }, body: err.message || 'denied' },
      };
    }
  }
}

/**
 * @param {PepOptions} opts
 */
function createPep(opts) {
  return new PepClient(opts);
}

module.exports = {
  PepClient,
  createPep,
};
