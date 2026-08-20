'use strict';

/**
 * KMS-backed JWT signer (Tier A.1 — production-hardening).
 *
 * Provides a single interface with three implementations selected by the
 * KMS_BACKEND env var:
 *
 *   • 'local' (default): RS256 key stored in Postgres `signing_keys` table
 *     and decrypted into memory on use. Behaviour-compatible with the legacy
 *     code path; suitable for development and CI.
 *
 *   • 'vault': HashiCorp Vault Transit. Private key material never leaves
 *     Vault — sign/verify operations are HTTP round-trips against the
 *     Transit engine. JWKS is built from the Vault-published public key.
 *
 *   • 'aws': AWS KMS (asymmetric RSA_2048/3072 + RSASSA_PKCS1_V1_5_SHA_256).
 *     Requires AWS_KMS_KEY_ID (or alias) and standard AWS credentials.
 *
 * Public surface:
 *   async signJwt(payload, options) -> JWT string (RS256, kid set)
 *   async verifyJwt(token, options) -> decoded payload (throws on invalid)
 *   async getPublicJwks()           -> { keys: [JWK...] }  (for /.well-known/jwks.json)
 *   async rotate()                  -> creates a new key version
 *   getActiveKid()                  -> current key id (string)
 *   async selfTest()                -> sign + verify a dummy token (used at startup)
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const config = require('./config');
const db = require('./database');
const { logger } = require('./logger');

// ────────────────── helpers ──────────────────

function base64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/=+$/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64urlJson(obj) {
  return base64url(Buffer.from(JSON.stringify(obj), 'utf8'));
}

function base64urlDecode(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

function expiresInToSeconds(expiresIn) {
  if (typeof expiresIn === 'number') return expiresIn;
  if (typeof expiresIn !== 'string') return null;
  const m = /^(\d+)\s*([smhd])?$/.exec(expiresIn.trim());
  if (!m) return null;
  const n = parseInt(m[1], 10);
  switch ((m[2] || 's').toLowerCase()) {
    case 's': return n;
    case 'm': return n * 60;
    case 'h': return n * 3600;
    case 'd': return n * 86400;
    default: return n;
  }
}

function buildClaims(payload, options = {}) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iat: now, ...payload };
  if (options.issuer && claims.iss === undefined) claims.iss = options.issuer;
  if (options.audience && claims.aud === undefined) claims.aud = options.audience;
  if (options.subject && claims.sub === undefined) claims.sub = options.subject;
  if (claims.exp === undefined) {
    const seconds = expiresInToSeconds(options.expiresIn);
    if (seconds !== null && seconds !== undefined) claims.exp = now + seconds;
  }
  if (claims.jti === undefined && options.jwtid) claims.jti = options.jwtid;
  return claims;
}

function pemToJwk(publicKeyPem, kid) {
  const pubKeyObj = crypto.createPublicKey(publicKeyPem);
  const jwk = pubKeyObj.export({ format: 'jwk' });
  return { ...jwk, kid, use: 'sig', alg: 'RS256' };
}

// ────────────────── LocalSigner ──────────────────

const LOCAL_KEY_TYPE = 'access_rsa';

class LocalSigner {
  constructor() {
    this.kid = null;
    this.privateKey = null;
    this.publicKey = null;
    this.jwk = null;
    this._initPromise = null;
  }

  async _ensureInit() {
    if (this.privateKey && this.publicKey) return;
    if (!this._initPromise) this._initPromise = this._init();
    await this._initPromise;
  }

  async _init() {
    let key = await db.getActiveSigningKey(LOCAL_KEY_TYPE);
    if (!key) {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 3072,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      const kid = `local:${LOCAL_KEY_TYPE}:${Date.now()}`;
      await db.storeSigningKey(kid, LOCAL_KEY_TYPE, privateKey, publicKey, 'RS256');
      key = await db.getActiveSigningKey(LOCAL_KEY_TYPE);
    }
    this.kid = key.key_id;
    this.privateKey = key.private_key;
    this.publicKey = key.public_key;
    this.jwk = pemToJwk(this.publicKey, this.kid);
  }

  async signJwt(payload, options = {}) {
    await this._ensureInit();
    return jwt.sign(payload, this.privateKey, {
      algorithm: 'RS256',
      keyid: this.kid,
      ...options,
    });
  }

  async verifyJwt(token, options = {}) {
    await this._ensureInit();
    return jwt.verify(token, this.publicKey, {
      algorithms: ['RS256'],
      ...options,
    });
  }

  async getPublicJwks() {
    await this._ensureInit();
    return { keys: [this.jwk] };
  }

  async rotate() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 3072,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const kid = `local:${LOCAL_KEY_TYPE}:${Date.now()}`;
    await db.storeSigningKey(kid, LOCAL_KEY_TYPE, privateKey, publicKey, 'RS256');
    this.privateKey = null;
    this.publicKey = null;
    this.jwk = null;
    this._initPromise = null;
    await this._ensureInit();
    return { kid: this.kid };
  }

  getActiveKid() {
    return this.kid;
  }
}

// ────────────────── VaultTransitSigner ──────────────────

class VaultUnavailableError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'VaultUnavailableError';
    if (cause) this.cause = cause;
  }
}

class VaultTransitSigner {
  /**
   * @param {{addr?: string, token?: string, keyName?: string, timeoutMs?: number, fetchImpl?: typeof fetch}} [opts]
   */
  constructor(opts = {}) {
    this.addr = (opts.addr || config.vaultAddr || '').replace(/\/$/, '');
    this.token = opts.token || config.vaultToken || '';
    this.keyName = opts.keyName || config.vaultTransitKeyName;
    this.timeoutMs = opts.timeoutMs || config.vaultTimeoutMs || 3000;
    this.fetchImpl = opts.fetchImpl || ((...a) => globalThis.fetch(...a));
    this._publicKeyCache = null; // { version: number, pem: string, kid: string, jwk: any, allKeys: Map }
    this._initPromise = null;
  }

  async _vaultFetch(method, path, body) {
    if (!this.addr) throw new VaultUnavailableError('VAULT_ADDR is not configured');
    if (!this.token) throw new VaultUnavailableError('VAULT_TOKEN is not configured');
    const url = `${this.addr}/v1/${path.replace(/^\//, '')}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(url, {
        method,
        headers: {
          'X-Vault-Token': this.token,
          'Content-Type': 'application/json',
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
      const text = await res.text();
      if (!res.ok) {
        throw new VaultUnavailableError(
          `Vault ${method} ${path} failed: HTTP ${res.status} ${text || res.statusText}`
        );
      }
      return text ? JSON.parse(text) : {};
    } catch (err) {
      if (err instanceof VaultUnavailableError) throw err;
      throw new VaultUnavailableError(`Vault ${method} ${path} failed: ${err.message}`, err);
    } finally {
      clearTimeout(timer);
    }
  }

  async _ensureKey() {
    if (this._publicKeyCache) return;
    if (!this._initPromise) this._initPromise = this._init();
    try {
      await this._initPromise;
    } finally {
      this._initPromise = null;
    }
  }

  async _init() {
    // Create the key if it does not exist (idempotent — Vault returns 204 either way).
    try {
      await this._vaultFetch('POST', `transit/keys/${encodeURIComponent(this.keyName)}`, {
        type: 'rsa-3072',
        derived: false,
        exportable: false,
        allow_plaintext_backup: false,
      });
    } catch (err) {
      // If the key already exists, Vault may 400 — we tolerate that and re-read.
      logger.debug({ err: err.message }, 'Vault transit key create returned non-success (may already exist)');
    }
    await this._refreshKey();
  }

  async _refreshKey() {
    const meta = await this._vaultFetch('GET', `transit/keys/${encodeURIComponent(this.keyName)}`);
    const data = meta && meta.data ? meta.data : {};
    const latest = data.latest_version || (data.keys && Math.max(...Object.keys(data.keys).map(Number))) || 1;
    const allKeys = new Map();
    if (data.keys && typeof data.keys === 'object') {
      for (const [version, info] of Object.entries(data.keys)) {
        const pem = info && info.public_key ? info.public_key : null;
        if (pem) {
          const kid = `vault:${this.keyName}:v${version}`;
          allKeys.set(String(version), { pem, kid, jwk: pemToJwk(pem, kid) });
        }
      }
    }
    const latestEntry = allKeys.get(String(latest));
    if (!latestEntry) {
      throw new VaultUnavailableError(`Vault transit key "${this.keyName}" has no public key material`);
    }
    this._publicKeyCache = {
      version: latest,
      pem: latestEntry.pem,
      kid: latestEntry.kid,
      jwk: latestEntry.jwk,
      allKeys,
    };
  }

  _kidToVersion(kid) {
    const m = /^vault:[^:]+:v(\d+)$/.exec(kid || '');
    return m ? m[1] : null;
  }

  async signJwt(payload, options = {}) {
    await this._ensureKey();
    const claims = buildClaims(payload, options);
    const header = { alg: 'RS256', typ: 'JWT', kid: this._publicKeyCache.kid };
    const signingInput = `${base64urlJson(header)}.${base64urlJson(claims)}`;
    const inputB64 = Buffer.from(signingInput, 'utf8').toString('base64');
    const result = await this._vaultFetch(
      'POST',
      `transit/sign/${encodeURIComponent(this.keyName)}/sha2-256`,
      {
        input: inputB64,
        prehashed: false,
        signature_algorithm: 'pkcs1v15',
        marshaling_algorithm: 'jws',
      }
    );
    const sigField = result && result.data && result.data.signature;
    if (!sigField || typeof sigField !== 'string') {
      throw new VaultUnavailableError('Vault sign response missing signature');
    }
    // Vault returns "vault:vN:<base64sig>" — pull off the suffix.
    const parts = sigField.split(':');
    const sigPart = parts[parts.length - 1];
    const sigB64u = sigPart
      .replace(/=+$/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
    return `${signingInput}.${sigB64u}`;
  }

  async verifyJwt(token, options = {}) {
    await this._ensureKey();
    const segments = String(token || '').split('.');
    if (segments.length !== 3) throw new Error('jwt malformed');
    const [headerB64u, payloadB64u, sigB64u] = segments;
    let header;
    let payload;
    try {
      header = JSON.parse(base64urlDecode(headerB64u).toString('utf8'));
      payload = JSON.parse(base64urlDecode(payloadB64u).toString('utf8'));
    } catch (err) {
      throw new Error('jwt malformed');
    }
    if (header.alg !== 'RS256') throw new Error(`Unexpected alg ${header.alg}`);
    const version = this._kidToVersion(header.kid) || String(this._publicKeyCache.version);
    const signingInput = `${headerB64u}.${payloadB64u}`;
    const inputB64 = Buffer.from(signingInput, 'utf8').toString('base64');
    // Vault verify expects its own signature envelope.
    const sigStd = sigB64u.replace(/-/g, '+').replace(/_/g, '/');
    const sigField = `vault:v${version}:${sigStd}`;
    const result = await this._vaultFetch(
      'POST',
      `transit/verify/${encodeURIComponent(this.keyName)}/sha2-256`,
      {
        input: inputB64,
        signature: sigField,
        prehashed: false,
        signature_algorithm: 'pkcs1v15',
        marshaling_algorithm: 'jws',
      }
    );
    const valid = !!(result && result.data && result.data.valid);
    if (!valid) throw new Error('invalid signature');
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp === 'number' && now >= payload.exp) {
      const err = new Error('jwt expired');
      err.name = 'TokenExpiredError';
      throw err;
    }
    if (typeof payload.nbf === 'number' && now < payload.nbf) {
      throw new Error('jwt not active');
    }
    if (options.issuer && payload.iss !== options.issuer) {
      throw new Error(`jwt issuer invalid (expected ${options.issuer})`);
    }
    if (options.audience) {
      const expected = Array.isArray(options.audience) ? options.audience : [options.audience];
      const actual = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!expected.some((a) => actual.includes(a))) {
        throw new Error('jwt audience invalid');
      }
    }
    return payload;
  }

  async getPublicJwks() {
    await this._ensureKey();
    return { keys: Array.from(this._publicKeyCache.allKeys.values()).map((v) => v.jwk) };
  }

  async rotate() {
    await this._vaultFetch('POST', `transit/keys/${encodeURIComponent(this.keyName)}/rotate`, {});
    this._publicKeyCache = null;
    await this._ensureKey();
    return { kid: this._publicKeyCache.kid };
  }

  getActiveKid() {
    return this._publicKeyCache ? this._publicKeyCache.kid : null;
  }
}

// ────────────────── AwsKmsSigner ──────────────────

class AwsKmsSigner {
  /**
   * Signs JWTs with an asymmetric CMK in AWS KMS. Private key never leaves KMS.
   *
   * Env:
   *   AWS_KMS_KEY_ID     — key id, ARN, or alias/xxx
   *   AWS_REGION         — region (default us-east-1)
   *   AWS_KMS_KEY_SPEC   — RSA_2048 | RSA_3072 | RSA_4096 (informational)
   * Optional per-tenant override via constructor opts.keyId (CMK).
   */
  constructor(opts = {}) {
    this.keyId = opts.keyId || process.env.AWS_KMS_KEY_ID || process.env.AWS_KMS_KEY_ARN || '';
    this.region = opts.region || process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1';
    this.kid = opts.kid || (this.keyId ? `aws-kms:${this.keyId.split('/').pop()}` : null);
    this._client = null;
    this._publicPem = null;
    this._jwk = null;
    this._initPromise = null;
  }

  _getClient() {
    if (this._client) return this._client;
    // Lazy require so local/vault backends do not need the SDK installed path at load
    // eslint-disable-next-line global-require
    const { KMSClient } = require('@aws-sdk/client-kms');
    this._client = new KMSClient({ region: this.region });
    return this._client;
  }

  async _ensurePublic() {
    if (this._publicPem) return;
    if (!this._initPromise) {
      this._initPromise = (async () => {
        if (!this.keyId) throw new Error('AWS_KMS_KEY_ID is required when KMS_BACKEND=aws');
        // eslint-disable-next-line global-require
        const { GetPublicKeyCommand } = require('@aws-sdk/client-kms');
        const client = this._getClient();
        const out = await client.send(new GetPublicKeyCommand({ KeyId: this.keyId }));
        // PublicKey is DER SPKI
        const der = Buffer.from(out.PublicKey);
        const pub = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
        this._publicPem = pub.export({ type: 'spki', format: 'pem' });
        this._jwk = pemToJwk(this._publicPem, this.kid);
        if (out.KeyId) this.kid = `aws-kms:${String(out.KeyId).split('/').pop()}`;
        this._jwk.kid = this.kid;
        logger.info({ kid: this.kid, keyId: this.keyId }, 'AWS KMS public key loaded');
      })();
    }
    await this._initPromise;
  }

  async signJwt(payload, options = {}) {
    await this._ensurePublic();
    const claims = buildClaims(payload, options);
    const header = { alg: 'RS256', typ: 'JWT', kid: this.kid };
    const signingInput = `${base64urlJson(header)}.${base64urlJson(claims)}`;

    // eslint-disable-next-line global-require
    const { SignCommand } = require('@aws-sdk/client-kms');
    const client = this._getClient();
    const out = await client.send(new SignCommand({
      KeyId: this.keyId,
      Message: Buffer.from(signingInput, 'utf8'),
      MessageType: 'RAW',
      SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
    }));
    const sig = base64url(Buffer.from(out.Signature));
    return `${signingInput}.${sig}`;
  }

  async verifyJwt(token, options = {}) {
    await this._ensurePublic();
    return jwt.verify(token, this._publicPem, {
      algorithms: ['RS256'],
      ...options,
    });
  }

  async getPublicJwks() {
    await this._ensurePublic();
    return { keys: [this._jwk] };
  }

  /**
   * AWS KMS asymmetric keys are not rotated in-place the same way as symmetric.
   * Rotation = create new key version / new CMK and update AWS_KMS_KEY_ID.
   * This method refreshes the cached public key for the configured KeyId.
   */
  async rotate() {
    this._publicPem = null;
    this._jwk = null;
    this._initPromise = null;
    await this._ensurePublic();
    return { kid: this.kid, keyId: this.keyId, note: 'Refreshed public key; create a new CMK in AWS to rotate material' };
  }

  getActiveKid() {
    return this.kid;
  }
}

/**
 * Tenant CMK signer factory — uses tenant-specific key ARN when provided.
 * @param {string} keyId
 */
function createAwsTenantSigner(keyId) {
  return new AwsKmsSigner({ keyId, kid: `aws-kms-tenant:${String(keyId).split('/').pop()}` });
}

// ────────────────── Selector / module API ──────────────────

let activeInstance = null;

function createSigner(backend) {
  switch ((backend || 'local').toLowerCase()) {
    case 'vault':
      return new VaultTransitSigner();
    case 'aws':
    case 'aws-kms':
    case 'awskms':
      return new AwsKmsSigner();
    case 'local':
    default:
      return new LocalSigner();
  }
}

/** Returns the current process-wide signer (singleton). */
function getSigner() {
  if (!activeInstance) activeInstance = createSigner(config.kmsBackend);
  return activeInstance;
}

/** Test/admin hook: replace the singleton (used by selfTest re-init and unit tests). */
function _setSigner(instance) {
  activeInstance = instance || null;
}

async function signJwt(payload, options) {
  return getSigner().signJwt(payload, options);
}

async function verifyJwt(token, options) {
  return getSigner().verifyJwt(token, options);
}

async function getPublicJwks() {
  return getSigner().getPublicJwks();
}

async function rotate() {
  return getSigner().rotate();
}

function getActiveKid() {
  return getSigner().getActiveKid();
}

/**
 * Sign + verify a dummy token end-to-end. Run at startup when KMS_BACKEND=vault
 * so we fail fast (exit 1) rather than blocking real authentication later.
 */
async function selfTest() {
  const probe = { sub: '__kms_self_test__', purpose: 'startup-check' };
  const token = await signJwt(probe, { expiresIn: '60s' });
  const decoded = await verifyJwt(token);
  if (!decoded || decoded.sub !== probe.sub) {
    throw new Error('KMS self-test: round-trip payload mismatch');
  }
  return true;
}

module.exports = {
  signJwt,
  verifyJwt,
  getPublicJwks,
  rotate,
  getActiveKid,
  selfTest,
  getSigner,
  createSigner,
  createAwsTenantSigner,
  _setSigner,
  LocalSigner,
  VaultTransitSigner,
  AwsKmsSigner,
  VaultUnavailableError,
};
