'use strict';

const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const { encryptSecret, decryptSecret } = require('./secrets');

/** @type {import('pg').Pool|null} */
let pool = null;

function getConnectionString() {
  const url = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL || '';
  if (!url) {
    throw new Error('Set DATABASE_URL (or TEST_DATABASE_URL in tests). PostgreSQL is required.');
  }
  return url;
}

const MIGRATIONS = [{
  name: '001_initial',
  /** @param {import('pg').PoolClient} client */
  up: async (client) => {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        usual_country TEXT NOT NULL DEFAULT 'UNKNOWN',
        usual_city TEXT NOT NULL DEFAULT 'UNKNOWN',
        normal_hours_start INTEGER NOT NULL DEFAULT 9,
        normal_hours_end INTEGER NOT NULL DEFAULT 17,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        did TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS devices (
        id SERIAL PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        device_id TEXT NOT NULL,
        label TEXT,
        registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(user_id, device_id)
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        revoked SMALLINT NOT NULL DEFAULT 0
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS mfa_secrets (
        user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
        secret TEXT NOT NULL,
        enabled SMALLINT NOT NULL DEFAULT 1,
        enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS mfa_challenges (
        challenge_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        context JSONB NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        verified SMALLINT NOT NULL DEFAULT 0
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS oauth_codes (
        code TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        scope TEXT NOT NULL DEFAULT 'openid',
        nonce TEXT,
        expires_at TIMESTAMPTZ NOT NULL,
        used SMALLINT NOT NULL DEFAULT 0
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY,
        client_secret TEXT NOT NULL,
        redirect_uris JSONB NOT NULL,
        grant_types JSONB NOT NULL,
        scope TEXT NOT NULL DEFAULT 'openid profile email'
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS did_documents (
        did TEXT PRIMARY KEY,
        user_id TEXT,
        document_json JSONB NOT NULL,
        private_key TEXT,
        deactivated SMALLINT NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS verifiable_credentials (
        credential_id TEXT PRIMARY KEY,
        issuer_did TEXT NOT NULL,
        subject_did TEXT NOT NULL,
        credential_json JSONB NOT NULL,
        issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS login_history (
        id SERIAL PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        device_id TEXT,
        country TEXT,
        city TEXT,
        timestamp TIMESTAMPTZ NOT NULL,
        risk_score DOUBLE PRECISION,
        decision TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS anomaly_profiles (
        user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
        login_hours_mean DOUBLE PRECISION NOT NULL DEFAULT 12,
        login_hours_std DOUBLE PRECISION NOT NULL DEFAULT 4,
        login_hours_samples INTEGER NOT NULL DEFAULT 0,
        known_locations JSONB NOT NULL DEFAULT '[]'::jsonb,
        known_devices JSONB NOT NULL DEFAULT '[]'::jsonb,
        last_login_json JSONB,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS signing_keys (
        key_id TEXT PRIMARY KEY,
        key_type TEXT NOT NULL,
        public_key TEXT,
        private_key TEXT NOT NULL,
        algorithm TEXT NOT NULL DEFAULT 'HS256',
        active SMALLINT NOT NULL DEFAULT 1,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        rotated_at TIMESTAMPTZ
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS local_audit_log (
        id SERIAL PRIMARY KEY,
        tx_id TEXT,
        user_id TEXT,
        device_id TEXT,
        risk_score DOUBLE PRECISION,
        decision TEXT,
        reason TEXT,
        layer TEXT,
        metadata JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS policy_public_params (
        policy_id TEXT PRIMARY KEY,
        params_json JSONB NOT NULL,
        active SMALLINT NOT NULL DEFAULT 1,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS access_grants (
        grant_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        device_id TEXT,
        resource TEXT NOT NULL,
        permission TEXT NOT NULL,
        issuing_tx_id TEXT,
        policy_id TEXT,
        policy_version TEXT,
        model_version TEXT,
        proof_id TEXT,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked SMALLINT NOT NULL DEFAULT 0,
        grant_data JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id SERIAL PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        credential_id TEXT NOT NULL,
        public_key BYTEA NOT NULL,
        counter INTEGER NOT NULL DEFAULT 0,
        transports JSONB NOT NULL DEFAULT '[]'::jsonb,
        registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(user_id, credential_id)
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS webauthn_challenges (
        challenge_key TEXT PRIMARY KEY,
        challenge TEXT NOT NULL,
        user_id TEXT NOT NULL,
        type TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL
      )
    `);

    await client.query('CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_refresh_token_expires ON refresh_tokens(token, expires_at)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_mfa_challenges_lookup ON mfa_challenges(challenge_id, expires_at)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_anomaly_profiles_user ON anomaly_profiles(user_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_local_audit_user_created ON local_audit_log(user_id, created_at)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_access_grants_lookup ON access_grants(grant_id, user_id, expires_at)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_login_history_timestamp ON login_history(timestamp)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON oauth_codes(expires_at)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires ON webauthn_challenges(expires_at)');
  },
}];

async function init() {
  if (pool) return pool;
  pool = new Pool({ connectionString: getConnectionString(), max: 20 });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    const { rows: appliedRows } = await client.query('SELECT name FROM schema_migrations');
    const applied = new Set(appliedRows.map((r) => r.name));
    for (const m of MIGRATIONS) {
      if (applied.has(m.name)) continue;
      await m.up(client);
      await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [m.name]);
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
  return pool;
}

// ──────────────────────── Users ────────────────────────

async function getUser(userId) {
  const { rows: [row] } = await pool.query('SELECT * FROM users WHERE user_id = $1', [userId]);
  if (!row) return null;
  const { rows: devices } = await pool.query('SELECT device_id FROM devices WHERE user_id = $1', [userId]);
  return {
    userId: row.user_id,
    passwordHash: row.password_hash,
    role: row.role,
    registeredDevices: devices.map((d) => d.device_id),
    usualLocation: { country: row.usual_country, city: row.usual_city },
    normalHours: [row.normal_hours_start, row.normal_hours_end],
    status: row.status,
    did: row.did,
    createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
  };
}

async function createUser({ userId, password, role, usualCountry, usualCity, normalHoursStart, normalHoursEnd, devices }) {
  const config = require('./config');
  const passwordHash = bcrypt.hashSync(password, config.bcryptRounds);
  await pool.query(`
    INSERT INTO users (user_id, password_hash, role, usual_country, usual_city, normal_hours_start, normal_hours_end, status)
    VALUES ($1,$2,$3,$4,$5,$6,$7,'ACTIVE')
  `, [userId, passwordHash, role || 'viewer', usualCountry || 'UNKNOWN', usualCity || 'UNKNOWN', normalHoursStart || 9, normalHoursEnd || 17]);
  if (devices?.length > 0) {
    for (const deviceId of devices) {
      await pool.query(
        'INSERT INTO devices (user_id, device_id) VALUES ($1, $2) ON CONFLICT (user_id, device_id) DO NOTHING',
        [userId, deviceId]
      );
    }
  }
}

async function getAllUsers() {
  const { rows } = await pool.query('SELECT user_id, role, status, did, created_at FROM users');
  return rows.map((row) => ({
    ...row,
    created_at: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
  }));
}

async function registerDevice(userId, deviceId, label) {
  await pool.query(
    'INSERT INTO devices (user_id, device_id, label) VALUES ($1, $2, $3) ON CONFLICT (user_id, device_id) DO NOTHING',
    [userId, deviceId, label ?? null]
  );
}

async function getUserDevices(userId) {
  const { rows } = await pool.query('SELECT device_id, label, registered_at FROM devices WHERE user_id = $1', [userId]);
  return rows;
}

async function storeRefreshToken(token, userId, expiresAt) {
  await pool.query('INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)', [token, userId, expiresAt]);
}

async function isRefreshTokenValid(token) {
  const { rows: [row] } = await pool.query(
    'SELECT * FROM refresh_tokens WHERE token = $1 AND revoked = 0 AND expires_at > NOW()',
    [token]
  );
  return !!row;
}

async function revokeRefreshToken(token) {
  await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE token = $1', [token]);
}

async function revokeAllUserTokens(userId) {
  await pool.query('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = $1', [userId]);
}

async function cleanExpiredTokens() {
  const r = await pool.query("DELETE FROM refresh_tokens WHERE expires_at < NOW() OR revoked = 1");
  return r.rowCount ?? 0;
}

async function storeMFASecret(userId, secret) {
  await pool.query(`
    INSERT INTO mfa_secrets (user_id, secret, enabled, enrolled_at) VALUES ($1, $2, 1, NOW())
    ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, enabled = 1, enrolled_at = NOW()
  `, [userId, encryptSecret(secret)]);
}

async function getMFASecret(userId) {
  const { rows: [row] } = await pool.query('SELECT * FROM mfa_secrets WHERE user_id = $1', [userId]);
  if (!row) return null;
  return { ...row, secret: decryptSecret(row.secret) };
}

async function storeMFAChallenge(challengeId, userId, context, expiresAt) {
  await pool.query(
    'INSERT INTO mfa_challenges (challenge_id, user_id, context, expires_at) VALUES ($1, $2, $3::jsonb, $4)',
    [challengeId, userId, JSON.stringify(context), expiresAt]
  );
}

async function getMFAChallenge(challengeId) {
  const { rows: [row] } = await pool.query(
    'SELECT * FROM mfa_challenges WHERE challenge_id = $1 AND verified = 0 AND expires_at > NOW()',
    [challengeId]
  );
  if (!row) return null;
  const ctx = typeof row.context === 'object' && row.context !== null ? row.context : JSON.parse(String(row.context));
  return { ...row, context: ctx };
}

async function deleteMFAChallenge(challengeId) {
  await pool.query('DELETE FROM mfa_challenges WHERE challenge_id = $1', [challengeId]);
}

async function cleanExpiredChallenges() {
  const r = await pool.query('DELETE FROM mfa_challenges WHERE expires_at < NOW()');
  return r.rowCount ?? 0;
}

async function storeOAuthCode(code, userId, clientId, redirectUri, scope, nonce, expiresAt) {
  await pool.query(
    `INSERT INTO oauth_codes (code, user_id, client_id, redirect_uri, scope, nonce, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [code, userId, clientId, redirectUri, scope, nonce, expiresAt]
  );
}

async function consumeOAuthCode(code) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [row] } = await client.query(
      'SELECT * FROM oauth_codes WHERE code = $1 AND used = 0 AND expires_at > NOW()',
      [code]
    );
    if (!row) {
      await client.query('ROLLBACK');
      return null;
    }
    await client.query('UPDATE oauth_codes SET used = 1 WHERE code = $1', [code]);
    await client.query('COMMIT');
    return row;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

async function storeOAuthClient(clientId, clientSecret, redirectUris, grantTypes, scope) {
  await pool.query(`
    INSERT INTO oauth_clients (client_id, client_secret, redirect_uris, grant_types, scope)
    VALUES ($1, $2, $3::jsonb, $4::jsonb, $5)
    ON CONFLICT (client_id) DO UPDATE SET client_secret = EXCLUDED.client_secret,
      redirect_uris = EXCLUDED.redirect_uris, grant_types = EXCLUDED.grant_types, scope = EXCLUDED.scope
  `, [clientId, clientSecret, JSON.stringify(redirectUris), JSON.stringify(grantTypes), scope]);
}

async function getOAuthClient(clientId) {
  const { rows: [row] } = await pool.query('SELECT * FROM oauth_clients WHERE client_id = $1', [clientId]);
  if (!row) return null;
  return {
    clientId: row.client_id,
    clientSecret: row.client_secret,
    redirectUris: typeof row.redirect_uris === 'object' ? row.redirect_uris : JSON.parse(row.redirect_uris),
    grantTypes: typeof row.grant_types === 'object' ? row.grant_types : JSON.parse(row.grant_types),
    scope: row.scope,
  };
}

async function cleanExpiredOAuthCodes() {
  const r = await pool.query('DELETE FROM oauth_codes WHERE expires_at < NOW() OR used = 1');
  return r.rowCount ?? 0;
}

async function storeDID(did, userId, documentJson, privateKey) {
  await pool.query(`
    INSERT INTO did_documents (did, user_id, document_json, private_key, updated_at)
    VALUES ($1, $2, $3::jsonb, $4, NOW())
    ON CONFLICT (did) DO UPDATE SET user_id = EXCLUDED.user_id, document_json = EXCLUDED.document_json,
      private_key = EXCLUDED.private_key, updated_at = NOW()
  `, [did, userId, JSON.stringify(documentJson), privateKey ? encryptSecret(privateKey) : null]);
  if (userId) {
    await pool.query('UPDATE users SET did = $1, updated_at = NOW() WHERE user_id = $2', [did, userId]);
  }
}

async function getDID(did) {
  const { rows: [row] } = await pool.query('SELECT * FROM did_documents WHERE did = $1', [did]);
  if (!row) return null;
  const doc = typeof row.document_json === 'object' ? row.document_json : JSON.parse(row.document_json);
  return {
    did: row.did,
    userId: row.user_id,
    document: doc,
    privateKey: decryptSecret(row.private_key),
    deactivated: !!row.deactivated,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function getAllDIDs() {
  return (await pool.query('SELECT did, user_id, deactivated, created_at FROM did_documents')).rows;
}

async function deactivateDID(did) {
  await pool.query('UPDATE did_documents SET deactivated = 1, updated_at = NOW() WHERE did = $1', [did]);
}

async function storeVC(credentialId, issuerDid, subjectDid, credentialJson) {
  await pool.query(`
    INSERT INTO verifiable_credentials (credential_id, issuer_did, subject_did, credential_json)
    VALUES ($1, $2, $3, $4::jsonb)
    ON CONFLICT (credential_id) DO UPDATE SET issuer_did = EXCLUDED.issuer_did,
      subject_did = EXCLUDED.subject_did, credential_json = EXCLUDED.credential_json
  `, [credentialId, issuerDid, subjectDid, JSON.stringify(credentialJson)]);
}

async function getVC(credentialId) {
  const { rows: [row] } = await pool.query('SELECT * FROM verifiable_credentials WHERE credential_id = $1', [credentialId]);
  if (!row) return null;
  const cred = typeof row.credential_json === 'object' ? row.credential_json : JSON.parse(row.credential_json);
  return { ...row, credential: cred };
}

async function recordLoginHistory(userId, deviceId, country, city, timestamp, riskScore, decision) {
  await pool.query(
    `INSERT INTO login_history (user_id, device_id, country, city, timestamp, risk_score, decision)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [userId, deviceId, country, city, timestamp, riskScore, decision]
  );
}

async function getRecentLogins(userId, limitMinutes) {
  const cutoff = new Date(Date.now() - limitMinutes * 60 * 1000).toISOString();
  const { rows } = await pool.query(
    'SELECT * FROM login_history WHERE user_id = $1 AND timestamp > $2 ORDER BY timestamp DESC',
    [userId, cutoff]
  );
  return rows;
}

async function getLoginHistory(userId, limit) {
  const { rows } = await pool.query(
    'SELECT * FROM login_history WHERE user_id = $1 ORDER BY timestamp DESC LIMIT $2',
    [userId, limit || 100]
  );
  return rows;
}

async function getAnomalyProfile(userId) {
  let { rows: [row] } = await pool.query('SELECT * FROM anomaly_profiles WHERE user_id = $1', [userId]);
  if (!row) {
    await pool.query(
      'INSERT INTO anomaly_profiles (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING',
      [userId]
    );
    ({ rows: [row] } = await pool.query('SELECT * FROM anomaly_profiles WHERE user_id = $1', [userId]));
  }
  const loc = typeof row.known_locations === 'object' ? row.known_locations : JSON.parse(row.known_locations || '[]');
  const dev = typeof row.known_devices === 'object' ? row.known_devices : JSON.parse(row.known_devices || '[]');
  let lastLogin = null;
  if (row.last_login_json) {
    lastLogin = typeof row.last_login_json === 'object' ? row.last_login_json : JSON.parse(JSON.stringify(row.last_login_json));
  }
  return {
    userId: row.user_id,
    loginHours: { mean: row.login_hours_mean, std: row.login_hours_std, samples: row.login_hours_samples },
    knownLocations: loc,
    knownDevices: dev,
    lastLogin,
  };
}

async function updateAnomalyProfile(userId, profile) {
  await pool.query(`
    UPDATE anomaly_profiles SET
      login_hours_mean = $1, login_hours_std = $2, login_hours_samples = $3,
      known_locations = $4::jsonb, known_devices = $5::jsonb, last_login_json = $6::jsonb,
      updated_at = NOW()
    WHERE user_id = $7
  `, [
    profile.loginHours.mean,
    profile.loginHours.std,
    profile.loginHours.samples,
    JSON.stringify(profile.knownLocations),
    JSON.stringify(profile.knownDevices),
    profile.lastLogin ? JSON.stringify(profile.lastLogin) : null,
    userId,
  ]);
}

async function storeSigningKey(keyId, keyType, privateKey, publicKey, algorithm) {
  const enc = encryptSecret(privateKey);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE signing_keys SET active = 0 WHERE key_type = $1', [keyType]);
    await client.query(`
      INSERT INTO signing_keys (key_id, key_type, private_key, public_key, algorithm, active)
      VALUES ($1, $2, $3, $4, $5, 1)
      ON CONFLICT (key_id) DO UPDATE SET key_type = EXCLUDED.key_type, private_key = EXCLUDED.private_key,
        public_key = EXCLUDED.public_key, algorithm = EXCLUDED.algorithm, active = 1
    `, [keyId, keyType, enc, publicKey || null, algorithm]);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

async function getActiveSigningKey(keyType) {
  const { rows: [row] } = await pool.query(
    'SELECT * FROM signing_keys WHERE key_type = $1 AND active = 1 ORDER BY created_at DESC LIMIT 1',
    [keyType]
  );
  return row ? { ...row, private_key: decryptSecret(row.private_key) } : null;
}

async function rotateSigningKey(keyType) {
  await pool.query(
    "UPDATE signing_keys SET active = 0, rotated_at = NOW() WHERE key_type = $1 AND active = 1",
    [keyType]
  );
}

async function writeAuditLog(entry) {
  await pool.query(
    `INSERT INTO local_audit_log (tx_id, user_id, device_id, risk_score, decision, reason, layer, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
    [
      entry.txId,
      entry.userId,
      entry.deviceId,
      entry.riskScore,
      entry.decision,
      entry.reason,
      entry.layer,
      entry.metadata ? JSON.stringify(entry.metadata) : null,
    ]
  );
}

async function queryAuditLog({ userId, decision, limit, offset } = {}) {
  let sql = 'SELECT * FROM local_audit_log WHERE 1=1';
  const params = [];
  let i = 1;
  if (userId) {
    sql += ` AND user_id = $${i++}`;
    params.push(userId);
  }
  if (decision) {
    sql += ` AND decision = $${i++}`;
    params.push(decision);
  }
  sql += ` ORDER BY created_at DESC LIMIT $${i++} OFFSET $${i++}`;
  params.push(limit || 100, offset || 0);
  const { rows } = await pool.query(sql, params);
  return rows;
}

async function storePolicyPublicParams(params) {
  const policyId = params.policyId || 'zt-iam-policy-v1';
  await pool.query(`
    INSERT INTO policy_public_params (policy_id, params_json, active, updated_at)
    VALUES ($1, $2::jsonb, 1, NOW())
    ON CONFLICT (policy_id) DO UPDATE SET params_json = EXCLUDED.params_json, active = 1, updated_at = NOW()
  `, [policyId, JSON.stringify(params)]);
}

async function getActivePolicyPublicParams() {
  const { rows: [row] } = await pool.query(
    'SELECT * FROM policy_public_params WHERE active = 1 ORDER BY updated_at DESC LIMIT 1'
  );
  if (!row) return null;
  return typeof row.params_json === 'object' ? row.params_json : JSON.parse(row.params_json);
}

async function storeAccessGrant(grant) {
  if (!grant?.grantId) return;
  await pool.query(`
    INSERT INTO access_grants (
      grant_id, user_id, device_id, resource, permission, issuing_tx_id,
      policy_id, policy_version, model_version, proof_id, expires_at, revoked,
      grant_data, updated_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, NOW())
    ON CONFLICT (grant_id) DO UPDATE SET user_id = EXCLUDED.user_id, device_id = EXCLUDED.device_id,
      resource = EXCLUDED.resource, permission = EXCLUDED.permission, issuing_tx_id = EXCLUDED.issuing_tx_id,
      policy_id = EXCLUDED.policy_id, policy_version = EXCLUDED.policy_version, model_version = EXCLUDED.model_version,
      proof_id = EXCLUDED.proof_id, expires_at = EXCLUDED.expires_at, revoked = EXCLUDED.revoked,
      grant_data = EXCLUDED.grant_data, updated_at = NOW()
  `, [
    grant.grantId,
    grant.subject,
    grant.deviceId || null,
    grant.resource || 'default',
    grant.permission,
    grant.issuingTxId || null,
    grant.policyId || null,
    grant.policyVersion || null,
    grant.modelVersion || null,
    grant.proofId || null,
    grant.expiresAt,
    grant.revoked ? 1 : 0,
    JSON.stringify(grant),
  ]);
}

async function getAccessGrant(grantId) {
  const { rows: [row] } = await pool.query('SELECT * FROM access_grants WHERE grant_id = $1', [grantId]);
  if (!row) return null;
  const g = typeof row.grant_data === 'object' ? row.grant_data : JSON.parse(row.grant_data);
  return { ...row, grant: g, revoked: !!row.revoked };
}

async function markAccessGrantRevoked(grantId) {
  await pool.query('UPDATE access_grants SET revoked = 1, updated_at = NOW() WHERE grant_id = $1', [grantId]);
}

async function cleanExpiredAccessGrants() {
  const r = await pool.query('DELETE FROM access_grants WHERE expires_at < NOW() OR revoked = 1');
  return r.rowCount ?? 0;
}

async function storeWebAuthnCredential(userId, credentialId, publicKey, counter, transports) {
  await pool.query(`
    INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter, transports)
    VALUES ($1, $2, $3, $4, $5::jsonb)
    ON CONFLICT (user_id, credential_id) DO UPDATE SET public_key = EXCLUDED.public_key,
      counter = EXCLUDED.counter, transports = EXCLUDED.transports
  `, [userId, credentialId, Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey), counter, JSON.stringify(transports || [])]);
}

async function getWebAuthnCredentials(userId) {
  const { rows } = await pool.query('SELECT * FROM webauthn_credentials WHERE user_id = $1', [userId]);
  return rows.map((r) => ({
    credentialID: r.credential_id,
    credentialPublicKey: r.public_key,
    counter: r.counter,
    transports: typeof r.transports === 'object' ? r.transports : JSON.parse(r.transports || '[]'),
    registeredAt: r.registered_at,
  }));
}

async function updateWebAuthnCounter(userId, credentialId, newCounter) {
  await pool.query(
    'UPDATE webauthn_credentials SET counter = $1 WHERE user_id = $2 AND credential_id = $3',
    [newCounter, userId, credentialId]
  );
}

async function storeWebAuthnChallenge(challengeKey, challenge, userId, type, expiresAt) {
  await pool.query(`
    INSERT INTO webauthn_challenges (challenge_key, challenge, user_id, type, expires_at)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (challenge_key) DO UPDATE SET challenge = EXCLUDED.challenge, user_id = EXCLUDED.user_id,
      type = EXCLUDED.type, expires_at = EXCLUDED.expires_at
  `, [challengeKey, challenge, userId, type, expiresAt]);
}

async function getWebAuthnChallenge(challengeKey) {
  const { rows: [row] } = await pool.query(
    'SELECT * FROM webauthn_challenges WHERE challenge_key = $1 AND expires_at > NOW()',
    [challengeKey]
  );
  return row || null;
}

async function deleteWebAuthnChallenge(challengeKey) {
  await pool.query('DELETE FROM webauthn_challenges WHERE challenge_key = $1', [challengeKey]);
}

async function cleanExpiredWebAuthnChallenges() {
  const r = await pool.query('DELETE FROM webauthn_challenges WHERE expires_at < NOW()');
  return r.rowCount ?? 0;
}

async function runCleanupJobs() {
  const tokens = await cleanExpiredTokens();
  const codes = await cleanExpiredOAuthCodes();
  const challenges = await cleanExpiredChallenges();
  const webauthnChallenges = await cleanExpiredWebAuthnChallenges();
  const accessGrants = await cleanExpiredAccessGrants();
  return { tokens, codes, challenges, webauthnChallenges, accessGrants };
}

async function seedOAuthClient() {
  const config = require('./config');
  const existing = await getOAuthClient(config.oauthDefaultClientId);
  if (existing) return false;
  await storeOAuthClient(
    config.oauthDefaultClientId,
    config.oauthDefaultClientSecret || 'change-me-in-production',
    [config.oauthCallbackUrl],
    ['authorization_code', 'refresh_token'],
    'openid profile email'
  );
  return true;
}

async function seedDemoData() {
  const configLocal = require('./config');
  if (!configLocal.seedDemo) return false;
  if (configLocal.nodeEnv === 'production') return false;

  const existing = await getUser('alice');
  if (existing) return false;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await createUserTx(client, {
      userId: 'alice', password: 'pass123', role: 'admin',
      usualCountry: 'IN', usualCity: 'Gwalior',
      normalHoursStart: 8, normalHoursEnd: 18,
      devices: ['dev-001'],
    });
    await createUserTx(client, {
      userId: 'bob', password: 'bob456', role: 'viewer',
      usualCountry: 'IN', usualCity: 'Delhi',
      normalHoursStart: 9, normalHoursEnd: 17,
      devices: ['dev-002'],
    });
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
  return true;
}

/** @param {import('pg').PoolClient} client */
async function createUserTx(client, { userId, password, role, usualCountry, usualCity, normalHoursStart, normalHoursEnd, devices }) {
  const configLocal = require('./config');
  const passwordHash = bcrypt.hashSync(password, configLocal.bcryptRounds);
  await client.query(`
    INSERT INTO users (user_id, password_hash, role, usual_country, usual_city, normal_hours_start, normal_hours_end, status)
    VALUES ($1,$2,$3,$4,$5,$6,$7,'ACTIVE')
  `, [userId, passwordHash, role || 'viewer', usualCountry || 'UNKNOWN', usualCity || 'UNKNOWN', normalHoursStart || 9, normalHoursEnd || 17]);
  if (devices?.length > 0) {
    for (const deviceId of devices) {
      await client.query(
        'INSERT INTO devices (user_id, device_id) VALUES ($1, $2) ON CONFLICT (user_id, device_id) DO NOTHING',
        [userId, deviceId]
      );
    }
  }
}

function getDb() {
  return pool;
}

async function close() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

/** Clears all tables in `public` (used by Jest + shared Postgres). */
async function truncateTestData() {
  if (process.env.NODE_ENV !== 'test') throw new Error('truncateTestData is only allowed when NODE_ENV=test');
  if (!pool) throw new Error('call db.init() before truncateTestData');
  const { rows } = await pool.query(`
    SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename
  `);
  if (rows.length === 0) return;
  const list = rows.map((r) => `"${String(r.tablename).replace(/"/g, '""')}"`).join(', ');
  await pool.query(`TRUNCATE TABLE ${list} RESTART IDENTITY CASCADE`);
}

async function _prepareStatements() {
  /* legacy no-op: prepared statements are per-query with pg */
}

module.exports = {
  init,
  getDb,
  close,
  truncateTestData,
  getUser,
  createUser,
  getAllUsers,
  registerDevice,
  getUserDevices,
  storeRefreshToken,
  isRefreshTokenValid,
  revokeRefreshToken,
  revokeAllUserTokens,
  storeMFASecret,
  getMFASecret,
  storeMFAChallenge,
  getMFAChallenge,
  deleteMFAChallenge,
  storeOAuthCode,
  consumeOAuthCode,
  storeOAuthClient,
  getOAuthClient,
  storeDID,
  getDID,
  getAllDIDs,
  deactivateDID,
  storeVC,
  getVC,
  recordLoginHistory,
  getRecentLogins,
  getLoginHistory,
  getAnomalyProfile,
  updateAnomalyProfile,
  storeSigningKey,
  getActiveSigningKey,
  rotateSigningKey,
  writeAuditLog,
  queryAuditLog,
  storePolicyPublicParams,
  getActivePolicyPublicParams,
  storeAccessGrant,
  getAccessGrant,
  markAccessGrantRevoked,
  storeWebAuthnCredential,
  getWebAuthnCredentials,
  updateWebAuthnCounter,
  storeWebAuthnChallenge,
  getWebAuthnChallenge,
  deleteWebAuthnChallenge,
  runCleanupJobs,
  seedOAuthClient,
  seedDemoData,
  _prepareStatements,
};
