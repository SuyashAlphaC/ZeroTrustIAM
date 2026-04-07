'use strict';

const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'iam.db');

let db;

/**
 * Initialize the SQLite database with all required tables.
 * Called once on server startup.
 */
function init() {
  const fs = require('fs');
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  db = new Database(DB_PATH, { verbose: process.env.DB_VERBOSE === 'true' ? console.log : undefined });

  // Enable WAL mode for concurrent reads + writes
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    -- Users table (replaces hardcoded identityStore)
    CREATE TABLE IF NOT EXISTS users (
      user_id       TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      role          TEXT NOT NULL DEFAULT 'viewer',
      usual_country TEXT NOT NULL DEFAULT 'UNKNOWN',
      usual_city    TEXT NOT NULL DEFAULT 'UNKNOWN',
      normal_hours_start INTEGER NOT NULL DEFAULT 9,
      normal_hours_end   INTEGER NOT NULL DEFAULT 17,
      status        TEXT NOT NULL DEFAULT 'ACTIVE',
      did           TEXT,
      created_at    TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Registered devices
    CREATE TABLE IF NOT EXISTS devices (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id   TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      device_id TEXT NOT NULL,
      label     TEXT,
      registered_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(user_id, device_id)
    );

    -- Refresh tokens (replaces in-memory Set)
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      token     TEXT PRIMARY KEY,
      user_id   TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      issued_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL,
      revoked   INTEGER NOT NULL DEFAULT 0
    );

    -- MFA secrets (replaces in-memory Map)
    CREATE TABLE IF NOT EXISTS mfa_secrets (
      user_id     TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
      secret      TEXT NOT NULL,
      enabled     INTEGER NOT NULL DEFAULT 1,
      enrolled_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- MFA challenges (replaces in-memory Map)
    CREATE TABLE IF NOT EXISTS mfa_challenges (
      challenge_id TEXT PRIMARY KEY,
      user_id      TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      context_json TEXT NOT NULL,
      expires_at   TEXT NOT NULL,
      verified     INTEGER NOT NULL DEFAULT 0
    );

    -- OAuth authorization codes (replaces in-memory Map)
    CREATE TABLE IF NOT EXISTS oauth_codes (
      code         TEXT PRIMARY KEY,
      user_id      TEXT NOT NULL,
      client_id    TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      scope        TEXT NOT NULL DEFAULT 'openid',
      nonce        TEXT,
      expires_at   TEXT NOT NULL,
      used         INTEGER NOT NULL DEFAULT 0
    );

    -- OAuth clients
    CREATE TABLE IF NOT EXISTS oauth_clients (
      client_id     TEXT PRIMARY KEY,
      client_secret TEXT NOT NULL,
      redirect_uris TEXT NOT NULL, -- JSON array
      grant_types   TEXT NOT NULL, -- JSON array
      scope         TEXT NOT NULL DEFAULT 'openid profile email'
    );

    -- DID documents (replaces in-memory Map)
    CREATE TABLE IF NOT EXISTS did_documents (
      did           TEXT PRIMARY KEY,
      user_id       TEXT,
      document_json TEXT NOT NULL,
      private_key   TEXT, -- encrypted PEM
      deactivated   INTEGER NOT NULL DEFAULT 0,
      created_at    TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Verifiable Credentials (replaces in-memory Map)
    CREATE TABLE IF NOT EXISTS verifiable_credentials (
      credential_id  TEXT PRIMARY KEY,
      issuer_did     TEXT NOT NULL,
      subject_did    TEXT NOT NULL,
      credential_json TEXT NOT NULL,
      issued_at      TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Login history for anomaly detection (replaces in-memory arrays)
    CREATE TABLE IF NOT EXISTS login_history (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      device_id  TEXT,
      country    TEXT,
      city       TEXT,
      timestamp  TEXT NOT NULL,
      risk_score REAL,
      decision   TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Anomaly behavioral profiles (replaces in-memory Map)
    CREATE TABLE IF NOT EXISTS anomaly_profiles (
      user_id          TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
      login_hours_mean REAL NOT NULL DEFAULT 12,
      login_hours_std  REAL NOT NULL DEFAULT 4,
      login_hours_samples INTEGER NOT NULL DEFAULT 0,
      known_locations  TEXT NOT NULL DEFAULT '[]', -- JSON array
      known_devices    TEXT NOT NULL DEFAULT '[]', -- JSON array
      last_login_json  TEXT,
      updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Signing keys (replaces startup-generated keys)
    CREATE TABLE IF NOT EXISTS signing_keys (
      key_id       TEXT PRIMARY KEY,
      key_type     TEXT NOT NULL, -- 'jwt', 'oauth_rsa', 'jwt_refresh'
      public_key   TEXT,
      private_key  TEXT NOT NULL, -- encrypted
      algorithm    TEXT NOT NULL DEFAULT 'HS256',
      active       INTEGER NOT NULL DEFAULT 1,
      created_at   TEXT NOT NULL DEFAULT (datetime('now')),
      rotated_at   TEXT
    );

    -- Audit log (local mirror for when blockchain is unavailable)
    CREATE TABLE IF NOT EXISTS local_audit_log (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      tx_id      TEXT,
      user_id    TEXT,
      device_id  TEXT,
      risk_score REAL,
      decision   TEXT,
      reason     TEXT,
      layer      TEXT,
      metadata   TEXT, -- JSON
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- WebAuthn credentials (replaces in-memory Map)
    CREATE TABLE IF NOT EXISTS webauthn_credentials (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id         TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      credential_id   TEXT NOT NULL,
      public_key      BLOB NOT NULL,
      counter         INTEGER NOT NULL DEFAULT 0,
      transports      TEXT NOT NULL DEFAULT '[]', -- JSON array
      registered_at   TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(user_id, credential_id)
    );

    -- WebAuthn challenges (replaces in-memory Map)
    CREATE TABLE IF NOT EXISTS webauthn_challenges (
      challenge_key   TEXT PRIMARY KEY, -- 'userId:type'
      challenge       TEXT NOT NULL,
      user_id         TEXT NOT NULL,
      type            TEXT NOT NULL, -- 'registration' or 'authentication'
      expires_at      TEXT NOT NULL
    );

    -- Indexes
    CREATE INDEX IF NOT EXISTS idx_webauthn_creds_user ON webauthn_credentials(user_id);
    CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires ON webauthn_challenges(expires_at);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
    CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON oauth_codes(expires_at);
    CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);
    CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id);
    CREATE INDEX IF NOT EXISTS idx_login_history_timestamp ON login_history(timestamp);
    CREATE INDEX IF NOT EXISTS idx_local_audit_user ON local_audit_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
  `);

  return db;
}

// ──────────────────────── Users ────────────────────────

const userStmts = {};

function prepareUserStmts() {
  userStmts.getUser = db.prepare('SELECT * FROM users WHERE user_id = ?');
  userStmts.getAllUsers = db.prepare('SELECT user_id, role, status, did, created_at FROM users');
  userStmts.insertUser = db.prepare(`
    INSERT INTO users (user_id, password_hash, role, usual_country, usual_city, normal_hours_start, normal_hours_end, status)
    VALUES (@user_id, @password_hash, @role, @usual_country, @usual_city, @normal_hours_start, @normal_hours_end, @status)
  `);
  userStmts.updateUser = db.prepare(`
    UPDATE users SET role=@role, usual_country=@usual_country, usual_city=@usual_city,
    normal_hours_start=@normal_hours_start, normal_hours_end=@normal_hours_end, status=@status,
    updated_at=datetime('now') WHERE user_id=@user_id
  `);
  userStmts.setUserDID = db.prepare('UPDATE users SET did=?, updated_at=datetime(\'now\') WHERE user_id=?');
  userStmts.deleteUser = db.prepare('DELETE FROM users WHERE user_id = ?');
}

function getUser(userId) {
  const row = userStmts.getUser.get(userId);
  if (!row) return null;
  const devices = db.prepare('SELECT device_id FROM devices WHERE user_id = ?').all(userId);
  return {
    userId: row.user_id,
    passwordHash: row.password_hash,
    role: row.role,
    registeredDevices: devices.map(d => d.device_id),
    usualLocation: { country: row.usual_country, city: row.usual_city },
    normalHours: [row.normal_hours_start, row.normal_hours_end],
    status: row.status,
    did: row.did,
    createdAt: row.created_at,
  };
}

function createUser({ userId, password, role, usualCountry, usualCity, normalHoursStart, normalHoursEnd, devices }) {
  const config = require('./config');
  const passwordHash = bcrypt.hashSync(password, config.bcryptRounds);
  userStmts.insertUser.run({
    user_id: userId,
    password_hash: passwordHash,
    role: role || 'viewer',
    usual_country: usualCountry || 'UNKNOWN',
    usual_city: usualCity || 'UNKNOWN',
    normal_hours_start: normalHoursStart || 9,
    normal_hours_end: normalHoursEnd || 17,
    status: 'ACTIVE',
  });
  if (devices && devices.length > 0) {
    const insertDevice = db.prepare('INSERT OR IGNORE INTO devices (user_id, device_id) VALUES (?, ?)');
    for (const deviceId of devices) {
      insertDevice.run(userId, deviceId);
    }
  }
}

function getAllUsers() {
  return userStmts.getAllUsers.all();
}

// ──────────────────────── Devices ────────────────────────

function registerDevice(userId, deviceId, label) {
  db.prepare('INSERT OR IGNORE INTO devices (user_id, device_id, label) VALUES (?, ?, ?)').run(userId, deviceId, label || null);
}

function getUserDevices(userId) {
  return db.prepare('SELECT device_id, label, registered_at FROM devices WHERE user_id = ?').all(userId);
}

// ──────────────────────── Refresh Tokens ────────────────────────

function storeRefreshToken(token, userId, expiresAt) {
  db.prepare('INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, userId, expiresAt);
}

function isRefreshTokenValid(token) {
  const row = db.prepare('SELECT * FROM refresh_tokens WHERE token = ? AND revoked = 0 AND expires_at > datetime(\'now\')').get(token);
  return !!row;
}

function revokeRefreshToken(token) {
  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token = ?').run(token);
}

function revokeAllUserTokens(userId) {
  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').run(userId);
}

function cleanExpiredTokens() {
  const result = db.prepare('DELETE FROM refresh_tokens WHERE expires_at < datetime(\'now\') OR revoked = 1').run();
  return result.changes;
}

// ──────────────────────── MFA ────────────────────────

function storeMFASecret(userId, secret) {
  db.prepare('INSERT OR REPLACE INTO mfa_secrets (user_id, secret, enabled, enrolled_at) VALUES (?, ?, 1, datetime(\'now\'))').run(userId, secret);
}

function getMFASecret(userId) {
  return db.prepare('SELECT * FROM mfa_secrets WHERE user_id = ?').get(userId);
}

function storeMFAChallenge(challengeId, userId, context, expiresAt) {
  db.prepare('INSERT INTO mfa_challenges (challenge_id, user_id, context_json, expires_at) VALUES (?, ?, ?, ?)').run(challengeId, userId, JSON.stringify(context), expiresAt);
}

function getMFAChallenge(challengeId) {
  const row = db.prepare('SELECT * FROM mfa_challenges WHERE challenge_id = ? AND verified = 0 AND expires_at > datetime(\'now\')').get(challengeId);
  if (!row) return null;
  return { ...row, context: JSON.parse(row.context_json) };
}

function deleteMFAChallenge(challengeId) {
  db.prepare('DELETE FROM mfa_challenges WHERE challenge_id = ?').run(challengeId);
}

function cleanExpiredChallenges() {
  return db.prepare('DELETE FROM mfa_challenges WHERE expires_at < datetime(\'now\')').run().changes;
}

// ──────────────────────── OAuth ────────────────────────

function storeOAuthCode(code, userId, clientId, redirectUri, scope, nonce, expiresAt) {
  db.prepare('INSERT INTO oauth_codes (code, user_id, client_id, redirect_uri, scope, nonce, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(code, userId, clientId, redirectUri, scope, nonce, expiresAt);
}

function consumeOAuthCode(code) {
  const row = db.prepare('SELECT * FROM oauth_codes WHERE code = ? AND used = 0 AND expires_at > datetime(\'now\')').get(code);
  if (!row) return null;
  db.prepare('UPDATE oauth_codes SET used = 1 WHERE code = ?').run(code);
  return row;
}

function storeOAuthClient(clientId, clientSecret, redirectUris, grantTypes, scope) {
  db.prepare('INSERT OR REPLACE INTO oauth_clients (client_id, client_secret, redirect_uris, grant_types, scope) VALUES (?, ?, ?, ?, ?)').run(clientId, clientSecret, JSON.stringify(redirectUris), JSON.stringify(grantTypes), scope);
}

function getOAuthClient(clientId) {
  const row = db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(clientId);
  if (!row) return null;
  return {
    clientId: row.client_id,
    clientSecret: row.client_secret,
    redirectUris: JSON.parse(row.redirect_uris),
    grantTypes: JSON.parse(row.grant_types),
    scope: row.scope,
  };
}

function cleanExpiredOAuthCodes() {
  return db.prepare('DELETE FROM oauth_codes WHERE expires_at < datetime(\'now\') OR used = 1').run().changes;
}

// ──────────────────────── DIDs ────────────────────────

function storeDID(did, userId, documentJson, privateKey) {
  db.prepare('INSERT OR REPLACE INTO did_documents (did, user_id, document_json, private_key, updated_at) VALUES (?, ?, ?, ?, datetime(\'now\'))').run(did, userId, JSON.stringify(documentJson), privateKey || null);
  if (userId) {
    userStmts.setUserDID.run(did, userId);
  }
}

function getDID(did) {
  const row = db.prepare('SELECT * FROM did_documents WHERE did = ?').get(did);
  if (!row) return null;
  return {
    did: row.did,
    userId: row.user_id,
    document: JSON.parse(row.document_json),
    privateKey: row.private_key,
    deactivated: !!row.deactivated,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function getAllDIDs() {
  return db.prepare('SELECT did, user_id, deactivated, created_at FROM did_documents').all();
}

function deactivateDID(did) {
  db.prepare('UPDATE did_documents SET deactivated = 1, updated_at = datetime(\'now\') WHERE did = ?').run(did);
}

// ──────────────────────── Verifiable Credentials ────────────────────────

function storeVC(credentialId, issuerDid, subjectDid, credentialJson) {
  db.prepare('INSERT INTO verifiable_credentials (credential_id, issuer_did, subject_did, credential_json) VALUES (?, ?, ?, ?)').run(credentialId, issuerDid, subjectDid, JSON.stringify(credentialJson));
}

function getVC(credentialId) {
  const row = db.prepare('SELECT * FROM verifiable_credentials WHERE credential_id = ?').get(credentialId);
  if (!row) return null;
  return { ...row, credential: JSON.parse(row.credential_json) };
}

// ──────────────────────── Login History ────────────────────────

function recordLoginHistory(userId, deviceId, country, city, timestamp, riskScore, decision) {
  db.prepare('INSERT INTO login_history (user_id, device_id, country, city, timestamp, risk_score, decision) VALUES (?, ?, ?, ?, ?, ?, ?)').run(userId, deviceId, country, city, timestamp, riskScore, decision);
}

function getRecentLogins(userId, limitMinutes) {
  const cutoff = new Date(Date.now() - limitMinutes * 60 * 1000).toISOString();
  return db.prepare('SELECT * FROM login_history WHERE user_id = ? AND timestamp > ? ORDER BY timestamp DESC').all(userId, cutoff);
}

function getLoginHistory(userId, limit) {
  return db.prepare('SELECT * FROM login_history WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?').all(userId, limit || 100);
}

// ──────────────────────── Anomaly Profiles ────────────────────────

function getAnomalyProfile(userId) {
  let row = db.prepare('SELECT * FROM anomaly_profiles WHERE user_id = ?').get(userId);
  if (!row) {
    db.prepare('INSERT OR IGNORE INTO anomaly_profiles (user_id) VALUES (?)').run(userId);
    row = db.prepare('SELECT * FROM anomaly_profiles WHERE user_id = ?').get(userId);
  }
  return {
    userId: row.user_id,
    loginHours: { mean: row.login_hours_mean, std: row.login_hours_std, samples: row.login_hours_samples },
    knownLocations: JSON.parse(row.known_locations),
    knownDevices: JSON.parse(row.known_devices),
    lastLogin: row.last_login_json ? JSON.parse(row.last_login_json) : null,
  };
}

function updateAnomalyProfile(userId, profile) {
  db.prepare(`
    UPDATE anomaly_profiles SET
      login_hours_mean=?, login_hours_std=?, login_hours_samples=?,
      known_locations=?, known_devices=?, last_login_json=?,
      updated_at=datetime('now')
    WHERE user_id=?
  `).run(
    profile.loginHours.mean, profile.loginHours.std, profile.loginHours.samples,
    JSON.stringify(profile.knownLocations), JSON.stringify(profile.knownDevices),
    profile.lastLogin ? JSON.stringify(profile.lastLogin) : null,
    userId
  );
}

// ──────────────────────── Signing Keys ────────────────────────

function storeSigningKey(keyId, keyType, privateKey, publicKey, algorithm) {
  db.prepare('INSERT OR REPLACE INTO signing_keys (key_id, key_type, private_key, public_key, algorithm) VALUES (?, ?, ?, ?, ?)').run(keyId, keyType, privateKey, publicKey || null, algorithm);
}

function getActiveSigningKey(keyType) {
  return db.prepare('SELECT * FROM signing_keys WHERE key_type = ? AND active = 1 ORDER BY created_at DESC LIMIT 1').get(keyType);
}

function rotateSigningKey(keyType) {
  db.prepare('UPDATE signing_keys SET active = 0, rotated_at = datetime(\'now\') WHERE key_type = ? AND active = 1').run(keyType);
}

// ──────────────────────── Local Audit Log ────────────────────────

function writeAuditLog(entry) {
  db.prepare('INSERT INTO local_audit_log (tx_id, user_id, device_id, risk_score, decision, reason, layer, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
    entry.txId, entry.userId, entry.deviceId, entry.riskScore, entry.decision, entry.reason, entry.layer, entry.metadata ? JSON.stringify(entry.metadata) : null
  );
}

function queryAuditLog({ userId, decision, limit, offset } = {}) {
  let sql = 'SELECT * FROM local_audit_log WHERE 1=1';
  const params = [];
  if (userId) { sql += ' AND user_id = ?'; params.push(userId); }
  if (decision) { sql += ' AND decision = ?'; params.push(decision); }
  sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit || 100, offset || 0);
  return db.prepare(sql).all(...params);
}

// ──────────────────────── WebAuthn ────────────────────────

function storeWebAuthnCredential(userId, credentialId, publicKey, counter, transports) {
  db.prepare('INSERT OR REPLACE INTO webauthn_credentials (user_id, credential_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?)').run(
    userId, credentialId, publicKey, counter, JSON.stringify(transports || [])
  );
}

function getWebAuthnCredentials(userId) {
  const rows = db.prepare('SELECT * FROM webauthn_credentials WHERE user_id = ?').all(userId);
  return rows.map(r => ({
    credentialID: r.credential_id,
    credentialPublicKey: r.public_key,
    counter: r.counter,
    transports: JSON.parse(r.transports),
    registeredAt: r.registered_at,
  }));
}

function updateWebAuthnCounter(userId, credentialId, newCounter) {
  db.prepare('UPDATE webauthn_credentials SET counter = ? WHERE user_id = ? AND credential_id = ?').run(newCounter, userId, credentialId);
}

function storeWebAuthnChallenge(challengeKey, challenge, userId, type, expiresAt) {
  db.prepare('INSERT OR REPLACE INTO webauthn_challenges (challenge_key, challenge, user_id, type, expires_at) VALUES (?, ?, ?, ?, ?)').run(
    challengeKey, challenge, userId, type, expiresAt
  );
}

function getWebAuthnChallenge(challengeKey) {
  const row = db.prepare('SELECT * FROM webauthn_challenges WHERE challenge_key = ? AND expires_at > datetime(\'now\')').get(challengeKey);
  return row || null;
}

function deleteWebAuthnChallenge(challengeKey) {
  db.prepare('DELETE FROM webauthn_challenges WHERE challenge_key = ?').run(challengeKey);
}

function cleanExpiredWebAuthnChallenges() {
  return db.prepare('DELETE FROM webauthn_challenges WHERE expires_at < datetime(\'now\')').run().changes;
}

// ──────────────────────── Cleanup Jobs ────────────────────────

function runCleanupJobs() {
  const tokens = cleanExpiredTokens();
  const codes = cleanExpiredOAuthCodes();
  const challenges = cleanExpiredChallenges();
  const webauthnChallenges = cleanExpiredWebAuthnChallenges();
  return { tokens, codes, challenges, webauthnChallenges };
}

// ──────────────────────── Seed Default OAuth Client ────────────────────────

/**
 * Ensures the default OAuth client exists in the database.
 * Uses values from config (overridable via environment variables).
 * Called on every startup — idempotent.
 */
function seedOAuthClient() {
  const config = require('./config');
  const existing = getOAuthClient(config.oauthDefaultClientId);
  if (existing) return false;

  storeOAuthClient(
    config.oauthDefaultClientId,
    config.oauthDefaultClientSecret || 'change-me-in-production',
    [config.oauthCallbackUrl],
    ['authorization_code', 'refresh_token'],
    'openid profile email'
  );
  return true;
}

// ──────────────────────── Seed Demo Data (Development Only) ────────────────────────

/**
 * Seeds demo users for development and testing.
 * Only runs when SEED_DEMO=true is set in environment.
 * NEVER runs in production mode.
 */
function seedDemoData() {
  const config = require('./config');
  if (!config.seedDemo) return false;
  if (config.nodeEnv === 'production') return false;

  const existing = userStmts.getUser.get('alice');
  if (existing) return false;

  const seed = db.transaction(() => {
    createUser({
      userId: 'alice', password: 'pass123', role: 'admin',
      usualCountry: 'IN', usualCity: 'Gwalior',
      normalHoursStart: 8, normalHoursEnd: 18,
      devices: ['dev-001'],
    });
    createUser({
      userId: 'bob', password: 'bob456', role: 'viewer',
      usualCountry: 'IN', usualCity: 'Delhi',
      normalHoursStart: 9, normalHoursEnd: 17,
      devices: ['dev-002'],
    });
  });

  seed();
  return true;
}

// ──────────────────────── Lifecycle ────────────────────────

function getDb() { return db; }

function close() {
  if (db) db.close();
}

module.exports = {
  init,
  getDb,
  close,
  // Users
  getUser,
  createUser,
  getAllUsers,
  // Devices
  registerDevice,
  getUserDevices,
  // Refresh tokens
  storeRefreshToken,
  isRefreshTokenValid,
  revokeRefreshToken,
  revokeAllUserTokens,
  // MFA
  storeMFASecret,
  getMFASecret,
  storeMFAChallenge,
  getMFAChallenge,
  deleteMFAChallenge,
  // OAuth
  storeOAuthCode,
  consumeOAuthCode,
  storeOAuthClient,
  getOAuthClient,
  // DIDs
  storeDID,
  getDID,
  getAllDIDs,
  deactivateDID,
  // VCs
  storeVC,
  getVC,
  // Login history
  recordLoginHistory,
  getRecentLogins,
  getLoginHistory,
  // Anomaly profiles
  getAnomalyProfile,
  updateAnomalyProfile,
  // Signing keys
  storeSigningKey,
  getActiveSigningKey,
  rotateSigningKey,
  // Audit
  writeAuditLog,
  queryAuditLog,
  // WebAuthn
  storeWebAuthnCredential,
  getWebAuthnCredentials,
  updateWebAuthnCounter,
  storeWebAuthnChallenge,
  getWebAuthnChallenge,
  deleteWebAuthnChallenge,
  // Maintenance
  runCleanupJobs,
  seedOAuthClient,
  seedDemoData,
  // Internal (for prepared statements)
  _prepareStatements: prepareUserStmts,
};
