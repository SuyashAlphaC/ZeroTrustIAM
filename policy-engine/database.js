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
  id: '001_initial',
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
  /** Non-trivial reverse of 001_initial: drops all application tables (not schema_migrations). */
  down: async (client) => {
    await client.query('DROP TABLE IF EXISTS webauthn_challenges CASCADE');
    await client.query('DROP TABLE IF EXISTS webauthn_credentials CASCADE');
    await client.query('DROP TABLE IF EXISTS access_grants CASCADE');
    await client.query('DROP TABLE IF EXISTS local_audit_log CASCADE');
    await client.query('DROP TABLE IF EXISTS login_history CASCADE');
    await client.query('DROP TABLE IF EXISTS anomaly_profiles CASCADE');
    await client.query('DROP TABLE IF EXISTS refresh_tokens CASCADE');
    await client.query('DROP TABLE IF EXISTS devices CASCADE');
    await client.query('DROP TABLE IF EXISTS mfa_challenges CASCADE');
    await client.query('DROP TABLE IF EXISTS mfa_secrets CASCADE');
    await client.query('DROP TABLE IF EXISTS verifiable_credentials CASCADE');
    await client.query('DROP TABLE IF EXISTS did_documents CASCADE');
    await client.query('DROP TABLE IF EXISTS oauth_codes CASCADE');
    await client.query('DROP TABLE IF EXISTS oauth_clients CASCADE');
    await client.query('DROP TABLE IF EXISTS signing_keys CASCADE');
    await client.query('DROP TABLE IF EXISTS policy_public_params CASCADE');
    await client.query('DROP TABLE IF EXISTS users CASCADE');
  },
}, {
  id: '005_audit_feedback',
  /** Analyst feedback on audit decisions — provides ground-truth labels to break the
   *  ML self-reinforcement loop. Multiple reviewers per audit are allowed. */
  /** @param {import('pg').PoolClient} client */
  up: async (client) => {
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_feedback (
        id SERIAL PRIMARY KEY,
        audit_id TEXT NOT NULL,
        label TEXT NOT NULL CHECK (label IN ('true_positive', 'false_positive', 'true_negative', 'false_negative')),
        reviewer TEXT NOT NULL,
        reviewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        notes TEXT,
        UNIQUE(audit_id, reviewer)
      )
    `);
    await client.query('CREATE INDEX IF NOT EXISTS idx_feedback_audit_id ON audit_feedback(audit_id)');
  },
  /** @param {import('pg').PoolClient} client */
  down: async (client) => {
    await client.query('DROP TABLE IF EXISTS audit_feedback CASCADE');
  },
}, {
  id: '006_refresh_token_families',
  /** Refresh-token families enable RFC 6819 §5.2.2.3 reuse detection: rotated
   *  tokens are kept (status='ROTATED'). Replaying any rotated/compromised
   *  token in a family causes the entire family to be marked COMPROMISED. */
  /** @param {import('pg').PoolClient} client */
  up: async (client) => {
    await client.query("ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ACTIVE'");
    await client.query('ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS family_id UUID');
    await client.query('ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS parent_token_hash TEXT');
    await client.query('CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id)');
    await client.query("UPDATE refresh_tokens SET family_id = gen_random_uuid() WHERE family_id IS NULL");
    // Backfill status from the legacy `revoked` flag for tokens predating this column.
    await client.query("UPDATE refresh_tokens SET status = 'REVOKED' WHERE revoked = 1 AND status = 'ACTIVE'");
  },
  /** @param {import('pg').PoolClient} client */
  down: async (client) => {
    await client.query('DROP INDEX IF EXISTS idx_refresh_family');
    await client.query('ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS parent_token_hash');
    await client.query('ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS family_id');
    await client.query('ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS status');
  },
}, {
  id: '007_lockout_abac_selfservice',
  /** Account lockout counters, ABAC policies, password-reset tokens, session ids. */
  /** @param {import('pg').PoolClient} client */
  up: async (client) => {
    await client.query(`
      CREATE TABLE IF NOT EXISTS account_lockouts (
        user_id TEXT PRIMARY KEY,
        failure_count INTEGER NOT NULL DEFAULT 0,
        window_started_at TIMESTAMPTZ,
        locked_until TIMESTAMPTZ,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS abac_policies (
        policy_id TEXT PRIMARY KEY,
        policy_json JSONB NOT NULL,
        active SMALLINT NOT NULL DEFAULT 1,
        description TEXT,
        created_by TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL,
        used SMALLINT NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query('CREATE INDEX IF NOT EXISTS idx_password_reset_user ON password_reset_tokens(user_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_abac_active ON abac_policies(active)');
    // Stable session id for self-service revoke without exposing raw refresh tokens
    await client.query('ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS session_id UUID DEFAULT gen_random_uuid()');
    await client.query('CREATE INDEX IF NOT EXISTS idx_refresh_session ON refresh_tokens(session_id)');
  },
  /** @param {import('pg').PoolClient} client */
  down: async (client) => {
    await client.query('DROP INDEX IF EXISTS idx_refresh_session');
    await client.query('ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS session_id');
    await client.query('DROP TABLE IF EXISTS password_reset_tokens CASCADE');
    await client.query('DROP TABLE IF EXISTS abac_policies CASCADE');
    await client.query('DROP TABLE IF EXISTS account_lockouts CASCADE');
  },
}, {
  id: '008_multitenancy_federation',
  /** Tenants, billing/CMK metadata, federated identities, tenant_id on users. */
  /** @param {import('pg').PoolClient} client */
  up: async (client) => {
    await client.query(`
      CREATE TABLE IF NOT EXISTS tenants (
        tenant_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        plan TEXT NOT NULL DEFAULT 'free',
        billing_email TEXT,
        cmk_arn TEXT,
        cmk_key_id TEXT,
        settings JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      INSERT INTO tenants (tenant_id, name, slug, plan, status)
      VALUES ('default', 'Default Organization', 'default', 'enterprise', 'ACTIVE')
      ON CONFLICT (tenant_id) DO NOTHING
    `);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id TEXT DEFAULT 'default'`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT`);
    await client.query(`
      CREATE TABLE IF NOT EXISTS federated_identities (
        id SERIAL PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        subject TEXT NOT NULL,
        email TEXT,
        claims JSONB,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(provider, subject)
      )
    `);
    await client.query('CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_fed_user ON federated_identities(user_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_fed_tenant ON federated_identities(tenant_id)');
    await client.query(`
      CREATE TABLE IF NOT EXISTS tenant_billing_events (
        id SERIAL PRIMARY KEY,
        tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
        event_type TEXT NOT NULL,
        amount_cents INTEGER,
        currency TEXT DEFAULT 'USD',
        metadata JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
  },
  /** @param {import('pg').PoolClient} client */
  down: async (client) => {
    await client.query('DROP TABLE IF EXISTS tenant_billing_events CASCADE');
    await client.query('DROP TABLE IF EXISTS federated_identities CASCADE');
    await client.query('ALTER TABLE users DROP COLUMN IF EXISTS email');
    await client.query('ALTER TABLE users DROP COLUMN IF EXISTS tenant_id');
    await client.query('DROP TABLE IF EXISTS tenants CASCADE');
  },
}, {
  id: '009_stripe_billing',
  /** Stripe customer/subscription fields on tenants + richer billing events. */
  /** @param {import('pg').PoolClient} client */
  up: async (client) => {
    await client.query('ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT');
    await client.query('ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT');
    await client.query('ALTER TABLE tenants ADD COLUMN IF NOT EXISTS subscription_status TEXT');
    await client.query('ALTER TABLE tenants ADD COLUMN IF NOT EXISTS subscription_period_end TIMESTAMPTZ');
    await client.query('ALTER TABLE tenants ADD COLUMN IF NOT EXISTS cancel_at_period_end SMALLINT NOT NULL DEFAULT 0');
    await client.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_stripe_customer ON tenants(stripe_customer_id) WHERE stripe_customer_id IS NOT NULL');
    await client.query('CREATE INDEX IF NOT EXISTS idx_billing_events_tenant ON tenant_billing_events(tenant_id, created_at DESC)');
  },
  /** @param {import('pg').PoolClient} client */
  down: async (client) => {
    await client.query('DROP INDEX IF EXISTS idx_billing_events_tenant');
    await client.query('DROP INDEX IF EXISTS idx_tenants_stripe_customer');
    await client.query('ALTER TABLE tenants DROP COLUMN IF EXISTS cancel_at_period_end');
    await client.query('ALTER TABLE tenants DROP COLUMN IF EXISTS subscription_period_end');
    await client.query('ALTER TABLE tenants DROP COLUMN IF EXISTS subscription_status');
    await client.query('ALTER TABLE tenants DROP COLUMN IF EXISTS stripe_subscription_id');
    await client.query('ALTER TABLE tenants DROP COLUMN IF EXISTS stripe_customer_id');
  },
}, {
  id: '010_user_phone_notifications',
  /** Phone on users + notification outbox for admin lifecycle events. */
  /** @param {import('pg').PoolClient} client */
  up: async (client) => {
    await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT');
    await client.query(`
      CREATE TABLE IF NOT EXISTS notification_outbox (
        id SERIAL PRIMARY KEY,
        user_id TEXT,
        event TEXT NOT NULL,
        actor TEXT,
        subject TEXT,
        channels JSONB NOT NULL DEFAULT '[]'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query('CREATE INDEX IF NOT EXISTS idx_notify_outbox_user ON notification_outbox(user_id, created_at DESC)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_notify_outbox_event ON notification_outbox(event, created_at DESC)');
  },
  /** @param {import('pg').PoolClient} client */
  down: async (client) => {
    await client.query('DROP TABLE IF EXISTS notification_outbox CASCADE');
    await client.query('ALTER TABLE users DROP COLUMN IF EXISTS phone');
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
      if (applied.has(m.id)) continue;
      await m.up(client);
      await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [m.id]);
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
    tenantId: row.tenant_id || 'default',
    email: row.email || null,
    phone: row.phone || null,
    createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
  };
}

async function createUser({ userId, password, role, usualCountry, usualCity, normalHoursStart, normalHoursEnd, devices }) {
  const config = require('./config');
  const passwordHash = bcrypt.hashSync(password, config.bcryptRounds);
  await createUserWithHash({
    userId,
    passwordHash,
    role,
    usualCountry,
    usualCity,
    normalHoursStart,
    normalHoursEnd,
    devices,
  });
}

async function createUserWithHash({ userId, passwordHash, role, usualCountry, usualCity, normalHoursStart, normalHoursEnd, devices, tenantId, email, phone }) {
  await pool.query(`
    INSERT INTO users (user_id, password_hash, role, usual_country, usual_city, normal_hours_start, normal_hours_end, status, tenant_id, email, phone)
    VALUES ($1,$2,$3,$4,$5,$6,$7,'ACTIVE',$8,$9,$10)
  `, [
    userId, passwordHash, role || 'viewer',
    usualCountry || 'UNKNOWN', usualCity || 'UNKNOWN',
    normalHoursStart || 9, normalHoursEnd || 17,
    tenantId || 'default', email || null, phone || null,
  ]);
  if (devices?.length > 0) {
    for (const deviceId of devices) {
      await pool.query(
        'INSERT INTO devices (user_id, device_id) VALUES ($1, $2) ON CONFLICT (user_id, device_id) DO NOTHING',
        [userId, deviceId]
      );
    }
  }
}

async function updateUserContact(userId, { email, phone } = {}) {
  const sets = [];
  const vals = [];
  let i = 1;
  if (email !== undefined) { sets.push(`email = $${i++}`); vals.push(email || null); }
  if (phone !== undefined) { sets.push(`phone = $${i++}`); vals.push(phone || null); }
  if (!sets.length) return;
  vals.push(userId);
  await pool.query(
    `UPDATE users SET ${sets.join(', ')}, updated_at = NOW() WHERE user_id = $${i}`,
    vals
  );
}

async function recordNotification({ userId, event, channels, actor, subject }) {
  await pool.query(
    `INSERT INTO notification_outbox (user_id, event, actor, subject, channels)
     VALUES ($1, $2, $3, $4, $5::jsonb)`,
    [userId || null, event, actor || null, subject || null, JSON.stringify(channels || [])]
  );
}

async function listNotifications({ userId, limit = 50 } = {}) {
  const lim = Math.min(parseInt(limit, 10) || 50, 200);
  if (userId) {
    const { rows } = await pool.query(
      `SELECT id, user_id, event, actor, subject, channels, created_at
       FROM notification_outbox WHERE user_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [userId, lim]
    );
    return rows;
  }
  const { rows } = await pool.query(
    `SELECT id, user_id, event, actor, subject, channels, created_at
     FROM notification_outbox ORDER BY created_at DESC LIMIT $1`,
    [lim]
  );
  return rows;
}

/** Hard-delete a just-provisioned user (compensating transaction after Fabric failure). */
async function rollbackNewUser(userId) {
  await pool.query('DELETE FROM devices WHERE user_id = $1', [userId]);
  await pool.query('DELETE FROM users WHERE user_id = $1', [userId]);
}

async function updateUserPassword(userId, passwordHash) {
  await pool.query(
    'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE user_id = $2',
    [passwordHash, userId]
  );
}

async function setUserStatus(userId, status) {
  await pool.query(
    'UPDATE users SET status = $1, updated_at = NOW() WHERE user_id = $2',
    [status, userId]
  );
}

async function deleteUserDevice(userId, deviceId) {
  const r = await pool.query(
    'DELETE FROM devices WHERE user_id = $1 AND device_id = $2',
    [userId, deviceId]
  );
  return (r.rowCount || 0) > 0;
}

async function listUserSessions(userId) {
  const { rows } = await pool.query(
    `SELECT session_id, family_id, status, issued_at, expires_at
     FROM refresh_tokens
     WHERE user_id = $1 AND status = 'ACTIVE' AND expires_at > NOW()
     ORDER BY issued_at DESC
     LIMIT 100`,
    [userId]
  );
  return rows;
}

async function revokeUserSession(userId, sessionId) {
  const r = await pool.query(
    `UPDATE refresh_tokens SET status = 'REVOKED', revoked = 1
     WHERE user_id = $1 AND session_id::text = $2 AND status = 'ACTIVE'`,
    [userId, sessionId]
  );
  return (r.rowCount || 0) > 0;
}

async function revokeOtherUserSessions(userId, keepRefreshToken) {
  if (keepRefreshToken) {
    const r = await pool.query(
      `UPDATE refresh_tokens SET status = 'REVOKED', revoked = 1
       WHERE user_id = $1 AND token <> $2 AND status = 'ACTIVE'`,
      [userId, keepRefreshToken]
    );
    return r.rowCount || 0;
  }
  const r = await pool.query(
    `UPDATE refresh_tokens SET status = 'REVOKED', revoked = 1
     WHERE user_id = $1 AND status = 'ACTIVE'`,
    [userId]
  );
  return r.rowCount || 0;
}

/** GDPR Art. 17 — erase PII from operational stores; leave hashed tombstones in audit. */
async function eraseUserAccount(userId, redactionId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Redact audit rows (keep decision metadata for fraud prevention)
    await client.query(
      `UPDATE local_audit_log SET
         device_id = CASE WHEN device_id IS NOT NULL THEN 'redacted' ELSE NULL END,
         metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('redacted', true, 'redactionId', $1::text)
       WHERE user_id = $2`,
      [redactionId, userId]
    );
    await client.query(
      `UPDATE login_history SET device_id = 'redacted', country = NULL, city = NULL WHERE user_id = $1`,
      [userId]
    );
    await client.query('DELETE FROM webauthn_credentials WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM webauthn_challenges WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM mfa_secrets WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM mfa_challenges WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM devices WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM anomaly_profiles WHERE user_id = $1', [userId]);
    await client.query(
      "UPDATE refresh_tokens SET status = 'REVOKED', revoked = 1 WHERE user_id = $1",
      [userId]
    );
    await client.query('DELETE FROM refresh_tokens WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [userId]);
    await client.query('DELETE FROM account_lockouts WHERE user_id = $1', [userId]);
    // Soft-delete: keep PK for historical FKs, wipe credentials and PII
    await client.query(
      `UPDATE users SET
         password_hash = $1,
         status = 'DELETED',
         usual_country = 'XX',
         usual_city = 'REDACTED',
         did = NULL,
         role = 'viewer',
         updated_at = NOW()
       WHERE user_id = $2`,
      [`REDACTED:${redactionId}`, userId]
    );
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

// ── Account lockout (Postgres fallback when Redis unavailable) ──

async function getAccountLockout(userId) {
  const { rows: [row] } = await pool.query(
    'SELECT * FROM account_lockouts WHERE user_id = $1',
    [userId]
  );
  return row || null;
}

async function incrementLoginFailures(userId, windowSeconds) {
  const { rows: [row] } = await pool.query(
    'SELECT * FROM account_lockouts WHERE user_id = $1',
    [userId]
  );
  const now = Date.now();
  if (!row || !row.window_started_at
      || (now - new Date(row.window_started_at).getTime()) > windowSeconds * 1000) {
    await pool.query(`
      INSERT INTO account_lockouts (user_id, failure_count, window_started_at, updated_at)
      VALUES ($1, 1, NOW(), NOW())
      ON CONFLICT (user_id) DO UPDATE SET
        failure_count = 1, window_started_at = NOW(), locked_until = NULL, updated_at = NOW()
    `, [userId]);
    return 1;
  }
  const { rows: [updated] } = await pool.query(`
    UPDATE account_lockouts SET failure_count = failure_count + 1, updated_at = NOW()
    WHERE user_id = $1 RETURNING failure_count
  `, [userId]);
  return updated.failure_count;
}

async function setAccountLockout(userId, lockedUntilIso, failureCount) {
  await pool.query(`
    INSERT INTO account_lockouts (user_id, failure_count, locked_until, window_started_at, updated_at)
    VALUES ($1, $2, $3, NOW(), NOW())
    ON CONFLICT (user_id) DO UPDATE SET
      failure_count = $2, locked_until = $3, updated_at = NOW()
  `, [userId, failureCount || 0, lockedUntilIso]);
}

async function clearAccountLockout(userId) {
  await pool.query('DELETE FROM account_lockouts WHERE user_id = $1', [userId]);
}

// ── ABAC policies ──

async function listAbacPolicies({ activeOnly } = {}) {
  const sql = activeOnly
    ? 'SELECT * FROM abac_policies WHERE active = 1 ORDER BY created_at ASC'
    : 'SELECT * FROM abac_policies ORDER BY created_at ASC';
  return (await pool.query(sql)).rows;
}

async function upsertAbacPolicy(policyId, policyJson, description, createdBy) {
  await pool.query(`
    INSERT INTO abac_policies (policy_id, policy_json, description, created_by, active, updated_at)
    VALUES ($1, $2::jsonb, $3, $4, 1, NOW())
    ON CONFLICT (policy_id) DO UPDATE SET
      policy_json = EXCLUDED.policy_json,
      description = EXCLUDED.description,
      active = 1,
      updated_at = NOW()
  `, [policyId, JSON.stringify(policyJson), description || null, createdBy || null]);
}

async function deleteAbacPolicy(policyId) {
  const r = await pool.query('DELETE FROM abac_policies WHERE policy_id = $1', [policyId]);
  return (r.rowCount || 0) > 0;
}

// ── Password reset tokens ──

async function storePasswordResetToken(tokenHash, userId, expiresAt) {
  await pool.query(
    `INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
    [tokenHash, userId, expiresAt]
  );
}

async function consumePasswordResetToken(tokenHash) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [row] } = await client.query(
      'SELECT * FROM password_reset_tokens WHERE token_hash = $1 AND used = 0 AND expires_at > NOW()',
      [tokenHash]
    );
    if (!row) {
      await client.query('ROLLBACK');
      return null;
    }
    await client.query('UPDATE password_reset_tokens SET used = 1 WHERE token_hash = $1', [tokenHash]);
    await client.query('COMMIT');
    return row;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

// ── Multi-tenancy ──

async function getTenant(tenantId) {
  const { rows: [row] } = await pool.query('SELECT * FROM tenants WHERE tenant_id = $1', [tenantId]);
  return row || null;
}

async function createTenant({ tenantId, name, slug, plan, billingEmail, cmkArn, settings }) {
  await pool.query(`
    INSERT INTO tenants (tenant_id, name, slug, plan, billing_email, cmk_arn, cmk_key_id, settings)
    VALUES ($1,$2,$3,$4,$5,$6,$6,$7::jsonb)
  `, [
    tenantId, name, slug, plan || 'free', billingEmail || null, cmkArn || null,
    JSON.stringify(settings || {}),
  ]);
}

async function listTenants() {
  return (await pool.query('SELECT * FROM tenants ORDER BY created_at ASC')).rows;
}

async function updateTenant(tenantId, patch) {
  const fields = [];
  const vals = [];
  let i = 1;
  for (const [k, col] of [
    ['name', 'name'], ['slug', 'slug'], ['plan', 'plan'], ['status', 'status'],
    ['billingEmail', 'billing_email'], ['cmkArn', 'cmk_arn'], ['cmkKeyId', 'cmk_key_id'],
  ]) {
    if (patch[k] !== undefined) {
      fields.push(`${col} = $${i++}`);
      vals.push(patch[k]);
    }
  }
  if (patch.settings !== undefined) {
    fields.push(`settings = $${i++}::jsonb`);
    vals.push(JSON.stringify(patch.settings));
  }
  if (!fields.length) return getTenant(tenantId);
  fields.push('updated_at = NOW()');
  vals.push(tenantId);
  await pool.query(`UPDATE tenants SET ${fields.join(', ')} WHERE tenant_id = $${i}`, vals);
  return getTenant(tenantId);
}

async function linkFederatedIdentity({ userId, provider, subject, email, claims, tenantId }) {
  await pool.query(`
    INSERT INTO federated_identities (user_id, provider, subject, email, claims, tenant_id)
    VALUES ($1,$2,$3,$4,$5::jsonb,$6)
    ON CONFLICT (provider, subject) DO UPDATE SET
      user_id = EXCLUDED.user_id,
      email = EXCLUDED.email,
      claims = EXCLUDED.claims,
      tenant_id = EXCLUDED.tenant_id,
      linked_at = NOW()
  `, [userId, provider, subject, email || null, JSON.stringify(claims || {}), tenantId || 'default']);
}

async function getFederatedIdentity(provider, subject) {
  const { rows: [row] } = await pool.query(
    'SELECT * FROM federated_identities WHERE provider = $1 AND subject = $2',
    [provider, subject]
  );
  return row || null;
}

async function listUsersByTenant(tenantId) {
  const { rows } = await pool.query(
    'SELECT user_id, role, status, email, tenant_id, did, created_at FROM users WHERE tenant_id = $1',
    [tenantId]
  );
  return rows;
}

async function recordBillingEvent(tenantId, eventType, amountCents, metadata) {
  await pool.query(
    `INSERT INTO tenant_billing_events (tenant_id, event_type, amount_cents, metadata)
     VALUES ($1,$2,$3,$4::jsonb)`,
    [tenantId, eventType, amountCents ?? null, JSON.stringify(metadata || {})]
  );
}

async function listBillingEvents(tenantId, limit = 20) {
  const { rows } = await pool.query(
    `SELECT * FROM tenant_billing_events WHERE tenant_id = $1
     ORDER BY created_at DESC LIMIT $2`,
    [tenantId, limit]
  );
  return rows;
}

async function setTenantStripeCustomer(tenantId, customerId) {
  await pool.query(
    `UPDATE tenants SET stripe_customer_id = $1, updated_at = NOW() WHERE tenant_id = $2`,
    [customerId, tenantId]
  );
}

async function setTenantSubscription(tenantId, {
  stripeSubscriptionId,
  plan,
  status,
  periodEnd,
  cancelAtPeriodEnd,
} = {}) {
  const sets = ['updated_at = NOW()'];
  const vals = [];
  let i = 1;
  if (stripeSubscriptionId !== undefined) {
    sets.push(`stripe_subscription_id = $${i++}`);
    vals.push(stripeSubscriptionId);
  }
  if (plan !== undefined) {
    sets.push(`plan = $${i++}`);
    vals.push(plan);
  }
  if (status !== undefined) {
    sets.push(`subscription_status = $${i++}`);
    vals.push(status);
  }
  if (periodEnd !== undefined) {
    sets.push(`subscription_period_end = $${i++}`);
    vals.push(periodEnd);
  }
  if (cancelAtPeriodEnd !== undefined) {
    sets.push(`cancel_at_period_end = $${i++}`);
    vals.push(cancelAtPeriodEnd ? 1 : 0);
  }
  vals.push(tenantId);
  await pool.query(`UPDATE tenants SET ${sets.join(', ')} WHERE tenant_id = $${i}`, vals);
}

async function findTenantByStripeCustomer(customerId) {
  if (!customerId) return null;
  const { rows: [row] } = await pool.query(
    'SELECT * FROM tenants WHERE stripe_customer_id = $1',
    [customerId]
  );
  return row || null;
}

async function getAllUsers() {
  const { rows } = await pool.query('SELECT user_id, role, status, did, created_at FROM users');
  return rows.map((row) => ({
    ...row,
    created_at: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
  }));
}

/**
 * Admin directory: users with device/session counts and last login (no password hashes).
 * Risk scores are omitted from the public admin list (use audit for investigations).
 */
async function getAdminUserDirectory() {
  const { rows } = await pool.query(`
    SELECT
      u.user_id AS username,
      u.user_id AS "userId",
      u.role,
      u.status,
      u.email,
      u.phone,
      u.usual_country AS "usualCountry",
      u.usual_city AS "usualCity",
      u.created_at,
      (SELECT COUNT(*)::int FROM devices d WHERE d.user_id = u.user_id) AS "deviceCount",
      (SELECT COUNT(*)::int FROM refresh_tokens r
        WHERE r.user_id = u.user_id AND r.status = 'ACTIVE' AND r.expires_at > NOW()) AS "activeSessions",
      (SELECT EXISTS(SELECT 1 FROM mfa_secrets m WHERE m.user_id = u.user_id AND m.enabled = 1)) AS "mfaEnabled",
      lh.timestamp AS "lastLoginAt",
      lh.country AS "lastLoginCountry",
      lh.city AS "lastLoginCity",
      lh.decision AS "lastLoginDecision"
    FROM users u
    LEFT JOIN LATERAL (
      SELECT timestamp, country, city, decision
      FROM login_history
      WHERE user_id = u.user_id
      ORDER BY timestamp DESC
      LIMIT 1
    ) lh ON TRUE
    ORDER BY u.created_at DESC NULLS LAST, u.user_id ASC
  `);
  return rows.map((row) => ({
    ...row,
    created_at: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
    lastLoginAt: row.lastLoginAt instanceof Date ? row.lastLoginAt.toISOString() : row.lastLoginAt,
    mfaEnabled: !!row.mfaEnabled,
  }));
}

async function getAdminOverview() {
  const { rows: [counts] } = await pool.query(`
    SELECT
      (SELECT COUNT(*)::int FROM users WHERE status = 'ACTIVE') AS "activeUsers",
      (SELECT COUNT(*)::int FROM users WHERE status = 'SUSPENDED') AS "suspendedUsers",
      (SELECT COUNT(*)::int FROM users WHERE status = 'DELETED') AS "deletedUsers",
      (SELECT COUNT(*)::int FROM users) AS "totalUsers",
      (SELECT COUNT(*)::int FROM devices) AS "totalDevices",
      (SELECT COUNT(*)::int FROM refresh_tokens WHERE status = 'ACTIVE' AND expires_at > NOW()) AS "activeSessions",
      (SELECT COUNT(*)::int FROM local_audit_log WHERE created_at > NOW() - INTERVAL '24 hours') AS "auditLast24h"
  `);
  return counts || {};
}

async function registerDevice(userId, deviceId, label) {
  await pool.query(
    `INSERT INTO devices (user_id, device_id, label) VALUES ($1, $2, $3)
     ON CONFLICT (user_id, device_id) DO UPDATE SET
       label = COALESCE(EXCLUDED.label, devices.label)`,
    [userId, deviceId, label ?? null]
  );
}

async function getUserDevices(userId) {
  const { rows } = await pool.query(
    `
    SELECT
      d.device_id,
      d.label,
      d.registered_at,
      lh.timestamp AS last_seen_at,
      lh.country AS last_country,
      lh.city AS last_city,
      lh.decision AS last_decision
    FROM devices d
    LEFT JOIN LATERAL (
      SELECT timestamp, country, city, decision
      FROM login_history h
      WHERE h.user_id = d.user_id AND h.device_id = d.device_id
      ORDER BY h.timestamp DESC
      LIMIT 1
    ) lh ON TRUE
    WHERE d.user_id = $1
    ORDER BY COALESCE(lh.timestamp, d.registered_at) DESC NULLS LAST
    `,
    [userId]
  );
  return rows;
}

async function storeRefreshToken(token, userId, expiresAt, opts = {}) {
  // family_id is generated server-side when omitted (new family on login). When
  // a token rotates within a family, callers pass opts.familyId + opts.parentTokenHash.
  const familyId = opts.familyId || null;
  const parentHash = opts.parentTokenHash || null;
  if (familyId) {
    await pool.query(
      `INSERT INTO refresh_tokens (token, user_id, expires_at, family_id, parent_token_hash, status)
       VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
      [token, userId, expiresAt, familyId, parentHash]
    );
  } else {
    await pool.query(
      `INSERT INTO refresh_tokens (token, user_id, expires_at, family_id, parent_token_hash, status)
       VALUES ($1, $2, $3, gen_random_uuid(), $4, 'ACTIVE')`,
      [token, userId, expiresAt, parentHash]
    );
  }
}

async function isRefreshTokenValid(token) {
  const { rows: [row] } = await pool.query(
    "SELECT 1 FROM refresh_tokens WHERE token = $1 AND status = 'ACTIVE' AND expires_at > NOW()",
    [token]
  );
  return !!row;
}

async function getRefreshTokenStatus(token) {
  const { rows: [row] } = await pool.query(
    'SELECT status, family_id, user_id, expires_at FROM refresh_tokens WHERE token = $1',
    [token]
  );
  if (!row) return null;
  return {
    status: row.status,
    familyId: row.family_id,
    userId: row.user_id,
    expiresAt: row.expires_at instanceof Date ? row.expires_at.toISOString() : row.expires_at,
  };
}

async function markRefreshTokenRotated(token) {
  const { rows: [row] } = await pool.query(
    "UPDATE refresh_tokens SET status = 'ROTATED' WHERE token = $1 RETURNING family_id",
    [token]
  );
  return row ? row.family_id : null;
}

async function markFamilyCompromised(familyId, reason) {
  if (!familyId) return 0;
  const { rowCount } = await pool.query(
    "UPDATE refresh_tokens SET status = 'COMPROMISED' WHERE family_id = $1 AND status <> 'COMPROMISED'",
    [familyId]
  );
  // reason is logged by the caller; persisted only via audit log.
  void reason;
  return rowCount;
}

async function revokeRefreshToken(token) {
  await pool.query("UPDATE refresh_tokens SET status = 'REVOKED', revoked = 1 WHERE token = $1", [token]);
}

async function revokeAllUserTokens(userId) {
  await pool.query("UPDATE refresh_tokens SET status = 'REVOKED', revoked = 1 WHERE user_id = $1", [userId]);
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

async function deleteMFASecret(userId) {
  const r = await pool.query('DELETE FROM mfa_secrets WHERE user_id = $1', [userId]);
  await pool.query('DELETE FROM mfa_challenges WHERE user_id = $1', [userId]).catch(() => {});
  return (r.rowCount || 0) > 0;
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

/**
 * User-facing access decision history: audit rows (have reason + real created_at)
 * enriched with geo from nearby login_history when available.
 */
async function getUserAccessHistory(userId, limit = 25) {
  const lim = Math.min(parseInt(limit, 10) || 25, 200);
  const { rows } = await pool.query(
    `
    SELECT
      a.created_at AS timestamp,
      a.decision,
      a.reason,
      a.layer,
      a.device_id,
      a.tx_id,
      lh.country,
      lh.city
    FROM local_audit_log a
    LEFT JOIN LATERAL (
      SELECT country, city
      FROM login_history h
      WHERE h.user_id = a.user_id
        AND (
          h.device_id IS NOT DISTINCT FROM a.device_id
          OR a.device_id IS NULL
          OR h.device_id IS NULL
        )
        AND abs(EXTRACT(EPOCH FROM (h.timestamp - a.created_at))) < 120
      ORDER BY abs(EXTRACT(EPOCH FROM (h.timestamp - a.created_at))) ASC
      LIMIT 1
    ) lh ON TRUE
    WHERE a.user_id = $1
      AND a.decision IN ('ALLOW', 'DENY', 'MFA_REQUIRED', 'STEP_UP')
    ORDER BY a.created_at DESC
    LIMIT $2
    `,
    [userId, lim]
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

// ──────────────────────── Analyst feedback (Tier B.6) ────────────────────────

/**
 * Record a reviewer's label for an audit entry. Reviewers are unique per audit_id —
 * an existing review by the same reviewer is updated in place.
 */
async function recordAuditFeedback({ auditId, label, reviewer, notes }) {
  const valid = new Set(['true_positive', 'false_positive', 'true_negative', 'false_negative']);
  if (!valid.has(label)) {
    throw new Error(`invalid feedback label: ${label}`);
  }
  const { rows: [row] } = await pool.query(
    `INSERT INTO audit_feedback (audit_id, label, reviewer, notes)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (audit_id, reviewer) DO UPDATE SET
       label = EXCLUDED.label, notes = EXCLUDED.notes, reviewed_at = NOW()
     RETURNING id, audit_id, label, reviewer, reviewed_at, notes`,
    [auditId, label, reviewer, notes ?? null]
  );
  return {
    id: row.id,
    auditId: row.audit_id,
    label: row.label,
    reviewer: row.reviewer,
    reviewedAt: row.reviewed_at instanceof Date ? row.reviewed_at.toISOString() : row.reviewed_at,
    notes: row.notes,
  };
}

async function getAuditFeedback(auditId) {
  const { rows } = await pool.query(
    'SELECT id, audit_id, label, reviewer, reviewed_at, notes FROM audit_feedback WHERE audit_id = $1 ORDER BY reviewed_at DESC',
    [auditId]
  );
  return rows.map((row) => ({
    id: row.id,
    auditId: row.audit_id,
    label: row.label,
    reviewer: row.reviewer,
    reviewedAt: row.reviewed_at instanceof Date ? row.reviewed_at.toISOString() : row.reviewed_at,
    notes: row.notes,
  }));
}

async function getRecentFeedback(limit = 100) {
  const { rows } = await pool.query(
    'SELECT id, audit_id, label, reviewer, reviewed_at, notes FROM audit_feedback ORDER BY reviewed_at DESC LIMIT $1',
    [Math.max(1, Math.min(1000, limit))]
  );
  return rows.map((row) => ({
    id: row.id,
    auditId: row.audit_id,
    label: row.label,
    reviewer: row.reviewer,
    reviewedAt: row.reviewed_at instanceof Date ? row.reviewed_at.toISOString() : row.reviewed_at,
    notes: row.notes,
  }));
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

async function rollbackMigrationsTo(targetId) {
  if (!MIGRATIONS.some((m) => m.id === targetId) && targetId !== '0') {
    throw new Error(`Unknown migration id "${targetId}" (use 0 to drop all app migrations).`);
  }
  if (!pool) await init();
  const canon = new Map(MIGRATIONS.map((m, i) => [m.id, i]));
  const targetIdx = targetId === '0' ? -1 : canon.get(targetId);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      'SELECT name FROM schema_migrations ORDER BY applied_at DESC, id DESC'
    );
    for (const { name } of rows) {
      const ix = canon.get(name);
      if (ix === undefined) continue;
      if (targetId === '0' || ix > targetIdx) {
        const m = MIGRATIONS[ix];
        await m.down(client);
        await client.query('DELETE FROM schema_migrations WHERE name = $1', [name]);
      }
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

async function getMigrationStatus() {
  if (!pool) await init();
  const appliedRows = (await pool.query('SELECT name, applied_at FROM schema_migrations ORDER BY applied_at ASC, id ASC'))
    .rows;
  const applied = new Set(appliedRows.map((r) => r.name));
  const pending = MIGRATIONS.filter((m) => !applied.has(m.id)).map((m) => m.id);
  return { applied: appliedRows, pending };
}

module.exports = {
  MIGRATIONS,
  rollbackMigrationsTo,
  getMigrationStatus,
  init,
  getDb,
  close,
  truncateTestData,
  getUser,
  createUser,
  createUserWithHash,
  rollbackNewUser,
  updateUserPassword,
  setUserStatus,
  updateUserContact,
  getAllUsers,
  getAdminUserDirectory,
  getAdminOverview,
  recordNotification,
  listNotifications,
  registerDevice,
  getUserDevices,
  deleteUserDevice,
  listUserSessions,
  revokeUserSession,
  revokeOtherUserSessions,
  eraseUserAccount,
  getAccountLockout,
  incrementLoginFailures,
  setAccountLockout,
  clearAccountLockout,
  listAbacPolicies,
  upsertAbacPolicy,
  deleteAbacPolicy,
  storePasswordResetToken,
  consumePasswordResetToken,
  storeRefreshToken,
  isRefreshTokenValid,
  revokeRefreshToken,
  revokeAllUserTokens,
  getRefreshTokenStatus,
  markRefreshTokenRotated,
  markFamilyCompromised,
  storeMFASecret,
  getMFASecret,
  deleteMFASecret,
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
  getUserAccessHistory,
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
  recordAuditFeedback,
  getAuditFeedback,
  getRecentFeedback,
  // multi-tenancy + federation
  getTenant,
  createTenant,
  listTenants,
  updateTenant,
  linkFederatedIdentity,
  getFederatedIdentity,
  listUsersByTenant,
  recordBillingEvent,
  listBillingEvents,
  setTenantStripeCustomer,
  setTenantSubscription,
  findTenantByStripeCustomer,
  _prepareStatements,
};
