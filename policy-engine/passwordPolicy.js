'use strict';

/**
 * Password policy validation and (optional) Argon2id hashing.
 * bcrypt remains the default for compatibility; set PASSWORD_HASHER=argon2id
 * for new hashes. Verification accepts both bcrypt and argon2id prefixes.
 */

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const config = require('./config');

const MIN_LENGTH = parseInt(process.env.PASSWORD_MIN_LENGTH || '12', 10);
const REQUIRE_UPPER = process.env.PASSWORD_REQUIRE_UPPER !== 'false';
const REQUIRE_LOWER = process.env.PASSWORD_REQUIRE_LOWER !== 'false';
const REQUIRE_DIGIT = process.env.PASSWORD_REQUIRE_DIGIT !== 'false';
const REQUIRE_SPECIAL = process.env.PASSWORD_REQUIRE_SPECIAL === 'true';
const HASHER = (process.env.PASSWORD_HASHER || 'bcrypt').toLowerCase();

// Common weak passwords blocklist (subset — production should use HIBP k-anonymity)
const BLOCKLIST = new Set([
  'password', 'password123', 'password1234', '12345678', '123456789', '1234567890',
  'qwerty123', 'letmein', 'welcome1', 'admin123', 'changeme', 'passw0rd',
  'iloveyou', 'monkey123', 'dragon123', 'master123', 'login1234',
]);

/**
 * @param {string} password
 * @param {{username?: string}} [opts]
 * @returns {{ ok: boolean, errors: string[] }}
 */
function validatePassword(password, opts = {}) {
  const errors = [];
  if (typeof password !== 'string' || password.length < MIN_LENGTH) {
    errors.push(`Password must be at least ${MIN_LENGTH} characters`);
  }
  if (password && password.length > 128) {
    errors.push('Password must be at most 128 characters');
  }
  if (REQUIRE_UPPER && password && !/[A-Z]/.test(password)) {
    errors.push('Password must include an uppercase letter');
  }
  if (REQUIRE_LOWER && password && !/[a-z]/.test(password)) {
    errors.push('Password must include a lowercase letter');
  }
  if (REQUIRE_DIGIT && password && !/[0-9]/.test(password)) {
    errors.push('Password must include a digit');
  }
  if (REQUIRE_SPECIAL && password && !/[^A-Za-z0-9]/.test(password)) {
    errors.push('Password must include a special character');
  }
  if (password && BLOCKLIST.has(password.toLowerCase())) {
    errors.push('Password is too common');
  }
  if (opts.username && password && password.toLowerCase().includes(String(opts.username).toLowerCase())) {
    errors.push('Password must not contain the username');
  }
  // Reject all-same-character passwords
  if (password && /^(.)\1+$/.test(password)) {
    errors.push('Password is too repetitive');
  }
  return { ok: errors.length === 0, errors };
}

/**
 * @param {string} password
 * @returns {Promise<string>}
 */
async function hashPassword(password) {
  if (HASHER === 'argon2id') {
    try {
      // Optional dependency — use crypto.scrypt as portable Argon2-adjacent fallback
      // when argon2 package is not installed. Prefer native argon2 when available.
      let argon2;
      try {
        // eslint-disable-next-line global-require, import/no-extraneous-dependencies
        argon2 = require('argon2');
      } catch {
        argon2 = null;
      }
      if (argon2) {
        return argon2.hash(password, { type: argon2.argon2id });
      }
      // scrypt-based portable hash with identifiable prefix
      const salt = crypto.randomBytes(16);
      const derived = await new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, 32, { N: 16384, r: 8, p: 1 }, (err, key) => {
          if (err) reject(err);
          else resolve(key);
        });
      });
      return `$scrypt$N=16384$r=8$p=1$${salt.toString('base64')}$${derived.toString('base64')}`;
    } catch (err) {
      // fall through to bcrypt
    }
  }
  return bcrypt.hash(password, config.bcryptRounds);
}

/**
 * @param {string} password
 * @param {string} storedHash
 * @returns {Promise<boolean>}
 */
async function verifyPassword(password, storedHash) {
  if (!storedHash) return false;
  if (storedHash.startsWith('$argon2')) {
    try {
      // eslint-disable-next-line global-require, import/no-extraneous-dependencies
      const argon2 = require('argon2');
      return argon2.verify(storedHash, password);
    } catch {
      return false;
    }
  }
  if (storedHash.startsWith('$scrypt$')) {
    try {
      const parts = storedHash.split('$');
      // $ scrypt $ N=... $ r=... $ p=... $ salt $ hash
      const salt = Buffer.from(parts[5], 'base64');
      const expected = Buffer.from(parts[6], 'base64');
      const derived = await new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, expected.length, { N: 16384, r: 8, p: 1 }, (err, key) => {
          if (err) reject(err);
          else resolve(key);
        });
      });
      return crypto.timingSafeEqual(expected, derived);
    } catch {
      return false;
    }
  }
  // bcrypt ($2a$, $2b$, $2y$)
  return bcrypt.compare(password, storedHash);
}

/**
 * Constant-time dummy verify to reduce user-enumeration timing side channels.
 */
async function dummyVerify() {
  const dummy = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.G2oQ5qJ5qJ5qJu';
  try {
    await bcrypt.compare('timing-pad', dummy);
  } catch {
    /* ignore */
  }
}

module.exports = {
  validatePassword,
  hashPassword,
  verifyPassword,
  dummyVerify,
  MIN_LENGTH,
};
