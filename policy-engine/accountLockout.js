'use strict';

/**
 * Distributed failed-attempt tracking + account lockout.
 *
 * Prefer Redis (shared across replicas). Fall back to Postgres counters, then
 * process-local Map when neither is available (tests / single-node dev).
 */

const redis = require('./redisClient');
const db = require('./database');
const config = require('./config');
const { logger } = require('./logger');

const WINDOW_SECONDS = parseInt(process.env.LOCKOUT_WINDOW_SECONDS || '900', 10); // 15 min
const MAX_ATTEMPTS = parseInt(process.env.LOCKOUT_MAX_ATTEMPTS || '5', 10);
const LOCKOUT_SECONDS = parseInt(process.env.LOCKOUT_DURATION_SECONDS || '900', 10); // 15 min

// Process-local fallback (tests / no Redis)
const localAttempts = new Map();
const localLocks = new Map();

function attemptKey(username) {
  return `ztiam:fail:${String(username).toLowerCase()}`;
}

function lockKey(username) {
  return `ztiam:lock:${String(username).toLowerCase()}`;
}

/**
 * @param {string} username
 * @returns {Promise<{ locked: boolean, remainingSeconds?: number, reason?: string }>}
 */
async function isLocked(username) {
  if (!username) return { locked: false };

  // Redis
  const until = await redis.get(lockKey(username));
  if (until) {
    const remaining = Math.max(0, Math.ceil((parseInt(until, 10) - Date.now()) / 1000));
    if (remaining > 0) {
      return { locked: true, remainingSeconds: remaining, reason: 'account_locked' };
    }
    await redis.del(lockKey(username));
  }

  // Postgres
  try {
    const row = await db.getAccountLockout(username);
    if (row && row.locked_until) {
      const lockedUntil = new Date(row.locked_until).getTime();
      if (lockedUntil > Date.now()) {
        return {
          locked: true,
          remainingSeconds: Math.ceil((lockedUntil - Date.now()) / 1000),
          reason: 'account_locked',
        };
      }
    }
  } catch (err) {
    logger.debug({ err: err.message }, 'lockout: postgres check failed');
  }

  // Local
  const localUntil = localLocks.get(username);
  if (localUntil && localUntil > Date.now()) {
    return {
      locked: true,
      remainingSeconds: Math.ceil((localUntil - Date.now()) / 1000),
      reason: 'account_locked',
    };
  }
  if (localUntil) localLocks.delete(username);

  return { locked: false };
}

/**
 * @param {string} username
 * @returns {Promise<number>} new attempt count
 */
async function incrementFailedAttempts(username) {
  if (!username) return 0;

  let count = await redis.incr(attemptKey(username), WINDOW_SECONDS);
  if (count === null) {
    // Postgres fallback
    try {
      count = await db.incrementLoginFailures(username, WINDOW_SECONDS);
    } catch {
      const prev = localAttempts.get(username) || { n: 0, exp: 0 };
      if (prev.exp < Date.now()) {
        count = 1;
      } else {
        count = prev.n + 1;
      }
      localAttempts.set(username, { n: count, exp: Date.now() + WINDOW_SECONDS * 1000 });
    }
  }

  if (count >= MAX_ATTEMPTS) {
    await lockAccount(username);
  }
  return count;
}

/**
 * @param {string} username
 */
async function lockAccount(username) {
  const untilMs = Date.now() + LOCKOUT_SECONDS * 1000;
  await redis.set(lockKey(username), String(untilMs), LOCKOUT_SECONDS);
  localLocks.set(username, untilMs);
  try {
    await db.setAccountLockout(username, new Date(untilMs).toISOString(), MAX_ATTEMPTS);
  } catch (err) {
    logger.debug({ err: err.message }, 'lockout: postgres set failed');
  }
  logger.warn({ username, lockoutSeconds: LOCKOUT_SECONDS }, 'Account locked due to failed attempts');
}

/**
 * @param {string} username
 * @returns {Promise<number>}
 */
async function getFailedAttempts(username) {
  if (!username) return 0;
  const raw = await redis.get(attemptKey(username));
  if (raw !== null && raw !== undefined) return parseInt(raw, 10) || 0;
  try {
    const row = await db.getAccountLockout(username);
    if (row) return row.failure_count || 0;
  } catch {
    /* ignore */
  }
  const local = localAttempts.get(username);
  if (local && local.exp > Date.now()) return local.n;
  return 0;
}

/**
 * Clear counters on successful auth.
 * @param {string} username
 */
async function resetFailedAttempts(username) {
  if (!username) return;
  await redis.del(attemptKey(username));
  await redis.del(lockKey(username));
  localAttempts.delete(username);
  localLocks.delete(username);
  try {
    await db.clearAccountLockout(username);
  } catch {
    /* ignore */
  }
}

/**
 * Score component for risk scorer: min(attempts / MAX_ATTEMPTS, 1)
 * @param {string} username
 */
async function getAttemptScore(username) {
  const n = await getFailedAttempts(username);
  return Math.min(n / MAX_ATTEMPTS, 1);
}

module.exports = {
  isLocked,
  incrementFailedAttempts,
  resetFailedAttempts,
  getFailedAttempts,
  getAttemptScore,
  lockAccount,
  MAX_ATTEMPTS,
  LOCKOUT_SECONDS,
  WINDOW_SECONDS,
};
