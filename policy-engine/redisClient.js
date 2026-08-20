'use strict';

/**
 * Shared Redis client for decision cache, failed-attempt counters, and lockouts.
 * Failures degrade gracefully — callers must treat Redis as best-effort and
 * fall back to in-process / Postgres state when unavailable.
 */

const { logger } = require('./logger');

const redisUrl = process.env.REDIS_URL || 'redis://redis:6379';
const wantRedis = (process.env.REDIS_ENABLED || process.env.DECISION_CACHE_ENABLED || 'true')
  .toLowerCase() !== 'false';

let client = null;
let disabled = !wantRedis;
let warned = false;

function getClient() {
  if (disabled) return null;
  if (client) return client;
  try {
    // eslint-disable-next-line global-require
    const Redis = require('ioredis');
    client = new Redis(redisUrl, {
      lazyConnect: false,
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      connectTimeout: 2000,
    });
    client.on('error', (err) => {
      if (!warned) {
        warned = true;
        logger.warn({ err: err.message }, 'redis: connection error (will fall back)');
      }
    });
    return client;
  } catch (err) {
    if (!warned) {
      warned = true;
      logger.warn({ err: err.message }, 'redis: ioredis unavailable, disabling');
    }
    disabled = true;
    return null;
  }
}

/**
 * @param {string} key
 * @returns {Promise<string|null>}
 */
async function get(key) {
  const c = getClient();
  if (!c) return null;
  try {
    return await c.get(key);
  } catch (err) {
    logger.debug({ err: err.message, key }, 'redis get failed');
    return null;
  }
}

/**
 * @param {string} key
 * @param {string|number} value
 * @param {number} [ttlSeconds]
 */
async function set(key, value, ttlSeconds) {
  const c = getClient();
  if (!c) return false;
  try {
    if (ttlSeconds && ttlSeconds > 0) {
      await c.set(key, String(value), 'EX', ttlSeconds);
    } else {
      await c.set(key, String(value));
    }
    return true;
  } catch (err) {
    logger.debug({ err: err.message, key }, 'redis set failed');
    return false;
  }
}

/**
 * Atomic INCR with optional expiry on first creation.
 * @param {string} key
 * @param {number} [ttlSeconds]
 * @returns {Promise<number|null>} new value, or null if Redis unavailable
 */
async function incr(key, ttlSeconds) {
  const c = getClient();
  if (!c) return null;
  try {
    const n = await c.incr(key);
    if (n === 1 && ttlSeconds && ttlSeconds > 0) {
      await c.expire(key, ttlSeconds);
    }
    return n;
  } catch (err) {
    logger.debug({ err: err.message, key }, 'redis incr failed');
    return null;
  }
}

/**
 * @param {string} key
 */
async function del(key) {
  const c = getClient();
  if (!c) return false;
  try {
    await c.del(key);
    return true;
  } catch (err) {
    logger.debug({ err: err.message, key }, 'redis del failed');
    return false;
  }
}

/**
 * @param {string} key
 * @returns {Promise<number|null>} TTL in seconds, -1 if no expiry, -2 if missing
 */
async function ttl(key) {
  const c = getClient();
  if (!c) return null;
  try {
    return await c.ttl(key);
  } catch (err) {
    return null;
  }
}

async function close() {
  if (client) {
    try {
      await client.quit();
    } catch {
      /* ignore */
    }
    client = null;
  }
}

function __resetForTests() {
  client = null;
  disabled = !wantRedis;
  warned = false;
}

module.exports = {
  getClient,
  get,
  set,
  incr,
  del,
  ttl,
  close,
  __resetForTests,
  __isDisabled: () => disabled,
};
