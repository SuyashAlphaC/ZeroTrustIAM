// Optional Redis-backed cache for ALLOW decisions.
//
// Keyed on the user's stable risk-relevant context. DENY/STEP_UP decisions are
// NEVER cached so that a transient ALLOW cannot be replayed past a policy
// change. Failures degrade silently — the cache is best-effort and must never
// break the request path.
'use strict';

const { logger } = require('./logger');

const enabled = (process.env.DECISION_CACHE_ENABLED || 'false').toLowerCase() === 'true';
const redisUrl = process.env.REDIS_URL || 'redis://redis:6379';
const ttlSeconds = parseInt(process.env.DECISION_CACHE_TTL_SECONDS || '60', 10);

let client = null;
let disabled = !enabled;
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
    });
    client.on('error', (err) => {
      if (!warned) {
        warned = true;
        logger.warn({ err: err.message }, 'decision cache: redis connection error, disabling');
      }
      disabled = true;
    });
    return client;
  } catch (err) {
    if (!warned) {
      warned = true;
      logger.warn({ err: err.message }, 'decision cache: ioredis unavailable, disabling');
    }
    disabled = true;
    return null;
  }
}

function buildCacheKey({ userId, deviceId, country, city, hourBucket, requiredPermission } = {}) {
  const bucket = hourBucket !== undefined ? hourBucket : Math.floor(Date.now() / 3600000);
  return [
    'dc',
    userId || '-',
    deviceId || '-',
    country || '-',
    city || '-',
    bucket,
    requiredPermission || '-',
  ].join(':');
}

async function getCachedDecision(key) {
  if (disabled) return null;
  const c = getClient();
  if (!c) return null;
  try {
    const raw = await c.get(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return { ...parsed, fromCache: true };
  } catch (err) {
    if (!warned) {
      warned = true;
      logger.warn({ err: err.message }, 'decision cache get failed');
    }
    return null;
  }
}

async function setCachedDecision(key, decision) {
  if (disabled) return;
  if (!decision || decision.decision !== 'ALLOW') return; // never cache DENY/STEP_UP
  const c = getClient();
  if (!c) return;
  try {
    await c.set(key, JSON.stringify(decision), 'EX', ttlSeconds);
  } catch (err) {
    if (!warned) {
      warned = true;
      logger.warn({ err: err.message }, 'decision cache set failed');
    }
  }
}

async function close() {
  if (client) {
    try { await client.quit(); } catch (_) { /* ignore */ }
    client = null;
  }
}

module.exports = {
  getCachedDecision,
  setCachedDecision,
  buildCacheKey,
  close,
  // Test-only helpers:
  __isDisabled: () => disabled,
};
