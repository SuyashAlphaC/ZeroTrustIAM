'use strict';

// ioredis is fully mocked — no real Redis connection.
// Variables prefixed with `mock` are allowed inside jest.mock factory.
const mockSet = jest.fn();
const mockGet = jest.fn();
const mockQuit = jest.fn();
const mockOn = jest.fn();

jest.mock('ioredis', () => {
  return jest.fn().mockImplementation(() => ({
    set: mockSet,
    get: mockGet,
    quit: mockQuit,
    on: mockOn,
  }));
}, { virtual: true });

describe('decisionCache', () => {
  let cache;

  beforeEach(() => {
    jest.resetModules();
    mockSet.mockReset();
    mockGet.mockReset();
    mockQuit.mockReset();
    mockOn.mockReset();
    delete process.env.DECISION_CACHE_ENABLED;
    delete process.env.DECISION_CACHE_TTL_SECONDS;
  });

  afterEach(async () => {
    if (cache) await cache.close();
  });

  test('disabled by default: gets return null, sets are no-ops', async () => {
    cache = require('../../decisionCache');
    expect(cache.__isDisabled()).toBe(true);
    expect(await cache.getCachedDecision('key')).toBeNull();
    await cache.setCachedDecision('key', { decision: 'ALLOW' });
    expect(mockSet).not.toHaveBeenCalled();
  });

  test('buildCacheKey is deterministic for the same inputs', () => {
    cache = require('../../decisionCache');
    const a = cache.buildCacheKey({
      userId: 'alice', deviceId: 'dev-1', country: 'IN', city: 'Gwalior',
      hourBucket: 12345, requiredPermission: 'read',
    });
    const b = cache.buildCacheKey({
      userId: 'alice', deviceId: 'dev-1', country: 'IN', city: 'Gwalior',
      hourBucket: 12345, requiredPermission: 'read',
    });
    expect(a).toBe(b);
    const c = cache.buildCacheKey({
      userId: 'bob', deviceId: 'dev-1', country: 'IN', city: 'Gwalior',
      hourBucket: 12345, requiredPermission: 'read',
    });
    expect(c).not.toBe(a);
  });

  test('DENY decisions are never cached', async () => {
    process.env.DECISION_CACHE_ENABLED = 'true';
    cache = require('../../decisionCache');
    await cache.setCachedDecision('k', { decision: 'DENY', reason: 'risk' });
    await cache.setCachedDecision('k', { decision: 'STEP_UP', reason: 'mfa' });
    expect(mockSet).not.toHaveBeenCalled();
  });

  test('ALLOW decisions are JSON-serialized with EX TTL', async () => {
    process.env.DECISION_CACHE_ENABLED = 'true';
    process.env.DECISION_CACHE_TTL_SECONDS = '90';
    mockSet.mockResolvedValueOnce('OK');
    cache = require('../../decisionCache');
    const dec = { decision: 'ALLOW', reason: 'ok', riskScore: 0.1 };
    await cache.setCachedDecision('mykey', dec);
    expect(mockSet).toHaveBeenCalledTimes(1);
    expect(mockSet.mock.calls[0][0]).toBe('mykey');
    expect(JSON.parse(mockSet.mock.calls[0][1])).toEqual(dec);
    expect(mockSet.mock.calls[0][2]).toBe('EX');
    expect(mockSet.mock.calls[0][3]).toBe(90);
  });

  test('getCachedDecision returns parsed object with fromCache flag', async () => {
    process.env.DECISION_CACHE_ENABLED = 'true';
    mockGet.mockResolvedValueOnce(JSON.stringify({ decision: 'ALLOW', reason: 'ok' }));
    cache = require('../../decisionCache');
    const result = await cache.getCachedDecision('mykey');
    expect(result).toEqual({ decision: 'ALLOW', reason: 'ok', fromCache: true });
  });
});
