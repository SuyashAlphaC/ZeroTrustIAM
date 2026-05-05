'use strict';

process.env.TEST_DATABASE_URL = process.env.TEST_DATABASE_URL
  || 'postgresql://ztiam:testpassword@127.0.0.1:5432/ztiam_test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'unit-test-jwt';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'unit-test-refresh';
process.env.OAUTH_DEFAULT_CLIENT_SECRET = process.env.OAUTH_DEFAULT_CLIENT_SECRET || 'unit-test-oauth';

const db = require('../../database');

describe('anomalyDetector', () => {
  let detectAnomalies;
  let adjustRiskScore;
  let recordLogin;
  let getProfileSummary;
  let getModelDiagnostics;
  let MODEL_VERSION;

  const baseContext = {
    timestamp: '2026-04-02T10:00:00Z',
    location: { country: 'IN', city: 'Gwalior' },
    deviceId: 'dev-test-001',
  };

  beforeAll(async () => {
    await db.init();
    await db.truncateTestData();
    await db._prepareStatements();
    await db.createUser({ userId: 'test-anomaly-user', password: 'test', role: 'viewer' });
    await db.createUser({ userId: 'travel-test-user', password: 'test', role: 'viewer' });

    ({
      detectAnomalies,
      adjustRiskScore,
      recordLogin,
      getProfileSummary,
      getModelDiagnostics,
      MODEL_VERSION,
    } = require('../../anomalyDetector'));

    const logins = [
      { timestamp: '2026-04-01T09:00:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-test-001' },
      { timestamp: '2026-04-01T10:00:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-test-001' },
      { timestamp: '2026-04-01T11:00:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-test-001' },
      { timestamp: '2026-04-01T14:00:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-test-001' },
    ];
    for (const login of logins) {
      await recordLogin('test-anomaly-user', login);
    }
  });

  afterAll(async () => {
    await db.close();
  });

  describe('detectAnomalies', () => {
    it('returns low anomaly for normal login pattern', async () => {
      const result = await detectAnomalies('test-anomaly-user', baseContext);
      expect(result.combined).toBeLessThan(0.4);
      expect(result.anomalyDetected).toBe(false);
      expect(result.scores.timeAnomaly).toBeDefined();
      expect(result.scores.locationNovelty).toBe(0);
      expect(result.scores.deviceNovelty).toBe(0);
    });

    it('flags unknown location as anomalous', async () => {
      const ctx = { ...baseContext, location: { country: 'RU', city: 'Moscow' } };
      const result = await detectAnomalies('test-anomaly-user', ctx);
      expect(result.scores.locationNovelty).toBe(0.8);
    });

    it('flags unknown device as anomalous', async () => {
      const ctx = { ...baseContext, deviceId: 'unknown-device-xyz' };
      const result = await detectAnomalies('test-anomaly-user', ctx);
      expect(result.scores.deviceNovelty).toBe(0.6);
    });

    it('detects impossible travel', async () => {
      await recordLogin('travel-test-user', {
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'IN', city: 'Gwalior' },
        deviceId: 'dev-travel',
      });
      const result = await detectAnomalies('travel-test-user', {
        timestamp: '2026-04-02T10:30:00Z',
        location: { country: 'US', city: 'New York' },
        deviceId: 'dev-travel',
      });
      expect(result.scores.travelAnomaly).toBe(1.0);
    });

    it('returns 0 time anomaly with insufficient samples', async () => {
      await db.createUser({ userId: 'brand-new-user-123', password: 'test', role: 'viewer' });
      const result = await detectAnomalies('brand-new-user-123', baseContext);
      expect(result.scores.timeAnomaly).toBe(0);
      expect(result.profileMaturity).toBe(0);
    });

    it('includes model version in result', async () => {
      const result = await detectAnomalies('test-anomaly-user', baseContext);
      expect(result.modelVersion).toBe(MODEL_VERSION);
    });

    it('includes human-readable explanations', async () => {
      const ctx = { ...baseContext, location: { country: 'CN', city: 'Beijing' }, deviceId: 'new-dev-999' };
      const result = await detectAnomalies('test-anomaly-user', ctx);
      expect(result.explanation.length).toBeGreaterThan(0);
      expect(result.explanation.some(e => e.includes('never been seen'))).toBe(true);
    });
  });

  describe('adjustRiskScore', () => {
    it('adjusts risk score based on anomaly detection', async () => {
      const result = await adjustRiskScore(0.2, 'test-anomaly-user', baseContext);
      expect(result.originalRiskScore).toBe(0.2);
      expect(result.adjustedRiskScore).toBeGreaterThanOrEqual(0.2);
      expect(result.anomalyAdjustment).toBeDefined();
      expect(result.anomaly).toBeDefined();
    });

    it('caps adjusted risk score at 1.0', async () => {
      const result = await adjustRiskScore(0.99, 'test-anomaly-user', {
        ...baseContext,
        location: { country: 'CN', city: 'Beijing' },
        deviceId: 'unknown-dev',
      });
      expect(result.adjustedRiskScore).toBeLessThanOrEqual(1.0);
    });
  });

  describe('getProfileSummary', () => {
    it('returns profile summary for existing user', async () => {
      const summary = await getProfileSummary('test-anomaly-user');
      expect(summary.userId).toBe('test-anomaly-user');
      expect(summary.knownLocations).toContain('IN:Gwalior');
      expect(summary.knownDevices).toContain('dev-test-001');
      expect(summary.loginHours.samples).toBeGreaterThan(0);
    });

    it('returns default profile for new user', async () => {
      await db.createUser({ userId: 'nonexistent-user-xyz', password: 'test', role: 'viewer' });
      const summary = await getProfileSummary('nonexistent-user-xyz');
      expect(summary.loginHours.samples).toBe(0);
      expect(summary.knownLocations).toHaveLength(0);
    });
  });

  describe('getModelDiagnostics', () => {
    it('returns complete diagnostics', () => {
      const config = require('../../config');
      const diag = getModelDiagnostics();
      expect(diag.modelVersion).toBe(MODEL_VERSION);
      expect(diag.anomalyWeight).toBe(config.anomalyWeight);
      expect(diag.detectionThreshold).toBe(config.anomalyThreshold);
      expect(diag.coldStart.minSamples).toBe(config.anomalyColdStartMinSamples);
      expect(diag.weights).toBeDefined();
    });
  });
});
