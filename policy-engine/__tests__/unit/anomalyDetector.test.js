'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');

// Setup test database before requiring any modules that depend on it
const TEST_DB_DIR = path.join(os.tmpdir(), `zt-iam-anomaly-test-${Date.now()}`);
process.env.DB_PATH = path.join(TEST_DB_DIR, 'test.db');

const db = require('../../database');

// Initialize DB before loading anomaly detector
db.init();
db._prepareStatements();

// Create a test user so anomaly_profiles foreign key is satisfied
db.createUser({ userId: 'test-anomaly-user', password: 'test', role: 'viewer' });
db.createUser({ userId: 'travel-test-user', password: 'test', role: 'viewer' });

const {
  detectAnomalies,
  adjustRiskScore,
  recordLogin,
  getProfileSummary,
  getModelDiagnostics,
  MODEL_VERSION,
} = require('../../anomalyDetector');

const config = require('../../config');

describe('anomalyDetector', () => {
  const baseContext = {
    timestamp: '2026-04-02T10:00:00Z',
    location: { country: 'IN', city: 'Gwalior' },
    deviceId: 'dev-test-001',
  };

  beforeAll(() => {
    const logins = [
      { timestamp: '2026-04-01T09:00:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-test-001' },
      { timestamp: '2026-04-01T10:00:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-test-001' },
      { timestamp: '2026-04-01T11:00:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-test-001' },
      { timestamp: '2026-04-01T14:00:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-test-001' },
    ];
    for (const login of logins) {
      recordLogin('test-anomaly-user', login);
    }
  });

  afterAll(() => {
    db.close();
    try { fs.rmSync(TEST_DB_DIR, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  describe('detectAnomalies', () => {
    it('returns low anomaly for normal login pattern', () => {
      const result = detectAnomalies('test-anomaly-user', baseContext);
      expect(result.combined).toBeLessThan(0.4);
      expect(result.anomalyDetected).toBe(false);
      expect(result.scores.timeAnomaly).toBeDefined();
      expect(result.scores.locationNovelty).toBe(0);
      expect(result.scores.deviceNovelty).toBe(0);
    });

    it('flags unknown location as anomalous', () => {
      const ctx = { ...baseContext, location: { country: 'RU', city: 'Moscow' } };
      const result = detectAnomalies('test-anomaly-user', ctx);
      expect(result.scores.locationNovelty).toBe(0.8);
    });

    it('flags unknown device as anomalous', () => {
      const ctx = { ...baseContext, deviceId: 'unknown-device-xyz' };
      const result = detectAnomalies('test-anomaly-user', ctx);
      expect(result.scores.deviceNovelty).toBe(0.6);
    });

    it('detects impossible travel', () => {
      recordLogin('travel-test-user', {
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'IN', city: 'Gwalior' },
        deviceId: 'dev-travel',
      });
      const result = detectAnomalies('travel-test-user', {
        timestamp: '2026-04-02T10:30:00Z',
        location: { country: 'US', city: 'New York' },
        deviceId: 'dev-travel',
      });
      expect(result.scores.travelAnomaly).toBe(1.0);
    });

    it('returns 0 time anomaly with insufficient samples', () => {
      db.createUser({ userId: 'brand-new-user-123', password: 'test', role: 'viewer' });
      const result = detectAnomalies('brand-new-user-123', baseContext);
      expect(result.scores.timeAnomaly).toBe(0);
      expect(result.profileMaturity).toBe(0);
    });

    it('includes model version in result', () => {
      const result = detectAnomalies('test-anomaly-user', baseContext);
      expect(result.modelVersion).toBe(MODEL_VERSION);
    });

    it('includes human-readable explanations', () => {
      const ctx = { ...baseContext, location: { country: 'CN', city: 'Beijing' }, deviceId: 'new-dev-999' };
      const result = detectAnomalies('test-anomaly-user', ctx);
      expect(result.explanation.length).toBeGreaterThan(0);
      expect(result.explanation.some(e => e.includes('never been seen'))).toBe(true);
    });
  });

  describe('adjustRiskScore', () => {
    it('adjusts risk score based on anomaly detection', () => {
      const result = adjustRiskScore(0.2, 'test-anomaly-user', baseContext);
      expect(result.originalRiskScore).toBe(0.2);
      expect(result.adjustedRiskScore).toBeGreaterThanOrEqual(0.2);
      expect(result.anomalyAdjustment).toBeDefined();
      expect(result.anomaly).toBeDefined();
    });

    it('caps adjusted risk score at 1.0', () => {
      const result = adjustRiskScore(0.99, 'test-anomaly-user', {
        ...baseContext,
        location: { country: 'CN', city: 'Beijing' },
        deviceId: 'unknown-dev',
      });
      expect(result.adjustedRiskScore).toBeLessThanOrEqual(1.0);
    });
  });

  describe('getProfileSummary', () => {
    it('returns profile summary for existing user', () => {
      const summary = getProfileSummary('test-anomaly-user');
      expect(summary.userId).toBe('test-anomaly-user');
      expect(summary.knownLocations).toContain('IN:Gwalior');
      expect(summary.knownDevices).toContain('dev-test-001');
      expect(summary.loginHours.samples).toBeGreaterThan(0);
    });

    it('returns default profile for new user', () => {
      db.createUser({ userId: 'nonexistent-user-xyz', password: 'test', role: 'viewer' });
      const summary = getProfileSummary('nonexistent-user-xyz');
      expect(summary.loginHours.samples).toBe(0);
      expect(summary.knownLocations).toHaveLength(0);
    });
  });

  describe('getModelDiagnostics', () => {
    it('returns complete diagnostics', () => {
      const diag = getModelDiagnostics();
      expect(diag.modelVersion).toBe(MODEL_VERSION);
      expect(diag.anomalyWeight).toBe(config.anomalyWeight);
      expect(diag.detectionThreshold).toBe(config.anomalyThreshold);
      expect(diag.weights).toBeDefined();
    });
  });
});
