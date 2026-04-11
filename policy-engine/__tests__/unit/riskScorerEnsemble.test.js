'use strict';

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test-refresh-secret';
process.env.OAUTH_DEFAULT_CLIENT_SECRET = process.env.OAUTH_DEFAULT_CLIENT_SECRET || 'test-oauth-secret';

const { computeEnsembleRisk } = require('../../riskScorerEnsemble');

describe('computeEnsembleRisk', () => {
  test('blends AHP + ML + anomaly using configured weights when ML available', () => {
    const r = computeEnsembleRisk({
      ahpScore: 0.9,
      mlResult: { available: true, score: 1.0, modelVersion: '1.0.0', explanation: [] },
      anomalyScore: 0.5,
    });
    // 0.4*0.9 + 0.4*1.0 + 0.2*0.5 = 0.86
    expect(r.ensembleScore).toBeCloseTo(0.86, 2);
    expect(r.mlAvailable).toBe(true);
    expect(r.weights.ml).toBeCloseTo(0.4, 3);
  });

  test('redistributes ML weight when sidecar unavailable', () => {
    const r = computeEnsembleRisk({
      ahpScore: 0.9,
      mlResult: { available: false, error: 'timeout' },
      anomalyScore: 0.5,
    });
    // weights rescaled: ahp 0.4/0.6=0.667, anomaly 0.2/0.6=0.333
    // 0.667*0.9 + 0.333*0.5 ≈ 0.767
    expect(r.ensembleScore).toBeCloseTo(0.77, 2);
    expect(r.mlAvailable).toBe(false);
    expect(r.mlError).toBe('timeout');
    expect(r.weights.ml).toBe(0);
    expect(r.weights.ahp + r.weights.anomaly).toBeCloseTo(1, 3);
  });

  test('clamps output to [0,1]', () => {
    const hi = computeEnsembleRisk({
      ahpScore: 1.5,
      mlResult: { available: true, score: 1.2 },
      anomalyScore: 2.0,
    });
    expect(hi.ensembleScore).toBeLessThanOrEqual(1);

    const lo = computeEnsembleRisk({
      ahpScore: -0.5,
      mlResult: { available: true, score: -0.2 },
      anomalyScore: -1.0,
    });
    expect(lo.ensembleScore).toBeGreaterThanOrEqual(0);
  });

  test('null mlResult falls back to AHP+anomaly', () => {
    const r = computeEnsembleRisk({
      ahpScore: 0.6,
      mlResult: null,
      anomalyScore: 0.3,
    });
    expect(r.mlAvailable).toBe(false);
    expect(r.weights.ml).toBe(0);
  });
});
