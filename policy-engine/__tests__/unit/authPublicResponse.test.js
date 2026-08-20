'use strict';

const {
  sanitizePublicAuthResponse,
  classifyReason,
} = require('../../authPublicResponse');

describe('classifyReason', () => {
  test('ALLOW is safe', () => {
    const c = classifyReason('ALLOW', 'All checks passed');
    expect(c.reasonCode).toBe('OK');
    expect(c.userMessage).not.toMatch(/\d\.\d/);
  });

  test('risk deny never includes threshold numbers', () => {
    const c = classifyReason('DENY', 'Risk score too high (0.82 >= 0.6)');
    expect(c.reasonCode).toBe('RISK_DENIED');
    expect(c.reason).not.toMatch(/0\.\d/);
    expect(c.userMessage).not.toMatch(/0\.\d/);
  });

  test('unregistered device maps to UNTRUSTED_DEVICE', () => {
    const c = classifyReason('DENY', 'Unregistered device');
    expect(c.reasonCode).toBe('UNTRUSTED_DEVICE');
  });
});

describe('sanitizePublicAuthResponse', () => {
  test('strips riskScore, breakdown, ensemble, anomaly', () => {
    const out = sanitizePublicAuthResponse({
      decision: 'ALLOW',
      reason: 'All checks passed',
      riskScore: 0.12,
      baseRiskScore: 0.1,
      breakdown: { d_score: 0 },
      ensemble: { weights: { ahp: 1 } },
      anomaly: { combined: 0.2 },
      accessToken: 'tok',
      txId: 'tx-1',
    });
    expect(out.riskScore).toBeUndefined();
    expect(out.baseRiskScore).toBeUndefined();
    expect(out.breakdown).toBeUndefined();
    expect(out.ensemble).toBeUndefined();
    expect(out.anomaly).toBeUndefined();
    expect(out.accessToken).toBe('tok');
    expect(out.txId).toBe('tx-1');
    expect(out.reasonCode).toBe('OK');
    expect(out.userMessage).toBeTruthy();
  });

  test('keeps risk fields when exposeRiskDetails is true', () => {
    const out = sanitizePublicAuthResponse(
      { decision: 'DENY', reason: 'Risk too high', riskScore: 0.9 },
      { exposeRiskDetails: true }
    );
    expect(out.riskScore).toBe(0.9);
  });
});
