'use strict';

const config = require('./config');
const { logger } = require('./logger');

/**
 * HTTP client for the Python ML sidecar at config.mlServiceUrl.
 *
 * Builds a RiskRequest from the same user profile + request context the
 * existing AHP scorer consumes, calls POST /predict with a hard timeout, and
 * returns { available, score, explanation } or { available: false, error }
 * so the ensemble can rebalance weights when the sidecar is unreachable.
 */

async function fetchWithTimeout(url, opts = {}, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

function toRiskRequest(userProfile, requestContext, opts = {}) {
  const profile = {
    registered_devices: userProfile.registeredDevices || [],
    usual_location: {
      country: userProfile.usualLocation?.country || 'UNKNOWN',
      city: userProfile.usualLocation?.city || 'UNKNOWN',
      lat: userProfile.usualLocation?.lat ?? null,
      lon: userProfile.usualLocation?.lon ?? null,
    },
    normal_hours: userProfile.normalHours || [9, 18],
    known_locations: opts.knownLocations || [],
    known_devices: opts.knownDevices || [],
    login_hours_mean: opts.loginHoursMean ?? 12.0,
    login_hours_std: opts.loginHoursStd ?? 4.0,
    profile_samples: opts.profileSamples ?? 0,
  };

  const ctx = {
    device_id: requestContext.deviceId || 'unknown',
    timestamp: requestContext.timestamp || new Date().toISOString(),
    ip: requestContext.ip || '0.0.0.0',
    location: {
      country: requestContext.location?.country || 'UNKNOWN',
      city: requestContext.location?.city || 'UNKNOWN',
      lat: requestContext.location?.lat ?? null,
      lon: requestContext.location?.lon ?? null,
    },
    required_permission: opts.requiredPermission || 'read',
    failed_attempts: opts.failedAttempts || 0,
    last_login: opts.lastLogin || null,
  };

  return {
    username: requestContext.username,
    user_profile: profile,
    request_context: ctx,
  };
}

async function scoreWithML(userProfile, requestContext, opts = {}) {
  if (!config.mlServiceEnabled) {
    return { available: false, error: 'disabled' };
  }
  const { getRequestId } = require('./requestContext');
  const rid = getRequestId();
  const body = toRiskRequest(userProfile, requestContext, opts);
  try {
    const res = await fetchWithTimeout(
      `${config.mlServiceUrl}/predict`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-ml-service-token': config.mlServiceToken,
          ...(rid ? { 'x-request-id': rid } : {}),
        },
        body: JSON.stringify(body),
      },
      config.mlServiceTimeoutMs
    );
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      logger.warn({ status: res.status, text }, 'ML sidecar returned non-OK');
      return { available: false, error: `http_${res.status}` };
    }
    const data = await res.json();
    return {
      available: true,
      score: typeof data.risk_score === 'number' ? data.risk_score : 0,
      modelVersion: data.model_version,
      explanation: data.explanation || [],
    };
  } catch (err) {
    logger.warn({ err: err.message }, 'ML sidecar unreachable — falling back');
    return { available: false, error: err.message };
  }
}

/**
 * Derive a training label from the observed decision and reason.
 *
 * Maps the 4-rule chaincode outcomes to supervised labels:
 *  - ALLOW                                       -> benign (0)
 *  - DENY (Unregistered device, Risk too high,
 *          Suspended, RBAC lack, wrong password) -> attack (1)
 *  - MFA_REQUIRED + verified downstream          -> benign (0)
 *
 * The soft "benign" signal from successful logins isn't perfect but it gives
 * the model a growing baseline of real legitimate traffic for subsequent
 * retraining.
 */
function deriveLabel(decision, reason) {
  if (decision === 'ALLOW' || decision === 'MFA_REQUIRED') return 0;
  if (decision === 'DENY') return 1;
  return null;
}

/**
 * Fire-and-forget: push a labeled feature vector to the sidecar so it's stored
 * for the next scheduled retrain. Failures are logged but never surfaced to
 * the caller — label ingestion is strictly best-effort.
 */
function ingestSample(userProfile, requestContext, opts = {}) {
  if (!config.mlServiceEnabled) return;
  const label = opts.label ?? deriveLabel(opts.decision, opts.reason);
  if (label === null || label === undefined) return;

  const body = {
    risk_request: toRiskRequest(userProfile, requestContext, opts),
    label,
    source: opts.source || 'live',
    username: requestContext.username,
    decision: opts.decision,
    reason: opts.reason,
    audit_id: opts.auditId || null,
  };

  const { getRequestId } = require('./requestContext');
  const rid = getRequestId();

  // Fire-and-forget — use a generous timeout but never await from the handler.
  fetchWithTimeout(
    `${config.mlServiceUrl}/ingest`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-ml-service-token': config.mlServiceToken,
        ...(rid ? { 'x-request-id': rid } : {}),
      },
      body: JSON.stringify(body),
    },
    config.mlServiceTimeoutMs * 2
  ).then(async (res) => {
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      logger.warn({ status: res.status, text }, 'ML ingest non-OK');
    }
  }).catch((err) => {
    logger.debug({ err: err.message }, 'ML ingest failed (non-fatal)');
  });
}

/**
 * Map analyst feedback labels to the supervised binary label expected by the
 * ML service.
 *  - true_positive  / false_negative -> 1 (attack)
 *  - false_positive / true_negative  -> 0 (benign)
 */
function feedbackLabelToBinary(label) {
  if (label === 'true_positive' || label === 'false_negative') return 1;
  if (label === 'false_positive' || label === 'true_negative') return 0;
  return null;
}

/**
 * Forward an analyst feedback label to the ML service /relabel endpoint.
 * Returns { ok, status, body? } — never throws.
 */
async function relabelMlSample({ auditId, label, reviewer }) {
  if (!config.mlServiceEnabled) return { ok: false, status: 0, error: 'disabled' };
  const binary = feedbackLabelToBinary(label);
  if (binary === null) return { ok: false, status: 0, error: 'invalid_label' };
  const { getRequestId } = require('./requestContext');
  const rid = getRequestId();
  try {
    const res = await fetchWithTimeout(
      `${config.mlServiceUrl}/relabel`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-ml-service-token': config.mlServiceToken,
          ...(rid ? { 'x-request-id': rid } : {}),
        },
        body: JSON.stringify({ audit_id: auditId, label: binary, reviewer }),
      },
      config.mlServiceTimeoutMs * 2
    );
    let body = null;
    try { body = await res.json(); } catch { /* non-json body is fine */ }
    if (!res.ok) {
      logger.warn({ status: res.status, auditId }, 'ML relabel returned non-OK');
      return { ok: false, status: res.status, body };
    }
    return { ok: true, status: res.status, body };
  } catch (err) {
    logger.warn({ err: err.message, auditId }, 'ML relabel failed');
    return { ok: false, status: 0, error: err.message };
  }
}

async function mlHealth() {
  if (!config.mlServiceEnabled) return { enabled: false };
  try {
    const res = await fetchWithTimeout(
      `${config.mlServiceUrl}/health`,
      { method: 'GET' },
      config.mlServiceTimeoutMs
    );
    return { enabled: true, ok: res.ok, body: await res.json().catch(() => null) };
  } catch (err) {
    return { enabled: true, ok: false, error: err.message };
  }
}

module.exports = {
  scoreWithML,
  mlHealth,
  toRiskRequest,
  ingestSample,
  deriveLabel,
  relabelMlSample,
  feedbackLabelToBinary,
};
