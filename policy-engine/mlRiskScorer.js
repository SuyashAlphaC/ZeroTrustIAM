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
  const body = toRiskRequest(userProfile, requestContext, opts);
  try {
    const res = await fetchWithTimeout(
      `${config.mlServiceUrl}/predict`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
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

module.exports = { scoreWithML, mlHealth, toRiskRequest };
