'use strict';

const config = require('./config');
const lockout = require('./accountLockout');

/**
 * Compute the contextual risk score R for an authentication attempt.
 *
 * R = w1*d_score + w2*l_score + w3*t_score + w4*a_score
 *
 * Weights loaded from config (overridable via environment variables).
 * Defaults via AHP: w1=0.40, w2=0.30, w3=0.20, w4=0.10
 *
 * Failed-attempt counters are shared via accountLockout (Redis → Postgres → local).
 */

async function getFailedAttempts(username) {
  return lockout.getFailedAttempts(username);
}

async function incrementFailedAttempts(username) {
  return lockout.incrementFailedAttempts(username);
}

async function resetFailedAttempts(username) {
  return lockout.resetFailedAttempts(username);
}

/**
 * @param {object} userProfile
 * @param {object} requestContext
 * @returns {Promise<{ score: number, breakdown: object }>}
 */
async function computeRiskScore(userProfile, requestContext) {
  const W1 = config.riskWeights.device;
  const W2 = config.riskWeights.location;
  const W3 = config.riskWeights.time;
  const W4 = config.riskWeights.attempts;

  // Device score: 1 if device is not registered, 0 if known
  const d_score = userProfile.registeredDevices.includes(requestContext.deviceId) ? 0 : 1;

  // Location score: 1 if different country, 0.5 if same country but different city, 0 if match
  let l_score = 0;
  if (requestContext.location.country !== userProfile.usualLocation.country) {
    l_score = 1;
  } else if (requestContext.location.city !== userProfile.usualLocation.city) {
    l_score = 0.5;
  }

  // Time score: 1 if outside normal hours, 0 otherwise
  const requestHour = new Date(requestContext.timestamp).getHours();
  const [startHour, endHour] = userProfile.normalHours;
  const t_score = (requestHour >= startHour && requestHour < endHour) ? 0 : 1;

  // Attempt score: shared counter (Redis-backed when available)
  const a_score = await lockout.getAttemptScore(requestContext.username);

  const score = W1 * d_score + W2 * l_score + W3 * t_score + W4 * a_score;

  return {
    score: Math.round(score * 100) / 100,
    breakdown: { d_score, l_score, t_score, a_score },
  };
}

module.exports = {
  computeRiskScore,
  incrementFailedAttempts,
  resetFailedAttempts,
  getFailedAttempts,
};
