'use strict';

const config = require('./config');
const db = require('./database');

/**
 * ML-based Behavioral Anomaly Detection — fully database-backed.
 *
 * Uses statistical models to detect anomalous login behavior:
 * 1. Login time pattern (Gaussian distribution per user)
 * 2. Login frequency (rate limiting via sliding window)
 * 3. Location velocity (impossible travel detection)
 * 4. Session duration patterns
 * 5. Device novelty
 *
 * Each factor produces an anomaly score [0, 1].
 * Combined anomaly score adjusts the risk score additively.
 *
 * All behavioral profiles persist in SQLite via the anomaly_profiles table.
 *
 * @module anomalyDetector
 * @version 2.0.0
 */

const MODEL_VERSION = '2.0.0';

// Weights for combining anomaly signals
const SIGNAL_WEIGHTS = {
  timeAnomaly: 0.15,
  locationNovelty: 0.25,
  frequencyAnomaly: 0.20,
  travelAnomaly: 0.25,
  deviceNovelty: 0.15,
};

/**
 * Get a user's behavioral profile from the database.
 * Creates a default profile if none exists.
 */
function getProfile(userId) {
  return db.getAnomalyProfile(userId);
}

/**
 * Record a login event and update the behavioral model in the database.
 */
function recordLogin(userId, context) {
  const profile = getProfile(userId);
  const timestamp = new Date(context.timestamp);
  const hour = timestamp.getHours() + timestamp.getMinutes() / 60;

  // Update time pattern (Welford's online variance algorithm)
  profile.loginHours.samples++;
  const n = profile.loginHours.samples;
  const oldMean = profile.loginHours.mean;
  const newMean = oldMean + (hour - oldMean) / n;
  if (n > 1) {
    const oldStd = profile.loginHours.std;
    const newVariance = ((n - 2) / (n - 1)) * (oldStd * oldStd) + ((hour - oldMean) * (hour - newMean)) / (n - 1);
    profile.loginHours.std = Math.sqrt(Math.max(newVariance, 1));
  }
  profile.loginHours.mean = newMean;

  // Update known locations
  const locations = new Set(profile.knownLocations);
  if (context.location) {
    locations.add(`${context.location.country}:${context.location.city}`);
  }
  profile.knownLocations = [...locations];

  // Update known devices
  const devices = new Set(profile.knownDevices);
  if (context.deviceId) {
    devices.add(context.deviceId);
  }
  profile.knownDevices = [...devices];

  // Update last login
  profile.lastLogin = {
    timestamp: context.timestamp,
    location: context.location,
    deviceId: context.deviceId,
  };

  // Persist to database
  db.updateAnomalyProfile(userId, profile);
}

/**
 * Compute anomaly scores for a login attempt.
 * All profile data is read from the database.
 */
function detectAnomalies(userId, context) {
  const profile = getProfile(userId);
  const timestamp = new Date(context.timestamp);
  const hour = timestamp.getHours() + timestamp.getMinutes() / 60;
  const scores = {};

  // 1. Time anomaly: z-score from mean login time
  if (profile.loginHours.samples >= 3) {
    const zScore = Math.abs(hour - profile.loginHours.mean) / profile.loginHours.std;
    scores.timeAnomaly = Math.min(zScore / 3, 1);
  } else {
    scores.timeAnomaly = 0;
  }

  // 2. Location novelty
  const locKey = context.location
    ? `${context.location.country}:${context.location.city}`
    : 'UNKNOWN:UNKNOWN';
  const knownLocs = new Set(profile.knownLocations);
  if (knownLocs.size > 0) {
    scores.locationNovelty = knownLocs.has(locKey) ? 0 : 0.8;
  } else {
    scores.locationNovelty = 0;
  }

  // 3. Login frequency (check recent logins from DB)
  const recentLogins = db.getRecentLogins(userId, 5); // last 5 minutes
  const recentCount = recentLogins.length;
  scores.frequencyAnomaly = Math.min(recentCount / 10, 1);

  // 4. Impossible travel
  if (profile.lastLogin && context.location && profile.lastLogin.location) {
    const lastTime = new Date(profile.lastLogin.timestamp).getTime();
    const currentTime = timestamp.getTime();
    const timeDiffHours = (currentTime - lastTime) / (1000 * 60 * 60);
    const lastLoc = profile.lastLogin.location;
    const currLoc = context.location;

    if (lastLoc.country !== currLoc.country && timeDiffHours < 2) {
      scores.travelAnomaly = 1.0;
    } else if (lastLoc.city !== currLoc.city && lastLoc.country === currLoc.country && timeDiffHours < 0.5) {
      scores.travelAnomaly = 0.7;
    } else {
      scores.travelAnomaly = 0;
    }
  } else {
    scores.travelAnomaly = 0;
  }

  // 5. Device novelty
  const knownDevs = new Set(profile.knownDevices);
  if (knownDevs.size > 0) {
    scores.deviceNovelty = knownDevs.has(context.deviceId) ? 0 : 0.6;
  } else {
    scores.deviceNovelty = 0;
  }

  // Combined score
  let combined = 0;
  for (const [key, weight] of Object.entries(SIGNAL_WEIGHTS)) {
    combined += (scores[key] || 0) * weight;
  }
  combined = Math.round(combined * 100) / 100;

  // Human-readable explanations
  const explanations = [];
  if (scores.timeAnomaly > 0.3) explanations.push(`Login time deviates ${(scores.timeAnomaly * 3).toFixed(1)} std devs from usual pattern`);
  if (scores.locationNovelty > 0) explanations.push(`Location ${locKey} has never been seen before`);
  if (scores.frequencyAnomaly > 0.3) explanations.push(`${recentCount} logins in last 5 minutes exceeds normal rate`);
  if (scores.travelAnomaly > 0) explanations.push('Impossible travel detected from previous login location');
  if (scores.deviceNovelty > 0) explanations.push(`Device ${context.deviceId} has never been seen before`);

  return {
    scores,
    combined,
    anomalyDetected: combined >= config.anomalyThreshold,
    profileMaturity: profile.loginHours.samples,
    modelVersion: MODEL_VERSION,
    explanation: explanations.length > 0 ? explanations : ['No anomalies detected'],
  };
}

/**
 * Adjust risk score based on anomaly detection.
 */
function adjustRiskScore(originalRiskScore, userId, context) {
  const anomaly = detectAnomalies(userId, context);
  const adjustment = anomaly.combined * config.anomalyWeight;
  const adjustedScore = Math.min(Math.round((originalRiskScore + adjustment) * 100) / 100, 1);

  return {
    originalRiskScore,
    adjustedRiskScore: adjustedScore,
    anomalyAdjustment: Math.round(adjustment * 100) / 100,
    anomaly,
  };
}

/**
 * Get behavioral profile summary from the database.
 */
function getProfileSummary(userId) {
  const profile = getProfile(userId);
  return {
    userId,
    loginHours: {
      mean: Math.round(profile.loginHours.mean * 100) / 100,
      std: Math.round(profile.loginHours.std * 100) / 100,
      samples: profile.loginHours.samples,
    },
    knownLocations: profile.knownLocations,
    knownDevices: profile.knownDevices,
    lastLogin: profile.lastLogin,
  };
}

/**
 * Seed behavioral profiles for demo users via database.
 */
function seedDemoProfiles() {
  const aliceLogins = [
    { timestamp: '2026-04-01T09:30:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-001' },
    { timestamp: '2026-04-01T10:15:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-001' },
    { timestamp: '2026-04-01T14:00:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-001' },
    { timestamp: '2026-04-02T09:00:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-001' },
    { timestamp: '2026-04-02T11:30:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-001' },
  ];
  for (const login of aliceLogins) recordLogin('alice', login);

  const bobLogins = [
    { timestamp: '2026-04-01T10:00:00Z', location: { country: 'IN', city: 'Delhi' }, deviceId: 'dev-002' },
    { timestamp: '2026-04-01T15:00:00Z', location: { country: 'IN', city: 'Delhi' }, deviceId: 'dev-002' },
    { timestamp: '2026-04-02T09:30:00Z', location: { country: 'IN', city: 'Delhi' }, deviceId: 'dev-002' },
    { timestamp: '2026-04-02T14:00:00Z', location: { country: 'IN', city: 'Delhi' }, deviceId: 'dev-002' },
  ];
  for (const login of bobLogins) recordLogin('bob', login);
}

/**
 * Get model diagnostics for monitoring.
 */
function getModelDiagnostics() {
  return {
    modelVersion: MODEL_VERSION,
    weights: SIGNAL_WEIGHTS,
    anomalyWeight: config.anomalyWeight,
    detectionThreshold: config.anomalyThreshold,
  };
}

module.exports = {
  detectAnomalies,
  adjustRiskScore,
  recordLogin,
  getProfileSummary,
  seedDemoProfiles,
  getModelDiagnostics,
  MODEL_VERSION,
};
