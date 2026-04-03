/**
 * ML-based Behavioral Anomaly Detection
 *
 * Uses statistical models to detect anomalous login behavior:
 * 1. Login time pattern (Gaussian distribution per user)
 * 2. Login frequency (rate limiting via sliding window)
 * 3. Location velocity (impossible travel detection)
 * 4. Session duration patterns
 * 5. Typing cadence / interaction patterns (placeholder for future biometrics)
 *
 * Each factor produces an anomaly score [0, 1].
 * Combined anomaly score adjusts the risk score additively.
 */

// Per-user behavioral profiles
const userProfiles = new Map();

// Login history (for pattern learning)
const loginHistory = new Map(); // userId -> [{ timestamp, location, deviceId, riskScore, decision }]

const MAX_HISTORY = 100;
const ANOMALY_WEIGHT = 0.15; // Weight of anomaly score in final risk

/**
 * Initialize or get a user's behavioral profile.
 */
function getProfile(userId) {
  if (!userProfiles.has(userId)) {
    userProfiles.set(userId, {
      // Time pattern: mean and std of login hours
      loginHours: { mean: 12, std: 4, samples: 0 },
      // Location pattern: set of known (country, city) pairs
      knownLocations: new Set(),
      // Device pattern: set of known device IDs
      knownDevices: new Set(),
      // Frequency: timestamps of recent logins
      recentLogins: [],
      // Last login location and time (for velocity check)
      lastLogin: null,
    });
  }
  return userProfiles.get(userId);
}

/**
 * Record a login event and update the behavioral model.
 */
function recordLogin(userId, context) {
  const profile = getProfile(userId);
  const timestamp = new Date(context.timestamp);
  const hour = timestamp.getHours() + timestamp.getMinutes() / 60;

  // Update time pattern (online mean/std update)
  profile.loginHours.samples++;
  const n = profile.loginHours.samples;
  const oldMean = profile.loginHours.mean;
  const newMean = oldMean + (hour - oldMean) / n;
  const oldStd = profile.loginHours.std;
  // Welford's online variance algorithm
  if (n > 1) {
    const newVariance = ((n - 2) / (n - 1)) * (oldStd * oldStd) + ((hour - oldMean) * (hour - newMean)) / (n - 1);
    profile.loginHours.std = Math.sqrt(Math.max(newVariance, 1)); // min std of 1 hour
  }
  profile.loginHours.mean = newMean;

  // Update known locations
  if (context.location) {
    profile.knownLocations.add(`${context.location.country}:${context.location.city}`);
  }

  // Update known devices
  if (context.deviceId) {
    profile.knownDevices.add(context.deviceId);
  }

  // Update recent logins
  profile.recentLogins.push(Date.now());
  if (profile.recentLogins.length > 50) {
    profile.recentLogins = profile.recentLogins.slice(-50);
  }

  // Update last login
  profile.lastLogin = {
    timestamp: context.timestamp,
    location: context.location,
    deviceId: context.deviceId,
  };

  // Add to history
  const history = loginHistory.get(userId) || [];
  history.push({
    timestamp: context.timestamp,
    location: context.location,
    deviceId: context.deviceId,
  });
  if (history.length > MAX_HISTORY) {
    loginHistory.set(userId, history.slice(-MAX_HISTORY));
  } else {
    loginHistory.set(userId, history);
  }
}

/**
 * Compute anomaly scores for a login attempt.
 * Returns individual scores and a combined anomaly score.
 */
function detectAnomalies(userId, context) {
  const profile = getProfile(userId);
  const timestamp = new Date(context.timestamp);
  const hour = timestamp.getHours() + timestamp.getMinutes() / 60;

  const scores = {};

  // 1. Time anomaly: how many standard deviations from mean login time?
  if (profile.loginHours.samples >= 3) {
    const zScore = Math.abs(hour - profile.loginHours.mean) / profile.loginHours.std;
    scores.timeAnomaly = Math.min(zScore / 3, 1); // Normalize: 3+ std devs = max anomaly
  } else {
    scores.timeAnomaly = 0; // Not enough data
  }

  // 2. Location novelty: have we seen this location before?
  const locKey = context.location
    ? `${context.location.country}:${context.location.city}`
    : 'UNKNOWN:UNKNOWN';
  if (profile.knownLocations.size > 0) {
    scores.locationNovelty = profile.knownLocations.has(locKey) ? 0 : 0.8;
  } else {
    scores.locationNovelty = 0; // No history
  }

  // 3. Login frequency: too many logins in short window?
  const now = Date.now();
  const recentWindow = 5 * 60 * 1000; // 5 minutes
  const recentCount = profile.recentLogins.filter(t => (now - t) < recentWindow).length;
  scores.frequencyAnomaly = Math.min(recentCount / 10, 1); // 10+ in 5 min = max anomaly

  // 4. Impossible travel: could user physically travel from last location?
  if (profile.lastLogin && context.location && profile.lastLogin.location) {
    const lastTime = new Date(profile.lastLogin.timestamp).getTime();
    const currentTime = timestamp.getTime();
    const timeDiffHours = (currentTime - lastTime) / (1000 * 60 * 60);

    const lastLoc = profile.lastLogin.location;
    const currLoc = context.location;

    if (lastLoc.country !== currLoc.country && timeDiffHours < 2) {
      // Different country in under 2 hours = impossible travel
      scores.travelAnomaly = 1.0;
    } else if (lastLoc.city !== currLoc.city && lastLoc.country === currLoc.country && timeDiffHours < 0.5) {
      // Different city in under 30 minutes
      scores.travelAnomaly = 0.7;
    } else {
      scores.travelAnomaly = 0;
    }
  } else {
    scores.travelAnomaly = 0;
  }

  // 5. Device novelty: have we seen this device before?
  if (profile.knownDevices.size > 0) {
    scores.deviceNovelty = profile.knownDevices.has(context.deviceId) ? 0 : 0.6;
  } else {
    scores.deviceNovelty = 0;
  }

  // Combined anomaly score (weighted average)
  const weights = {
    timeAnomaly: 0.15,
    locationNovelty: 0.25,
    frequencyAnomaly: 0.20,
    travelAnomaly: 0.25,
    deviceNovelty: 0.15,
  };

  let combined = 0;
  for (const [key, weight] of Object.entries(weights)) {
    combined += (scores[key] || 0) * weight;
  }
  combined = Math.round(combined * 100) / 100;

  return {
    scores,
    combined,
    anomalyDetected: combined >= 0.4,
    profileMaturity: profile.loginHours.samples,
  };
}

/**
 * Adjust risk score based on anomaly detection.
 * Returns the adjusted risk score and anomaly details.
 */
function adjustRiskScore(originalRiskScore, userId, context) {
  const anomaly = detectAnomalies(userId, context);

  // Anomaly contributes additively to risk score
  const adjustment = anomaly.combined * ANOMALY_WEIGHT;
  const adjustedScore = Math.min(Math.round((originalRiskScore + adjustment) * 100) / 100, 1);

  return {
    originalRiskScore,
    adjustedRiskScore: adjustedScore,
    anomalyAdjustment: Math.round(adjustment * 100) / 100,
    anomaly,
  };
}

/**
 * Get behavioral profile summary for a user.
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
    knownLocations: [...profile.knownLocations],
    knownDevices: [...profile.knownDevices],
    recentLoginCount: profile.recentLogins.length,
    lastLogin: profile.lastLogin,
  };
}

/**
 * Seed behavioral profiles for demo users.
 */
function seedDemoProfiles() {
  // Simulate historical logins for alice
  const aliceLogins = [
    { timestamp: '2026-04-01T09:30:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-001' },
    { timestamp: '2026-04-01T10:15:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-001' },
    { timestamp: '2026-04-01T14:00:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-001' },
    { timestamp: '2026-04-02T09:00:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-001' },
    { timestamp: '2026-04-02T11:30:00Z', location: { country: 'IN', city: 'Gwalior' }, deviceId: 'dev-001' },
  ];
  for (const login of aliceLogins) {
    recordLogin('alice', login);
  }

  // Simulate historical logins for bob
  const bobLogins = [
    { timestamp: '2026-04-01T10:00:00Z', location: { country: 'IN', city: 'Delhi' }, deviceId: 'dev-002' },
    { timestamp: '2026-04-01T15:00:00Z', location: { country: 'IN', city: 'Delhi' }, deviceId: 'dev-002' },
    { timestamp: '2026-04-02T09:30:00Z', location: { country: 'IN', city: 'Delhi' }, deviceId: 'dev-002' },
    { timestamp: '2026-04-02T14:00:00Z', location: { country: 'IN', city: 'Delhi' }, deviceId: 'dev-002' },
  ];
  for (const login of bobLogins) {
    recordLogin('bob', login);
  }
}

module.exports = {
  detectAnomalies,
  adjustRiskScore,
  recordLogin,
  getProfileSummary,
  seedDemoProfiles,
  ANOMALY_WEIGHT,
};
