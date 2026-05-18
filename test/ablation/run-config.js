'use strict';

/**
 * Run all ablation scenarios for a single configuration.
 * Usage: node test/ablation/run-config.js <configId>
 * Prints JSON result to stdout.
 *
 * Exit codes:
 *   0 — success
 *   1 — fatal error
 *   2 — skipped (e.g. ML sidecar or Redis unreachable for a requireMl/requireRedis config)
 */

const path = require('path');
const net = require('net');

const configId = process.argv[2];
if (!configId) {
  console.error('Usage: node run-config.js <configId>');
  process.exit(1);
}

const { CONFIGS } = require('./configs');
const { SCENARIOS } = require('./scenarios');
const cfg = CONFIGS.find((c) => c.id === configId);
if (!cfg) {
  console.error(`Unknown config: ${configId}`);
  process.exit(1);
}

// Base test environment
process.env.DOTENV_CONFIG_QUIET = 'true';
process.env.NODE_ENV = 'test';
process.env.BCRYPT_ROUNDS = '4';
process.env.FABRIC_TEST_MODE = 'true';
process.env.SEED_DEMO = 'true';
process.env.LOG_LEVEL = 'silent';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'ablation-jwt-secret-minimum-32-chars';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'ablation-refresh-secret-min-32c';
process.env.OAUTH_DEFAULT_CLIENT_SECRET = process.env.OAUTH_DEFAULT_CLIENT_SECRET || 'ablation-oauth-secret';
process.env.TEST_DATABASE_URL = process.env.TEST_DATABASE_URL
  || 'postgresql://ztiam:testpassword@127.0.0.1:5433/ztiam_test';
process.env.ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://172.19.0.2:5000';
process.env.ML_SERVICE_TOKEN = process.env.ML_SERVICE_TOKEN || 'local-test-ml-token';
process.env.ML_SERVICE_TIMEOUT_MS = process.env.ML_SERVICE_TIMEOUT_MS || '2000';

for (const [key, val] of Object.entries(cfg.env || {})) {
  process.env[key] = val;
}

const POLICY_DIR = path.resolve(__dirname, '../../policy-engine');

function loadModules() {
  const config = require(path.join(POLICY_DIR, 'config'));
  return {
    config,
    db: require(path.join(POLICY_DIR, 'database')),
    riskScorer: require(path.join(POLICY_DIR, 'riskScorer')),
    anomalyDetector: require(path.join(POLICY_DIR, 'anomalyDetector')),
    mlRiskScorer: require(path.join(POLICY_DIR, 'mlRiskScorer')),
    riskScorerEnsemble: require(path.join(POLICY_DIR, 'riskScorerEnsemble')),
    mfa: require(path.join(POLICY_DIR, 'mfa')),
    zkp: require(path.join(POLICY_DIR, 'zkpVerifier')),
    blockchain: require(path.join(POLICY_DIR, 'fabricClient')),
  };
}

const { simulateEvaluate } = require('./simulator');

async function runSetup(setup, modules, scenarioPayload) {
  if (setup === 'bruteforce_5') {
    for (let i = 1; i <= 5; i += 1) {
      await simulateEvaluate(modules, {
        ...scenarioPayload,
        password: `wrong${i}`,
      });
    }
  }
}

/**
 * Fix 6 — anomaly profile warmup.
 *
 * The baseline `seedDemoProfiles()` writes 5 logins for alice and 4 for bob,
 * all from a single city and a narrow hour window. That leaves `loginHoursStd`
 * close to zero and gives the anomaly detector almost nothing to deviate
 * against. To make ablations of the anomaly component meaningful, we generate
 * ~30 additional logins per user with realistic time / weekday variance.
 *
 * Generation is deterministic (no Math.random) so results are reproducible.
 */
async function warmAnomalyProfiles(anomalyDetector) {
  // 30 days of historical logins per user. Times are perturbed via a
  // deterministic mulberry-style sequence so the profile gets a realistic std.
  const baseDate = new Date('2026-03-01T00:00:00Z').getTime();
  const dayMs = 24 * 60 * 60 * 1000;
  const aliceCities = ['Gwalior', 'Gwalior', 'Gwalior', 'Gwalior', 'Mumbai', 'Bangalore', 'Gwalior'];
  const bobCities = ['Delhi', 'Delhi', 'Delhi', 'Delhi', 'Delhi', 'Pune', 'Delhi'];

  // Deterministic offset sequence in minutes around 09:30 - 17:30
  const offsetMinutes = (i) => {
    // 0..480 minutes (8 hour business window) using a deterministic generator
    const x = ((i * 2654435761) >>> 0) % 480;
    return x;
  };

  for (let d = 0; d < 30; d += 1) {
    const ts = baseDate + d * dayMs;
    // skip weekends for realism (lower volume)
    const dow = new Date(ts).getUTCDay();
    if (dow === 0 || dow === 6) continue;

    // Alice: 1 morning + 1 afternoon login
    const aliceMorning = new Date(ts + (9 * 60 + offsetMinutes(d * 2)) * 60 * 1000);
    const aliceAfternoon = new Date(ts + (13 * 60 + offsetMinutes(d * 2 + 1)) * 60 * 1000);
    await anomalyDetector.recordLogin('alice', {
      timestamp: aliceMorning.toISOString(),
      location: { country: 'IN', city: aliceCities[d % aliceCities.length] },
      deviceId: 'dev-001',
    });
    await anomalyDetector.recordLogin('alice', {
      timestamp: aliceAfternoon.toISOString(),
      location: { country: 'IN', city: aliceCities[d % aliceCities.length] },
      deviceId: 'dev-001',
    });

    // Bob: 1 login per weekday
    const bobTime = new Date(ts + (10 * 60 + offsetMinutes(d * 3)) * 60 * 1000);
    await anomalyDetector.recordLogin('bob', {
      timestamp: bobTime.toISOString(),
      location: { country: 'IN', city: bobCities[d % bobCities.length] },
      deviceId: 'dev-002',
    });
  }
}

function checkPort(host, port, timeoutMs = 800) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let settled = false;
    const done = (ok) => { if (settled) return; settled = true; sock.destroy(); resolve(ok); };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => done(true));
    sock.once('timeout', () => done(false));
    sock.once('error', () => done(false));
    sock.connect(port, host);
  });
}

async function probeRedis() {
  try {
    const url = new URL(process.env.REDIS_URL || 'redis://127.0.0.1:6379');
    return await checkPort(url.hostname, Number(url.port) || 6379, 600);
  } catch {
    return false;
  }
}

function classifyDecision(scenario, actual) {
  const expected = scenario.baselineExpected;
  const cat = scenario.category;
  const matches = actual === expected;

  // Hard security regression: must DENY but ALLOWed
  const hardSecRegression = expected === 'DENY' && actual === 'ALLOW';

  // Soft security regression: must DENY but only step-up'd, OR a risk
  // scenario that should have required MFA but ALLOWed through (a real
  // weakening even though the scenario category isn't "attack").
  const softSecRegression =
    (expected === 'DENY' && actual === 'MFA_REQUIRED')
    || (expected === 'MFA_REQUIRED' && actual === 'ALLOW');

  // Friction regression: must ALLOW but ended up MFA or DENY (false positive)
  const frictionRegression = expected === 'ALLOW' && actual !== 'ALLOW';

  // Over-deny: must MFA but DENYed (false positive on a risk scenario)
  const overDenyRegression = expected === 'MFA_REQUIRED' && actual === 'DENY';

  return {
    matchesBaseline: matches,
    hardSecurityRegression: hardSecRegression,
    softSecurityRegression: softSecRegression,
    securityRegression: hardSecRegression || softSecRegression, // legacy alias
    frictionRegression,
    overDenyRegression,
    // For false-positive rate metric: a "false positive" is a benign or risk
    // scenario whose ground truth was ALLOW but the system added friction.
    isFalsePositive: expected === 'ALLOW' && actual !== 'ALLOW',
    // For false-negative rate metric: an attack or attack-like scenario
    // (DENY-expected or MFA_REQUIRED-expected) that became ALLOW.
    isFalseNegative:
      (expected === 'DENY' || expected === 'MFA_REQUIRED') && actual === 'ALLOW',
  };
}

async function main() {
  const modules = loadModules();
  const { config, db, mfa, anomalyDetector, mlRiskScorer } = modules;

  await db.init();
  await db.truncateTestData();
  await db.seedDemoData();
  await mfa.seedDemoSecrets();
  await anomalyDetector.seedDemoProfiles();
  await warmAnomalyProfiles(anomalyDetector); // Fix 6 — warm profiles

  // --- Probes for optional resources ---
  let mlAvailableAtStart = null;
  if (cfg.requireMl || cfg.mlOptional) {
    const probe = await mlRiskScorer.scoreWithML(
      await db.getUser('alice'),
      { username: 'alice', deviceId: 'dev-001', timestamp: '2026-04-02T10:00:00Z', location: { country: 'IN', city: 'Gwalior' } },
      { requiredPermission: 'read', failedAttempts: 0, knownLocations: ['IN:Gwalior'], knownDevices: ['dev-001'], loginHoursMean: 12, loginHoursStd: 4, profileSamples: 30, lastLogin: null }
    );
    mlAvailableAtStart = !!probe.available;
    if (cfg.requireMl && !mlAvailableAtStart) {
      console.error(JSON.stringify({ configId, error: 'ML sidecar unavailable', mlError: probe.error }));
      process.exit(2);
    }
  }

  let redisAvailable = null;
  if (cfg.requireRedis) {
    redisAvailable = await probeRedis();
    if (!redisAvailable) {
      console.error(JSON.stringify({ configId, error: 'Redis unreachable at REDIS_URL', redisUrl: process.env.REDIS_URL }));
      process.exit(2);
    }
  }

  const scenarioResults = [];
  const cacheHits = [];

  for (const scenario of SCENARIOS) {
    if (scenario.setup) {
      await runSetup(scenario.setup, modules, scenario.payload);
    }
    const first = await simulateEvaluate(modules, scenario.payload);

    // Fix-5 cache run: if the config asks for it AND the first call ALLOWed,
    // run the same payload a second time and capture whether the cache layer
    // (a thin wrapper inside the simulator) reports a hit.
    let secondPass = null;
    if (cfg.cacheTwice && first.decision === 'ALLOW') {
      secondPass = await simulateEvaluate(modules, scenario.payload, { secondPass: true });
      cacheHits.push({
        id: scenario.id,
        firstDecision: first.decision,
        secondDecision: secondPass.decision,
        cacheHit: !!secondPass.fromCache,
      });
    }

    const cls = classifyDecision(scenario, first.decision);

    scenarioResults.push({
      id: scenario.id,
      name: scenario.name,
      category: scenario.category,
      baselineExpected: scenario.baselineExpected,
      decision: first.decision,
      reason: first.reason,
      layer: first.layer,
      riskScore: first.riskScore,
      baseRiskScore: first.baseRiskScore,
      breakdown: first.breakdown,
      ensemble: first.ensemble,
      anomalyCombined: first.anomaly?.combined,
      anomalyMature: first.anomaly?.profileMature ?? null,
      mlAvailable: first.mlAvailable,
      zkProofGenerated: !!first.zkProof,
      ...cls,
      secondPass: secondPass ? {
        decision: secondPass.decision,
        cacheHit: !!secondPass.fromCache,
      } : null,
    });
  }

  // --- Aggregate metrics ---
  const attacks = scenarioResults.filter((s) => s.category === 'attack');
  const benign = scenarioResults.filter((s) => s.category === 'benign');
  const risk = scenarioResults.filter((s) => s.category === 'risk');
  const evasion = scenarioResults.filter((s) => s.category === 'evasion');

  // Fix 7: false-positive rate metric across the union of benign + risk-ALLOW.
  const allowExpected = scenarioResults.filter((s) => s.baselineExpected === 'ALLOW');
  const denyExpected = scenarioResults.filter((s) => s.baselineExpected === 'DENY');
  const mfaExpected = scenarioResults.filter((s) => s.baselineExpected === 'MFA_REQUIRED');

  const falsePositiveRate = allowExpected.length
    ? allowExpected.filter((s) => s.isFalsePositive).length / allowExpected.length
    : 0;

  const falseNegativeRate = (denyExpected.length + mfaExpected.length)
    ? scenarioResults.filter((s) => s.isFalseNegative).length / (denyExpected.length + mfaExpected.length)
    : 0;

  const hardSecurityRegressions = scenarioResults.filter((s) => s.hardSecurityRegression).length;
  const softSecurityRegressions = scenarioResults.filter((s) => s.softSecurityRegression).length;
  const frictionRegressions = scenarioResults.filter((s) => s.frictionRegression).length;
  const overDenyRegressions = scenarioResults.filter((s) => s.overDenyRegression).length;

  const output = {
    configId: cfg.id,
    configName: cfg.name,
    description: cfg.description,
    env: cfg.env,
    mlServiceEnabled: config.mlServiceEnabled,
    mlAvailableAtStart,
    redisAvailable,
    riskThreshold: config.riskThreshold,
    mfaStepUpThreshold: config.mfaStepUpThreshold,
    riskWeights: config.riskWeights,
    ensembleWeights: {
      ahp: config.ensembleAhpWeight,
      ml: config.ensembleMlWeight,
      anomaly: config.ensembleAnomalyWeight,
    },
    zkpEnabled: config.zkpEnabled,
    blockchainAblation: process.env.ABLATION_BLOCKCHAIN || null,
    cacheRun: cfg.cacheTwice ? {
      total: cacheHits.length,
      hits: cacheHits.filter((c) => c.cacheHit).length,
      consistency: cacheHits.every((c) => c.firstDecision === c.secondDecision),
      perScenario: cacheHits,
    } : null,
    summary: {
      total: scenarioResults.length,
      matchesBaseline: scenarioResults.filter((s) => s.matchesBaseline).length,
      // Fix 1 — clean split of regression flavors
      hardSecurityRegressions,
      softSecurityRegressions,
      securityRegressionsTotal: hardSecurityRegressions + softSecurityRegressions,
      // Legacy field kept for back-compat with older reports
      securityRegressions: hardSecurityRegressions,
      frictionRegressions,
      overDenyRegressions,
      attackBlockRate: attacks.length
        ? attacks.filter((s) => s.decision === 'DENY').length / attacks.length
        : 0,
      benignAllowRate: benign.length
        ? benign.filter((s) => s.decision === 'ALLOW').length / benign.length
        : 0,
      evasionBlockOrStepUpRate: evasion.length
        ? evasion.filter((s) => s.decision !== 'ALLOW' || s.baselineExpected === 'ALLOW').length / evasion.length
        : 0,
      // Fix 7 — false positive / false negative rates
      falsePositiveRate: Math.round(falsePositiveRate * 1000) / 1000,
      falseNegativeRate: Math.round(falseNegativeRate * 1000) / 1000,
      meanRiskScore: Math.round(
        (scenarioResults.filter((s) => s.riskScore != null).reduce((a, s) => a + s.riskScore, 0)
          / Math.max(scenarioResults.filter((s) => s.riskScore != null).length, 1)) * 1000
      ) / 1000,
      riskScenariosMfaRate: risk.length
        ? risk.filter((s) => s.decision === 'MFA_REQUIRED').length / risk.length
        : 0,
    },
    scenarios: scenarioResults,
  };

  await db.close();
  console.log(JSON.stringify(output));
}

main().catch((err) => {
  console.error(JSON.stringify({ error: err.message, stack: err.stack }));
  process.exit(1);
});
