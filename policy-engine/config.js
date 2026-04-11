'use strict';

require('dotenv').config();

/**
 * Centralized configuration. Every tunable value lives here.
 * Override any value via environment variable.
 *
 * In production (NODE_ENV=production), certain secrets MUST be set
 * via environment variables — the server will refuse to start without them.
 */

const isProd = (process.env.NODE_ENV || 'development') === 'production';

// Enforce required secrets in production
function requireEnv(name) {
  const val = process.env[name];
  if (!val && isProd) {
    throw new Error(`FATAL: Environment variable ${name} is required in production mode`);
  }
  return val;
}

const config = {
  // Server
  port: parseInt(process.env.PORT || '4000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  useMock: process.env.USE_MOCK === 'true',
  seedDemo: process.env.SEED_DEMO === 'true', // only seed demo data when explicitly requested

  // Database
  dbPath: process.env.DB_PATH || undefined, // defaults to ./data/iam.db

  // Bcrypt
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '12', 10),

  // Risk scoring
  riskThreshold: parseFloat(process.env.RISK_THRESHOLD || '0.6'),
  riskWeights: {
    device: parseFloat(process.env.RISK_WEIGHT_DEVICE || '0.40'),
    location: parseFloat(process.env.RISK_WEIGHT_LOCATION || '0.30'),
    time: parseFloat(process.env.RISK_WEIGHT_TIME || '0.20'),
    attempts: parseFloat(process.env.RISK_WEIGHT_ATTEMPTS || '0.10'),
  },

  // Anomaly detection
  anomalyWeight: parseFloat(process.env.ANOMALY_WEIGHT || '0.15'),
  anomalyThreshold: parseFloat(process.env.ANOMALY_THRESHOLD || '0.4'),

  // MFA
  mfaStepUpThreshold: parseFloat(process.env.MFA_STEP_UP_THRESHOLD || '0.3'),
  mfaIssuer: process.env.MFA_ISSUER || 'ZeroTrustIAM',
  mfaChallengeExpiry: parseInt(process.env.MFA_CHALLENGE_EXPIRY_SECONDS || '300', 10),

  // JWT — required in production
  jwtSecret: requireEnv('JWT_SECRET'),
  jwtRefreshSecret: requireEnv('JWT_REFRESH_SECRET'),
  jwtAccessExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
  jwtRefreshExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
  jwtIssuer: process.env.JWT_ISSUER || 'zt-iam-policy-engine',

  // OAuth — required in production
  oauthIssuer: process.env.OAUTH_ISSUER || 'http://localhost:4000',
  oauthCodeExpiry: parseInt(process.env.OAUTH_CODE_EXPIRY_SECONDS || '600', 10),
  oauthDefaultClientId: process.env.OAUTH_DEFAULT_CLIENT_ID || 'zt-iam-web',
  oauthDefaultClientSecret: requireEnv('OAUTH_DEFAULT_CLIENT_SECRET'),
  oauthCallbackUrl: process.env.OAUTH_CALLBACK_URL || 'http://localhost:3000/oauth/callback',

  // WebAuthn
  webauthnRpName: process.env.WEBAUTHN_RP_NAME || 'Zero Trust IAM',
  webauthnRpId: process.env.WEBAUTHN_RP_ID || 'localhost',
  webauthnOrigin: process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000',

  // Rate limiting
  rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || '30', 10),
  rateLimitAuthMax: parseInt(process.env.RATE_LIMIT_AUTH_MAX || '10', 10),

  // Logging
  logLevel: process.env.LOG_LEVEL || 'info',

  // Fabric
  fabricChannelName: process.env.FABRIC_CHANNEL || 'iamchannel',
  fabricChaincodeName: process.env.FABRIC_CHAINCODE || 'iam-cc',
  fabricMspId: process.env.FABRIC_MSP_ID || 'Org1MSP',
  fabricPeerEndpoint: process.env.FABRIC_PEER_ENDPOINT || 'localhost:7051',

  // Cleanup job interval (ms)
  cleanupInterval: parseInt(process.env.CLEANUP_INTERVAL_MS || '300000', 10),

  // ZKP
  zkpEnabled: process.env.ZKP_ENABLED !== 'false',
  zkpExperimental: true,

  // ML risk scoring sidecar (Python FastAPI)
  mlServiceEnabled: process.env.ML_SERVICE_ENABLED !== 'false',
  mlServiceUrl: process.env.ML_SERVICE_URL || 'http://localhost:5000',
  mlServiceTimeoutMs: parseInt(process.env.ML_SERVICE_TIMEOUT_MS || '800', 10),

  // Ensemble weights: AHP + ML + anomaly (must sum to 1)
  ensembleAhpWeight: parseFloat(process.env.ENSEMBLE_AHP_WEIGHT || '0.4'),
  ensembleMlWeight: parseFloat(process.env.ENSEMBLE_ML_WEIGHT || '0.4'),
  ensembleAnomalyWeight: parseFloat(process.env.ENSEMBLE_ANOMALY_WEIGHT || '0.2'),
};

module.exports = config;
