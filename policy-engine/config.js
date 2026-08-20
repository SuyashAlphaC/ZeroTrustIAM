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
const mlEnabled = process.env.ML_SERVICE_ENABLED !== 'false';

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
  seedDemo: process.env.SEED_DEMO === 'true', // only seed demo data when explicitly requested

  // Database
  dbPath: process.env.DB_PATH || undefined,
  dbUrl: process.env.DATABASE_URL || '',

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

  /**
   * When true, /evaluate may include raw riskScore/breakdown (debug only).
   * Default false — production and normal clients never see scores.
   * Set EXPOSE_RISK_DETAILS=true only for local model debugging.
   */
  exposeRiskDetails: process.env.EXPOSE_RISK_DETAILS === 'true',

  /**
   * How unknown device credentials are enrolled at login:
   *  first_only | password | mfa | off
   * Production default: first_only (TOFU for brand-new accounts only).
   * Development default: password (enroll after password when risk is under threshold).
   */
  deviceEnrollMode: process.env.DEVICE_ENROLL_MODE
    || (isProd ? 'first_only' : 'password'),

  // Anomaly detection
  anomalyWeight: parseFloat(process.env.ANOMALY_WEIGHT || '0.15'),
  anomalyThreshold: parseFloat(process.env.ANOMALY_THRESHOLD || '0.4'),
  /** Require this many profile samples before using the normal anomaly threshold (cold-start hardening). */
  anomalyColdStartMinSamples: parseInt(process.env.ANOMALY_COLDSTART_MIN_SAMPLES || '8', 10),
  /** Extra margin added to the anomaly threshold while the profile is immature. */
  anomalyColdStartEpsilon: parseFloat(process.env.ANOMALY_COLDSTART_EPSILON || '0.12'),

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
  fabricPeerEndpointOrg2: process.env.FABRIC_PEER_ENDPOINT_ORG2 || 'localhost:9051',

  // mTLS HTTPS (recommended in production: web-app → policy-engine uses a client certificate)
  tlsEnabled: process.env.TLS_ENABLED === 'true',
  tlsKeyPath: process.env.TLS_KEY_PATH || '',
  tlsCertPath: process.env.TLS_CERT_PATH || '',
  /** CA used to validate trusted service clients during the TLS handshake */
  tlsClientCaPath: process.env.MTLS_CA_PATH || process.env.TLS_CLIENT_CA_PATH || '',

  // Cleanup job interval (ms)
  cleanupInterval: parseInt(process.env.CLEANUP_INTERVAL_MS || '300000', 10),

  // ZKP — PERMANENTLY disabled by default. Custom EC proofs are not audited.
  // Set ZKP_MODE=experimental to re-enable the demo implementation for research only.
  // When ZKP_MODE is set (including 'disabled'), it wins over legacy ZKP_ENABLED.
  zkpMode: (process.env.ZKP_MODE || (process.env.ZKP_ENABLED === 'true' ? 'experimental' : 'disabled')).toLowerCase(),
  get zkpEnabled() {
    const mode = (process.env.ZKP_MODE
      || (process.env.ZKP_ENABLED === 'true' ? 'experimental' : 'disabled')).toLowerCase();
    return mode === 'experimental';
  },
  zkpExperimental: true,
  /** When true, Fabric outage fails closed on evaluate (default). soft = AHP-only deny-on-high-risk without ledger. */
  fabricFailureMode: process.env.FABRIC_FAILURE_MODE || 'fail_closed',
  /** ML timeout already in mlServiceTimeoutMs; on timeout ensemble falls back to AHP+anomaly. */
  mlFailureMode: process.env.ML_FAILURE_MODE || 'degrade', // degrade | fail_closed

  // Encryption for at-rest local secrets
  appEncryptionKey: isProd
    ? requireEnv('APP_ENCRYPTION_KEY')
    : (process.env.APP_ENCRYPTION_KEY || process.env.JWT_SECRET || 'local-dev-only-encryption-key'),

  // ML risk scoring sidecar (Python FastAPI)
  mlServiceEnabled: mlEnabled,
  mlServiceUrl: process.env.ML_SERVICE_URL || 'http://localhost:5000',
  mlServiceTimeoutMs: parseInt(process.env.ML_SERVICE_TIMEOUT_MS || '800', 10),
  mlServiceToken: mlEnabled
    ? (isProd ? requireEnv('ML_SERVICE_TOKEN') : (process.env.ML_SERVICE_TOKEN || 'dev-ml-service-token'))
    : null,

  // ─── Lifecycle notifications (email / SMS) ───────────────────────────
  /** Master switch. Default true — log mode still records intent without providers. */
  notifyEnabled: process.env.NOTIFY_ENABLED !== 'false',
  /**
   * log  = structured logs + DB outbox only (safe default)
   * smtp = real email when SMTP_* set; SMS log unless Twilio set
   * full = email + SMS when both configured
   */
  notifyMode: (process.env.NOTIFICATION_MODE || 'log').toLowerCase(),
  notifyOrgName: process.env.NOTIFY_ORG_NAME || 'ZeroTrust IAM',
  notifyLoginUrl: process.env.NOTIFY_LOGIN_URL || process.env.OAUTH_CALLBACK_URL?.replace(/\/oauth\/callback$/, '') || 'http://localhost:3000',
  /** Include temporary password in email body (never in SMS). Default false in production. */
  notifyIncludeTempPassword: process.env.NOTIFY_INCLUDE_TEMP_PASSWORD === 'true'
    || (!isProd && process.env.NOTIFY_INCLUDE_TEMP_PASSWORD !== 'false'),

  get notifyEmailEnabled() {
    const mode = (process.env.NOTIFICATION_MODE || 'log').toLowerCase();
    if (mode === 'log') return false;
    return !!(process.env.SMTP_HOST && process.env.SMTP_FROM);
  },
  get notifySmsEnabled() {
    const mode = (process.env.NOTIFICATION_MODE || 'log').toLowerCase();
    if (mode === 'log') return false;
    if (mode === 'smtp' && process.env.NOTIFY_SMS !== 'true') return false;
    return !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM);
  },
  smtpHost: process.env.SMTP_HOST || '',
  smtpPort: parseInt(process.env.SMTP_PORT || '587', 10),
  smtpSecure: process.env.SMTP_SECURE === 'true',
  smtpUser: process.env.SMTP_USER || '',
  smtpPass: process.env.SMTP_PASS || '',
  smtpFrom: process.env.SMTP_FROM || 'noreply@zerotrust.local',
  twilioAccountSid: process.env.TWILIO_ACCOUNT_SID || '',
  twilioAuthToken: process.env.TWILIO_AUTH_TOKEN || '',
  twilioFrom: process.env.TWILIO_FROM || '',

  // Ensemble weights: AHP + ML + anomaly (must sum to 1)
  ensembleAhpWeight: parseFloat(process.env.ENSEMBLE_AHP_WEIGHT || '0.4'),
  ensembleMlWeight: parseFloat(process.env.ENSEMBLE_ML_WEIGHT || '0.4'),
  ensembleAnomalyWeight: parseFloat(process.env.ENSEMBLE_ANOMALY_WEIGHT || '0.2'),

  // KMS / Vault Transit (Tier A.1)
  // KMS_BACKEND ∈ { 'local' (default, RSA key in Postgres signing_keys),
  //                 'vault'  (HashiCorp Vault Transit — key never leaves Vault),
  //                 'aws'    (AWS KMS — stub, NotImplemented) }
  kmsBackend: process.env.KMS_BACKEND || 'local',
  vaultAddr: process.env.VAULT_ADDR || 'http://vault:8200',
  vaultToken: process.env.VAULT_TOKEN || '',
  vaultTransitKeyName: process.env.VAULT_TRANSIT_KEY_NAME
    || `ztiam-jwt-${process.env.NODE_ENV || 'dev'}`,
  vaultTimeoutMs: parseInt(process.env.VAULT_TIMEOUT_MS || '3000', 10),
};

if (isProd) {
  requireEnv('DATABASE_URL');
  if (!config.tlsEnabled) throw new Error('Production requires TLS_ENABLED=true for the policy-engine HTTP API');
  requireEnv('TLS_KEY_PATH');
  requireEnv('TLS_CERT_PATH');
  requireEnv('MTLS_CA_PATH');
  // Prefer external KMS in production
  if (config.kmsBackend === 'local') {
    // eslint-disable-next-line no-console
    console.warn('WARN: KMS_BACKEND=local in production — prefer vault or aws');
  }
}

module.exports = config;
