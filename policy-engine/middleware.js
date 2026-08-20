'use strict';

const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const Joi = require('joi');
const config = require('./config');

// ──────────────────────── Helmet (security headers) ────────────────────────

const securityHeaders = helmet({
  contentSecurityPolicy: (process.env.NODE_ENV || 'development') === 'production' ? undefined : false,
  crossOriginEmbedderPolicy: false,
});

// ──────────────────────── Rate Limiting ────────────────────────

const globalLimiter = rateLimit({
  windowMs: config.rateLimitWindow,
  max: config.rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
});

const authLimiter = rateLimit({
  windowMs: config.rateLimitWindow,
  max: config.rateLimitAuthMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts, please try again later' },
});

// ──────────────────────── JWT Auth Middleware ────────────────────────

/**
 * Middleware that requires a valid JWT access token (RS256 via kmsSigner).
 * Populates req.user with { sub, role, type }.
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
  }

  const token = authHeader.split(' ')[1];
  // Lazy-require to avoid circular init with kmsSigner → database → config
  const kmsSigner = require('./kmsSigner');
  kmsSigner.verifyJwt(token, { issuer: config.jwtIssuer })
    .then((decoded) => {
      if (decoded.type !== 'access') {
        return res.status(401).json({ error: 'Invalid token type', code: 'INVALID_TOKEN_TYPE' });
      }
      req.user = decoded;
      next();
    })
    .catch(() => res.status(401).json({ error: 'Token expired or invalid', code: 'INVALID_TOKEN' }));
}

/**
 * Middleware that requires a specific role.
 * Must be used after requireAuth.
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions', required: roles, current: req.user.role });
    }
    next();
  };
}

// ──────────────────────── Input Validation Schemas ────────────────────────

const schemas = {
  // POST /evaluate
  evaluate: Joi.object({
    username: Joi.string().alphanum().min(2).max(50).required(),
    password: Joi.string().min(1).max(128).required(),
    deviceId: Joi.string().max(100).required(),
    timestamp: Joi.string().isoDate().optional(),
    ip: Joi.string().ip({ cidr: 'optional' }).optional(),
    location: Joi.object({
      country: Joi.string().max(10).required(),
      city: Joi.string().max(100).required(),
    }).optional(),
    resource: Joi.string().max(200).optional(),
    requiredPermission: Joi.string().valid('read', 'write', 'delete', 'manage').optional(),
    mfaCode: Joi.string().length(6).pattern(/^[0-9]+$/).optional(),
  }),

  // POST /mfa/enroll and /did/create
  credentialAuth: Joi.object({
    username: Joi.string().alphanum().min(2).max(50).required(),
    password: Joi.string().min(1).max(128).required(),
  }),

  // POST /mfa/verify
  mfaVerify: Joi.object({
    username: Joi.string().alphanum().min(2).max(50).required(),
    code: Joi.string().length(6).pattern(/^[0-9]+$/).required(),
  }),

  // POST /mfa/challenge
  mfaChallenge: Joi.object({
    challengeId: Joi.string().hex().length(64).required(),
    code: Joi.string().length(6).pattern(/^[0-9]+$/).required(),
  }),

  // POST /refresh-token
  refreshToken: Joi.object({
    refreshToken: Joi.string().required(),
  }),

  // POST /logout
  logout: Joi.object({
    refreshToken: Joi.string().optional(),
  }),

  // POST /oauth/token
  oauthToken: Joi.object({
    grant_type: Joi.string().valid('authorization_code', 'refresh_token').required(),
    code: Joi.string().optional(),
    client_id: Joi.string().max(100).required(),
    client_secret: Joi.string().max(200).required(),
    redirect_uri: Joi.string().uri().optional(),
  }),

  // POST /did/credential/issue
  issueVC: Joi.object({
    username: Joi.string().alphanum().min(2).max(50).required(),
    password: Joi.string().min(1).max(128).required(),
    issuerDid: Joi.string().pattern(/^did:/).required(),
    subjectDid: Joi.string().pattern(/^did:/).required(),
    types: Joi.array().items(Joi.string()).optional(),
    claims: Joi.object().optional(),
  }),

  // POST /zkp/prove
  zkpProve: Joi.object({
    riskScore: Joi.number().min(0).max(1).required(),
    threshold: Joi.number().min(0).max(1).optional(),
  }),

  // POST /zkp/verify
  zkpVerify: Joi.object({
    proof: Joi.object().required(),
  }),

  // POST /access-grants/verify
  verifyAccessGrant: Joi.object({
    grantId: Joi.string().hex().length(64).required(),
    subject: Joi.string().alphanum().min(2).max(50).optional(),
    resource: Joi.string().max(200).optional(),
    permission: Joi.string().valid('read', 'write', 'delete', 'manage').optional(),
  }),

  // POST /admin/access-grants/revoke
  revokeAccessGrant: Joi.object({
    grantId: Joi.string().hex().length(64).required(),
    reason: Joi.string().max(200).optional(),
  }),

  // POST /admin/policy/public-params and POST /admin/policies
  updatePolicyPublicParams: Joi.object({
    policyId: Joi.string().max(100).optional(),
    policyVersion: Joi.string().max(40).optional(),
    riskThreshold: Joi.number().min(0.01).max(1).optional(),
    mfaStepUpThreshold: Joi.number().min(0).max(1).optional(),
    zkpScheme: Joi.string().valid('PedersenBitRangeProof').optional(),
    zkpRequiredForAllow: Joi.boolean().optional(),
    accessGrantTtlSeconds: Joi.number().integer().min(30).max(86400).optional(),
    authorizedRiskEngines: Joi.array().items(Joi.string().max(100)).optional(),
    authorizedAuditors: Joi.array().items(Joi.string().max(100)).optional(),
    activeModelVersion: Joi.string().max(100).optional(),
    roleSchemaVersion: Joi.string().max(100).optional(),
  }).min(1),

  // POST /admin/risk-models
  registerRiskModel: Joi.object({
    modelVersion: Joi.string().max(100).required(),
    modelHash: Joi.string().max(200).required(),
    modelType: Joi.string().max(100).optional(),
    approvedBy: Joi.string().max(100).optional(),
    activate: Joi.boolean().optional(),
  }),

  // POST /anomaly/detect
  anomalyDetect: Joi.object({
    username: Joi.string().alphanum().min(2).max(50).required(),
    deviceId: Joi.string().max(100).optional(),
    timestamp: Joi.string().isoDate().optional(),
    location: Joi.object({
      country: Joi.string().max(10).required(),
      city: Joi.string().max(100).required(),
    }).optional(),
  }),

  // POST /v1/audit/:auditId/feedback (analyst ground-truth label)
  auditFeedback: Joi.object({
    label: Joi.string()
      .valid('true_positive', 'false_positive', 'true_negative', 'false_negative')
      .required(),
    notes: Joi.string().max(1000).optional(),
  }),

  // User registration
  createUser: Joi.object({
    userId: Joi.string().alphanum().min(2).max(50).required(),
    password: Joi.string().min(12).max(128).required(),
    role: Joi.string().valid('admin', 'viewer', 'editor').optional(),
    email: Joi.string().email().max(200).optional().allow('', null),
    phone: Joi.string().max(30).pattern(/^\+?[0-9\s\-().]{7,30}$/).optional().allow('', null),
    usualCountry: Joi.string().max(10).optional(),
    usualCity: Joi.string().max(100).optional(),
    normalHoursStart: Joi.number().integer().min(0).max(23).optional(),
    normalHoursEnd: Joi.number().integer().min(0).max(23).optional(),
    devices: Joi.array().items(Joi.string().max(100)).optional(),
  }),

  changePassword: Joi.object({
    currentPassword: Joi.string().min(1).max(128).required(),
    newPassword: Joi.string().min(12).max(128).required(),
  }),

  registerOwnDevice: Joi.object({
    deviceId: Joi.string().max(100).required(),
    label: Joi.string().max(100).optional().allow('', null),
  }),

  requestPasswordReset: Joi.object({
    username: Joi.string().alphanum().min(2).max(50).required(),
  }),

  completePasswordReset: Joi.object({
    token: Joi.string().min(20).max(200).required(),
    newPassword: Joi.string().min(12).max(128).required(),
  }),

  abacPolicy: Joi.object({
    policyId: Joi.string().max(100).required(),
    effect: Joi.string().valid('permit', 'forbid').required(),
    principal: Joi.object().optional(),
    action: Joi.array().items(Joi.string()).optional(),
    resource: Joi.object().optional(),
    when: Joi.object().optional(),
    description: Joi.string().max(500).optional(),
  }),

  abacEvaluate: Joi.object({
    userId: Joi.string().alphanum().min(2).max(50).required(),
    role: Joi.string().max(50).optional(),
    action: Joi.string().valid('read', 'write', 'delete', 'manage').required(),
    resourceId: Joi.string().max(200).optional(),
    resourceType: Joi.string().max(100).optional(),
    riskScore: Joi.number().min(0).max(1).optional(),
    country: Joi.string().max(10).optional(),
    mfaVerified: Joi.boolean().optional(),
    status: Joi.string().max(20).optional(),
  }),
};

/**
 * Validation middleware factory.
 * Usage: validate('evaluate') -> middleware that validates req.body against schemas.evaluate
 */
function validate(schemaName) {
  return (req, res, next) => {
    const schema = schemas[schemaName];
    if (!schema) {
      return next(); // No schema defined, skip
    }
    const { error, value } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
    if (error) {
      const details = error.details.map(d => ({ field: d.path.join('.'), message: d.message }));
      return res.status(400).json({ error: 'Validation failed', details });
    }
    req.body = value; // Use sanitized values
    next();
  };
}

// ──────────────────────── Error Handler ────────────────────────

function errorHandler(err, req, res, _next) {
  const log = req.log || require('./logger').logger;
  log.error({ err, reqId: req.id }, 'Unhandled error');
  res.status(500).json({
    error: config.nodeEnv === 'production' ? 'Internal server error' : err.message,
    reqId: req.id,
  });
}

module.exports = {
  securityHeaders,
  globalLimiter,
  authLimiter,
  requireAuth,
  requireRole,
  validate,
  schemas,
  errorHandler,
};
