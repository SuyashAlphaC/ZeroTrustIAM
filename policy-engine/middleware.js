'use strict';

const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const Joi = require('joi');
const config = require('./config');
const db = require('./database');

// ──────────────────────── Helmet (security headers) ────────────────────────

const securityHeaders = helmet({
  contentSecurityPolicy: config.nodeEnv === 'production' ? undefined : false,
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
 * Middleware that requires a valid JWT access token.
 * Populates req.user with { sub, role, type }.
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const jwtKey = db.getActiveSigningKey('jwt');
    if (!jwtKey) {
      return res.status(500).json({ error: 'Server configuration error' });
    }
    const decoded = jwt.verify(token, jwtKey.private_key, { issuer: config.jwtIssuer });
    if (decoded.type !== 'access') {
      return res.status(401).json({ error: 'Invalid token type', code: 'INVALID_TOKEN_TYPE' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token expired or invalid', code: 'INVALID_TOKEN' });
  }
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

  // User registration
  createUser: Joi.object({
    userId: Joi.string().alphanum().min(2).max(50).required(),
    password: Joi.string().min(6).max(128).required(),
    role: Joi.string().valid('admin', 'viewer', 'editor').optional(),
    usualCountry: Joi.string().max(10).optional(),
    usualCity: Joi.string().max(100).optional(),
    normalHoursStart: Joi.number().integer().min(0).max(23).optional(),
    normalHoursEnd: Joi.number().integer().min(0).max(23).optional(),
    devices: Joi.array().items(Joi.string().max(100)).optional(),
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
