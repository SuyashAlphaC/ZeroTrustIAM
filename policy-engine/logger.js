'use strict';

const pino = require('pino');
const crypto = require('crypto');
const config = require('./config');

const logger = pino({
  level: config.logLevel,
  transport: config.nodeEnv === 'development'
    ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'SYS:standard', ignore: 'pid,hostname' } }
    : undefined, // JSON in production
  base: { service: 'zt-iam-policy-engine' },
});

/**
 * Express middleware that attaches a request logger with a unique request ID.
 */
function requestLogger(req, res, next) {
  req.id = req.headers['x-request-id'] || crypto.randomUUID();
  req.log = logger.child({ reqId: req.id });

  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    req.log[level]({
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration,
      ip: req.ip,
    }, `${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
  });

  res.setHeader('X-Request-ID', req.id);
  next();
}

module.exports = { logger, requestLogger };
