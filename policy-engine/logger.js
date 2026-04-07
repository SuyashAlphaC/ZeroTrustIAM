'use strict';

const pino = require('pino');
const crypto = require('crypto');
const config = require('./config');

const isJest = typeof process.env.JEST_WORKER_ID !== 'undefined';
const loggerLevel = isJest && process.env.ENABLE_TEST_LOGS !== 'true' ? 'silent' : config.logLevel;
const usePrettyTransport = config.nodeEnv === 'development' && !isJest && loggerLevel !== 'silent';

const logger = pino({
  level: loggerLevel,
  transport: usePrettyTransport
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
