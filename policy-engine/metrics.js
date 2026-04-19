'use strict';

/**
 * Minimal, dependency-free Prometheus counters/gauges + Express middleware.
 *
 * We deliberately avoid pulling a full client library — the handful of
 * counters we need (total requests, decisions, errors) keeps the exposition
 * trivial and the runtime tiny.
 */

const counters = new Map();
const gauges = new Map();

function inc(name, labels = {}, value = 1) {
  const key = _key(name, labels);
  counters.set(key, (counters.get(key) || 0) + value);
}

function setGauge(name, labels, value) {
  const key = _key(name, labels);
  gauges.set(key, value);
}

function _key(name, labels) {
  const parts = Object.entries(labels)
    .filter(([, v]) => v !== undefined && v !== null)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}="${String(v).replace(/"/g, '\\"')}"`);
  return parts.length ? `${name}{${parts.join(',')}}` : name;
}

function httpMetricsMiddleware(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const route = req.route?.path || req.path;
    inc('ztiam_http_requests_total', {
      method: req.method,
      route,
      status: res.statusCode,
    });
    const bucket = _latencyBucket(Date.now() - start);
    inc('ztiam_http_latency_bucket_total', { route, le: bucket });
  });
  next();
}

function _latencyBucket(ms) {
  const buckets = [5, 25, 100, 250, 500, 1000, 2500, 5000];
  for (const b of buckets) if (ms <= b) return String(b);
  return '+Inf';
}

function renderText() {
  const lines = [];
  lines.push('# HELP ztiam_http_requests_total HTTP requests received');
  lines.push('# TYPE ztiam_http_requests_total counter');
  for (const [k, v] of counters) {
    if (k.startsWith('ztiam_http_requests_total')) lines.push(`${k} ${v}`);
  }
  lines.push('# HELP ztiam_http_latency_bucket_total Request latency histogram (ms)');
  lines.push('# TYPE ztiam_http_latency_bucket_total counter');
  for (const [k, v] of counters) {
    if (k.startsWith('ztiam_http_latency_bucket_total')) lines.push(`${k} ${v}`);
  }
  lines.push('# HELP ztiam_decisions_total Access decisions emitted by /evaluate');
  lines.push('# TYPE ztiam_decisions_total counter');
  for (const [k, v] of counters) {
    if (k.startsWith('ztiam_decisions_total')) lines.push(`${k} ${v}`);
  }
  lines.push('# HELP ztiam_ml_ingest_total Labeled samples sent to ML sidecar');
  lines.push('# TYPE ztiam_ml_ingest_total counter');
  for (const [k, v] of counters) {
    if (k.startsWith('ztiam_ml_ingest_total')) lines.push(`${k} ${v}`);
  }
  for (const [k, v] of gauges) lines.push(`${k} ${v}`);
  return lines.join('\n') + '\n';
}

module.exports = { inc, setGauge, httpMetricsMiddleware, renderText };
