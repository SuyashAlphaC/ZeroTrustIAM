#!/usr/bin/env node
'use strict';

/**
 * Minimal Envoy ext_authz gRPC/HTTP sidecar using @ztiam/pep-sdk.
 * Default: HTTP JSON on :9001 for simplicity (Envoy http_service).
 */

const http = require('http');
const path = require('path');

// Resolve pep-sdk from monorepo packages/
let createPep;
try {
  createPep = require('../../pep-sdk').createPep;
} catch {
  createPep = require('@ztiam/pep-sdk').createPep;
}

const PORT = parseInt(process.env.PEP_PORT || '9001', 10);
const pep = createPep({
  issuerUrl: process.env.ZTIAM_URL || 'http://localhost:4000',
  requireTenant: process.env.PEP_REQUIRE_TENANT === 'true',
});

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  const headers = { ...req.headers };
  // Check path: Envoy may POST body with attributes — also support Authorization header passthrough
  let body = {};
  if (req.method === 'POST') {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    try {
      body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
    } catch {
      body = {};
    }
  }
  const httpAttrs = body.attributes?.request?.http || {};
  const mergedHeaders = { ...headers, ...(httpAttrs.headers || {}) };

  const decision = await pep.envoyCheck({ headers: mergedHeaders, path: httpAttrs.path });
  const denied = decision.status?.code && decision.status.code !== 0;
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(decision));
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`PEP ext_authz listening on :${PORT} → ${process.env.ZTIAM_URL || 'http://localhost:4000'}`);
});
