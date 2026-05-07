// Off-chain immutable mirror for audit log entries.
//
// Mirrors each chaincode audit entry to an S3 bucket with Object Lock in
// COMPLIANCE mode for a 90-day retention window. Designed to be fire-and-
// forget: any S3 failure is logged but never propagated to the request path.
'use strict';

const { logger } = require('./logger');

let s3Client = null;
let S3PutObjectCommand = null;

function getRetainUntilDate() {
  return new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
}

function buildObjectKey(entryHash, now = new Date()) {
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(now.getUTCDate()).padStart(2, '0');
  return `audit/${yyyy}/${mm}/${dd}/${entryHash}.json`;
}

function getClient() {
  if (s3Client) return s3Client;
  // Lazy-load SDK so the dep is optional when mirroring is disabled.
  // eslint-disable-next-line global-require
  const sdk = require('@aws-sdk/client-s3');
  S3PutObjectCommand = sdk.PutObjectCommand;
  s3Client = new sdk.S3Client({ region: process.env.AWS_REGION || 'us-east-1' });
  return s3Client;
}

async function mirrorAuditEntry(entry) {
  const bucket = process.env.AUDIT_MIRROR_BUCKET;
  if (!bucket) return; // mirror disabled
  if (!entry || !entry.entryHash) return;

  try {
    const client = getClient();
    const key = buildObjectKey(entry.entryHash);
    const command = new S3PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: JSON.stringify(entry),
      ContentType: 'application/json',
      ObjectLockMode: 'COMPLIANCE',
      ObjectLockRetainUntilDate: getRetainUntilDate(),
    });
    await client.send(command);
  } catch (err) {
    logger.warn({ err: err.message, entryHash: entry.entryHash }, 'audit mirror S3 put failed');
  }
}

async function close() {
  if (s3Client && typeof s3Client.destroy === 'function') {
    try { s3Client.destroy(); } catch (_) { /* ignore */ }
  }
  s3Client = null;
  S3PutObjectCommand = null;
}

module.exports = { mirrorAuditEntry, close, buildObjectKey };
