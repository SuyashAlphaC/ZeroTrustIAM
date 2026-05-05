'use strict';

/**
 * Optional HashiCorp KV v2 bootstrap (sync, before the rest of the app loads).
 *
 * - Reads a local JSON file first (SECRETS_JSON_PATH / VAULT_LOCAL_SECRET_FILE).
 * - If VAULT_BOOTSTRAP_SYNC=true and VAULT_ADDR + VAULT_TOKEN are set, curls
 *   the KV v2 read API and merges `{ data: { data: { KEY: "value" }}}` into
 *   `process.env` (only when the key is absent from the environment).
 *
 * In production, Vault Agent or init containers are equally valid; this module
 * keeps a small in-process path for docker-compose and demos.
 */

const fs = require('fs');
const { spawnSync } = require('child_process');

function mergeEnvFromJson(obj) {
  if (!obj || typeof obj !== 'object') return;
  for (const [key, value] of Object.entries(obj)) {
    if (process.env[key] !== undefined && process.env[key] !== '') continue;
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      process.env[key] = String(value);
    } else if (value != null) {
      process.env[key] = JSON.stringify(value);
    }
  }
}

function hydrateFromLocalSecretsFile() {
  const p = process.env.SECRETS_JSON_PATH || process.env.VAULT_LOCAL_SECRET_FILE;
  if (!p || !fs.existsSync(p)) return;
  const raw = fs.readFileSync(p, 'utf8');
  mergeEnvFromJson(JSON.parse(raw));
}

function hydrateFromVaultKvSync() {
  const addr = (process.env.VAULT_ADDR || '').replace(/\/$/, '');
  const token = process.env.VAULT_TOKEN || '';
  const enabled = process.env.VAULT_BOOTSTRAP_SYNC === 'true' || process.env.VAULT_BOOTSTRAP_SYNC === '1';
  const pathSuffix = (
    process.env.VAULT_SECRET_PATH
    || process.env.VAULT_KV_PATH
    || 'secret/data/policy-engine'
  ).replace(/^\//, '');

  if (!enabled || !addr || !token) return;

  const url = `${addr}/v1/${pathSuffix}`;
  const res = spawnSync(
    'curl',
    ['-sS', '-g', '--fail-with-body', '--max-time', '15', '-H', `X-Vault-Token: ${token}`, url],
    { encoding: 'utf8', maxBuffer: 1024 * 1024 },
  );

  if (res.status !== 0) {
    throw new Error(`vault KV bootstrap failed (curl exit ${res.status}): ${res.stderr || res.stdout}`);
  }

  const payload = JSON.parse(res.stdout || '{}');
  const secretMap = payload.data?.data?.data || payload.data?.data;
  if (!secretMap || typeof secretMap !== 'object') {
    throw new Error('vault KV response missing data.data envelope');
  }
  mergeEnvFromJson(secretMap);
}

function bootstrapVaultEnvSync() {
  hydrateFromLocalSecretsFile();
  hydrateFromVaultKvSync();
}

module.exports = { bootstrapVaultEnvSync, hydrateFromLocalSecretsFile, hydrateFromVaultKvSync, mergeEnvFromJson };
