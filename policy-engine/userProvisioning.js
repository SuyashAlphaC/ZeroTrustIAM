'use strict';

/**
 * Dual-write user provisioning: Postgres (credentials) + Fabric (authorization registry).
 *
 * Call sites: admin create, SCIM, federation, self-service device registration.
 */

const db = require('./database');
const blockchain = require('./fabricClient');
const passwordPolicy = require('./passwordPolicy');
const { logger } = require('./logger');

/**
 * Create a user in Postgres and on Fabric.
 *
 * @param {object} opts
 * @param {string} opts.userId
 * @param {string} [opts.password] - plain password (hashed here); optional if passwordHash set
 * @param {string} [opts.passwordHash]
 * @param {string} [opts.role]
 * @param {string[]} [opts.devices]
 * @param {string} [opts.usualCountry]
 * @param {string} [opts.usualCity]
 * @param {number} [opts.normalHoursStart]
 * @param {number} [opts.normalHoursEnd]
 * @param {string} [opts.tenantId]
 * @param {string} [opts.email]
 * @param {boolean} [opts.skipPasswordPolicy]
 * @returns {Promise<{ userId: string, fabric: object|null, devices: string[] }>}
 */
async function provisionUser(opts) {
  const userId = opts.userId;
  if (!userId) throw Object.assign(new Error('userId required'), { code: 'INVALID' });

  const existing = await db.getUser(userId);
  if (existing) {
    throw Object.assign(new Error('User already exists'), { code: 'EXISTS' });
  }

  let passwordHash = opts.passwordHash;
  if (!passwordHash) {
    if (!opts.password) {
      throw Object.assign(new Error('password or passwordHash required'), { code: 'INVALID' });
    }
    if (!opts.skipPasswordPolicy) {
      const check = passwordPolicy.validatePassword(opts.password, { username: userId });
      if (!check.ok) {
        const err = new Error('Password policy violation');
        err.code = 'PASSWORD_POLICY';
        err.details = check.errors;
        throw err;
      }
    }
    passwordHash = await passwordPolicy.hashPassword(opts.password);
  }

  const devices = Array.isArray(opts.devices)
    ? opts.devices.map(String).filter(Boolean)
    : [];
  const role = opts.role || 'viewer';

  await db.createUserWithHash({
    userId,
    passwordHash,
    role,
    usualCountry: opts.usualCountry,
    usualCity: opts.usualCity,
    normalHoursStart: opts.normalHoursStart,
    normalHoursEnd: opts.normalHoursEnd,
    devices,
    tenantId: opts.tenantId,
    email: opts.email,
    phone: opts.phone,
  });

  let fabric = null;
  try {
    fabric = await blockchain.createUser({
      userId,
      role,
      devices,
      status: 'ACTIVE',
    });
    logger.info({ userId, fabricStatus: fabric.status }, 'User dual-written to Fabric');
  } catch (err) {
    logger.error({ err: err.message, userId }, 'Fabric CreateUser failed — rolling back Postgres user');
    try {
      await db.rollbackNewUser(userId);
    } catch (rbErr) {
      logger.error({ err: rbErr.message, userId }, 'Postgres rollback after Fabric failure also failed');
    }
    const e = new Error(`Fabric provisioning failed: ${err.message}`);
    e.code = 'FABRIC_PROVISION_FAILED';
    e.cause = err;
    throw e;
  }

  await db.writeAuditLog({
    userId,
    decision: 'USER_CREATED',
    reason: `Provisioned role=${role} devices=${devices.length}`,
    layer: 'Provisioning',
    metadata: { fabric: fabric?.status, devices },
  }).catch(() => {});

  return { userId, fabric, devices, role };
}

/**
 * Register a device in Postgres + Fabric (creates on-chain user if missing).
 *
 * @param {string} userId
 * @param {string} deviceId
 * @param {{ label?: string, role?: string }} [opts]
 */
async function provisionDevice(userId, deviceId, opts = {}) {
  if (!userId || !deviceId) {
    throw Object.assign(new Error('userId and deviceId required'), { code: 'INVALID' });
  }

  const user = await db.getUser(userId);
  if (!user) {
    throw Object.assign(new Error('User not found'), { code: 'NOT_FOUND' });
  }

  await db.registerDevice(userId, deviceId, opts.label || null);

  let fabric = null;
  try {
    fabric = await blockchain.registerDevice(userId, deviceId, {
      role: opts.role || user.role || 'viewer',
      ensureUser: true,
    });
    logger.info({ userId, deviceId, fabricStatus: fabric.status }, 'Device dual-written to Fabric');
  } catch (err) {
    // Compensating: remove the just-added device from Postgres so stores stay aligned
    logger.error({ err: err.message, userId, deviceId }, 'Fabric RegisterDevice failed — rolling back Postgres device');
    try {
      await db.deleteUserDevice(userId, deviceId);
    } catch (rbErr) {
      logger.error({ err: rbErr.message }, 'Device rollback failed');
    }
    const e = new Error(`Fabric device registration failed: ${err.message}`);
    e.code = 'FABRIC_DEVICE_FAILED';
    e.cause = err;
    throw e;
  }

  await db.writeAuditLog({
    userId,
    deviceId,
    decision: 'DEVICE_REGISTERED',
    reason: opts.label ? `label=${opts.label}` : 'Device registered',
    layer: 'Provisioning',
    metadata: { fabric: fabric?.status },
  }).catch(() => {});

  return { userId, deviceId, fabric, label: opts.label || null };
}

/**
 * Ensure an existing Postgres user also exists on Fabric (e.g. after federation
 * created the local row, or migrating seed users). Merges current devices.
 */
async function syncUserToFabric(userId) {
  const user = await db.getUser(userId);
  if (!user) {
    throw Object.assign(new Error('User not found'), { code: 'NOT_FOUND' });
  }
  const fabric = await blockchain.createUser({
    userId: user.userId,
    role: user.role,
    devices: user.registeredDevices || [],
    status: user.status || 'ACTIVE',
  });
  return fabric;
}

module.exports = {
  provisionUser,
  provisionDevice,
  syncUserToFabric,
};
