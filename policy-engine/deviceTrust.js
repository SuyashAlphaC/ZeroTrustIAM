'use strict';

/**
 * Device trust / enrollment helpers for login.
 *
 * Clients must present an opaque, non-user-editable device credential
 * (e.g. UUID stored in localStorage). Free-text "device id" entry is not a
 * trust factor.
 *
 * Enrollment modes (config.deviceEnrollMode):
 *  - first_only  — auto-enroll only when the account has zero devices (TOFU)
 *  - password    — auto-enroll unknown device after password + risk under threshold
 *  - mfa         — enroll only after successful MFA step-up (challenge flag)
 *  - off         — never auto-enroll; unknown device is denied
 */

const config = require('./config');
const userProvisioning = require('./userProvisioning');
const { logger } = require('./logger');

/** Accept opaque credentials: UUID, d_<token>, plus legacy seed ids (dev-001). */
const DEVICE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{5,99}$/;

function isValidDeviceCredential(deviceId) {
  if (!deviceId || typeof deviceId !== 'string') return false;
  if (deviceId.length < 6 || deviceId.length > 100) return false;
  return DEVICE_ID_RE.test(deviceId);
}

function isDeviceRegistered(userProfile, deviceId) {
  const list = userProfile?.registeredDevices || [];
  return list.includes(deviceId);
}

/**
 * Ensure the presented device may proceed to authorization.
 * May dual-write a new device registration (Postgres + Fabric).
 *
 * @returns {Promise<{ ok: true, enrolled: boolean, userProfile } | { ok: false, decision: string, reason: string, reasonCode: string }>}
 */
async function ensureDeviceTrusted(userProfile, deviceId, opts = {}) {
  if (!isValidDeviceCredential(deviceId)) {
    return {
      ok: false,
      decision: 'DENY',
      reason: 'Untrusted device',
      reasonCode: 'UNTRUSTED_DEVICE',
    };
  }

  if (isDeviceRegistered(userProfile, deviceId)) {
    return { ok: true, enrolled: false, userProfile };
  }

  const mode = config.deviceEnrollMode || 'first_only';
  const deviceCount = (userProfile.registeredDevices || []).length;
  const riskScore = typeof opts.riskScore === 'number' ? opts.riskScore : 1;
  const mfaVerified = opts.mfaVerified === true;
  const forceEnroll = opts.forceEnroll === true;

  let mayEnroll = false;
  if (forceEnroll || mode === 'password') {
    mayEnroll = riskScore < config.riskThreshold;
  } else if (mode === 'mfa') {
    mayEnroll = mfaVerified && riskScore < config.riskThreshold;
  } else if (mode === 'first_only') {
    mayEnroll = deviceCount === 0 && riskScore < config.riskThreshold;
  } else {
    mayEnroll = false;
  }

  // MFA mode without verification yet: signal step-up enroll path
  if (!mayEnroll && mode === 'mfa' && !mfaVerified && riskScore < config.riskThreshold) {
    return {
      ok: false,
      decision: 'MFA_REQUIRED',
      reason: 'New device requires step-up authentication',
      reasonCode: 'MFA_REQUIRED',
      enrollDevice: true,
    };
  }

  if (!mayEnroll) {
    return {
      ok: false,
      decision: 'DENY',
      reason: 'Untrusted device',
      reasonCode: 'UNTRUSTED_DEVICE',
    };
  }

  try {
    await userProvisioning.provisionDevice(userProfile.userId || userProfile.username, deviceId, {
      label: opts.label || 'Browser',
      role: userProfile.role,
    });
    const devices = [...(userProfile.registeredDevices || []), deviceId];
    const updated = { ...userProfile, registeredDevices: devices };
    logger.info(
      { userId: userProfile.userId || userProfile.username, deviceId, mode },
      'Auto-enrolled device credential'
    );
    return { ok: true, enrolled: true, userProfile: updated };
  } catch (err) {
    logger.error({ err: err.message, deviceId }, 'Device auto-enroll failed');
    return {
      ok: false,
      decision: 'DENY',
      reason: 'Untrusted device',
      reasonCode: 'UNTRUSTED_DEVICE',
    };
  }
}

module.exports = {
  isValidDeviceCredential,
  isDeviceRegistered,
  ensureDeviceTrusted,
};
