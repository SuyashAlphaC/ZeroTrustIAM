'use strict';

const otplib = require('otplib');
const QRCode = require('qrcode');
const config = require('./config');
const db = require('./database');

/**
 * TOTP MFA module — fully database-backed.
 * No in-memory state. All secrets and challenges persist in SQLite.
 */

/**
 * Enroll a user in TOTP MFA.
 * Stores the secret in the database and returns a QR code for authenticator apps.
 */
async function enrollMFA(userId) {
  const secret = otplib.generateSecret();
  db.storeMFASecret(userId, secret);

  const otpauth = otplib.generateURI({
    issuer: config.mfaIssuer,
    label: userId,
    secret,
    type: 'totp',
  });
  const qrCodeDataUrl = await QRCode.toDataURL(otpauth);

  return {
    secret,
    otpauth,
    qrCodeDataUrl,
    message: 'Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)',
  };
}

/**
 * Verify a TOTP code for a user.
 * Reads the secret from the database.
 */
function verifyTOTP(userId, token) {
  const mfaData = db.getMFASecret(userId);
  if (!mfaData || !mfaData.enabled) {
    return { valid: false, reason: 'MFA not enrolled' };
  }

  const result = otplib.verifySync({ token, secret: mfaData.secret });
  const isValid = result && result.valid;
  return { valid: isValid, reason: isValid ? 'Valid TOTP code' : 'Invalid or expired TOTP code' };
}

/**
 * Check if a user has MFA enabled (from database).
 */
function isMFAEnabled(userId) {
  const mfaData = db.getMFASecret(userId);
  return !!(mfaData && mfaData.enabled);
}

/**
 * Determine if MFA step-up is required based on risk score and operation.
 */
function requiresStepUp(riskScore, requiredPermission) {
  const sensitiveOps = ['write', 'delete', 'manage'];
  if (riskScore >= config.mfaStepUpThreshold) return true;
  if (sensitiveOps.includes(requiredPermission) && riskScore > 0) return true;
  return false;
}

/**
 * Seed MFA secrets for demo users into the database.
 */
function seedDemoSecrets() {
  const aliceSecret = otplib.generateSecret();
  const bobSecret = otplib.generateSecret();
  db.storeMFASecret('alice', aliceSecret);
  db.storeMFASecret('bob', bobSecret);
  return { alice: aliceSecret, bob: bobSecret };
}

module.exports = {
  enrollMFA,
  verifyTOTP,
  isMFAEnabled,
  requiresStepUp,
  seedDemoSecrets,
};
