const otplib = require('otplib');
const QRCode = require('qrcode');

// MFA configuration
const MFA_ISSUER = 'ZeroTrustIAM';

// Step-up threshold: if risk score >= this, MFA is required even if user has valid session
const STEP_UP_THRESHOLD = 0.3;

// In-memory MFA secret store (in production, encrypt and store in database)
const mfaSecrets = new Map();

// Track pending MFA challenges
const mfaChallenges = new Map(); // challengeId -> { userId, deviceId, riskScore, requiredPermission, expiresAt, context }

/**
 * Enroll a user in TOTP MFA.
 * Returns the secret and a QR code data URL for authenticator apps.
 */
async function enrollMFA(userId) {
  const secret = otplib.generateSecret();
  mfaSecrets.set(userId, { secret, enabled: true, enrolledAt: new Date().toISOString() });

  const otpauth = otplib.generateURI({ issuer: MFA_ISSUER, label: userId, secret, type: 'totp' });
  const qrCodeDataUrl = await QRCode.toDataURL(otpauth);

  return {
    secret,
    otpauth,
    qrCodeDataUrl,
    message: `Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)`,
  };
}

/**
 * Verify a TOTP code for a user.
 */
function verifyTOTP(userId, token) {
  const mfaData = mfaSecrets.get(userId);
  if (!mfaData || !mfaData.enabled) {
    return { valid: false, reason: 'MFA not enrolled' };
  }

  const result = otplib.verifySync({ token, secret: mfaData.secret });
  const isValid = result && result.valid;
  return { valid: isValid, reason: isValid ? 'Valid TOTP code' : 'Invalid or expired TOTP code' };
}

/**
 * Check if a user has MFA enabled.
 */
function isMFAEnabled(userId) {
  const mfaData = mfaSecrets.get(userId);
  return !!(mfaData && mfaData.enabled);
}

/**
 * Determine if MFA step-up is required based on risk score and operation.
 * Step-up is triggered when:
 * - Risk score >= STEP_UP_THRESHOLD (elevated but below deny threshold)
 * - User requests a sensitive operation (write, delete, manage)
 */
function requiresStepUp(riskScore, requiredPermission) {
  const sensitiveOps = ['write', 'delete', 'manage'];
  if (riskScore >= STEP_UP_THRESHOLD) return true;
  if (sensitiveOps.includes(requiredPermission) && riskScore > 0) return true;
  return false;
}

/**
 * Create an MFA challenge that the user must complete.
 */
function createChallenge(userId, context) {
  const crypto = require('crypto');
  const challengeId = crypto.randomBytes(32).toString('hex');
  mfaChallenges.set(challengeId, {
    userId,
    ...context,
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
    verified: false,
  });
  return challengeId;
}

/**
 * Complete an MFA challenge with a TOTP code.
 */
function completeChallenge(challengeId, totpCode) {
  const challenge = mfaChallenges.get(challengeId);
  if (!challenge) {
    return { valid: false, reason: 'Challenge not found' };
  }

  if (Date.now() > challenge.expiresAt) {
    mfaChallenges.delete(challengeId);
    return { valid: false, reason: 'Challenge expired' };
  }

  const verification = verifyTOTP(challenge.userId, totpCode);
  if (!verification.valid) {
    return { valid: false, reason: verification.reason };
  }

  // Mark as verified and return challenge context
  challenge.verified = true;
  const context = { ...challenge };
  mfaChallenges.delete(challengeId);
  return { valid: true, context };
}

/**
 * Seed MFA secrets for demo users.
 * In production, users would enroll themselves.
 */
function seedDemoSecrets() {
  // Generate deterministic secrets for demo (so tests can use them)
  const aliceSecret = otplib.generateSecret();
  const bobSecret = otplib.generateSecret();

  mfaSecrets.set('alice', { secret: aliceSecret, enabled: true, enrolledAt: new Date().toISOString() });
  mfaSecrets.set('bob', { secret: bobSecret, enabled: true, enrolledAt: new Date().toISOString() });

  return { alice: aliceSecret, bob: bobSecret };
}

module.exports = {
  enrollMFA,
  verifyTOTP,
  isMFAEnabled,
  requiresStepUp,
  createChallenge,
  completeChallenge,
  seedDemoSecrets,
  STEP_UP_THRESHOLD,
  mfaSecrets,
};
