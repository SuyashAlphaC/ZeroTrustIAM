'use strict';

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const config = require('./config');
const db = require('./database');

/**
 * WebAuthn/FIDO2 module — fully database-backed.
 * Credentials and challenges persist in SQLite.
 */

/**
 * Generate registration options for a user to register a new passkey.
 */
async function getRegistrationOptions(userId) {
  const userAuthenticators = db.getWebAuthnCredentials(userId);

  const options = await generateRegistrationOptions({
    rpName: config.webauthnRpName,
    rpID: config.webauthnRpId,
    userName: userId,
    userDisplayName: userId,
    attestationType: 'none',
    excludeCredentials: userAuthenticators.map(auth => ({
      id: auth.credentialID,
      transports: auth.transports,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  db.storeWebAuthnChallenge(userId + ':registration', options.challenge, userId, 'registration', expiresAt);

  return options;
}

/**
 * Verify registration response and store the new credential in the database.
 */
async function verifyRegistration(userId, response) {
  const challengeData = db.getWebAuthnChallenge(userId + ':registration');
  if (!challengeData) {
    return { verified: false, reason: 'No pending registration challenge' };
  }

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challengeData.challenge,
      expectedOrigin: config.webauthnOrigin,
      expectedRPID: config.webauthnRpId,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;

      db.storeWebAuthnCredential(
        userId,
        credential.id,
        credential.publicKey,
        credential.counter,
        response.response?.transports || []
      );

      db.deleteWebAuthnChallenge(userId + ':registration');

      return {
        verified: true,
        credentialId: credential.id,
        message: 'Passkey registered successfully',
      };
    }

    return { verified: false, reason: 'Verification failed' };
  } catch (err) {
    return { verified: false, reason: err.message };
  }
}

/**
 * Generate authentication options for passwordless login.
 */
async function getAuthenticationOptions(userId) {
  const userAuthenticators = db.getWebAuthnCredentials(userId);

  if (userAuthenticators.length === 0) {
    return { error: 'No passkeys registered for this user' };
  }

  const options = await generateAuthenticationOptions({
    rpID: config.webauthnRpId,
    allowCredentials: userAuthenticators.map(auth => ({
      id: auth.credentialID,
      transports: auth.transports,
    })),
    userVerification: 'preferred',
  });

  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  db.storeWebAuthnChallenge(userId + ':authentication', options.challenge, userId, 'authentication', expiresAt);

  return options;
}

/**
 * Verify authentication response for passwordless login.
 */
async function verifyAuthentication(userId, response) {
  const challengeData = db.getWebAuthnChallenge(userId + ':authentication');
  if (!challengeData) {
    return { verified: false, reason: 'No pending authentication challenge' };
  }

  const userAuthenticators = db.getWebAuthnCredentials(userId);
  const matchingAuth = userAuthenticators.find(auth => auth.credentialID === response.id);

  if (!matchingAuth) {
    return { verified: false, reason: 'Unknown credential' };
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challengeData.challenge,
      expectedOrigin: config.webauthnOrigin,
      expectedRPID: config.webauthnRpId,
      credential: {
        id: matchingAuth.credentialID,
        publicKey: matchingAuth.credentialPublicKey,
        counter: matchingAuth.counter,
      },
    });

    if (verification.verified) {
      db.updateWebAuthnCounter(userId, matchingAuth.credentialID, verification.authenticationInfo.newCounter);
      db.deleteWebAuthnChallenge(userId + ':authentication');
      return { verified: true, userId, message: 'Passwordless authentication successful' };
    }

    return { verified: false, reason: 'Verification failed' };
  } catch (err) {
    return { verified: false, reason: err.message };
  }
}

/**
 * Check if a user has registered passkeys (from database).
 */
function hasPasskeys(userId) {
  return db.getWebAuthnCredentials(userId).length > 0;
}

/**
 * Get passkey count for a user (from database).
 */
function getPasskeyCount(userId) {
  return db.getWebAuthnCredentials(userId).length;
}

module.exports = {
  getRegistrationOptions,
  verifyRegistration,
  getAuthenticationOptions,
  verifyAuthentication,
  hasPasskeys,
  getPasskeyCount,
};
