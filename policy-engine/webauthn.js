const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

// WebAuthn configuration
const RP_NAME = 'Zero Trust IAM';
const RP_ID = 'localhost';
const ORIGIN = 'http://localhost:3000';

// In-memory stores
const authenticators = new Map(); // userId -> [{ credentialID, credentialPublicKey, counter, transports }]
const challenges = new Map(); // challengeId -> { challenge, userId, type, expiresAt }

/**
 * Generate registration options for a user to register a new passkey.
 */
async function getRegistrationOptions(userId) {
  const userAuthenticators = authenticators.get(userId) || [];

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
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

  // Store challenge for verification
  challenges.set(userId + ':registration', {
    challenge: options.challenge,
    userId,
    type: 'registration',
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  return options;
}

/**
 * Verify registration response and store the new credential.
 */
async function verifyRegistration(userId, response) {
  const challengeData = challenges.get(userId + ':registration');
  if (!challengeData) {
    return { verified: false, reason: 'No pending registration challenge' };
  }

  if (Date.now() > challengeData.expiresAt) {
    challenges.delete(userId + ':registration');
    return { verified: false, reason: 'Challenge expired' };
  }

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challengeData.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;

      const existingAuths = authenticators.get(userId) || [];
      existingAuths.push({
        credentialID: credential.id,
        credentialPublicKey: credential.publicKey,
        counter: credential.counter,
        transports: response.response?.transports || [],
        registeredAt: new Date().toISOString(),
      });
      authenticators.set(userId, existingAuths);

      challenges.delete(userId + ':registration');

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
  const userAuthenticators = authenticators.get(userId) || [];

  if (userAuthenticators.length === 0) {
    return { error: 'No passkeys registered for this user' };
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: userAuthenticators.map(auth => ({
      id: auth.credentialID,
      transports: auth.transports,
    })),
    userVerification: 'preferred',
  });

  challenges.set(userId + ':authentication', {
    challenge: options.challenge,
    userId,
    type: 'authentication',
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  return options;
}

/**
 * Verify authentication response for passwordless login.
 */
async function verifyAuthentication(userId, response) {
  const challengeData = challenges.get(userId + ':authentication');
  if (!challengeData) {
    return { verified: false, reason: 'No pending authentication challenge' };
  }

  if (Date.now() > challengeData.expiresAt) {
    challenges.delete(userId + ':authentication');
    return { verified: false, reason: 'Challenge expired' };
  }

  const userAuthenticators = authenticators.get(userId) || [];
  const matchingAuth = userAuthenticators.find(
    auth => auth.credentialID === response.id
  );

  if (!matchingAuth) {
    return { verified: false, reason: 'Unknown credential' };
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challengeData.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: matchingAuth.credentialID,
        publicKey: matchingAuth.credentialPublicKey,
        counter: matchingAuth.counter,
      },
    });

    if (verification.verified) {
      // Update counter
      matchingAuth.counter = verification.authenticationInfo.newCounter;
      challenges.delete(userId + ':authentication');

      return {
        verified: true,
        userId,
        message: 'Passwordless authentication successful',
      };
    }

    return { verified: false, reason: 'Verification failed' };
  } catch (err) {
    return { verified: false, reason: err.message };
  }
}

/**
 * Check if a user has registered passkeys.
 */
function hasPasskeys(userId) {
  const auths = authenticators.get(userId) || [];
  return auths.length > 0;
}

/**
 * Get passkey count for a user.
 */
function getPasskeyCount(userId) {
  const auths = authenticators.get(userId) || [];
  return auths.length;
}

module.exports = {
  getRegistrationOptions,
  verifyRegistration,
  getAuthenticationOptions,
  verifyAuthentication,
  hasPasskeys,
  getPasskeyCount,
  RP_ID,
  RP_NAME,
  ORIGIN,
};
