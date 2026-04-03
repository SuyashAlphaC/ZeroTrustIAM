const crypto = require('crypto');

/**
 * W3C DID Resolver for did:fabric:iam method.
 *
 * In mock mode, DIDs are stored in memory.
 * In Fabric mode, DIDs are resolved from the blockchain ledger.
 */

// In-memory DID store (mock mode)
const didStore = new Map();
const vcStore = new Map();

/**
 * Generate a key pair for a DID.
 */
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Convert public key to JWK
  const pubKeyObj = crypto.createPublicKey(publicKey);
  const jwk = pubKeyObj.export({ format: 'jwk' });

  return { publicKey, privateKey, publicKeyJwk: jwk };
}

/**
 * Create a DID document (mock mode).
 */
function createDID(userId) {
  const did = `did:fabric:iam:${userId}`;
  const { publicKeyJwk, privateKey } = generateKeyPair();
  const timestamp = new Date().toISOString();

  const didDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/jws-2020/v1',
    ],
    id: did,
    controller: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk,
      },
    ],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`],
    service: [
      {
        id: `${did}#iam-service`,
        type: 'ZeroTrustIAM',
        serviceEndpoint: 'http://localhost:4000',
      },
    ],
    created: timestamp,
    updated: timestamp,
  };

  didStore.set(did, { document: didDocument, privateKey });
  return { did, didDocument };
}

/**
 * Resolve a DID document (mock mode).
 */
function resolveDID(did) {
  const entry = didStore.get(did);
  if (!entry) {
    return {
      '@context': 'https://w3id.org/did-resolution/v1',
      didResolutionMetadata: { error: 'notFound' },
      didDocument: null,
      didDocumentMetadata: {},
    };
  }

  return {
    '@context': 'https://w3id.org/did-resolution/v1',
    didResolutionMetadata: {
      contentType: 'application/did+json',
      retrieved: new Date().toISOString(),
    },
    didDocument: entry.document,
    didDocumentMetadata: {
      created: entry.document.created,
      updated: entry.document.updated,
    },
  };
}

/**
 * Issue a Verifiable Credential (mock mode).
 */
function issueCredential(issuerDid, subjectDid, types, claims) {
  const credentialId = `vc-${crypto.randomUUID().slice(0, 8)}`;

  const credential = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: credentialId,
    type: ['VerifiableCredential', ...types],
    issuer: issuerDid,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: subjectDid,
      ...claims,
    },
    proof: {
      type: 'BlockchainProof2024',
      created: new Date().toISOString(),
      proofPurpose: 'assertionMethod',
      verificationMethod: `${issuerDid}#key-1`,
      blockchainTxId: `mock-${crypto.randomUUID().slice(0, 8)}`,
    },
  };

  vcStore.set(credentialId, credential);
  return credential;
}

/**
 * Verify a Verifiable Credential (mock mode).
 */
function verifyCredential(credentialId) {
  const credential = vcStore.get(credentialId);
  if (!credential) {
    return { verified: false, reason: 'Credential not found' };
  }

  const issuerEntry = didStore.get(credential.issuer);
  if (!issuerEntry) {
    return { verified: false, reason: 'Issuer DID not found' };
  }

  if (issuerEntry.document.deactivated) {
    return { verified: false, reason: 'Issuer DID deactivated' };
  }

  return { verified: true, credential };
}

/**
 * Seed DIDs for demo users.
 */
function seedDemoDIDs() {
  const aliceDID = createDID('alice');
  const bobDID = createDID('bob');

  // Issue role credentials
  issueCredential(
    aliceDID.did, aliceDID.did,
    ['RoleCredential'],
    { role: 'admin', grantedBy: 'system', grantedAt: new Date().toISOString() }
  );

  issueCredential(
    aliceDID.did, bobDID.did,
    ['RoleCredential'],
    { role: 'viewer', grantedBy: 'alice', grantedAt: new Date().toISOString() }
  );

  return { alice: aliceDID.did, bob: bobDID.did };
}

module.exports = {
  createDID,
  resolveDID,
  issueCredential,
  verifyCredential,
  seedDemoDIDs,
  generateKeyPair,
  didStore,
  vcStore,
};
