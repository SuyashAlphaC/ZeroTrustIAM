'use strict';

const crypto = require('crypto');
const config = require('./config');
const db = require('./database');

/**
 * W3C DID Resolver for did:fabric:iam method — fully database-backed.
 * All DID documents and Verifiable Credentials persist in SQLite.
 */

/**
 * Generate an EC P-256 key pair for a DID.
 */
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const pubKeyObj = crypto.createPublicKey(publicKey);
  const publicKeyJwk = pubKeyObj.export({ format: 'jwk' });
  return { publicKey, privateKey, publicKeyJwk };
}

/**
 * Create a DID document and persist it in the database.
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
    verificationMethod: [{
      id: `${did}#key-1`,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk,
    }],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`],
    service: [{
      id: `${did}#iam-service`,
      type: 'ZeroTrustIAM',
      serviceEndpoint: config.oauthIssuer,
    }],
    created: timestamp,
    updated: timestamp,
  };

  db.storeDID(did, userId, didDocument, privateKey);
  return { did, didDocument };
}

/**
 * Resolve a DID document from the database.
 */
function resolveDID(did) {
  const entry = db.getDID(did);
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
      deactivated: entry.deactivated || false,
    },
  };
}

/**
 * Issue a Verifiable Credential and persist it in the database.
 */
function issueCredential(issuerDid, subjectDid, types, claims) {
  const credentialId = `vc-${crypto.randomUUID().slice(0, 8)}`;
  const credential = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id: credentialId,
    type: ['VerifiableCredential', ...types],
    issuer: issuerDid,
    issuanceDate: new Date().toISOString(),
    credentialSubject: { id: subjectDid, ...claims },
    proof: {
      type: 'BlockchainProof2024',
      created: new Date().toISOString(),
      proofPurpose: 'assertionMethod',
      verificationMethod: `${issuerDid}#key-1`,
      blockchainTxId: `mock-${crypto.randomUUID().slice(0, 8)}`,
    },
  };

  db.storeVC(credentialId, issuerDid, subjectDid, credential);
  return credential;
}

/**
 * Verify a Verifiable Credential from the database.
 */
function verifyCredential(credentialId) {
  const vcRow = db.getVC(credentialId);
  if (!vcRow) {
    return { verified: false, reason: 'Credential not found' };
  }
  const credential = vcRow.credential;

  const issuerEntry = db.getDID(credential.issuer);
  if (!issuerEntry) {
    return { verified: false, reason: 'Issuer DID not found' };
  }
  if (issuerEntry.deactivated) {
    return { verified: false, reason: 'Issuer DID deactivated' };
  }

  return { verified: true, credential };
}

/**
 * List all DIDs from the database.
 */
function listDIDs() {
  return db.getAllDIDs().map(row => ({
    did: row.did,
    userId: row.user_id,
    deactivated: !!row.deactivated,
    createdAt: row.created_at,
  }));
}

/**
 * Seed DIDs for demo users into the database.
 */
function seedDemoDIDs() {
  // Only seed if not already present
  if (db.getDID('did:fabric:iam:alice')) {
    return {
      alice: 'did:fabric:iam:alice',
      bob: 'did:fabric:iam:bob',
    };
  }

  const aliceDID = createDID('alice');
  const bobDID = createDID('bob');

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
  listDIDs,
  seedDemoDIDs,
  generateKeyPair,
};
