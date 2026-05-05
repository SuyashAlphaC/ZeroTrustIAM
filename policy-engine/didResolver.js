'use strict';

const crypto = require('crypto');
const config = require('./config');
const db = require('./database');
const blockchain = require('./fabricClient');

/**
 * W3C DID Resolver for did:fabric:iam method — fully database-backed.
 * All DID documents and Verifiable Credentials persist in PostgreSQL.
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
async function createDID(userId) {
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

  try {
    const blockchainResult = await blockchain.createDID(userId, publicKeyJwk, 'JsonWebKey2020');
    didDocument.txId = blockchainResult.txId;
    await db.storeDID(did, userId, didDocument, privateKey);
    return { did, didDocument, txId: blockchainResult.txId, status: blockchainResult.status };
  } catch (err) {
    if (!/already exists/i.test(err.message)) {
      throw err;
    }

    const resolution = await blockchain.resolveDID(did);
    await db.storeDID(did, userId, resolution.didDocument, null);
    return {
      did,
      didDocument: resolution.didDocument,
      txId: resolution.didDocument?.txId,
      status: 'existing',
    };
  }
}

/**
 * Resolve a DID document from the database.
 */
async function resolveDID(did) {
  try {
    const resolution = await blockchain.resolveDID(did);
    const existing = await db.getDID(did);
    await db.storeDID(did, existing?.userId || null, resolution.didDocument, existing?.privateKey || null);
    if (resolution.didDocument?.deactivated) {
      await db.deactivateDID(did);
    }
    return resolution;
  } catch (err) {
    if (/not found/i.test(err.message)) {
      return {
        '@context': 'https://w3id.org/did-resolution/v1',
        didResolutionMetadata: { error: 'notFound' },
        didDocument: null,
        didDocumentMetadata: {},
      };
    }
    throw err;
  }
}

/**
 * Issue a Verifiable Credential and persist it in the database.
 */
async function issueCredential(issuerDid, subjectDid, types, claims) {
  const credentialId = `vc-${crypto.randomUUID().slice(0, 8)}`;
  const blockchainResult = await blockchain.issueVerifiableCredential(
    credentialId,
    issuerDid,
    subjectDid,
    types,
    claims
  );

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
      blockchainTxId: blockchainResult.txId,
      channel: config.fabricChannelName,
    },
  };

  await db.storeVC(credentialId, issuerDid, subjectDid, credential);
  return credential;
}

/**
 * Verify a Verifiable Credential from the database.
 */
async function verifyCredential(credentialId) {
  const result = await blockchain.verifyCredential(credentialId);
  if (result.verified && result.credential) {
    await db.storeVC(
      credentialId,
      result.credential.issuer,
      result.credential.credentialSubject?.id,
      result.credential
    );
  }
  return result;
}

/**
 * List all DIDs from the database.
 */
async function listDIDs() {
  const rows = await db.getAllDIDs();
  return rows.map(row => ({
    did: row.did,
    userId: row.user_id,
    deactivated: !!row.deactivated,
    createdAt: row.created_at,
  }));
}

/**
 * Seed DIDs for demo users into the database.
 */
async function seedDemoDIDs() {
  if (await db.getDID('did:fabric:iam:alice')) {
    return {
      alice: 'did:fabric:iam:alice',
      bob: 'did:fabric:iam:bob',
    };
  }

  const aliceDID = await createDID('alice');
  const bobDID = await createDID('bob');

  await issueCredential(
    aliceDID.did, aliceDID.did,
    ['RoleCredential'],
    { role: 'admin', grantedBy: 'system', grantedAt: new Date().toISOString() }
  );
  await issueCredential(
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
