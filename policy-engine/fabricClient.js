'use strict';

const grpc = require('@grpc/grpc-js');
const { connect, signers } = require('@hyperledger/fabric-gateway');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const config = require('./config');
const { logger } = require('./logger');

const DEFAULT_POLICY_PARAMS = {
  policyId: 'zt-iam-policy-v1',
  policyVersion: '1.0.0',
  riskThreshold: 0.6,
  zkpScheme: 'PedersenBitRangeProof',
  zkpRequiredForAllow: true,
  accessGrantTtlSeconds: 900,
  authorizedRiskEngines: ['Org1MSP'],
  authorizedAuditors: ['Org1MSP'],
  activeModelVersion: 'rules-ahp-v1',
  roleSchemaVersion: 'rbac-v1',
};

const testLedger = {
  policyParams: { ...DEFAULT_POLICY_PARAMS },
  audit: [],
  grants: new Map(),
  dids: new Map(),
  vcs: new Map(),
  models: new Map([
    ['rules-ahp-v1', {
      modelVersion: 'rules-ahp-v1',
      modelHash: 'builtin-ahp-risk-scorer',
      modelType: 'AHP+Anomaly+OptionalML',
      approvedBy: 'system',
      active: true,
    }],
  ]),
};

function isTestMode() {
  return process.env.NODE_ENV === 'test' && process.env.FABRIC_TEST_MODE !== 'false';
}

// Paths to crypto material
const NETWORK_DIR = process.env.FABRIC_NETWORK_DIR
  ? path.resolve(process.env.FABRIC_NETWORK_DIR)
  : path.resolve(__dirname, '..', 'fabric-network');
const CRYPTO_PATH_ORG1 = path.join(NETWORK_DIR, 'organizations', 'peerOrganizations', 'org1.example.com');
const CRYPTO_PATH_ORG2 = path.join(NETWORK_DIR, 'organizations', 'peerOrganizations', 'org2.example.com');
const PEER_TLS_CERT_ORG1 = path.join(CRYPTO_PATH_ORG1, 'peers', 'peer0.org1.example.com', 'tls', 'ca.crt');
const PEER_TLS_CERT_ORG2 = path.join(CRYPTO_PATH_ORG2, 'peers', 'peer0.org2.example.com', 'tls', 'ca.crt');
const USER_CERT_DIR = path.join(CRYPTO_PATH_ORG1, 'users', 'User1@org1.example.com', 'msp', 'signcerts');
const USER_KEY_DIR = path.join(CRYPTO_PATH_ORG1, 'users', 'User1@org1.example.com', 'msp', 'keystore');

const peerGrpcClients = [];

function isGrpcTransportError(err) {
  if (!err || typeof err.code !== 'number') return false;
  const { status } = grpc;
  return [
    status.UNAVAILABLE,
    status.DEADLINE_EXCEEDED,
    status.RESOURCE_EXHAUSTED,
    status.ABORTED,
    status.INTERNAL,
    status.UNKNOWN,
  ].includes(err.code);
}

function buildPeerGrpcClients() {
  peerGrpcClients.length = 0;
  const specs = [];
  specs.push({
    endpoint: config.fabricPeerEndpoint,
    tlsOverride: 'peer0.org1.example.com',
    caPath: PEER_TLS_CERT_ORG1,
  });
  if (config.fabricPeerEndpointOrg2 && fs.existsSync(PEER_TLS_CERT_ORG2)) {
    specs.push({
      endpoint: config.fabricPeerEndpointOrg2,
      tlsOverride: 'peer0.org2.example.com',
      caPath: PEER_TLS_CERT_ORG2,
    });
  }
  for (const spec of specs) {
    try {
      if (!fs.existsSync(spec.caPath)) {
        logger.warn({ caPath: spec.caPath }, 'Fabric peer TLS CA missing; skipping peer endpoint');
        continue;
      }
    } catch {
      continue;
    }
    const tlsRootCert = fs.readFileSync(spec.caPath);
    const tlsCredentials = grpc.credentials.createSsl(tlsRootCert);
    peerGrpcClients.push(new grpc.Client(spec.endpoint, tlsCredentials, {
      'grpc.ssl_target_name_override': spec.tlsOverride,
    }));
  }
  if (peerGrpcClients.length === 0) {
    throw new Error('No usable Fabric peer gRPC endpoints (TLS CA files missing?)');
  }
}

function getPeerGrpcClientsList() {
  if (isTestMode()) return [];
  if (peerGrpcClients.length === 0) buildPeerGrpcClients();
  return peerGrpcClients;
}

function closeGrpcClients() {
  for (const client of peerGrpcClients) {
    try {
      client.close();
    } catch {
      /* ignore */
    }
  }
  peerGrpcClients.length = 0;
}

function newIdentity() {
  const certFiles = fs.readdirSync(USER_CERT_DIR);
  const certPath = path.join(USER_CERT_DIR, certFiles[0]);
  const credentials = fs.readFileSync(certPath);
  return { mspId: config.fabricMspId, credentials };
}

function newSigner() {
  const keyFiles = fs.readdirSync(USER_KEY_DIR);
  const keyPath = path.join(USER_KEY_DIR, keyFiles[0]);
  const privateKeyPem = fs.readFileSync(keyPath);
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  return signers.newPrivateKeySigner(privateKey);
}

function connectGateway(peerClient, options = {}) {
  return connect({
    client: peerClient,
    identity: newIdentity(),
    signer: newSigner(),
    evaluateOptions: () => ({ deadline: Date.now() + (options.evaluateDeadlineMs || 5000) }),
    endorseOptions: () => ({ deadline: Date.now() + (options.endorseDeadlineMs || 15000) }),
    submitOptions: () => ({ deadline: Date.now() + (options.submitDeadlineMs || 5000) }),
    commitStatusOptions: () => ({ deadline: Date.now() + (options.commitDeadlineMs || 60000) }),
  });
}

async function withGateway(options, fn) {
  const clients = getPeerGrpcClientsList();
  let lastErr;
  for (let i = 0; i < clients.length; i += 1) {
    const peerClient = clients[i];
    const gateway = connectGateway(peerClient, options);
    try {
      return await fn(gateway);
    } catch (err) {
      lastErr = err;
      const canRetry = i < clients.length - 1 && isGrpcTransportError(err);
      if (canRetry) {
        logger.warn({ peerIndex: i, message: err.message }, 'Fabric gRPC peer error; retrying fallback peer');
        continue;
      }
      throw err;
    } finally {
      try {
        gateway.close();
      } catch {
        /* ignore */
      }
    }
  }
  throw lastErr;
}

async function submitJson(transactionName, ...args) {
  return withGateway({}, async (gateway) => {
    const network = gateway.getNetwork(config.fabricChannelName);
    const contract = network.getContract(config.fabricChaincodeName);
    const resultBytes = await contract.submitTransaction(transactionName, ...args);
    return JSON.parse(Buffer.from(resultBytes).toString());
  });
}

async function evaluateJson(transactionName, ...args) {
  return withGateway({ endorseDeadlineMs: 0, submitDeadlineMs: 0, commitDeadlineMs: 0 }, async (gateway) => {
    const network = gateway.getNetwork(config.fabricChannelName);
    const contract = network.getContract(config.fabricChaincodeName);
    const resultBytes = await contract.evaluateTransaction(transactionName, ...args);
    return JSON.parse(Buffer.from(resultBytes).toString());
  });
}

/**
 * Evaluate access via the real Hyperledger Fabric smart contract.
 */
function mockTxId() {
  return crypto.randomBytes(16).toString('hex');
}

function mockIssueGrant({ txId, userId, deviceId, requiredPermission, options }) {
  if (options.issueGrant === false) return undefined;
  const now = new Date();
  const grantId = crypto.createHash('sha256')
    .update(`${txId}:${userId}:${deviceId}:${options.resource || 'default'}:${requiredPermission}:${now.toISOString()}`)
    .digest('hex');
  const grant = {
    grantId,
    subject: userId,
    deviceId,
    resource: options.resource || 'default',
    permission: requiredPermission,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + testLedger.policyParams.accessGrantTtlSeconds * 1000).toISOString(),
    revoked: false,
    issuingTxId: txId,
    policyId: testLedger.policyParams.policyId,
    policyVersion: testLedger.policyParams.policyVersion,
    modelVersion: options.modelVersion || testLedger.policyParams.activeModelVersion,
    proofId: options.proofPackage?.rangeProof?.proofId,
  };
  testLedger.grants.set(grantId, grant);
  return grant;
}

async function mockEvaluateAccess(userId, deviceId, riskScore, requiredPermission, options) {
  const users = {
    alice: { role: 'admin', registeredDevices: ['dev-001'], status: 'ACTIVE' },
    bob: { role: 'viewer', registeredDevices: ['dev-002'], status: 'ACTIVE' },
  };
  const roles = {
    admin: ['read', 'write', 'delete', 'manage'],
    viewer: ['read'],
    editor: ['read', 'write'],
  };
  const txId = mockTxId();
  const user = users[userId];
  let decision = 'ALLOW';
  let reason = options.issueGrant === false ? 'Preflight checks passed' : 'All checks passed';
  if (!user) {
    decision = 'DENY'; reason = 'User not found';
  } else if (user.status !== 'ACTIVE') {
    decision = 'DENY'; reason = 'Account inactive';
  } else if (!user.registeredDevices.includes(deviceId)) {
    decision = 'DENY'; reason = 'Unregistered device';
  } else if (riskScore >= testLedger.policyParams.riskThreshold) {
    decision = 'DENY'; reason = 'Risk score exceeds threshold';
  } else if (!roles[user.role]?.includes(requiredPermission)) {
    decision = 'DENY'; reason = 'Insufficient permissions';
  }

  const accessGrant = decision === 'ALLOW'
    ? mockIssueGrant({ txId, userId, deviceId, requiredPermission, options })
    : undefined;
  testLedger.audit.push({
    txId,
    userId,
    deviceId,
    decision,
    reason,
    riskScoreRedacted: !!options.proofPackage,
    riskScore: options.proofPackage ? undefined : riskScore,
    accessGrantId: accessGrant?.grantId,
  });
  return {
    decision,
    reason,
    txId,
    layer: 'Smart Contract (Hyperledger Fabric)',
    policyId: testLedger.policyParams.policyId,
    policyVersion: testLedger.policyParams.policyVersion,
    modelVersion: options.modelVersion || testLedger.policyParams.activeModelVersion,
    accessGrant,
  };
}

async function evaluateAccess(userId, deviceId, riskScore, requiredPermission, options = {}) {
  if (isTestMode()) {
    return mockEvaluateAccess(userId, deviceId, riskScore, requiredPermission, options);
  }
  const result = await submitJson(
    'EvaluateAccess',
    userId,
    deviceId,
    options.proofPackage ? '' : String(riskScore),
    requiredPermission,
    options.proofPackage ? JSON.stringify(options.proofPackage) : '',
    options.modelVersion || '',
    options.resource || 'default',
    options.issueGrant === false ? 'false' : 'true'
  );
  logger.info({ txId: result.txId, userId, decision: result.decision, reason: result.reason }, 'Fabric blockchain decision');

  return {
    decision: result.decision,
    reason: result.reason,
    txId: result.txId,
    layer: 'Smart Contract (Hyperledger Fabric)',
    policyId: result.policyId,
    policyVersion: result.policyVersion,
    modelVersion: result.modelVersion,
    accessGrant: result.accessGrant,
  };
}

/**
 * Get all audit logs from the blockchain.
 */
async function getAuditLog() {
  if (isTestMode()) {
    return testLedger.audit;
  }
  return evaluateJson('GetAllAuditLogs');
}

async function getPolicyPublicParams() {
  if (isTestMode()) {
    return testLedger.policyParams;
  }
  return evaluateJson('GetPolicyPublicParams');
}

async function updatePolicyPublicParams(params) {
  if (isTestMode()) {
    testLedger.policyParams = { ...testLedger.policyParams, ...params, updatedAt: new Date().toISOString(), updateTxId: mockTxId() };
    return { status: 'updated', txId: testLedger.policyParams.updateTxId, params: testLedger.policyParams };
  }
  return submitJson('UpdatePolicyPublicParams', JSON.stringify(params));
}

async function registerRiskModel(modelVersion, modelHash, modelType, approvedBy, activate = false) {
  if (isTestMode()) {
    const model = { modelVersion, modelHash, modelType: modelType || 'unknown', approvedBy: approvedBy || 'policy-engine', active: activate, txId: mockTxId() };
    testLedger.models.set(modelVersion, model);
    if (activate) testLedger.policyParams.activeModelVersion = modelVersion;
    return { status: 'registered', model };
  }
  return submitJson(
    'RegisterRiskModel',
    modelVersion,
    modelHash,
    modelType || 'unknown',
    approvedBy || 'policy-engine',
    String(activate)
  );
}

async function getRiskModel(modelVersion) {
  if (isTestMode()) {
    const model = testLedger.models.get(modelVersion);
    if (!model) throw new Error(`Risk model ${modelVersion} not found`);
    return model;
  }
  return evaluateJson('GetRiskModel', modelVersion);
}

async function verifyAccessGrant(grantId, subject, resource, permission) {
  if (isTestMode()) {
    const grant = testLedger.grants.get(grantId);
    if (!grant) return { valid: false, reason: 'Access grant not found' };
    if (grant.revoked) return { valid: false, reason: 'Access grant revoked', grant };
    if (Date.parse(grant.expiresAt) <= Date.now()) return { valid: false, reason: 'Access grant expired', grant };
    if (subject && grant.subject !== subject) return { valid: false, reason: 'Subject mismatch', grant };
    if (resource && grant.resource !== resource) return { valid: false, reason: 'Resource mismatch', grant };
    if (permission && grant.permission !== permission) return { valid: false, reason: 'Permission mismatch', grant };
    return { valid: true, reason: 'Access grant valid', grant };
  }
  return evaluateJson('VerifyAccessGrant', grantId, subject || '', resource || '', permission || '');
}

async function revokeAccessGrant(grantId, reason) {
  if (isTestMode()) {
    const grant = testLedger.grants.get(grantId);
    if (!grant) throw new Error(`Access grant ${grantId} not found`);
    grant.revoked = true;
    grant.revokedAt = new Date().toISOString();
    grant.revocationReason = reason || 'revoked';
    testLedger.grants.set(grantId, grant);
    return { revoked: true, grantId, txId: mockTxId() };
  }
  return submitJson('RevokeAccessGrant', grantId, reason || 'revoked');
}

async function createDID(userId, publicKeyJwk, authenticationMethod = 'JsonWebKey2020') {
  if (isTestMode()) {
    const did = `did:fabric:iam:${userId}`;
    if (testLedger.dids.has(did)) {
      throw new Error(`DID ${did} already exists`);
    }
    const txId = mockTxId();
    const timestamp = new Date().toISOString();
    const didDocument = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
      id: did,
      controller: did,
      verificationMethod: [{
        id: `${did}#key-1`,
        type: authenticationMethod || 'JsonWebKey2020',
        controller: did,
        publicKeyJwk,
      }],
      authentication: [`${did}#key-1`],
      assertionMethod: [`${did}#key-1`],
      service: [{ id: `${did}#iam-service`, type: 'ZeroTrustIAM', serviceEndpoint: config.oauthIssuer }],
      created: timestamp,
      updated: timestamp,
      txId,
    };
    testLedger.dids.set(did, didDocument);
    return { did, status: 'created', txId };
  }
  return submitJson('CreateDID', userId, JSON.stringify(publicKeyJwk), authenticationMethod);
}

async function resolveDID(did) {
  if (isTestMode()) {
    const didDocument = testLedger.dids.get(did);
    if (!didDocument) throw new Error(`DID ${did} not found`);
    return {
      '@context': 'https://w3id.org/did-resolution/v1',
      didResolutionMetadata: {
        contentType: 'application/did+json',
        retrieved: new Date().toISOString(),
      },
      didDocument,
      didDocumentMetadata: {
        created: didDocument.created,
        updated: didDocument.updated,
        txId: didDocument.txId,
      },
    };
  }
  return evaluateJson('ResolveDID', did);
}

async function issueVerifiableCredential(credentialId, issuerDid, subjectDid, credentialTypes, claims) {
  if (isTestMode()) {
    const txId = mockTxId();
    const credential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: credentialId,
      type: ['VerifiableCredential', ...(credentialTypes || [])],
      issuer: issuerDid,
      issuanceDate: new Date().toISOString(),
      credentialSubject: { id: subjectDid, ...(claims || {}) },
      proof: {
        type: 'BlockchainProof2024',
        created: new Date().toISOString(),
        proofPurpose: 'assertionMethod',
        verificationMethod: `${issuerDid}#key-1`,
        blockchainTxId: txId,
        channel: config.fabricChannelName,
      },
    };
    testLedger.vcs.set(credentialId, credential);
    return { credentialId, status: 'issued', txId };
  }
  return submitJson(
    'IssueVerifiableCredential',
    credentialId,
    issuerDid,
    subjectDid,
    JSON.stringify(credentialTypes || []),
    JSON.stringify(claims || {})
  );
}

async function verifyCredential(credentialId) {
  if (isTestMode()) {
    const credential = testLedger.vcs.get(credentialId);
    if (!credential) return { verified: false, reason: 'Credential not found on blockchain' };
    const issuerDoc = testLedger.dids.get(credential.issuer);
    if (!issuerDoc) return { verified: false, reason: 'Issuer DID not found' };
    if (issuerDoc.deactivated) return { verified: false, reason: 'Issuer DID deactivated' };
    return { verified: true, credential, issuerDid: credential.issuer, blockchainProof: credential.proof };
  }
  return evaluateJson('VerifyCredential', credentialId);
}

module.exports = {
  evaluateAccess,
  getAuditLog,
  getPolicyPublicParams,
  updatePolicyPublicParams,
  registerRiskModel,
  getRiskModel,
  verifyAccessGrant,
  revokeAccessGrant,
  createDID,
  resolveDID,
  issueVerifiableCredential,
  verifyCredential,
  closeGrpcClients,
};
