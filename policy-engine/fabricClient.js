const grpc = require('@grpc/grpc-js');
const { connect, signers } = require('@hyperledger/fabric-gateway');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const CHANNEL_NAME = 'iamchannel';
const CHAINCODE_NAME = 'iam-cc';
const MSP_ID = 'Org1MSP';

// Paths to crypto material
const NETWORK_DIR = path.resolve(__dirname, '..', 'fabric-network');
const CRYPTO_PATH = path.join(NETWORK_DIR, 'organizations', 'peerOrganizations', 'org1.example.com');
const PEER_TLS_CERT = path.join(CRYPTO_PATH, 'peers', 'peer0.org1.example.com', 'tls', 'ca.crt');
const USER_CERT_DIR = path.join(CRYPTO_PATH, 'users', 'User1@org1.example.com', 'msp', 'signcerts');
const USER_KEY_DIR = path.join(CRYPTO_PATH, 'users', 'User1@org1.example.com', 'msp', 'keystore');

let grpcClient = null;

function getGrpcClient() {
  if (grpcClient) return grpcClient;

  const tlsRootCert = fs.readFileSync(PEER_TLS_CERT);
  const tlsCredentials = grpc.credentials.createSsl(tlsRootCert);

  grpcClient = new grpc.Client('localhost:7051', tlsCredentials, {
    'grpc.ssl_target_name_override': 'peer0.org1.example.com',
  });

  return grpcClient;
}

function newIdentity() {
  const certFiles = fs.readdirSync(USER_CERT_DIR);
  const certPath = path.join(USER_CERT_DIR, certFiles[0]);
  const credentials = fs.readFileSync(certPath);
  return { mspId: MSP_ID, credentials };
}

function newSigner() {
  const keyFiles = fs.readdirSync(USER_KEY_DIR);
  const keyPath = path.join(USER_KEY_DIR, keyFiles[0]);
  const privateKeyPem = fs.readFileSync(keyPath);
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  return signers.newPrivateKeySigner(privateKey);
}

/**
 * Evaluate access via the real Hyperledger Fabric smart contract.
 * Same interface as mockBlockchain.evaluateAccess().
 */
async function evaluateAccess(userId, deviceId, riskScore, requiredPermission) {
  const client = getGrpcClient();
  const gateway = connect({
    client,
    identity: newIdentity(),
    signer: newSigner(),
    evaluateOptions: () => ({ deadline: Date.now() + 5000 }),
    endorseOptions: () => ({ deadline: Date.now() + 15000 }),
    submitOptions: () => ({ deadline: Date.now() + 5000 }),
    commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
  });

  try {
    const network = gateway.getNetwork(CHANNEL_NAME);
    const contract = network.getContract(CHAINCODE_NAME);

    const resultBytes = await contract.submitTransaction(
      'EvaluateAccess',
      userId,
      deviceId,
      String(riskScore),
      requiredPermission
    );

    const result = JSON.parse(Buffer.from(resultBytes).toString());
    console.log(`[BLOCKCHAIN] ${result.decision} | ${userId} | ${result.reason} | txId=${result.txId}`);

    return {
      decision: result.decision,
      reason: result.reason,
      txId: result.txId,
      layer: 'Smart Contract (Hyperledger Fabric)',
    };
  } finally {
    gateway.close();
  }
}

/**
 * Get all audit logs from the blockchain.
 */
async function getAuditLog() {
  const client = getGrpcClient();
  const gateway = connect({
    client,
    identity: newIdentity(),
    signer: newSigner(),
    evaluateOptions: () => ({ deadline: Date.now() + 5000 }),
  });

  try {
    const network = gateway.getNetwork(CHANNEL_NAME);
    const contract = network.getContract(CHAINCODE_NAME);
    const resultBytes = await contract.evaluateTransaction('GetAllAuditLogs');
    return JSON.parse(Buffer.from(resultBytes).toString());
  } finally {
    gateway.close();
  }
}

module.exports = { evaluateAccess, getAuditLog };
