'use strict';

const { Contract } = require('fabric-contract-api');

class IAMContract extends Contract {

  /**
   * Initialize the ledger with seed data:
   * - User registry (alice, bob)
   * - Role-permission mappings
   * - Policy thresholds
   */
  async InitLedger(ctx) {
    // Seed users
    const users = [
      {
        userId: 'alice',
        role: 'admin',
        registeredDevices: ['dev-001'],
        status: 'ACTIVE',
      },
      {
        userId: 'bob',
        role: 'viewer',
        registeredDevices: ['dev-002'],
        status: 'ACTIVE',
      },
    ];

    for (const user of users) {
      await ctx.stub.putState(
        `UserRegistry:${user.userId}`,
        Buffer.from(JSON.stringify(user))
      );
    }

    // Role-permission mappings
    const roles = {
      admin: { permissions: ['read', 'write', 'delete', 'manage'] },
      viewer: { permissions: ['read'] },
    };

    for (const [roleName, roleData] of Object.entries(roles)) {
      await ctx.stub.putState(
        `RolePermissions:${roleName}`,
        Buffer.from(JSON.stringify(roleData))
      );
    }

    // Policy thresholds
    await ctx.stub.putState(
      'PolicyThresholds:default',
      Buffer.from(JSON.stringify({ riskThreshold: 0.6 }))
    );

    return JSON.stringify({ status: 'Ledger initialized successfully' });
  }

  /**
   * Core authorization method. Evaluates 4 rules sequentially:
   * 1. User account is ACTIVE
   * 2. Device is registered
   * 3. Risk score < threshold
   * 4. Role has required permission (RBAC)
   *
   * Logs every decision to the blockchain as an immutable audit entry.
   */
  async EvaluateAccess(ctx, userId, deviceId, riskScoreStr, requiredPermission) {
    const riskScore = parseFloat(riskScoreStr);
    const txId = ctx.stub.getTxID();
    const timestamp = new Date().toISOString();

    // Rule 1: Check user exists and is ACTIVE
    const userBytes = await ctx.stub.getState(`UserRegistry:${userId}`);
    if (!userBytes || userBytes.length === 0) {
      return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'DENY', 'User not found', timestamp);
    }

    const user = JSON.parse(userBytes.toString());

    if (user.status !== 'ACTIVE') {
      return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'DENY', 'Account inactive', timestamp);
    }

    // Rule 2: Check device is registered
    if (!user.registeredDevices.includes(deviceId)) {
      return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'DENY', 'Unregistered device', timestamp);
    }

    // Rule 3: Check risk score below threshold
    const thresholdBytes = await ctx.stub.getState('PolicyThresholds:default');
    const threshold = JSON.parse(thresholdBytes.toString());

    if (riskScore >= threshold.riskThreshold) {
      return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'DENY', 'Risk score exceeds threshold', timestamp);
    }

    // Rule 4: RBAC - check role has required permission
    const roleBytes = await ctx.stub.getState(`RolePermissions:${user.role}`);
    if (!roleBytes || roleBytes.length === 0) {
      return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'DENY', 'Role not found', timestamp);
    }

    const rolePerms = JSON.parse(roleBytes.toString());
    if (!rolePerms.permissions.includes(requiredPermission)) {
      return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'DENY', 'Insufficient permissions', timestamp);
    }

    // All checks passed
    return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'ALLOW', 'All checks passed', timestamp);
  }

  /**
   * Log the access decision to the blockchain and return the result.
   */
  async _logDecision(ctx, txId, userId, deviceId, riskScore, decision, reason, timestamp) {
    const auditEntry = {
      txId,
      userId,
      deviceId,
      riskScore,
      decision,
      reason,
      timestamp,
    };

    await ctx.stub.putState(
      `AuditLog:${txId}`,
      Buffer.from(JSON.stringify(auditEntry))
    );

    return JSON.stringify({ decision, reason, txId });
  }

  /**
   * Register a new device for a user.
   */
  async RegisterDevice(ctx, userId, newDeviceId) {
    const userBytes = await ctx.stub.getState(`UserRegistry:${userId}`);
    if (!userBytes || userBytes.length === 0) {
      throw new Error(`User ${userId} not found`);
    }

    const user = JSON.parse(userBytes.toString());

    if (user.registeredDevices.includes(newDeviceId)) {
      return JSON.stringify({ status: 'Device already registered' });
    }

    user.registeredDevices.push(newDeviceId);
    await ctx.stub.putState(
      `UserRegistry:${userId}`,
      Buffer.from(JSON.stringify(user))
    );

    return JSON.stringify({ status: 'Device registered', userId, deviceId: newDeviceId });
  }

  /**
   * Update user account status (ACTIVE / SUSPENDED).
   */
  async UpdateUserStatus(ctx, userId, newStatus) {
    const userBytes = await ctx.stub.getState(`UserRegistry:${userId}`);
    if (!userBytes || userBytes.length === 0) {
      throw new Error(`User ${userId} not found`);
    }

    const user = JSON.parse(userBytes.toString());
    user.status = newStatus;
    await ctx.stub.putState(
      `UserRegistry:${userId}`,
      Buffer.from(JSON.stringify(user))
    );

    return JSON.stringify({ status: 'User status updated', userId, newStatus });
  }

  /**
   * Read a specific audit log entry by transaction ID.
   */
  async GetAuditLog(ctx, txId) {
    const logBytes = await ctx.stub.getState(`AuditLog:${txId}`);
    if (!logBytes || logBytes.length === 0) {
      throw new Error(`Audit log entry ${txId} not found`);
    }
    return logBytes.toString();
  }

  /**
   * Get all audit log entries.
   */
  async GetAllAuditLogs(ctx) {
    const results = [];
    const iterator = await ctx.stub.getStateByRange('AuditLog:', 'AuditLog:~');

    let result = await iterator.next();
    while (!result.done) {
      const value = JSON.parse(result.value.value.toString());
      results.push(value);
      result = await iterator.next();
    }
    await iterator.close();

    return JSON.stringify(results);
  }

  /**
   * Read a user record from the registry.
   */
  async GetUser(ctx, userId) {
    const userBytes = await ctx.stub.getState(`UserRegistry:${userId}`);
    if (!userBytes || userBytes.length === 0) {
      throw new Error(`User ${userId} not found`);
    }
    return userBytes.toString();
  }

  // --- W3C DID Methods ---

  /**
   * Create a W3C DID Document on the ledger.
   * DID format: did:fabric:iam:<userId>
   *
   * @param {string} userId - The user identifier
   * @param {string} publicKeyJwkJson - JSON string of the user's public key in JWK format
   * @param {string} authenticationMethod - Authentication method type (e.g., "Ed25519VerificationKey2020")
   */
  async CreateDID(ctx, userId, publicKeyJwkJson, authenticationMethod) {
    const did = `did:fabric:iam:${userId}`;
    const txId = ctx.stub.getTxID();
    const timestamp = new Date().toISOString();

    // Check if DID already exists
    const existingBytes = await ctx.stub.getState(`DID:${did}`);
    if (existingBytes && existingBytes.length > 0) {
      throw new Error(`DID ${did} already exists`);
    }

    const publicKeyJwk = JSON.parse(publicKeyJwkJson);

    // W3C DID Document (conformant to DID Core spec)
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
          type: authenticationMethod || 'JsonWebKey2020',
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
      txId,
    };

    await ctx.stub.putState(
      `DID:${did}`,
      Buffer.from(JSON.stringify(didDocument))
    );

    // Link DID to user registry
    const userBytes = await ctx.stub.getState(`UserRegistry:${userId}`);
    if (userBytes && userBytes.length > 0) {
      const user = JSON.parse(userBytes.toString());
      user.did = did;
      await ctx.stub.putState(
        `UserRegistry:${userId}`,
        Buffer.from(JSON.stringify(user))
      );
    }

    return JSON.stringify({ did, status: 'created', txId });
  }

  /**
   * Resolve a DID Document from the ledger.
   */
  async ResolveDID(ctx, did) {
    const didBytes = await ctx.stub.getState(`DID:${did}`);
    if (!didBytes || didBytes.length === 0) {
      throw new Error(`DID ${did} not found`);
    }

    const didDocument = JSON.parse(didBytes.toString());

    // Return DID Resolution Result (W3C DID Resolution spec)
    return JSON.stringify({
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
    });
  }

  /**
   * Update a DID Document (add/rotate verification keys).
   */
  async UpdateDID(ctx, did, newPublicKeyJwkJson) {
    const didBytes = await ctx.stub.getState(`DID:${did}`);
    if (!didBytes || didBytes.length === 0) {
      throw new Error(`DID ${did} not found`);
    }

    const didDocument = JSON.parse(didBytes.toString());
    const newPublicKeyJwk = JSON.parse(newPublicKeyJwkJson);
    const timestamp = new Date().toISOString();

    // Add new key and rotate
    const keyIndex = didDocument.verificationMethod.length + 1;
    const newKeyId = `${did}#key-${keyIndex}`;

    didDocument.verificationMethod.push({
      id: newKeyId,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk: newPublicKeyJwk,
    });

    // Update authentication to use latest key
    didDocument.authentication = [newKeyId];
    didDocument.updated = timestamp;
    didDocument.txId = ctx.stub.getTxID();

    await ctx.stub.putState(
      `DID:${did}`,
      Buffer.from(JSON.stringify(didDocument))
    );

    return JSON.stringify({ did, status: 'updated', newKeyId, txId: didDocument.txId });
  }

  /**
   * Deactivate a DID (revoke all keys).
   */
  async DeactivateDID(ctx, did) {
    const didBytes = await ctx.stub.getState(`DID:${did}`);
    if (!didBytes || didBytes.length === 0) {
      throw new Error(`DID ${did} not found`);
    }

    const didDocument = JSON.parse(didBytes.toString());
    didDocument.verificationMethod = [];
    didDocument.authentication = [];
    didDocument.assertionMethod = [];
    didDocument.deactivated = true;
    didDocument.updated = new Date().toISOString();
    didDocument.txId = ctx.stub.getTxID();

    await ctx.stub.putState(
      `DID:${did}`,
      Buffer.from(JSON.stringify(didDocument))
    );

    return JSON.stringify({ did, status: 'deactivated', txId: didDocument.txId });
  }

  /**
   * Issue a Verifiable Credential (stored on-chain).
   */
  async IssueVerifiableCredential(ctx, credentialId, issuerDid, subjectDid, credentialTypeJson, claimsJson) {
    const txId = ctx.stub.getTxID();
    const timestamp = new Date().toISOString();

    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
      ],
      id: credentialId,
      type: ['VerifiableCredential', ...JSON.parse(credentialTypeJson)],
      issuer: issuerDid,
      issuanceDate: timestamp,
      credentialSubject: {
        id: subjectDid,
        ...JSON.parse(claimsJson),
      },
      proof: {
        type: 'BlockchainProof2024',
        created: timestamp,
        proofPurpose: 'assertionMethod',
        verificationMethod: `${issuerDid}#key-1`,
        blockchainTxId: txId,
        channel: 'iamchannel',
      },
    };

    await ctx.stub.putState(
      `VC:${credentialId}`,
      Buffer.from(JSON.stringify(credential))
    );

    return JSON.stringify({ credentialId, status: 'issued', txId });
  }

  /**
   * Verify a Verifiable Credential exists on-chain.
   */
  async VerifyCredential(ctx, credentialId) {
    const vcBytes = await ctx.stub.getState(`VC:${credentialId}`);
    if (!vcBytes || vcBytes.length === 0) {
      return JSON.stringify({ verified: false, reason: 'Credential not found on blockchain' });
    }

    const credential = JSON.parse(vcBytes.toString());

    // Check issuer DID is still active
    const issuerDidBytes = await ctx.stub.getState(`DID:${credential.issuer}`);
    if (!issuerDidBytes || issuerDidBytes.length === 0) {
      return JSON.stringify({ verified: false, reason: 'Issuer DID not found' });
    }

    const issuerDoc = JSON.parse(issuerDidBytes.toString());
    if (issuerDoc.deactivated) {
      return JSON.stringify({ verified: false, reason: 'Issuer DID deactivated' });
    }

    return JSON.stringify({
      verified: true,
      credential,
      issuerDid: credential.issuer,
      blockchainProof: credential.proof,
    });
  }
}

module.exports = IAMContract;
