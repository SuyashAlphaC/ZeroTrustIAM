'use strict';

const { Contract } = require('fabric-contract-api');
const crypto = require('crypto');

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

const CURVE = {
  P: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
  N: BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
  Gx: BigInt('0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
  Gy: BigInt('0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
};
const ZKP_PARAMS = {
  curve: 'secp256k1',
  proofType: 'PedersenBitRangeProof',
  scale: 1000,
  hDomain: 'ZeroTrustIAM/risk/H/v1',
};
const INF = { inf: true };
const G = { x: CURVE.Gx, y: CURVE.Gy };
const H = deriveGeneratorH();

function mod(a, m = CURVE.P) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base, exp, m) {
  let b = mod(base, m);
  let e = exp;
  let out = 1n;
  while (e > 0n) {
    if (e & 1n) out = (out * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return out;
}

function inv(a, m = CURVE.N) {
  if (mod(a, m) === 0n) throw new Error('inverse of zero');
  return modPow(mod(a, m), m - 2n, m);
}

function isInf(p) {
  return !p || p.inf;
}

function pointNeg(p) {
  return isInf(p) ? INF : { x: p.x, y: mod(-p.y) };
}

function pointAdd(p, q) {
  if (isInf(p)) return q;
  if (isInf(q)) return p;
  if (p.x === q.x && mod(p.y + q.y) === 0n) return INF;
  const lambda = p.x === q.x && p.y === q.y
    ? mod((3n * p.x * p.x) * inv(2n * p.y, CURVE.P), CURVE.P)
    : mod((q.y - p.y) * inv(q.x - p.x, CURVE.P), CURVE.P);
  const x = mod(lambda * lambda - p.x - q.x);
  const y = mod(lambda * (p.x - x) - p.y);
  return { x, y };
}

function pointSub(p, q) {
  return pointAdd(p, pointNeg(q));
}

function pointMul(p, scalar) {
  let n = mod(scalar, CURVE.N);
  let acc = INF;
  let base = p;
  while (n > 0n) {
    if (n & 1n) acc = pointAdd(acc, base);
    base = pointAdd(base, base);
    n >>= 1n;
  }
  return acc;
}

function pointEq(a, b) {
  if (isInf(a) && isInf(b)) return true;
  if (isInf(a) || isInf(b)) return false;
  return a.x === b.x && a.y === b.y;
}

function hex32(n) {
  return n.toString(16).padStart(64, '0');
}

function encodePoint(p) {
  if (isInf(p)) throw new Error('cannot encode infinity');
  return `${p.y & 1n ? '03' : '02'}${hex32(p.x)}`;
}

function decodePoint(hex) {
  if (typeof hex !== 'string' || !/^(02|03)[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('invalid compressed point');
  }
  const odd = hex.slice(0, 2) === '03';
  const x = BigInt(`0x${hex.slice(2)}`);
  const y2 = mod(x ** 3n + 7n);
  let y = modPow(y2, (CURVE.P + 1n) / 4n, CURVE.P);
  if (mod(y * y) !== y2) throw new Error('point is not on curve');
  if (Boolean(y & 1n) !== odd) y = mod(-y);
  return { x, y };
}

function hashHex(...parts) {
  const h = crypto.createHash('sha256');
  for (const part of parts) {
    h.update(String(part));
    h.update('|');
  }
  return h.digest('hex');
}

function hashScalar(...parts) {
  return BigInt(`0x${hashHex(...parts)}`) % CURVE.N;
}

function deriveGeneratorH() {
  for (let i = 0; i < 1024; i++) {
    const x = BigInt(`0x${hashHex(ZKP_PARAMS.hDomain, i)}`) % CURVE.P;
    const y2 = mod(x ** 3n + 7n);
    let y = modPow(y2, (CURVE.P + 1n) / 4n, CURVE.P);
    if (mod(y * y) === y2) {
      if (y & 1n) y = mod(-y);
      return { x, y };
    }
  }
  throw new Error('failed to derive secondary generator');
}

function ceilLog2(n) {
  let bits = 0;
  let value = Math.max(1, n - 1);
  while (value > 0) {
    bits++;
    value >>= 1;
  }
  return bits;
}

function weightedCommitmentSum(bitProofs) {
  return bitProofs.reduce((acc, item, index) => {
    return pointAdd(acc, pointMul(decodePoint(item.commitment), 2n ** BigInt(index)));
  }, INF);
}

function verifyBitProof(commitment, proof, index, domain) {
  const p0 = commitment;
  const p1 = pointSub(commitment, G);
  const a0 = decodePoint(proof.a0);
  const a1 = decodePoint(proof.a1);
  const e0 = BigInt(`0x${proof.e0}`);
  const e1 = BigInt(`0x${proof.e1}`);
  const z0 = BigInt(`0x${proof.z0}`);
  const z1 = BigInt(`0x${proof.z1}`);
  const e = hashScalar('bit-or', domain, index, encodePoint(commitment), proof.a0, proof.a1);
  if (mod(e0 + e1, CURVE.N) !== e) return false;
  const lhs0 = pointMul(H, z0);
  const rhs0 = pointAdd(a0, pointMul(p0, e0));
  const lhs1 = pointMul(H, z1);
  const rhs1 = pointAdd(a1, pointMul(p1, e1));
  return pointEq(lhs0, rhs0) && pointEq(lhs1, rhs1);
}

function verifyLinkProof(proof, expectedStatement, context) {
  const statement = decodePoint(proof.statement);
  if (!pointEq(statement, expectedStatement)) return false;
  const nonceCommitment = decodePoint(proof.nonceCommitment);
  const challenge = BigInt(`0x${proof.challenge}`);
  const expectedChallenge = hashScalar('link', context, proof.statement, proof.nonceCommitment);
  if (challenge !== expectedChallenge) return false;
  const response = BigInt(`0x${proof.response}`);
  const lhs = pointMul(H, response);
  const rhs = pointAdd(nonceCommitment, pointMul(statement, challenge));
  return pointEq(lhs, rhs);
}

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

    await ctx.stub.putState(
      'PolicyPublicParams:active',
      Buffer.from(JSON.stringify(DEFAULT_POLICY_PARAMS))
    );

    await ctx.stub.putState(
      'RiskModel:rules-ahp-v1',
      Buffer.from(JSON.stringify({
        modelVersion: 'rules-ahp-v1',
        modelHash: 'builtin-ahp-risk-scorer',
        modelType: 'AHP+Anomaly+OptionalML',
        approvedBy: 'system',
        active: true,
        createdAt: new Date().toISOString(),
      }))
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
  async EvaluateAccess(
    ctx,
    userId,
    deviceId,
    riskScoreStr,
    requiredPermission,
    proofPackageJson,
    modelVersion,
    resource,
    issueGrantStr
  ) {
    const riskScore = parseFloat(riskScoreStr);
    const txId = ctx.stub.getTxID();
    const timestamp = new Date().toISOString();
    const params = await this._getPolicyPublicParams(ctx);
    const proofPackage = this._parseOptionalJson(proofPackageJson);
    const activeModelVersion = modelVersion || params.activeModelVersion;
    const targetResource = resource || 'default';
    const issueGrant = issueGrantStr !== 'false';
    const proofValidation = this._validateRiskProof(proofPackage, params);
    const proofBacked = proofValidation.valid;

    // Rule 1: Check user exists and is ACTIVE
    const userBytes = await ctx.stub.getState(`UserRegistry:${userId}`);
    if (!userBytes || userBytes.length === 0) {
      return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'DENY', 'User not found', timestamp, {
        modelVersion: activeModelVersion,
        resource: targetResource,
      });
    }

    const user = JSON.parse(userBytes.toString());

    if (user.status !== 'ACTIVE') {
      return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'DENY', 'Account inactive', timestamp, {
        modelVersion: activeModelVersion,
        resource: targetResource,
      });
    }

    // Rule 2: Check device is registered
    if (!user.registeredDevices.includes(deviceId)) {
      return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'DENY', 'Unregistered device', timestamp, {
        modelVersion: activeModelVersion,
        resource: targetResource,
      });
    }

    // Rule 3: Check risk score below threshold
    if (!proofBacked && (Number.isNaN(riskScore) || riskScore >= params.riskThreshold)) {
      return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'DENY', 'Risk score exceeds threshold', timestamp, {
        modelVersion: activeModelVersion,
        resource: targetResource,
        policyId: params.policyId,
        policyVersion: params.policyVersion,
      });
    }

    if (params.zkpRequiredForAllow && !proofBacked) {
      return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'DENY', `Risk proof invalid: ${proofValidation.reason}`, timestamp, {
        modelVersion: activeModelVersion,
        resource: targetResource,
        policyId: params.policyId,
        policyVersion: params.policyVersion,
      });
    }

    // Rule 4: RBAC - check role has required permission
    const roleBytes = await ctx.stub.getState(`RolePermissions:${user.role}`);
    if (!roleBytes || roleBytes.length === 0) {
      return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'DENY', 'Role not found', timestamp, {
        modelVersion: activeModelVersion,
        resource: targetResource,
      });
    }

    const rolePerms = JSON.parse(roleBytes.toString());
    if (!rolePerms.permissions.includes(requiredPermission)) {
      return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'DENY', 'Insufficient permissions', timestamp, {
        modelVersion: activeModelVersion,
        resource: targetResource,
      });
    }

    // All checks passed
    const grant = issueGrant
      ? await this._issueAccessGrant(ctx, {
        txId,
        userId,
        deviceId,
        permission: requiredPermission,
        resource: targetResource,
        timestamp,
        params,
        modelVersion: activeModelVersion,
        proofPackage,
      })
      : undefined;

    return this._logDecision(ctx, txId, userId, deviceId, riskScore, 'ALLOW', issueGrant ? 'All checks passed' : 'Preflight checks passed', timestamp, {
      policyId: params.policyId,
      policyVersion: params.policyVersion,
      modelVersion: activeModelVersion,
      resource: targetResource,
      permission: requiredPermission,
      riskProof: proofValidation.audit,
      accessGrant: grant,
    });
  }

  /**
   * Log the access decision to the blockchain and return the result.
   */
  async _logDecision(ctx, txId, userId, deviceId, riskScore, decision, reason, timestamp, metadata = {}) {
    const hasProof = metadata.riskProof && metadata.riskProof.valid;
    const auditEntry = {
      txId,
      userId,
      deviceId,
      decision,
      reason,
      timestamp,
      resource: metadata.resource || 'default',
      permission: metadata.permission,
      policyId: metadata.policyId,
      policyVersion: metadata.policyVersion,
      modelVersion: metadata.modelVersion,
      riskScoreRedacted: hasProof,
      riskScore: hasProof ? undefined : riskScore,
      riskProof: metadata.riskProof,
      accessGrantId: metadata.accessGrant?.grantId,
    };

    await ctx.stub.putState(
      `AuditLog:${txId}`,
      Buffer.from(JSON.stringify(auditEntry))
    );

    return JSON.stringify({
      decision,
      reason,
      txId,
      policyId: metadata.policyId,
      policyVersion: metadata.policyVersion,
      modelVersion: metadata.modelVersion,
      accessGrant: metadata.accessGrant,
    });
  }

  _parseOptionalJson(jsonValue) {
    if (!jsonValue) {
      return null;
    }
    if (typeof jsonValue !== 'string') {
      return jsonValue;
    }
    const trimmed = jsonValue.trim();
    if (!trimmed) {
      return null;
    }
    return JSON.parse(trimmed);
  }

  async _getPolicyPublicParams(ctx) {
    const paramsBytes = await ctx.stub.getState('PolicyPublicParams:active');
    if (!paramsBytes || paramsBytes.length === 0) {
      return DEFAULT_POLICY_PARAMS;
    }
    return { ...DEFAULT_POLICY_PARAMS, ...JSON.parse(paramsBytes.toString()) };
  }

  _hashJson(value) {
    return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
  }

  _validateRiskProof(proofPackage, params) {
    try {
      if (!proofPackage || !proofPackage.rangeProof) {
        return { valid: false, reason: 'missing proof package' };
      }

      const proof = proofPackage.rangeProof;
      if (proof.proofType !== params.zkpScheme) {
        return { valid: false, reason: `unexpected proof type ${proof.proofType}` };
      }
      if (proof.curve !== ZKP_PARAMS.curve || proof.scale !== ZKP_PARAMS.scale) {
        return { valid: false, reason: 'unsupported proof parameters' };
      }
      const scaledThreshold = Math.round(params.riskThreshold * ZKP_PARAMS.scale);
      if (Number(proof.threshold) !== scaledThreshold) {
        return { valid: false, reason: 'proof threshold does not match active public parameters' };
      }
      if (!Number.isInteger(proof.bitLength) || proof.bitLength !== ceilLog2(proof.threshold)) {
        return { valid: false, reason: 'invalid bit length' };
      }
      if (!Array.isArray(proof.valueBits) || !Array.isArray(proof.diffBits)) {
        return { valid: false, reason: 'missing bit commitments' };
      }
      if (proof.valueBits.length !== proof.bitLength || proof.diffBits.length !== proof.bitLength) {
        return { valid: false, reason: 'bit commitment length mismatch' };
      }

      const valueCommitment = decodePoint(proof.valueCommitment);
      const diffCommitment = decodePoint(proof.diffCommitment);
      if (!pointEq(weightedCommitmentSum(proof.valueBits), valueCommitment)) {
        return { valid: false, reason: 'value bit decomposition mismatch' };
      }
      if (!pointEq(weightedCommitmentSum(proof.diffBits), diffCommitment)) {
        return { valid: false, reason: 'difference bit decomposition mismatch' };
      }

      for (let i = 0; i < proof.bitLength; i++) {
        if (!verifyBitProof(decodePoint(proof.valueBits[i].commitment), proof.valueBits[i].proof, i, 'value')) {
          return { valid: false, reason: `invalid value bit proof at index ${i}` };
        }
        if (!verifyBitProof(decodePoint(proof.diffBits[i].commitment), proof.diffBits[i].proof, i, 'diff')) {
          return { valid: false, reason: `invalid difference bit proof at index ${i}` };
        }
      }

      const maxValue = BigInt(proof.threshold - 1);
      const thresholdPoint = pointMul(G, maxValue);
      const expectedStatement = pointSub(pointAdd(valueCommitment, diffCommitment), thresholdPoint);
      const context = [
        proof.valueCommitment,
        proof.diffCommitment,
        proof.threshold,
        proof.bitLength,
        proof.proofType,
      ].join('|');
      if (!verifyLinkProof(proof.linkProof, expectedStatement, context)) {
        return { valid: false, reason: 'threshold link proof failed' };
      }

      return {
        valid: true,
        audit: {
          valid: true,
          proofId: proof.proofId,
          proofType: proof.proofType,
          commitment: proofPackage.commitment,
          proofHash: this._hashJson(proof),
          curve: proof.curve,
          threshold: params.riskThreshold,
        },
      };
    } catch (err) {
      return { valid: false, reason: err.message };
    }
  }

  async _issueAccessGrant(ctx, { txId, userId, deviceId, permission, resource, timestamp, params, modelVersion, proofPackage }) {
    const issuedAtMs = Date.parse(timestamp);
    const expiresAt = new Date(issuedAtMs + params.accessGrantTtlSeconds * 1000).toISOString();
    const grantId = crypto.createHash('sha256')
      .update(`${txId}:${userId}:${deviceId}:${resource}:${permission}:${timestamp}`)
      .digest('hex');
    const grant = {
      grantId,
      subject: userId,
      deviceId,
      resource,
      permission,
      issuedAt: timestamp,
      expiresAt,
      revoked: false,
      issuingTxId: txId,
      policyId: params.policyId,
      policyVersion: params.policyVersion,
      modelVersion,
      proofId: proofPackage?.rangeProof?.proofId,
      proofHash: proofPackage ? this._hashJson(proofPackage.rangeProof) : undefined,
    };

    await ctx.stub.putState(`AccessGrant:${grantId}`, Buffer.from(JSON.stringify(grant)));
    return grant;
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

  /**
   * Return the active public parameters that govern access decisions.
   * These are the IAM equivalent of Fabric Token SDK public parameters.
   */
  async GetPolicyPublicParams(ctx) {
    const params = await this._getPolicyPublicParams(ctx);
    return JSON.stringify(params);
  }

  /**
   * Update the active policy public parameters.
   *
   * In a production multi-org network this transaction should be guarded by a
   * strict endorsement policy and client-identity attribute checks. The current
   * single-org prototype relies on Fabric endorsement policy for governance.
   */
  async UpdatePolicyPublicParams(ctx, paramsJson) {
    const current = await this._getPolicyPublicParams(ctx);
    const updates = JSON.parse(paramsJson);
    const next = {
      ...current,
      ...updates,
      updatedAt: new Date().toISOString(),
      updateTxId: ctx.stub.getTxID(),
    };

    if (typeof next.riskThreshold !== 'number' || next.riskThreshold <= 0 || next.riskThreshold > 1) {
      throw new Error('riskThreshold must be a number in (0, 1]');
    }
    if (!Number.isInteger(next.accessGrantTtlSeconds) || next.accessGrantTtlSeconds <= 0) {
      throw new Error('accessGrantTtlSeconds must be a positive integer');
    }

    await ctx.stub.putState('PolicyPublicParams:active', Buffer.from(JSON.stringify(next)));
    await ctx.stub.putState(
      'PolicyThresholds:default',
      Buffer.from(JSON.stringify({ riskThreshold: next.riskThreshold }))
    );

    return JSON.stringify({ status: 'updated', txId: next.updateTxId, params: next });
  }

  /**
   * Register a risk-model version and optionally mark it active.
   */
  async RegisterRiskModel(ctx, modelVersion, modelHash, modelType, approvedBy, activateStr) {
    const activate = activateStr === true || activateStr === 'true';
    const model = {
      modelVersion,
      modelHash,
      modelType: modelType || 'unknown',
      approvedBy: approvedBy || 'unknown',
      active: activate,
      createdAt: new Date().toISOString(),
      txId: ctx.stub.getTxID(),
    };

    await ctx.stub.putState(`RiskModel:${modelVersion}`, Buffer.from(JSON.stringify(model)));

    if (activate) {
      const params = await this._getPolicyPublicParams(ctx);
      params.activeModelVersion = modelVersion;
      params.updatedAt = model.createdAt;
      params.updateTxId = model.txId;
      await ctx.stub.putState('PolicyPublicParams:active', Buffer.from(JSON.stringify(params)));
    }

    return JSON.stringify({ status: 'registered', model });
  }

  async GetRiskModel(ctx, modelVersion) {
    const modelBytes = await ctx.stub.getState(`RiskModel:${modelVersion}`);
    if (!modelBytes || modelBytes.length === 0) {
      throw new Error(`Risk model ${modelVersion} not found`);
    }
    return modelBytes.toString();
  }

  /**
   * Verify a short-lived, non-transferable access grant.
   */
  async VerifyAccessGrant(ctx, grantId, subject, resource, permission) {
    const grantBytes = await ctx.stub.getState(`AccessGrant:${grantId}`);
    if (!grantBytes || grantBytes.length === 0) {
      return JSON.stringify({ valid: false, reason: 'Access grant not found' });
    }

    const grant = JSON.parse(grantBytes.toString());
    const now = Date.now();
    if (grant.revoked) {
      return JSON.stringify({ valid: false, reason: 'Access grant revoked', grant });
    }
    if (Date.parse(grant.expiresAt) <= now) {
      return JSON.stringify({ valid: false, reason: 'Access grant expired', grant });
    }
    if (subject && grant.subject !== subject) {
      return JSON.stringify({ valid: false, reason: 'Subject mismatch', grant });
    }
    if (resource && grant.resource !== resource) {
      return JSON.stringify({ valid: false, reason: 'Resource mismatch', grant });
    }
    if (permission && grant.permission !== permission) {
      return JSON.stringify({ valid: false, reason: 'Permission mismatch', grant });
    }

    return JSON.stringify({ valid: true, reason: 'Access grant valid', grant });
  }

  async RevokeAccessGrant(ctx, grantId, reason) {
    const grantBytes = await ctx.stub.getState(`AccessGrant:${grantId}`);
    if (!grantBytes || grantBytes.length === 0) {
      throw new Error(`Access grant ${grantId} not found`);
    }

    const grant = JSON.parse(grantBytes.toString());
    grant.revoked = true;
    grant.revokedAt = new Date().toISOString();
    grant.revokedByTxId = ctx.stub.getTxID();
    grant.revocationReason = reason || 'revoked';

    await ctx.stub.putState(`AccessGrant:${grantId}`, Buffer.from(JSON.stringify(grant)));
    return JSON.stringify({ revoked: true, grantId, txId: grant.revokedByTxId });
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
