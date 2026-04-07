'use strict';

const crypto = require('crypto');
const { logger } = require('./logger');

// In-memory world state (mirrors what the real Fabric chaincode will store)
const worldState = {
  UserRegistry: {
    alice: {
      userId: 'alice',
      role: 'admin',
      registeredDevices: ['dev-001'],
      status: 'ACTIVE',
    },
    bob: {
      userId: 'bob',
      role: 'viewer',
      registeredDevices: ['dev-002'],
      status: 'ACTIVE',
    },
  },
  RolePermissions: {
    admin: { permissions: ['read', 'write', 'delete', 'manage'] },
    viewer: { permissions: ['read'] },
  },
  PolicyThresholds: {
    riskThreshold: 0.6,
  },
};

// Immutable audit log (append-only)
const auditLog = [];

/**
 * Evaluate access using the same 4 rules the real chaincode will enforce:
 * 1. User account is ACTIVE
 * 2. Device is in registeredDevices
 * 3. Risk score < threshold
 * 4. User role has required permissions (RBAC)
 */
function evaluateAccess(userId, deviceId, riskScore, requiredPermission) {
  const txId = 'mock-' + crypto.randomUUID().slice(0, 8);
  const timestamp = new Date().toISOString();

  // Rule 1: User exists and is ACTIVE
  const user = worldState.UserRegistry[userId];
  if (!user) {
    return logAndReturn(txId, userId, deviceId, riskScore, 'DENY', 'User not found', timestamp);
  }
  if (user.status !== 'ACTIVE') {
    return logAndReturn(txId, userId, deviceId, riskScore, 'DENY', 'Account inactive', timestamp);
  }

  // Rule 2: Device is registered
  if (!user.registeredDevices.includes(deviceId)) {
    return logAndReturn(txId, userId, deviceId, riskScore, 'DENY', 'Unregistered device', timestamp);
  }

  // Rule 3: Risk score below threshold
  if (riskScore >= worldState.PolicyThresholds.riskThreshold) {
    return logAndReturn(txId, userId, deviceId, riskScore, 'DENY', 'Risk score exceeds threshold', timestamp);
  }

  // Rule 4: RBAC - role has required permission
  const rolePerms = worldState.RolePermissions[user.role];
  if (!rolePerms || !rolePerms.permissions.includes(requiredPermission)) {
    return logAndReturn(txId, userId, deviceId, riskScore, 'DENY', 'Insufficient permissions', timestamp);
  }

  return logAndReturn(txId, userId, deviceId, riskScore, 'ALLOW', 'All checks passed', timestamp);
}

function logAndReturn(txId, userId, deviceId, riskScore, decision, reason, timestamp) {
  const entry = { txId, userId, deviceId, riskScore, decision, reason, timestamp };
  auditLog.push(entry);
  logger.info({ txId, userId, decision, reason }, 'Blockchain decision logged');
  return { decision, reason, txId, layer: 'Smart Contract (mock)' };
}

function getAuditLog() {
  return [...auditLog];
}

function getWorldState() {
  return { ...worldState };
}

module.exports = { evaluateAccess, getAuditLog, getWorldState };
