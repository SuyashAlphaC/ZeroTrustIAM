'use strict';

/**
 * Public auth response shaping.
 *
 * Risk scores, ensemble weights, and factor breakdowns are security-control
 * plane data. They must never leave the policy engine on user-facing paths
 * (login /evaluate, MFA challenge completion). Full detail stays in logs and
 * admin-only audit APIs.
 */

const SENSITIVE_KEYS = [
  'riskScore',
  'baseRiskScore',
  'breakdown',
  'ensemble',
  'anomaly',
  'anomalyResult',
  'mlResult',
  'weights',
  'components',
  'profile',
  'pdp',
];

/**
 * Map internal decision reasons to stable codes + end-user safe copy.
 * Never embed numeric scores in reason or userMessage.
 */
function classifyReason(decision, reason) {
  const r = String(reason || '');
  const lower = r.toLowerCase();

  if (decision === 'ALLOW') {
    return {
      reasonCode: 'OK',
      userMessage: 'Sign-in successful.',
      reason: 'All checks passed',
    };
  }

  if (decision === 'MFA_REQUIRED') {
    return {
      reasonCode: 'MFA_REQUIRED',
      userMessage: 'Additional verification is required to continue.',
      reason: 'Step-up authentication required',
    };
  }

  if (lower.includes('invalid credentials') || lower.includes('user not found')) {
    return {
      reasonCode: 'INVALID_CREDENTIALS',
      userMessage: 'Invalid username or password.',
      reason: 'Invalid credentials',
    };
  }

  if (lower.includes('locked')) {
    return {
      reasonCode: 'ACCOUNT_LOCKED',
      userMessage: 'Account temporarily locked. Try again later.',
      reason: 'Account temporarily locked due to failed attempts',
    };
  }

  if (lower.includes('unregistered device') || lower.includes('untrusted device') || lower.includes('new device')) {
    return {
      reasonCode: 'UNTRUSTED_DEVICE',
      userMessage: 'This device is not trusted for your account. Complete verification or register it from a trusted session.',
      reason: 'Untrusted device',
    };
  }

  if (lower.includes('risk') || lower.includes('too high') || lower.includes('threshold')) {
    return {
      reasonCode: 'RISK_DENIED',
      userMessage: 'We could not verify this sign-in. Try again later or contact support.',
      reason: 'Sign-in could not be verified',
    };
  }

  if (lower.includes('mfa')) {
    return {
      reasonCode: 'MFA_FAILED',
      userMessage: 'Multi-factor verification failed.',
      reason: 'MFA verification failed',
    };
  }

  if (lower.includes('permission') || lower.includes('rbac') || lower.includes('insufficient') || lower.includes('role')) {
    return {
      reasonCode: 'FORBIDDEN',
      userMessage: 'You do not have permission for this action.',
      reason: 'Insufficient permissions',
    };
  }

  if (lower.includes('inactive') || lower.includes('suspended') || lower.includes('deleted')) {
    return {
      reasonCode: 'ACCOUNT_INACTIVE',
      userMessage: 'This account cannot sign in.',
      reason: 'Account inactive',
    };
  }

  if (lower.includes('pdp') || lower.includes('forbid') || lower.includes('policy')) {
    return {
      reasonCode: 'POLICY_DENIED',
      userMessage: 'Access denied by policy.',
      reason: 'Access denied by policy',
    };
  }

  if (
    lower.includes('fail-closed')
    || lower.includes('fail closed')
    || lower.includes('authorization service unavailable')
    || lower.includes('fabric unavailable')
    || lower.includes('ledger')
  ) {
    return {
      reasonCode: 'AUTHZ_UNAVAILABLE',
      userMessage: 'Authorization service is temporarily unavailable. Try again in a moment.',
      reason: 'Authorization service unavailable',
    };
  }

  return {
    reasonCode: 'DENIED',
    userMessage: 'Access denied.',
    reason: 'Access denied',
  };
}

/**
 * Strip sensitive fields and normalize reason for public clients.
 * Tokens and operational flags (challengeId, tokenSet, txId) are preserved.
 *
 * @param {object} body
 * @param {{ exposeRiskDetails?: boolean }} [opts]
 */
function sanitizePublicAuthResponse(body, opts = {}) {
  if (!body || typeof body !== 'object') return body;

  const expose = opts.exposeRiskDetails === true;
  const out = { ...body };

  if (!expose) {
    for (const k of SENSITIVE_KEYS) {
      delete out[k];
    }
    // Nested leftovers on zkProof experimental payloads
    if (out.zkProof && typeof out.zkProof === 'object') {
      const { proofId, experimental } = out.zkProof;
      out.zkProof = experimental ? { proofId, experimental: true } : (proofId ? { proofId } : undefined);
      if (!out.zkProof) delete out.zkProof;
    }
  }

  const classified = classifyReason(out.decision, body.reason);
  out.reasonCode = out.reasonCode || classified.reasonCode;
  out.userMessage = out.userMessage || classified.userMessage;
  // Replace reason with non-leaking text unless already a safe constant
  if (!expose) {
    out.reason = classified.reason;
  }

  return out;
}

/**
 * Express helper: res.json with public sanitization.
 */
function sendPublicAuth(res, statusOrBody, maybeBody) {
  let status = 200;
  let body = statusOrBody;
  if (typeof statusOrBody === 'number') {
    status = statusOrBody;
    body = maybeBody;
  }
  const config = require('./config');
  return res.status(status).json(
    sanitizePublicAuthResponse(body, { exposeRiskDetails: config.exposeRiskDetails })
  );
}

module.exports = {
  SENSITIVE_KEYS,
  classifyReason,
  sanitizePublicAuthResponse,
  sendPublicAuth,
};
