'use strict';

/**
 * Authenticated self-service routes under /me/*
 * Wired into the policy-engine API router.
 */

const crypto = require('crypto');
const express = require('express');
const db = require('./database');
const { requireAuth, validate } = require('./middleware');
const passwordPolicy = require('./passwordPolicy');
const userProvisioning = require('./userProvisioning');
const { logger } = require('./logger');

const router = express.Router();

function userId(req) {
  return req.user.sub;
}

// ──────────────────────── Profile ────────────────────────

router.get('/profile', requireAuth, async (req, res, next) => {
  try {
    const user = await db.getUser(userId(req));
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      userId: user.userId,
      role: user.role,
      status: user.status,
      usualLocation: user.usualLocation,
      normalHours: user.normalHours,
      did: user.did,
      createdAt: user.createdAt,
      deviceCount: user.registeredDevices.length,
    });
  } catch (err) {
    next(err);
  }
});

// ──────────────────────── Devices ────────────────────────

router.get('/devices', requireAuth, async (req, res, next) => {
  try {
    const currentId = typeof req.query.current === 'string' ? req.query.current : null;
    const devices = await db.getUserDevices(userId(req));
    res.json({
      devices: devices.map((d) => {
        const registeredAt = d.registered_at instanceof Date
          ? d.registered_at.toISOString()
          : d.registered_at;
        const lastSeenAt = d.last_seen_at instanceof Date
          ? d.last_seen_at.toISOString()
          : (d.last_seen_at || registeredAt || null);
        const isCurrent = !!(currentId && d.device_id === currentId);
        return {
          id: d.device_id,
          deviceId: d.device_id,
          label: d.label || null,
          registeredAt,
          lastSeenAt,
          lastSeenAtSource: d.last_seen_at ? 'login' : 'registered',
          country: d.last_country || null,
          city: d.last_city || null,
          lastDecision: d.last_decision || null,
          // Registered devices are trusted credentials; UI can show "trusted"
          trusted: true,
          current: isCurrent,
        };
      }),
    });
  } catch (err) {
    next(err);
  }
});

router.delete('/devices/:deviceId', requireAuth, async (req, res, next) => {
  try {
    const deviceId = req.params.deviceId;
    if (!deviceId || deviceId.length > 100) {
      return res.status(400).json({ error: 'Invalid deviceId' });
    }
    const devices = await db.getUserDevices(userId(req));
    if (devices.length <= 1) {
      return res.status(400).json({ error: 'Cannot remove the last registered device' });
    }
    const removed = await db.deleteUserDevice(userId(req), deviceId);
    if (!removed) return res.status(404).json({ error: 'Device not found' });
    await db.writeAuditLog({
      userId: userId(req),
      deviceId,
      decision: 'DEVICE_REMOVED',
      reason: 'User removed device',
      layer: 'Self-service',
    });
    res.json({ removed: true, deviceId });
  } catch (err) {
    next(err);
  }
});

router.post('/devices', requireAuth, validate('registerOwnDevice'), async (req, res, next) => {
  try {
    const { deviceId, label } = req.body;
    const deviceTrust = require('./deviceTrust');
    if (!deviceTrust.isValidDeviceCredential(deviceId)) {
      return res.status(400).json({ error: 'Invalid device credential' });
    }
    const uid = userId(req);
    const me = await db.getUser(uid);
    const result = await userProvisioning.provisionDevice(uid, deviceId, {
      label: label || null,
      role: me?.role || req.user.role,
    });
    res.status(201).json({
      registered: true,
      deviceId: result.deviceId,
      label: result.label,
      fabric: result.fabric,
    });
  } catch (err) {
    if (err.code === 'FABRIC_DEVICE_FAILED') {
      return res.status(502).json({ error: err.message, code: err.code });
    }
    if (err.code === 'NOT_FOUND') {
      return res.status(404).json({ error: 'User not found' });
    }
    next(err);
  }
});

// ──────────────────────── Sessions (refresh tokens) ────────────────────────

router.get('/sessions', requireAuth, async (req, res, next) => {
  try {
    const sessions = await db.listUserSessions(userId(req));
    res.json({
      sessions: sessions.map((s) => ({
        id: s.session_id,
        familyId: s.family_id,
        status: s.status,
        issuedAt: s.issued_at instanceof Date ? s.issued_at.toISOString() : s.issued_at,
        expiresAt: s.expires_at instanceof Date ? s.expires_at.toISOString() : s.expires_at,
        current: false,
      })),
    });
  } catch (err) {
    next(err);
  }
});

router.delete('/sessions/:sessionId', requireAuth, async (req, res, next) => {
  try {
    const ok = await db.revokeUserSession(userId(req), req.params.sessionId);
    if (!ok) return res.status(404).json({ error: 'Session not found' });
    res.json({ revoked: true, sessionId: req.params.sessionId });
  } catch (err) {
    next(err);
  }
});

router.post('/sessions/revoke-others', requireAuth, async (req, res, next) => {
  try {
    // Optional: keepCurrentToken in body
    const keepToken = req.body?.keepRefreshToken || null;
    const n = await db.revokeOtherUserSessions(userId(req), keepToken);
    res.json({ revoked: n });
  } catch (err) {
    next(err);
  }
});

// ──────────────────────── Login history ────────────────────────

router.get('/login-history', requireAuth, async (req, res, next) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '25', 10) || 25, 200);
    const { classifyReason } = require('./authPublicResponse');
    let rows = [];
    try {
      rows = await db.getUserAccessHistory(userId(req), limit);
    } catch {
      // Fallback if join query fails on older schemas
      rows = (await db.getLoginHistory(userId(req), limit)).map((r) => ({
        timestamp: r.timestamp,
        decision: r.decision,
        reason: null,
        layer: null,
        device_id: r.device_id,
        country: r.country,
        city: r.city,
        tx_id: null,
      }));
    }
    // Never expose raw risk scores. Map internal reasons to safe copy.
    res.json({
      history: rows.map((r) => {
        const classified = classifyReason(r.decision, r.reason);
        const ts = r.timestamp instanceof Date ? r.timestamp.toISOString() : r.timestamp;
        return {
          deviceId: r.device_id || r.deviceId || null,
          country: r.country || null,
          city: r.city || null,
          timestamp: ts,
          decision: r.decision,
          reason: classified.reason,
          userMessage: classified.userMessage,
          reasonCode: classified.reasonCode,
          layer: r.layer || null,
          txId: r.tx_id || r.txId || null,
        };
      }),
    });
  } catch (err) {
    next(err);
  }
});

// ──────────────────────── Change password ────────────────────────

router.post('/change-password', requireAuth, validate('changePassword'), async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await db.getUser(userId(req));
    if (!user) return res.status(404).json({ error: 'User not found' });

    const valid = await passwordPolicy.verifyPassword(currentPassword, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const policy = passwordPolicy.validatePassword(newPassword, { username: userId(req) });
    if (!policy.ok) {
      return res.status(400).json({ error: 'Password policy violation', details: policy.errors });
    }

    const hash = await passwordPolicy.hashPassword(newPassword);
    await db.updateUserPassword(userId(req), hash);
    await db.revokeAllUserTokens(userId(req));
    await db.writeAuditLog({
      userId: userId(req),
      decision: 'PASSWORD_CHANGED',
      reason: 'User changed password; all sessions revoked',
      layer: 'Self-service',
    });
    res.json({ changed: true, sessionsRevoked: true });
  } catch (err) {
    next(err);
  }
});

// ──────────────────────── GDPR export ────────────────────────

router.get('/export', requireAuth, async (req, res, next) => {
  try {
    const uid = userId(req);
    const user = await db.getUser(uid);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const [devices, history, sessions, mfa, webauthn, audit] = await Promise.all([
      db.getUserDevices(uid),
      db.getLoginHistory(uid, 500),
      db.listUserSessions(uid),
      db.getMFASecret(uid),
      db.getWebAuthnCredentials(uid),
      db.queryAuditLog({ userId: uid, limit: 500 }),
    ]);

    const archive = {
      exportVersion: 1,
      exportedAt: new Date().toISOString(),
      subject: uid,
      profile: {
        userId: user.userId,
        role: user.role,
        status: user.status,
        usualLocation: user.usualLocation,
        normalHours: user.normalHours,
        did: user.did,
        createdAt: user.createdAt,
      },
      devices: devices.map((d) => ({
        deviceId: d.device_id,
        label: d.label,
        registeredAt: d.registered_at,
      })),
      loginHistory: history,
      sessions: sessions.map((s) => ({
        sessionId: s.session_id,
        familyId: s.family_id,
        status: s.status,
        issuedAt: s.issued_at,
        expiresAt: s.expires_at,
      })),
      mfa: {
        enrolled: !!(mfa && mfa.enabled),
        enrolledAt: mfa?.enrolled_at || null,
        // never export TOTP secret
      },
      webauthn: (webauthn || []).map((c) => ({
        credentialId: c.credential_id,
        counter: c.counter,
        registeredAt: c.registered_at,
        transports: c.transports,
      })),
      auditLog: audit.map((a) => ({
        txId: a.tx_id,
        deviceId: a.device_id,
        riskScore: a.risk_score,
        decision: a.decision,
        reason: a.reason,
        layer: a.layer,
        createdAt: a.created_at,
      })),
      notes: [
        'TOTP secrets and password hashes are never included.',
        'Hyperledger Fabric audit hashes remain on-chain; PII is redacted on erasure.',
      ],
    };

    const body = JSON.stringify(archive, null, 2);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="ztiam-${uid}-export.json"`);
    res.send(body);
  } catch (err) {
    next(err);
  }
});

// ──────────────────────── Account erasure (GDPR Art. 17) ────────────────────────

router.delete('/account', requireAuth, async (req, res, next) => {
  try {
    const uid = userId(req);
    const user = await db.getUser(uid);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.role === 'admin') {
      // Prevent accidental wipe of last admin — require confirmation header
      const confirm = req.headers['x-confirm-admin-erase'];
      if (confirm !== 'ERASE-ADMIN') {
        return res.status(400).json({
          error: 'Admin account erasure requires header X-Confirm-Admin-Erase: ERASE-ADMIN',
        });
      }
    }

    const redactionId = crypto.randomBytes(16).toString('hex');
    await db.eraseUserAccount(uid, redactionId);
    logger.info({ userId: uid, redactionId }, 'Account erased (GDPR Art. 17)');
    res.json({
      erased: true,
      redactionId,
      message: 'Account PII deleted from operational stores. On-chain audit entries retain hashed tombstones only.',
    });
  } catch (err) {
    next(err);
  }
});

// ──────────────────────── MFA status (self) ────────────────────────

router.get('/mfa', requireAuth, async (req, res, next) => {
  try {
    const mfaData = await db.getMFASecret(userId(req));
    res.json({
      enabled: !!(mfaData && mfaData.enabled),
      enrolledAt: mfaData?.enrolled_at || null,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
