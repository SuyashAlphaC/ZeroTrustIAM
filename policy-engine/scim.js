'use strict';

/**
 * Minimal SCIM 2.0 User provisioning API (RFC 7643 / 7644 subset).
 *
 * Endpoints (mounted at /scim/v2):
 *   GET    /Users
 *   GET    /Users/:id
 *   POST   /Users
 *   PATCH  /Users/:id
 *   DELETE /Users/:id
 *   GET    /ServiceProviderConfig
 *   GET    /Schemas
 *   GET    /ResourceTypes
 *
 * Auth: Bearer token with admin role (or SCIM_BEARER_TOKEN shared secret).
 */

const express = require('express');
const crypto = require('crypto');
const db = require('./database');
const passwordPolicy = require('./passwordPolicy');
const userProvisioning = require('./userProvisioning');
const blockchain = require('./fabricClient');
const { requireAuth, requireRole } = require('./middleware');
const config = require('./config');

const router = express.Router();

const SCIM_CONTENT = 'application/scim+json';

function scimError(res, status, detail, scimType) {
  return res.status(status).type(SCIM_CONTENT).json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
    detail,
    status: String(status),
    scimType: scimType || undefined,
  });
}

/** Admin JWT or static SCIM bearer for automation. */
function requireScimAuth(req, res, next) {
  const scimToken = process.env.SCIM_BEARER_TOKEN;
  const auth = req.headers.authorization || '';
  if (scimToken && auth === `Bearer ${scimToken}`) {
    req.user = { sub: 'scim-provisioner', role: 'admin', type: 'access' };
    return next();
  }
  return requireAuth(req, res, (err) => {
    if (err) return next(err);
    return requireRole('admin')(req, res, next);
  });
}

function toScimUser(row) {
  const active = row.status === 'ACTIVE';
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id: row.user_id || row.userId,
    userName: row.user_id || row.userId,
    active,
    name: {
      formatted: row.user_id || row.userId,
    },
    roles: [{ value: row.role, primary: true }],
    meta: {
      resourceType: 'User',
      created: row.created_at || row.createdAt,
      lastModified: row.updated_at || row.created_at || row.createdAt,
      location: `${config.oauthIssuer}/scim/v2/Users/${row.user_id || row.userId}`,
    },
  };
}

router.use(requireScimAuth);

router.get('/ServiceProviderConfig', (_req, res) => {
  res.type(SCIM_CONTENT).json({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 200 },
    changePassword: { supported: true },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [{
      type: 'oauthbearertoken',
      name: 'OAuth Bearer Token',
      description: 'Admin JWT or SCIM_BEARER_TOKEN',
      primary: true,
    }],
  });
});

router.get('/ResourceTypes', (_req, res) => {
  res.type(SCIM_CONTENT).json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: 1,
    Resources: [{
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
      id: 'User',
      name: 'User',
      endpoint: '/Users',
      schema: 'urn:ietf:params:scim:schemas:core:2.0:User',
    }],
  });
});

router.get('/Schemas', (_req, res) => {
  res.type(SCIM_CONTENT).json({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    totalResults: 1,
    Resources: [{
      id: 'urn:ietf:params:scim:schemas:core:2.0:User',
      name: 'User',
      attributes: [
        { name: 'userName', type: 'string', required: true, uniqueness: 'server' },
        { name: 'active', type: 'boolean' },
        { name: 'password', type: 'string', mutability: 'writeOnly' },
      ],
    }],
  });
});

router.get('/Users', async (req, res, next) => {
  try {
    const users = await db.getAllUsers();
    let filtered = users;
    const filter = req.query.filter;
    if (filter && typeof filter === 'string') {
      // Support: userName eq "alice"
      const m = /userName\s+eq\s+"([^"]+)"/i.exec(filter);
      if (m) filtered = users.filter((u) => u.user_id === m[1]);
    }
    const start = Math.max(parseInt(req.query.startIndex || '1', 10) - 1, 0);
    const count = Math.min(parseInt(req.query.count || '100', 10) || 100, 200);
    const page = filtered.slice(start, start + count);
    res.type(SCIM_CONTENT).json({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: filtered.length,
      startIndex: start + 1,
      itemsPerPage: page.length,
      Resources: page.map(toScimUser),
    });
  } catch (err) {
    next(err);
  }
});

router.get('/Users/:id', async (req, res, next) => {
  try {
    const user = await db.getUser(req.params.id);
    if (!user) return scimError(res, 404, 'User not found', 'noTarget');
    res.type(SCIM_CONTENT).json(toScimUser({
      user_id: user.userId,
      role: user.role,
      status: user.status,
      created_at: user.createdAt,
    }));
  } catch (err) {
    next(err);
  }
});

router.post('/Users', async (req, res, next) => {
  try {
    const userName = req.body.userName || req.body.user_name;
    if (!userName || !/^[a-zA-Z0-9]{2,50}$/.test(userName)) {
      return scimError(res, 400, 'userName required (alphanumeric 2-50)', 'invalidValue');
    }
    const existing = await db.getUser(userName);
    if (existing) return scimError(res, 409, 'User already exists', 'uniqueness');

    let password = req.body.password;
    if (!password) {
      password = crypto.randomBytes(24).toString('base64url') + 'Aa1!';
    }
    const policy = passwordPolicy.validatePassword(password, { username: userName });
    if (!policy.ok) {
      return scimError(res, 400, policy.errors.join('; '), 'invalidValue');
    }

    const role = req.body.roles?.[0]?.value || 'viewer';
    const resolvedRole = ['admin', 'viewer', 'editor'].includes(role) ? role : 'viewer';
    await userProvisioning.provisionUser({
      userId: userName,
      password,
      role: resolvedRole,
      devices: [],
      skipPasswordPolicy: false,
    });

    const user = await db.getUser(userName);
    res.status(201).type(SCIM_CONTENT).json(toScimUser({
      user_id: user.userId,
      role: user.role,
      status: user.status,
      created_at: user.createdAt,
    }));
  } catch (err) {
    if (err.code === 'EXISTS') return scimError(res, 409, 'User already exists', 'uniqueness');
    if (err.code === 'PASSWORD_POLICY') return scimError(res, 400, (err.details || []).join('; '), 'invalidValue');
    if (err.code === 'FABRIC_PROVISION_FAILED') return scimError(res, 502, err.message, 'invalidValue');
    next(err);
  }
});

router.patch('/Users/:id', async (req, res, next) => {
  try {
    const user = await db.getUser(req.params.id);
    if (!user) return scimError(res, 404, 'User not found', 'noTarget');

    const ops = req.body.Operations || req.body.operations || [];
    for (const op of ops) {
      const path = (op.path || '').toLowerCase();
      const value = op.value;
      if (path === 'active' || (!path && value && typeof value.active === 'boolean')) {
        const active = path === 'active' ? value : value.active;
        const status = active ? 'ACTIVE' : 'SUSPENDED';
        await db.setUserStatus(req.params.id, status);
        try {
          await blockchain.updateUserStatus(req.params.id, status);
        } catch (fabricErr) {
          // Best-effort on-chain status; Postgres remains source for login gates
          require('./logger').logger.warn({ err: fabricErr.message }, 'SCIM Fabric status update failed');
        }
      }
      if (path === 'password' || (!path && value?.password)) {
        const pw = path === 'password' ? value : value.password;
        const policy = passwordPolicy.validatePassword(pw, { username: req.params.id });
        if (!policy.ok) return scimError(res, 400, policy.errors.join('; '), 'invalidValue');
        const hash = await passwordPolicy.hashPassword(pw);
        await db.updateUserPassword(req.params.id, hash);
        await db.revokeAllUserTokens(req.params.id);
      }
    }

    const updated = await db.getUser(req.params.id);
    res.type(SCIM_CONTENT).json(toScimUser({
      user_id: updated.userId,
      role: updated.role,
      status: updated.status,
      created_at: updated.createdAt,
    }));
  } catch (err) {
    next(err);
  }
});

router.delete('/Users/:id', async (req, res, next) => {
  try {
    const user = await db.getUser(req.params.id);
    if (!user) return scimError(res, 404, 'User not found', 'noTarget');
    const redactionId = crypto.randomBytes(12).toString('hex');
    await db.eraseUserAccount(req.params.id, redactionId);
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

module.exports = router;
