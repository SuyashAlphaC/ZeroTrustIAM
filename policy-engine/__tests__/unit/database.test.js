'use strict';

process.env.TEST_DATABASE_URL = process.env.TEST_DATABASE_URL
  || 'postgresql://ztiam:testpassword@127.0.0.1:5432/ztiam_test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'unit-test-jwt';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'unit-test-refresh';
process.env.OAUTH_DEFAULT_CLIENT_SECRET = process.env.OAUTH_DEFAULT_CLIENT_SECRET || 'unit-test-oauth';

const db = require('../../database');

describe('database', () => {
  beforeAll(async () => {
    await db.init();
    await db.truncateTestData();
    await db._prepareStatements();
  });

  afterAll(async () => {
    await db.close();
  });

  describe('users', () => {
    it('creates and retrieves a user', async () => {
      await db.createUser({
        userId: 'testuser1',
        password: 'testpass',
        role: 'viewer',
        usualCountry: 'US',
        usualCity: 'NYC',
        normalHoursStart: 9,
        normalHoursEnd: 17,
        devices: ['dev-t1'],
      });

      const user = await db.getUser('testuser1');
      expect(user).not.toBeNull();
      expect(user.userId).toBe('testuser1');
      expect(user.role).toBe('viewer');
      expect(user.usualLocation.country).toBe('US');
      expect(user.usualLocation.city).toBe('NYC');
      expect(user.normalHours).toEqual([9, 17]);
      expect(user.registeredDevices).toContain('dev-t1');
    });

    it('returns null for non-existent user', async () => {
      expect(await db.getUser('nonexistent')).toBeNull();
    });

    it('stores password as bcrypt hash', async () => {
      const user = await db.getUser('testuser1');
      expect(user.passwordHash).toMatch(/^\$2[aby]\$/);
      expect(user.passwordHash).not.toBe('testpass');
    });

    it('lists all users', async () => {
      await db.createUser({ userId: 'testuser2', password: 'pass2', role: 'admin' });
      const users = await db.getAllUsers();
      expect(users.length).toBeGreaterThanOrEqual(2);
      expect(users.some(u => u.user_id === 'testuser1')).toBe(true);
      expect(users.some(u => u.user_id === 'testuser2')).toBe(true);
    });

    it('rejects duplicate user_id', async () => {
      await expect(
        db.createUser({ userId: 'testuser1', password: 'dup' })
      ).rejects.toMatchObject({ code: '23505' });
    });
  });

  describe('devices', () => {
    it('registers and retrieves devices', async () => {
      await db.registerDevice('testuser1', 'dev-t2', 'Work laptop');
      const devices = await db.getUserDevices('testuser1');
      expect(devices.some(d => d.device_id === 'dev-t2')).toBe(true);
    });

    it('ignores duplicate device registration', async () => {
      await db.registerDevice('testuser1', 'dev-t1');
      const devices = await db.getUserDevices('testuser1');
      const count = devices.filter(d => d.device_id === 'dev-t1').length;
      expect(count).toBe(1);
    });
  });

  describe('refresh tokens', () => {
    const token = 'test-refresh-token-abc';
    const futureDate = new Date(Date.now() + 86400000).toISOString();

    it('stores and validates a refresh token', async () => {
      await db.storeRefreshToken(token, 'testuser1', futureDate);
      expect(await db.isRefreshTokenValid(token)).toBe(true);
    });

    it('revokes a refresh token', async () => {
      await db.revokeRefreshToken(token);
      expect(await db.isRefreshTokenValid(token)).toBe(false);
    });

    it('rejects non-existent token', async () => {
      expect(await db.isRefreshTokenValid('nonexistent-token')).toBe(false);
    });

    it('revokes all tokens for a user', async () => {
      await db.storeRefreshToken('tok-a', 'testuser1', futureDate);
      await db.storeRefreshToken('tok-b', 'testuser1', futureDate);
      await db.revokeAllUserTokens('testuser1');
      expect(await db.isRefreshTokenValid('tok-a')).toBe(false);
      expect(await db.isRefreshTokenValid('tok-b')).toBe(false);
    });
  });

  describe('MFA', () => {
    it('stores and retrieves MFA secret', async () => {
      await db.storeMFASecret('testuser1', 'JBSWY3DPEHPK3PXP');
      const mfa = await db.getMFASecret('testuser1');
      expect(mfa).not.toBeNull();
      expect(mfa.secret).toBe('JBSWY3DPEHPK3PXP');
      expect(Number(mfa.enabled)).toBe(1);
    });

    it('stores and retrieves MFA challenge', async () => {
      const challengeId = 'test-challenge-123';
      const expiresAt = new Date(Date.now() + 300000).toISOString();
      await db.storeMFAChallenge(challengeId, 'testuser1', { riskScore: 0.4 }, expiresAt);
      const challenge = await db.getMFAChallenge(challengeId);
      expect(challenge).not.toBeNull();
      expect(challenge.user_id).toBe('testuser1');
      expect(challenge.context.riskScore).toBe(0.4);
    });

    it('deletes MFA challenge', async () => {
      await db.deleteMFAChallenge('test-challenge-123');
      expect(await db.getMFAChallenge('test-challenge-123')).toBeNull();
    });
  });

  describe('OAuth', () => {
    it('stores and retrieves OAuth client', async () => {
      await db.storeOAuthClient('test-client', 'secret123', ['http://localhost/cb'], ['authorization_code'], 'openid');
      const client = await db.getOAuthClient('test-client');
      expect(client).not.toBeNull();
      expect(client.clientId).toBe('test-client');
      expect(client.redirectUris).toContain('http://localhost/cb');
    });

    it('stores and consumes OAuth code', async () => {
      const expiresAt = new Date(Date.now() + 300000).toISOString();
      await db.storeOAuthCode('auth-code-1', 'testuser1', 'test-client', 'http://localhost/cb', 'openid', 'nonce1', expiresAt);
      const code = await db.consumeOAuthCode('auth-code-1');
      expect(code).not.toBeNull();
      expect(code.user_id).toBe('testuser1');
      const second = await db.consumeOAuthCode('auth-code-1');
      expect(second).toBeNull();
    });
  });

  describe('DIDs', () => {
    it('stores and retrieves a DID document', async () => {
      await db.storeDID('did:fabric:iam:testuser1', 'testuser1', { id: 'did:fabric:iam:testuser1', controller: 'testuser1' }, 'pem-key');
      const did = await db.getDID('did:fabric:iam:testuser1');
      expect(did).not.toBeNull();
      expect(did.document.id).toBe('did:fabric:iam:testuser1');
    });

    it('deactivates a DID', async () => {
      await db.deactivateDID('did:fabric:iam:testuser1');
      const did = await db.getDID('did:fabric:iam:testuser1');
      expect(did.deactivated).toBe(true);
    });
  });

  describe('login history', () => {
    it('records and retrieves login history', async () => {
      await db.recordLoginHistory('testuser1', 'dev-t1', 'IN', 'Gwalior', '2026-04-02T10:00:00Z', 0.2, 'ALLOW');
      const history = await db.getLoginHistory('testuser1', 10);
      expect(history.length).toBeGreaterThan(0);
      expect(history[0].user_id).toBe('testuser1');
    });
  });

  describe('signing keys', () => {
    it('stores and retrieves active signing key', async () => {
      await db.storeSigningKey('jwt-key-1', 'jwt', 'private-secret', null, 'HS256');
      const key = await db.getActiveSigningKey('jwt');
      expect(key).not.toBeNull();
      expect(key.private_key).toBe('private-secret');
    });

    it('rotates signing keys', async () => {
      await db.rotateSigningKey('jwt');
      await db.storeSigningKey('jwt-key-2', 'jwt', 'new-secret', null, 'HS256');
      const key = await db.getActiveSigningKey('jwt');
      expect(key.key_id).toBe('jwt-key-2');
    });
  });

  describe('audit log', () => {
    it('writes and queries audit log', async () => {
      await db.writeAuditLog({ txId: 'tx-1', userId: 'testuser1', deviceId: 'dev-t1', riskScore: 0.2, decision: 'ALLOW', reason: 'OK', layer: 'test' });
      await db.writeAuditLog({ txId: 'tx-2', userId: 'testuser1', deviceId: 'dev-t1', riskScore: 0.8, decision: 'DENY', reason: 'Too risky', layer: 'test' });
      const logs = await db.queryAuditLog({ userId: 'testuser1' });
      expect(logs.length).toBeGreaterThanOrEqual(2);
    });

    it('filters by decision', async () => {
      const denies = await db.queryAuditLog({ userId: 'testuser1', decision: 'DENY' });
      expect(denies.every(l => l.decision === 'DENY')).toBe(true);
    });
  });

  describe('seedDemoData', () => {
    it('seeds alice and bob', async () => {
      await db.seedDemoData();
      const alice = await db.getUser('alice');
      const bob = await db.getUser('bob');
      expect(alice).not.toBeNull();
      expect(alice.role).toBe('admin');
      expect(bob).not.toBeNull();
      expect(bob.role).toBe('viewer');
    });
  });

  describe('cleanup', () => {
    it('runs cleanup jobs without error', async () => {
      const result = await db.runCleanupJobs();
      expect(result).toHaveProperty('tokens');
      expect(result).toHaveProperty('codes');
      expect(result).toHaveProperty('challenges');
    });
  });
});
