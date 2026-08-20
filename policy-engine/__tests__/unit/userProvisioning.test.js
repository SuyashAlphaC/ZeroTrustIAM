'use strict';

process.env.NODE_ENV = 'test';
process.env.FABRIC_TEST_MODE = 'true';

const blockchain = require('../../fabricClient');

describe('fabric dual-write (test mode ledger)', () => {
  it('creates a user on the mock ledger', async () => {
    const r = await blockchain.createUser({
      userId: 'carol_test',
      role: 'editor',
      devices: ['dev-carol'],
    });
    expect(r.status).toMatch(/created|updated/i);
    expect(r.registeredDevices).toContain('dev-carol');
    const u = await blockchain.getUser('carol_test');
    expect(u.role).toBe('editor');
  });

  it('registers a device and allows evaluate', async () => {
    await blockchain.createUser({
      userId: 'dave_test',
      role: 'viewer',
      devices: [],
    });
    const reg = await blockchain.registerDevice('dave_test', 'dev-dave-1');
    expect(reg.status).toMatch(/registered/i);

    const access = await blockchain.evaluateAccess(
      'dave_test',
      'dev-dave-1',
      0.1,
      'read',
      {}
    );
    expect(access.decision).toBe('ALLOW');
  });

  it('denies unregistered device for new user', async () => {
    await blockchain.createUser({
      userId: 'erin_test',
      role: 'viewer',
      devices: ['dev-erin-ok'],
    });
    const access = await blockchain.evaluateAccess(
      'erin_test',
      'dev-erin-bad',
      0.1,
      'read',
      {}
    );
    expect(access.decision).toBe('DENY');
    expect(access.reason).toMatch(/unregistered/i);
  });
});
