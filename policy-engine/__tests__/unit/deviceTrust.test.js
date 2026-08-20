'use strict';

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test-refresh';
process.env.OAUTH_DEFAULT_CLIENT_SECRET = process.env.OAUTH_DEFAULT_CLIENT_SECRET || 'oauth';
process.env.DEVICE_ENROLL_MODE = 'first_only';

const deviceTrust = require('../../deviceTrust');

describe('isValidDeviceCredential', () => {
  test('accepts UUID and legacy seed ids', () => {
    expect(deviceTrust.isValidDeviceCredential('dev-001')).toBe(true);
    expect(deviceTrust.isValidDeviceCredential('a1b2c3d4-e5f6-7890-abcd-ef1234567890')).toBe(true);
  });

  test('rejects empty or short values', () => {
    expect(deviceTrust.isValidDeviceCredential('')).toBe(false);
    expect(deviceTrust.isValidDeviceCredential('ab')).toBe(false);
    expect(deviceTrust.isValidDeviceCredential('../../etc')).toBe(false);
  });
});

describe('isDeviceRegistered', () => {
  test('membership check', () => {
    expect(deviceTrust.isDeviceRegistered({ registeredDevices: ['dev-001'] }, 'dev-001')).toBe(true);
    expect(deviceTrust.isDeviceRegistered({ registeredDevices: ['dev-001'] }, 'other')).toBe(false);
  });
});
