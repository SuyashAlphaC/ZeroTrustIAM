'use strict';

const federation = require('../../federation');

describe('federation', () => {
  it('lists providers', () => {
    const list = federation.listProviders();
    expect(list.find((p) => p.name === 'google')).toBeDefined();
    expect(list.find((p) => p.name === 'entra')).toBeDefined();
    expect(list.find((p) => p.name === 'okta')).toBeDefined();
  });

  it('throws when provider not configured', () => {
    // Ensure google client id unset for this test
    const prev = process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_ID;
    jest.resetModules();
    const fed = require('../../federation');
    expect(() => fed.startAuth('google')).toThrow(/not configured/);
    if (prev !== undefined) process.env.GOOGLE_CLIENT_ID = prev;
  });
});
