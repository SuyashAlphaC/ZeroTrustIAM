// Jest settings for chaincode unit tests (BigInt + in-memory Fabric stub).
'use strict';

process.env.CHAINCODE_UNIT_TEST = '1';

module.exports = {
  testEnvironment: 'node',
  testTimeout: 120_000,
  setupFilesAfterEnv: ['<rootDir>/tests/setup.js'],
  testMatch: ['**/tests/**/*.test.js'],
  collectCoverageFrom: ['lib/iamContract.js'],
  coveragePathIgnorePatterns: ['/node_modules/'],
  coverageThreshold: {
    'lib/iamContract.js': {
      lines: 75,
      functions: 75,
      branches: 65,
    },
  },
};
