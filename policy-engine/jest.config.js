module.exports = {
  testEnvironment: 'node',
  transformIgnorePatterns: [
    // Transform ESM packages that Jest can't handle natively
    'node_modules/(?!(@scure|@noble|otplib|@otplib|uuid|@simplewebauthn|cbor-x)/)',
  ],
  transform: {
    '^.+\\.[jt]sx?$': ['babel-jest', { presets: [['@babel/preset-env', { targets: { node: 'current' } }]] }],
  },
};
