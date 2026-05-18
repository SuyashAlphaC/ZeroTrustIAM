// Jest setupFiles entry. Runs BEFORE each test file's top-level code so that
// `process.env.TEST_DATABASE_URL` (and other secrets used by the harness) is
// populated from .env when the shell has not exported them explicitly. This
// lets `npm test` work locally without requiring shell-side env-var prefixing.
'use strict';
const path = require('path');
try {
  // eslint-disable-next-line global-require
  require('dotenv').config({ path: path.resolve(__dirname, '.env') });
} catch (_) {
  // dotenv is a regular dep — if missing, just skip (CI sets env directly).
}
