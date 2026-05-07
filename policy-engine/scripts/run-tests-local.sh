#!/bin/bash
# Local helper to run policy-engine tests with the standard env vars expected
# by the harness. Mirrors the command in the project README/CLAUDE.md.
set -euo pipefail
export NODE_ENV=test
export FABRIC_TEST_MODE=true
export JWT_SECRET=test-jwt-secret-minimum-32chars-xx
export JWT_REFRESH_SECRET=test-refresh-secret-minimum32chxx
export OAUTH_DEFAULT_CLIENT_SECRET=test-client-secret
export ML_SERVICE_ENABLED=false
export TEST_DATABASE_URL=${TEST_DATABASE_URL:-postgresql://ztiam:testpassword@localhost:5433/ztiam_test}
cd "$(dirname "$0")/.."
exec npm test "$@"
