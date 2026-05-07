#!/usr/bin/env bash
set -euo pipefail
# POST /evaluate through policy-engine (mTLS paths optional) to sanity-check Fabric after chaos drills.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PE="${PE_URL:-http://localhost:4000}"
CA="${FABRIC_SUBMIT_CA:-${REPO_ROOT}/certs/internal/ca.pem}"
CERT="${FABRIC_SUBMIT_CERT:-${REPO_ROOT}/certs/internal/client.pem}"
KEY="${FABRIC_SUBMIT_KEY:-${REPO_ROOT}/certs/internal/client-key.pem}"

body='{"username":"alice","password":"pass123","deviceId":"dev-001","timestamp":"2026-05-01T08:00:00Z","location":{"country":"IN","city":"Gwalior"}}'

curl_opts=(-sS -o /tmp/pe-eval.json -w "%{http_code}" -X POST "${PE}/evaluate" -H "Content-Type: application/json" -d "${body}")
if [[ -f "${CERT}" && -f "${KEY}" && -f "${CA}" ]]; then
  code="$(curl "${curl_opts[@]}" --cacert "${CA}" --cert "${CERT}" --key "${KEY}")"
else
  code="$(curl "${curl_opts[@]}")"
fi

echo "policy-engine POST /evaluate HTTP ${code}"

if grep -Eq '"decision"|"DENY"|"ALLOW"' /tmp/pe-eval.json; then echo "CHAINCODE RESPONSE OK"; else cat /tmp/pe-eval.json; exit 2; fi
