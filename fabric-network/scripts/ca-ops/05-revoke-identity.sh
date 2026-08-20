#!/usr/bin/env bash
# Revoke a Fabric CA identity and generate CRL.
set -euo pipefail
ORG="${1:?org name e.g. org1}"
IDENTITY="${2:?identity name e.g. peer0}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="${ROOT}/fabric-network/bin"
export PATH="${BIN}:${PATH}"
export FABRIC_CA_CLIENT_HOME="${FABRIC_CA_CLIENT_HOME:-${ROOT}/fabric-network/organizations/ca-client}/${ORG}}"

CA_URL="${CA_URL:-https://admin:adminpw@localhost:7054}"
CANAME="${CANAME:-ca-${ORG}}"

echo "Revoking ${IDENTITY} in ${ORG}"
fabric-ca-client revoke \
  -u "${CA_URL}" \
  --caname "${CANAME}" \
  --revoke.name "${IDENTITY}" \
  --revoke.reason "compromise_or_rotation"

echo "Generating CRL"
fabric-ca-client gencrl -u "${CA_URL}" --caname "${CANAME}" || true
echo "Distribute CRL to peers and update MSPs. Restart peers if required by your version."
