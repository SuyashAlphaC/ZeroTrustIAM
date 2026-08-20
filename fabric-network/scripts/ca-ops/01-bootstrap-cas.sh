#!/usr/bin/env bash
# Bootstrap Fabric CA admins for orderer + Org1 + Org2.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="${ROOT}/fabric-network/bin"
export PATH="${BIN}:${PATH}"
OUT="${FABRIC_CA_CLIENT_HOME:-${ROOT}/fabric-network/organizations/ca-client}"
mkdir -p "$OUT"

enroll_admin() {
  local name="$1" url="$2" caname="$3" mspdir="$4"
  echo "==> Enrolling CA admin for ${name} at ${url}"
  export FABRIC_CA_CLIENT_HOME="${OUT}/${name}"
  mkdir -p "$FABRIC_CA_CLIENT_HOME"
  fabric-ca-client enroll \
    -u "${url}" \
    --caname "${caname}" \
    -M "${mspdir}" \
    --tls.certfiles "${TLS_CA_CERT:-}" 2>/dev/null || \
  fabric-ca-client enroll \
    -u "${url}" \
    --caname "${caname}" \
    -M "${mspdir}"
  echo "    MSP written to ${mspdir}"
}

# Defaults match fabric-network/docker-compose.yaml style lab names.
# Override via env for production.
ORG1_CA_URL="${ORG1_CA_URL:-https://admin:adminpw@localhost:7054}"
ORG2_CA_URL="${ORG2_CA_URL:-https://admin:adminpw@localhost:8054}"
ORDERER_CA_URL="${ORDERER_CA_URL:-https://admin:adminpw@localhost:9054}"

enroll_admin org1 "$ORG1_CA_URL" ca-org1 \
  "${ROOT}/fabric-network/organizations/peerOrganizations/org1.example.com/msp"
enroll_admin org2 "$ORG2_CA_URL" ca-org2 \
  "${ROOT}/fabric-network/organizations/peerOrganizations/org2.example.com/msp"
enroll_admin orderer "$ORDERER_CA_URL" ca-orderer \
  "${ROOT}/fabric-network/organizations/ordererOrganizations/example.com/msp"

echo "Bootstrap complete. Next: 02-enroll-peers-and-users.sh"
