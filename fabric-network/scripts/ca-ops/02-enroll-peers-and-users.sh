#!/usr/bin/env bash
# Register + enroll peer0 and application user for Org1/Org2.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="${ROOT}/fabric-network/bin"
export PATH="${BIN}:${PATH}"
CA_HOME="${FABRIC_CA_CLIENT_HOME:-${ROOT}/fabric-network/organizations/ca-client}"

register_enroll() {
  local org="$1" ca_url="$2" caname="$3" id="$4" type="$5" secret="$6" msp_out="$7"
  export FABRIC_CA_CLIENT_HOME="${CA_HOME}/${org}"
  echo "==> Register ${id} (${type}) in ${org}"
  fabric-ca-client register \
    --caname "${caname}" \
    --id.name "${id}" \
    --id.secret "${secret}" \
    --id.type "${type}" \
    -u "${ca_url}" || true
  echo "==> Enroll ${id}"
  mkdir -p "${msp_out}"
  fabric-ca-client enroll \
    -u "https://${id}:${secret}@${ca_url#https://}" \
    --caname "${caname}" \
    -M "${msp_out}"
}

ORG1_CA="${ORG1_CA_URL:-https://admin:adminpw@localhost:7054}"
ORG2_CA="${ORG2_CA_URL:-https://admin:adminpw@localhost:8054}"
PEER_SECRET="${PEER_ENROLL_SECRET:-peer1pw}"
USER_SECRET="${USER_ENROLL_SECRET:-user1pw}"

register_enroll org1 "$ORG1_CA" ca-org1 peer0 peer "$PEER_SECRET" \
  "${ROOT}/fabric-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp"
register_enroll org1 "$ORG1_CA" ca-org1 user1 client "$USER_SECRET" \
  "${ROOT}/fabric-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp"

register_enroll org2 "$ORG2_CA" ca-org2 peer0 peer "$PEER_SECRET" \
  "${ROOT}/fabric-network/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/msp"
register_enroll org2 "$ORG2_CA" ca-org2 user1 client "$USER_SECRET" \
  "${ROOT}/fabric-network/organizations/peerOrganizations/org2.example.com/users/User1@org2.example.com/msp"

# Policy-engine gateway identity (client)
register_enroll org1 "$ORG1_CA" ca-org1 policy-engine client "${POLICY_ENGINE_SECRET:-pe1pw}" \
  "${ROOT}/fabric-network/organizations/peerOrganizations/org1.example.com/users/policy-engine@org1.example.com/msp"

echo "Enrollments complete."
