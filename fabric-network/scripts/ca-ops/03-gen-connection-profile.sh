#!/usr/bin/env bash
# Generate a multi-org connection profile JSON for policy-engine Fabric Gateway.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="${ROOT}/fabric-network/connection-profile-prod.json"
ORG1_PEER="${ORG1_PEER_ENDPOINT:-peer0.org1.example.com:7051}"
ORG2_PEER="${ORG2_PEER_ENDPOINT:-peer0.org2.example.com:9051}"
CHANNEL="${FABRIC_CHANNEL:-iamchannel}"
CC="${FABRIC_CHAINCODE:-iam-cc}"

cat > "$OUT" <<EOF
{
  "name": "ztiam-prod",
  "version": "1.0.0",
  "client": {
    "organization": "Org1",
    "connection": { "timeout": { "peer": { "endorser": "10s" } } }
  },
  "organizations": {
    "Org1": {
      "mspid": "Org1MSP",
      "peers": ["peer0.org1.example.com"],
      "certificateAuthorities": ["ca.org1.example.com"]
    },
    "Org2": {
      "mspid": "Org2MSP",
      "peers": ["peer0.org2.example.com"],
      "certificateAuthorities": ["ca.org2.example.com"]
    }
  },
  "peers": {
    "peer0.org1.example.com": {
      "url": "grpcs://${ORG1_PEER}",
      "tlsCACerts": { "path": "organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem" },
      "grpcOptions": { "ssl-target-name-override": "peer0.org1.example.com" }
    },
    "peer0.org2.example.com": {
      "url": "grpcs://${ORG2_PEER}",
      "tlsCACerts": { "path": "organizations/peerOrganizations/org2.example.com/tlsca/tlsca.org2.example.com-cert.pem" },
      "grpcOptions": { "ssl-target-name-override": "peer0.org2.example.com" }
    }
  },
  "certificateAuthorities": {
    "ca.org1.example.com": {
      "url": "${ORG1_CA_HTTP:-https://localhost:7054}",
      "caName": "ca-org1",
      "tlsCACerts": { "path": "organizations/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem" },
      "httpOptions": { "verify": true }
    },
    "ca.org2.example.com": {
      "url": "${ORG2_CA_HTTP:-https://localhost:8054}",
      "caName": "ca-org2",
      "tlsCACerts": { "path": "organizations/peerOrganizations/org2.example.com/ca/ca.org2.example.com-cert.pem" },
      "httpOptions": { "verify": true }
    }
  },
  "channels": {
    "${CHANNEL}": {
      "peers": {
        "peer0.org1.example.com": { "endorsingPeer": true, "chaincodeQuery": true, "ledgerQuery": true, "eventSource": true },
        "peer0.org2.example.com": { "endorsingPeer": true, "chaincodeQuery": true, "ledgerQuery": true, "eventSource": true }
      }
    }
  },
  "ztiam": {
    "channel": "${CHANNEL}",
    "chaincode": "${CC}",
    "endorsementPolicy": "AND('Org1MSP.peer','Org2MSP.peer')",
    "gatewayIdentityMsp": "organizations/peerOrganizations/org1.example.com/users/policy-engine@org1.example.com/msp"
  }
}
EOF

echo "Wrote ${OUT}"
echo "Point FABRIC_CONNECTION_PROFILE to this file in production."
