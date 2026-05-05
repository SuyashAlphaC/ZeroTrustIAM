#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NETWORK_DIR="$(dirname "$SCRIPT_DIR")"
BIN_DIR="${NETWORK_DIR}/bin"
export PATH="${BIN_DIR}:${PATH}"

CHANNEL_NAME="iamchannel"
CC_NAME="iam-cc"
CC_VERSION="1.0"
CC_SEQUENCE=1

PEER1_TLS_CA="/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
PEER2_TLS_CA="/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
ORDERER_CA="/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

ORG2_PEER_BASE="/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls"
ORG2_ADMIN_MSP="/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp"

SIGNATURE_POLICY="AND('Org1MSP.peer','Org2MSP.peer')"

echo "============================================"
echo "  Deploying IAM Chaincode (CCaaS)"
echo "============================================"
echo ""

# Step 1: Create the CCaaS chaincode package
echo "[1/9] Creating CCaaS chaincode package..."

CCAAS_PKG_DIR=$(mktemp -d)

# connection.json tells the peer where to find the running chaincode
cat > "${CCAAS_PKG_DIR}/connection.json" <<EOF
{
  "address": "iam-chaincode:9999",
  "dial_timeout": "10s",
  "tls_required": false
}
EOF

# metadata.json identifies the chaincode type
cat > "${CCAAS_PKG_DIR}/metadata.json" <<EOF
{
  "type": "ccaas",
  "label": "${CC_NAME}_${CC_VERSION}"
}
EOF

# Create the code.tar.gz (just connection.json)
tar -czf "${CCAAS_PKG_DIR}/code.tar.gz" -C "${CCAAS_PKG_DIR}" connection.json

# Create the final package
tar -czf "${NETWORK_DIR}/${CC_NAME}.tar.gz" -C "${CCAAS_PKG_DIR}" code.tar.gz metadata.json

rm -rf "${CCAAS_PKG_DIR}"
echo "  CCaaS package created."

# Step 2: Copy package to CLI container
echo "[2/9] Copying package to CLI container..."
docker cp "${NETWORK_DIR}/${CC_NAME}.tar.gz" cli:/opt/gopath/src/github.com/hyperledger/fabric/peer/${CC_NAME}.tar.gz
echo "  Package copied."

# Step 3: Install chaincode on Org1 peer
echo "[3/9] Installing chaincode on peer0.org1..."
docker exec cli peer lifecycle chaincode install ${CC_NAME}.tar.gz
echo "  Installed on Org1 peer."

# Step 4: Install chaincode on Org2 peer
echo "[4/9] Installing chaincode on peer0.org2..."
docker exec \
  -e CORE_PEER_LOCALMSPID=Org2MSP \
  -e CORE_PEER_ADDRESS=peer0.org2.example.com:7051 \
  -e CORE_PEER_TLS_CERT_FILE="${ORG2_PEER_BASE}/server.crt" \
  -e CORE_PEER_TLS_KEY_FILE="${ORG2_PEER_BASE}/server.key" \
  -e CORE_PEER_TLS_ROOTCERT_FILE="${ORG2_PEER_BASE}/ca.crt" \
  -e CORE_PEER_MSPCONFIGPATH="${ORG2_ADMIN_MSP}" \
  cli peer lifecycle chaincode install ${CC_NAME}.tar.gz
echo "  Installed on Org2 peer."

# Step 5: Get package ID
echo "[5/9] Querying installed chaincode..."
PACKAGE_ID=$(docker exec cli peer lifecycle chaincode queryinstalled --output json | \
  python3 -c "import sys,json; refs=json.load(sys.stdin).get('installed_chaincodes',[]); matching=[x for x in refs if '${CC_NAME}_${CC_VERSION}' in x.get('label','')]; print(matching[0]['package_id'] if matching else (refs[0]['package_id'] if refs else ''))")

if [ -z "$PACKAGE_ID" ]; then
  echo "  ERROR: Could not find installed chaincode package ID"
  exit 1
fi
echo "  Package ID: ${PACKAGE_ID}"

# Step 6: Restart chaincode container with the correct CHAINCODE_ID
echo "[6/9] Starting chaincode container with correct ID..."
cd "${NETWORK_DIR}"
docker compose stop iam-chaincode 2>/dev/null || true
docker compose rm -f iam-chaincode 2>/dev/null || true

export CHAINCODE_CCID="${PACKAGE_ID}"
docker compose up -d iam-chaincode

echo "  Waiting for chaincode container to start..."
sleep 5

echo "  Chaincode container logs:"
docker logs iam-chaincode 2>&1 | tail -5

# Step 7: Approve chaincode for Org1
echo "[7/9] Approving chaincode for Org1..."
docker exec cli peer lifecycle chaincode approveformyorg \
  --channelID "${CHANNEL_NAME}" \
  --name "${CC_NAME}" \
  --version "${CC_VERSION}" \
  --package-id "${PACKAGE_ID}" \
  --sequence ${CC_SEQUENCE} \
  --signature-policy "${SIGNATURE_POLICY}" \
  --tls \
  --cafile "${ORDERER_CA}" \
  -o orderer.example.com:7050
echo "  Org1 approved."

# Step 8: Approve chaincode for Org2
echo "[8/9] Approving chaincode for Org2..."
docker exec \
  -e CORE_PEER_LOCALMSPID=Org2MSP \
  -e CORE_PEER_ADDRESS=peer0.org2.example.com:7051 \
  -e CORE_PEER_TLS_CERT_FILE="${ORG2_PEER_BASE}/server.crt" \
  -e CORE_PEER_TLS_KEY_FILE="${ORG2_PEER_BASE}/server.key" \
  -e CORE_PEER_TLS_ROOTCERT_FILE="${ORG2_PEER_BASE}/ca.crt" \
  -e CORE_PEER_MSPCONFIGPATH="${ORG2_ADMIN_MSP}" \
  cli peer lifecycle chaincode approveformyorg \
  --channelID "${CHANNEL_NAME}" \
  --name "${CC_NAME}" \
  --version "${CC_VERSION}" \
  --package-id "${PACKAGE_ID}" \
  --sequence ${CC_SEQUENCE} \
  --signature-policy "${SIGNATURE_POLICY}" \
  --tls \
  --cafile "${ORDERER_CA}" \
  -o orderer.example.com:7050
echo "  Org2 approved."

# Step 9: Commit chaincode
echo "[9/9] Committing chaincode..."
docker exec cli peer lifecycle chaincode commit \
  --channelID "${CHANNEL_NAME}" \
  --name "${CC_NAME}" \
  --version "${CC_VERSION}" \
  --sequence ${CC_SEQUENCE} \
  --signature-policy "${SIGNATURE_POLICY}" \
  --tls \
  --cafile "${ORDERER_CA}" \
  -o orderer.example.com:7050 \
  --peerAddresses peer0.org1.example.com:7051 \
  --peerAddresses peer0.org2.example.com:7051 \
  --tlsRootCertFiles "${PEER1_TLS_CA}" \
  --tlsRootCertFiles "${PEER2_TLS_CA}"
echo "  Chaincode committed."

# Verify deployment
echo ""
echo "  Verifying deployment..."
docker exec cli peer lifecycle chaincode querycommitted \
  --channelID "${CHANNEL_NAME}" \
  --name "${CC_NAME}" \
  --tls \
  --cafile "${ORDERER_CA}"

# Initialize ledger
echo ""
echo "  Initializing ledger with seed data..."
sleep 3
docker exec cli peer chaincode invoke \
  -o orderer.example.com:7050 \
  --tls \
  --cafile "${ORDERER_CA}" \
  -C "${CHANNEL_NAME}" \
  -n "${CC_NAME}" \
  --peerAddresses peer0.org1.example.com:7051 \
  --peerAddresses peer0.org2.example.com:7051 \
  --tlsRootCertFiles "${PEER1_TLS_CA}" \
  --tlsRootCertFiles "${PEER2_TLS_CA}" \
  -c '{"function":"InitLedger","Args":[]}'

sleep 2

# Test query
echo ""
echo "  Testing: GetUser(alice)..."
docker exec cli peer chaincode query \
  -C "${CHANNEL_NAME}" \
  -n "${CC_NAME}" \
  -c '{"function":"GetUser","Args":["alice"]}'

echo ""
echo "============================================"
echo "  Chaincode deployed and initialized!"
echo "============================================"
