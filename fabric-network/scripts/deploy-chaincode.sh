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

PEER_TLS_CA="/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
ORDERER_CA="/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

echo "============================================"
echo "  Deploying IAM Chaincode (CCaaS)"
echo "============================================"
echo ""

# Step 1: Create the CCaaS chaincode package
echo "[1/7] Creating CCaaS chaincode package..."

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
echo "[2/7] Copying package to CLI container..."
docker cp "${NETWORK_DIR}/${CC_NAME}.tar.gz" cli:/opt/gopath/src/github.com/hyperledger/fabric/peer/${CC_NAME}.tar.gz
echo "  Package copied."

# Step 3: Install chaincode on peer
echo "[3/7] Installing chaincode on peer..."
docker exec cli peer lifecycle chaincode install ${CC_NAME}.tar.gz
echo "  Chaincode installed."

# Step 4: Get package ID
echo "[4/7] Querying installed chaincode..."
PACKAGE_ID=$(docker exec cli peer lifecycle chaincode queryinstalled --output json | \
  python3 -c "import sys,json; refs=json.load(sys.stdin).get('installed_chaincodes',[]); print(refs[0]['package_id'] if refs else '')")

if [ -z "$PACKAGE_ID" ]; then
  echo "  ERROR: Could not find installed chaincode package ID"
  exit 1
fi
echo "  Package ID: ${PACKAGE_ID}"

# Step 5: Restart chaincode container with the correct CHAINCODE_ID
echo "[5/7] Starting chaincode container with correct ID..."
cd "${NETWORK_DIR}"
docker compose stop iam-chaincode 2>/dev/null || true
docker compose rm -f iam-chaincode 2>/dev/null || true

export CHAINCODE_CCID="${PACKAGE_ID}"
docker compose up -d iam-chaincode

echo "  Waiting for chaincode container to start..."
sleep 5

# Verify chaincode container is running
echo "  Chaincode container logs:"
docker logs iam-chaincode 2>&1 | tail -5

# Step 6: Approve chaincode for Org1
echo "[6/7] Approving chaincode for Org1..."
docker exec cli peer lifecycle chaincode approveformyorg \
  --channelID "${CHANNEL_NAME}" \
  --name "${CC_NAME}" \
  --version "${CC_VERSION}" \
  --package-id "${PACKAGE_ID}" \
  --sequence ${CC_SEQUENCE} \
  --tls \
  --cafile "${ORDERER_CA}" \
  -o orderer.example.com:7050
echo "  Chaincode approved."

# Step 7: Commit chaincode
echo "[7/7] Committing chaincode..."
docker exec cli peer lifecycle chaincode commit \
  --channelID "${CHANNEL_NAME}" \
  --name "${CC_NAME}" \
  --version "${CC_VERSION}" \
  --sequence ${CC_SEQUENCE} \
  --tls \
  --cafile "${ORDERER_CA}" \
  -o orderer.example.com:7050 \
  --peerAddresses peer0.org1.example.com:7051 \
  --tlsRootCertFiles "${PEER_TLS_CA}"
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
  --tlsRootCertFiles "${PEER_TLS_CA}" \
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
