#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NETWORK_DIR="$(dirname "$SCRIPT_DIR")"
BIN_DIR="${NETWORK_DIR}/bin"
export PATH="${BIN_DIR}:${PATH}"
if ! command -v cryptogen >/dev/null 2>&1; then
  echo "FATAL: cryptogen not in PATH. Install Hyperledger Fabric binaries first." >&2
  exit 1
fi
export FABRIC_CFG_PATH="${NETWORK_DIR}"

echo "============================================"
echo "  Zero Trust IAM - Fabric Network Setup"
echo "============================================"
echo ""

# Step 1: Clean up volatile state while preserving MSP material when org2 already bootstrapped
echo "[1/7] Cleaning up previous state..."
cd "${NETWORK_DIR}"
ORG2MSP="${NETWORK_DIR}/organizations/peerOrganizations/org2.example.com"
EXISTING_CRYPTO=0
[[ -d "${ORG2MSP}" ]] && EXISTING_CRYPTO=1
docker compose down -v 2>/dev/null || true
if [[ "${EXISTING_CRYPTO}" -eq 0 ]]; then
  rm -rf organizations channel-artifacts/*.block
else
  mkdir -p channel-artifacts
  echo "  Existing crypto under organizations/ retained (Org2 MSP present)."
fi

# Step 2: Generate crypto material when missing
echo "[2/7] Generating crypto material..."
if [[ "${EXISTING_CRYPTO}" -eq 0 ]]; then
  cryptogen generate --config=crypto-config-orderer.yaml --output=organizations
  cryptogen generate --config=crypto-config-org1.yaml --output=organizations
  cryptogen generate --config=crypto-config-org2.yaml --output=organizations
  echo "  Crypto material generated."
else
  echo "  Skipping cryptogen (organizations/ already populated)."
fi

# Step 3: Generate genesis block for channel
echo "[3/7] Generating channel genesis block..."
mkdir -p channel-artifacts
configtxgen -profile IAMChannel -outputBlock ./channel-artifacts/iamchannel.block -channelID iamchannel
echo "  Genesis block created."

# Step 4: Start Docker containers
echo "[4/7] Starting Docker containers..."
docker compose up -d
echo "  Waiting for containers to start..."
sleep 5

# Verify containers
echo "  Container status:"
docker ps --filter "label=service=hyperledger-fabric" --format "  {{.Names}}: {{.Status}}"

# Step 5: Join each Raft orderer to channel (channel participation API)
echo "[5/7] Joining orderers to channel..."
ORDERER_TLSCA="${NETWORK_DIR}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"

orderer_join() {
  local admin_port="$1"
  local admin_tls_dir="$2"
  osnadmin channel join \
    --channelID iamchannel \
    --config-block ./channel-artifacts/iamchannel.block \
    -o "localhost:${admin_port}" \
    --ca-file "${ORDERER_TLSCA}" \
    --client-cert "${admin_tls_dir}/server.crt" \
    --client-key "${admin_tls_dir}/server.key"
}

orderer_join 7053 "${NETWORK_DIR}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls"
orderer_join 8053 "${NETWORK_DIR}/organizations/ordererOrganizations/example.com/orderers/orderer2.example.com/tls"
orderer_join 9053 "${NETWORK_DIR}/organizations/ordererOrganizations/example.com/orderers/orderer3.example.com/tls"
echo "  Orderers joined channel."

# Step 6: Join peers to channel
echo "[6/7] Joining peers to channel..."
PEER1_BLOCK="/opt/gopath/src/github.com/hyperledger/fabric/peer/channel-artifacts/iamchannel.block"

docker exec cli peer channel join -b "${PEER1_BLOCK}"

ORG2_PEER_BASE="/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls"
ORG2_ADMIN_MSP="/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp"

docker exec \
  -e CORE_PEER_LOCALMSPID=Org2MSP \
  -e CORE_PEER_ADDRESS=peer0.org2.example.com:7051 \
  -e CORE_PEER_TLS_CERT_FILE="${ORG2_PEER_BASE}/server.crt" \
  -e CORE_PEER_TLS_KEY_FILE="${ORG2_PEER_BASE}/server.key" \
  -e CORE_PEER_TLS_ROOTCERT_FILE="${ORG2_PEER_BASE}/ca.crt" \
  -e CORE_PEER_MSPCONFIGPATH="${ORG2_ADMIN_MSP}" \
  cli peer channel join -b "${PEER1_BLOCK}"

echo "  Peers joined channel."

# Verify channel
echo ""
echo "  Verifying channel membership (Org1)..."
docker exec cli peer channel list

echo ""
echo "  Verifying channel membership (Org2)..."
docker exec \
  -e CORE_PEER_LOCALMSPID=Org2MSP \
  -e CORE_PEER_ADDRESS=peer0.org2.example.com:7051 \
  -e CORE_PEER_TLS_CERT_FILE="${ORG2_PEER_BASE}/server.crt" \
  -e CORE_PEER_TLS_KEY_FILE="${ORG2_PEER_BASE}/server.key" \
  -e CORE_PEER_TLS_ROOTCERT_FILE="${ORG2_PEER_BASE}/ca.crt" \
  -e CORE_PEER_MSPCONFIGPATH="${ORG2_ADMIN_MSP}" \
  cli peer channel list

echo ""
echo "============================================"
echo "  Fabric network is UP and RUNNING!"
echo "  Channel: iamchannel"
echo "============================================"
