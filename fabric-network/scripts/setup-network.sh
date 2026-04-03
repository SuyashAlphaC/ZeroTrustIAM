#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NETWORK_DIR="$(dirname "$SCRIPT_DIR")"
BIN_DIR="${NETWORK_DIR}/bin"
export PATH="${BIN_DIR}:${PATH}"
export FABRIC_CFG_PATH="${NETWORK_DIR}"

echo "============================================"
echo "  Zero Trust IAM - Fabric Network Setup"
echo "============================================"
echo ""

# Step 1: Clean up any previous state
echo "[1/6] Cleaning up previous state..."
cd "${NETWORK_DIR}"
docker compose down -v 2>/dev/null || true
rm -rf organizations channel-artifacts/*.block

# Step 2: Generate crypto material
echo "[2/6] Generating crypto material..."
cryptogen generate --config=crypto-config-orderer.yaml --output=organizations
cryptogen generate --config=crypto-config-org1.yaml --output=organizations
echo "  Crypto material generated."

# Step 3: Generate genesis block for channel
echo "[3/6] Generating channel genesis block..."
mkdir -p channel-artifacts
configtxgen -profile IAMChannel -outputBlock ./channel-artifacts/iamchannel.block -channelID iamchannel
echo "  Genesis block created."

# Step 4: Start Docker containers
echo "[4/6] Starting Docker containers..."
docker compose up -d
echo "  Waiting for containers to start..."
sleep 5

# Verify containers
echo "  Container status:"
docker ps --filter "label=service=hyperledger-fabric" --format "  {{.Names}}: {{.Status}}"

# Step 5: Join orderer to channel
echo "[5/6] Joining orderer to channel..."
ORDERER_CA="${NETWORK_DIR}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
ORDERER_ADMIN_TLS="${NETWORK_DIR}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/tls"

osnadmin channel join \
  --channelID iamchannel \
  --config-block ./channel-artifacts/iamchannel.block \
  -o localhost:7053 \
  --ca-file "${ORDERER_CA}" \
  --client-cert "${ORDERER_ADMIN_TLS}/server.crt" \
  --client-key "${ORDERER_ADMIN_TLS}/server.key"
echo "  Orderer joined channel."

# Step 6: Join peer to channel
echo "[6/6] Joining peer to channel..."
PEER_TLS_CA="${NETWORK_DIR}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"

docker exec cli peer channel join \
  -b /opt/gopath/src/github.com/hyperledger/fabric/peer/channel-artifacts/iamchannel.block

echo "  Peer joined channel."

# Verify channel
echo ""
echo "  Verifying channel membership..."
docker exec cli peer channel list

echo ""
echo "============================================"
echo "  Fabric network is UP and RUNNING!"
echo "  Channel: iamchannel"
echo "============================================"
