#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NETWORK_DIR="$(dirname "$SCRIPT_DIR")"

echo "Tearing down Fabric network..."
cd "${NETWORK_DIR}"

# Stop and remove containers + volumes
docker compose down -v 2>/dev/null || true

# Remove generated crypto material and channel artifacts
rm -rf organizations
rm -f channel-artifacts/*.block

# Remove any chaincode Docker containers and images
docker ps -a --filter "name=dev-peer" -q 2>/dev/null | xargs -r docker rm -f
docker images --filter "reference=dev-peer*" -q 2>/dev/null | xargs -r docker rmi -f

echo "Fabric network torn down."
