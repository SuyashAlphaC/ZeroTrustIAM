#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$(dirname "${SCRIPT_DIR}")"
cd "${NETWORK_DIR}"
docker compose -f docker-compose.yaml down -v
rm -rf organizations channel-artifacts system-genesis-block
