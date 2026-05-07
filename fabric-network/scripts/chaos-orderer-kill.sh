#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$(dirname "${SCRIPT_DIR}")"

echo "Killing primary orderer (orderer.example.com) — Raft must keep serving via orderer2/orderer3"
docker stop orderer.example.com
sleep 10
"${SCRIPT_DIR}/submit-test-tx.sh"
docker start orderer.example.com
sleep 15
"${SCRIPT_DIR}/submit-test-tx.sh"
echo "Chaos drill complete."
