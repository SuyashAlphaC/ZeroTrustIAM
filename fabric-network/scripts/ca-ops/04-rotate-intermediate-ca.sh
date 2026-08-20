#!/usr/bin/env bash
# Documented rotation steps for intermediate CA material.
# Full automation depends on your CA DB backend; this script enforces a safe checklist.
set -euo pipefail
ORG="${1:-org1}"
echo "=== Intermediate CA rotation checklist for ${ORG} ==="
echo "1. Generate new intermediate CA cert signed by root CA (offline ceremony recommended)."
echo "2. fabric-ca-server reconfigure with new intermediate key/cert; rolling restart."
echo "3. Re-enroll all peers/orderers/users under the new intermediate (02-enroll-peers-and-users.sh)."
echo "4. Update channel config MSP root certs if intermediate was added to org MSP."
echo "5. Redeploy policy-engine connection profile (03-gen-connection-profile.sh)."
echo "6. Revoke old intermediate if compromised; distribute CRL to peers."
echo "7. Run chaos-orderer-kill.sh + submit-test-tx.sh to validate Raft + CC."
echo ""
echo "Dry-run complete — perform steps with change ticket and dual control."
