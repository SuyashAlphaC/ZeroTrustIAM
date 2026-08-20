#!/usr/bin/env bash
# End-to-end smoke test for live ZeroTrustIAM stack.
# Asserts: containers up, health endpoints OK, Fabric live, chaincode reachable,
# ALLOW/DENY/STEP_UP decisions flow end-to-end, audit chain valid.
set -uo pipefail

PASS=0
FAIL=0
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; NC='\033[0m'

check() {
  local name="$1"; local cmd="$2"; local expected="$3"
  local out
  out=$(eval "$cmd" 2>&1)
  if echo "$out" | grep -qE "$expected"; then
    echo -e "${GRN}✓${NC} $name"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}✗${NC} $name"
    echo "  cmd: $cmd"
    echo "  expected: $expected"
    echo "  got: $(echo "$out" | head -2)"
    FAIL=$((FAIL + 1))
  fi
}

echo "=== ZeroTrustIAM smoke test ==="
echo ""

echo "--- 1. Containers ---"
for c in ztiam-web-app ztiam-policy-engine ztiam-ml-service ztiam-postgres \
         orderer.example.com orderer2.example.com orderer3.example.com \
         peer0.org1.example.com peer0.org2.example.com iam-chaincode; do
  check "$c running" "docker ps --format '{{.Names}}' | grep -w $c" "^$c$"
done

echo ""
echo "--- 2. Health endpoints ---"
check "web-app /health"        "curl -s http://127.0.0.1:3000/health"  '"status":"healthy"'
check "policy-engine /health"  "curl -sk https://127.0.0.1:4000/health" '"status":"healthy"'

echo ""
echo "--- 3. Fabric live (chaincode sync) ---"
check "policy-engine synced policy params from Fabric" \
  "docker logs ztiam-policy-engine 2>&1 | grep 'Policy public params synced'" \
  "Policy public params synced from Fabric"

check "chaincode GetUser(alice) via cli" \
  "docker exec cli peer chaincode query -C iamchannel -n iam-cc -c '{\"function\":\"GetUser\",\"Args\":[\"alice\"]}'" \
  '"userId":"alice".*"role":"admin"'

echo ""
echo "--- 4. End-to-end login flows ---"
CSRF=$(curl -s -c /tmp/smoke-cookies.txt http://127.0.0.1:3000/api/csrf-token | python3 -c "import json,sys;print(json.load(sys.stdin)['csrfToken'])" 2>/dev/null)
if [[ -z "$CSRF" ]]; then
  echo -e "${RED}✗${NC} CSRF token unobtainable"; FAIL=$((FAIL + 1))
else
  echo -e "${GRN}✓${NC} CSRF token acquired"
  PASS=$((PASS + 1))

  check "alice ALLOW (known device, home city)" \
    "curl -s -b /tmp/smoke-cookies.txt -X POST http://127.0.0.1:3000/api/login \
      -H 'Content-Type: application/json' -H 'X-CSRF-Token: $CSRF' \
      --max-time 60 \
      -d '{\"username\":\"alice\",\"password\":\"pass123\",\"deviceId\":\"dev-001\",\"timestamp\":\"2026-06-03T10:00:00Z\",\"location\":{\"country\":\"IN\",\"city\":\"Gwalior\"},\"requiredPermission\":\"read\"}'" \
    '"decision":"ALLOW"'

  check "alice DENY (unknown device)" \
    "curl -s -b /tmp/smoke-cookies.txt -X POST http://127.0.0.1:3000/api/login \
      -H 'Content-Type: application/json' -H 'X-CSRF-Token: $CSRF' \
      --max-time 60 \
      -d '{\"username\":\"alice\",\"password\":\"pass123\",\"deviceId\":\"attacker-laptop\",\"timestamp\":\"2026-06-03T10:00:00Z\",\"location\":{\"country\":\"IN\",\"city\":\"Gwalior\"},\"requiredPermission\":\"read\"}'" \
    '"decision":"DENY"'

  check "alice MFA_REQUIRED (foreign country)" \
    "curl -s -b /tmp/smoke-cookies.txt -X POST http://127.0.0.1:3000/api/login \
      -H 'Content-Type: application/json' -H 'X-CSRF-Token: $CSRF' \
      --max-time 60 \
      -d '{\"username\":\"alice\",\"password\":\"pass123\",\"deviceId\":\"dev-001\",\"timestamp\":\"2026-06-03T10:00:00Z\",\"location\":{\"country\":\"RU\",\"city\":\"Moscow\"},\"requiredPermission\":\"read\"}'" \
    '"decision":"MFA_REQUIRED"'
fi

echo ""
echo "--- 5. Audit chain integrity (chaincode-side) ---"
check "VerifyAuditChain returns valid:true" \
  "docker exec cli peer chaincode query -C iamchannel -n iam-cc -c '{\"function\":\"VerifyAuditChain\",\"Args\":[]}'" \
  '"valid":true'

echo ""
echo "--- 6. Observability ---"
check "ml-service metrics exposed" \
  "curl -s http://172.19.0.2:5000/metrics" \
  "ml_predict_total"

echo ""
echo "================================="
echo -e "PASS: ${GRN}$PASS${NC}   FAIL: ${RED}$FAIL${NC}"
echo "================================="
exit $FAIL
