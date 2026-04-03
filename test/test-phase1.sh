#!/bin/bash
# Phase 1 Tests - Web App + Policy Engine (Mock Blockchain)
# Requires both servers running: web-app (:3000) and policy-engine (:4000)

BASE_URL="http://localhost:3000/api/login"
PASS=0
FAIL=0

run_test() {
  local name="$1"
  local payload="$2"
  local expected_decision="$3"

  echo ""
  echo "=== TEST: $name ==="
  result=$(curl -s -X POST "$BASE_URL" -H 'Content-Type: application/json' -d "$payload")
  decision=$(echo "$result" | grep -o '"decision":"[^"]*"' | head -1 | cut -d'"' -f4)

  echo "  Payload: $payload"
  echo "  Response: $result"
  echo "  Expected: $expected_decision | Got: $decision"

  if [ "$decision" = "$expected_decision" ]; then
    echo "  >> PASS"
    PASS=$((PASS + 1))
  else
    echo "  >> FAIL"
    FAIL=$((FAIL + 1))
  fi
}

echo "============================================"
echo "  Zero Trust IAM - Phase 1 Test Suite"
echo "============================================"

# Test 1: Valid login (known user, correct password, registered device, normal location)
run_test "Valid login - alice" \
  '{"username":"alice","password":"pass123","deviceId":"dev-001","timestamp":"2026-04-02T10:00:00Z","location":{"country":"IN","city":"Gwalior"},"requiredPermission":"read"}' \
  "ALLOW"

# Test 2: Wrong password
run_test "Wrong password" \
  '{"username":"alice","password":"wrongpass","deviceId":"dev-001","timestamp":"2026-04-02T10:00:00Z","location":{"country":"IN","city":"Gwalior"},"requiredPermission":"read"}' \
  "DENY"

# Test 3: Unknown user
run_test "Unknown user" \
  '{"username":"charlie","password":"pass123","deviceId":"dev-001","timestamp":"2026-04-02T10:00:00Z","location":{"country":"IN","city":"Gwalior"},"requiredPermission":"read"}' \
  "DENY"

# Test 4: Unregistered device (d_score=1, R=0.40 -> still below 0.6 if all else normal)
# But smart contract will DENY because device not in registered list
run_test "Unregistered device" \
  '{"username":"alice","password":"pass123","deviceId":"unknown-dev","timestamp":"2026-04-02T10:00:00Z","location":{"country":"IN","city":"Gwalior"},"requiredPermission":"read"}' \
  "DENY"

# Test 5: Foreign country (d_score=0 + l_score=1 = 0.30, still < 0.6)
# But this uses registered device, so smart contract ALLOW if role permits
run_test "Foreign country with registered device" \
  '{"username":"alice","password":"pass123","deviceId":"dev-001","timestamp":"2026-04-02T10:00:00Z","location":{"country":"US","city":"New York"},"requiredPermission":"read"}' \
  "ALLOW"

# Test 6: Unknown device + foreign country (d_score=1 + l_score=1 = 0.70 >= 0.6 -> DENY by policy engine)
run_test "Unknown device + foreign country (cumulative risk)" \
  '{"username":"alice","password":"pass123","deviceId":"attacker-dev","timestamp":"2026-04-02T10:00:00Z","location":{"country":"RU","city":"Moscow"},"requiredPermission":"read"}' \
  "DENY"

# Test 7: Off-hours access with registered device (t_score=1, R=0.20 < 0.6)
run_test "Off-hours with registered device" \
  '{"username":"alice","password":"pass123","deviceId":"dev-001","timestamp":"2026-04-02T03:00:00Z","location":{"country":"IN","city":"Gwalior"},"requiredPermission":"read"}' \
  "ALLOW"

# Test 8: Bob tries to delete (viewer role lacks delete permission)
run_test "RBAC - viewer tries delete" \
  '{"username":"bob","password":"bob456","deviceId":"dev-002","timestamp":"2026-04-02T10:00:00Z","location":{"country":"IN","city":"Delhi"},"requiredPermission":"delete"}' \
  "DENY"

# Test 9: Bob reads (viewer role has read permission)
run_test "RBAC - viewer reads" \
  '{"username":"bob","password":"bob456","deviceId":"dev-002","timestamp":"2026-04-02T10:00:00Z","location":{"country":"IN","city":"Delhi"},"requiredPermission":"read"}' \
  "ALLOW"

echo ""
echo "============================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================"
