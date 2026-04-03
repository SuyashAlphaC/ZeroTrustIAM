/**
 * Zero Trust IAM - Attack Scenario Simulation (Phase 5)
 *
 * Tests 7 attack vectors against the system to demonstrate
 * the two-layer defense (Policy Engine + Blockchain Smart Contract).
 *
 * Requires: web-app (:3000) and policy-engine (:4000) running.
 */

const BASE_URL = 'http://localhost:3000/api/login';

let passed = 0;
let failed = 0;

async function runTest(name, payload, expectedDecision) {
  try {
    const res = await fetch(BASE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const result = await res.json();

    const status = result.decision === expectedDecision ? 'PASS' : 'FAIL';
    if (status === 'PASS') passed++;
    else failed++;

    console.log(`\n[${ status }] ${name}`);
    console.log(`  Expected: ${expectedDecision} | Got: ${result.decision}`);
    console.log(`  Reason: ${result.reason}`);
    if (result.riskScore !== undefined) {
      console.log(`  Risk Score: ${result.riskScore}`);
      if (result.breakdown) {
        console.log(`  Breakdown: d=${result.breakdown.d_score} l=${result.breakdown.l_score} t=${result.breakdown.t_score} a=${result.breakdown.a_score}`);
      }
    }
    console.log(`  Layer: ${result.layer || 'N/A'}`);
    if (result.txId) console.log(`  TxID: ${result.txId}`);

    return result;
  } catch (err) {
    failed++;
    console.log(`\n[FAIL] ${name}`);
    console.log(`  Error: ${err.message}`);
    return null;
  }
}

async function main() {
  console.log('='.repeat(60));
  console.log('  Zero Trust IAM - Attack Scenario Simulation');
  console.log('='.repeat(60));

  // Scenario 1: Brute Force Attack
  // Send multiple wrong passwords. The a_score should escalate.
  console.log('\n--- Scenario 1: Brute Force Attack ---');
  for (let i = 1; i <= 5; i++) {
    await runTest(
      `Brute force attempt ${i}/5`,
      {
        username: 'alice',
        password: `wrong${i}`,
        deviceId: 'dev-001',
        timestamp: '2026-04-02T10:00:00Z',
        location: { country: 'IN', city: 'Gwalior' },
        requiredPermission: 'read',
      },
      'DENY'
    );
  }
  // Now try with correct password but accumulated failed attempts
  // a_score = min(5/5, 1) = 1.0 -> R += 0.10
  // With registered device and normal location, R = 0.10 < 0.6, should still ALLOW
  // but the smart contract checks pass too
  await runTest(
    'Login after 5 failed attempts (a_score=1.0, R=0.10)',
    {
      username: 'alice',
      password: 'pass123',
      deviceId: 'dev-001',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Gwalior' },
      requiredPermission: 'read',
    },
    'ALLOW'
  );

  // Scenario 2: Stolen Credentials + Unknown Device
  console.log('\n--- Scenario 2: Stolen Credentials + Unknown Device ---');
  await runTest(
    'Attacker with stolen password, unknown device',
    {
      username: 'alice',
      password: 'pass123',
      deviceId: 'attacker-laptop-999',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Gwalior' },
      requiredPermission: 'read',
    },
    'DENY'  // d_score=1 -> R=0.40 < 0.6, but smart contract DENY (unregistered device)
  );

  // Scenario 3: Location Anomaly
  console.log('\n--- Scenario 3: Location Anomaly ---');
  await runTest(
    'Login from foreign country (Russia) with registered device',
    {
      username: 'alice',
      password: 'pass123',
      deviceId: 'dev-001',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'RU', city: 'Moscow' },
      requiredPermission: 'read',
    },
    'MFA_REQUIRED'  // l_score=1 -> R=0.30 >= step-up threshold, MFA required
  );

  // Scenario 4: Off-Hours Access
  console.log('\n--- Scenario 4: Off-Hours Access ---');
  await runTest(
    'Login at 3 AM (outside 8-18 normal hours) with registered device',
    {
      username: 'alice',
      password: 'pass123',
      deviceId: 'dev-001',
      timestamp: '2026-04-02T03:00:00Z',
      location: { country: 'IN', city: 'Gwalior' },
      requiredPermission: 'read',
    },
    'ALLOW'  // t_score=1 -> R=0.20 < 0.6, device OK
  );

  // Scenario 5: Suspended Account
  console.log('\n--- Scenario 5: Suspended Account ---');
  // Note: Bob's account would need to be suspended via chaincode.
  // For this test, we use a non-existent user to demonstrate DENY.
  await runTest(
    'Login as non-existent user (simulates suspended/removed account)',
    {
      username: 'charlie',
      password: 'charlie123',
      deviceId: 'dev-003',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Mumbai' },
      requiredPermission: 'read',
    },
    'DENY'
  );

  // Scenario 6: Privilege Escalation (RBAC)
  console.log('\n--- Scenario 6: Privilege Escalation (RBAC) ---');
  await runTest(
    'Viewer (bob) tries to delete - insufficient permissions',
    {
      username: 'bob',
      password: 'bob456',
      deviceId: 'dev-002',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Delhi' },
      requiredPermission: 'delete',
    },
    'DENY'
  );

  // Scenario 7: Cumulative Risk (Unknown device + Foreign location + Off-hours)
  console.log('\n--- Scenario 7: Cumulative Risk Attack ---');
  await runTest(
    'Unknown device + foreign country + off-hours (R = 0.40+0.30+0.20 = 0.90)',
    {
      username: 'alice',
      password: 'pass123',
      deviceId: 'hacker-dev-xyz',
      timestamp: '2026-04-02T02:00:00Z',
      location: { country: 'CN', city: 'Beijing' },
      requiredPermission: 'write',
    },
    'DENY'  // R=0.90 >= 0.6, DENY by policy engine before reaching blockchain
  );

  // Summary
  console.log('\n' + '='.repeat(60));
  console.log(`  Results: ${passed} PASSED, ${failed} FAILED out of ${passed + failed} tests`);
  console.log('='.repeat(60));

  // Fetch and display audit log
  try {
    const auditRes = await fetch('http://localhost:4000/audit-log');
    const logs = await auditRes.json();
    console.log(`\n  Blockchain Audit Log: ${logs.length} entries recorded`);
    console.log('  (All decisions are immutably stored on Hyperledger Fabric)');
  } catch (e) {
    console.log('  Could not fetch audit log:', e.message);
  }
}

main().catch(console.error);
