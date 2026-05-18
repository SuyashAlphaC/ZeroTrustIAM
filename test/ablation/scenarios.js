'use strict';

/**
 * Canonical access scenarios for ablation (aligned with test/attack-scenarios.js
 * and policy-engine integration tests).
 *
 * Categories:
 *   - benign    : routine valid login; baseline must ALLOW
 *   - risk      : suspicious-but-valid; baseline must MFA_REQUIRED or ALLOW
 *   - attack    : malicious; baseline must DENY
 *   - evasion   : adversarial attempts crafted to slip past one or more layers
 */
const SCENARIOS = [
  {
    id: 'legitimate_login',
    name: 'Legitimate login (known device, home location, business hours)',
    category: 'benign',
    setup: null,
    payload: {
      username: 'alice',
      password: 'pass123',
      deviceId: 'dev-001',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Gwalior' },
      requiredPermission: 'read',
    },
    baselineExpected: 'ALLOW',
  },
  {
    id: 'wrong_password',
    name: 'Invalid password',
    category: 'attack',
    setup: null,
    payload: {
      username: 'alice',
      password: 'wrong-password',
      deviceId: 'dev-001',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Gwalior' },
      requiredPermission: 'read',
    },
    baselineExpected: 'DENY',
  },
  {
    id: 'unknown_user',
    name: 'Non-existent user',
    category: 'attack',
    setup: null,
    payload: {
      username: 'charlie',
      password: 'charlie123',
      deviceId: 'dev-003',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Mumbai' },
      requiredPermission: 'read',
    },
    baselineExpected: 'DENY',
  },
  {
    id: 'stolen_creds_unknown_device',
    name: 'Valid password from unregistered device',
    category: 'attack',
    setup: null,
    payload: {
      username: 'alice',
      password: 'pass123',
      deviceId: 'attacker-laptop-999',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Gwalior' },
      requiredPermission: 'read',
    },
    baselineExpected: 'DENY',
  },
  {
    id: 'foreign_country',
    name: 'Registered device, foreign country (Russia)',
    category: 'risk',
    setup: null,
    payload: {
      username: 'alice',
      password: 'pass123',
      deviceId: 'dev-001',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'RU', city: 'Moscow' },
      requiredPermission: 'read',
    },
    baselineExpected: 'MFA_REQUIRED',
  },
  {
    id: 'off_hours',
    name: 'Registered device, off-hours access (03:00 UTC)',
    category: 'risk',
    setup: null,
    payload: {
      username: 'alice',
      password: 'pass123',
      deviceId: 'dev-001',
      timestamp: '2026-04-02T03:00:00Z',
      location: { country: 'IN', city: 'Gwalior' },
      requiredPermission: 'read',
    },
    baselineExpected: 'ALLOW',
  },
  {
    id: 'privilege_escalation',
    name: 'Viewer role requests delete permission',
    category: 'attack',
    setup: null,
    payload: {
      username: 'bob',
      password: 'bob456',
      deviceId: 'dev-002',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Delhi' },
      requiredPermission: 'delete',
    },
    baselineExpected: 'DENY',
  },
  {
    id: 'cumulative_high_risk',
    name: 'Unknown device + foreign country + off-hours + write',
    category: 'attack',
    setup: null,
    payload: {
      username: 'alice',
      password: 'pass123',
      deviceId: 'hacker-dev-xyz',
      timestamp: '2026-04-02T02:00:00Z',
      location: { country: 'CN', city: 'Beijing' },
      requiredPermission: 'write',
    },
    baselineExpected: 'DENY',
  },
  {
    id: 'post_bruteforce_login',
    name: 'Correct password after 5 failed attempts (elevated a_score)',
    category: 'risk',
    setup: 'bruteforce_5',
    payload: {
      username: 'alice',
      password: 'pass123',
      deviceId: 'dev-001',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Gwalior' },
      requiredPermission: 'read',
    },
    baselineExpected: 'ALLOW',
  },
  {
    id: 'same_country_different_city',
    name: 'Registered device, same country different city',
    category: 'risk',
    setup: null,
    payload: {
      username: 'alice',
      password: 'pass123',
      deviceId: 'dev-001',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Delhi' },
      requiredPermission: 'read',
    },
    baselineExpected: 'ALLOW',
  },

  // ─── Evasion scenarios (v2) ──────────────────────────────────────────────
  // These are crafted to defeat single-signal detection. Their baselineExpected
  // values reflect what the full ensemble SHOULD do, not what an attacker hopes.

  {
    id: 'evasion_perfect_mimic',
    name: 'Stolen creds + stolen device + home location + normal hour (perfect mimic)',
    category: 'evasion',
    setup: null,
    payload: {
      username: 'alice',
      password: 'pass123',
      deviceId: 'dev-001',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Gwalior' },
      requiredPermission: 'read',
    },
    // Honest expectation: contextual signals cannot catch a perfect mimic.
    // Documents the ceiling of behavior-based detection; ALLOW is the
    // worst-case truth the system has to defend against (motivates passkeys).
    baselineExpected: 'ALLOW',
    evasion: {
      goal: 'Slip past every behavioral signal; demonstrates need for hardware-bound auth (WebAuthn).',
      defeats: ['device-AHP', 'location-AHP', 'time-AHP', 'anomaly-detector', 'ML-RF'],
      defendedBy: ['WebAuthn passkey (hardware factor)', 'token binding', 'session anomalies (out of scope here)'],
    },
  },
  {
    id: 'evasion_normal_hours_foreign_country',
    name: 'Foreign country during target user normal hours (read)',
    category: 'evasion',
    setup: null,
    payload: {
      username: 'alice',
      password: 'pass123',
      deviceId: 'dev-001',
      timestamp: '2026-04-02T11:00:00Z',
      location: { country: 'RU', city: 'Moscow' },
      requiredPermission: 'read',
    },
    // Defeats the time-AHP factor (normal hour) but location-AHP + anomaly
    // (geo novelty) must still raise risk into MFA territory.
    baselineExpected: 'MFA_REQUIRED',
    evasion: {
      goal: 'Defeat the time-of-day signal by attacking during target normal hours.',
      defeats: ['time-AHP'],
      defendedBy: ['location-AHP', 'anomaly geo novelty', 'ML RF feature mix'],
    },
  },
  {
    id: 'evasion_credential_stuffing_known_device',
    name: 'Credential stuffing — wrong owner on registered device',
    category: 'evasion',
    setup: null,
    payload: {
      username: 'alice',
      password: 'pass123',
      // dev-002 is registered to bob, not alice; attacker has alice's
      // password from a breach and tries it from bob's compromised laptop.
      deviceId: 'dev-002',
      timestamp: '2026-04-02T10:00:00Z',
      location: { country: 'IN', city: 'Delhi' },
      requiredPermission: 'read',
    },
    // Password works at bcrypt layer; blockchain device-registry must DENY
    // because dev-002 is not in alice's registered devices.
    baselineExpected: 'DENY',
    evasion: {
      goal: 'Credential stuffing through a device that is registered to a different user.',
      defeats: ['password check'],
      defendedBy: ['blockchain device registry', 'location-AHP (alice rarely in Delhi)'],
    },
  },
];

module.exports = { SCENARIOS };
