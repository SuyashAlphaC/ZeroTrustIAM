import http from 'k6/http';
import { check } from 'k6';
import { Rate } from 'k6/metrics';

const stepUp = new Rate('step_up_signals');
const denyRate = new Rate('deny_signals');

export const options = {
  stages: [{ duration: '45s', target: 28 }],
  thresholds: {
    step_up_signals: ['rate>=0.25'],
    deny_signals: ['rate<=0.10'],
    http_req_failed: ['rate<0.15'],
    http_req_duration: ['p(95)<2500'],
  },
};

/** 70% low-risk geography; 30% step-up inducing payload (risky location for seeded demo profile). */
export default function () {
  const pe = __ENV.PE_URL || 'http://localhost:4000';
  const risky = (__ITER % 10) >= 7;
  const body = risky
    ? {
        username: 'alice',
        password: 'pass123',
        deviceId: 'dev-001',
        timestamp: new Date().toISOString(),
        location: { country: 'RU', city: 'Moscow' },
        requiredPermission: 'read',
      }
    : {
        username: 'alice',
        password: 'pass123',
        deviceId: 'dev-001',
        timestamp: new Date().toISOString(),
        location: { country: 'IN', city: 'Gwalior' },
        requiredPermission: 'read',
      };

  const res = http.post(`${pe}/evaluate`, JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
    tags: { scenario: risky ? 'risky' : 'benign' },
  });

  let decision = '';
  try {
    decision = JSON.parse(String(res.body || '{}')).decision || '';
  } catch (_) {}

  stepUp.add(decision === 'MFA_REQUIRED' ? 1 : 0);
  denyRate.add(decision === 'DENY' ? 1 : 0);

  check(res, {
    'status 200': (r) => r.status === 200,
  });
}
