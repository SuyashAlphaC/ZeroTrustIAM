import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '30s', target: 50 },
    { duration: '2m', target: 200 },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<2000'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const pe = __ENV.PE_URL || 'http://localhost:4000';
  const vu = (__VU || 1) % 9999;
  const res = http.post(`${pe}/evaluate`, JSON.stringify({
    username: `user${vu}`,
    password: 'TestPass123!',
    deviceId: `dv${vu}`,
    timestamp: new Date().toISOString(),
    location: { country: 'US', city: 'NYC' },
  }), {
    headers: { 'Content-Type': 'application/json' },
  });
  check(res, { 'status is 200 or 401': (r) => [200, 401].includes(r.status) });
  sleep(1);
}
