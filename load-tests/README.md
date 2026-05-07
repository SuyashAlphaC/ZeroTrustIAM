Run k6 from the repo root after the policy-engine (and Postgres + demo seeds) stack is reachable.

```bash
PE_URL=http://localhost:4000 k6 run load-tests/k6/login-burst.js
PE_URL=http://localhost:4000 k6 run load-tests/k6/evaluate-access-mix.js
```

The mix script probes `/evaluate`; tune usernames/passwords against your deployed dataset. CI uses a deterministic demo seed (`alice/pass123`) when enabled.
