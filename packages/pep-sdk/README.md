# @ztiam/pep-sdk

Policy Enforcement Point SDK for ZeroTrustIAM.

## Install

```bash
# from monorepo
cd packages/pep-sdk && npm link
# or copy into your service
```

## Express

```js
const { createPep } = require('@ztiam/pep-sdk');

const pep = createPep({
  issuerUrl: process.env.ZTIAM_URL || 'http://localhost:4000',
  requireTenant: true,
});

app.get('/api/orders', pep.express({ roles: ['viewer', 'editor', 'admin'] }), (req, res) => {
  res.json({ user: req.user.sub, tenant: req.user.tid });
});
```

## Envoy ext_authz

Point Envoy `envoy.filters.http.ext_authz` at a small Node service:

```js
const http = require('http');
const { createPep } = require('@ztiam/pep-sdk');
const pep = createPep({ issuerUrl: process.env.ZTIAM_URL });

http.createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = JSON.parse(Buffer.concat(chunks).toString() || '{}');
  const decision = await pep.envoyCheck({ headers: body.attributes?.request?.http?.headers || {} });
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(decision));
}).listen(9001);
```

## Nginx auth_request

```nginx
location /api/ {
  auth_request /_ztiam_auth;
  proxy_pass http://backend;
}
location = /_ztiam_auth {
  internal;
  proxy_pass http://pep-sidecar:9001/check;
  proxy_pass_request_body off;
  proxy_set_header Authorization $http_authorization;
}
```
