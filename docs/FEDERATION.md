# Identity federation

## OIDC (Google, Entra ID, Okta)

### Environment

```bash
# Google
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...

# Microsoft Entra ID
ENTRA_TENANT_ID=common   # or directory GUID
ENTRA_CLIENT_ID=...
ENTRA_CLIENT_SECRET=...

# Okta
OKTA_DOMAIN=dev-xxx.okta.com
# or OKTA_ISSUER=https://dev-xxx.okta.com
OKTA_CLIENT_ID=...
OKTA_CLIENT_SECRET=...

FEDERATION_CALLBACK_BASE=https://iam.example.com   # public URL of policy-engine
WEB_APP_URL=https://app.example.com
```

### Redirect URIs to register at the IdP

```
{FEDERATION_CALLBACK_BASE}/v1/federation/google/callback
{FEDERATION_CALLBACK_BASE}/v1/federation/entra/callback
{FEDERATION_CALLBACK_BASE}/v1/federation/okta/callback
```

### User journey

1. Browser → `GET /v1/federation/google/start?tenant=acme`
2. IdP login
3. Callback exchanges code (PKCE), upserts `fed_*` user + `federated_identities` row
4. Redirect to web app with access/refresh tokens

## SAML 2.0 (exclusive C14N XMLDSig)

Verification uses exclusive canonicalization (`samlExclusiveC14n.js` + `samlXmlDSig.js`):
enveloped-signature transforms, InclusiveNamespaces PrefixList, RSA-SHA1/256/512,
response and/or assertion signatures, Audience / Destination / NotBefore / NotOnOrAfter,
InResponseTo correlation, multi-cert IdP pins.

```bash
SAML_SP_ENTITY_ID=https://iam.example.com/saml/metadata
SAML_ACS_URL=https://iam.example.com/v1/federation/saml/acs
SAML_IDP_ENTITY_ID=https://sts.windows.net/{tenant}/
SAML_IDP_SSO_URL=https://login.microsoftonline.com/{tenant}/saml2
SAML_IDP_CERT="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
SAML_IDP_CERT_2=...   # optional extra pin
SAML_WANT_ASSERTIONS_SIGNED=true
SAML_WANT_RESPONSE_SIGNED=false
SAML_CLOCK_SKEW_SECONDS=120
```

- Metadata: `GET /v1/federation/saml/metadata`
- Start SSO: `GET /v1/federation/saml/start`
- ACS: `POST /v1/federation/saml/acs`

## Listing providers

`GET /v1/federation/providers` — which integrations are configured.
