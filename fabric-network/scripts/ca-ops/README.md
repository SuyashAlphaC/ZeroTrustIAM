# Fabric multi-org CA production operations

This directory automates **Fabric CA** lifecycle for multi-org ZeroTrustIAM deployments. Prefer Fabric CA over `cryptogen` for any non-lab environment.

## Topology assumed

| Org | CA host (example) | MSP ID |
|-----|-------------------|--------|
| Orderer | `ca.orderer.example.com:7054` | `OrdererMSP` |
| Org1 | `ca.org1.example.com:7054` | `Org1MSP` |
| Org2 | `ca.org2.example.com:7054` | `Org2MSP` |

## Prerequisites

- `fabric-ca-client` on `PATH` (from `fabric-network/bin/`)
- TLS CA certs reachable
- Docker Compose or k8s Fabric CA pods running

## Quick start

```bash
export PATH="$(pwd)/fabric-network/bin:$PATH"
export FABRIC_CA_CLIENT_HOME=/tmp/fabric-ca-client

# 1. Bootstrap org CAs and enroll admin
./fabric-network/scripts/ca-ops/01-bootstrap-cas.sh

# 2. Enroll peers + users for Org1/Org2
./fabric-network/scripts/ca-ops/02-enroll-peers-and-users.sh

# 3. Generate connection profile for policy-engine
./fabric-network/scripts/ca-ops/03-gen-connection-profile.sh

# 4. Rotate intermediate CA (annual / compromise)
./fabric-network/scripts/ca-ops/04-rotate-intermediate-ca.sh org1

# 5. Revoke a compromised identity
./fabric-network/scripts/ca-ops/05-revoke-identity.sh org1 peer0
```

## Endorsement policy (production)

Chaincode lifecycle should require both orgs for policy updates:

```
AND('Org1MSP.peer','Org2MSP.peer')
```

Read-only evaluate can use `OR(...)` if your trust model allows.

## Backup

- Backup Fabric CA SQLite/Postgres DB
- Backup MSP folders under `organizations/`
- Backup orderer genesis / channel config blocks

See also `docs/OPERATIONS.md` and `docs/FABRIC_CA_RUNBOOK.md`.
