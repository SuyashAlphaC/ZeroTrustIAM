# Fabric CA multi-org production runbook

## Goals

- Replace `cryptogen` with **Fabric CA** issued identities
- Dual-org endorsement for sensitive chaincode
- Documented enroll / revoke / rotate procedures

## Scripts

See `fabric-network/scripts/ca-ops/`:

| Script | Purpose |
|--------|---------|
| `01-bootstrap-cas.sh` | Enroll CA admins |
| `02-enroll-peers-and-users.sh` | Peer + user + policy-engine client |
| `03-gen-connection-profile.sh` | Multi-peer connection profile JSON |
| `04-rotate-intermediate-ca.sh` | Rotation checklist |
| `05-revoke-identity.sh` | Revoke + CRL |

## policy-engine wiring

```bash
export FABRIC_CONNECTION_PROFILE=/path/to/connection-profile-prod.json
export FABRIC_MSP_ID=Org1MSP
export FABRIC_PEER_ENDPOINT=peer0.org1.example.com:7051
export FABRIC_PEER_ENDPOINT_ORG2=peer0.org2.example.com:9051
# Identity cert/key from policy-engine@org1 MSP folder
```

## Chaincode endorsement (production)

```
peer lifecycle chaincode approveformyorg \
  --signature-policy "AND('Org1MSP.peer','Org2MSP.peer')" ...
```

## Validation

```bash
./fabric-network/scripts/submit-test-tx.sh
./fabric-network/scripts/chaos-orderer-kill.sh
```
