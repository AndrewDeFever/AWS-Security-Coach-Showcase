# AWS Security Coach — Workload Account Connector

**Milestone:** A-010  
**Status:** Design packet only  
**Execution authorization:** Not granted

## Purpose

This packet defines the first bounded workload-account connector for AWS Security Coach.

The connector creates one read-only IAM role that may be assumed only by an exact AWS Security Coach scanner-role principal using a connector-specific ExternalId.

## First-slice boundary

- One controlled workload account
- One dedicated read-only connector role
- One exact environment-specific scanner principal
- One connector-specific ExternalId
- Existing nine checks only
- Manual onboarding and offboarding
- `us-east-1` coverage for the regional security-group check
- No remediation role
- No Organizations or StackSets deployment
- No billing, subscription, or self-service tenancy workflow
- No Version 2 lease or lifecycle automation

## Packet contents

- `template.yaml` — workload-account CloudFormation template
- `permissions.md` — permission rationale and source mapping
- `onboarding-checklist.md` — manual onboarding procedure
- `offboarding-checklist.md` — disable-first trust-removal procedure
- `verify-template.sh` — local static validation helper
- `../docs/cross-account-permission-matrix.md` — source permission-to-check matrix

## Deployment parameters

| Parameter | Purpose |
|---|---|
| `TrustedScannerRoleArn` | Exact environment-specific AWS Security Coach scanner role ARN |
| `ExternalId` | Unique connector-specific confused-deputy protection value |
| `HomeRegion` | Regional scan boundary; currently restricted to `us-east-1` |

The ExternalId is declared with `NoEcho: true` and is not returned as a stack output.

## Stack outputs

The stack returns only:

- Connector role ARN
- Connector role name
- Configured home region

## Security boundary

The connector role cannot mutate workload-account resources and cannot assume other roles. The browser must never choose or submit the workload account ID, role ARN, or ExternalId for execution. Those values belong to the future application-owned connector registry.

## Important status distinction

Removing or disabling a future connector registration in the tool account would stop normal AWS Security Coach scans, but it would not itself remove workload-account trust. Complete revocation requires deleting this stack or otherwise removing the workload role trust and then verifying that role assumption fails.

## Not yet authorized

This packet does not authorize:

- Backend `sts:AssumeRole` integration
- Connector registry implementation
- Cross-account scan execution
- Production deployment
- UI account selection
- Automated expiration or stack deletion
