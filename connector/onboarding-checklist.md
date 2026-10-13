# Manual Connector Onboarding Checklist

**Milestone:** A-010 design packet  
**Execution status:** Cross-account scanning remains disabled

## Before deployment

- [ ] Confirm the workload account is the approved controlled pilot account.
- [ ] Confirm the target environment is development.
- [ ] Obtain the exact development scanner-role ARN from stack-managed tool-account infrastructure.
- [ ] Generate a unique connector-specific ExternalId with at least 128 bits of entropy.
- [ ] Store the ExternalId only in an approved protected operator location pending future registry implementation.
- [ ] Confirm the ExternalId is not placed in tickets, chat transcripts, screenshots, reports, stack outputs, or frontend configuration.
- [ ] Review `docs/cross-account-permission-matrix.md`.
- [ ] Confirm V-010-01 and V-010-02 are still tracked if unresolved.

## Template validation

- [ ] Run `connector/verify-template.sh`.
- [ ] Run CloudFormation template validation in the workload account.
- [ ] Run IAM Access Analyzer policy validation and review every finding.
- [ ] Confirm the template creates exactly one IAM role and one inline permissions policy.
- [ ] Confirm no mutation action exists.
- [ ] Confirm no `iam:PassRole` permission exists.
- [ ] Confirm the workload permissions policy does not contain `sts:AssumeRole`.
- [ ] Confirm the trust policy names one exact scanner role and requires `sts:ExternalId`.
- [ ] Confirm the ExternalId parameter uses `NoEcho` and is not output.

## Deployment

- [ ] Deploy the stack using an explicit stack name approved for the pilot.
- [ ] Supply `TrustedScannerRoleArn` with the exact development scanner-role ARN.
- [ ] Supply the connector-specific ExternalId securely.
- [ ] Leave `HomeRegion` set to `us-east-1`.
- [ ] Record the stack ID, role ARN, role name, template version, and deployment timestamp.
- [ ] Do not record the ExternalId in the connector evidence package.

## Workload-account verification

- [ ] Read the deployed role trust policy and confirm the exact principal.
- [ ] Read the inline policy and compare it with the approved nine-action matrix.
- [ ] Confirm no unexpected managed policies are attached.
- [ ] Confirm the role maximum session duration is one hour.
- [ ] Confirm the role cannot mutate IAM, CloudTrail, S3, or EC2 resources.
- [ ] Confirm the role cannot assume another workload-account role.

## Future execution verification gate

These steps are documented now but are not authorized until a separate implementation objective begins:

- [ ] Assume the role from the exact development scanner principal using the correct ExternalId.
- [ ] Call `sts:GetCallerIdentity` and verify the expected workload account and assumed role.
- [ ] Confirm an incorrect ExternalId is denied.
- [ ] Confirm an unapproved principal is denied.
- [ ] Confirm every required read call succeeds.
- [ ] Confirm representative write calls are denied.
- [ ] Confirm failed or incomplete checks return `ERROR`, never `PASS`.
- [ ] Confirm reports use opaque connector and account references rather than public account identifiers.

## Activation boundary

Deployment of the workload stack does not activate a connector. A future application-owned registry record and requester-to-connector membership must exist before any scan can be authorized.
