# Manual Connector Offboarding Checklist

## Phase 1 — Disable application access

These steps apply after the future connector registry exists:

- [ ] Change the tool-account connector state from `ACTIVE` to `DISABLED` or `EXPIRED`.
- [ ] Reject new scan requests before calling STS.
- [ ] Prevent queued but unstarted connector scans from beginning.
- [ ] Disable requester-to-connector memberships.
- [ ] Remove or tombstone the protected ExternalId record according to the approved retention policy.
- [ ] Preserve sanitized audit evidence and historical reports under the normal retention policy.

Application disablement stops normal AWS Security Coach use but does not itself remove workload-account trust.

## Phase 2 — Remove workload-account trust

- [ ] Confirm no approved scan is running.
- [ ] Delete the connector CloudFormation stack in the workload account, or otherwise remove the role trust through an approved change.
- [ ] Confirm the `aws-security-coach-read-only` role is absent.
- [ ] Confirm no replacement role retains the AWS Security Coach scanner principal and ExternalId condition.
- [ ] Record the cleanup timestamp and operator reference.

## Phase 3 — Verify revocation

- [ ] Attempt role assumption from the previously trusted scanner principal using the former connector parameters.
- [ ] Confirm role assumption is denied.
- [ ] Mark the connector `REVOKED` only after denial is verified.
- [ ] If trust removal cannot be verified, retain the explicit state: `Application access disabled; workload-account trust cleanup pending.`

## Boundaries

- Do not claim complete offboarding from tool-account disablement alone.
- Do not automate workload-stack deletion during A-010.
- Do not delete historical reports as part of connector offboarding.
- Do not restore access without repeating trust, ownership, and membership verification.
