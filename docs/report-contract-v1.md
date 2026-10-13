# AWS Security Coach — Report Contract V1 Proposal

Last reconciled: August 2, 2026

## Status

**Selected primary milestone:** Versioned report contract and bounded rules foundation.

This document defines the design boundary for the next implementation milestone. It does not change the currently deployed report shape by itself.

## Problem

The hosted application produces and renders a stable nine-check report, but the JSON remains adapter-based rather than an explicit versioned contract. Future report history, rule metadata, cross-account attribution, and external consumers would otherwise couple themselves to incidental field names and current implementation details.

The goal is to establish a small, versioned envelope without rewriting the verified checks or creating a generic policy language.

## Current source baseline

The active runner findings use these core fields:

- `id`
- `title`
- `severity`
- `status`
- `details`

The deployed flow also associates the report with a scan identifier, target context, generation time, scan state, and summary counts. Existing reports must remain readable during migration.

## Proposed V1 envelope

```json
{
  "schemaVersion": "1.0",
  "scan": {
    "scanId": "uuid",
    "status": "COMPLETE",
    "generatedAt": "2026-08-02T19:02:41.650142Z"
  },
  "target": {
    "type": "tool-account",
    "accountRef": "configured-account",
    "regionScope": ["us-east-1"]
  },
  "ruleset": {
    "id": "aws-security-coach-core",
    "version": "1.0",
    "checkCount": 9
  },
  "summary": {
    "total": 9,
    "passed": 9,
    "failed": 0,
    "warnings": 0,
    "errors": 0
  },
  "findings": []
}
```

## Required finding fields

Every V1 finding must include:

| Field | Type | Purpose |
| --- | --- | --- |
| `id` | string | Stable machine identifier for the check. |
| `title` | string | Human-readable result title. |
| `status` | enum | `PASS`, `FAIL`, `WARN`, or `ERROR`. |
| `severity` | enum | `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. |
| `details` | string | Human-readable evidence or evaluation explanation. |

Optional bounded fields:

| Field | Type | Purpose |
| --- | --- | --- |
| `service` | string | AWS service family such as `iam`, `s3`, or `ec2`. |
| `resourceRefs` | array | Sanitized resource references when useful and safe. |
| `evaluatedAt` | timestamp | Per-check evaluation timestamp when materially different from report generation. |
| `metadata` | object | Small rule-specific values with documented keys; not arbitrary nested evidence dumps. |

## Status semantics

- `PASS`: the check completed and the active condition was satisfied.
- `FAIL`: the check completed and found a condition requiring attention.
- `WARN`: the check completed but the result is advisory, incomplete, or below the threshold for failure.
- `ERROR`: the check could not be evaluated reliably.

An incomplete or truncated evaluation must never be represented as `PASS`.

## Summary rules

- `total` equals the number of findings.
- `passed` counts `PASS` findings.
- `failed` counts `FAIL` findings.
- `warnings` counts `WARN` findings.
- `errors` counts `ERROR` findings.
- Summary values are derived from findings, not independently authored.

## Target attribution

V1 supports the existing tool-account path only:

```json
{
  "type": "tool-account",
  "accountRef": "configured-account"
}
```

The public response must not expose the full AWS account ID or private account name.

Cross-account identifiers, role ARNs, tenant ownership, and report isolation are explicitly outside this implementation milestone. The envelope reserves a target object so those decisions can be introduced later through a new compatible contract revision.

## Compatibility policy

1. Existing unversioned reports remain readable through the current adapter.
2. New reports may add `schemaVersion: "1.0"` only after backend and frontend fixtures pass.
3. The report reader dispatches by `schemaVersion` when present.
4. Missing `schemaVersion` is treated as the legacy format, not as malformed V1.
5. V1 readers ignore unknown additive fields.
6. Removing or changing the meaning or type of a required field requires a new major schema version.
7. Adding an optional field may use a minor version only when existing readers remain correct.

## Implementation slices

### Slice 1 — Contract fixtures and validation

- Add one clean V1 report fixture.
- Add fixtures containing `FAIL`, `WARN`, and `ERROR` findings.
- Add one legacy unversioned fixture.
- Implement a small validator for required envelope and finding fields.
- Test summary derivation and invalid status handling.

### Slice 2 — Backend V1 emission

- Add the V1 envelope around the existing nine findings.
- Preserve the current check implementations and outcomes.
- Store the versioned report under the existing `reports/{scanId}.json` path.
- Do not change scanner permissions or add checks.

### Slice 3 — Frontend compatibility adapter

- Read V1 reports explicitly.
- Continue reading legacy reports.
- Preserve sanitized output and masked scan references.
- Keep raw report JSON out of the public interface.

### Slice 4 — One bounded rule descriptor

- Represent one existing check with static rule metadata outside its evaluation function.
- Prove that the outcome is unchanged.
- Stop before migrating additional checks unless the first slice demonstrates clear value and low complexity.

## Verification gates

Development:

1. Source validation passes.
2. Contract fixtures and backend tests pass.
3. Frontend builds and renders both legacy and V1 fixtures.
4. Hosted development scan completes 9/9.
5. Stored report contains `schemaVersion: "1.0"` and summary counts match findings.
6. Sanitized public output remains unchanged or intentionally improved.

Production:

1. Reviewed development baseline is promoted through a focused PR.
2. Backend and frontend deployments succeed.
3. Hosted production scan completes 9/9.
4. Stored production report validates as V1.
5. Incorrect-key and public-output sanitization regressions remain closed.

## Non-goals

This milestone does **not** include:

- a generic policy or query language;
- migration of all checks into a new rules engine;
- cross-account scanning;
- user-aware authentication;
- scan history or trend analytics;
- remediation workflows;
- broad UI redesign;
- new scanner checks;
- arbitrary nested evidence payloads.

## Risks and controls

| Risk | Control |
| --- | --- |
| Schema work becomes a rules-engine rewrite. | Implement the envelope and fixtures first; migrate at most one check descriptor in this milestone. |
| Existing reports stop rendering. | Keep the legacy adapter and test an unversioned fixture. |
| Summary counts drift from findings. | Derive summary values and test the derivation. |
| Private account identity leaks through target metadata. | Use sanitized `accountRef`; retain bundle and public-output checks. |
| Partial evaluation appears clean. | Require `WARN` or `ERROR`; never map incomplete evaluation to `PASS`. |
| Cross-account assumptions enter early. | Limit V1 implementation to `tool-account`; reserve structure without implementing ownership semantics. |

## Decision rule

Proceed when the first implementation PR is limited to contract fixtures, validation, and compatibility scaffolding.

## Kill criteria

Stop and redesign if any of the following occurs:

- the change requires replacing all nine verified checks at once;
- the schema introduces a generic expression language;
- legacy reports cannot remain readable without large branching complexity;
- target attribution requires unresolved cross-account or tenant semantics;
- the public UI must expose raw JSON or private account identity;
- hosted scan behavior changes before contract fixtures prove equivalence.

## Done criteria

The milestone is complete when:

- `schemaVersion` is explicit on new reports;
- legacy and V1 reports both render;
- summary values are derived and tested;
- all nine existing checks preserve their verified outcomes;
- development and production hosted scans complete successfully;
- one existing check can use bounded static rule metadata without changing its result;
- limitations and compatibility behavior are documented in repository source.
