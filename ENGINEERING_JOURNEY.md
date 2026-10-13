# Engineering Journey

AWS Security Coach did not begin as a finished product. It evolved through a sequence of bounded engineering problems: getting a scanner working, making deployments repeatable, replacing temporary authentication, designing safe cross-account access, introducing customer isolation, hardening runtime behavior, producing actionable reports, and finally preparing a safe public derivative.

This document reconstructs that journey from the private project's design records, implementation milestones, runtime tests, production incidents, and acceptance evidence.

> **Transparency:** this public repository is a sanitized derivative with fresh history. The timeline below documents the real engineering progression, but the public Git commit history is not intended to reproduce the private repository's original commit graph.

## Table of Contents

- [1. Starting point: prove a complete engineering loop](#1-starting-point-prove-a-complete-engineering-loop)
- [2. Building the serverless foundation](#2-building-the-serverless-foundation)
- [3. Moving from manual infrastructure to repeatable delivery](#3-moving-from-manual-infrastructure-to-repeatable-delivery)
- [4. Authentication: replacing the temporary operator gate](#4-authentication-replacing-the-temporary-operator-gate)
- [5. Designing cross-account scanning](#5-designing-cross-account-scanning)
- [6. From one pilot connector to registry-backed isolation](#6-from-one-pilot-connector-to-registry-backed-isolation)
- [7. Self-service onboarding exposed integration problems](#7-self-service-onboarding-exposed-integration-problems)
- [8. Production self-service validation](#8-production-self-service-validation)
- [9. Ruleset hardening: bounded claims over inflated coverage](#9-ruleset-hardening-bounded-claims-over-inflated-coverage)
- [10. Turning findings into useful reports](#10-turning-findings-into-useful-reports)
- [11. Production incident: missing immutable release artifact](#11-production-incident-missing-immutable-release-artifact)
- [12. Production incident: report actions unreachable on short viewports](#12-production-incident-report-actions-unreachable-on-short-viewports)
- [13. Source-control drift: when promotion history stopped matching intent](#13-source-control-drift-when-promotion-history-stopped-matching-intent)
- [14. Sanitizing the project for public review](#14-sanitizing-the-project-for-public-review)
- [15. What the project demonstrates](#15-what-the-project-demonstrates)
- [16. What remains intentionally out of scope](#16-what-remains-intentionally-out-of-scope)
- [17. Engineering principles that survived the journey](#17-engineering-principles-that-survived-the-journey)


## 1. Starting point: prove a complete engineering loop

The original goal was deliberately smaller than a full cloud security posture management platform.

The project needed to prove that a useful AWS security tool could:

- collect bounded evidence;
- identify foundational AWS security risks;
- expose findings in a hosted application;
- deploy repeatably to development and production;
- enforce least-privilege access;
- recover from bounded failures;
- preserve evidence;
- and state limitations honestly.

The scope stayed narrow on purpose. The active scanner stopped at nine controls rather than expanding into a large rule catalog without equivalent design, negative-path testing, and operational proof.

That constraint became one of the project's most important engineering habits: **complete enough to act on, honest enough to trust.**

## 2. Building the serverless foundation

The first durable architecture settled on AWS-managed, low-idle-cost components:

- CloudFront + private S3 for the hosted frontend;
- React, TypeScript, and Vite in the browser;
- API Gateway HTTP API;
- Lambda for admission, connector lifecycle, scan execution, report retrieval, and authorization-aware handlers;
- DynamoDB for scan state, admission locking, connector metadata, and memberships;
- S3 for report artifacts;
- EventBridge Scheduler for bounded recovery;
- IAM, KMS, SSM Parameter Store, and STS for security boundaries.

A scan request does not execute synchronously in the browser request path. The API admits work, persists state, and asynchronously invokes the runner.

The resulting lifecycle is intentionally simple:

```text
QUEUED -> RUNNING -> COMPLETE
                  -> FAILED
```

Server-side admission controls enforce idempotency, active-scan locking, cooldowns, bounded leases, throttling, and concurrency limits.

### Why this mattered

The project stopped being "a Lambda that calls AWS APIs" and became an operating system with state, failure handling, deployment discipline, and evidence.

## 3. Moving from manual infrastructure to repeatable delivery

Early infrastructure included manually created resources. Those were useful for proving concepts, but they were not a defensible long-term deployment model.

The project moved toward:

- one environment-aware SAM/CloudFormation source;
- isolated development and production resources;
- GitHub Actions deployments;
- environment-scoped GitHub roles;
- AWS OIDC instead of stored deployment access keys;
- source validation before deployment;
- dev-first promotion to production.

The intended release discipline became:

1. validate source;
2. deploy development;
3. verify hosted behavior;
4. promote accepted source;
5. deploy production;
6. repeat runtime verification.

Legacy console-created resources were later retired only after evidence was preserved and the replacement stacks were verified.

### Lesson

Infrastructure as Code was not treated as a checkbox. The real objective was to make the deployed state explainable, reproducible, reviewable, and removable.

## 4. Authentication: replacing the temporary operator gate

The first hosted application used a shared runtime operator secret as a temporary gate.

That was acceptable for an early development slice, but it could not provide individual identity, role attribution, clean revocation, or customer authorization.

The replacement architecture used:

- Cognito Managed Login;
- authorization-code flow with PKCE;
- in-memory access tokens in the browser;
- API Gateway JWT validation;
- backend operator/customer role enforcement;
- server-derived pseudonymous requester references.

### A useful failure

The first live Cognito-backed scan failed closed even though authentication itself had succeeded.

The group claim arrived in a JSON-style string representation that the original parser did not handle correctly. Rather than weakening authorization, the parser was fixed, redeployed, and retested.

The subsequent hosted scan completed successfully.

That incident also reinforced a logging rule: protected handlers should log only bounded request metadata, not complete events that may contain bearer tokens.

### Lesson

A successful login is not the same thing as correct authorization. Claims must be parsed, validated, and enforced at the backend boundary.

## 5. Designing cross-account scanning

The next major challenge was scanning an AWS account that did not host the application.

The connector model evolved around a customer-deployed CloudFormation role with:

- path `/aws-security-coach/`;
- tag `AWSSecurityCoachConnector=true`;
- read-only permissions required by the active ruleset;
- exact trust to the environment-specific scanner role;
- a connector-specific ExternalId.

The hosted runner retrieves protected connector metadata, calls STS `AssumeRole`, and uses temporary credentials for the assessment.

Customer AWS passwords, console credentials, and long-lived access keys are not collected.

### Negative-path proof

The cross-account trust model was tested from both directions.

The intended scanner role could assume the connector role with the correct ExternalId, while an ordinary IAM principal in the tool account could not.

That negative result was as important as the successful scan: it proved the trust policy had not accidentally granted broad tool-account access.

### Lesson

"Read-only" is not enough by itself. The trusted principal, ExternalId, role path, tags, and application authorization all matter.

## 6. From one pilot connector to registry-backed isolation

A single known connector was useful for proving the cross-account mechanics, but a real customer workflow required application-owned identity and authorization state.

The connector architecture evolved into:

- an environment-scoped connector registry;
- protected ExternalIds in SSM Parameter Store;
- pseudonymous requester references;
- connector memberships;
- operator/customer separation;
- authorized target discovery;
- server-side scan/report authorization;
- connector health and lifecycle state.

The browser never receives the protected ExternalId or temporary AWS credentials.

Connector IDs themselves are not treated as authorization.

### Retirement mattered too

Once the registry-backed path was proven, temporary pilot fallbacks and one-off IAM exceptions were removed. Post-cleanup scans were used to prove the general path worked without the old escape hatches.

### Lesson

A migration is not complete while the legacy bypass still silently keeps the new design working.

## 7. Self-service onboarding exposed integration problems

Customer onboarding introduced a multi-stage flow:

```text
Name connection
-> Review access
-> Create connector in AWS
-> Wait for AWS deployment
-> Verify connection
-> Await operator approval
```

A customer creates only their own connector, deploys the versioned CloudFormation stack, and returns the resulting connector role ARN.

Technical validation reaches `APPROVAL_PENDING`; operator approval performs fresh validation before the connector becomes `ENABLED`.

Two runtime problems were especially useful.

### Problem: target required a fresh login after approval

An already-authenticated customer initially needed to sign out and back in before the newly approved connector appeared.

The fix was not to weaken caching or authorization. The UI added bounded authorized-target refresh, and runtime testing showed the approved target appearing automatically within seconds.

### Problem: the first connector verification sometimes failed

The first submission could fail while a second click succeeded.

CloudWatch evidence showed that:

1. STS `AssumeRole` had already succeeded;
2. `iam:GenerateCredentialReport` had started;
3. `iam:GetCredentialReport` returned `ReportInProgress`.

The validation logic had confused an asynchronous AWS service state with a permission failure.

The fix accepted `ReportInProgress` as evidence that the IAM permission existed while still treating genuine `AccessDenied` and deterministic failures as fail-closed.

A fresh teardown and onboarding run then reached `APPROVAL_PENDING` on the first submission.

### Lesson

Retrying can hide a race. Logs can distinguish "permission denied" from "AWS is still doing the thing you asked it to do."

## 8. Production self-service validation

After development onboarding stabilized, the production path was exercised from a clean baseline.

The release-distribution model was also tightened so development and production used separate environment-scoped OIDC roles while sharing a private, versioned connector-release bucket.

A fresh customer identity completed:

- signup and email verification;
- access disclosure;
- CloudFormation Quick Create;
- connector role submission;
- technical verification;
- operator approval;
- authorized target discovery;
- cross-account scan.

The production assessment completed all nine checks through the generalized connector path.

The same cross-account design was later exercised against an independently owned AWS account with the owner's permission, providing additional evidence that the architecture was not coupled only to the project's own test environment.

## 9. Ruleset hardening: bounded claims over inflated coverage

The scanner remained intentionally small, but several controls were hardened to avoid overclaiming.

Examples:

### Root MFA

Root MFA is not reported as a failure when root sign-in credentials are intentionally absent.

That state is `NOT_APPLICABLE`.

If the credential report is too uncertain to support a trustworthy conclusion, the rule returns an evaluation error instead of guessing.

### Unused IAM access keys

Unused-key logic uses a 90-day baseline and distinguishes a newly created never-used key from one that has actually remained unused long enough to be meaningful.

### CloudTrail

The CloudTrail control proves **multi-Region trail presence only**.

It does not claim:

- active logging;
- successful delivery;
- event-selector coverage;
- retention;
- or complete CloudTrail configuration.

### Security groups

Connector release `1.1.0` evaluates internet-exposed SSH/RDP security groups across all AWS Regions enabled for the connected account.

Evidence is Region-qualified.

Incomplete Region coverage fails closed rather than quietly presenting a clean result.

### Lesson

A security finding is only as trustworthy as the evidence semantics behind it.

## 10. Turning findings into useful reports

The reporting layer evolved from scan output into two audiences:

- **Management** — concise posture, scope, priorities, and business-readable findings;
- **Engineering** — evidence, AWS context, remediation, cautions, verification, and references.

Managed and self-service experiences use the same normalized findings but differ in workflow context.

There are four renderers:

- managed Management;
- managed Engineering;
- self-service Management;
- self-service Engineering.

The reports intentionally avoid synthetic security scores.

They distinguish:

- evaluated controls;
- passes;
- confirmed findings;
- evaluation errors;
- and not-applicable controls.

### Deterministic browser PDFs

Managed PDF delivery was implemented in the frontend rather than by adding a server-side PDF service.

The browser builds a real PDF byte stream from the normalized report data, producing selectable text, deterministic filenames, page numbers, and the same canonical finding content displayed in the application.

One legacy connector lacked newly required managed-customer identity metadata. PDF generation failed closed rather than inventing a customer identity.

That was accepted as correct behavior.

### Lesson

Presentation logic can differ by audience, but the security truth should remain singular.

## 11. Production incident: missing immutable release artifact

The first production managed Quick Create failed.

A tempting diagnosis was that the setup path needed broader S3 permissions.

That would have been the wrong fix.

The actual problem was that the immutable production connector artifact had not been published.

The correction was to publish the missing release artifact while preserving the narrow `GetObject` / presigning model.

A proposed broad `s3:ListBucket` change was not merged.

### Lesson

**Missing artifact is a publication failure, not automatically an IAM failure.**

This incident became an important example of resisting permission broadening when the evidence points somewhere else.

## 12. Production incident: report actions unreachable on short viewports

The reports built and loaded correctly, but a production runtime check found that modal actions could become unreachable on a short browser viewport.

The root issue was layout behavior: a viewport-capped dialog combined with hidden overflow.

The fix made the modal body scrollable, and the corrected behavior was promoted and reverified.

### Lesson

A successful build is not a UI acceptance test.

Runtime verification must include realistic viewport and interaction conditions.

## 13. Source-control drift: when promotion history stopped matching intent

Later self-service PDF work exposed a repository-governance problem.

`main` and `dev` had diverged because functionality had been selectively reconstructed on `main` rather than promoted from the accepted development branch.

The important distinction was:

- the desired **source trees** needed to match;
- the production history on `main` should not be destroyed just to make the commit graphs identical.

The reconciliation used a history-preserving merge commit whose resulting tree exactly matched the canonical `dev` tree.

After merge:

- `dev` was the merge base;
- `main` remained ahead by preserved history;
- there were zero file differences.

Validation and frontend deployment completed successfully.

### Lesson

Git graph equality and source-tree equality are different requirements. Do not force-reset useful history when a history-preserving reconciliation can restore the intended source state.

## 14. Sanitizing the project for public review

Preparing this repository for public release exposed a different class of engineering problem.

The private runtime was generally environment-driven, but the source still contained environment-bound convenience values such as:

- a real KMS ARN used as a CloudFormation default;
- private CloudTrail bucket/account references;
- live deployment-domain defaults;
- private provider/contact details;
- resource names tied to the private deployment;
- CI rules that literally contained the private account ID and workstation username they were intended to reject;
- stale documentation from earlier architectural phases.

The public derivative therefore did more than redact a README.

The sanitization work:

- replaced real infrastructure identifiers with examples or parameters;
- generalized GitHub OIDC repository trust;
- replaced public-facing private identity/contact information;
- removed internal project-management and obsolete migration documents;
- refreshed stale backend/UI documentation;
- strengthened the frontend source gate to reject hard-coded 12-digit AWS account identifiers;
- added `PUBLIC_CONFIGURATION.md`, `ARCHITECTURE.md`, and `SECURITY.md`.

### CI caught sanitization mistakes

The public branch was validated through the same repository CI rather than trusted by inspection alone.

The source gate first caught literal example account IDs remaining in UI placeholders.

The fix was to use symbolic `<AWS_ACCOUNT_ID>` placeholders instead of weakening the check.

Later, CloudFormation lint caught malformed YAML introduced during sanitization. Rather than patching a broken template incrementally, the affected public templates were rebuilt from the known-good private baseline and the intended sanitization changes were reapplied.

The final sanitized tree passed:

- source/privacy gates;
- frontend build;
- sanitized bundle verification;
- backend unit tests;
- SAM validation;
- connector template verification;
- connector release infrastructure lint; and
- connector release access infrastructure lint.

### Lesson

Sanitization is a software change. It deserves compilation, linting, tests, and review just like product code.

## 15. What the project demonstrates

The strongest result is not "nine AWS checks."

It is the end-to-end engineering loop:

- constrained problem definition;
- serverless architecture;
- repeatable Infrastructure as Code;
- dev/prod isolation;
- OIDC-based CI/CD;
- user-aware authentication;
- backend authorization;
- cross-account least privilege;
- negative-path testing;
- asynchronous failure handling;
- evidence-backed scanner semantics;
- customer onboarding;
- deterministic reporting;
- production debugging;
- source-control reconciliation;
- evidence-preserving cleanup;
- and safe public release preparation.

## 16. What remains intentionally out of scope

AWS Security Coach does not claim to be:

- a complete CSPM;
- a complete AWS Well-Architected Review;
- a penetration-testing platform;
- continuous compliance;
- proactive monitoring;
- a remediation engine;
- an AWS Organizations / StackSets management platform;
- or proof that an assessed AWS account is secure.

A clean result means no findings were detected in the active ruleset at that point in time.

That boundary is intentional.

## 17. Engineering principles that survived the journey

Several principles emerged repeatedly:

**Evidence before assumption.**  
Use runtime logs, AWS state, and negative tests to determine what actually failed.

**Do not solve missing artifacts with broader permissions.**  
Authorization changes require authorization evidence.

**The browser is not an authorization boundary.**  
Identity, ownership, and membership are enforced server-side.

**Legacy paths must be removed after migration.**  
A new architecture is not proven while an old exception can still make it work.

**Uncertainty is not a pass.**  
Incomplete evidence should fail closed or surface as an evaluation error.

**Build success is not runtime acceptance.**  
Hosted flows, browser behavior, AWS integration states, and failure paths require explicit verification.

**Production history has value.**  
Source reconciliation should not destroy useful deployment history without a real reason.

**Public-safe is a higher portability standard than private-safe.**  
Non-secret account identifiers and convenience defaults can still be inappropriate in a public repository.

---

For the current implementation and trust boundaries, see [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and [PUBLIC_CONFIGURATION.md](PUBLIC_CONFIGURATION.md).
