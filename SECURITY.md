# Security

AWS Security Coach is a portfolio/public derivative of a privately operated AWS security-assessment application.

This document describes the security boundaries represented by the code. It is not a security certification.

## Credential model

The application is designed so that customer AWS passwords, console credentials, and long-lived AWS access keys are not collected.

Cross-account access uses:

- a customer-deployed read-only IAM role;
- exact trust to the environment-specific scanner role;
- a connector-specific ExternalId; and
- temporary AWS STS credentials.

ExternalIds and other protected connector metadata remain server-side.

## Authentication and authorization

The frontend uses Cognito authorization-code flow with PKCE.

API Gateway validates JWT origin and audience. Backend handlers enforce application roles, connector ownership, memberships, scan authorization, and report authorization.

Browser filtering is not treated as an authorization control.

## Least privilege

The workload connector role contains read-only permissions required by the current assessment ruleset.

The hosted runner's cross-account authority is bounded to the connector role path/tag model. Connector setup and lifecycle functions have separate permissions from workload scanning.

GitHub Actions deployments use OIDC roles rather than stored AWS access keys.

## Data handling

Report artifacts are stored in private S3 buckets with Block Public Access and encryption.

Application connector metadata is stored in DynamoDB. Protected ExternalIds are stored in SSM Parameter Store.

The public repository intentionally contains no real customer reports, ExternalIds, account identifiers, private KMS key IDs, or GitHub Environment secrets.

## Fail-closed behavior

The project prefers explicit uncertainty to invented security claims.

Examples include:

- connector validation must succeed before a connector becomes scan-eligible;
- incomplete regional security-group coverage produces evaluation uncertainty rather than a clean result;
- root MFA state returns an evaluation error when the credential report cannot support a trustworthy conclusion; and
- managed report generation fails when required identity metadata is absent rather than inventing customer/account identity.

## Public deployment

Values in this repository are examples or parameters. Review `PUBLIC_CONFIGURATION.md` before deploying.

Do not commit:

- AWS access keys or session credentials;
- connector ExternalIds;
- customer account IDs or role ARNs copied from real environments;
- GitHub Environment secrets;
- Cognito tokens;
- private KMS key identifiers from another environment; or
- real report/customer evidence.

## Vulnerability reporting

This repository is provided primarily as an engineering portfolio and reference implementation.

If you discover a security issue in the public source, use GitHub's private vulnerability-reporting feature when available rather than opening an issue that contains exploit details or sensitive information.

Do not test vulnerabilities against private or hosted deployments without explicit authorization.
