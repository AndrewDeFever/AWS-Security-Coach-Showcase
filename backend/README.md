# AWS Security Coach Backend

The backend is an environment-aware AWS SAM application that provides authentication-aware scan admission, connector lifecycle APIs, asynchronous scan execution, report retrieval, and the server-side authorization boundaries used by AWS Security Coach.

## Architecture

Key AWS services:

- API Gateway HTTP API with Cognito/JWT authorization
- Lambda for connector management, scan admission, scan execution, status, and report retrieval
- DynamoDB for scans, connector registry, memberships, and admission state
- S3 for versioned report artifacts
- SSM Parameter Store for protected connector ExternalIds
- AWS STS for short-lived cross-account connector sessions
- EventBridge Scheduler for bounded queued-work recovery and stale-run handling
- KMS for protected application data

`backend/template.yaml` is the authoritative SAM template for development and production.

## Authorization boundary

The browser is not an authorization source.

Protected handlers use validated JWT claims and server-side application state to enforce:

- operator/customer role separation;
- requester-to-connector ownership and membership;
- target discovery authorization;
- connector lifecycle authorization;
- scan creation/read authorization; and
- report authorization.

Cross-account workload access uses connector-specific ExternalIds and short-lived STS credentials. Customer AWS passwords, console credentials, and long-lived access keys are not part of the connector model.

## Scan execution

A scan request is admitted through server-side DynamoDB conditions and asynchronously invokes the runner. The runner executes the bounded posture ruleset and writes normalized report data to S3.

Typical state flow:

```text
QUEUED -> RUNNING -> COMPLETE
                  -> FAILED
```

Admission controls include idempotency, active-work locking, cooldowns, bounded leases, API throttling, and Lambda concurrency controls.

## Validation

From `backend/`:

```bash
python scripts/prepare_jwt_template.py
sam validate --lint --template-file template.generated.yaml
python -m unittest discover -s tests -p 'test_*.py'
sam build --template-file template.generated.yaml
```

CI performs the same source and infrastructure checks before deployment.

## Deployment

GitHub Actions uses AWS OIDC rather than stored AWS access keys. Development and production use separate GitHub Environments and deployment roles.

The intended release discipline is:

1. validate source;
2. deploy and verify development;
3. complete runtime acceptance for the changed behavior;
4. promote accepted source to `main`;
5. deploy and verify production.

See `../PUBLIC_CONFIGURATION.md` for the values that must be supplied in a public deployment.
