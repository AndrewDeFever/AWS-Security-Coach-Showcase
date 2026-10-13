# Public Deployment Configuration

This sanitized repository is intended to demonstrate the AWS Security Coach architecture without publishing identifiers from the private working environment.

Before deploying a copy, replace or configure the environment-specific values below. Do not commit real credentials, ExternalIds, access keys, passwords, or other secrets.

## Placeholder values in source

| Placeholder | Replace with |
| --- | --- |
| `123456789012` | Your AWS account ID where an example ARN or bucket name requires an account component |
| `arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000000` | A customer-managed KMS key ARN in the deployment account |
| `https://dev.example.invalid` | Development frontend origin |
| `https://prod.example.invalid` | Production frontend origin |
| `aws-security-coach-connector-releases-example` | A globally unique private S3 bucket for immutable connector release artifacts |
| `aws-cloudtrail-logs-123456789012-example` | The CloudTrail log bucket used by the optional tool-account lifecycle helper |

The example values are intentionally non-production placeholders.

## GitHub Environment configuration

The workflows use GitHub OIDC and expect separate `development` and `production` GitHub Environments.

Configure the variables referenced by the workflows, including:

- `BACKEND_AWS_ROLE_ARN`
- `BACKEND_STACK_NAME`
- `AWS_ROLE_ARN`
- `S3_BUCKET`
- `CLOUDFRONT_DISTRIBUTION_ID`
- `VITE_API_BASE_URL`
- `VITE_COGNITO_DOMAIN`
- `VITE_COGNITO_AUTHORITY`
- `VITE_COGNITO_CLIENT_ID`
- `VITE_COGNITO_REDIRECT_URI`
- `VITE_COGNITO_LOGOUT_URI`
- `CONNECTOR_RELEASE_AWS_ROLE_ARN`
- `CONNECTOR_RELEASE_INFRA_AWS_ROLE_ARN`

Use environment-specific roles and values. The repository intentionally does not contain the private project's GitHub Environment values.

## AWS connector boundary

Customer/workload access is designed around a customer-deployed read-only CloudFormation role, connector-specific ExternalId, and short-lived STS credentials.

Never replace this model with stored customer access keys. Do not commit generated ExternalIds or connector registry data.

## Public-repository boundary

The public derivative must not contain:

- real AWS account IDs from the private project or external test accounts;
- private KMS key IDs or ARNs;
- live customer connector identifiers, ExternalIds, role ARNs, or report payloads;
- private Google Drive/project-management links;
- customer names or report artifacts;
- local usernames or workstation-specific identifiers;
- GitHub Environment secrets or variables from the private repository.

The private repository and private scan-evidence archive remain the source of truth for runtime acceptance evidence.
