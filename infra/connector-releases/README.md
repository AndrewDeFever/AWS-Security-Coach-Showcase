# Connector release infrastructure

This directory owns the shared, private distribution plane for AWS Security Coach workload connector releases.

The CloudFormation stack creates one S3 bucket, `aws-security-coach-connector-releases-example`, with environment-isolated object prefixes:

- `dev/<templateVersion>/...`
- `prod/<templateVersion>/...`

Only the development publisher role is created in the current slice. It is GitHub OIDC-bound to the repository's `development` environment and can list, read, and create objects only under `dev/*`. It cannot delete release objects and cannot access `prod/*`.

The bucket is retained on stack deletion/replacement, versioned, private, BucketOwnerEnforced, TLS-only, SSE-KMS encrypted with an S3 Bucket Key, and blocks SSE-C uploads.

Deploy the stack from the `dev` branch through the `Deploy Connector Release Infrastructure` workflow. After the first deployment, copy the `DevConnectorReleasePublisherRoleArn` stack output into the development GitHub Environment variable `CONNECTOR_RELEASE_AWS_ROLE_ARN`. The `Publish Connector Release` workflow then uses only that dedicated role.

Production publication/promotion is intentionally not enabled in this slice.
