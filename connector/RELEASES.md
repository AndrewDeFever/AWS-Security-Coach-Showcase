# Connector releases

Published workload-account connector templates live under `connector/releases/<templateVersion>/`.

Each release directory contains:

- `template.yaml` — the exact CloudFormation template customers install for that template version.
- `manifest.json` — release metadata, including the template version and compatible connector runtime version.

## Publication rules

1. A published release is immutable. Existing files under a published version directory must never be modified, deleted, renamed, or extended.
2. A changed connector template requires a new semantic `templateVersion` and a new release directory.
3. `connector/template.yaml` is the working/current template and must be byte-identical to the published release matching the version declared in its `Metadata.AWSSecurityCoach.ConnectorTemplateVersion` field.
4. Historical scan reports retain the exact `templateVersion` and `connectorVersion` that executed. Release publication must never rewrite that historical truth.
5. Release artifacts must not contain connector-specific secrets, ExternalIds, customer account IDs, or environment-specific role ARNs.
6. Repository release `1.0.0` is already published and remains byte-for-byte immutable; checksum metadata must not be retrofitted into that release directory.

## Distribution

Release artifacts are distributed from the private IaC-managed S3 bucket `aws-security-coach-connector-releases-example`.

Environment publication uses isolated prefixes:

- development: `dev/<templateVersion>/template.yaml` and `dev/<templateVersion>/manifest.json`
- production: `prod/<templateVersion>/template.yaml` and `prod/<templateVersion>/manifest.json`

The development publisher is allowed to read and create objects only under `dev/*`; it has no delete permission and no production-prefix permission. Publication computes SHA-256 for each source artifact, uploads with an S3 SHA-256 checksum, downloads the object again, and requires byte-identical and SHA-256-identical verification. An existing non-identical object causes publication to fail rather than overwrite the release.

The `Connector Release Immutability` GitHub Actions workflow rejects changes to an already published release directory. Source tests verify version coherence between the working template and the corresponding published artifact.

For the next newly created release after `1.0.0`, evolve the manifest schema to carry an explicit artifact SHA-256 value at release-creation time. Do not alter `1.0.0` to backfill it.
