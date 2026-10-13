# Connector Permission Rationale

The authoritative permission-to-check mapping is maintained in:

`docs/cross-account-permission-matrix.md`

## Allowed workload-account actions

```text
iam:GenerateCredentialReport
iam:GetCredentialReport
iam:GetAccountSummary
iam:ListUsers
iam:ListMFADevices
iam:GetAccountPasswordPolicy
cloudtrail:DescribeTrails
s3:GetAccountPublicAccessBlock
ec2:DescribeRegions
ec2:DescribeSecurityGroups
```

These ten read-only actions support only the current nine-check baseline. `ec2:DescribeRegions` discovers the AWS Regions enabled for the connected account so the existing security-group control can evaluate SSH/RDP exposure across those enabled Regions.

## Why `Resource: "*"` appears

The included actions are account-level, list, describe, or report operations that generally do not support useful individual-resource ARN scoping. Least privilege is enforced through:

- Exact actions rather than managed broad-read policies
- One exact trusted scanner-role ARN
- A connector-specific ExternalId
- `ec2:DescribeRegions` for enabled-Region discovery only
- `ec2:DescribeSecurityGroups` as a read-only query in the enabled Regions returned by AWS
- No write or remediation permissions

## STS identity verification

The scanner calls `sts:GetCallerIdentity` after role assumption to verify the actual workload account and assumed role identity. That call does not require an explicit connector-policy permission.

## Regional security-group coverage

`HomeRegion` remains `us-east-1` as the connector bootstrap/setup Region. It is not the security-group coverage boundary. At scan time, AWS Security Coach asks AWS for the Regions enabled for the connected account and evaluates the SSH/RDP security-group control in each enabled Region.

No EC2 instances, security groups, or other workload resources are created or modified by this process.

## Forbidden additions

Do not add:

- `iam:PassRole`
- `sts:AssumeRole` to the workload permissions policy
- Any create, update, delete, modify, enable, disable, start, or stop action
- Organizations discovery permissions
- Permissions for inactive or future checks
- AWS managed `SecurityAudit` or `ReadOnlyAccess` policies as a shortcut
