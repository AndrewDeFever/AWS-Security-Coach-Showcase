# AWS Security Coach — Cross-Account Permission-to-Check Matrix

**Milestone:** A-010 baseline with A-016 enabled-Region SG extension  
**Status:** Approved implementation input  
**Scope:** Existing nine-check baseline only  
**Target:** One controlled workload account  
**Regional coverage:** Account-global checks plus all AWS Regions enabled for the connected account for the security-group control

## Purpose

This document maps every AWS API call used by the existing nine-check scanner to the minimum workload-account IAM permission required by the cross-account connector.

The connector role is read-only. It must not include mutation permissions, remediation permissions, `iam:PassRole`, or permission to assume additional workload-account roles.

This matrix is the source of truth for the connector permissions policy.

## Permission-to-check matrix

### 1. Root account MFA enabled

- **Check ID:** `iam-root-mfa-enabled`
- **AWS service:** IAM
- **boto3 call:** IAM credential-report evaluation
- **Required IAM actions:** `iam:GenerateCredentialReport`, `iam:GetCredentialReport`
- **Coverage:** Account-global
- **Resource scope:** `*`
- **Failure behavior:** Return `ERROR`; never infer `PASS`.

### 2. Root access keys absent

- **Check ID:** `iam-root-access-keys-absent`
- **AWS service:** IAM
- **boto3 call:** Shared credential-report loader
- **Required IAM actions:** `iam:GenerateCredentialReport`, `iam:GetCredentialReport`
- **Coverage:** Account-global
- **Resource scope:** `*`
- **Failure behavior:** Return `ERROR` if the report cannot be loaded or the root row is absent.

### 3. IAM users have MFA

- **Check ID:** `iam-users-mfa`
- **AWS service:** IAM
- **boto3 calls:** `iam.list_users()`, `iam.list_mfa_devices()`
- **Required IAM actions:** `iam:ListUsers`, `iam:ListMFADevices`
- **Coverage:** Account-global
- **Resource scope:** `*`
- **Failure behavior:** Return `ERROR`; never infer that all users have MFA.

### 4. Unused IAM access keys

- **Check ID:** `iam-unused-access-keys`
- **AWS service:** IAM
- **boto3 call:** Shared credential-report loader
- **Required IAM actions:** `iam:GenerateCredentialReport`, `iam:GetCredentialReport`
- **Coverage:** Account-global
- **Resource scope:** `*`
- **Failure behavior:** Return `ERROR`; never infer that no unused keys exist.

### 5. IAM access keys older than 90 days

- **Check ID:** `iam-old-access-keys`
- **AWS service:** IAM
- **boto3 call:** Shared credential-report loader
- **Required IAM actions:** `iam:GenerateCredentialReport`, `iam:GetCredentialReport`
- **Coverage:** Account-global
- **Resource scope:** `*`
- **Failure behavior:** Return `ERROR`; never infer that no old keys exist.

### 6. IAM password policy baseline

- **Check ID:** `iam-account-password-policy`
- **AWS service:** IAM
- **boto3 call:** `iam.get_account_password_policy()`
- **Required IAM action:** `iam:GetAccountPasswordPolicy`
- **Coverage:** Account-global
- **Resource scope:** `*`
- **Failure behavior:** `NoSuchEntity` is a valid `FAIL`; other errors return `ERROR`.

### 7. Multi-region CloudTrail trail exists

- **Check ID:** `cloudtrail-multi-region`
- **AWS service:** CloudTrail
- **boto3 call:** `cloudtrail.describe_trails(includeShadowTrails=False)`
- **Required IAM action:** `cloudtrail:DescribeTrails`
- **Coverage:** Account-level through the configured bootstrap endpoint
- **Resource scope:** `*`
- **Failure behavior:** Return `ERROR`; never infer a trail exists.

### 8. S3 account-level Block Public Access

- **Check ID:** `s3-account-public-access-block`
- **AWS services:** STS and S3 Control
- **boto3 calls:** `sts.get_caller_identity()`, `s3control.get_public_access_block()`
- **Required IAM action:** `s3:GetAccountPublicAccessBlock`
- **Coverage:** Account-level
- **Resource scope:** `*`
- **Failure behavior:** Missing configuration is `FAIL`; other errors return `ERROR`.

`sts:GetCallerIdentity` is used for identity verification but does not require an explicit connector-policy permission.

### 9. Security groups expose SSH or RDP publicly

- **Check ID:** `ec2-security-groups-open-admin-ports`
- **AWS service:** EC2
- **boto3 calls:** `ec2.describe_regions(AllRegions=False)`, then `ec2.describe_security_groups()` in each enabled Region
- **Required IAM actions:** `ec2:DescribeRegions`, `ec2:DescribeSecurityGroups`
- **Coverage:** Every AWS Region enabled for the connected account
- **Resource scope:** `*`
- **Failure behavior:** A confirmed exposure remains `FAIL`. If no exposure is confirmed but one or more enabled Regions cannot be evaluated, return `ERROR`; never infer all-region compliance from partial coverage.

## Shared credential-report dependency

The following checks share one IAM credential-report retrieval:

1. Root MFA state
2. Root access keys absent
3. Unused IAM access keys
4. IAM access keys older than 90 days

The report is account-global and point-in-time.

## Approved connector permissions policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadIamAccountPosture",
      "Effect": "Allow",
      "Action": [
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:GetAccountPasswordPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadCloudTrailPosture",
      "Effect": "Allow",
      "Action": "cloudtrail:DescribeTrails",
      "Resource": "*"
    },
    {
      "Sid": "ReadS3AccountPublicAccessConfiguration",
      "Effect": "Allow",
      "Action": "s3:GetAccountPublicAccessBlock",
      "Resource": "*"
    },
    {
      "Sid": "DiscoverEnabledRegionsAndSecurityGroups",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

## Permission inventory

| Service | Actions |
|---|---|
| IAM | `iam:GenerateCredentialReport` |
| IAM | `iam:GetCredentialReport` |
| IAM | `iam:GetAccountSummary` |
| IAM | `iam:ListUsers` |
| IAM | `iam:ListMFADevices` |
| IAM | `iam:GetAccountPasswordPolicy` |
| CloudTrail | `cloudtrail:DescribeTrails` |
| S3 | `s3:GetAccountPublicAccessBlock` |
| EC2 | `ec2:DescribeRegions` |
| EC2 | `ec2:DescribeSecurityGroups` |

**Total permission-bearing actions:** 10

## Explicit exclusions

The connector role must not include:

- Any `Create`, `Put`, `Update`, `Delete`, `Modify`, `Start`, `Stop`, `Enable`, or `Disable` action
- `iam:PassRole`
- `sts:AssumeRole` to the workload permissions policy
- IAM policy mutation actions
- CloudTrail mutation actions
- S3 bucket or account public-access mutation actions
- EC2 security-group mutation actions
- Organization-wide discovery permissions
- Permissions for inactive or future checks

## Regional boundary

`HomeRegion` remains `us-east-1` as the connector bootstrap/setup Region. It is not a security-group coverage boundary for connector template version 1.1.0 and later.

For those connector versions, the scanner discovers Regions enabled for the connected account with `DescribeRegions` and evaluates the existing SSH/RDP security-group rule in each enabled Region. The result remains one aggregated control finding.

Connector template 1.0.0 retains its original `us-east-1`-only security-group permission and runtime behavior. This preserves the immutable 1.0.0 release and prevents an older connector from being asked to perform reads it was never granted.

No EC2 instances, security groups, or other workload resources are created or modified.

## Required failure semantics

Permission denial, throttling, endpoint failure, malformed responses, and unavailable account data must produce an explicit incomplete-coverage result.

For the multi-Region security-group control:

- confirmed public SSH/RDP exposure is `FAIL`, even if another Region is unavailable;
- no confirmed exposure plus incomplete regional coverage is `ERROR`;
- `PASS` requires successful evaluation of every enabled Region returned by AWS.

An incomplete check must never be converted into `PASS`, "No resources found," "No exposure found," or "Configuration compliant."
