"""Deterministic customer-report guidance for the nine-check baseline.

This module enriches evaluated findings after scan execution. It does not change
rule evaluation, severity decisions, AWS permissions, or scan lifecycle behavior.
All AWS references are first-party documentation and all framework language is
bounded to the Security Pillar context represented by the current checks.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

GUIDANCE_VERSION = "1.1"

ASSESSMENT_TITLE = "AWS Security Posture Review"
FRAMEWORK_DISCLAIMER = "This is NOT a complete AWS Well-Architected Review."
SCOPE_STATEMENT = (
    "This assessment evaluates selected foundational AWS security controls informed "
    "by AWS security guidance and the Security Pillar of the AWS Well-Architected Framework."
)

SECURITY_PILLAR_REFERENCE = (
    "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/security.html"
)


def _reference(title: str, url: str) -> dict[str, str]:
    return {"title": title, "url": url}


GUIDANCE_BY_CHECK_ID: dict[str, dict[str, Any]] = {
    "iam-root-mfa-enabled": {
        "awsSecurityArea": "Identity and access management",
        "awsDesignPrinciple": "Implement a strong identity foundation",
        "awsBestPracticeContext": (
            "Protect the AWS account root user with MFA and reserve root credentials "
            "for tasks that specifically require them."
        ),
        "customerRisk": (
            "Without MFA, the root password is the primary barrier protecting the account's "
            "highest-privilege identity. If that password is obtained through phishing, credential "
            "reuse, guessing, or another compromise path, an unauthorized party could gain broad "
            "account-level access. MFA adds an independent control that materially reduces the risk "
            "of a password-only compromise."
        ),
        "remediationEffort": "LOW",
        "remediation": (
            "Register MFA for the AWS account root user. Prefer a phishing-resistant "
            "passkey or security key where practical, and restrict routine root-user use."
        ),
        "verificationCriteria": (
            "When root sign-in credentials are present, the AWS account root user has an active MFA device. "
            "If root sign-in credentials are intentionally absent through centralized root access, this control is not applicable."
        ),
        "awsReference": _reference(
            "Root user best practices for your AWS account",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html",
        ),
    },
    "iam-root-access-keys-absent": {
        "awsSecurityArea": "Identity and access management",
        "awsDesignPrinciple": "Implement a strong identity foundation",
        "awsBestPracticeContext": (
            "AWS strongly recommends not creating access keys for the root user. "
            "Use roles or other temporary credentials for programmatic access instead."
        ),
        "customerRisk": (
            "Root access keys are long-term credentials tied to the account's most privileged identity. "
            "If copied from a workstation, repository, backup, log, or other storage location, they can "
            "be used programmatically until revoked and may permit broad changes or data access. Their "
            "existence increases exposure even when they are not part of normal operations."
        ),
        "remediationEffort": "MEDIUM",
        "remediation": (
            "Identify any dependency on root access keys, migrate that access to an IAM "
            "role or other temporary-credential mechanism, then deactivate and delete the root keys."
        ),
        "verificationCriteria": "The AWS account root user has no active access keys.",
        "awsReference": _reference(
            "Root user best practices for your AWS account",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html",
        ),
    },
    "iam-users-mfa": {
        "awsSecurityArea": "Identity and access management",
        "awsDesignPrinciple": "Implement a strong identity foundation",
        "awsBestPracticeContext": (
            "Require MFA for human identities that authenticate to AWS. AWS recommends "
            "federation and temporary credentials where possible."
        ),
        "customerRisk": (
            "An IAM user without MFA can be authenticated with a password alone. That makes phishing, "
            "credential stuffing, password spraying, or password reuse more consequential because a "
            "successful password compromise can become console access. The resulting impact depends on "
            "that user's permissions; MFA provides an additional barrier even when a password is exposed."
        ),
        "remediationEffort": "MEDIUM",
        "remediation": (
            "Enable MFA for affected IAM users. Where practical, move human access to "
            "IAM Identity Center or another federated identity provider using temporary credentials."
        ),
        "verificationCriteria": (
            "Every retained human IAM user that can sign in to the AWS console has an MFA device assigned; "
            "IAM users that are no longer required are removed through the normal offboarding process."
        ),
        "awsReference": _reference(
            "Security best practices in IAM",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        ),
    },
    "iam-unused-access-keys": {
        "awsSecurityArea": "Identity and access management",
        "awsDesignPrinciple": "Implement a strong identity foundation",
        "awsBestPracticeContext": (
            "Regularly review and remove credentials that are no longer needed, and prefer "
            "temporary credentials over long-term IAM user access keys."
        ),
        "customerRisk": (
            "Unused active access keys create an authentication path that provides no current business "
            "value. Forgotten credentials can remain in old scripts, developer machines, backups, or "
            "repositories; if one is later exposed, it may still work while attracting less operational "
            "attention than an actively managed credential. Removing it eliminates that unnecessary path."
        ),
        "remediationEffort": "LOW",
        "remediation": (
            "Confirm the affected access keys are not required, deactivate them, monitor for "
            "unexpected dependency failures, and delete them when safe. Replace long-term keys "
            "with roles or temporary credentials where possible."
        ),
        "verificationCriteria": (
            "No active IAM user access key has been unused for 90 days or more. Never-used keys younger than "
            "90 days remain below this assessment threshold."
        ),
        "awsReference": _reference(
            "Find unused AWS credentials",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html",
        ),
    },
    "iam-old-access-keys": {
        "awsSecurityArea": "Identity and access management",
        "awsDesignPrinciple": "Implement a strong identity foundation",
        "awsBestPracticeContext": (
            "Audit and rotate long-term credentials regularly. AWS Well-Architected guidance "
            "recommends rotating long-term IAM access keys at least every 90 days when temporary "
            "credentials cannot be used."
        ),
        "customerRisk": (
            "The longer an access key remains valid, the more opportunity there is for copies to persist "
            "in code, configuration, logs, backups, or developer environments. If an old copy is exposed, "
            "it can remain useful to an unauthorized party until the key is rotated or revoked. Rotation "
            "limits that credential lifetime; temporary credentials reduce the exposure further."
        ),
        "remediationEffort": "MEDIUM",
        "remediation": (
            "Prefer replacing the affected long-term keys with temporary credentials. If the keys "
            "must remain, rotate them safely by introducing a new key, updating dependencies, "
            "verifying use of the new key, and then deactivating and deleting the old key."
        ),
        "verificationCriteria": "No active IAM user access key is older than the 90-day assessment baseline.",
        "awsReference": _reference(
            "SEC02-BP05 Audit and rotate credentials periodically",
            "https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_identities_audit.html",
        ),
    },
    "iam-account-password-policy": {
        "awsSecurityArea": "Identity and access management",
        "awsDesignPrinciple": "Implement a strong identity foundation",
        "awsBestPracticeContext": (
            "Where IAM user passwords remain in use, configure an account password policy that "
            "matches organizational requirements and combine strong passwords with MFA."
        ),
        "customerRisk": (
            "A weak or absent IAM password policy can allow shorter, simpler, or repeatedly reused "
            "passwords. Those choices are generally more susceptible to password guessing, password "
            "spraying, credential-reuse attacks, or recovery if the same credential is exposed elsewhere. "
            "This finding does not mean an account has been compromised; it means an important layer of "
            "resistance to password-based attacks is below the assessed baseline. MFA remains an important "
            "additional safeguard for human identities."
        ),
        "remediationEffort": "LOW",
        "remediation": (
            "Review the reported policy gaps and configure the IAM account password policy to meet "
            "the assessed baseline: minimum length 14, uppercase, lowercase, number and symbol "
            "requirements, password reuse prevention, and a maximum password age. Also require MFA "
            "for human identities."
        ),
        "verificationCriteria": (
            "IAM Account settings show a minimum password length of 14 or greater, uppercase, lowercase, "
            "number, and symbol requirements enabled, password reuse prevention configured, and a maximum password age configured."
        ),
        "awsReference": _reference(
            "Set an account password policy for IAM users",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
        ),
    },
    "cloudtrail-multi-region": {
        "awsSecurityArea": "Detection",
        "awsDesignPrinciple": "Maintain traceability",
        "awsBestPracticeContext": (
            "Create a multi-Region CloudTrail trail to maintain an ongoing record of activity "
            "across all enabled AWS Regions."
        ),
        "customerRisk": (
            "Without a multi-Region trail, API activity in Regions outside the trail's coverage may be "
            "missing from the organization's ongoing audit record. That does not imply suspicious activity "
            "is occurring, but it can create a visibility gap that slows detection, investigation, and "
            "incident reconstruction if unauthorized or accidental changes occur in an uncovered Region."
        ),
        "remediationEffort": "MEDIUM",
        "remediation": (
            "Create a new multi-Region CloudTrail trail or convert an appropriate existing trail "
            "to multi-Region coverage. Protect the destination logs according to organizational "
            "logging and retention requirements."
        ),
        "verificationCriteria": "At least one CloudTrail trail is configured as a multi-Region trail.",
        "awsReference": _reference(
            "Security best practices in AWS CloudTrail",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html",
        ),
    },
    "s3-account-public-access-block": {
        "awsSecurityArea": "Data protection",
        "awsDesignPrinciple": "Protect data in transit and at rest",
        "awsBestPracticeContext": (
            "Use Amazon S3 Block Public Access controls at the account level to provide a broad "
            "guardrail against unintended public access to S3 resources."
        ),
        "customerRisk": (
            "Missing account-level Block Public Access does not mean the account currently has a public "
            "bucket. It means an important preventive guardrail is absent, so a later bucket policy, ACL, "
            "or access-point configuration mistake has a greater chance of making S3 data publicly "
            "reachable. Depending on the data involved, that could lead to unintended disclosure of "
            "customer, operational, or proprietary information."
        ),
        "remediationEffort": "LOW",
        "remediation": (
            "Review workloads that intentionally require public S3 access, then enable the four "
            "account-level Block Public Access settings where compatible: BlockPublicAcls, "
            "IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets."
        ),
        "verificationCriteria": (
            "All four effective account-level S3 Block Public Access settings are enabled: BlockPublicAcls, "
            "IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets."
        ),
        "awsReference": _reference(
            "Configuring block public access settings for your account",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-block-public-access-account.html",
        ),
    },
    "ec2-security-groups-open-admin-ports": {
        "awsSecurityArea": "Infrastructure protection",
        "awsDesignPrinciple": "Apply security at all layers",
        "awsBestPracticeContext": (
            "Restrict administrative network access to trusted sources. AWS security controls treat "
            "unrestricted ingress from 0.0.0.0/0 or ::/0 to SSH (22) and RDP (3389) as high-risk exposure."
        ),
        "customerRisk": (
            "Internet-wide SSH or RDP exposure makes administrative services reachable by anyone on the "
            "internet, including automated scanners that continuously probe for weak credentials and "
            "vulnerable services. This does not mean a host has been compromised, but it increases exposure "
            "to brute-force attempts, credential attacks, software exploitation, and unauthorized remote "
            "administration compared with restricting access to trusted networks or private management paths."
        ),
        "remediationEffort": "LOW",
        "remediation": (
            "Remove unrestricted SSH/RDP ingress rules and limit administration to explicitly trusted "
            "CIDR ranges or private access paths such as VPN, bastion, or Systems Manager Session Manager, "
            "as appropriate for the workload."
        ),
        "verificationCriteria": (
            "Within the assessment's stated security-group Region scope, no security group permits SSH (22) or "
            "RDP (3389) from 0.0.0.0/0 or ::/0."
        ),
        "awsReference": _reference(
            "Security Hub CSPM controls for Amazon EC2",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html",
        ),
    },
}


class GuidanceMappingError(ValueError):
    """Raised when a report finding has no approved customer-report mapping."""


def build_assessment_profile(check_count: int) -> dict[str, Any]:
    if check_count <= 0:
        raise GuidanceMappingError("assessment check count must be positive")

    return {
        "title": ASSESSMENT_TITLE,
        "assessmentType": "point-in-time",
        "accessModel": "read-only",
        "scopeStatement": SCOPE_STATEMENT,
        "frameworkDisclaimer": FRAMEWORK_DISCLAIMER,
        "frameworkContext": {
            "framework": "AWS Well-Architected Framework",
            "pillar": "Security",
            "referenceUrl": SECURITY_PILLAR_REFERENCE,
        },
        "controlCount": check_count,
        "guidanceVersion": GUIDANCE_VERSION,
    }


def enrich_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return copied findings enriched with the approved deterministic guidance."""
    enriched: list[dict[str, Any]] = []

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise GuidanceMappingError(f"findings[{index}] must be an object")

        check_id = str(finding.get("id", "")).strip()
        if not check_id:
            raise GuidanceMappingError(f"findings[{index}] is missing a check id")

        guidance = GUIDANCE_BY_CHECK_ID.get(check_id)
        if guidance is None:
            raise GuidanceMappingError(
                f"finding {check_id!r} has no approved customer-report guidance mapping"
            )

        item = deepcopy(finding)
        item["guidance"] = deepcopy(guidance)
        enriched.append(item)

    return enriched
