"""Attach deterministic engineering runbooks and final report correctness metadata.

This is the final enrichment boundary for customer-facing guidance. It preserves the
shared nine-control security truth while making remediation and AWS-side success
criteria explicit, safe, and independent of a product rerun.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from engineering_guidance import ENGINEERING_REMEDIATION_BY_CHECK_ID

ENGINEERING_GUIDANCE_VERSION = "1.1"

AWS_END_STATE_BY_CHECK_ID: dict[str, str] = {
    "iam-root-mfa-enabled": (
        "When root sign-in credentials are present, the AWS account root user has an active MFA device. "
        "If root sign-in credentials are intentionally absent through centralized root access, this control is not applicable."
    ),
    "iam-root-access-keys-absent": "The AWS account root user has no active access keys.",
    "iam-users-mfa": (
        "Every retained human IAM user that can sign in to the AWS console has an MFA device assigned; "
        "IAM users that are no longer required are removed through the normal offboarding process."
    ),
    "iam-unused-access-keys": (
        "No active IAM user access key has been unused for 90 days or more. Never-used keys younger than "
        "90 days remain below this assessment threshold."
    ),
    "iam-old-access-keys": "No active IAM user access key is older than the 90-day assessment baseline.",
    "iam-account-password-policy": (
        "IAM Account settings show a minimum password length of 14 or greater, uppercase, lowercase, number, "
        "and symbol requirements enabled, password reuse prevention configured, and a maximum password age configured."
    ),
    "cloudtrail-multi-region": "At least one CloudTrail trail is configured as a multi-Region trail.",
    "s3-account-public-access-block": (
        "All four effective account-level S3 Block Public Access settings are enabled: BlockPublicAcls, "
        "IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets."
    ),
    "ec2-security-groups-open-admin-ports": (
        "Within the assessment's stated security-group Region scope, no security group permits SSH (22) or "
        "RDP (3389) from 0.0.0.0/0 or ::/0."
    ),
}


class EngineeringGuidanceError(ValueError):
    """Raised when a finding cannot be mapped to approved report guidance."""


def _correct_runbook(check_id: str, runbook: dict[str, Any]) -> dict[str, Any]:
    corrected = deepcopy(runbook)

    if check_id == "iam-account-password-policy":
        corrected["prerequisites"] = [
            "Confirm you have permission to view and change the IAM account password policy.",
            "Capture the complete current password policy in IAM Account settings or with aws iam get-account-password-policy before changing it.",
            "Identify IAM users that still sign in with IAM passwords and review any organizational password requirements that are stricter than this assessment baseline.",
        ]
        corrected["steps"] = [
            "Open IAM Account settings and compare the complete current Password policy with the assessment baseline and any stricter organizational requirements.",
            "Record every current password-policy setting before making a change so an intentional setting is not accidentally reset.",
            "Choose Edit password policy and set the minimum password length to at least 14 characters.",
            "Require uppercase letters, lowercase letters, numbers, and non-alphanumeric symbols.",
            "Enable password reuse prevention with a value greater than zero; use the organization's required history value if it is stricter.",
            "Set a maximum password age greater than zero according to organizational policy. The assessment baseline requires that a maximum age be configured but does not prescribe a specific number of days.",
            "Review the complete resulting policy, including settings such as whether users may change their own passwords and hard expiry, then save only after every intended setting is explicit.",
            "Confirm the intended values are active and continue to require MFA for human identities.",
        ]
        corrected["cliCommands"] = [
            {
                "label": "Inspect the complete current IAM password policy before any CLI update",
                "command": "aws iam get-account-password-policy",
            },
        ]
        corrected["cautions"] = [
            "AWS UpdateAccountPasswordPolicy does not support partial updates. Any parameter omitted from an update reverts to its AWS default value, so do not use a shortened update command as though it patches only selected settings.",
            "If you use the AWS CLI to update the policy, explicitly define the complete intended policy state, including boolean choices such as whether users may change their own passwords and hard expiry. The console procedure above is safer when those choices have not already been decided.",
            "Password-policy changes affect IAM users that authenticate with IAM passwords. When a maximum password age is introduced, users whose current passwords are already older than that threshold can be required to change them at their next sign-in.",
            "Coordinate changes that may force password updates or disrupt established access procedures, and do not weaken a stricter organizational policy merely to match this baseline.",
        ]

    if check_id == "s3-account-public-access-block":
        corrected["steps"][0] = (
            "Open S3 Account and organization settings and review the four effective account-level Block Public Access settings."
        )

    if check_id == "cloudtrail-multi-region":
        corrected["verificationSteps"] = [
            "Confirm CloudTrail shows at least one trail configured for multi-Region coverage; this is the AWS state required by the assessed control.",
            "As additional operational hardening, confirm the selected trail is actively logging and recent log files are arriving at the intended destination.",
            "Confirm management-event configuration, retention, and downstream consumers meet the organization's logging requirements; these additional states are not verified by the current assessment control.",
        ]

    return corrected


def enrich_engineering_guidance(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise EngineeringGuidanceError(f"findings[{index}] must be an object")

        check_id = str(finding.get("id", "")).strip()
        runbook = ENGINEERING_REMEDIATION_BY_CHECK_ID.get(check_id)
        if runbook is None:
            raise EngineeringGuidanceError(
                f"finding {check_id!r} has no approved engineering remediation mapping"
            )

        verification_criteria = AWS_END_STATE_BY_CHECK_ID.get(check_id)
        if verification_criteria is None:
            raise EngineeringGuidanceError(
                f"finding {check_id!r} has no approved AWS end-state verification mapping"
            )

        guidance = finding.get("guidance")
        if not isinstance(guidance, dict):
            raise EngineeringGuidanceError(
                f"finding {check_id!r} must have customer guidance before engineering enrichment"
            )

        item = deepcopy(finding)
        item["guidance"]["verificationCriteria"] = verification_criteria
        item["guidance"]["engineeringRemediation"] = _correct_runbook(check_id, runbook)
        enriched.append(item)

    return enriched
