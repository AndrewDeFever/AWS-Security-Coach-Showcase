"""Deterministic engineering remediation runbooks for the nine-check baseline.

The runbooks contain AWS-native remediation and verification only. Delivery-specific
follow-up belongs to the managed or self-service report renderer so the remediation
truth stays shared across both products.
"""

from __future__ import annotations

from typing import Any


ENGINEERING_REMEDIATION_BY_CHECK_ID: dict[str, dict[str, Any]] = {
    "iam-root-mfa-enabled": {
        "objective": "Protect the AWS account root user with multi-factor authentication when root sign-in credentials are present.",
        "consolePath": "AWS account menu → Security credentials → Multi-factor authentication (MFA)",
        "prerequisites": [
            "Confirm whether the account currently has usable root sign-in credentials. If root credentials were intentionally removed through AWS Organizations centralized root access, do not recreate them solely for this procedure.",
            "If root sign-in credentials are present, confirm you can sign in as root and have an approved MFA device or phishing-resistant authenticator ready.",
        ],
        "steps": [
            "Confirm the account has usable root sign-in credentials. If root credentials have intentionally been removed through AWS Organizations centralized root access, do not recreate them solely to satisfy this procedure; escalate the finding for assessment review.",
            "If root sign-in credentials are present, sign in to the AWS Management Console as the root user and open Security credentials.",
            "Locate Multi-factor authentication (MFA) and choose the option to assign or register an MFA device.",
            "Select the approved device type and complete the AWS registration challenge.",
            "Confirm the MFA device appears as active, then perform a controlled sign-in to verify the password and MFA challenge both work.",
            "Return to delegated IAM or federated identities for normal administration and reserve root use for tasks that require it.",
        ],
        "cliCommands": [],
        "cautions": [
            "Do not recreate root sign-in credentials on an Organizations member account when centralized root access intentionally removed them.",
            "Do not disable or replace a working root MFA device until the replacement is confirmed usable.",
        ],
        "verificationSteps": [
            "If root sign-in credentials are present, confirm the root-user Security credentials page shows an active MFA device.",
            "Perform a controlled root sign-in and confirm AWS requires the registered MFA factor.",
        ],
    },
    "iam-root-access-keys-absent": {
        "objective": "Remove long-term programmatic credentials from the AWS account root user.",
        "consolePath": "AWS account menu → Security credentials → Access keys",
        "prerequisites": [
            "Confirm you can access the root-user Security credentials page if root credentials are present.",
            "Identify any application, script, integration, or operator workflow that may still depend on a root access key.",
            "Choose the delegated replacement access method—such as an IAM role, workload role, IAM Identity Center, or another temporary-credential mechanism—before retiring the root key.",
        ],
        "steps": [
            "Identify every active root access key shown in the root-user Security credentials page.",
            "Trace any remaining dependency using application configuration, secret stores, deployment systems, and relevant access logs before changing a key.",
            "Create or select the least-privilege IAM role or other temporary-credential mechanism that will replace the root credential.",
            "Update each confirmed dependency and verify the workload or administrative task succeeds without the root key.",
            "Deactivate the root access key, monitor for missed dependencies, then delete the key once replacement use is confirmed.",
            "Repeat the procedure for any second root access key.",
        ],
        "cliCommands": [],
        "cautions": [
            "Do not delete a root access key merely because it is unexpected; first determine whether a production dependency still uses it.",
            "Do not create a new root access key as the long-term replacement.",
        ],
        "verificationSteps": [
            "Confirm the root-user Security credentials page lists no active root access keys.",
            "Confirm replacement workloads and administrative procedures still operate through delegated identities.",
        ],
    },
    "iam-users-mfa": {
        "objective": "Require a second authentication factor for each retained human IAM user detected without MFA.",
        "consolePath": "IAM → Users → <user> → Security credentials → Multi-factor authentication (MFA)",
        "prerequisites": [
            "Confirm you have permission to manage MFA devices for the affected IAM users.",
            "Review each listed IAM user and confirm whether the identity is still required and belongs to a human user.",
            "For each retained user, have an approved MFA device or authenticator available before enrollment.",
        ],
        "steps": [
            "Use the finding evidence to identify every IAM user reported without MFA.",
            "For each user, first decide whether the IAM user should still exist. Remove obsolete users through the normal offboarding process rather than enrolling unnecessary identities.",
            "For each retained human user, open the user's Security credentials tab and assign an MFA device.",
            "Complete the AWS enrollment challenge with the user or identity owner and confirm the MFA device appears on the Security credentials page.",
            "Have the user perform a controlled console sign-in and confirm AWS requires the MFA challenge.",
            "Where practical, plan migration of long-lived IAM-user console access to IAM Identity Center or another federated identity provider using temporary sessions.",
        ],
        "cliCommands": [],
        "cautions": [
            "Coordinate MFA enrollment with the user so the account is not left without a usable authentication method.",
            "Enabling MFA does not reduce excessive IAM permissions; review authorization separately where required.",
        ],
        "verificationSteps": [
            "Confirm each retained IAM user identified by the finding has an MFA device assigned, or confirm the obsolete user was removed.",
            "Perform a controlled sign-in for retained human users and confirm the MFA challenge is required.",
        ],
    },
    "iam-unused-access-keys": {
        "objective": "Remove active IAM access keys that no longer provide required business functionality.",
        "consolePath": "IAM → Users → <user> → Security credentials → Access keys",
        "prerequisites": [
            "Use the finding evidence to identify the affected IAM user and access key.",
            "Confirm you can review the places where the credential might still be referenced, including application configuration, CI/CD variables, secret stores, and operational documentation.",
            "Decide how you will restore service if an unexpected dependency appears after the key is deactivated.",
        ],
        "steps": [
            "Locate the affected IAM user and access key in IAM.",
            "Review last-used information and search application configuration, repositories, secret stores, CI/CD systems, and operational documentation for references to the credential.",
            "If the credential is truly unnecessary, set the access key to Inactive rather than deleting it immediately.",
            "Monitor the affected environment for authentication failures, broken jobs, or operator reports that could indicate an unknown dependency.",
            "If no dependency appears during the organization's chosen observation period, delete the inactive access key.",
            "If a dependency is discovered, migrate it to an IAM role or temporary credentials before retiring the key again.",
        ],
        "cliCommands": [
            {"label": "Deactivate the confirmed unused key", "command": "aws iam update-access-key --user-name <user-name> --access-key-id <access-key-id> --status Inactive"},
            {"label": "Delete the key after the dependency check", "command": "aws iam delete-access-key --user-name <user-name> --access-key-id <access-key-id>"},
        ],
        "cautions": [
            "This assessment uses IAM credential-report data to identify an apparently unused active key; validate business dependencies before permanent deletion.",
            "Treat access-key IDs as identifiers, not secrets. Never place secret access keys in tickets, reports, or chat.",
        ],
        "verificationSteps": [
            "Confirm the retired key no longer appears as Active for the IAM user.",
            "Confirm dependent workloads continue to authenticate through their intended identity path.",
        ],
    },
    "iam-old-access-keys": {
        "objective": "Replace long-lived IAM access keys older than the 90-day assessment baseline, preferably with temporary credentials.",
        "consolePath": "IAM → Users → <user> → Security credentials → Access keys",
        "prerequisites": [
            "Use the finding evidence to identify the affected IAM user and aged access key.",
            "Identify the owner of every workload or integration that uses the existing key.",
            "Confirm an approved secret-management location is ready for any temporary replacement secret used during rotation.",
        ],
        "steps": [
            "Determine whether the workload can stop using an IAM-user access key entirely. Prefer an IAM role, workload identity, or another temporary-credential mechanism when available.",
            "If a long-term key must remain, verify the IAM user has capacity for a second access key before starting rotation.",
            "Create the replacement access key and store the secret only in the approved secret-management or deployment system.",
            "Update each application, integration, script, or CI/CD job to use the new key and exercise the affected workflows.",
            "Set the old access key to Inactive and keep it available only for the approved rollback window while monitoring for missed dependencies.",
            "Delete the old key after the replacement credential has been proven and the rollback window is complete.",
        ],
        "cliCommands": [
            {"label": "Create a replacement key when long-term credentials are unavoidable", "command": "aws iam create-access-key --user-name <user-name>"},
            {"label": "Deactivate the old key after replacement validation", "command": "aws iam update-access-key --user-name <user-name> --access-key-id <old-access-key-id> --status Inactive"},
            {"label": "Delete the old key after the rollback window", "command": "aws iam delete-access-key --user-name <user-name> --access-key-id <old-access-key-id>"},
        ],
        "cautions": [
            "Do not delete the old key before the replacement credential has been deployed and verified; doing so can create an application outage.",
            "AWS limits the number of access keys per IAM user. Resolve any existing second key before a rotation that requires temporary overlap.",
            "A new secret access key is displayed only when created. Store it directly in the approved secret store and avoid copying it into logs or tickets.",
        ],
        "verificationSteps": [
            "Confirm production or administrative workflows succeed using the replacement identity.",
            "Confirm the old access key is deleted or no longer active and any remaining active key is within the approved age baseline.",
        ],
    },
    "iam-account-password-policy": {
        "objective": "Configure the IAM account password policy to meet the assessment baseline for IAM-user passwords.",
        "consolePath": "IAM → Account settings → Password policy → Edit",
        "prerequisites": [
            "Confirm you have permission to view and change the IAM account password policy.",
            "Capture the complete current password policy in IAM Account settings or with aws iam get-account-password-policy before changing it.",
            "Identify IAM users that still sign in with IAM passwords and review any organizational password requirements that are stricter than this assessment baseline.",
        ],
        "steps": [
            "Open IAM Account settings and compare the complete current Password policy with the assessment baseline and any stricter organizational requirements.",
            "Record every current password-policy setting before making a change so an intentional setting is not accidentally reset.",
            "Choose Edit password policy and set the minimum password length to at least 14 characters.",
            "Require uppercase letters, lowercase letters, numbers, and non-alphanumeric symbols.",
            "Enable password reuse prevention with a value greater than zero; use the organization's required history value if it is stricter.",
            "Set a maximum password age greater than zero according to organizational policy. The assessment baseline requires that a maximum age be configured but does not prescribe a specific number of days.",
            "Review the complete resulting policy, including settings such as whether users may change their own passwords and hard expiry, then save only after every intended setting is explicit.",
            "Confirm the intended values are active and continue to require MFA for human identities.",
        ],
        "cliCommands": [
            {"label": "Inspect the complete current IAM password policy before any CLI update", "command": "aws iam get-account-password-policy"},
        ],
        "cautions": [
            "AWS UpdateAccountPasswordPolicy does not support partial updates. Any parameter omitted from an update reverts to its AWS default value, so do not use a shortened update command as though it patches only selected settings.",
            "If you use the AWS CLI to update the policy, explicitly define the complete intended policy state, including boolean choices such as whether users may change their own passwords and hard expiry. The console procedure above is safer when those choices have not already been decided.",
            "Password-policy changes affect IAM users that authenticate with IAM passwords. When a maximum password age is introduced, users whose current passwords are already older than that threshold can be required to change them at their next sign-in.",
            "Coordinate changes that may force password updates or disrupt established access procedures, and do not weaken a stricter organizational policy merely to match this baseline.",
        ],
        "verificationSteps": [
            "Confirm IAM Account settings show minimum length 14 or greater, all four character requirements enabled, password reuse prevention configured, and a maximum password age configured.",
            "Confirm retained IAM password users can complete any required password-change flow and authenticate as expected.",
        ],
    },
    "cloudtrail-multi-region": {
        "objective": "Maintain an ongoing CloudTrail audit trail that covers activity across enabled AWS Regions.",
        "consolePath": "CloudTrail → Trails",
        "prerequisites": [
            "Confirm you have permission to create or update CloudTrail trails and manage the associated log destination.",
            "Confirm where CloudTrail logs should go: which S3 bucket to use, whether encryption is required, how long logs must be retained, and whether your organization centralizes CloudTrail logs.",
            "If you plan to convert an existing single-Region trail, identify that trail's home Region before using the CLI conversion command.",
            "Confirm the assessment boundary before remediation: this control verifies multi-Region trail presence only. Active logging, log-delivery health, and management-event configuration are recommended operational hardening checks, not states this control currently proves.",
        ],
        "steps": [
            "Open CloudTrail Trails and review existing trails before creating a duplicate logging path.",
            "If creating a new trail in the CloudTrail console, create the trail with the approved S3 destination and required encryption or log-file validation settings; console-created trails provide multi-Region coverage.",
            "If converting an existing single-Region trail, perform the conversion from that trail's home Region with the AWS CLI update-trail command using --is-multi-region-trail; the console does not convert an existing single-Region trail to multi-Region.",
            "Ensure management-event logging is enabled according to the organization's audit requirements and start logging if it is not already active.",
            "Confirm the trail details report multi-Region coverage and active logging.",
            "Confirm the destination bucket is receiving new CloudTrail log objects before considering the operational hardening complete.",
        ],
        "cliCommands": [
            {"label": "Convert an existing trail to multi-Region coverage from its home Region", "command": "aws cloudtrail update-trail --name <trail-name> --is-multi-region-trail --region <trail-home-region>"},
            {"label": "Ensure logging is running", "command": "aws cloudtrail start-logging --name <trail-name> --region <trail-home-region>"},
        ],
        "cautions": [
            "Changing or duplicating CloudTrail destinations can affect retention, SIEM ingestion, alerting, and compliance workflows. Preserve required downstream integrations.",
            "Do not delete an existing trail until the replacement or converted trail is confirmed to be logging and downstream consumers are validated.",
        ],
        "verificationSteps": [
            "Confirm CloudTrail shows at least one trail configured for multi-Region coverage; this is the AWS state required by the assessed control.",
            "As additional operational hardening, confirm the selected trail is actively logging and recent log files are arriving at the intended destination.",
            "Confirm management-event configuration, retention, and downstream consumers meet the organization's logging requirements; these additional states are not verified by the current assessment control.",
        ],
    },
    "s3-account-public-access-block": {
        "objective": "Enable all four Amazon S3 account-level Block Public Access guardrails where compatible with the account's intended workloads.",
        "consolePath": "Amazon S3 → Account and organization settings → Block Public Access settings for this account → Edit",
        "prerequisites": [
            "Confirm you have permission to modify the account-level S3 Block Public Access settings.",
            "Identify any buckets or access points that are intentionally designed for public access so those workloads can be tested before enforcement.",
            "Check whether an AWS Organizations S3 Block Public Access policy centrally controls this account; if it does, coordinate the change through the organization administrator.",
        ],
        "steps": [
            "Open S3 Account and organization settings and review the four effective account-level Block Public Access settings.",
            "If the account setting is controlled by an AWS Organizations S3 Block Public Access policy and cannot be edited, coordinate with the organization administrator instead of attempting to override the policy locally.",
            "Review intentionally public S3 workloads and determine whether they should remain public or move behind a controlled delivery mechanism such as CloudFront.",
            "When the account setting is locally editable, choose Edit and enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.",
            "Acknowledge the AWS confirmation, save the account-level settings, and test applications that read from or publish through S3.",
            "Resolve unintended public-access dependencies rather than disabling the account-wide guardrail again where a safer architecture is available.",
        ],
        "cliCommands": [
            {"label": "Enable all four account-level controls when not centrally governed", "command": "aws s3control put-public-access-block --account-id <account-id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"},
        ],
        "cautions": [
            "Enabling account-level Block Public Access can intentionally break workloads that depend on public S3 access. Validate those designs before enforcement.",
            "An AWS Organizations S3 Block Public Access policy can prevent direct account-level changes; use the organization governance path when applicable.",
            "This finding does not prove that any current bucket is public; remediation adds the preventive account-level guardrail.",
        ],
        "verificationSteps": [
            "Confirm all four effective S3 account-level Block Public Access settings are enabled, whether locally or through organization policy.",
            "Confirm expected S3-dependent applications still function after the guardrail change.",
        ],
    },
    "ec2-security-groups-open-admin-ports": {
        "objective": "Remove internet-wide SSH and RDP ingress and restrict administrative access to explicitly trusted paths.",
        "consolePath": "EC2 → Network & Security → Security Groups → <affected group> → Inbound rules → Edit inbound rules",
        "prerequisites": [
            "Use the finding evidence to identify the affected security group IDs and exposed administrative ports.",
            "Confirm administrators have a replacement access path—such as a trusted CIDR, VPN, bastion host, private network, or AWS Systems Manager Session Manager—before removing the internet-wide rule.",
            "Keep a test session open or define a rollback method so you can recover if the rule change blocks legitimate administration.",
        ],
        "steps": [
            "Use the finding evidence to identify each security group that permits TCP 22 or 3389 from 0.0.0.0/0 or ::/0.",
            "Before removing the rule, identify how administrators are expected to reach the associated instances and establish the replacement path.",
            "Open the affected security group and remove each internet-wide SSH or RDP rule reported by the assessment.",
            "If direct administrative ingress is still required, add a narrowly scoped rule for the approved trusted source CIDR instead of the internet-wide source. Prefer private administration paths where practical.",
            "Save the rules while keeping an existing administrative session open when possible.",
            "From the approved administration path, open a new SSH, RDP, or Session Manager session and confirm access works.",
            "Confirm attempts from an untrusted network no longer reach the administrative port.",
        ],
        "cliCommands": [
            {"label": "Example: remove internet-wide SSH from an affected IPv4 rule", "command": "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0"},
            {"label": "Example: permit SSH only from an approved IPv4 source when direct ingress is required", "command": "aws ec2 authorize-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr <trusted-cidr>"},
        ],
        "cautions": [
            "Removing an ingress rule before a replacement administration path is confirmed can lock operators out of an instance.",
            "Security groups can be shared by multiple instances or interfaces. Review the group's attachments before changing it.",
            "Repeat the review for IPv6 (::/0) and for RDP port 3389 when those variants are present in the finding evidence.",
        ],
        "verificationSteps": [
            "Confirm no affected security group permits SSH or RDP from 0.0.0.0/0 or ::/0 within the assessment's stated security-group Region scope.",
            "Confirm administrators can still connect through the approved restricted path and untrusted networks cannot reach the administrative port.",
        ],
    },
}
