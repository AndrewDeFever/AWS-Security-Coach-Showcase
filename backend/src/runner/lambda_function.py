import csv
import io
import json
import os
import time
import datetime
import urllib.parse
import boto3
from botocore.exceptions import ClientError

ddb = boto3.resource("dynamodb")
s3 = boto3.client("s3")
iam = boto3.client("iam")
cloudtrail = boto3.client("cloudtrail")
s3control = boto3.client("s3control")
sts = boto3.client("sts")

HOME_REGION = os.environ.get("HOME_REGION", "us-east-1")
ec2 = boto3.client("ec2", region_name=HOME_REGION)

STALE_RUNNING_MINUTES = 15
OLD_ACCESS_KEY_DAYS = 90


def _utc_now():
    return datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")


def _parse_iso_z(ts: str):
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _parse_credential_report_date(value: str):
    if not value:
        return None

    clean = str(value).strip()
    if clean.upper() in ("N/A", "NO_INFORMATION"):
        return None

    try:
        return datetime.datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except Exception:
        return None


def _is_true(value) -> bool:
    return str(value).strip().upper() == "TRUE"


def _format_name_list(names: list, max_items: int = 10) -> str:
    if not names:
        return ""

    names = sorted(str(x) for x in names)
    shown = names[:max_items]
    remaining = len(names) - len(shown)

    if remaining > 0:
        return ", ".join(shown) + f", and {remaining} more"

    return ", ".join(shown)


def _resp(status: str, extra: dict = None):
    body = {"ok": True, "status": status}
    if extra:
        body.update(extra)
    return body


def _get_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise Exception(f"Missing env var {name}")
    return value


def _find_oldest_queued_scan(table):
    response = table.scan()
    items = response.get("Items", [])

    queued = [x for x in items if x.get("status") == "QUEUED"]
    if not queued:
        return None

    queued.sort(key=lambda x: x.get("createdAt", ""))
    return queued[0]


def _find_stale_running_scan(table):
    response = table.scan()
    items = response.get("Items", [])

    now = datetime.datetime.now(datetime.UTC)
    stale = []

    for item in items:
        if item.get("status") != "RUNNING":
            continue

        started_at = _parse_iso_z(item.get("startedAt"))
        if not started_at:
            continue

        age = now - started_at
        if age.total_seconds() > (STALE_RUNNING_MINUTES * 60):
            stale.append(item)

    if not stale:
        return None

    stale.sort(key=lambda x: x.get("startedAt", ""))
    return stale[0]


def _claim_scan(table, scan_id: str):
    now = _utc_now()

    response = table.update_item(
        Key={"scanId": scan_id},
        UpdateExpression="SET #s = :running, startedAt = :started, updatedAt = :updated",
        ConditionExpression="#s = :queued",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":queued": "QUEUED",
            ":running": "RUNNING",
            ":started": now,
            ":updated": now,
        },
        ReturnValues="ALL_NEW",
    )

    return response["Attributes"]


def _mark_complete(table, scan_id: str, report_key: str):
    now = _utc_now()

    table.update_item(
        Key={"scanId": scan_id},
        UpdateExpression=(
            "SET #s = :complete, completedAt = :completed, "
            "updatedAt = :updated, reportKey = :reportKey"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":complete": "COMPLETE",
            ":completed": now,
            ":updated": now,
            ":reportKey": report_key,
        },
    )


def _mark_failed(table, scan_id: str, error_message: str):
    now = _utc_now()

    table.update_item(
        Key={"scanId": scan_id},
        UpdateExpression="SET #s = :failed, updatedAt = :updated, errorMessage = :err",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":failed": "FAILED",
            ":updated": now,
            ":err": error_message[:1000],
        },
    )


def _mark_stale_running_failed(table, scan_id: str):
    now = _utc_now()
    message = (
        f"Marked FAILED by sweeper after stale RUNNING timeout of "
        f"{STALE_RUNNING_MINUTES} minutes"
    )

    table.update_item(
        Key={"scanId": scan_id},
        UpdateExpression="SET #s = :failed, updatedAt = :updated, errorMessage = :err",
        ConditionExpression="#s = :running",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":running": "RUNNING",
            ":failed": "FAILED",
            ":updated": now,
            ":err": message,
        },
    )

    return message


def _load_rules_stub(bucket: str, rules_prefix: str):
    response = s3.list_objects_v2(
        Bucket=bucket,
        Prefix=rules_prefix,
        MaxKeys=20,
    )

    contents = response.get("Contents", [])
    rules = []

    for obj in contents:
        key = obj.get("Key")
        if not key or key.endswith("/"):
            continue

        rules.append(
            {
                "ruleKey": key,
                "sizeBytes": obj.get("Size", 0),
                "lastModified": (
                    obj.get("LastModified").isoformat()
                    if obj.get("LastModified")
                    else None
                ),
            }
        )

    return rules


def _load_credential_report_rows():
    """
    Generates and loads the IAM credential report.

    The report is account-global, not regional.
    """
    try:
        for attempt in range(5):
            generate_response = iam.generate_credential_report()
            state = generate_response.get("State")

            if state == "COMPLETE":
                break

            print(
                f"Credential report generation state={state}; "
                f"attempt {attempt + 1}/5"
            )
            time.sleep(1)

        report_response = iam.get_credential_report()
        content = report_response["Content"].decode("utf-8")

        reader = csv.DictReader(io.StringIO(content))
        return list(reader)

    except Exception as e:
        raise Exception(f"Unable to load IAM credential report: {str(e)}")


def _check_root_mfa():
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        enabled = int(summary.get("AccountMFAEnabled", 0)) == 1

        if enabled:
            return {
                "id": "iam-root-mfa-enabled",
                "title": "Root account MFA is enabled",
                "severity": "INFO",
                "status": "PASS",
                "details": "Root account MFA is enabled for the tool account.",
            }

        return {
            "id": "iam-root-mfa-enabled",
            "title": "Root account MFA is not enabled",
            "severity": "HIGH",
            "status": "FAIL",
            "details": "Root account MFA is not enabled for the tool account.",
        }

    except Exception as e:
        return {
            "id": "iam-root-mfa-enabled",
            "title": "Root account MFA check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": f"Runner could not complete the root MFA check: {str(e)}",
        }


def _check_root_access_keys_absent(credential_report_rows: list):
    try:
        root_row = next(
            (row for row in credential_report_rows if row.get("user") == "<root_account>"),
            None,
        )

        if not root_row:
            return {
                "id": "iam-root-access-keys-absent",
                "title": "Root account access key check could not be completed",
                "severity": "LOW",
                "status": "ERROR",
                "details": "Runner could not find the <root_account> row in the IAM credential report.",
            }

        access_key_1_active = _is_true(root_row.get("access_key_1_active", ""))
        access_key_2_active = _is_true(root_row.get("access_key_2_active", ""))

        if access_key_1_active or access_key_2_active:
            active_keys = []
            if access_key_1_active:
                active_keys.append("access_key_1")
            if access_key_2_active:
                active_keys.append("access_key_2")

            return {
                "id": "iam-root-access-keys-absent",
                "title": "Root account access keys are present",
                "severity": "HIGH",
                "status": "FAIL",
                "details": (
                    "One or more active root account access keys are present: "
                    + ", ".join(active_keys)
                    + ". Delete root access keys and use IAM users or roles for programmatic access."
                ),
            }

        return {
            "id": "iam-root-access-keys-absent",
            "title": "Root account access keys are not present",
            "severity": "HIGH",
            "status": "PASS",
            "details": "No active root account access keys are present.",
        }

    except Exception as e:
        return {
            "id": "iam-root-access-keys-absent",
            "title": "Root account access key check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": f"Runner could not complete the root access key check: {str(e)}",
        }


def _check_iam_user_mfa():
    try:
        users = []
        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():
            users.extend(page.get("Users", []))

        if not users:
            return {
                "id": "iam-users-mfa",
                "title": "No IAM users were found",
                "severity": "INFO",
                "status": "PASS",
                "details": "No IAM users were found in the tool account.",
            }

        no_mfa_users = []

        for user in users:
            user_name = user["UserName"]
            devices = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
            if len(devices) == 0:
                no_mfa_users.append(user_name)

        if not no_mfa_users:
            return {
                "id": "iam-users-mfa",
                "title": "All IAM users have MFA enabled",
                "severity": "INFO",
                "status": "PASS",
                "details": "All IAM users in the tool account have MFA enabled.",
            }

        no_mfa_users.sort()
        count = len(no_mfa_users)
        names = ", ".join(no_mfa_users)

        return {
            "id": "iam-users-mfa",
            "title": "IAM users without MFA were found",
            "severity": "MEDIUM",
            "status": "FAIL",
            "details": f"{count} IAM users do not have MFA enabled: {names}.",
        }

    except Exception as e:
        return {
            "id": "iam-users-mfa",
            "title": "IAM user MFA check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": f"Runner could not complete the IAM user MFA check: {str(e)}",
        }


def _check_unused_iam_access_keys(credential_report_rows: list):
    try:
        unused_keys = []

        for row in credential_report_rows:
            user_name = row.get("user")
            if not user_name or user_name == "<root_account>":
                continue

            for key_number in ("1", "2"):
                active_field = f"access_key_{key_number}_active"
                last_used_field = f"access_key_{key_number}_last_used_date"

                if not _is_true(row.get(active_field, "")):
                    continue

                last_used_raw = str(row.get(last_used_field, "")).strip()
                last_used = _parse_credential_report_date(last_used_raw)

                if last_used is None:
                    unused_keys.append(f"{user_name}: access_key_{key_number}")

        if not unused_keys:
            return {
                "id": "iam-unused-access-keys",
                "title": "No unused IAM access keys were found",
                "severity": "INFO",
                "status": "PASS",
                "details": "No active IAM user access keys appear to be unused.",
            }

        count = len(unused_keys)
        sample = _format_name_list(unused_keys)

        return {
            "id": "iam-unused-access-keys",
            "title": "Unused IAM access keys were found",
            "severity": "MEDIUM",
            "status": "FAIL",
            "details": (
                f"{count} active IAM user access keys appear to be unused: {sample}. "
                "Delete unused access keys or replace them with IAM roles where possible."
            ),
        }

    except Exception as e:
        return {
            "id": "iam-unused-access-keys",
            "title": "Unused IAM access key check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": f"Runner could not complete the unused IAM access key check: {str(e)}",
        }


def _check_old_iam_access_keys(credential_report_rows: list):
    try:
        now = datetime.datetime.now(datetime.UTC)
        old_keys = []

        for row in credential_report_rows:
            user_name = row.get("user")
            if not user_name or user_name == "<root_account>":
                continue

            for key_number in ("1", "2"):
                active_field = f"access_key_{key_number}_active"
                rotated_field = f"access_key_{key_number}_last_rotated"

                if not _is_true(row.get(active_field, "")):
                    continue

                rotated = _parse_credential_report_date(row.get(rotated_field, ""))
                if not rotated:
                    continue

                age_days = (now - rotated).days
                if age_days > OLD_ACCESS_KEY_DAYS:
                    old_keys.append(
                        f"{user_name}: access_key_{key_number} ({age_days} days old)"
                    )

        if not old_keys:
            return {
                "id": "iam-old-access-keys",
                "title": "No old IAM access keys were found",
                "severity": "INFO",
                "status": "PASS",
                "details": (
                    f"No active IAM user access keys are older than "
                    f"{OLD_ACCESS_KEY_DAYS} days."
                ),
            }

        count = len(old_keys)
        sample = _format_name_list(old_keys)

        return {
            "id": "iam-old-access-keys",
            "title": "Old IAM access keys were found",
            "severity": "MEDIUM",
            "status": "FAIL",
            "details": (
                f"{count} active IAM user access keys are older than "
                f"{OLD_ACCESS_KEY_DAYS} days: {sample}. Rotate old access keys "
                "or replace them with IAM roles where possible."
            ),
        }

    except Exception as e:
        return {
            "id": "iam-old-access-keys",
            "title": "Old IAM access key check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": f"Runner could not complete the old IAM access key check: {str(e)}",
        }


def _check_account_password_policy():
    try:
        response = iam.get_account_password_policy()
        policy = response.get("PasswordPolicy", {})

        min_length = int(policy.get("MinimumPasswordLength", 0))
        require_uppercase = bool(policy.get("RequireUppercaseCharacters", False))
        require_lowercase = bool(policy.get("RequireLowercaseCharacters", False))
        require_numbers = bool(policy.get("RequireNumbers", False))
        require_symbols = bool(policy.get("RequireSymbols", False))
        reuse_prevention = int(policy.get("PasswordReusePrevention", 0) or 0)
        max_age = int(policy.get("MaxPasswordAge", 0) or 0)

        failures = []

        if min_length < 14:
            failures.append(f"MinimumPasswordLength={min_length} (<14)")
        if not require_uppercase:
            failures.append("RequireUppercaseCharacters=false")
        if not require_lowercase:
            failures.append("RequireLowercaseCharacters=false")
        if not require_numbers:
            failures.append("RequireNumbers=false")
        if not require_symbols:
            failures.append("RequireSymbols=false")
        if reuse_prevention <= 0:
            failures.append("PasswordReusePrevention not set")
        if max_age <= 0:
            failures.append("MaxPasswordAge not set")

        if not failures:
            return {
                "id": "iam-account-password-policy",
                "title": "IAM account password policy meets baseline",
                "severity": "INFO",
                "status": "PASS",
                "details": (
                    "The IAM account password policy meets the current baseline "
                    "for length, complexity, reuse prevention, and max age."
                ),
            }

        return {
            "id": "iam-account-password-policy",
            "title": "IAM account password policy does not meet baseline",
            "severity": "MEDIUM",
            "status": "FAIL",
            "details": "Password policy gaps found: " + ", ".join(failures) + ".",
        }

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")

        if error_code == "NoSuchEntity":
            return {
                "id": "iam-account-password-policy",
                "title": "IAM account password policy is not configured",
                "severity": "HIGH",
                "status": "FAIL",
                "details": "No IAM account password policy was found for the tool account.",
            }

        return {
            "id": "iam-account-password-policy",
            "title": "IAM account password policy check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": f"Runner could not complete the IAM account password policy check: {str(e)}",
        }

    except Exception as e:
        return {
            "id": "iam-account-password-policy",
            "title": "IAM account password policy check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": f"Runner could not complete the IAM account password policy check: {str(e)}",
        }


def _check_cloudtrail_multi_region():
    try:
        response = cloudtrail.describe_trails(includeShadowTrails=False)
        trails = response.get("trailList", [])

        multi_region_trails = [t for t in trails if t.get("IsMultiRegionTrail")]

        if multi_region_trails:
            return {
                "id": "cloudtrail-multi-region",
                "title": "CloudTrail multi-region trail is enabled",
                "severity": "INFO",
                "status": "PASS",
                "details": "At least one multi-region CloudTrail trail is configured in the tool account.",
            }

        return {
            "id": "cloudtrail-multi-region",
            "title": "CloudTrail multi-region trail is not enabled",
            "severity": "HIGH",
            "status": "FAIL",
            "details": "No multi-region CloudTrail trail was detected in the tool account.",
        }

    except Exception as e:
        return {
            "id": "cloudtrail-multi-region",
            "title": "CloudTrail check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": f"Runner could not complete the CloudTrail check: {str(e)}",
        }


def _check_s3_account_public_access_block():
    try:
        account_id = sts.get_caller_identity()["Account"]
        response = s3control.get_public_access_block(AccountId=account_id)
        config = response.get("PublicAccessBlockConfiguration", {})

        block_public_acls = bool(config.get("BlockPublicAcls", False))
        ignore_public_acls = bool(config.get("IgnorePublicAcls", False))
        block_public_policy = bool(config.get("BlockPublicPolicy", False))
        restrict_public_buckets = bool(config.get("RestrictPublicBuckets", False))

        all_enabled = (
            block_public_acls
            and ignore_public_acls
            and block_public_policy
            and restrict_public_buckets
        )

        if all_enabled:
            return {
                "id": "s3-account-public-access-block",
                "title": "S3 account-level Block Public Access is fully enabled",
                "severity": "INFO",
                "status": "PASS",
                "details": "All four S3 account-level public access block settings are enabled for the tool account.",
            }

        disabled = []
        if not block_public_acls:
            disabled.append("BlockPublicAcls")
        if not ignore_public_acls:
            disabled.append("IgnorePublicAcls")
        if not block_public_policy:
            disabled.append("BlockPublicPolicy")
        if not restrict_public_buckets:
            disabled.append("RestrictPublicBuckets")

        disabled_text = ", ".join(disabled)

        return {
            "id": "s3-account-public-access-block",
            "title": "S3 account-level Block Public Access is not fully enabled",
            "severity": "HIGH",
            "status": "FAIL",
            "details": (
                "One or more S3 account-level public access block settings "
                f"are disabled for the tool account: {disabled_text}."
            ),
        }

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")

        if error_code == "NoSuchPublicAccessBlockConfiguration":
            return {
                "id": "s3-account-public-access-block",
                "title": "S3 account-level Block Public Access is not configured",
                "severity": "HIGH",
                "status": "FAIL",
                "details": (
                    "No account-level S3 Public Access Block configuration was "
                    "found for the tool account."
                ),
            }

        return {
            "id": "s3-account-public-access-block",
            "title": "S3 account-level Block Public Access check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": (
                "Runner could not complete the S3 account-level public access "
                f"block check: {str(e)}"
            ),
        }

    except Exception as e:
        return {
            "id": "s3-account-public-access-block",
            "title": "S3 account-level Block Public Access check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": (
                "Runner could not complete the S3 account-level public access "
                f"block check: {str(e)}"
            ),
        }


def _as_list(value):
    if isinstance(value, list):
        return value
    return [value]


def _statement_has_wildcard_admin(statement: dict) -> bool:
    if statement.get("Effect") != "Allow":
        return False

    actions = [str(x).strip() for x in _as_list(statement.get("Action", []))]
    resources = [str(x).strip() for x in _as_list(statement.get("Resource", []))]

    action_all = "*" in actions or "*:*" in actions
    resource_all = "*" in resources

    return action_all and resource_all


def _policy_document_has_wildcard_admin(policy_document) -> bool:
    if not isinstance(policy_document, dict):
        return False

    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if isinstance(statement, dict) and _statement_has_wildcard_admin(statement):
            return True

    return False


def _decode_policy_document(policy_document):
    if isinstance(policy_document, dict):
        return policy_document

    if isinstance(policy_document, str):
        decoded = urllib.parse.unquote(policy_document)
        return json.loads(decoded)

    return {}


def _check_managed_policy_for_wildcard_admin(policy_arn: str, owner_label: str):
    policy = iam.get_policy(PolicyArn=policy_arn).get("Policy", {})
    version_id = policy.get("DefaultVersionId")

    if not version_id:
        return None

    version = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=version_id,
    ).get("PolicyVersion", {})

    document = _decode_policy_document(version.get("Document", {}))

    if _policy_document_has_wildcard_admin(document):
        policy_name = policy.get("PolicyName", policy_arn.split("/")[-1])
        return f"{owner_label}: {policy_name}"

    return None


def _check_inline_policy_for_wildcard_admin(owner_label: str, policy_document):
    document = _decode_policy_document(policy_document)

    if _policy_document_has_wildcard_admin(document):
        return owner_label

    return None


def _check_wildcard_admin_policy():
    try:
        findings = []

        user_paginator = iam.get_paginator("list_users")
        for page in user_paginator.paginate():
            for user in page.get("Users", []):
                user_name = user["UserName"]

                attached_paginator = iam.get_paginator("list_attached_user_policies")
                for attached_page in attached_paginator.paginate(UserName=user_name):
                    for policy in attached_page.get("AttachedPolicies", []):
                        hit = _check_managed_policy_for_wildcard_admin(
                            policy["PolicyArn"],
                            f"user/{user_name}",
                        )
                        if hit:
                            findings.append(hit)

                inline_paginator = iam.get_paginator("list_user_policies")
                for inline_page in inline_paginator.paginate(UserName=user_name):
                    for policy_name in inline_page.get("PolicyNames", []):
                        policy_doc = iam.get_user_policy(
                            UserName=user_name,
                            PolicyName=policy_name,
                        ).get("PolicyDocument", {})
                        hit = _check_inline_policy_for_wildcard_admin(
                            f"user/{user_name}: inline/{policy_name}",
                            policy_doc,
                        )
                        if hit:
                            findings.append(hit)

        role_paginator = iam.get_paginator("list_roles")
        for page in role_paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]

                attached_paginator = iam.get_paginator("list_attached_role_policies")
                for attached_page in attached_paginator.paginate(RoleName=role_name):
                    for policy in attached_page.get("AttachedPolicies", []):
                        hit = _check_managed_policy_for_wildcard_admin(
                            policy["PolicyArn"],
                            f"role/{role_name}",
                        )
                        if hit:
                            findings.append(hit)

                inline_paginator = iam.get_paginator("list_role_policies")
                for inline_page in inline_paginator.paginate(RoleName=role_name):
                    for policy_name in inline_page.get("PolicyNames", []):
                        policy_doc = iam.get_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name,
                        ).get("PolicyDocument", {})
                        hit = _check_inline_policy_for_wildcard_admin(
                            f"role/{role_name}: inline/{policy_name}",
                            policy_doc,
                        )
                        if hit:
                            findings.append(hit)

        group_paginator = iam.get_paginator("list_groups")
        for page in group_paginator.paginate():
            for group in page.get("Groups", []):
                group_name = group["GroupName"]

                attached_paginator = iam.get_paginator("list_attached_group_policies")
                for attached_page in attached_paginator.paginate(GroupName=group_name):
                    for policy in attached_page.get("AttachedPolicies", []):
                        hit = _check_managed_policy_for_wildcard_admin(
                            policy["PolicyArn"],
                            f"group/{group_name}",
                        )
                        if hit:
                            findings.append(hit)

                inline_paginator = iam.get_paginator("list_group_policies")
                for inline_page in inline_paginator.paginate(GroupName=group_name):
                    for policy_name in inline_page.get("PolicyNames", []):
                        policy_doc = iam.get_group_policy(
                            GroupName=group_name,
                            PolicyName=policy_name,
                        ).get("PolicyDocument", {})
                        hit = _check_inline_policy_for_wildcard_admin(
                            f"group/{group_name}: inline/{policy_name}",
                            policy_doc,
                        )
                        if hit:
                            findings.append(hit)

        if not findings:
            return {
                "id": "iam-wildcard-admin-policy",
                "title": "No wildcard administrator policies were found",
                "severity": "INFO",
                "status": "PASS",
                "details": "No IAM policies granting Action=* and Resource=* were found on users, roles, or groups.",
            }

        count = len(findings)
        sample = _format_name_list(findings)

        return {
            "id": "iam-wildcard-admin-policy",
            "title": "Wildcard administrator policies were found",
            "severity": "HIGH",
            "status": "FAIL",
            "details": (
                f"{count} IAM policy attachments or inline policies grant broad "
                f"wildcard administrator access: {sample}."
            ),
        }

    except Exception as e:
        return {
            "id": "iam-wildcard-admin-policy",
            "title": "Wildcard administrator policy check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": f"Runner could not complete the wildcard administrator policy check: {str(e)}",
        }


def _permission_allows_public_admin_port(permission: dict):
    ip_protocol = str(permission.get("IpProtocol", "")).lower()

    if ip_protocol not in ("tcp", "-1"):
        return []

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")

    if ip_protocol == "-1":
        ports = [22, 3389]
    else:
        if from_port is None or to_port is None:
            return []

        ports = []
        if int(from_port) <= 22 <= int(to_port):
            ports.append(22)
        if int(from_port) <= 3389 <= int(to_port):
            ports.append(3389)

    if not ports:
        return []

    public_sources = []

    for ip_range in permission.get("IpRanges", []):
        if ip_range.get("CidrIp") == "0.0.0.0/0":
            public_sources.append("0.0.0.0/0")

    for ipv6_range in permission.get("Ipv6Ranges", []):
        if ipv6_range.get("CidrIpv6") == "::/0":
            public_sources.append("::/0")

    if not public_sources:
        return []

    results = []
    for port in ports:
        for source in public_sources:
            results.append(f"tcp/{port} from {source}")

    return results


def _check_security_groups_open_admin_ports():
    try:
        open_rules = []
        paginator = ec2.get_paginator("describe_security_groups")

        for page in paginator.paginate():
            for group in page.get("SecurityGroups", []):
                group_id = group.get("GroupId", "unknown")
                group_name = group.get("GroupName", "unknown")

                for permission in group.get("IpPermissions", []):
                    exposures = _permission_allows_public_admin_port(permission)
                    for exposure in exposures:
                        open_rules.append(f"{group_name} ({group_id}): {exposure}")

        if not open_rules:
            return {
                "id": "ec2-security-groups-open-admin-ports",
                "title": "No security groups expose SSH or RDP to the internet",
                "severity": "INFO",
                "status": "PASS",
                "details": (
                    f"No security groups in {HOME_REGION} allow inbound SSH "
                    "or RDP from 0.0.0.0/0 or ::/0."
                ),
            }

        count = len(open_rules)
        sample = _format_name_list(open_rules)

        return {
            "id": "ec2-security-groups-open-admin-ports",
            "title": "Security groups expose SSH or RDP to the internet",
            "severity": "HIGH",
            "status": "FAIL",
            "details": (
                f"{count} public admin-port security group rules were found in "
                f"{HOME_REGION}: {sample}."
            ),
        }

    except Exception as e:
        return {
            "id": "ec2-security-groups-open-admin-ports",
            "title": "Security group admin-port exposure check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": (
                "Runner could not complete the security group admin-port exposure "
                f"check in {HOME_REGION}: {str(e)}"
            ),
        }


def _summarize_findings(findings: list):
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }

    for finding in findings:
        sev = str(finding.get("severity", "INFO")).upper()
        if sev == "CRITICAL":
            counts["critical"] += 1
        elif sev == "HIGH":
            counts["high"] += 1
        elif sev == "MEDIUM":
            counts["medium"] += 1
        elif sev == "LOW":
            counts["low"] += 1
        else:
            counts["informational"] += 1

    return {
        "status": "COMPLETE",
        "findingCount": len(findings),
        "ruleFileCount": 0,
        **counts,
    }


def _build_report(scan_item: dict, loaded_rules: list):
    credential_report_rows = _load_credential_report_rows()

    findings = [
        _check_root_mfa(),
        _check_root_access_keys_absent(credential_report_rows),
        _check_iam_user_mfa(),
        _check_unused_iam_access_keys(credential_report_rows),
        _check_old_iam_access_keys(credential_report_rows),
        _check_account_password_policy(),
        _check_cloudtrail_multi_region(),
        _check_s3_account_public_access_block(),
        _check_security_groups_open_admin_ports(),
    ]

    report = {
        "schemaVersion": "2026-03-29",
        "generatedAt": _utc_now(),
        "scan": {
            "scanId": scan_item.get("scanId"),
            "targetType": scan_item.get("targetType"),
            "targetId": scan_item.get("targetId"),
            "createdAt": scan_item.get("createdAt"),
            "startedAt": scan_item.get("startedAt"),
            "notes": scan_item.get("notes", ""),
        },
        "summary": _summarize_findings(findings),
        "rulesStub": loaded_rules,
        "findings": findings,
    }

    return report


def _write_report(bucket: str, reports_prefix: str, scan_id: str, report: dict):
    report_key = f"{reports_prefix}{scan_id}.json"

    s3.put_object(
        Bucket=bucket,
        Key=report_key,
        Body=json.dumps(report, indent=2).encode("utf-8"),
        ContentType="application/json",
    )

    return report_key


def lambda_handler(event, context):
    print("RUNNER EVENT:", json.dumps(event, default=str))

    table_name = _get_env("SCANS_TABLE")
    artifacts_bucket = _get_env("ARTIFACTS_BUCKET")
    rules_prefix = os.environ.get("RULES_PREFIX", "rules/")
    reports_prefix = os.environ.get("REPORTS_PREFIX", "reports/")

    table = ddb.Table(table_name)

    scan_id = event.get("scanId") if isinstance(event, dict) else None

    try:
        if scan_id:
            print(f"Runner invoked directly for scanId: {scan_id}")
        else:
            print("No scanId provided; entering sweeper mode")

            stale_running = _find_stale_running_scan(table)
            if stale_running:
                stale_scan_id = stale_running["scanId"]
                print(f"Found stale RUNNING scan: {stale_scan_id}")

                try:
                    message = _mark_stale_running_failed(table, stale_scan_id)
                    print(f"Marked stale RUNNING scan FAILED: {stale_scan_id}")
                    return _resp(
                        "STALE_RUNNING_FAILED",
                        {
                            "scanId": stale_scan_id,
                            "message": message,
                        },
                    )
                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "")
                    if error_code == "ConditionalCheckFailedException":
                        print(
                            f"Stale RUNNING scan {stale_scan_id} changed before update; skipping"
                        )
                        return _resp("SKIPPED", {"scanId": stale_scan_id})
                    raise

            queued_item = _find_oldest_queued_scan(table)
            if not queued_item:
                print("No QUEUED scans found")
                return _resp("NO_WORK")

            scan_id = queued_item["scanId"]
            print(f"Sweeper selected scanId: {scan_id}")

        try:
            claimed_item = _claim_scan(table, scan_id)
            print("Claimed scan:", json.dumps(claimed_item, default=str))
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ConditionalCheckFailedException":
                print(f"Scan {scan_id} was not QUEUED; skipping")
                return _resp("SKIPPED", {"scanId": scan_id})
            raise

        loaded_rules = _load_rules_stub(artifacts_bucket, rules_prefix)
        print(
            f"Loaded {len(loaded_rules)} rule file(s) from "
            f"s3://{artifacts_bucket}/{rules_prefix}"
        )

        report = _build_report(claimed_item, loaded_rules)
        report_key = _write_report(artifacts_bucket, reports_prefix, scan_id, report)
        print(f"Wrote report to s3://{artifacts_bucket}/{report_key}")

        _mark_complete(table, scan_id, report_key)
        print(f"Marked scan COMPLETE: {scan_id}")

        return _resp("COMPLETE", {"scanId": scan_id, "reportKey": report_key})

    except Exception as e:
        print("Runner failed:", str(e))
        if scan_id:
            try:
                _mark_failed(table, scan_id, str(e))
                print(f"Marked scan FAILED: {scan_id}")
            except Exception as inner:
                print("Failed to mark scan as FAILED:", str(inner))

        raise