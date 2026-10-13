from __future__ import annotations

import re
import time
from typing import Any

import boto3


CONNECTOR_ID_PATTERN = re.compile(r"^con_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
ROLE_ARN_PATTERN = re.compile(r"^arn:aws:iam::(?P<account>[0-9]{12}):role/aws-security-coach/[A-Za-z0-9+=,.@_/-]+$")
SUPPORTED_CONNECTOR_VERSION = "1.0"
SUPPORTED_HOME_REGION = "us-east-1"
ASSUME_ROLE_RETRY_DELAYS_SECONDS = (5, 5)

HEALTH_CONFIG_MISSING = "CONFIG_MISSING"
HEALTH_CONFIG_INVALID = "CONFIG_INVALID"
HEALTH_ASSUME_ROLE_FAILED = "ASSUME_ROLE_FAILED"
HEALTH_ACCOUNT_MISMATCH = "ACCOUNT_MISMATCH"
HEALTH_PERMISSION_CHECK_FAILED = "PERMISSION_CHECK_FAILED"
HEALTH_UNSUPPORTED_CONNECTOR_VERSION = "UNSUPPORTED_CONNECTOR_VERSION"
HEALTH_ROLE_NOT_FOUND = "ROLE_NOT_FOUND"
HEALTH_UNKNOWN_VALIDATION_ERROR = "UNKNOWN_VALIDATION_ERROR"


def _aws_error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return ""
    error = response.get("Error") or {}
    return str(error.get("Code", "")) if isinstance(error, dict) else ""


def _failure(reason: str, account_id: str = "") -> dict:
    result = {"ok": False, "healthReason": reason}
    if re.fullmatch(r"[0-9]{12}", account_id):
        result["accountId"] = account_id
    return result


def _credentials(response: dict) -> dict:
    credentials = response.get("Credentials") or {}
    for key in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
        if not credentials.get(key):
            raise RuntimeError("incomplete credentials")
    return credentials


def _client(service: str, region: str, credentials: dict):
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def _probe(name: str, call, accepted=()):
    try:
        call()
    except Exception as exc:
        error_code = _aws_error_code(exc)
        if error_code in accepted:
            return
        print(
            "CONNECTOR PERMISSION PROBE FAILED: "
            f"probe={name} errorCode={error_code or 'UNKNOWN'}"
        )
        raise


def _validate_permissions(credentials: dict, region: str, account_id: str) -> None:
    iam = _client("iam", region, credentials)
    cloudtrail = _client("cloudtrail", region, credentials)
    s3control = _client("s3control", region, credentials)
    ec2 = _client("ec2", region, credentials)

    _probe("iam.generate_credential_report", lambda: iam.generate_credential_report())
    _probe(
        "iam.get_credential_report",
        lambda: iam.get_credential_report(),
        ("CredentialReportNotPresent", "CredentialReportNotReady", "ReportInProgress"),
    )
    _probe("iam.get_account_summary", lambda: iam.get_account_summary())
    _probe("iam.list_users", lambda: iam.list_users(MaxItems=1))
    _probe(
        "iam.list_mfa_devices",
        lambda: iam.list_mfa_devices(
            UserName="aws-security-coach-permission-probe",
            MaxItems=1,
        ),
        ("NoSuchEntity",),
    )
    _probe(
        "iam.get_account_password_policy",
        lambda: iam.get_account_password_policy(),
        ("NoSuchEntity",),
    )
    _probe(
        "cloudtrail.describe_trails",
        lambda: cloudtrail.describe_trails(includeShadowTrails=False),
    )
    _probe(
        "s3control.get_public_access_block",
        lambda: s3control.get_public_access_block(AccountId=account_id),
        ("NoSuchPublicAccessBlockConfiguration",),
    )
    _probe(
        "ec2.describe_regions",
        lambda: ec2.describe_regions(AllRegions=False),
    )
    _probe(
        "ec2.describe_security_groups",
        lambda: ec2.describe_security_groups(MaxResults=5),
    )


def _assume_role_with_propagation_retry(sts_client: Any, *, role_arn: str, session_name: str, external_id: str) -> dict:
    attempts = len(ASSUME_ROLE_RETRY_DELAYS_SECONDS) + 1
    for attempt in range(attempts):
        try:
            return sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                ExternalId=external_id,
                DurationSeconds=900,
            )
        except Exception as exc:
            error_code = _aws_error_code(exc)
            if error_code == "NoSuchEntity":
                raise
            if error_code not in {"AccessDenied", "AccessDeniedException"}:
                raise
            if attempt >= len(ASSUME_ROLE_RETRY_DELAYS_SECONDS):
                raise
            time.sleep(ASSUME_ROLE_RETRY_DELAYS_SECONDS[attempt])
    raise RuntimeError("AssumeRole retry exhausted")


def validate_connector(connectors_table: Any, ssm_client: Any, sts_client: Any, environment_name: str, connector_id: str) -> dict:
    connector_id = str(connector_id or "").strip()
    if not CONNECTOR_ID_PATTERN.fullmatch(connector_id):
        return _failure(HEALTH_CONFIG_INVALID)
    if environment_name not in {"dev", "prod"}:
        return _failure(HEALTH_CONFIG_INVALID)

    response = connectors_table.get_item(Key={"connectorId": connector_id}, ConsistentRead=True)
    item = response.get("Item") or {}
    if item.get("connectorId") != connector_id or item.get("status") != "VALIDATING":
        return _failure(HEALTH_CONFIG_INVALID)

    if str(item.get("connectorVersion", "")).strip() != SUPPORTED_CONNECTOR_VERSION:
        return _failure(HEALTH_UNSUPPORTED_CONNECTOR_VERSION)

    region = str(item.get("homeRegion", "")).strip()
    if region != SUPPORTED_HOME_REGION:
        return _failure(HEALTH_CONFIG_INVALID)

    role_arn = str(item.get("connectorRoleArn", "")).strip()
    role_match = ROLE_ARN_PATTERN.fullmatch(role_arn)
    if not role_match:
        return _failure(HEALTH_CONFIG_INVALID)
    arn_account_id = role_match.group("account")

    parameter_name = f"/security-coach/{environment_name}/connectors/{connector_id}/external-id"
    try:
        secret = ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
    except Exception as exc:
        return _failure(HEALTH_CONFIG_MISSING if _aws_error_code(exc) == "ParameterNotFound" else HEALTH_CONFIG_INVALID)

    external_id = str((secret.get("Parameter") or {}).get("Value", "")).strip()
    if len(external_id) < 32:
        return _failure(HEALTH_CONFIG_INVALID)

    try:
        assumed = _assume_role_with_propagation_retry(
            sts_client,
            role_arn=role_arn,
            session_name=f"aws-security-coach-validate-{connector_id}"[:64],
            external_id=external_id,
        )
        credentials = _credentials(assumed)
    except Exception as exc:
        return _failure(HEALTH_ROLE_NOT_FOUND if _aws_error_code(exc) == "NoSuchEntity" else HEALTH_ASSUME_ROLE_FAILED)

    try:
        identity = _client("sts", region, credentials).get_caller_identity()
    except Exception:
        return _failure(HEALTH_ACCOUNT_MISMATCH)

    actual_account_id = str(identity.get("Account", "")).strip()
    if not re.fullmatch(r"[0-9]{12}", actual_account_id) or actual_account_id != arn_account_id:
        return _failure(HEALTH_ACCOUNT_MISMATCH, actual_account_id)

    try:
        sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"aws-security-coach-validate-{connector_id}"[:64],
            ExternalId=f"{external_id}-invalid",
            DurationSeconds=900,
        )
    except Exception as exc:
        if _aws_error_code(exc) not in {"AccessDenied", "AccessDeniedException"}:
            return _failure(HEALTH_ASSUME_ROLE_FAILED, actual_account_id)
    else:
        return _failure(HEALTH_ASSUME_ROLE_FAILED, actual_account_id)

    try:
        _validate_permissions(credentials, region, actual_account_id)
    except Exception:
        return _failure(HEALTH_PERMISSION_CHECK_FAILED, actual_account_id)

    return {"ok": True, "accountId": actual_account_id}
