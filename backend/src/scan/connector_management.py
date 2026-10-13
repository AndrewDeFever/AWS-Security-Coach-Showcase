import datetime
import json
import os
import re
import secrets
import time
import uuid

import boto3


CONNECTOR_ID_PREFIX = "con_"
CONNECTOR_STATUS_PENDING = "PENDING"
CONNECTOR_STATUS_VALIDATING = "VALIDATING"
CONNECTOR_STATUS_APPROVAL_PENDING = "APPROVAL_PENDING"
CONNECTOR_STATUS_ENABLED = "ENABLED"
CONNECTOR_STATUS_UNHEALTHY = "UNHEALTHY"
CONNECTOR_TEMPLATE_VERSION = "1.1.0"
CONNECTOR_VERSION = "1.0"
SUPPORTED_HOME_REGION = "us-east-1"
MANAGEMENT_BUCKET = "ACTIVE"
DISPLAY_NAME_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]{1,80}$")
CUSTOMER_ORGANIZATION_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]{1,120}$")
CONNECTOR_ID_PATTERN = re.compile(
    r"^con_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
CONNECTOR_ROLE_ARN_PATTERN = re.compile(
    r"^arn:aws:iam::(?P<account>[0-9]{12}):role/aws-security-coach/[A-Za-z0-9+=,.@_/-]+$"
)

HEALTH_CONFIG_MISSING = "CONFIG_MISSING"
HEALTH_CONFIG_INVALID = "CONFIG_INVALID"
HEALTH_ASSUME_ROLE_FAILED = "ASSUME_ROLE_FAILED"
HEALTH_ACCOUNT_MISMATCH = "ACCOUNT_MISMATCH"
HEALTH_PERMISSION_CHECK_FAILED = "PERMISSION_CHECK_FAILED"
HEALTH_UNSUPPORTED_CONNECTOR_VERSION = "UNSUPPORTED_CONNECTOR_VERSION"
HEALTH_ROLE_NOT_FOUND = "ROLE_NOT_FOUND"
HEALTH_UNKNOWN_VALIDATION_ERROR = "UNKNOWN_VALIDATION_ERROR"


class ConnectorValidationError(RuntimeError):
    def __init__(self, health_reason: str):
        super().__init__(health_reason)
        self.health_reason = health_reason


def _utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")


def _management_sort_key(status: str, now_ms: int, connector_id: str) -> str:
    priority = {
        "UNHEALTHY": 0,
        "APPROVAL_PENDING": 1,
        "PENDING": 2,
        "VALIDATING": 3,
        "DISABLED": 4,
        "ENABLED": 5,
        "REVOKED": 6,
    }[status]
    reverse_ms = 9_999_999_999_999 - now_ms
    return f"{priority}#{reverse_ms:013d}#{connector_id}"


def _status_fields(status: str, connector_id: str) -> tuple[str, str, str]:
    now_iso = _utc_now()
    now_ms = int(time.time() * 1000)
    return (
        now_iso,
        _management_sort_key(status, now_ms, connector_id),
        f"{now_iso}#{connector_id}",
    )


def _aws_error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return ""
    error = response.get("Error") or {}
    if not isinstance(error, dict):
        return ""
    return str(error.get("Code", ""))


def _connector_id(value: str) -> str:
    connector_id = str(value or "").strip()
    if not CONNECTOR_ID_PATTERN.fullmatch(connector_id):
        raise ValueError("Invalid connector identifier")
    return connector_id


def _customer_organization(value: str) -> str:
    organization = str(value or "").strip()
    if not CUSTOMER_ORGANIZATION_PATTERN.fullmatch(organization):
        raise ValueError("Invalid customer organization")
    return organization


def validate_provisioning_input(data: dict) -> tuple[str, str]:
    if not isinstance(data, dict):
        raise ValueError("Invalid request body")
    allowed = {"displayName", "homeRegion", "customerOrganization"}
    if not set(data).issubset(allowed) or not {"displayName", "homeRegion"}.issubset(data):
        raise ValueError("Only displayName, homeRegion, and optional customerOrganization are accepted")
    display_name = str(data.get("displayName", "")).strip()
    home_region = str(data.get("homeRegion", "")).strip()
    if not DISPLAY_NAME_PATTERN.fullmatch(display_name):
        raise ValueError("Invalid displayName")
    if home_region != SUPPORTED_HOME_REGION:
        raise ValueError("Unsupported homeRegion")
    if "customerOrganization" in data:
        _customer_organization(data.get("customerOrganization", ""))
    return display_name, home_region


def validate_registration_input(data: dict) -> tuple[str, str]:
    if not isinstance(data, dict) or set(data) != {"connectorRoleArn"}:
        raise ValueError("Only connectorRoleArn is accepted")
    role_arn = str(data.get("connectorRoleArn", "")).strip()
    match = CONNECTOR_ROLE_ARN_PATTERN.fullmatch(role_arn)
    if not match:
        raise ValueError("Connector role ARN is outside the managed role boundary")
    return role_arn, match.group("account")


def external_id_parameter_name(environment_name: str, connector_id: str) -> str:
    environment_name = str(environment_name or "").strip()
    if environment_name not in {"dev", "prod"}:
        raise RuntimeError("Connector environment configuration is invalid")
    return f"/security-coach/{environment_name}/connectors/{_connector_id(connector_id)}/external-id"


def provision_connector(
    connectors_table,
    ssm_client,
    environment_name: str,
    kms_key_id: str,
    data: dict,
    *,
    owner_requester_ref: str | None = None,
    customer_organization: str | None = None,
) -> dict:
    environment_name = str(environment_name or "").strip()
    kms_key_id = str(kms_key_id or "").strip()
    owner_requester_ref = str(owner_requester_ref or "").strip()
    if environment_name not in {"dev", "prod"}:
        raise RuntimeError("Connector environment configuration is invalid")
    if not kms_key_id:
        raise RuntimeError("Connector KMS configuration is missing")
    display_name, home_region = validate_provisioning_input(data)
    customer_organization = str(
        customer_organization or data.get("customerOrganization", "")
    ).strip()
    if customer_organization:
        customer_organization = _customer_organization(customer_organization)
    connector_id = f"{CONNECTOR_ID_PREFIX}{uuid.uuid4()}"
    external_id = secrets.token_hex(32)
    now_iso = _utc_now()
    now_ms = int(time.time() * 1000)
    parameter_name = external_id_parameter_name(environment_name, connector_id)
    item = {
        "connectorId": connector_id,
        "displayName": display_name,
        "status": CONNECTOR_STATUS_PENDING,
        "connectorRoleArn": "",
        "expectedAccountId": "",
        "homeRegion": home_region,
        "templateVersion": CONNECTOR_TEMPLATE_VERSION,
        "connectorVersion": CONNECTOR_VERSION,
        "createdAt": now_iso,
        "updatedAt": now_iso,
        "lastValidatedAt": None,
        "healthReason": None,
        "managementBucket": MANAGEMENT_BUCKET,
        "managementSortKey": _management_sort_key(CONNECTOR_STATUS_PENDING, now_ms, connector_id),
        "statusBucket": CONNECTOR_STATUS_PENDING,
        "statusSortKey": f"{now_iso}#{connector_id}",
    }
    if owner_requester_ref:
        item["ownerRequesterRef"] = owner_requester_ref
    if customer_organization:
        item["customerOrganization"] = customer_organization
    ssm_client.put_parameter(
        Name=parameter_name,
        Description="AWS Security Coach connector ExternalId",
        Value=external_id,
        Type="SecureString",
        KeyId=kms_key_id,
        Overwrite=False,
        Tier="Standard",
        DataType="text",
    )
    try:
        connectors_table.put_item(Item=item, ConditionExpression="attribute_not_exists(connectorId)")
    except Exception:
        try:
            ssm_client.delete_parameter(Name=parameter_name)
        except Exception as rollback_exc:
            print("Connector provisioning rollback failed:", type(rollback_exc).__name__)
        raise
    result = {
        "connectorId": connector_id,
        "displayName": display_name,
        "status": CONNECTOR_STATUS_PENDING,
        "homeRegion": home_region,
        "templateVersion": CONNECTOR_TEMPLATE_VERSION,
        "connectorVersion": CONNECTOR_VERSION,
        "createdAt": now_iso,
    }
    if customer_organization:
        result["customerOrganization"] = customer_organization
    return result


def _update_status(connectors_table, connector_id: str, status: str, *, connector_role_arn: str | None = None, expected_account_id: str | None = None, health_reason: str | None = None, last_validated_at: str | None = None, expected_current_statuses: tuple[str, ...] = (CONNECTOR_STATUS_VALIDATING,)):
    now_iso, management_sort_key, status_sort_key = _status_fields(status, connector_id)
    expression_names = {"#status": "status"}
    values = {
        ":status": status,
        ":updatedAt": now_iso,
        ":managementBucket": MANAGEMENT_BUCKET,
        ":managementSortKey": management_sort_key,
        ":statusBucket": status,
        ":statusSortKey": status_sort_key,
        ":healthReason": health_reason,
    }
    assignments = ["#status = :status", "updatedAt = :updatedAt", "managementBucket = :managementBucket", "managementSortKey = :managementSortKey", "statusBucket = :statusBucket", "statusSortKey = :statusSortKey", "healthReason = :healthReason"]
    if connector_role_arn is not None:
        values[":connectorRoleArn"] = connector_role_arn
        assignments.append("connectorRoleArn = :connectorRoleArn")
    if expected_account_id is not None:
        values[":expectedAccountId"] = expected_account_id
        assignments.append("expectedAccountId = :expectedAccountId")
    if last_validated_at is not None:
        values[":lastValidatedAt"] = last_validated_at
        assignments.append("lastValidatedAt = :lastValidatedAt")
    condition_tokens = []
    for index, current_status in enumerate(expected_current_statuses):
        token = f":expected{index}"
        values[token] = current_status
        condition_tokens.append(token)
    condition_expression = f"#status IN ({', '.join(condition_tokens)})" if len(condition_tokens) > 1 else f"#status = {condition_tokens[0]}"
    return connectors_table.update_item(
        Key={"connectorId": connector_id},
        UpdateExpression="SET " + ", ".join(assignments),
        ConditionExpression=condition_expression,
        ExpressionAttributeNames=expression_names,
        ExpressionAttributeValues=values,
        ReturnValues="ALL_NEW",
    )


def _validation_failure(connectors_table, connector_id: str, health_reason: str, *, expected_account_id: str | None = None) -> ConnectorValidationError:
    _update_status(
        connectors_table,
        connector_id,
        CONNECTOR_STATUS_UNHEALTHY,
        expected_account_id=expected_account_id,
        health_reason=health_reason,
        last_validated_at=_utc_now(),
    )
    return ConnectorValidationError(health_reason)


def _invoke_runner_validation(connector_id: str) -> dict:
    runner_function_name = os.environ.get("RUNNER_FUNCTION_NAME", "").strip()
    if not runner_function_name:
        raise RuntimeError("Runner validation configuration is missing")
    response = boto3.client("lambda").invoke(
        FunctionName=runner_function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps({"operation": "VALIDATE_CONNECTOR", "connectorId": connector_id}).encode("utf-8"),
    )
    if response.get("FunctionError"):
        raise RuntimeError("Runner connector validation failed")
    payload = response.get("Payload")
    raw = payload.read() if hasattr(payload, "read") else payload
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    result = json.loads(raw or "{}") if isinstance(raw, str) else raw
    if not isinstance(result, dict):
        raise RuntimeError("Runner connector validation returned an invalid result")
    return result


def _finish_runner_validation(
    connectors_table,
    connector_id: str,
    item: dict,
    result: dict,
    *,
    final_status: str = CONNECTOR_STATUS_APPROVAL_PENDING,
) -> dict:
    if final_status not in {CONNECTOR_STATUS_APPROVAL_PENDING, CONNECTOR_STATUS_ENABLED}:
        raise RuntimeError("Connector validation final status is invalid")
    if result.get("ok") is not True:
        reason = str(result.get("healthReason", "")).strip()
        if reason not in {
            HEALTH_CONFIG_MISSING, HEALTH_CONFIG_INVALID, HEALTH_ASSUME_ROLE_FAILED,
            HEALTH_ACCOUNT_MISMATCH, HEALTH_PERMISSION_CHECK_FAILED,
            HEALTH_UNSUPPORTED_CONNECTOR_VERSION, HEALTH_ROLE_NOT_FOUND,
            HEALTH_UNKNOWN_VALIDATION_ERROR,
        }:
            reason = HEALTH_UNKNOWN_VALIDATION_ERROR
        account_id = str(result.get("accountId", "")).strip()
        raise _validation_failure(
            connectors_table,
            connector_id,
            reason,
            expected_account_id=account_id if re.fullmatch(r"[0-9]{12}", account_id) else None,
        )
    actual_account_id = str(result.get("accountId", "")).strip()
    if not re.fullmatch(r"[0-9]{12}", actual_account_id):
        raise _validation_failure(connectors_table, connector_id, HEALTH_ACCOUNT_MISMATCH)
    validated_at = _utc_now()
    final = _update_status(
        connectors_table,
        connector_id,
        final_status,
        expected_account_id=actual_account_id,
        health_reason=None,
        last_validated_at=validated_at,
    )
    attributes = final.get("Attributes") or {}
    result_payload = {
        "connectorId": connector_id,
        "displayName": str(attributes.get("displayName") or item.get("displayName", "")),
        "status": final_status,
        "homeRegion": str(item.get("homeRegion", "")),
        "templateVersion": str(item.get("templateVersion", "")),
        "connectorVersion": str(item.get("connectorVersion", "")),
        "expectedAccountId": actual_account_id,
        "lastValidatedAt": validated_at,
        "healthReason": None,
    }
    customer_organization = str(item.get("customerOrganization", "")).strip()
    if customer_organization:
        result_payload["customerOrganization"] = customer_organization
    return result_payload


def register_connector(connectors_table, ssm_client, sts_client, client_factory, environment_name: str, connector_id: str, data: dict, *, final_status: str = CONNECTOR_STATUS_APPROVAL_PENDING) -> dict:
    connector_id = _connector_id(connector_id)
    environment_name = str(environment_name or "").strip()
    if environment_name not in {"dev", "prod"}:
        raise RuntimeError("Connector environment configuration is invalid")
    if final_status not in {CONNECTOR_STATUS_APPROVAL_PENDING, CONNECTOR_STATUS_ENABLED}:
        raise RuntimeError("Connector validation final status is invalid")
    role_arn, _ = validate_registration_input(data)
    response = connectors_table.get_item(Key={"connectorId": connector_id}, ConsistentRead=True)
    item = response.get("Item") or {}
    if item.get("connectorId") != connector_id:
        raise LookupError("Connector not found")
    current_status = str(item.get("status", "")).strip()
    if current_status not in {CONNECTOR_STATUS_PENDING, CONNECTOR_STATUS_UNHEALTHY}:
        raise RuntimeError("Connector cannot be registered from its current status")
    home_region = str(item.get("homeRegion", "")).strip()
    if home_region != SUPPORTED_HOME_REGION:
        raise ConnectorValidationError(HEALTH_CONFIG_INVALID)
    _update_status(
        connectors_table,
        connector_id,
        CONNECTOR_STATUS_VALIDATING,
        connector_role_arn=role_arn,
        expected_account_id="",
        health_reason=None,
        expected_current_statuses=(CONNECTOR_STATUS_PENDING, CONNECTOR_STATUS_UNHEALTHY),
    )
    if str(item.get("connectorVersion", "")).strip() != CONNECTOR_VERSION:
        raise _validation_failure(connectors_table, connector_id, HEALTH_UNSUPPORTED_CONNECTOR_VERSION)

    # Connector validation is intentionally runner-only. ScanFunction never reads
    # the ExternalId and never assumes workload roles directly.
    try:
        result = _invoke_runner_validation(connector_id)
    except Exception as exc:
        raise _validation_failure(connectors_table, connector_id, HEALTH_UNKNOWN_VALIDATION_ERROR) from exc
    return _finish_runner_validation(
        connectors_table,
        connector_id,
        item,
        result,
        final_status=final_status,
    )
