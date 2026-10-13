from __future__ import annotations

import json
import re
from typing import Any

import boto3


ROLE_ARN_PATTERN = re.compile(
    r"^arn:aws:iam::(?P<account>[0-9]{12}):role/(?P<name>[A-Za-z0-9+=,.@_/-]+)$"
)
CONNECTOR_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
TEMPLATE_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SUPPORTED_CONNECTOR_VERSION = "1.0"
SUPPORTED_HOME_REGION = "us-east-1"


class ConnectorNotFound(RuntimeError):
    pass


def _validate_connector_id(connector_id: str) -> str:
    value = str(connector_id or "").strip()
    if not CONNECTOR_ID_PATTERN.fullmatch(value):
        raise RuntimeError("Connector identifier is invalid")
    return value


def _validate_role_arn(role_arn: str, expected_account_id: str | None = None):
    match = ROLE_ARN_PATTERN.fullmatch(str(role_arn or "").strip())
    if not match:
        raise RuntimeError("Connector role ARN is invalid")

    account_id = match.group("account")
    if expected_account_id is not None and account_id != expected_account_id:
        raise RuntimeError("Connector role ARN account does not match expected account")

    return match


def external_id_parameter_name(environment_name: str, connector_id: str) -> str:
    environment = str(environment_name or "").strip()
    if environment not in ("dev", "prod"):
        raise RuntimeError("Connector environment is invalid")

    validated_connector_id = _validate_connector_id(connector_id)
    return f"/security-coach/{environment}/connectors/{validated_connector_id}/external-id"


def load_registered_connector(
    connectors_table: Any,
    ssm_client: Any,
    connector_id: str,
    environment_name: str,
) -> dict:
    validated_connector_id = _validate_connector_id(connector_id)

    response = connectors_table.get_item(
        Key={"connectorId": validated_connector_id},
        ConsistentRead=True,
    )
    item = response.get("Item") or {}
    if not item:
        raise ConnectorNotFound("Connector is not registered")

    if item.get("connectorId") != validated_connector_id:
        raise RuntimeError("Connector registry identifier mismatch")
    if item.get("status") != "ENABLED":
        raise RuntimeError("Connector is not enabled")

    expected_account_id = str(item.get("expectedAccountId", "")).strip()
    if not re.fullmatch(r"[0-9]{12}", expected_account_id):
        raise RuntimeError("Connector expected account is invalid")

    role_arn = str(item.get("connectorRoleArn", "")).strip()
    _validate_role_arn(role_arn, expected_account_id)

    home_region = str(item.get("homeRegion", "")).strip()
    if home_region != SUPPORTED_HOME_REGION:
        raise RuntimeError("Connector home region is unsupported")

    template_version = str(item.get("templateVersion", "")).strip()
    if not TEMPLATE_VERSION_PATTERN.fullmatch(template_version):
        raise RuntimeError("Connector template version is invalid")

    connector_version = str(item.get("connectorVersion", "")).strip()
    if connector_version != SUPPORTED_CONNECTOR_VERSION:
        raise RuntimeError("Connector runtime version is unsupported")

    parameter_name = external_id_parameter_name(
        environment_name,
        validated_connector_id,
    )
    secret_response = ssm_client.get_parameter(
        Name=parameter_name,
        WithDecryption=True,
    )
    external_id = str((secret_response.get("Parameter") or {}).get("Value", "")).strip()
    if len(external_id) < 32:
        raise RuntimeError("Connector ExternalId is invalid")

    return {
        "connectorId": validated_connector_id,
        "roleArn": role_arn,
        "externalId": external_id,
        "homeRegion": home_region,
        "expectedAccountId": expected_account_id,
        "templateVersion": template_version,
        "connectorVersion": connector_version,
    }


def load_connector(ssm_client: Any, parameter_name: str, expected_connector_id: str) -> dict:
    """Load the temporary legacy pilot record during migration."""
    if not parameter_name or not expected_connector_id:
        raise RuntimeError("Connector configuration is incomplete")

    response = ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
    raw_value = (response.get("Parameter") or {}).get("Value", "")

    try:
        connector = json.loads(raw_value)
    except Exception as exc:
        raise RuntimeError("Connector configuration is not valid JSON") from exc

    if not isinstance(connector, dict):
        raise RuntimeError("Connector configuration must be an object")
    if connector.get("connectorId") != expected_connector_id:
        raise RuntimeError("Connector identifier does not match protected configuration")
    if connector.get("enabled") is not True:
        raise RuntimeError("Connector is disabled")

    role_arn = str(connector.get("roleArn", "")).strip()
    role_match = _validate_role_arn(role_arn)

    external_id = str(connector.get("externalId", "")).strip()
    if len(external_id) < 32:
        raise RuntimeError("Connector ExternalId is invalid")

    home_region = str(connector.get("homeRegion", "")).strip()
    if home_region != SUPPORTED_HOME_REGION:
        raise RuntimeError("Connector home region is outside the approved pilot boundary")

    return {
        "connectorId": expected_connector_id,
        "roleArn": role_arn,
        "externalId": external_id,
        "homeRegion": home_region,
        "expectedAccountId": role_match.group("account"),
        "connectorVersion": SUPPORTED_CONNECTOR_VERSION,
    }


def _role_session_name(connector_id: str) -> str:
    safe_id = re.sub(r"[^A-Za-z0-9+=,.@_-]", "-", str(connector_id or "connector"))
    return f"aws-security-coach-{safe_id}"[:64]


def assume_connector_clients(base_sts_client: Any, connector: dict) -> dict:
    response = base_sts_client.assume_role(
        RoleArn=connector["roleArn"],
        RoleSessionName=_role_session_name(connector["connectorId"]),
        ExternalId=connector["externalId"],
        DurationSeconds=900,
    )
    credentials = response.get("Credentials") or {}

    required = ("AccessKeyId", "SecretAccessKey", "SessionToken")
    if any(not credentials.get(key) for key in required):
        raise RuntimeError("STS did not return complete temporary credentials")

    credential_args = {
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"],
    }
    home_region = connector["homeRegion"]

    assumed_sts = boto3.client("sts", region_name=home_region, **credential_args)
    identity = assumed_sts.get_caller_identity()
    if str(identity.get("Account", "")) != connector["expectedAccountId"]:
        raise RuntimeError("Assumed connector identity does not match the configured role account")

    def ec2_client_for_region(region_name: str):
        region = str(region_name or "").strip()
        if not region:
            raise RuntimeError("EC2 Region is invalid")
        return boto3.client("ec2", region_name=region, **credential_args)

    return {
        "iam": boto3.client("iam", region_name=home_region, **credential_args),
        "cloudtrail": boto3.client("cloudtrail", region_name=home_region, **credential_args),
        "s3control": boto3.client("s3control", region_name=home_region, **credential_args),
        "sts": assumed_sts,
        "ec2": ec2_client_for_region(home_region),
        "ec2ClientForRegion": ec2_client_for_region,
    }
