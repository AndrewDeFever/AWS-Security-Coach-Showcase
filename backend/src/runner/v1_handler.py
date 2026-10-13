"""Lambda entry point for V1 report emission and bounded target execution.

The existing runner remains authoritative for scan lifecycle and the nine checks.
Connector execution resolves registered connectors from the management-plane
registry. Activation validation also executes here so the workload account only
needs to trust this exact runner principal.
"""

from __future__ import annotations

import os

import boto3

import lambda_function as runner
from connector_context import assume_connector_clients, load_registered_connector
from connector_validation import validate_connector
from regional_security_group_rule import evaluate as evaluate_regional_security_groups
from report_v1 import build_v1_report
from root_mfa_rule import evaluate as evaluate_root_mfa
from unused_access_key_rule import evaluate as evaluate_unused_access_keys


_ORIGINAL_WRITE_REPORT = runner._write_report
_ORIGINAL_BUILD_REPORT = runner._build_report
_ORIGINAL_LOAD_CREDENTIAL_REPORT_ROWS = runner._load_credential_report_rows
_ORIGINAL_CHECK_SECURITY_GROUPS = runner._check_security_groups_open_admin_ports
_TOOL_DDB = boto3.resource("dynamodb")
_TOOL_SSM = boto3.client("ssm")
_TOOL_STS = boto3.client("sts")
_CAPTURED_CREDENTIAL_REPORT_ROWS: list[dict] = []
_EC2_CLIENT_FOR_REGION = None


def _regional_scope_label(report: dict) -> str | None:
    for finding in report.get("findings", []):
        if finding.get("id") != "ec2-security-groups-open-admin-ports":
            continue
        evaluated = finding.get("regionsEvaluated")
        unavailable = finding.get("regionsUnavailable")
        if not isinstance(evaluated, list) or not isinstance(unavailable, list):
            return None
        total = len(evaluated) + len(unavailable)
        if total <= 0:
            return None
        if unavailable:
            return (
                "Account-global controls; SG: "
                f"{len(evaluated)} of {total} enabled Regions evaluated"
            )
        return f"Account-global controls; SG: all {total} enabled Regions"
    return None


def _write_v1_report(bucket: str, reports_prefix: str, scan_id: str, report: dict):
    versioned_report = build_v1_report(report)
    regional_scope = _regional_scope_label(report)
    if regional_scope:
        versioned_report["target"]["regionScope"] = [regional_scope]
    return _ORIGINAL_WRITE_REPORT(bucket, reports_prefix, scan_id, versioned_report)


def _load_credential_report_rows_with_capture():
    global _CAPTURED_CREDENTIAL_REPORT_ROWS
    rows = _ORIGINAL_LOAD_CREDENTIAL_REPORT_ROWS()
    _CAPTURED_CREDENTIAL_REPORT_ROWS = rows
    return rows


def _check_root_mfa_from_descriptor():
    return evaluate_root_mfa(runner.iam, _CAPTURED_CREDENTIAL_REPORT_ROWS)


def _check_unused_access_keys_from_descriptor(credential_report_rows: list[dict]):
    return evaluate_unused_access_keys(credential_report_rows)


def _check_security_groups_from_descriptor():
    if _EC2_CLIENT_FOR_REGION is None:
        return _ORIGINAL_CHECK_SECURITY_GROUPS()
    return evaluate_regional_security_groups(runner.ec2, _EC2_CLIENT_FOR_REGION)


def _connector_supports_regional_security_groups(connector: dict) -> bool:
    try:
        version = tuple(
            int(part)
            for part in str(connector.get("templateVersion", "")).split(".")
        )
    except ValueError:
        return False
    return version >= (1, 1, 0)


def _connector_safe_wording(report: dict) -> dict:
    for finding in report.get("findings", []):
        details = finding.get("details")
        if isinstance(details, str):
            finding["details"] = details.replace("tool account", "connected account")
    return report


def _stamp_connector_context(report: dict, connector: dict) -> dict:
    report["reportDeliveryModel"] = connector.get("reportDeliveryModel", "managed")
    report["connectorContext"] = {
        "connectorId": connector["connectorId"],
        "templateVersion": connector["templateVersion"],
        "connectorVersion": connector["connectorVersion"],
    }
    if report["reportDeliveryModel"] == "managed":
        customer_organization = str(connector.get("customerOrganization", "")).strip()
        aws_account_id = str(connector.get("expectedAccountId", "")).strip()
        if customer_organization and aws_account_id:
            report["managedCustomerContext"] = {
                "organization": customer_organization,
                "awsAccountId": aws_account_id,
            }
    return report


def _log_connector_resolution(source: str, connector: dict) -> None:
    print(
        "CONNECTOR RESOLUTION: "
        f"source={source} "
        f"connectorId={connector.get('connectorId', '')} "
        f"roleArn={connector.get('roleArn', '')} "
        f"homeRegion={connector.get('homeRegion', '')}"
    )


def _load_target_connector(connector_id: str) -> dict:
    environment_name = os.environ.get("ENVIRONMENT_NAME", "").strip()
    connectors_table_name = os.environ.get("CONNECTORS_TABLE", "").strip()
    if not environment_name or not connectors_table_name:
        raise RuntimeError("Connector registry configuration is incomplete")

    table = _TOOL_DDB.Table(connectors_table_name)
    connector = load_registered_connector(
        table,
        _TOOL_SSM,
        connector_id,
        environment_name,
    )
    registry_response = table.get_item(
        Key={"connectorId": connector["connectorId"]},
        ConsistentRead=True,
    )
    registry_item = registry_response.get("Item") or {}
    connector["reportDeliveryModel"] = (
        "self-service"
        if str(registry_item.get("ownerRequesterRef", "")).strip()
        else "managed"
    )
    connector["customerOrganization"] = str(
        registry_item.get("customerOrganization", "")
    ).strip()
    _log_connector_resolution("registry", connector)
    return connector


def _build_target_report(scan_item: dict, loaded_rules: list):
    global _EC2_CLIENT_FOR_REGION

    target_type = str(scan_item.get("targetType", "tool-account"))
    if target_type == "tool-account":
        report = _ORIGINAL_BUILD_REPORT(scan_item, loaded_rules)
        report["reportDeliveryModel"] = "managed"
        return report

    if target_type != "connector":
        raise RuntimeError("Unsupported runner target type")

    connector_id = str(
        scan_item.get("connectorId") or scan_item.get("targetId") or ""
    ).strip()
    if not connector_id:
        raise RuntimeError("Connector identifier is missing")

    connector = _load_target_connector(connector_id)
    clients = assume_connector_clients(_TOOL_STS, connector)

    originals = {
        "iam": runner.iam,
        "cloudtrail": runner.cloudtrail,
        "s3control": runner.s3control,
        "sts": runner.sts,
        "ec2": runner.ec2,
        "home_region": runner.HOME_REGION,
        "ec2_client_for_region": _EC2_CLIENT_FOR_REGION,
    }

    try:
        runner.iam = clients["iam"]
        runner.cloudtrail = clients["cloudtrail"]
        runner.s3control = clients["s3control"]
        runner.sts = clients["sts"]
        runner.ec2 = clients["ec2"]
        runner.HOME_REGION = connector["homeRegion"]
        if _connector_supports_regional_security_groups(connector):
            _EC2_CLIENT_FOR_REGION = clients["ec2ClientForRegion"]
        else:
            _EC2_CLIENT_FOR_REGION = None
        report = _ORIGINAL_BUILD_REPORT(scan_item, loaded_rules)
        report = _connector_safe_wording(report)
        return _stamp_connector_context(report, connector)
    finally:
        runner.iam = originals["iam"]
        runner.cloudtrail = originals["cloudtrail"]
        runner.s3control = originals["s3control"]
        runner.sts = originals["sts"]
        runner.ec2 = originals["ec2"]
        runner.HOME_REGION = originals["home_region"]
        _EC2_CLIENT_FOR_REGION = originals["ec2_client_for_region"]


def _validation_response(event: dict) -> dict:
    connectors_table_name = os.environ.get("CONNECTORS_TABLE", "").strip()
    environment_name = os.environ.get("ENVIRONMENT_NAME", "").strip()
    connector_id = str(event.get("connectorId", "")).strip()
    if not connectors_table_name or environment_name not in {"dev", "prod"}:
        return {"ok": False, "healthReason": "CONFIG_INVALID"}

    return validate_connector(
        _TOOL_DDB.Table(connectors_table_name),
        _TOOL_SSM,
        _TOOL_STS,
        environment_name,
        connector_id,
    )


def lambda_handler(event, context):
    global _CAPTURED_CREDENTIAL_REPORT_ROWS

    if isinstance(event, dict) and event.get("operation") == "VALIDATE_CONNECTOR":
        return _validation_response(event)

    _CAPTURED_CREDENTIAL_REPORT_ROWS = []
    runner._load_credential_report_rows = _load_credential_report_rows_with_capture
    runner._check_root_mfa = _check_root_mfa_from_descriptor
    runner._check_unused_iam_access_keys = _check_unused_access_keys_from_descriptor
    runner._check_security_groups_open_admin_ports = _check_security_groups_from_descriptor
    runner._build_report = _build_target_report
    runner._write_report = _write_v1_report
    return runner.lambda_handler(event, context)
