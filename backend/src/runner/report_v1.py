"""V1 report emission adapter for the existing nine-check runner.

This module deliberately transforms the current runner report after evaluation.
It does not change AWS permissions, scan admission, or scan lifecycle behavior.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Any

from engineering_enrichment import enrich_engineering_guidance
from report_guidance import build_assessment_profile, enrich_findings

SCHEMA_VERSION = "1.0"
RULESET_ID = "aws-security-coach-core"
RULESET_VERSION = "1.1"
VALID_STATUSES = {"PASS", "FAIL", "WARN", "ERROR", "NOT_APPLICABLE"}
VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_DELIVERY_MODELS = {"managed", "self-service"}
REQUIRED_FINDING_FIELDS = {"id", "title", "status", "severity", "details"}


class ReportEmissionError(ValueError):
    """Raised before storage when the emitted report violates V1."""


def derive_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    statuses: list[str] = []
    for index, finding in enumerate(findings):
        status = finding.get("status")
        if status not in VALID_STATUSES:
            raise ReportEmissionError(
                f"findings[{index}].status must be one of {sorted(VALID_STATUSES)}"
            )
        statuses.append(status)

    counts = Counter(statuses)
    not_applicable = counts["NOT_APPLICABLE"]
    return {
        "total": len(findings),
        "evaluated": len(findings) - not_applicable,
        "passed": counts["PASS"],
        "failed": counts["FAIL"],
        "warnings": counts["WARN"],
        "errors": counts["ERROR"],
        "notApplicable": not_applicable,
    }


def _delivery_model_from_legacy_report(legacy_report: dict[str, Any]) -> str:
    value = str(legacy_report.get("reportDeliveryModel", "managed")).strip()
    if value not in VALID_DELIVERY_MODELS:
        raise ReportEmissionError("reportDeliveryModel is invalid")
    return value


def _managed_customer_from_legacy_report(
    legacy_report: dict[str, Any],
    delivery_model: str,
) -> dict[str, str] | None:
    if delivery_model != "managed":
        return None

    context = legacy_report.get("managedCustomerContext")
    if context is None:
        return None
    if not isinstance(context, dict):
        raise ReportEmissionError("managedCustomerContext must be an object")

    organization = str(context.get("organization", "")).strip()
    aws_account_id = str(context.get("awsAccountId", "")).strip()
    if not organization or len(organization) > 120:
        raise ReportEmissionError("managedCustomerContext.organization is invalid")
    if len(aws_account_id) != 12 or not aws_account_id.isdigit():
        raise ReportEmissionError("managedCustomerContext.awsAccountId is invalid")

    return {
        "organization": organization,
        "awsAccountId": aws_account_id,
    }


def _target_from_legacy_report(legacy_report: dict[str, Any], home_region: str) -> dict[str, Any]:
    connector = legacy_report.get("connectorContext")
    if connector is None:
        return {
            "type": "tool-account",
            "accountRef": "configured-account",
            "regionScope": [home_region],
        }

    if not isinstance(connector, dict):
        raise ReportEmissionError("connectorContext must be an object")

    connector_id = connector.get("connectorId")
    template_version = connector.get("templateVersion")
    connector_version = connector.get("connectorVersion")
    for field_name, value in (
        ("connectorId", connector_id),
        ("templateVersion", template_version),
        ("connectorVersion", connector_version),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ReportEmissionError(f"connectorContext.{field_name} must be a non-empty string")

    return {
        "type": "connector",
        "accountRef": "connected-account",
        "connectorId": connector_id,
        "templateVersion": template_version,
        "connectorVersion": connector_version,
        "regionScope": [home_region],
    }


def build_v1_report(legacy_report: dict[str, Any]) -> dict[str, Any]:
    """Wrap an evaluated legacy runner report in the V1 envelope."""
    raw_findings = legacy_report.get("findings")
    if not isinstance(raw_findings, list):
        raise ReportEmissionError("legacy report findings must be an array")

    findings = enrich_engineering_guidance(enrich_findings(raw_findings))
    legacy_scan = legacy_report.get("scan") or {}
    generated_at = legacy_report.get("generatedAt")
    home_region = os.environ.get("HOME_REGION", "us-east-1")
    delivery_model = _delivery_model_from_legacy_report(legacy_report)
    managed_customer = _managed_customer_from_legacy_report(legacy_report, delivery_model)

    report = {
        "schemaVersion": SCHEMA_VERSION,
        "deliveryModel": delivery_model,
        "scan": {
            "scanId": legacy_scan.get("scanId"),
            "status": "COMPLETE",
            "generatedAt": generated_at,
        },
        "target": _target_from_legacy_report(legacy_report, home_region),
        "ruleset": {
            "id": RULESET_ID,
            "version": RULESET_VERSION,
            "checkCount": len(findings),
        },
        "assessment": build_assessment_profile(len(findings)),
        "summary": derive_summary(findings),
        "findings": findings,
    }
    if managed_customer is not None:
        report["customer"] = managed_customer

    validate_v1_report(report)
    return report


def validate_v1_report(report: dict[str, Any]) -> None:
    if report.get("schemaVersion") != SCHEMA_VERSION:
        raise ReportEmissionError(f"schemaVersion must equal {SCHEMA_VERSION!r}")

    for key in ("deliveryModel", "scan", "target", "ruleset", "summary", "findings"):
        if key not in report:
            raise ReportEmissionError(f"missing required field: {key}")

    if report.get("deliveryModel") not in VALID_DELIVERY_MODELS:
        raise ReportEmissionError("deliveryModel must be managed or self-service")

    customer = report.get("customer")
    if customer is not None:
        if report.get("deliveryModel") != "managed" or not isinstance(customer, dict):
            raise ReportEmissionError("customer metadata is only valid for managed reports")
        organization = customer.get("organization")
        aws_account_id = customer.get("awsAccountId")
        if not isinstance(organization, str) or not organization.strip() or len(organization.strip()) > 120:
            raise ReportEmissionError("customer.organization is invalid")
        if not isinstance(aws_account_id, str) or len(aws_account_id) != 12 or not aws_account_id.isdigit():
            raise ReportEmissionError("customer.awsAccountId is invalid")

    findings = report["findings"]
    if not isinstance(findings, list):
        raise ReportEmissionError("findings must be an array")

    scan = report["scan"]
    for key in ("scanId", "status", "generatedAt"):
        if not isinstance(scan.get(key), str) or not scan[key].strip():
            raise ReportEmissionError(f"scan.{key} must be a non-empty string")

    target = report["target"]
    target_type = target.get("type")
    if target_type not in {"tool-account", "connector"}:
        raise ReportEmissionError("target.type must equal 'tool-account' or 'connector'")
    expected_account_ref = "configured-account" if target_type == "tool-account" else "connected-account"
    if target.get("accountRef") != expected_account_ref:
        raise ReportEmissionError("target.accountRef must remain sanitized")
    if not isinstance(target.get("regionScope"), list) or not target["regionScope"]:
        raise ReportEmissionError("target.regionScope must contain the configured region")

    if target_type == "tool-account":
        for forbidden in ("connectorId", "templateVersion", "connectorVersion"):
            if forbidden in target:
                raise ReportEmissionError(f"tool-account target must not contain {forbidden}")
    else:
        for key in ("connectorId", "templateVersion", "connectorVersion"):
            if not isinstance(target.get(key), str) or not target[key].strip():
                raise ReportEmissionError(f"target.{key} must be a non-empty string")

    ruleset = report["ruleset"]
    if ruleset.get("checkCount") != len(findings):
        raise ReportEmissionError("ruleset.checkCount must equal findings length")

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise ReportEmissionError(f"findings[{index}] must be an object")
        missing = REQUIRED_FINDING_FIELDS - finding.keys()
        if missing:
            raise ReportEmissionError(
                f"findings[{index}] missing required fields: {sorted(missing)}"
            )
        if finding.get("status") not in VALID_STATUSES:
            raise ReportEmissionError(f"findings[{index}] has invalid status")
        if finding.get("severity") not in VALID_SEVERITIES:
            raise ReportEmissionError(f"findings[{index}] has invalid severity")

    expected = derive_summary(findings)
    if report["summary"] != expected:
        raise ReportEmissionError(
            f"summary must be derived from findings: expected {expected}"
        )
