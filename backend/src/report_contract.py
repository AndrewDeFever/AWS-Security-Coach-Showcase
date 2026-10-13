"""Validation and compatibility helpers for the AWS Security Coach report contract.

Slice 1 is intentionally isolated from deployed Lambda handlers. It establishes
fixtures and deterministic contract behavior before report emission changes.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

SCHEMA_VERSION = "1.0"
VALID_STATUSES = {"PASS", "FAIL", "WARN", "ERROR"}
VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
REQUIRED_FINDING_FIELDS = {"id", "title", "status", "severity", "details"}


class ReportContractError(ValueError):
    """Raised when a versioned report violates the V1 contract."""


def derive_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Derive summary counts from findings and reject unknown statuses."""
    statuses = []
    for index, finding in enumerate(findings):
        status = finding.get("status")
        if status not in VALID_STATUSES:
            raise ReportContractError(
                f"findings[{index}].status must be one of {sorted(VALID_STATUSES)}"
            )
        statuses.append(status)

    counts = Counter(statuses)
    return {
        "total": len(findings),
        "passed": counts["PASS"],
        "failed": counts["FAIL"],
        "warnings": counts["WARN"],
        "errors": counts["ERROR"],
    }


def report_format(report: dict[str, Any]) -> str:
    """Classify a report without treating legacy reports as malformed V1."""
    return "v1" if "schemaVersion" in report else "legacy"


def validate_v1_report(report: dict[str, Any]) -> None:
    """Validate required V1 envelope, finding fields, and derived summary."""
    if report.get("schemaVersion") != SCHEMA_VERSION:
        raise ReportContractError(f"schemaVersion must equal {SCHEMA_VERSION!r}")

    for key in ("scan", "target", "ruleset", "summary", "findings"):
        if key not in report:
            raise ReportContractError(f"missing required field: {key}")

    if not isinstance(report["findings"], list):
        raise ReportContractError("findings must be an array")

    scan = report["scan"]
    for key in ("scanId", "status", "generatedAt"):
        if not isinstance(scan.get(key), str) or not scan[key].strip():
            raise ReportContractError(f"scan.{key} must be a non-empty string")

    target = report["target"]
    if target.get("type") != "tool-account":
        raise ReportContractError("target.type must equal 'tool-account' in V1")
    if target.get("accountRef") != "configured-account":
        raise ReportContractError(
            "target.accountRef must equal 'configured-account' in V1"
        )

    ruleset = report["ruleset"]
    for key in ("id", "version"):
        if not isinstance(ruleset.get(key), str) or not ruleset[key].strip():
            raise ReportContractError(f"ruleset.{key} must be a non-empty string")
    if ruleset.get("checkCount") != len(report["findings"]):
        raise ReportContractError("ruleset.checkCount must equal findings length")

    for index, finding in enumerate(report["findings"]):
        if not isinstance(finding, dict):
            raise ReportContractError(f"findings[{index}] must be an object")

        missing = REQUIRED_FINDING_FIELDS - finding.keys()
        if missing:
            raise ReportContractError(
                f"findings[{index}] missing required fields: {sorted(missing)}"
            )

        for key in REQUIRED_FINDING_FIELDS:
            if not isinstance(finding[key], str) or not finding[key].strip():
                raise ReportContractError(
                    f"findings[{index}].{key} must be a non-empty string"
                )

        if finding["status"] not in VALID_STATUSES:
            raise ReportContractError(
                f"findings[{index}].status must be one of {sorted(VALID_STATUSES)}"
            )
        if finding["severity"] not in VALID_SEVERITIES:
            raise ReportContractError(
                f"findings[{index}].severity must be one of {sorted(VALID_SEVERITIES)}"
            )

    expected_summary = derive_summary(report["findings"])
    if report["summary"] != expected_summary:
        raise ReportContractError(
            f"summary must be derived from findings: expected {expected_summary}"
        )


def validate_report(report: dict[str, Any]) -> str:
    """Validate V1 reports while allowing legacy reports through the adapter path."""
    format_name = report_format(report)
    if format_name == "v1":
        validate_v1_report(report)
    return format_name
