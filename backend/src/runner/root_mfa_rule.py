"""Deterministic evaluator for the root-user MFA control.

The IAM credential report is authoritative for whether root sign-in credentials
exist. AWS Organizations member accounts can intentionally have root credentials
removed; in that state MFA is not applicable and credentials must not be recreated
solely to satisfy this control.
"""

from __future__ import annotations

from typing import Any

RULE = {
    "id": "iam-root-mfa-enabled",
    "service": "iam",
    "control": "root-mfa",
    "version": "1.1",
}


def _boolean_field(row: dict[str, Any], field_name: str) -> bool:
    value = str(row.get(field_name, "")).strip().upper()
    if value not in {"TRUE", "FALSE"}:
        raise ValueError(f"IAM credential report field {field_name} is unavailable")
    return value == "TRUE"


def evaluate(iam_client: Any, credential_report_rows: list[dict[str, Any]] | None = None) -> dict[str, str]:
    """Evaluate root MFA, including the centralized-root no-credentials state."""
    del iam_client  # Kept in the signature so the rule remains an IAM control descriptor.

    try:
        rows = credential_report_rows or []
        root_row = next(
            (row for row in rows if row.get("user") == "<root_account>"),
            None,
        )
        if not root_row:
            raise ValueError("IAM credential report does not contain the root account row")

        password_enabled = _boolean_field(root_row, "password_enabled")
        if not password_enabled:
            return {
                "id": RULE["id"],
                "title": "Root user MFA is not applicable",
                "severity": "INFO",
                "status": "NOT_APPLICABLE",
                "details": (
                    "Root sign-in credentials are not present for this AWS account. "
                    "MFA enrollment is therefore not applicable to this control; do not "
                    "recreate root credentials solely to satisfy the assessment."
                ),
            }

        mfa_active = _boolean_field(root_row, "mfa_active")
        if mfa_active:
            return {
                "id": RULE["id"],
                "title": "Root user MFA is enabled",
                "severity": "INFO",
                "status": "PASS",
                "details": "Root sign-in credentials are present and the root user has MFA enabled.",
            }

        return {
            "id": RULE["id"],
            "title": "Root user MFA is not enabled",
            "severity": "HIGH",
            "status": "FAIL",
            "details": "Root sign-in credentials are present, but the root user does not have MFA enabled.",
        }

    except Exception as error:
        return {
            "id": RULE["id"],
            "title": "Root user MFA check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": f"Runner could not establish the root-user MFA state: {str(error)}",
        }
