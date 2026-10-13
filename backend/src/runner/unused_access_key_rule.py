"""Deterministic evaluator for IAM access keys unused for 90 days or more."""

from __future__ import annotations

import datetime
from typing import Any

UNUSED_ACCESS_KEY_DAYS = 90
RULE = {
    "id": "iam-unused-access-keys",
    "service": "iam",
    "control": "unused-access-keys",
    "version": "1.1",
}


def _is_true(value: Any) -> bool:
    return str(value).strip().upper() == "TRUE"


def _parse_date(value: Any) -> datetime.datetime | None:
    clean = str(value or "").strip()
    if not clean or clean.upper() in {"N/A", "NO_INFORMATION"}:
        return None
    return datetime.datetime.fromisoformat(clean.replace("Z", "+00:00"))


def _format_name_list(names: list[str], max_items: int = 10) -> str:
    shown = sorted(names)[:max_items]
    remaining = len(names) - len(shown)
    if remaining > 0:
        return ", ".join(shown) + f", and {remaining} more"
    return ", ".join(shown)


def evaluate(
    credential_report_rows: list[dict[str, Any]],
    *,
    now: datetime.datetime | None = None,
) -> dict[str, str]:
    """Fail only when an active key has been unused for at least 90 days."""
    try:
        current = now or datetime.datetime.now(datetime.UTC)
        unused_keys: list[str] = []

        for row in credential_report_rows:
            user_name = str(row.get("user", "")).strip()
            if not user_name or user_name == "<root_account>":
                continue

            for key_number in ("1", "2"):
                active_field = f"access_key_{key_number}_active"
                if not _is_true(row.get(active_field, "")):
                    continue

                last_used = _parse_date(row.get(f"access_key_{key_number}_last_used_date", ""))
                created = _parse_date(row.get(f"access_key_{key_number}_last_rotated", ""))

                if last_used is not None:
                    unused_days = (current - last_used).days
                    if unused_days >= UNUSED_ACCESS_KEY_DAYS:
                        unused_keys.append(
                            f"{user_name}: access_key_{key_number} (last used {unused_days} days ago)"
                        )
                    continue

                if created is None:
                    raise ValueError(
                        f"active access_key_{key_number} for {user_name} has no usable creation date"
                    )

                age_days = (current - created).days
                if age_days >= UNUSED_ACCESS_KEY_DAYS:
                    unused_keys.append(
                        f"{user_name}: access_key_{key_number} (never used; {age_days} days old)"
                    )

        if not unused_keys:
            return {
                "id": RULE["id"],
                "title": "No IAM access keys unused for 90 days or more were found",
                "severity": "INFO",
                "status": "PASS",
                "details": (
                    "No active IAM user access keys have been unused for 90 days or more. "
                    "Never-used keys younger than 90 days do not fail this control."
                ),
            }

        count = len(unused_keys)
        sample = _format_name_list(unused_keys)
        return {
            "id": RULE["id"],
            "title": "IAM access keys unused for 90 days or more were found",
            "severity": "MEDIUM",
            "status": "FAIL",
            "details": (
                f"{count} active IAM user access keys have been unused for at least "
                f"{UNUSED_ACCESS_KEY_DAYS} days: {sample}."
            ),
        }

    except Exception as error:
        return {
            "id": RULE["id"],
            "title": "Unused IAM access key check could not be completed",
            "severity": "LOW",
            "status": "ERROR",
            "details": f"Runner could not establish the 90-day unused access-key state: {str(error)}",
        }
