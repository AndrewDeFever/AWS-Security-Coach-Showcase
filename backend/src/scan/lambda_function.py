import base64
import datetime
import json
import os
import time
import uuid

import boto3
from botocore.exceptions import ClientError

from requester_identity import requester_reference


ddb = boto3.resource("dynamodb")
lambda_client = boto3.client("lambda")

TERMINAL_STATUSES = {"COMPLETE", "FAILED"}
IDEMPOTENCY_HEADER = "x-idempotency-key"


def _resp(status: int, body: dict, extra_headers: dict | None = None):
    headers = {"content-type": "application/json"}
    if extra_headers:
        headers.update({str(k): str(v) for k, v in extra_headers.items()})

    return {
        "statusCode": status,
        "headers": headers,
        "body": json.dumps(body),
    }


def _utc_now():
    return datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")


def _is_authenticated_route(event: dict) -> bool:
    return str(event.get("rawPath", "")).startswith("/auth/")


def _jwt_claims(event: dict) -> dict:
    authorizer = (event.get("requestContext") or {}).get("authorizer") or {}
    claims = (authorizer.get("jwt") or {}).get("claims") or {}
    return claims if isinstance(claims, dict) else {}


def _claim_groups(raw_groups) -> set[str]:
    if isinstance(raw_groups, list):
        return {str(value).strip() for value in raw_groups if str(value).strip()}

    text = str(raw_groups or "").strip()
    if not text:
        return set()

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return {str(value).strip() for value in parsed if str(value).strip()}
    except json.JSONDecodeError:
        pass

    return {
        value.strip().strip('"').strip("'")
        for value in text.strip("[]").split(",")
        if value.strip().strip('"').strip("'")
    }


def _operator_authorized(event: dict) -> bool:
    return "operator" in _claim_groups(_jwt_claims(event).get("cognito:groups", ""))


def _requester_ref(event: dict) -> str | None:
    if not _is_authenticated_route(event):
        return None
    claims = _jwt_claims(event)
    return requester_reference(
        str(claims.get("sub", "")),
        os.environ.get("ENVIRONMENT_NAME", ""),
    )


def _parse_kv_fallback(raw: str) -> dict:
    s = (raw or "").strip()
    if s.startswith("{") and s.endswith("}"):
        s = s[1:-1]

    out = {}
    for part in [p.strip() for p in s.split(",") if p.strip()]:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        out[key.strip()] = value.strip()
    return out


def _headers(event: dict) -> dict:
    return {
        str(key).lower(): str(value)
        for key, value in (event.get("headers") or {}).items()
        if value is not None
    }


def _idempotency_key(event: dict) -> str:
    value = _headers(event).get(IDEMPOTENCY_HEADER, "").strip()
    if not value:
        return str(uuid.uuid4())

    if not 8 <= len(value) <= 128:
        raise ValueError("Invalid idempotency key length")

    return value


def _invoke_runner(scan_id: str, item: dict):
    runner_function_name = os.environ.get("RUNNER_FUNCTION_NAME")
    if not runner_function_name:
        raise RuntimeError("Missing env var RUNNER_FUNCTION_NAME")

    payload = {
        "scanId": scan_id,
        "invokedBy": "scan-api",
        "targetType": item.get("targetType"),
        "targetId": item.get("targetId"),
    }

    print("Invoking runner function:", runner_function_name)
    response = lambda_client.invoke(
        FunctionName=runner_function_name,
        InvocationType="Event",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    print(
        "Runner invoke accepted:",
        json.dumps({"StatusCode": response.get("StatusCode")}, default=str),
    )


def _read_item(table, key: dict) -> dict:
    response = table.get_item(Key=key, ConsistentRead=True)
    return response.get("Item") or {}


def _delete_admission_lock(admission_table, scope_key: str, scan_id: str):
    try:
        admission_table.delete_item(
            Key={"scopeKey": scope_key},
            ConditionExpression="scanId = :scanId",
            ExpressionAttributeValues={":scanId": scan_id},
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code != "ConditionalCheckFailedException":
            raise


def _put_admission_lock(
    admission_table,
    lock_item: dict,
    now_epoch: int,
    previous_scan_id: str | None = None,
):
    if previous_scan_id:
        admission_table.put_item(
            Item=lock_item,
            ConditionExpression="scanId = :previousScanId",
            ExpressionAttributeValues={":previousScanId": previous_scan_id},
        )
        return

    admission_table.put_item(
        Item=lock_item,
        ConditionExpression="attribute_not_exists(scopeKey) OR expiresAt < :now",
        ExpressionAttributeValues={":now": now_epoch},
    )


def _admission_result(
    admission_table,
    scans_table,
    lock_item: dict,
    request_id: str,
    now_epoch: int,
):
    try:
        _put_admission_lock(admission_table, lock_item, now_epoch)
        return {"decision": "ACQUIRED"}
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code != "ConditionalCheckFailedException":
            raise

    existing_lock = _read_item(admission_table, {"scopeKey": lock_item["scopeKey"]})
    if not existing_lock:
        _put_admission_lock(admission_table, lock_item, now_epoch)
        return {"decision": "ACQUIRED"}

    if existing_lock.get("requestId") == request_id and existing_lock.get("scanId"):
        return {
            "decision": "IDEMPOTENT",
            "scanId": existing_lock["scanId"],
        }

    existing_scan_id = str(existing_lock.get("scanId", ""))
    existing_scan = (
        _read_item(scans_table, {"scanId": existing_scan_id})
        if existing_scan_id
        else {}
    )
    existing_status = str(existing_scan.get("status", "UNKNOWN")).upper()
    cooldown_until = int(existing_lock.get("cooldownUntil", 0) or 0)

    if existing_status in TERMINAL_STATUSES and cooldown_until <= now_epoch:
        try:
            _put_admission_lock(
                admission_table,
                lock_item,
                now_epoch,
                previous_scan_id=existing_scan_id,
            )
            return {"decision": "ACQUIRED"}
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "ConditionalCheckFailedException":
                raise
            return {"decision": "ACTIVE", "retryAfter": 5}

    retry_after = max(1, cooldown_until - now_epoch)
    if existing_status in TERMINAL_STATUSES:
        return {"decision": "COOLDOWN", "retryAfter": retry_after}

    lease_until = int(existing_lock.get("expiresAt", now_epoch + 60) or now_epoch + 60)
    return {
        "decision": "ACTIVE",
        "retryAfter": max(1, min(60, lease_until - now_epoch)),
    }


def lambda_handler(event, context):
    request_context = event.get("requestContext") or {}
    print(
        "SCAN REQUEST:",
        json.dumps(
            {
                "routeKey": event.get("routeKey"),
                "requestId": request_context.get("requestId"),
            }
        ),
    )

    authenticated_route = _is_authenticated_route(event)
    if authenticated_route and not _operator_authorized(event):
        return _resp(403, {"ok": False, "code": "OPERATOR_REQUIRED"})

    try:
        requester_ref = _requester_ref(event)
    except ValueError:
        return _resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})

    scans_table_name = os.environ.get("SCANS_TABLE")
    admission_table_name = os.environ.get("ADMISSION_TABLE")
    target_account_id = os.environ.get("TARGET_ACCOUNT_ID")

    if not scans_table_name or not admission_table_name or not target_account_id:
        print("Missing required scan configuration")
        return _resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        try:
            raw = base64.b64decode(raw).decode("utf-8")
        except Exception as exc:
            print("Body base64 decode failed:", type(exc).__name__)
            return _resp(400, {"ok": False, "code": "INVALID_REQUEST"})

    try:
        data = json.loads(raw) if raw else {}
    except Exception:
        data = _parse_kv_fallback(raw)
        if not isinstance(data, dict) or not data:
            return _resp(400, {"ok": False, "code": "INVALID_REQUEST"})

    target_type = str(data.get("targetType", "tool-account"))
    if target_type != "tool-account":
        return _resp(400, {"ok": False, "code": "UNSUPPORTED_TARGET"})

    try:
        request_id = _idempotency_key(event)
    except ValueError:
        return _resp(400, {"ok": False, "code": "INVALID_IDEMPOTENCY_KEY"})

    now_epoch = int(time.time())
    now_iso = _utc_now()
    cooldown_seconds = int(os.environ.get("ADMISSION_COOLDOWN_SECONDS", "300"))
    lease_seconds = int(os.environ.get("ADMISSION_LEASE_SECONDS", "900"))

    scan_id = str(uuid.uuid4())
    scope_key = f"tool-account#{target_account_id}"
    lock_item = {
        "scopeKey": scope_key,
        "scanId": scan_id,
        "requestId": request_id,
        "createdAt": now_iso,
        "cooldownUntil": now_epoch + cooldown_seconds,
        "expiresAt": now_epoch + lease_seconds,
    }

    scans_table = ddb.Table(scans_table_name)
    admission_table = ddb.Table(admission_table_name)

    try:
        admission = _admission_result(
            admission_table,
            scans_table,
            lock_item,
            request_id,
            now_epoch,
        )
    except Exception as exc:
        print("Admission control failed:", type(exc).__name__)
        return _resp(500, {"ok": False, "code": "ADMISSION_CONTROL_ERROR"})

    if admission["decision"] == "IDEMPOTENT":
        return _resp(
            200,
            {
                "ok": True,
                "scanId": admission["scanId"],
                "status": "ACCEPTED",
                "idempotentReplay": True,
            },
        )

    if admission["decision"] == "ACTIVE":
        retry_after = int(admission.get("retryAfter", 5))
        return _resp(
            409,
            {"ok": False, "code": "SCAN_IN_PROGRESS"},
            {"Retry-After": retry_after},
        )

    if admission["decision"] == "COOLDOWN":
        retry_after = int(admission.get("retryAfter", 60))
        return _resp(
            429,
            {"ok": False, "code": "SCAN_COOLDOWN"},
            {"Retry-After": retry_after},
        )

    item = {
        "scanId": scan_id,
        "createdAt": now_iso,
        "status": "QUEUED",
        "targetType": "tool-account",
        "targetId": target_account_id,
        "requestId": request_id,
        "admissionKey": scope_key,
    }
    if requester_ref:
        item["requesterRef"] = requester_ref

    try:
        scans_table.put_item(Item=item)
        print("DynamoDB put_item succeeded for scanId:", scan_id)
    except Exception as exc:
        print("DynamoDB put_item failed:", type(exc).__name__)
        _delete_admission_lock(admission_table, scope_key, scan_id)
        return _resp(500, {"ok": False, "code": "SCAN_CREATE_FAILED"})

    try:
        _invoke_runner(scan_id, item)
        print("Runner invoke request accepted for scanId:", scan_id)
    except Exception as exc:
        print("Runner invoke failed:", type(exc).__name__)
        try:
            scans_table.update_item(
                Key={"scanId": scan_id},
                UpdateExpression="SET #s = :failed, updatedAt = :updated",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":failed": "FAILED",
                    ":updated": _utc_now(),
                },
            )
        finally:
            _delete_admission_lock(admission_table, scope_key, scan_id)
        return _resp(500, {"ok": False, "code": "RUNNER_START_FAILED"})

    return _resp(201, {"ok": True, "scanId": scan_id, "status": "QUEUED"})
