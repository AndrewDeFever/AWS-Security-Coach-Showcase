import json
import os
import datetime
import base64
import boto3

ddb = boto3.resource("dynamodb")

ALLOWED_STATUSES = {"QUEUED", "RUNNING", "COMPLETE", "FAILED"}

# Allowed transitions (current -> set of allowed next)
ALLOWED_TRANSITIONS = {
    "QUEUED": {"RUNNING"},
    "RUNNING": {"COMPLETE", "FAILED"},
    "COMPLETE": set(),
    "FAILED": set(),
}


def _resp(status: int, body: dict):
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body),
    }


def _parse_json_body(event) -> dict:
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")

    try:
        return json.loads(raw) if raw else {}
    except Exception as e:
        return {"__parse_error__": str(e), "__raw__": raw[:500]}


def lambda_handler(event, context):
    # Debug: keep for now; remove later if you want
    print("EVENT:", json.dumps(event))

    table_name = os.environ.get("SCANS_TABLE")
    if not table_name:
        return _resp(500, {"ok": False, "error": "Missing env var SCANS_TABLE"})

    # Path param: /scan/{scanId}/status
    path_params = event.get("pathParameters") or {}
    scan_id = path_params.get("scanId")
    if not scan_id:
        return _resp(400, {"ok": False, "error": "Missing path parameter scanId"})

    data = _parse_json_body(event)
    if "__parse_error__" in data:
        return _resp(
            400,
            {
                "ok": False,
                "error": "Invalid JSON body",
                "detail": data["__parse_error__"],
                "raw": data["__raw__"],
            },
        )

    new_status = data.get("status")
    if not new_status or new_status not in ALLOWED_STATUSES:
        return _resp(400, {"ok": False, "error": f"status must be one of {sorted(ALLOWED_STATUSES)}"})

    now = datetime.datetime.utcnow().isoformat() + "Z"
    table = ddb.Table(table_name)

    # Read current status (so we can return a clear 409 on invalid transitions)
    try:
        current_item = table.get_item(Key={"scanId": scan_id}).get("Item")
    except Exception as e:
        return _resp(500, {"ok": False, "error": "DynamoDB get_item failed", "detail": str(e)})

    if not current_item:
        return _resp(404, {"ok": False, "error": "Scan not found", "scanId": scan_id})

    current_status = current_item.get("status", "QUEUED")
    if new_status == current_status:
        # Idempotent: return the item as-is
        return _resp(200, {"ok": True, "scan": current_item})

    allowed_next = ALLOWED_TRANSITIONS.get(current_status, set())
    if new_status not in allowed_next:
        return _resp(
            409,
            {"ok": False, "error": "Invalid status transition", "from": current_status, "to": new_status},
        )

    # Build update expression
    # - status always changes
    # - updatedAt always changes
    # - startedAt set once when entering RUNNING
    # - completedAt set when entering COMPLETE/FAILED
    update_expr = "SET #s = :s, updatedAt = :u"
    expr_names = {"#s": "status"}
    expr_vals = {":s": new_status, ":u": now, ":expected": current_status}

    if new_status == "RUNNING":
        update_expr += ", startedAt = if_not_exists(startedAt, :u)"
    elif new_status in ("COMPLETE", "FAILED"):
        update_expr += ", completedAt = :u"

    # Conditional update to avoid races / enforce current status
    try:
        result = table.update_item(
            Key={"scanId": scan_id},
            UpdateExpression=update_expr,
            ConditionExpression="#s = :expected",
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_vals,
            ReturnValues="ALL_NEW",
        )
    except ddb.meta.client.exceptions.ConditionalCheckFailedException:
        # Someone else updated the status between our get_item and update_item
        latest = table.get_item(Key={"scanId": scan_id}).get("Item") or {}
        return _resp(
            409,
            {
                "ok": False,
                "error": "Conflict: scan status changed",
                "expected": current_status,
                "actual": latest.get("status"),
                "scan": latest,
            },
        )
    except Exception as e:
        return _resp(500, {"ok": False, "error": "DynamoDB update_item failed", "detail": str(e)})

    return _resp(200, {"ok": True, "scan": result.get("Attributes", {})})