import hashlib
import json
import os

import boto3
from botocore.exceptions import ClientError


ddb = boto3.resource("dynamodb")
s3 = boto3.client("s3")


def _resp(status: int, body: dict):
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body),
    }


def _get_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing env var {name}")
    return value


def _is_authenticated_route(event: dict) -> bool:
    return str(event.get("rawPath", "")).startswith("/auth/")


def _claims(event: dict) -> dict:
    authorizer = (event.get("requestContext") or {}).get("authorizer") or {}
    return (authorizer.get("jwt") or {}).get("claims") or {}


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
    return "operator" in _claim_groups(_claims(event).get("cognito:groups", ""))


def _requester_ref(event: dict) -> str:
    subject = str(_claims(event).get("sub", "")).strip()
    namespace = os.environ.get("ENVIRONMENT_NAME", "").strip()
    if not subject or not namespace:
        raise ValueError("Requester identity is required")
    digest = hashlib.sha256(f"{namespace}:{subject}".encode("utf-8")).hexdigest()
    return f"usr_{digest[:24]}"


def lambda_handler(event, context):
    request_context = event.get("requestContext") or {}
    print(
        "GET REPORT REQUEST:",
        json.dumps(
            {
                "routeKey": event.get("routeKey"),
                "requestId": request_context.get("requestId"),
            }
        ),
    )

    try:
        table_name = _get_env("SCANS_TABLE")
        artifacts_bucket = _get_env("ARTIFACTS_BUCKET")
        table = ddb.Table(table_name)

        path_params = event.get("pathParameters") or {}
        scan_id = path_params.get("scanId")
        if not scan_id:
            return _resp(400, {"ok": False, "code": "INVALID_REQUEST"})

        try:
            ddb_result = table.get_item(Key={"scanId": scan_id})
        except Exception as exc:
            print("DynamoDB get_item failed:", type(exc).__name__)
            return _resp(500, {"ok": False, "code": "SCAN_READ_FAILED"})

        scan_item = ddb_result.get("Item")
        if not scan_item:
            return _resp(404, {"ok": False, "code": "SCAN_NOT_FOUND", "scanId": scan_id})

        if _is_authenticated_route(event) and not _operator_authorized(event):
            try:
                requester_ref = _requester_ref(event)
            except ValueError:
                return _resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})
            if scan_item.get("requesterRef") != requester_ref:
                return _resp(403, {"ok": False, "code": "REPORT_ACCESS_DENIED"})

        report_key = scan_item.get("reportKey")
        if not report_key:
            return _resp(404, {"ok": False, "code": "REPORT_NOT_READY", "scanId": scan_id})

        try:
            s3_result = s3.get_object(Bucket=artifacts_bucket, Key=report_key)
            report_bytes = s3_result["Body"].read()
            report = json.loads(report_bytes.decode("utf-8"))
        except ClientError as exc:
            print("S3 get_object failed:", exc.response.get("Error", {}).get("Code", "Unknown"))
            return _resp(500, {"ok": False, "code": "REPORT_READ_FAILED"})
        except Exception as exc:
            print("Report parse failed:", type(exc).__name__)
            return _resp(500, {"ok": False, "code": "REPORT_PARSE_FAILED"})

        return _resp(200, {"ok": True, "scan": scan_item, "report": report})

    except Exception as exc:
        print("GET REPORT FAILED:", type(exc).__name__)
        return _resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})
