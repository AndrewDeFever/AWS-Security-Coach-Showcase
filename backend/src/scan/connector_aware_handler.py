import base64
import json
import os
import re
import time
import uuid

import connector_management
import lambda_function as scan


CONNECTOR_TARGET_TYPE = "connector"
TARGETS_PATH = "/auth/targets"
CONNECTORS_PATH = "/auth/connectors"
CONNECTOR_REGISTER_PATH_PATTERN = re.compile(
    r"^/auth/connectors/(?P<connector_id>con_[0-9a-f-]+)/register$"
)
CUSTOMER_GROUP = "customer"


def _parse_body(event: dict) -> dict:
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        try:
            raw = base64.b64decode(raw).decode("utf-8")
        except Exception as exc:
            raise ValueError("Invalid request body") from exc

    if not raw:
        return {}

    try:
        data = json.loads(raw)
    except Exception:
        data = scan._parse_kv_fallback(raw)

    if not isinstance(data, dict):
        raise ValueError("Invalid request body")
    return data


def _customer_authorized(event: dict) -> bool:
    groups = scan._claim_groups(scan._jwt_claims(event).get("cognito:groups", ""))
    return CUSTOMER_GROUP in groups


def _customer_connector_authorized(requester_ref: str, connector_id: str) -> bool:
    memberships_table_name = os.environ.get("CONNECTOR_MEMBERSHIPS_TABLE", "").strip()
    if not memberships_table_name:
        raise RuntimeError("Missing connector memberships table configuration")

    table = scan.ddb.Table(memberships_table_name)
    response = table.get_item(
        Key={"requesterRef": requester_ref, "connectorId": connector_id},
        ConsistentRead=True,
    )
    item = response.get("Item") or {}

    return (
        item.get("requesterRef") == requester_ref
        and item.get("connectorId") == connector_id
        and item.get("enabled") is True
    )


def _connector_owned_by(item: dict, requester_ref: str) -> bool:
    return bool(requester_ref) and str(item.get("ownerRequesterRef", "")).strip() == requester_ref


def _load_owned_connector(connectors_table, connector_id: str, requester_ref: str) -> dict:
    response = connectors_table.get_item(
        Key={"connectorId": connector_id},
        ConsistentRead=True,
    )
    item = response.get("Item") or {}
    if item.get("connectorId") != connector_id or not _connector_owned_by(item, requester_ref):
        raise LookupError("Connector not found")
    return item


def _create_connector_response(event: dict, data: dict):
    if not scan._is_authenticated_route(event):
        return scan._resp(403, {"ok": False, "code": "AUTHENTICATION_REQUIRED"})

    try:
        requester_ref = scan._requester_ref(event)
    except ValueError:
        return scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})

    if not requester_ref:
        return scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})

    connectors_table_name = os.environ.get("CONNECTORS_TABLE", "").strip()
    environment_name = os.environ.get("ENVIRONMENT_NAME", "").strip()
    kms_key_id = os.environ.get("APPLICATION_KMS_KEY_ARN", "").strip()
    if not connectors_table_name or not environment_name or not kms_key_id:
        print("Missing connector provisioning configuration")
        return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

    # Normal authenticated users own the connectors they self-provision. Operators
    # retain the existing elevated provisioning path without becoming customer owners.
    owner_requester_ref = None if scan._operator_authorized(event) else requester_ref

    try:
        result = connector_management.provision_connector(
            scan.ddb.Table(connectors_table_name),
            scan.boto3.client("ssm"),
            environment_name,
            kms_key_id,
            data,
            owner_requester_ref=owner_requester_ref,
        )
    except ValueError:
        return scan._resp(400, {"ok": False, "code": "INVALID_CONNECTOR_REQUEST"})
    except Exception as exc:
        print("Connector provisioning failed:", type(exc).__name__)
        return scan._resp(500, {"ok": False, "code": "CONNECTOR_CREATE_FAILED"})

    print("Connector provisioned:", result["connectorId"])
    return scan._resp(201, {"ok": True, "connector": result})


def _assumed_client_factory(service_name: str, region_name: str, credentials: dict):
    return scan.boto3.client(
        service_name,
        region_name=region_name,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def _register_connector_response(event: dict, data: dict, connector_id: str):
    if not scan._is_authenticated_route(event):
        return scan._resp(403, {"ok": False, "code": "AUTHENTICATION_REQUIRED"})

    try:
        requester_ref = scan._requester_ref(event)
    except ValueError:
        return scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})

    if not requester_ref:
        return scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})

    connectors_table_name = os.environ.get("CONNECTORS_TABLE", "").strip()
    environment_name = os.environ.get("ENVIRONMENT_NAME", "").strip()
    if not connectors_table_name or environment_name not in {"dev", "prod"}:
        print("Missing connector registration configuration")
        return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

    table = scan.ddb.Table(connectors_table_name)
    if not scan._operator_authorized(event):
        try:
            canonical_connector_id = connector_management._connector_id(connector_id)
            _load_owned_connector(table, canonical_connector_id, requester_ref)
        except (ValueError, LookupError):
            # Do not reveal whether another customer's connector exists.
            return scan._resp(404, {"ok": False, "code": "CONNECTOR_NOT_FOUND"})

    try:
        result = connector_management.register_connector(
            table,
            scan.boto3.client("ssm"),
            scan.boto3.client("sts"),
            _assumed_client_factory,
            environment_name,
            connector_id,
            data,
        )
    except ValueError:
        return scan._resp(400, {"ok": False, "code": "INVALID_CONNECTOR_REQUEST"})
    except LookupError:
        return scan._resp(404, {"ok": False, "code": "CONNECTOR_NOT_FOUND"})
    except connector_management.ConnectorValidationError as exc:
        print("Connector activation validation failed:", exc.health_reason)
        return scan._resp(
            422,
            {
                "ok": False,
                "code": "CONNECTOR_VALIDATION_FAILED",
                "connector": {
                    "connectorId": connector_id,
                    "status": "UNHEALTHY",
                    "healthReason": exc.health_reason,
                },
            },
        )
    except RuntimeError:
        return scan._resp(409, {"ok": False, "code": "CONNECTOR_STATE_CONFLICT"})
    except Exception as exc:
        print("Connector registration failed:", type(exc).__name__)
        return scan._resp(500, {"ok": False, "code": "CONNECTOR_REGISTER_FAILED"})

    public_result = {
        key: result[key]
        for key in (
            "connectorId",
            "displayName",
            "status",
            "homeRegion",
            "templateVersion",
            "connectorVersion",
            "lastValidatedAt",
            "healthReason",
        )
        if key in result
    }
    print("Connector validated and awaiting approval:", connector_id)
    return scan._resp(200, {"ok": True, "connector": public_result})


def _connector_target(item: dict) -> dict:
    connector_id = str(item.get("connectorId", "")).strip()
    display_name = str(item.get("displayName", "")).strip() or connector_id
    return {
        "targetType": CONNECTOR_TARGET_TYPE,
        "connectorId": connector_id,
        "displayName": display_name,
    }


def _enabled_connector(table, connector_id: str) -> dict:
    response = table.get_item(
        Key={"connectorId": connector_id},
        ConsistentRead=True,
    )
    item = response.get("Item") or {}
    if item.get("connectorId") != connector_id:
        return {}
    if str(item.get("status", "")).strip() != connector_management.CONNECTOR_STATUS_ENABLED:
        return {}
    return item


def _targets_response(event: dict):
    if not scan._is_authenticated_route(event):
        return scan._resp(403, {"ok": False, "code": "AUTHENTICATION_REQUIRED"})

    try:
        requester_ref = scan._requester_ref(event)
    except ValueError:
        return scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})

    if not requester_ref:
        return scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})

    connectors_table_name = os.environ.get("CONNECTORS_TABLE", "").strip()
    if not connectors_table_name:
        print("Missing connector registry configuration for target discovery")
        return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

    connectors_table = scan.ddb.Table(connectors_table_name)

    if scan._operator_authorized(event):
        targets = [
            {
                "targetType": "tool-account",
                "targetId": "tool-account",
                "displayName": "AWS Security Coach",
            }
        ]
        try:
            response = connectors_table.query(
                IndexName="management-index",
                KeyConditionExpression="managementBucket = :managementBucket",
                ExpressionAttributeValues={
                    ":managementBucket": connector_management.MANAGEMENT_BUCKET
                },
            )
        except Exception as exc:
            print("Connector target inventory query failed:", type(exc).__name__)
            return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

        targets.extend(
            _connector_target(item)
            for item in (response.get("Items") or [])
            if str(item.get("status", "")).strip()
            == connector_management.CONNECTOR_STATUS_ENABLED
        )
        return scan._resp(200, {"ok": True, "targets": targets})

    if not _customer_authorized(event):
        return scan._resp(403, {"ok": False, "code": "CUSTOMER_GROUP_REQUIRED"})

    memberships_table_name = os.environ.get("CONNECTOR_MEMBERSHIPS_TABLE", "").strip()
    if not memberships_table_name:
        print("Missing connector memberships table configuration")
        return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

    try:
        response = scan.ddb.Table(memberships_table_name).query(
            KeyConditionExpression="requesterRef = :requesterRef",
            ExpressionAttributeValues={":requesterRef": requester_ref},
            ConsistentRead=True,
        )
        targets = []
        for membership in response.get("Items") or []:
            connector_id = str(membership.get("connectorId", "")).strip()
            if not connector_id or membership.get("enabled") is not True:
                continue
            connector = _enabled_connector(connectors_table, connector_id)
            if connector:
                targets.append(_connector_target(connector))
    except Exception as exc:
        print("Connector target discovery failed:", type(exc).__name__)
        return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

    return scan._resp(200, {"ok": True, "targets": targets})


def _connector_response(event: dict, data: dict):
    if not scan._is_authenticated_route(event):
        return scan._resp(403, {"ok": False, "code": "AUTHENTICATION_REQUIRED"})

    try:
        requester_ref = scan._requester_ref(event)
    except ValueError:
        return scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})

    if not requester_ref:
        return scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})

    try:
        connector_id = connector_management._connector_id(data.get("connectorId", ""))
    except ValueError:
        return scan._resp(400, {"ok": False, "code": "UNSUPPORTED_TARGET"})

    # Platform operators may use any ENABLED connector admitted by the lifecycle
    # wrapper. Customer scan authorization remains membership-bounded until the
    # self-service ownership-to-entitlement bridge is implemented.
    if not scan._operator_authorized(event):
        if not _customer_authorized(event):
            return scan._resp(403, {"ok": False, "code": "CUSTOMER_GROUP_REQUIRED"})

        try:
            customer_authorized = _customer_connector_authorized(requester_ref, connector_id)
        except Exception as exc:
            print("Connector membership lookup failed:", type(exc).__name__)
            return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

        if not customer_authorized:
            return scan._resp(403, {"ok": False, "code": "CONNECTOR_ACCESS_DENIED"})

    scans_table_name = os.environ.get("SCANS_TABLE")
    admission_table_name = os.environ.get("ADMISSION_TABLE")
    if not scans_table_name or not admission_table_name:
        print("Missing required connector scan configuration")
        return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

    try:
        request_id = scan._idempotency_key(event)
    except ValueError:
        return scan._resp(400, {"ok": False, "code": "INVALID_IDEMPOTENCY_KEY"})

    now_epoch = int(time.time())
    now_iso = scan._utc_now()
    cooldown_seconds = int(os.environ.get("ADMISSION_COOLDOWN_SECONDS", "300"))
    lease_seconds = int(os.environ.get("ADMISSION_LEASE_SECONDS", "900"))

    scan_id = str(uuid.uuid4())
    scope_key = f"connector#{connector_id}"
    lock_item = {
        "scopeKey": scope_key,
        "scanId": scan_id,
        "requestId": request_id,
        "createdAt": now_iso,
        "cooldownUntil": now_epoch + cooldown_seconds,
        "expiresAt": now_epoch + lease_seconds,
    }

    scans_table = scan.ddb.Table(scans_table_name)
    admission_table = scan.ddb.Table(admission_table_name)

    try:
        admission = scan._admission_result(
            admission_table,
            scans_table,
            lock_item,
            request_id,
            now_epoch,
        )
    except Exception as exc:
        print("Connector admission control failed:", type(exc).__name__)
        return scan._resp(500, {"ok": False, "code": "ADMISSION_CONTROL_ERROR"})

    if admission["decision"] == "IDEMPOTENT":
        return scan._resp(
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
        return scan._resp(
            409,
            {"ok": False, "code": "SCAN_IN_PROGRESS"},
            {"Retry-After": retry_after},
        )

    if admission["decision"] == "COOLDOWN":
        retry_after = int(admission.get("retryAfter", 60))
        return scan._resp(
            429,
            {"ok": False, "code": "SCAN_COOLDOWN"},
            {"Retry-After": retry_after},
        )

    item = {
        "scanId": scan_id,
        "createdAt": now_iso,
        "status": "QUEUED",
        "targetType": CONNECTOR_TARGET_TYPE,
        "targetId": connector_id,
        "connectorId": connector_id,
        "requestId": request_id,
        "admissionKey": scope_key,
        "requesterRef": requester_ref,
    }

    try:
        scans_table.put_item(Item=item)
        print("DynamoDB put_item succeeded for connector scanId:", scan_id)
    except Exception as exc:
        print("Connector DynamoDB put_item failed:", type(exc).__name__)
        scan._delete_admission_lock(admission_table, scope_key, scan_id)
        return scan._resp(500, {"ok": False, "code": "SCAN_CREATE_FAILED"})

    try:
        scan._invoke_runner(scan_id, item)
        print("Connector runner invoke request accepted for scanId:", scan_id)
    except Exception as exc:
        print("Connector runner invoke failed:", type(exc).__name__)
        try:
            scans_table.update_item(
                Key={"scanId": scan_id},
                UpdateExpression="SET #s = :failed, updatedAt = :updated",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":failed": "FAILED",
                    ":updated": scan._utc_now(),
                },
            )
        finally:
            scan._delete_admission_lock(admission_table, scope_key, scan_id)
        return scan._resp(500, {"ok": False, "code": "RUNNER_START_FAILED"})

    return scan._resp(201, {"ok": True, "scanId": scan_id, "status": "QUEUED"})


def lambda_handler(event, context):
    raw_path = str(event.get("rawPath", ""))
    if raw_path == TARGETS_PATH:
        return _targets_response(event)

    try:
        data = _parse_body(event)
    except ValueError:
        return scan._resp(400, {"ok": False, "code": "INVALID_REQUEST"})

    if raw_path == CONNECTORS_PATH:
        return _create_connector_response(event, data)

    register_match = CONNECTOR_REGISTER_PATH_PATTERN.fullmatch(raw_path)
    if register_match:
        return _register_connector_response(
            event,
            data,
            register_match.group("connector_id"),
        )

    target_type = str(data.get("targetType", "tool-account")).strip()
    if target_type != CONNECTOR_TARGET_TYPE:
        return scan.lambda_handler(event, context)

    return _connector_response(event, data)
