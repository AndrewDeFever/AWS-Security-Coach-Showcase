import os
import re

import connector_aware_handler as connector_handler
import connector_lifecycle
import connector_management
import lambda_function as scan
import operator_connector_inventory


LIFECYCLE_PATH_PATTERN = re.compile(
    r"^/auth/connectors/(?P<connector_id>con_[0-9a-f-]+)/(?P<action>disable|enable|reset|revoke)$"
)
LIFECYCLE_SHAPE_PATTERN = re.compile(
    r"^/auth/connectors/(?P<connector_id>[^/]+)/(?P<action>disable|enable|reset|revoke)$"
)


def _operator_gate(event: dict):
    if not scan._is_authenticated_route(event):
        return scan._resp(403, {"ok": False, "code": "AUTHENTICATION_REQUIRED"})

    try:
        requester_ref = scan._requester_ref(event)
    except ValueError:
        return scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})

    if not requester_ref:
        return scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})
    if not scan._operator_authorized(event):
        return scan._resp(403, {"ok": False, "code": "OPERATOR_REQUIRED"})
    return None


def _grant_owner_membership(memberships_table, connector_item: dict, connector_id: str) -> None:
    owner_requester_ref = str(connector_item.get("ownerRequesterRef", "")).strip()
    if not owner_requester_ref:
        return
    memberships_table.update_item(
        Key={"requesterRef": owner_requester_ref, "connectorId": connector_id},
        UpdateExpression="SET enabled = :enabled",
        ExpressionAttributeValues={":enabled": True},
    )


def _lifecycle_response(event: dict, connector_id: str, action: str):
    denied = _operator_gate(event)
    if denied is not None:
        return denied

    connectors_table_name = os.environ.get("CONNECTORS_TABLE", "").strip()
    environment_name = os.environ.get("ENVIRONMENT_NAME", "").strip()
    if not connectors_table_name or environment_name not in {"dev", "prod"}:
        print("Missing connector lifecycle configuration")
        return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

    table = scan.ddb.Table(connectors_table_name)

    try:
        if action == "disable":
            result = connector_lifecycle.disable_connector(table, connector_id)
        elif action == "enable":
            memberships_table_name = os.environ.get(
                "CONNECTOR_MEMBERSHIPS_TABLE", ""
            ).strip()
            if not memberships_table_name:
                return scan._resp(
                    500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"}
                )
            connector_item = (
                table.get_item(
                    Key={"connectorId": connector_id},
                    ConsistentRead=True,
                ).get("Item")
                or {}
            )
            result = connector_lifecycle.enable_connector(
                table,
                scan.boto3.client("ssm"),
                scan.boto3.client("sts"),
                connector_handler._assumed_client_factory,
                environment_name,
                connector_id,
            )
            if str(result.get("status", "")).strip() == connector_management.CONNECTOR_STATUS_ENABLED:
                _grant_owner_membership(
                    scan.ddb.Table(memberships_table_name),
                    connector_item,
                    connector_id,
                )
        elif action == "reset":
            kms_key_id = os.environ.get("APPLICATION_KMS_KEY_ARN", "").strip()
            if not kms_key_id:
                return scan._resp(
                    500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"}
                )
            result = connector_lifecycle.reset_external_id(
                table,
                scan.boto3.client("ssm"),
                environment_name,
                kms_key_id,
                connector_id,
            )
        elif action == "revoke":
            memberships_table_name = os.environ.get(
                "CONNECTOR_MEMBERSHIPS_TABLE", ""
            ).strip()
            if not memberships_table_name:
                return scan._resp(
                    500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"}
                )
            result = connector_lifecycle.revoke_connector(
                table,
                scan.ddb.Table(memberships_table_name),
                scan.boto3.client("ssm"),
                environment_name,
                connector_id,
            )
        else:
            return scan._resp(404, {"ok": False, "code": "NOT_FOUND"})
    except ValueError:
        return scan._resp(400, {"ok": False, "code": "INVALID_CONNECTOR_REQUEST"})
    except LookupError:
        return scan._resp(404, {"ok": False, "code": "CONNECTOR_NOT_FOUND"})
    except connector_management.ConnectorValidationError as exc:
        print("Connector lifecycle validation failed:", exc.health_reason)
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
        print("Connector lifecycle operation failed:", type(exc).__name__)
        return scan._resp(500, {"ok": False, "code": "CONNECTOR_LIFECYCLE_FAILED"})

    print(f"Connector lifecycle action={action} connectorId={connector_id}")
    return scan._resp(200, {"ok": True, "connector": result})


def _connector_scan_gate(event: dict):
    raw_path = str(event.get("rawPath", ""))
    method = str((event.get("requestContext") or {}).get("http", {}).get("method", ""))
    if raw_path != "/auth/scan" or method != "POST":
        return None

    try:
        data = connector_handler._parse_body(event)
    except ValueError:
        return scan._resp(400, {"ok": False, "code": "INVALID_REQUEST"})

    if str(data.get("targetType", "tool-account")).strip() != connector_handler.CONNECTOR_TARGET_TYPE:
        return None

    if not scan._is_authenticated_route(event):
        return scan._resp(403, {"ok": False, "code": "AUTHENTICATION_REQUIRED"})

    try:
        requester_ref = scan._requester_ref(event)
    except ValueError:
        return scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})

    if not requester_ref:
        return scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})

    connector_id = str(data.get("connectorId", "")).strip()
    try:
        connector_id = connector_management._connector_id(connector_id)
    except ValueError:
        return scan._resp(400, {"ok": False, "code": "UNSUPPORTED_TARGET"})

    if not scan._operator_authorized(event):
        if not connector_handler._customer_authorized(event):
            return scan._resp(403, {"ok": False, "code": "CUSTOMER_GROUP_REQUIRED"})

        try:
            customer_authorized = connector_handler._customer_connector_authorized(
                requester_ref,
                connector_id,
            )
        except Exception as exc:
            print("Connector admission membership lookup failed:", type(exc).__name__)
            return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

        if not customer_authorized:
            return scan._resp(403, {"ok": False, "code": "CONNECTOR_ACCESS_DENIED"})

    connectors_table_name = os.environ.get("CONNECTORS_TABLE", "").strip()
    if not connectors_table_name:
        print("Missing connector registry configuration for scan admission")
        return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

    try:
        response = scan.ddb.Table(connectors_table_name).get_item(
            Key={"connectorId": connector_id},
            ConsistentRead=True,
        )
    except Exception as exc:
        error_response = getattr(exc, "response", {}) or {}
        error_code = str((error_response.get("Error") or {}).get("Code", "UNKNOWN"))
        print(
            "Connector registry admission lookup failed:",
            type(exc).__name__,
            error_code,
        )
        return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

    item = response.get("Item") or {}
    if item.get("connectorId") != connector_id:
        return scan._resp(400, {"ok": False, "code": "UNSUPPORTED_TARGET"})
    if str(item.get("status", "")).strip() != connector_management.CONNECTOR_STATUS_ENABLED:
        return scan._resp(409, {"ok": False, "code": "CONNECTOR_NOT_ENABLED"})

    return None


def lambda_handler(event, context):
    raw_path = str(event.get("rawPath", ""))
    method = str((event.get("requestContext") or {}).get("http", {}).get("method", ""))

    if raw_path == "/auth/connectors" and method == "GET":
        return operator_connector_inventory.list_connectors_response(event)

    match = LIFECYCLE_PATH_PATTERN.fullmatch(raw_path)
    if match and method == "POST":
        return _lifecycle_response(
            event,
            match.group("connector_id"),
            match.group("action"),
        )

    lifecycle_shape = LIFECYCLE_SHAPE_PATTERN.fullmatch(raw_path)
    if lifecycle_shape and method == "POST":
        denied = _operator_gate(event)
        if denied is not None:
            return denied
        return scan._resp(400, {"ok": False, "code": "INVALID_CONNECTOR_REQUEST"})

    denied = _connector_scan_gate(event)
    if denied is not None:
        return denied

    return connector_handler.lambda_handler(event, context)
