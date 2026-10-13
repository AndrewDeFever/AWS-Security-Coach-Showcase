import os

import connector_management
import lambda_function as scan


PUBLIC_CONNECTOR_FIELDS = (
    "connectorId",
    "displayName",
    "customerOrganization",
    "status",
    "expectedAccountId",
    "homeRegion",
    "templateVersion",
    "connectorVersion",
    "createdAt",
    "updatedAt",
    "lastValidatedAt",
    "healthReason",
)


def _safe_connector(item: dict) -> dict:
    result = {key: item.get(key) for key in PUBLIC_CONNECTOR_FIELDS if key in item}
    account_id = str(result.get("expectedAccountId") or "").strip()
    if account_id and (len(account_id) != 12 or not account_id.isdigit()):
        result["expectedAccountId"] = ""
    organization = str(result.get("customerOrganization") or "").strip()
    if organization and len(organization) > 120:
        result["customerOrganization"] = ""
    return result


def list_connectors_response(event: dict):
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

    connectors_table_name = os.environ.get("CONNECTORS_TABLE", "").strip()
    if not connectors_table_name:
        print("Missing connector registry configuration for operator inventory")
        return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

    try:
        response = scan.ddb.Table(connectors_table_name).query(
            IndexName="management-index",
            KeyConditionExpression="managementBucket = :managementBucket",
            ExpressionAttributeValues={":managementBucket": connector_management.MANAGEMENT_BUCKET},
        )
    except Exception as exc:
        print("Operator connector inventory query failed:", type(exc).__name__)
        return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

    connectors = [_safe_connector(item) for item in (response.get("Items") or [])]
    return scan._resp(200, {"ok": True, "connectors": connectors})
