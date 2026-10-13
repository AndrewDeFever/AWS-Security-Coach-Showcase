import json
import os
from urllib.parse import urlencode

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

import connector_management
import lambda_function as scan


ALLOWED_SETUP_STATUSES = {
    connector_management.CONNECTOR_STATUS_PENDING,
    connector_management.CONNECTOR_STATUS_UNHEALTHY,
}
RELEASE_BUCKET = "aws-security-coach-connector-releases-example"
PRESIGNED_TEMPLATE_TTL_SECONDS = 900
DISCLOSURE_VERSION = "1.0"


def _identity_gate(event: dict):
    if not scan._is_authenticated_route(event):
        return None, scan._resp(403, {"ok": False, "code": "AUTHENTICATION_REQUIRED"})

    try:
        requester_ref = scan._requester_ref(event)
    except ValueError:
        return None, scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})

    if not requester_ref:
        return None, scan._resp(403, {"ok": False, "code": "REQUESTER_IDENTITY_REQUIRED"})
    return requester_ref, None


def _request_method(event: dict) -> str:
    return str(((event.get("requestContext") or {}).get("http") or {}).get("method", "GET")).upper()


def _acknowledgment_input(event: dict) -> str:
    try:
        data = json.loads(event.get("body") or "{}")
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid disclosure acknowledgment body") from exc
    if not isinstance(data, dict) or set(data) != {"acknowledged", "disclosureVersion"}:
        raise ValueError("Only acknowledged and disclosureVersion are accepted")
    if data.get("acknowledged") is not True:
        raise ValueError("Disclosure acknowledgment must be true")
    disclosure_version = str(data.get("disclosureVersion", "")).strip()
    if disclosure_version != DISCLOSURE_VERSION:
        raise ValueError("Unsupported disclosure version")
    return disclosure_version


def _stack_name(connector_id: str) -> str:
    return f"aws-security-coach-connector-{connector_id.removeprefix('con_')[:8]}"


def _quick_create_url(
    region: str,
    template_url: str,
    stack_name: str,
    trusted_scanner_role_arn: str,
    home_region: str,
) -> str:
    params = urlencode(
        {
            "templateURL": template_url,
            "stackName": stack_name,
            "param_TrustedScannerRoleArn": trusted_scanner_role_arn,
            "param_HomeRegion": home_region,
        }
    )
    return (
        f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}"
        f"#/stacks/create/review?{params}"
    )


def _configuration():
    connectors_table_name = os.environ.get("CONNECTORS_TABLE", "").strip()
    environment_name = os.environ.get("ENVIRONMENT_NAME", "").strip()
    trusted_scanner_role_arn = os.environ.get("TRUSTED_SCANNER_ROLE_ARN", "").strip()
    release_bucket = os.environ.get("CONNECTOR_RELEASE_BUCKET", RELEASE_BUCKET).strip()

    if (
        not connectors_table_name
        or environment_name not in {"dev", "prod"}
        or not trusted_scanner_role_arn
        or not release_bucket
    ):
        raise RuntimeError("Connector setup configuration is incomplete")

    return (
        connectors_table_name,
        environment_name,
        trusted_scanner_role_arn,
        release_bucket,
    )


def _disclosure_acknowledged(item: dict) -> bool:
    return (
        str(item.get("disclosureVersion", "")).strip() == DISCLOSURE_VERSION
        and bool(str(item.get("disclosureAcknowledgedAt", "")).strip())
        and bool(str(item.get("disclosureAcknowledgedBy", "")).strip())
    )


def _limited_setup_response(item: dict, connector_id: str, status: str, home_region: str, template_version: str):
    connector = {
        "connectorId": connector_id,
        "displayName": str(item.get("displayName", "")),
        "status": status,
        "homeRegion": home_region,
        "templateVersion": template_version,
        "disclosureVersion": DISCLOSURE_VERSION,
        "disclosureAcknowledged": False,
    }
    customer_organization = str(item.get("customerOrganization", "")).strip()
    if customer_organization:
        connector["customerOrganization"] = customer_organization
    return scan._resp(200, {"ok": True, "connector": connector})


def lambda_handler(event, context):
    requester_ref, denied = _identity_gate(event)
    if denied is not None:
        return denied

    method = _request_method(event)
    if method not in {"GET", "POST"}:
        return scan._resp(405, {"ok": False, "code": "METHOD_NOT_ALLOWED"})

    raw_connector_id = str((event.get("pathParameters") or {}).get("connectorId", "")).strip()
    try:
        connector_id = connector_management._connector_id(raw_connector_id)
    except ValueError:
        return scan._resp(400, {"ok": False, "code": "INVALID_CONNECTOR_REQUEST"})

    try:
        (
            connectors_table_name,
            environment_name,
            trusted_scanner_role_arn,
            release_bucket,
        ) = _configuration()
    except RuntimeError:
        print("Missing connector setup configuration")
        return scan._resp(500, {"ok": False, "code": "SERVICE_CONFIGURATION_ERROR"})

    table = boto3.resource("dynamodb").Table(connectors_table_name)

    try:
        response = table.get_item(
            Key={"connectorId": connector_id},
            ConsistentRead=True,
        )
        item = response.get("Item") or {}
        if item.get("connectorId") != connector_id:
            return scan._resp(404, {"ok": False, "code": "CONNECTOR_NOT_FOUND"})

        if not scan._operator_authorized(event):
            owner_requester_ref = str(item.get("ownerRequesterRef", "")).strip()
            if not owner_requester_ref or owner_requester_ref != requester_ref:
                return scan._resp(404, {"ok": False, "code": "CONNECTOR_NOT_FOUND"})

        status = str(item.get("status", "")).strip()
        if status not in ALLOWED_SETUP_STATUSES:
            code = (
                "CONNECTOR_STATE_CONFLICT"
                if status == connector_management.CONNECTOR_STATUS_VALIDATING
                else "CONNECTOR_SETUP_NOT_AVAILABLE"
            )
            return scan._resp(409, {"ok": False, "code": code})

        home_region = str(item.get("homeRegion", "")).strip()
        template_version = str(item.get("templateVersion", "")).strip()
        if (
            home_region != connector_management.SUPPORTED_HOME_REGION
            or template_version != connector_management.CONNECTOR_TEMPLATE_VERSION
        ):
            return scan._resp(409, {"ok": False, "code": "CONNECTOR_SETUP_NOT_AVAILABLE"})

        acknowledged = _disclosure_acknowledged(item)
        if method == "POST":
            try:
                disclosure_version = _acknowledgment_input(event)
            except ValueError:
                return scan._resp(400, {"ok": False, "code": "INVALID_DISCLOSURE_ACKNOWLEDGMENT"})

            acknowledged_at = connector_management._utc_now()
            try:
                update = table.update_item(
                    Key={"connectorId": connector_id},
                    UpdateExpression=(
                        "SET disclosureVersion = :version, "
                        "disclosureAcknowledgedAt = :acknowledgedAt, "
                        "disclosureAcknowledgedBy = :acknowledgedBy, "
                        "updatedAt = :updatedAt"
                    ),
                    ConditionExpression="#status IN (:pending, :unhealthy)",
                    ExpressionAttributeNames={"#status": "status"},
                    ExpressionAttributeValues={
                        ":version": disclosure_version,
                        ":acknowledgedAt": acknowledged_at,
                        ":acknowledgedBy": requester_ref,
                        ":updatedAt": acknowledged_at,
                        ":pending": connector_management.CONNECTOR_STATUS_PENDING,
                        ":unhealthy": connector_management.CONNECTOR_STATUS_UNHEALTHY,
                    },
                    ReturnValues="ALL_NEW",
                )
            except ClientError as exc:
                if str((exc.response.get("Error") or {}).get("Code", "")) == "ConditionalCheckFailedException":
                    return scan._resp(409, {"ok": False, "code": "CONNECTOR_STATE_CONFLICT"})
                raise
            item = update.get("Attributes") or item
            acknowledged = True

        if not acknowledged:
            return _limited_setup_response(item, connector_id, status, home_region, template_version)

        parameter_name = connector_management.external_id_parameter_name(
            environment_name,
            connector_id,
        )
        external_id = str(
            boto3.client("ssm").get_parameter(
                Name=parameter_name,
                WithDecryption=True,
            )["Parameter"]["Value"]
        ).strip()
        if not external_id:
            raise RuntimeError("Connector ExternalId is empty")

        release_key = f"{environment_name}/{template_version}/template.yaml"
        template_url = boto3.client(
            "s3",
            region_name=home_region,
            config=Config(signature_version="s3v4"),
        ).generate_presigned_url(
            "get_object",
            Params={"Bucket": release_bucket, "Key": release_key},
            ExpiresIn=PRESIGNED_TEMPLATE_TTL_SECONDS,
        )
        stack_name = _stack_name(connector_id)
        quick_create_url = _quick_create_url(
            home_region,
            template_url,
            stack_name,
            trusted_scanner_role_arn,
            home_region,
        )
    except Exception as exc:
        print("Connector setup generation failed:", type(exc).__name__)
        return scan._resp(500, {"ok": False, "code": "CONNECTOR_SETUP_FAILED"})

    connector = {
        "connectorId": connector_id,
        "displayName": str(item.get("displayName", "")),
        "status": status,
        "homeRegion": home_region,
        "templateVersion": template_version,
        "disclosureVersion": DISCLOSURE_VERSION,
        "disclosureAcknowledged": True,
        "externalId": external_id,
        "quickCreateUrl": quick_create_url,
        "stackName": stack_name,
    }
    customer_organization = str(item.get("customerOrganization", "")).strip()
    if customer_organization:
        connector["customerOrganization"] = customer_organization
    return scan._resp(200, {"ok": True, "connector": connector})
