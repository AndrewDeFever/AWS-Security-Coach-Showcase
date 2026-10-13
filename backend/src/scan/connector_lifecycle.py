import secrets

import connector_management


CONNECTOR_STATUS_DISABLED = "DISABLED"
CONNECTOR_STATUS_REVOKED = "REVOKED"


def _connector_id(value: str) -> str:
    return connector_management._connector_id(value)


def _load_connector(connectors_table, connector_id: str) -> dict:
    connector_id = _connector_id(connector_id)
    response = connectors_table.get_item(
        Key={"connectorId": connector_id},
        ConsistentRead=True,
    )
    item = response.get("Item") or {}
    if item.get("connectorId") != connector_id:
        raise LookupError("Connector not found")
    return item


def _safe_connector(item: dict) -> dict:
    return {
        key: item.get(key)
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
        if key in item
    }


def disable_connector(connectors_table, connector_id: str) -> dict:
    item = _load_connector(connectors_table, connector_id)
    status = str(item.get("status", "")).strip()

    if status == CONNECTOR_STATUS_DISABLED:
        return _safe_connector(item)
    if status == CONNECTOR_STATUS_REVOKED:
        raise RuntimeError("Revoked connector is terminal")
    if status not in {
        connector_management.CONNECTOR_STATUS_ENABLED,
        connector_management.CONNECTOR_STATUS_UNHEALTHY,
    }:
        raise RuntimeError("Connector cannot be disabled from its current status")

    result = connector_management._update_status(
        connectors_table,
        connector_id,
        CONNECTOR_STATUS_DISABLED,
        health_reason=None,
        expected_current_statuses=(
            connector_management.CONNECTOR_STATUS_ENABLED,
            connector_management.CONNECTOR_STATUS_UNHEALTHY,
        ),
    )
    attributes = result.get("Attributes") or {}
    if not attributes:
        attributes = dict(item)
        attributes["status"] = CONNECTOR_STATUS_DISABLED
        attributes["healthReason"] = None
    return _safe_connector(attributes)


def enable_connector(
    connectors_table,
    ssm_client,
    sts_client,
    client_factory,
    environment_name: str,
    connector_id: str,
) -> dict:
    item = _load_connector(connectors_table, connector_id)
    status = str(item.get("status", "")).strip()

    if status == connector_management.CONNECTOR_STATUS_ENABLED:
        return _safe_connector(item)
    if status == CONNECTOR_STATUS_REVOKED:
        raise RuntimeError("Revoked connector is terminal")
    if status not in {
        CONNECTOR_STATUS_DISABLED,
        connector_management.CONNECTOR_STATUS_VALIDATING,
        connector_management.CONNECTOR_STATUS_APPROVAL_PENDING,
    }:
        raise RuntimeError("Connector cannot be enabled from its current status")

    role_arn = str(item.get("connectorRoleArn", "")).strip()
    if not connector_management.CONNECTOR_ROLE_ARN_PATTERN.fullmatch(role_arn):
        raise connector_management.ConnectorValidationError(
            connector_management.HEALTH_CONFIG_INVALID
        )

    # Approval, re-enable, and post-reset activation all perform a fresh fail-closed
    # runner validation rather than flipping status directly. Move through UNHEALTHY
    # only as the existing registration validator's accepted re-entry state.
    connector_management._update_status(
        connectors_table,
        connector_id,
        connector_management.CONNECTOR_STATUS_UNHEALTHY,
        health_reason=None,
        expected_current_statuses=(status,),
    )

    return connector_management.register_connector(
        connectors_table,
        ssm_client,
        sts_client,
        client_factory,
        environment_name,
        connector_id,
        {"connectorRoleArn": role_arn},
        final_status=connector_management.CONNECTOR_STATUS_ENABLED,
    )


def reset_external_id(
    connectors_table,
    ssm_client,
    environment_name: str,
    kms_key_id: str,
    connector_id: str,
) -> dict:
    item = _load_connector(connectors_table, connector_id)
    status = str(item.get("status", "")).strip()
    if status == CONNECTOR_STATUS_REVOKED:
        raise RuntimeError("Revoked connector is terminal")
    if status not in {
        connector_management.CONNECTOR_STATUS_ENABLED,
        connector_management.CONNECTOR_STATUS_UNHEALTHY,
        CONNECTOR_STATUS_DISABLED,
    }:
        raise RuntimeError("Connector ExternalId cannot be reset from its current status")

    environment_name = str(environment_name or "").strip()
    kms_key_id = str(kms_key_id or "").strip()
    if environment_name not in {"dev", "prod"} or not kms_key_id:
        raise RuntimeError("Connector reset configuration is invalid")

    # Fail closed before rotating the protected value. If the SecureString write
    # fails, move to UNHEALTHY so the old trust cannot continue scanning.
    validating = connector_management._update_status(
        connectors_table,
        connector_id,
        connector_management.CONNECTOR_STATUS_VALIDATING,
        health_reason=None,
        expected_current_statuses=(
            connector_management.CONNECTOR_STATUS_ENABLED,
            connector_management.CONNECTOR_STATUS_UNHEALTHY,
            CONNECTOR_STATUS_DISABLED,
        ),
    )
    parameter_name = connector_management.external_id_parameter_name(
        environment_name, connector_id
    )
    try:
        ssm_client.put_parameter(
            Name=parameter_name,
            Description="AWS Security Coach connector ExternalId",
            Value=secrets.token_hex(32),
            Type="SecureString",
            KeyId=kms_key_id,
            Overwrite=True,
            Tier="Standard",
            DataType="text",
        )
    except Exception:
        connector_management._update_status(
            connectors_table,
            connector_id,
            connector_management.CONNECTOR_STATUS_UNHEALTHY,
            health_reason=connector_management.HEALTH_CONFIG_MISSING,
            expected_current_statuses=(
                connector_management.CONNECTOR_STATUS_VALIDATING,
            ),
        )
        raise

    attributes = validating.get("Attributes") or {}
    if not attributes:
        attributes = dict(item)
        attributes["status"] = connector_management.CONNECTOR_STATUS_VALIDATING
        attributes["healthReason"] = None
    return _safe_connector(attributes)


def _disable_memberships(memberships_table, connector_id: str) -> None:
    scan_kwargs = {
        "FilterExpression": "connectorId = :connectorId",
        "ExpressionAttributeValues": {":connectorId": connector_id},
    }
    while True:
        response = memberships_table.scan(**scan_kwargs)
        for membership in response.get("Items") or []:
            requester_ref = membership.get("requesterRef")
            if not requester_ref or membership.get("connectorId") != connector_id:
                continue
            if membership.get("enabled") is not True:
                continue
            memberships_table.update_item(
                Key={"requesterRef": requester_ref, "connectorId": connector_id},
                UpdateExpression="SET enabled = :disabled",
                ExpressionAttributeValues={":disabled": False},
            )
        last_evaluated_key = response.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break
        scan_kwargs["ExclusiveStartKey"] = last_evaluated_key


def revoke_connector(
    connectors_table,
    memberships_table,
    ssm_client,
    environment_name: str,
    connector_id: str,
) -> dict:
    item = _load_connector(connectors_table, connector_id)
    status = str(item.get("status", "")).strip()

    if status != CONNECTOR_STATUS_REVOKED:
        result = connector_management._update_status(
            connectors_table,
            connector_id,
            CONNECTOR_STATUS_REVOKED,
            health_reason=None,
            expected_current_statuses=(
                connector_management.CONNECTOR_STATUS_PENDING,
                connector_management.CONNECTOR_STATUS_VALIDATING,
                connector_management.CONNECTOR_STATUS_APPROVAL_PENDING,
                connector_management.CONNECTOR_STATUS_ENABLED,
                connector_management.CONNECTOR_STATUS_UNHEALTHY,
                CONNECTOR_STATUS_DISABLED,
            ),
        )
        attributes = result.get("Attributes") or {}
        if attributes:
            item = attributes
        else:
            item = dict(item)
            item["status"] = CONNECTOR_STATUS_REVOKED
            item["healthReason"] = None

    parameter_name = connector_management.external_id_parameter_name(
        environment_name, connector_id
    )
    try:
        ssm_client.delete_parameter(Name=parameter_name)
    except Exception as exc:
        if connector_management._aws_error_code(exc) != "ParameterNotFound":
            raise

    _disable_memberships(memberships_table, connector_id)
    return _safe_connector(item)
