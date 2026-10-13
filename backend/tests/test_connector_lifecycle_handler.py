import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HANDLER = (ROOT / "src" / "scan" / "lifecycle_aware_handler.py").read_text(
    encoding="utf-8"
)
INVENTORY = (ROOT / "src" / "scan" / "operator_connector_inventory.py").read_text(
    encoding="utf-8"
)
TEMPLATE = (ROOT / "template.yaml").read_text(encoding="utf-8")


class ConnectorLifecycleHandlerTests(unittest.TestCase):
    def test_lifecycle_routes_are_bounded_to_supported_actions(self):
        self.assertIn("(?P<action>disable|enable|reset|revoke)", HANDLER)
        self.assertIn('if action == "disable":', HANDLER)
        self.assertIn('elif action == "enable":', HANDLER)
        self.assertIn('elif action == "reset":', HANDLER)
        self.assertIn('elif action == "revoke":', HANDLER)

    def test_operator_gate_runs_before_table_access(self):
        start = HANDLER.index("def _lifecycle_response")
        end = HANDLER.index("def _connector_scan_gate", start)
        section = HANDLER[start:end]
        gate = section.index("denied = _operator_gate(event)")
        table_name = section.index('os.environ.get("CONNECTORS_TABLE", "")')
        table_open = section.index("scan.ddb.Table(connectors_table_name)")
        self.assertLess(gate, table_name)
        self.assertLess(table_name, table_open)

    def test_validation_failure_is_sanitized(self):
        self.assertIn('"code": "CONNECTOR_VALIDATION_FAILED"', HANDLER)
        self.assertIn('"status": "UNHEALTHY"', HANDLER)
        self.assertIn('"healthReason": exc.health_reason', HANDLER)
        self.assertNotIn('"externalId"', HANDLER)
        self.assertNotIn('"connectorRoleArn"', HANDLER)
        self.assertNotIn('"expectedAccountId"', HANDLER)

    def test_template_exposes_reset_and_revoke_and_bounded_membership_write(self):
        self.assertIn("Path: /auth/connectors/{connectorId}/reset", TEMPLATE)
        self.assertIn("Path: /auth/connectors/{connectorId}/revoke", TEMPLATE)
        self.assertIn("Sid: DisableConnectorMembershipsOnRevoke", TEMPLATE)
        membership_section = TEMPLATE.split(
            "Sid: DisableConnectorMembershipsOnRevoke", 1
        )[1].split("Sid: ManageConnectorExternalIdLifecycle", 1)[0]
        self.assertIn("- dynamodb:UpdateItem", membership_section)
        self.assertIn("Resource: !GetAtt ConnectorMembershipsTable.Arn", membership_section)
        self.assertNotIn("dynamodb:*", membership_section)

    def test_operator_inventory_is_operator_only_and_sanitized(self):
        self.assertIn("scan._operator_authorized(event)", INVENTORY)
        self.assertIn('IndexName="management-index"', INVENTORY)
        self.assertIn('"expectedAccountId"', INVENTORY)
        self.assertNotIn('"connectorRoleArn"', INVENTORY)
        self.assertNotIn('"externalId"', INVENTORY)
        self.assertNotIn('"parameterName"', INVENTORY)

    def test_operator_inventory_route_precedes_generic_delegate(self):
        start = HANDLER.index("def lambda_handler")
        section = HANDLER[start:]
        inventory = section.index('raw_path == "/auth/connectors" and method == "GET"')
        delegate = section.index("return connector_handler.lambda_handler(event, context)")
        self.assertLess(inventory, delegate)

    def test_connector_scan_admission_requires_canonical_enabled_registry_item(self):
        start = HANDLER.index("def _connector_scan_gate")
        end = HANDLER.index("def lambda_handler", start)
        section = HANDLER[start:end]
        self.assertIn("connector_management._connector_id(connector_id)", section)
        self.assertIn("ConsistentRead=True", section)
        self.assertIn("connector_management.CONNECTOR_STATUS_ENABLED", section)
        self.assertIn('"code": "CONNECTOR_NOT_ENABLED"', section)
        self.assertIn('"code": "UNSUPPORTED_TARGET"', section)

    def test_connector_scan_authorization_precedes_registry_lookup(self):
        start = HANDLER.index("def _connector_scan_gate")
        end = HANDLER.index("def lambda_handler", start)
        section = HANDLER[start:end]
        authentication = section.index("if not scan._is_authenticated_route(event):")
        requester = section.index("requester_ref = scan._requester_ref(event)")
        operator = section.index("if not scan._operator_authorized(event):")
        customer_group = section.index("if not connector_handler._customer_authorized(event):")
        membership = section.index("connector_handler._customer_connector_authorized(")
        registry = section.index("scan.ddb.Table(connectors_table_name).get_item(")
        self.assertLess(authentication, requester)
        self.assertLess(requester, operator)
        self.assertLess(operator, customer_group)
        self.assertLess(customer_group, membership)
        self.assertLess(membership, registry)
        self.assertIn('"code": "CONNECTOR_ACCESS_DENIED"', section)

    def test_admission_lookup_logs_only_exception_type_and_aws_error_code(self):
        start = HANDLER.index("def _connector_scan_gate")
        end = HANDLER.index("def lambda_handler", start)
        section = HANDLER[start:end]
        self.assertIn('getattr(exc, "response", {})', section)
        self.assertIn('.get("Code", "UNKNOWN")', section)
        self.assertIn("type(exc).__name__", section)
        self.assertNotIn("str(exc)", section)
        self.assertNotIn("error_response)", section)

    def test_malformed_lifecycle_shape_is_rejected_before_generic_delegate(self):
        self.assertIn("LIFECYCLE_SHAPE_PATTERN = re.compile(", HANDLER)
        start = HANDLER.index("def lambda_handler")
        section = HANDLER[start:]
        shape_match = section.index("lifecycle_shape = LIFECYCLE_SHAPE_PATTERN.fullmatch(raw_path)")
        operator_gate = section.index("denied = _operator_gate(event)", shape_match)
        invalid_response = section.index('"code": "INVALID_CONNECTOR_REQUEST"', shape_match)
        delegate = section.index("return connector_handler.lambda_handler(event, context)")
        self.assertLess(shape_match, operator_gate)
        self.assertLess(operator_gate, invalid_response)
        self.assertLess(invalid_response, delegate)

    def test_scan_gate_runs_before_existing_connector_handler(self):
        start = HANDLER.index("def lambda_handler")
        section = HANDLER[start:]
        gate = section.index("denied = _connector_scan_gate(event)")
        delegate = section.index("return connector_handler.lambda_handler(event, context)")
        self.assertLess(gate, delegate)


if __name__ == "__main__":
    unittest.main()
