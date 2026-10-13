import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HANDLER = (ROOT / "src" / "scan" / "connector_aware_handler.py").read_text(
    encoding="utf-8"
)


class ConnectorProvisioningHandlerTests(unittest.TestCase):
    def test_post_connectors_route_is_explicitly_dispatched(self):
        self.assertIn('CONNECTORS_PATH = "/auth/connectors"', HANDLER)
        self.assertIn("if raw_path == CONNECTORS_PATH:", HANDLER)
        self.assertIn("return _create_connector_response(event, data)", HANDLER)

    def test_provisioning_requires_authenticated_requester_before_writes(self):
        start = HANDLER.index("def _create_connector_response")
        end = HANDLER.index("def _assumed_client_factory", start)
        section = HANDLER[start:end]

        auth_gate = section.index("if not scan._is_authenticated_route(event):")
        requester_gate = section.index("if not requester_ref:")
        table_lookup = section.index('os.environ.get("CONNECTORS_TABLE", "")')
        provision_call = section.index("connector_management.provision_connector(")

        self.assertLess(auth_gate, requester_gate)
        self.assertLess(requester_gate, table_lookup)
        self.assertLess(table_lookup, provision_call)
        self.assertNotIn('"code": "OPERATOR_REQUIRED"', section)

    def test_non_operator_provisioning_records_pseudonymous_owner_server_side(self):
        start = HANDLER.index("def _create_connector_response")
        end = HANDLER.index("def _assumed_client_factory", start)
        section = HANDLER[start:end]

        self.assertIn(
            "owner_requester_ref = None if scan._operator_authorized(event) else requester_ref",
            section,
        )
        self.assertIn("owner_requester_ref=owner_requester_ref", section)
        self.assertNotIn('"ownerRequesterRef"', section)

    def test_handler_requires_bounded_runtime_configuration(self):
        start = HANDLER.index("def _create_connector_response")
        end = HANDLER.index("def _assumed_client_factory", start)
        section = HANDLER[start:end]

        self.assertIn('os.environ.get("CONNECTORS_TABLE", "")', section)
        self.assertIn('os.environ.get("ENVIRONMENT_NAME", "")', section)
        self.assertIn('os.environ.get("APPLICATION_KMS_KEY_ARN", "")', section)
        self.assertIn('"code": "SERVICE_CONFIGURATION_ERROR"', section)

    def test_public_response_never_adds_external_id_or_parameter_name(self):
        start = HANDLER.index("def _create_connector_response")
        end = HANDLER.index("def _assumed_client_factory", start)
        section = HANDLER[start:end]

        self.assertNotIn('"externalId"', section)
        self.assertNotIn('"parameterName"', section)
        self.assertIn('"connector": result', section)


if __name__ == "__main__":
    unittest.main()
