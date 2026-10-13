import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONNECTOR_HANDLER = (ROOT / "src" / "scan" / "connector_aware_handler.py").read_text(
    encoding="utf-8"
)
LIFECYCLE_HANDLER = (ROOT / "src" / "scan" / "lifecycle_aware_handler.py").read_text(
    encoding="utf-8"
)
TEMPLATE = (ROOT / "template.yaml").read_text(encoding="utf-8")


class ProductionConnectorExecutionTests(unittest.TestCase):
    def test_target_discovery_is_registry_backed_not_environment_gated(self):
        targets_start = CONNECTOR_HANDLER.index("def _targets_response")
        connector_start = CONNECTOR_HANDLER.index("def _connector_response")
        targets_section = CONNECTOR_HANDLER[targets_start:connector_start]

        self.assertNotIn('environment_name == "dev"', targets_section)
        self.assertNotIn("LEGACY_PILOT_CONNECTOR_ID", targets_section)
        self.assertIn('IndexName="management-index"', targets_section)
        self.assertIn("connector_management.MANAGEMENT_BUCKET", targets_section)
        self.assertIn("connector_management.CONNECTOR_STATUS_ENABLED", targets_section)
        self.assertIn('Key={"connectorId": connector_id}', CONNECTOR_HANDLER)
        self.assertIn('ConsistentRead=True', CONNECTOR_HANDLER)

    def test_connector_execution_has_no_dev_only_guard(self):
        connector_start = CONNECTOR_HANDLER.index("def _connector_response")
        connector_section = CONNECTOR_HANDLER[connector_start:]

        self.assertNotIn('environment_name != "dev"', connector_section)
        self.assertNotIn("LEGACY_PILOT_CONNECTOR_ID", connector_section)
        self.assertIn("connector_management._connector_id", connector_section)
        self.assertIn("_customer_connector_authorized(requester_ref, connector_id)", connector_section)

    def test_lifecycle_wrapper_still_requires_enabled_registry_record(self):
        self.assertIn('Key={"connectorId": connector_id}', LIFECYCLE_HANDLER)
        self.assertIn("connector_management.CONNECTOR_STATUS_ENABLED", LIFECYCLE_HANDLER)
        self.assertIn('"code": "CONNECTOR_NOT_ENABLED"', LIFECYCLE_HANDLER)
        self.assertIn('"code": "CONNECTOR_ACCESS_DENIED"', LIFECYCLE_HANDLER)

    def test_scan_role_has_required_registry_read_permissions(self):
        self.assertIn("- dynamodb:GetItem", TEMPLATE)
        self.assertIn("- dynamodb:Query", TEMPLATE)
        self.assertIn("Resource: !GetAtt ConnectorsTable.Arn", TEMPLATE)
        self.assertIn("Resource: !Sub '${ConnectorsTable.Arn}/index/management-index'", TEMPLATE)


if __name__ == "__main__":
    unittest.main()
