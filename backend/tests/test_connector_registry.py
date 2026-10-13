from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "template.yaml").read_text(encoding="utf-8")


class ConnectorRegistryTemplateTests(unittest.TestCase):
    def test_connector_registry_table_is_cost_bounded_and_retained(self):
        section = TEMPLATE[TEMPLATE.index("  ConnectorsTable:"):TEMPLATE.index("  ArtifactsBucket:")]
        self.assertIn("TableName: !Sub '${ProjectName}-${EnvironmentName}-connectors'", section)
        self.assertIn("BillingMode: PAY_PER_REQUEST", section)
        self.assertIn("DeletionPolicy: Retain", section)
        self.assertIn("UpdateReplacePolicy: Retain", section)
        self.assertIn("SSESpecification:", section)
        self.assertIn("SSEEnabled: true", section)

    def test_connector_registry_uses_existing_security_coach_kms_key(self):
        section = TEMPLATE[TEMPLATE.index("  ConnectorsTable:"):TEMPLATE.index("  ArtifactsBucket:")]
        self.assertIn("SSEType: KMS", section)
        self.assertIn("KMSMasterKeyId: alias/awssecuritytool", section)

    def test_connector_registry_uses_connector_id_as_primary_key(self):
        section = TEMPLATE[TEMPLATE.index("  ConnectorsTable:"):TEMPLATE.index("  ArtifactsBucket:")]
        self.assertIn("AttributeName: connectorId", section)
        self.assertIn("KeySchema:\n        - AttributeName: connectorId\n          KeyType: HASH", section)

    def test_connector_registry_has_only_two_v1_management_indexes(self):
        section = TEMPLATE[TEMPLATE.index("  ConnectorsTable:"):TEMPLATE.index("  ArtifactsBucket:")]
        self.assertEqual(section.count("IndexName:"), 2)
        self.assertIn("IndexName: management-index", section)
        self.assertIn("IndexName: status-index", section)
        self.assertIn("AttributeName: managementBucket", section)
        self.assertIn("AttributeName: managementSortKey", section)
        self.assertIn("AttributeName: statusBucket", section)
        self.assertIn("AttributeName: statusSortKey", section)
        self.assertEqual(section.count("ProjectionType: ALL"), 2)

    def test_connector_registry_table_is_exported(self):
        self.assertIn("ConnectorsTableName:", TEMPLATE)
        self.assertIn("Value: !Ref ConnectorsTable", TEMPLATE)


if __name__ == "__main__":
    unittest.main()
