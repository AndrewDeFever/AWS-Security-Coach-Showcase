import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "template.yaml").read_text(encoding="utf-8")


class ConnectorSetupSamTests(unittest.TestCase):
    def test_dedicated_setup_function_and_get_post_routes_exist(self):
        self.assertIn("  ConnectorSetupFunction:", TEMPLATE)
        setup_section = TEMPLATE.split("  ConnectorSetupFunction:", 1)[1].split(
            "  GetScanFunction:", 1
        )[0]

        self.assertIn("Handler: connector_setup.lambda_handler", setup_section)
        self.assertEqual(setup_section.count("Path: /auth/connectors/{connectorId}/setup"), 2)
        self.assertIn("Method: GET", setup_section)
        self.assertIn("Method: POST", setup_section)
        self.assertIn("CONNECTORS_TABLE: !Ref ConnectorsTable", setup_section)
        self.assertIn("ENVIRONMENT_NAME: !Ref EnvironmentName", setup_section)
        self.assertIn(
            "CONNECTOR_RELEASE_BUCKET: !Ref ConnectorReleaseBucketName",
            setup_section,
        )
        self.assertIn("TRUSTED_SCANNER_ROLE_ARN: !GetAtt RunnerFunctionRole.Arn", setup_section)

    def test_setup_function_permissions_are_bounded(self):
        setup_section = TEMPLATE.split("  ConnectorSetupFunction:", 1)[1].split(
            "  GetScanFunction:", 1
        )[0]

        self.assertIn("Sid: ReadAndAcknowledgeConnectorSetupRecord", setup_section)
        self.assertIn("- dynamodb:GetItem", setup_section)
        self.assertIn("- dynamodb:UpdateItem", setup_section)
        self.assertNotIn("- dynamodb:PutItem", setup_section)
        self.assertNotIn("- dynamodb:DeleteItem", setup_section)
        self.assertIn("Resource: !GetAtt ConnectorsTable.Arn", setup_section)

        self.assertIn("Sid: ReadConnectorExternalIdForSetup", setup_section)
        self.assertIn("- ssm:GetParameter", setup_section)
        self.assertIn(
            "parameter/security-coach/${EnvironmentName}/connectors/*",
            setup_section,
        )

        self.assertIn("Sid: ReadReleasedConnectorTemplate", setup_section)
        self.assertIn("- s3:GetObject", setup_section)
        self.assertIn(
            "${ConnectorReleaseBucketName}/${EnvironmentName}/*",
            setup_section,
        )

        self.assertIn("Sid: DecryptConnectorSetupData", setup_section)
        self.assertIn("- kms:Decrypt", setup_section)
        self.assertIn("dynamodb.${AWS::Region}.amazonaws.com", setup_section)
        self.assertIn("ssm.${AWS::Region}.amazonaws.com", setup_section)
        self.assertIn("s3.${AWS::Region}.amazonaws.com", setup_section)

        self.assertNotIn("sts:AssumeRole", setup_section)
        self.assertNotIn("ssm:PutParameter", setup_section)
        self.assertNotIn("ssm:DeleteParameter", setup_section)
        self.assertNotIn("s3:PutObject", setup_section)
        self.assertNotIn("s3:DeleteObject", setup_section)
        self.assertNotIn("kms:*", setup_section)
        self.assertNotIn("ssm:*", setup_section)
        self.assertNotIn("s3:*", setup_section)

    def test_scan_function_secret_and_assume_role_boundary_is_unchanged(self):
        scan_section = TEMPLATE.split("  ScanFunction:", 1)[1].split(
            "  ConnectorSetupFunction:", 1
        )[0]

        self.assertNotIn("- ssm:GetParameter", scan_section)
        self.assertNotIn("- sts:AssumeRole", scan_section)
        self.assertNotIn("s3.${AWS::Region}.amazonaws.com", scan_section)
        self.assertNotIn("ReadReleasedConnectorTemplate", scan_section)


if __name__ == "__main__":
    unittest.main()
