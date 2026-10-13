import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "template.yaml").read_text(encoding="utf-8")


class ConnectorProvisioningSamTests(unittest.TestCase):
    def test_scan_function_has_connector_provisioning_route_and_configuration(self):
        self.assertIn("CreateConnectorRoute:", TEMPLATE)
        self.assertIn("Path: /auth/connectors", TEMPLATE)
        self.assertIn("Method: POST", TEMPLATE)
        self.assertIn("CONNECTORS_TABLE: !Ref ConnectorsTable", TEMPLATE)
        self.assertIn("APPLICATION_KMS_KEY_ARN: !Ref ApplicationKmsKeyArn", TEMPLATE)

    def test_scan_function_connector_management_permissions_are_runner_only(self):
        scan_section = TEMPLATE.split("  ScanFunction:", 1)[1].split(
            "  ConnectorSetupFunction:", 1
        )[0]

        self.assertIn("Sid: ManageConnectorRegistryLifecycle", scan_section)
        self.assertIn("- dynamodb:GetItem", scan_section)
        self.assertIn("- dynamodb:PutItem", scan_section)
        self.assertIn("- dynamodb:UpdateItem", scan_section)
        self.assertIn("Resource: !GetAtt ConnectorsTable.Arn", scan_section)

        self.assertIn("Sid: ManageConnectorExternalIdLifecycle", scan_section)
        self.assertIn("- ssm:PutParameter", scan_section)
        self.assertIn("- ssm:DeleteParameter", scan_section)
        self.assertNotIn("- ssm:GetParameter", scan_section)
        self.assertIn(
            "parameter/security-coach/${EnvironmentName}/connectors/*",
            scan_section,
        )

        self.assertIn("Sid: EncryptConnectorExternalIds", scan_section)
        encrypt_section = scan_section.split("Sid: EncryptConnectorExternalIds", 1)[1].split(
            "Sid: DecryptConnectorRegistryViaDynamoDb", 1
        )[0]
        self.assertIn("- kms:Encrypt", encrypt_section)
        self.assertNotIn("- kms:Decrypt", encrypt_section)
        self.assertIn("Resource: !Ref ApplicationKmsKeyArn", encrypt_section)
        self.assertIn("ssm.${AWS::Region}.amazonaws.com", encrypt_section)
        self.assertNotIn("dynamodb.${AWS::Region}.amazonaws.com", encrypt_section)

        self.assertIn("Sid: DecryptConnectorRegistryViaDynamoDb", scan_section)
        decrypt_section = scan_section.split("Sid: DecryptConnectorRegistryViaDynamoDb", 1)[1].split(
            "- LambdaInvokePolicy:", 1
        )[0]
        self.assertIn("- kms:Decrypt", decrypt_section)
        self.assertIn("Resource: !Ref ApplicationKmsKeyArn", decrypt_section)
        self.assertIn("dynamodb.${AWS::Region}.amazonaws.com", decrypt_section)
        self.assertNotIn("ssm.${AWS::Region}.amazonaws.com", decrypt_section)

        self.assertNotIn("Sid: ValidateManagedSecurityCoachConnectors", scan_section)
        self.assertNotIn("- sts:AssumeRole", scan_section)
        self.assertNotIn(
            "arn:${AWS::Partition}:iam::*:role/aws-security-coach/*",
            scan_section,
        )
        self.assertNotIn("iam:ResourceTag/AWSSecurityCoachConnector", scan_section)

        self.assertNotIn("kms:*", scan_section)
        self.assertNotIn("ssm:*", scan_section)
        self.assertNotIn("dynamodb:*", scan_section)
        self.assertNotIn("sts:*", scan_section)


if __name__ == "__main__":
    unittest.main()
