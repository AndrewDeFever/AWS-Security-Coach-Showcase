import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "template.yaml").read_text(encoding="utf-8")
HANDLER = (ROOT / "src" / "scan" / "connector_aware_handler.py").read_text(
    encoding="utf-8"
)


class ConnectorRegistrationRuntimeTests(unittest.TestCase):
    def test_registration_route_is_explicit_and_authenticated(self):
        self.assertIn(
            'CONNECTOR_REGISTER_PATH_PATTERN = re.compile(',
            HANDLER,
        )
        self.assertIn("return _register_connector_response(", HANDLER)

        start = HANDLER.index("def _register_connector_response")
        end = HANDLER.index("def _connector_target", start)
        section = HANDLER[start:end]
        auth_gate = section.index("if not scan._is_authenticated_route(event):")
        requester_gate = section.index("if not requester_ref:")
        table_lookup = section.index('os.environ.get("CONNECTORS_TABLE", "")')
        ownership_gate = section.index("if not scan._operator_authorized(event):")
        owned_lookup = section.index("_load_owned_connector(")
        register_call = section.index("connector_management.register_connector(")
        self.assertLess(auth_gate, requester_gate)
        self.assertLess(requester_gate, table_lookup)
        self.assertLess(table_lookup, ownership_gate)
        self.assertLess(ownership_gate, owned_lookup)
        self.assertLess(owned_lookup, register_call)
        self.assertNotIn('"code": "OPERATOR_REQUIRED"', section)
        self.assertIn('"code": "CONNECTOR_NOT_FOUND"', section)

    def test_public_registration_response_does_not_expose_role_account_or_owner_identity(self):
        start = HANDLER.index("def _register_connector_response")
        end = HANDLER.index("def _connector_target", start)
        section = HANDLER[start:end]
        public_result = section[section.index("public_result = {") :]
        self.assertNotIn('"connectorRoleArn"', public_result)
        self.assertNotIn('"expectedAccountId"', public_result)
        self.assertNotIn('"ownerRequesterRef"', public_result)
        self.assertNotIn('"externalId"', public_result)
        self.assertIn('"healthReason"', public_result)
        self.assertIn("validated and awaiting approval", section)

    def test_sam_wires_registration_route(self):
        self.assertIn("RegisterConnectorRoute:", TEMPLATE)
        self.assertIn("Path: /auth/connectors/{connectorId}/register", TEMPLATE)
        self.assertIn("Method: POST", TEMPLATE)

    def test_scan_function_registration_permissions_are_runner_only(self):
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
        self.assertNotIn("arn:${AWS::Partition}:iam::*:role/aws-security-coach/*", scan_section)
        self.assertNotIn("iam:ResourceTag/AWSSecurityCoachConnector", scan_section)

        self.assertNotIn("arn:${AWS::Partition}:iam::*:role/*", scan_section)
        self.assertNotIn("dynamodb:*", scan_section)
        self.assertNotIn("ssm:*", scan_section)
        self.assertNotIn("sts:*", scan_section)
        self.assertNotIn("kms:*", scan_section)


if __name__ == "__main__":
    unittest.main()
