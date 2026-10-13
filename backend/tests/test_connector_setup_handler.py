import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HANDLER = (ROOT / "src" / "scan" / "connector_setup.py").read_text(encoding="utf-8")


class ConnectorSetupHandlerTests(unittest.TestCase):
    def test_identity_and_ownership_gates_precede_secret_read(self):
        handler_start = HANDLER.index("def lambda_handler")
        section = HANDLER[handler_start:]
        identity_gate = section.index("requester_ref, denied = _identity_gate(event)")
        connector_validation = section.index("connector_management._connector_id")
        registry_lookup = section.index('boto3.resource("dynamodb")')
        ownership_gate = section.index("if not scan._operator_authorized(event):")
        owner_match = section.index("owner_requester_ref != requester_ref")
        secret_read = section.index('boto3.client("ssm").get_parameter')
        self.assertLess(identity_gate, connector_validation)
        self.assertLess(connector_validation, registry_lookup)
        self.assertLess(registry_lookup, ownership_gate)
        self.assertLess(ownership_gate, owner_match)
        self.assertLess(owner_match, secret_read)
        self.assertIn('"code": "CONNECTOR_NOT_FOUND"', section)

    def test_setup_is_available_only_for_pending_or_unhealthy_connectors(self):
        self.assertIn("connector_management.CONNECTOR_STATUS_PENDING", HANDLER)
        self.assertIn("connector_management.CONNECTOR_STATUS_UNHEALTHY", HANDLER)
        self.assertIn('"CONNECTOR_SETUP_NOT_AVAILABLE"', HANDLER)
        self.assertIn('"CONNECTOR_STATE_CONFLICT"', HANDLER)

    def test_disclosure_acknowledgment_is_versioned_and_fail_closed(self):
        self.assertIn('DISCLOSURE_VERSION = "1.0"', HANDLER)
        self.assertIn('set(data) != {"acknowledged", "disclosureVersion"}', HANDLER)
        self.assertIn('data.get("acknowledged") is not True', HANDLER)
        self.assertIn('"INVALID_DISCLOSURE_ACKNOWLEDGMENT"', HANDLER)
        self.assertIn('"disclosureAcknowledgedBy"', HANDLER)
        self.assertIn('"disclosureAcknowledgedAt"', HANDLER)
        self.assertIn('requester_ref, denied = _identity_gate(event)', HANDLER)
        self.assertIn('":acknowledgedBy": requester_ref', HANDLER)

    def test_setup_material_is_withheld_until_disclosure_is_acknowledged(self):
        handler_start = HANDLER.index("def lambda_handler")
        section = HANDLER[handler_start:]
        limited_response = section.index("if not acknowledged:")
        secret_read = section.index('boto3.client("ssm").get_parameter')
        release_generation = section.index('release_key = f"{environment_name}/{template_version}/template.yaml"')
        self.assertLess(limited_response, secret_read)
        self.assertLess(limited_response, release_generation)
        limited_start = HANDLER.index("def _limited_setup_response")
        limited_end = HANDLER.index("def lambda_handler", limited_start)
        limited = HANDLER[limited_start:limited_end]
        self.assertNotIn('"externalId"', limited)
        self.assertNotIn('"quickCreateUrl"', limited)

    def test_external_id_is_separate_from_quick_create_parameters(self):
        quick_create_start = HANDLER.index("def _quick_create_url")
        quick_create_end = HANDLER.index("def _configuration", quick_create_start)
        quick_create = HANDLER[quick_create_start:quick_create_end]
        self.assertIn('"param_TrustedScannerRoleArn"', quick_create)
        self.assertIn('"param_HomeRegion"', quick_create)
        self.assertNotIn("ExternalId", quick_create)
        self.assertIn('"externalId": external_id', HANDLER)

    def test_exact_release_key_and_short_presigned_ttl_are_used(self):
        self.assertIn('release_key = f"{environment_name}/{template_version}/template.yaml"', HANDLER)
        self.assertIn("PRESIGNED_TEMPLATE_TTL_SECONDS = 900", HANDLER)
        self.assertIn('"get_object"', HANDLER)
        self.assertIn('"Bucket": release_bucket', HANDLER)
        self.assertIn('"Key": release_key', HANDLER)

    def test_setup_response_does_not_expose_internal_paths_role_arn_or_owner(self):
        response_start = HANDLER.rindex("connector = {")
        response = HANDLER[response_start:]
        self.assertNotIn('"parameterName"', response)
        self.assertNotIn('"ssmParameter",', response)
        self.assertNotIn('"trustedScannerRoleArn"', response)
        self.assertNotIn('"connectorRoleArn"', response)
        self.assertNotIn('"ownerRequesterRef"', response)
        self.assertIn('"customerOrganization"', response)


if __name__ == "__main__":
    unittest.main()
