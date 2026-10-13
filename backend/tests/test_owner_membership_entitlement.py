import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HANDLER = (ROOT / "src" / "scan" / "lifecycle_aware_handler.py").read_text(
    encoding="utf-8"
)
TEMPLATE = (ROOT / "template.yaml").read_text(encoding="utf-8")


class OwnerMembershipEntitlementTests(unittest.TestCase):
    def test_approval_grants_owner_membership_only_after_enable_succeeds(self):
        start = HANDLER.index('elif action == "enable":')
        end = HANDLER.index('elif action == "reset":', start)
        section = HANDLER[start:end]

        validation = section.index("connector_lifecycle.enable_connector(")
        enabled_gate = section.index(
            "connector_management.CONNECTOR_STATUS_ENABLED",
            validation,
        )
        grant = section.index("_grant_owner_membership(", enabled_gate)

        self.assertLess(validation, enabled_gate)
        self.assertLess(enabled_gate, grant)
        self.assertIn('os.environ.get(\n                "CONNECTOR_MEMBERSHIPS_TABLE", ""', section)
        self.assertIn("ConsistentRead=True", section)

    def test_membership_grant_is_owner_bounded_and_idempotent(self):
        start = HANDLER.index("def _grant_owner_membership")
        end = HANDLER.index("def _lifecycle_response", start)
        section = HANDLER[start:end]

        self.assertIn('connector_item.get("ownerRequesterRef", "")', section)
        self.assertIn("if not owner_requester_ref:", section)
        self.assertIn("memberships_table.update_item(", section)
        self.assertIn(
            'Key={"requesterRef": owner_requester_ref, "connectorId": connector_id}',
            section,
        )
        self.assertIn('UpdateExpression="SET enabled = :enabled"', section)
        self.assertIn('ExpressionAttributeValues={":enabled": True}', section)

    def test_customer_scan_authorization_remains_membership_only(self):
        start = HANDLER.index("def _connector_scan_gate")
        end = HANDLER.index("def lambda_handler", start)
        section = HANDLER[start:end]

        self.assertIn(
            "connector_handler._customer_connector_authorized(",
            section,
        )
        self.assertIn('"code": "CONNECTOR_ACCESS_DENIED"', section)
        self.assertNotIn("ownerRequesterRef", section)
        self.assertNotIn("_connector_owned_by", section)

    def test_existing_membership_permission_is_bounded_to_update_item(self):
        membership_section = TEMPLATE.split(
            "Sid: DisableConnectorMembershipsOnRevoke", 1
        )[1].split("Sid: ManageConnectorExternalIdLifecycle", 1)[0]
        self.assertIn("- dynamodb:UpdateItem", membership_section)
        self.assertIn("Resource: !GetAtt ConnectorMembershipsTable.Arn", membership_section)
        self.assertNotIn("dynamodb:*", membership_section)


if __name__ == "__main__":
    unittest.main()
