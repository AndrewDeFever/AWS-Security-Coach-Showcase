import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MANAGED = (REPO_ROOT / "ui" / "src" / "operatorManagedAssessment.tsx").read_text(encoding="utf-8")
AUTHENTICATED_APP = (REPO_ROOT / "ui" / "src" / "AuthenticatedApp.tsx").read_text(encoding="utf-8")


class ManagedAssessmentUiTests(unittest.TestCase):
    def test_managed_assessment_entry_is_operator_gated(self):
        self.assertIn("OperatorManagedAssessment", AUTHENTICATED_APP)
        self.assertIn("New Managed Assessment", MANAGED)
        self.assertIn("/auth/connectors`,", MANAGED)
        self.assertIn("response.status === 403", MANAGED)
        self.assertIn("if (!operatorAvailable) return null", MANAGED)

    def test_managed_assessment_captures_customer_identity_separately_from_internal_label(self):
        self.assertIn("Customer / Organization", MANAGED)
        self.assertIn("Internal account / connector name", MANAGED)
        self.assertIn('placeholder="Acme Corporation"', MANAGED)
        self.assertIn("customerOrganization: organization", MANAGED)
        self.assertIn("displayName: name", MANAGED)
        self.assertIn("AWS account ID is not typed here", MANAGED)
        self.assertIn("captured from the validated ConnectorRoleArn/account match", MANAGED)

    def test_managed_assessment_reuses_existing_connector_contract(self):
        self.assertIn('method: "POST"', MANAGED)
        self.assertIn("body: JSON.stringify({ displayName: name, customerOrganization: organization, homeRegion: HOME_REGION })", MANAGED)
        self.assertIn("/setup`,", MANAGED)
        self.assertIn("disclosureVersion: DISCLOSURE_VERSION", MANAGED)
        self.assertIn("/register`,", MANAGED)
        self.assertIn("/enable`,", MANAGED)
        self.assertLess(MANAGED.index("/register`,"), MANAGED.index("/enable`,"))
        self.assertIn('registered.status !== "APPROVAL_PENDING"', MANAGED)
        self.assertIn('enabled.status !== "ENABLED"', MANAGED)

    def test_customer_handoff_is_credentialless_and_customer_controlled(self):
        self.assertIn("Please do NOT send an AWS password, access key, secret access key, or console credentials.", MANAGED)
        self.assertIn("ConnectorRoleArn", MANAGED)
        self.assertIn("Refresh AWS Link", MANAGED)
        self.assertIn("delete the CloudFormation stack named", MANAGED)
        self.assertIn("customer-controlled read-only AWS connection", MANAGED)

    def test_managed_draft_contains_only_non_secret_resume_identity(self):
        self.assertIn("localStorage.setItem(DRAFT_KEY", MANAGED)
        self.assertIn("connectorId: connector.connectorId", MANAGED)
        self.assertIn("displayName: connector.displayName", MANAGED)
        self.assertIn("customerOrganization: connector.customerOrganization", MANAGED)
        draft_section = MANAGED[MANAGED.index("function writeDraft"):MANAGED.index("function clearDraft")]
        self.assertNotIn("externalId", draft_section)
        self.assertNotIn("connectorRoleArn", draft_section)
        self.assertNotIn("quickCreateUrl", draft_section)


if __name__ == "__main__":
    unittest.main()
