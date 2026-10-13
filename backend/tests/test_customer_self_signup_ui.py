import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = (REPO_ROOT / "backend" / "template.yaml").read_text(encoding="utf-8")
AUTHENTICATED_APP = (REPO_ROOT / "ui" / "src" / "AuthenticatedApp.tsx").read_text(encoding="utf-8")
ONBOARDING = (REPO_ROOT / "ui" / "src" / "operatorConnectorOnboarding.tsx").read_text(encoding="utf-8")


class CustomerSelfSignupUiTests(unittest.TestCase):
    def test_cognito_allows_self_signup_with_verified_email(self):
        pool = TEMPLATE.split("  StackCognitoUserPool:", 1)[1].split(
            "  StackCognitoUserPoolClient:", 1
        )[0]
        self.assertIn("AllowAdminCreateUserOnly: false", pool)
        self.assertIn("AutoVerifiedAttributes:\n        - email", pool)
        self.assertIn("MinimumLength: 12", pool)
        self.assertIn("RequireLowercase: true", pool)
        self.assertIn("RequireNumbers: true", pool)
        self.assertIn("RequireSymbols: true", pool)
        self.assertIn("RequireUppercase: true", pool)

    def test_logged_out_connect_cta_records_only_resume_intent(self):
        self.assertIn(
            'CONNECTOR_ONBOARDING_INTENT_KEY = "aws-security-coach-connector-onboarding-intent"',
            AUTHENTICATED_APP,
        )
        self.assertIn(
            'sessionStorage.setItem(CONNECTOR_ONBOARDING_INTENT_KEY, "1")',
            AUTHENTICATED_APP,
        )
        self.assertIn("<Plus size={16} /> Connect AWS Account", AUTHENTICATED_APP)
        self.assertIn("autoOpen={resumeConnectorOnboarding}", AUTHENTICATED_APP)
        self.assertNotIn("localStorage", AUTHENTICATED_APP)

    def test_authenticated_customer_onboarding_is_not_operator_probe_gated(self):
        self.assertNotIn("operatorAvailable", ONBOARDING)
        self.assertNotIn("setOperatorAvailable", ONBOARDING)
        self.assertNotIn('fetch(`${API_BASE_URL}/auth/connectors`, { headers:', ONBOARDING)
        self.assertIn('status !== "APPROVAL_PENDING"', ONBOARDING)
        self.assertIn("Connector setup complete", ONBOARDING)
        self.assertIn("Current status: Waiting for approval", ONBOARDING)
        self.assertIn("Scans remain unavailable while this approval is pending", ONBOARDING)
        self.assertIn("appear automatically as an available scan target", ONBOARDING)
        self.assertNotIn("Tool Account approval", ONBOARDING)
        self.assertNotIn("localStorage", ONBOARDING)


if __name__ == "__main__":
    unittest.main()
