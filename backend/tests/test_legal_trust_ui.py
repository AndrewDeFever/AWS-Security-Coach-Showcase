import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
LEGAL = (REPO_ROOT / "ui" / "src" / "legalPages.tsx").read_text(encoding="utf-8")
LEGAL_CSS = (REPO_ROOT / "ui" / "src" / "legal.css").read_text(encoding="utf-8")
AUTHENTICATED_APP = (REPO_ROOT / "ui" / "src" / "AuthenticatedApp.tsx").read_text(encoding="utf-8")


class LegalTrustUiTests(unittest.TestCase):
    def test_public_legal_surfaces_are_routable_and_persistent(self):
        self.assertIn('"terms" | "privacy" | "security"', LEGAL)
        self.assertIn('href="#/terms"', LEGAL)
        self.assertIn('href="#/privacy"', LEGAL)
        self.assertIn('href="#/security"', LEGAL)
        self.assertIn("<SiteFooter />", AUTHENTICATED_APP)
        self.assertIn("legalPageFromHash(window.location.hash)", AUTHENTICATED_APP)

    def test_footer_uses_short_page_viewport_layout(self):
        self.assertIn("#root{min-height:100vh;display:flex;flex-direction:column}", LEGAL_CSS)
        self.assertIn("#root>.app,#root>.legal-page{flex:1 0 auto;min-height:0}", LEGAL_CSS)
        self.assertIn(".site-footer{", LEGAL_CSS)
        self.assertIn("flex:none", LEGAL_CSS)

    def test_identity_and_contact_use_public_placeholders(self):
        self.assertIn('const CONTACT_EMAIL = "security@example.invalid"', LEGAL)
        self.assertIn("Example Operator", LEGAL)

    def test_security_boundary_copy_remains_read_only_and_customer_controlled(self):
        self.assertIn("read-only cross-account connector", LEGAL)
        self.assertIn("temporary AWS STS sessions", LEGAL)
        self.assertIn("deleting the connector CloudFormation stack", LEGAL)
        self.assertIn("does not ask for or store your AWS console password or long-lived AWS access keys", LEGAL)
        self.assertIn("not a certification", LEGAL)


if __name__ == "__main__":
    unittest.main()
