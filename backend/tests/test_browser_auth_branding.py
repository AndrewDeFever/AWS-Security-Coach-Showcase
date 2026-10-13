import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
INDEX = (REPO_ROOT / "ui" / "index.html").read_text(encoding="utf-8")
WORKFLOW = (REPO_ROOT / ".github" / "workflows" / "deploy-backend.yml").read_text(encoding="utf-8")
BRANDING_SCRIPT = (REPO_ROOT / "backend" / "scripts" / "apply_managed_login_branding.sh").read_text(encoding="utf-8")
MANAGED_LOGIN_MARK = (REPO_ROOT / "ui" / "public" / "managed-login-mark.svg").read_text(encoding="utf-8")


class BrowserAuthBrandingTests(unittest.TestCase):
    def test_public_browser_title_is_product_name(self):
        self.assertIn("<title>AWS Security Coach | AWS Posture Review</title>", INDEX)
        self.assertNotIn("<title>aws-safety-coach-ui</title>", INDEX)
        self.assertIn('href="/managed-login-mark.svg"', INDEX)

    def test_backend_deploy_reconciles_existing_managed_login_branding(self):
        self.assertIn("Reconcile Cognito Managed Login branding", WORKFLOW)
        self.assertIn("apply_managed_login_branding.sh", WORKFLOW)
        self.assertIn("describe-managed-login-branding-by-client", BRANDING_SCRIPT)
        self.assertIn("update-managed-login-branding", BRANDING_SCRIPT)

    def test_managed_login_uses_existing_style_and_product_palette(self):
        self.assertIn('colorSchemeMode = "LIGHT"', BRANDING_SCRIPT)
        self.assertIn('pageBackground.lightMode.color = "06111fff"', BRANDING_SCRIPT)
        self.assertIn('form.lightMode.backgroundColor = "111827ff"', BRANDING_SCRIPT)
        self.assertIn('Category: "FAVICON_SVG"', BRANDING_SCRIPT)
        self.assertNotIn('Category: "FORM_LOGO"', BRANDING_SCRIPT)
        self.assertIn('.components.form.logo.enabled = false', BRANDING_SCRIPT)

    def test_managed_login_forces_shared_svg_favicon(self):
        self.assertIn('.components.favicon.enabledTypes = ["SVG"]', BRANDING_SCRIPT)
        self.assertIn('ColorMode: "DYNAMIC"', BRANDING_SCRIPT)
        self.assertIn('ColorMode: "LIGHT"', BRANDING_SCRIPT)
        self.assertIn('ColorMode: "DARK"', BRANDING_SCRIPT)
        self.assertIn('FaviconModes:', BRANDING_SCRIPT)
        self.assertNotIn('--return-merged-resources \\\n  --region "$region" \\\n  --output json)"\n\nverified_summary', BRANDING_SCRIPT)

    def test_managed_login_assets_match_cognito_contract(self):
        self.assertIn('asset_path="${2:-../ui/public/managed-login-mark.svg}"', BRANDING_SCRIPT)
        self.assertNotIn("ResourceId:", BRANDING_SCRIPT)
        self.assertIn('width="48" height="48"', MANAGED_LOGIN_MARK)
        self.assertIn('viewBox="0 0 48 48"', MANAGED_LOGIN_MARK)


if __name__ == "__main__":
    unittest.main()
