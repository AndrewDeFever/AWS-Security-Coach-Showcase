import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
APP = (REPO_ROOT / "ui" / "src" / "App.tsx").read_text(encoding="utf-8")
AUTHENTICATED_APP = (REPO_ROOT / "ui" / "src" / "AuthenticatedApp.tsx").read_text(encoding="utf-8")
ONBOARDING = (REPO_ROOT / "ui" / "src" / "operatorConnectorOnboarding.tsx").read_text(encoding="utf-8")
CSS = (REPO_ROOT / "ui" / "src" / "headerPolish.css").read_text(encoding="utf-8")


class HeaderActionHierarchyTests(unittest.TestCase):
    def test_brand_is_home_navigation(self):
        self.assertIn('className="topbar-brand" href="#/"', APP)
        self.assertIn('aria-label="AWS Security Coach home"', APP)

    def test_connector_cta_changes_after_first_connector(self):
        self.assertIn("hasConnector={hasConnector}", AUTHENTICATED_APP)
        self.assertIn("setHasConnector(Boolean(nextSignature))", AUTHENTICATED_APP)
        self.assertIn('hasConnector ? "Add AWS Account" : "Connect AWS Account"', ONBOARDING)
        self.assertIn('hasConnector ? "button-secondary connector-onboarding-trigger"', ONBOARDING)

    def test_operator_management_lives_in_profile_menu(self):
        menu_start = AUTHENTICATED_APP.index('role="menu"')
        identity_start = AUTHENTICATED_APP.index('const identityControl =')
        operator_index = AUTHENTICATED_APP.index("<OperatorConnectorManagement")
        self.assertGreater(operator_index, menu_start)
        self.assertLess(operator_index, identity_start)
        identity_section = AUTHENTICATED_APP[identity_start:]
        self.assertNotIn("<OperatorConnectorManagement", identity_section)

    def test_header_actions_have_responsive_spacing(self):
        self.assertIn(".topbar-actions {", CSS)
        self.assertIn("flex-wrap: wrap", CSS)
        self.assertIn("gap: 10px", CSS)
        self.assertIn(".identity-controls {", CSS)


if __name__ == "__main__":
    unittest.main()
