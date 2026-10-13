import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
UI = REPO_ROOT / "ui" / "src"
APP = (UI / "App.tsx").read_text(encoding="utf-8")
REPORT_PAGE = (UI / "ScanReportPage.tsx").read_text(encoding="utf-8")
DELIVERY = (UI / "reportDelivery.ts").read_text(encoding="utf-8")
MANAGED_MANAGEMENT = (UI / "ManagedManagementReport.tsx").read_text(encoding="utf-8")
SUBSCRIBER_MANAGEMENT = (UI / "SubscriberManagementReport.tsx").read_text(encoding="utf-8")
GUIDANCE = (REPO_ROOT / "backend" / "src" / "runner" / "report_guidance.py").read_text(encoding="utf-8")


class A016ReportPageTests(unittest.TestCase):
    def test_scan_dashboard_uses_delivery_specific_report_routes(self):
        self.assertIn("reportRoute(reportScanId, deliveryModel, \"management\")", APP)
        self.assertIn("reportRoute(reportScanId, deliveryModel, \"engineering\")", APP)
        self.assertIn('deliveryModel === "managed" ? "Customer Reports" : "Your Reports"', APP)

    def test_four_route_shapes_and_legacy_managed_aliases_exist(self):
        self.assertIn("managed|self-service", DELIVERY)
        self.assertIn("management|engineering", DELIVERY)
        self.assertIn('deliveryModel: "managed"', DELIVERY)
        self.assertIn("parseReportRoute", REPORT_PAGE)

    def test_report_page_refetches_authorized_report_by_scan_id(self):
        self.assertIn("/auth/report/${encodeURIComponent(route.scanId)}", REPORT_PAGE)
        self.assertIn('Authorization: `Bearer ${accessToken}`', REPORT_PAGE)
        self.assertIn("You are not authorized to view this report.", REPORT_PAGE)

    def test_report_page_selects_four_distinct_renderers(self):
        for component in (
            "ManagedManagementReport",
            "ManagedEngineeringReport",
            "SubscriberManagementReport",
            "SubscriberEngineeringReport",
        ):
            self.assertIn(component, REPORT_PAGE)

    def test_managed_management_is_consulting_facing(self):
        self.assertIn("What we observed:", MANAGED_MANAGEMENT)
        self.assertIn("Why this matters", MANAGED_MANAGEMENT)
        self.assertIn("Recommended action:", MANAGED_MANAGEMENT)
        self.assertIn("contact your assessment provider", MANAGED_MANAGEMENT)
        self.assertNotIn("AWS Security Coach", MANAGED_MANAGEMENT)

    def test_subscriber_management_is_product_native(self):
        self.assertIn("AWS Security Coach", SUBSCRIBER_MANAGEMENT)
        self.assertIn("run a new assessment", SUBSCRIBER_MANAGEMENT)
        self.assertIn("Open Engineering Report", SUBSCRIBER_MANAGEMENT)

    def test_password_policy_risk_is_specific_without_claiming_compromise(self):
        self.assertIn("password spraying", GUIDANCE)
        self.assertIn("credential-reuse attacks", GUIDANCE)
        self.assertIn("does not mean an account has been compromised", GUIDANCE)


if __name__ == "__main__":
    unittest.main()
