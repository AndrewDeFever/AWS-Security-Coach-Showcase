import importlib.util
import pathlib
import sys
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER_DIR = REPO_ROOT / "backend" / "src" / "runner"
UI_DIR = REPO_ROOT / "ui" / "src"
if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))
SPEC = importlib.util.spec_from_file_location("engineering_guidance", RUNNER_DIR / "engineering_guidance.py")
engineering_guidance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(engineering_guidance)

EXPECTED_CHECK_IDS = {
    "iam-root-mfa-enabled", "iam-root-access-keys-absent", "iam-users-mfa",
    "iam-unused-access-keys", "iam-old-access-keys", "iam-account-password-policy",
    "cloudtrail-multi-region", "s3-account-public-access-block", "ec2-security-groups-open-admin-ports",
}

APP = (UI_DIR / "App.tsx").read_text(encoding="utf-8")
REPORT_PAGE = (UI_DIR / "ScanReportPage.tsx").read_text(encoding="utf-8")
MANAGED_ENGINEERING = (UI_DIR / "ManagedEngineeringReport.tsx").read_text(encoding="utf-8")
SUBSCRIBER_ENGINEERING = (UI_DIR / "SubscriberEngineeringReport.tsx").read_text(encoding="utf-8")
REPORT_ADAPTER = (UI_DIR / "reportAdapter.ts").read_text(encoding="utf-8")
PRINT_CSS = (UI_DIR / "scanReportPage.css").read_text(encoding="utf-8")
REPORT_V1 = (RUNNER_DIR / "report_v1.py").read_text(encoding="utf-8")
V1_HANDLER = (RUNNER_DIR / "v1_handler.py").read_text(encoding="utf-8")


class A016EngineeringReportTests(unittest.TestCase):
    def test_all_nine_checks_have_complete_delivery_neutral_runbooks(self):
        mappings = engineering_guidance.ENGINEERING_REMEDIATION_BY_CHECK_ID
        self.assertEqual(set(mappings), EXPECTED_CHECK_IDS)
        required = {"objective", "consolePath", "prerequisites", "steps", "cliCommands", "cautions", "verificationSteps"}
        for check_id, runbook in mappings.items():
            self.assertEqual(set(runbook), required, check_id)
            self.assertTrue(runbook["objective"].strip(), check_id)
            self.assertTrue(runbook["consolePath"].strip(), check_id)
            self.assertGreaterEqual(len(runbook["prerequisites"]), 1, check_id)
            self.assertGreaterEqual(len(runbook["steps"]), 3, check_id)
            self.assertGreaterEqual(len(runbook["cautions"]), 1, check_id)
            self.assertGreaterEqual(len(runbook["verificationSteps"]), 2, check_id)
            self.assertNotIn("Rerun", " ".join(runbook["verificationSteps"]), check_id)
            self.assertNotIn("Security Coach", " ".join(runbook["verificationSteps"]), check_id)
            for command in runbook["cliCommands"]:
                self.assertEqual(set(command), {"label", "command"}, check_id)
                self.assertTrue(command["command"].startswith("aws "), check_id)
                if "<" in command["command"] or ">" in command["command"]:
                    self.assertIn("<", command["command"], check_id)
                    self.assertIn(">", command["command"], check_id)
                else:
                    self.assertEqual(command["command"], "aws iam get-account-password-policy", check_id)
                self.assertNotIn("AKIA", command["command"], check_id)

    def test_prerequisites_read_as_engineer_actions_or_conditions(self):
        action_prefixes = ("Confirm ", "Capture ", "Identify ", "Review ", "Use ", "Decide ", "Choose ", "Check ", "Keep ", "If ", "For each ")
        for check_id, runbook in engineering_guidance.ENGINEERING_REMEDIATION_BY_CHECK_ID.items():
            for prerequisite in runbook["prerequisites"]:
                self.assertTrue(prerequisite.startswith(action_prefixes), f"{check_id}: {prerequisite}")
        self.assertIn("Before you start", MANAGED_ENGINEERING)
        self.assertIn("Before you start", SUBSCRIBER_ENGINEERING)
        self.assertNotIn("Before you change anything", MANAGED_ENGINEERING)
        self.assertNotIn("Before you change anything", SUBSCRIBER_ENGINEERING)

    def test_high_risk_changes_include_operational_cautions(self):
        mappings = engineering_guidance.ENGINEERING_REMEDIATION_BY_CHECK_ID
        self.assertIn("Do not delete the old key", " ".join(mappings["iam-old-access-keys"]["cautions"]))
        self.assertIn("lock operators out", " ".join(mappings["ec2-security-groups-open-admin-ports"]["cautions"]))
        self.assertIn("break workloads", " ".join(mappings["s3-account-public-access-block"]["cautions"]))

    def test_audit_corrections_are_embedded_in_shared_runbooks(self):
        mappings = engineering_guidance.ENGINEERING_REMEDIATION_BY_CHECK_ID
        self.assertIn("console does not convert", " ".join(mappings["cloudtrail-multi-region"]["steps"]))
        self.assertIn("AWS Organizations", " ".join(mappings["s3-account-public-access-block"]["steps"] + mappings["s3-account-public-access-block"]["cautions"]))
        self.assertIn("next sign-in", " ".join(mappings["iam-account-password-policy"]["steps"] + mappings["iam-account-password-policy"]["cautions"]))
        self.assertIn("centralized root access", " ".join(mappings["iam-root-mfa-enabled"]["steps"] + mappings["iam-root-mfa-enabled"]["cautions"]))

    def test_password_policy_runbook_matches_current_baseline_and_safe_cli_boundary(self):
        runbook = engineering_guidance.ENGINEERING_REMEDIATION_BY_CHECK_ID["iam-account-password-policy"]
        text = " ".join(runbook["steps"])
        self.assertIn("at least 14", text)
        self.assertIn("does not prescribe a specific number of days", text)
        self.assertIn("password reuse prevention", text)
        self.assertEqual(runbook["cliCommands"], [{
            "label": "Inspect the complete current IAM password policy before any CLI update",
            "command": "aws iam get-account-password-policy",
        }])
        self.assertIn("does not support partial updates", " ".join(runbook["cautions"]))
        self.assertNotIn("finding evidence", text.lower())

    def test_v1_report_attaches_runbooks_delivery_model_and_not_applicable_status(self):
        self.assertIn("enrich_engineering_guidance(enrich_findings(raw_findings))", REPORT_V1)
        self.assertIn('"deliveryModel"', REPORT_V1)
        self.assertIn('"NOT_APPLICABLE"', REPORT_V1)
        self.assertIn("reportDeliveryModel", V1_HANDLER)
        self.assertIn("engineeringRemediation", REPORT_ADAPTER)
        self.assertIn('"NOT_APPLICABLE"', REPORT_ADAPTER)

    def test_managed_engineering_is_provider_verified_and_customer_identified(self):
        self.assertIn("Follow-up verification", MANAGED_ENGINEERING)
        self.assertIn("notify your assessment contact", MANAGED_ENGINEERING)
        self.assertNotIn("AWS Security Coach", MANAGED_ENGINEERING)
        self.assertIn("Customer / Organization", MANAGED_ENGINEERING)
        self.assertIn("AWS Account ID", MANAGED_ENGINEERING)
        self.assertIn("Not applicable appendix", MANAGED_ENGINEERING)

    def test_engineering_print_contract_starts_each_nonpassing_item_on_new_page(self):
        self.assertIn("engineering-print-page-start", MANAGED_ENGINEERING)
        self.assertIn("engineering-print-page-start", SUBSCRIBER_ENGINEERING)
        self.assertIn("engineering-appendix-page", MANAGED_ENGINEERING)
        self.assertIn("break-before: page", PRINT_CSS)
        self.assertIn("break-inside: avoid", PRINT_CSS)

    def test_subscriber_engineering_is_self_service(self):
        self.assertIn("AWS Security Coach", SUBSCRIBER_ENGINEERING)
        self.assertIn("Verify with AWS Security Coach", SUBSCRIBER_ENGINEERING)
        self.assertIn("run a new assessment", SUBSCRIBER_ENGINEERING)
        self.assertIn("Not applicable appendix", SUBSCRIBER_ENGINEERING)

    def test_scan_page_routes_to_both_engineering_experiences(self):
        self.assertIn("ManagedEngineeringReport", REPORT_PAGE)
        self.assertIn("SubscriberEngineeringReport", REPORT_PAGE)
        self.assertIn("reportRoute(reportScanId, deliveryModel, \"engineering\")", APP)


if __name__ == "__main__":
    unittest.main()
