import importlib.util
import os
import pathlib
import sys
import unittest


RUNNER_PATH = pathlib.Path(__file__).resolve().parents[1] / "src" / "runner"
MODULE_PATH = RUNNER_PATH / "report_v1.py"
if str(RUNNER_PATH) not in sys.path:
    sys.path.insert(0, str(RUNNER_PATH))
SPEC = importlib.util.spec_from_file_location("runner_report_v1", MODULE_PATH)
report_v1 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report_v1)


class RunnerReportV1Tests(unittest.TestCase):
    def setUp(self):
        os.environ["HOME_REGION"] = "us-east-1"
        self.findings = [
            {"id": "iam-root-mfa-enabled", "title": "Root MFA not applicable", "status": "NOT_APPLICABLE", "severity": "INFO", "details": "Root sign-in credentials are not present."},
            {"id": "iam-root-access-keys-absent", "title": "Passing check", "status": "PASS", "severity": "INFO", "details": "The check passed."},
            {"id": "cloudtrail-multi-region", "title": "Failing check", "status": "FAIL", "severity": "HIGH", "details": "The check found a condition requiring attention."},
            {"id": "iam-unused-access-keys", "title": "Advisory check", "status": "WARN", "severity": "LOW", "details": "The evaluation completed with an advisory result."},
            {"id": "s3-account-public-access-block", "title": "Evaluation error", "status": "ERROR", "severity": "LOW", "details": "The check could not be evaluated reliably."},
        ]

    def legacy_report(self):
        return {
            "schemaVersion": "2026-03-29",
            "generatedAt": "2026-08-02T19:02:41.650142Z",
            "scan": {"scanId": "11111111-2222-3333-4444-555555555555", "targetType": "tool-account", "targetId": "123456789012"},
            "summary": {"findingCount": len(self.findings)},
            "rulesStub": [],
            "findings": self.findings,
        }

    def test_builds_valid_v1_envelope_without_private_account_identity(self):
        report = report_v1.build_v1_report(self.legacy_report())
        self.assertEqual(report["schemaVersion"], "1.0")
        self.assertEqual(report["deliveryModel"], "managed")
        self.assertEqual(report["scan"]["status"], "COMPLETE")
        self.assertEqual(report["target"]["type"], "tool-account")
        self.assertEqual(report["target"]["accountRef"], "configured-account")
        self.assertEqual(report["target"]["regionScope"], ["us-east-1"])
        self.assertNotIn("targetId", report["target"])
        self.assertNotIn("connectorId", report["target"])
        self.assertNotIn("123456789012", str(report["target"]))
        report_v1.validate_v1_report(report)

    def test_connector_report_stamps_opaque_identity_and_resolved_versions(self):
        legacy = self.legacy_report()
        legacy["connectorContext"] = {"connectorId": "con_1234", "templateVersion": "1.0.0", "connectorVersion": "1.0"}
        report = report_v1.build_v1_report(legacy)
        self.assertEqual(report["target"], {"type": "connector", "accountRef": "connected-account", "connectorId": "con_1234", "templateVersion": "1.0.0", "connectorVersion": "1.0", "regionScope": ["us-east-1"]})
        self.assertNotIn("roleArn", str(report))
        self.assertNotIn("externalId", str(report))
        self.assertNotIn("expectedAccountId", str(report))
        report_v1.validate_v1_report(report)

    def test_managed_customer_identity_is_separate_from_sanitized_target(self):
        legacy = self.legacy_report()
        legacy["connectorContext"] = {"connectorId": "con_1234", "templateVersion": "1.0.0", "connectorVersion": "1.0"}
        legacy["managedCustomerContext"] = {"organization": "Acme Corporation", "awsAccountId": "123456789012"}
        report = report_v1.build_v1_report(legacy)
        self.assertEqual(report["customer"], {"organization": "Acme Corporation", "awsAccountId": "123456789012"})
        self.assertEqual(report["target"]["accountRef"], "connected-account")
        self.assertNotIn("123456789012", str(report["target"]))

    def test_self_service_report_does_not_emit_managed_customer_identity(self):
        legacy = self.legacy_report()
        legacy["reportDeliveryModel"] = "self-service"
        legacy["managedCustomerContext"] = {"organization": "Should Not Render", "awsAccountId": "123456789012"}
        report = report_v1.build_v1_report(legacy)
        self.assertNotIn("customer", report)

    def test_connector_report_rejects_incomplete_version_context(self):
        legacy = self.legacy_report()
        legacy["connectorContext"] = {"connectorId": "con_1234", "templateVersion": "1.0.0"}
        with self.assertRaises(report_v1.ReportEmissionError):
            report_v1.build_v1_report(legacy)

    def test_summary_is_derived_from_findings_and_excludes_not_applicable_from_evaluated(self):
        report = report_v1.build_v1_report(self.legacy_report())
        self.assertEqual(report["summary"], {"total": 5, "evaluated": 4, "passed": 1, "failed": 1, "warnings": 1, "errors": 1, "notApplicable": 1})
        self.assertEqual(report["ruleset"]["checkCount"], 5)
        self.assertEqual(report["ruleset"]["version"], "1.1")

    def test_existing_outcome_fields_are_preserved_and_guidance_is_additive(self):
        legacy = self.legacy_report()
        report = report_v1.build_v1_report(legacy)
        self.assertEqual([finding["status"] for finding in report["findings"]], ["NOT_APPLICABLE", "PASS", "FAIL", "WARN", "ERROR"])
        for original, enriched in zip(legacy["findings"], report["findings"], strict=True):
            for key in ("id", "title", "status", "severity", "details"):
                self.assertEqual(enriched[key], original[key])
            self.assertIn("guidance", enriched)
            self.assertNotIn("guidance", original)

    def test_assessment_profile_is_bounded_and_customer_facing(self):
        report = report_v1.build_v1_report(self.legacy_report())
        assessment = report["assessment"]
        self.assertEqual(assessment["title"], "AWS Security Posture Review")
        self.assertEqual(assessment["assessmentType"], "point-in-time")
        self.assertEqual(assessment["accessModel"], "read-only")
        self.assertEqual(assessment["frameworkDisclaimer"], "This is NOT a complete AWS Well-Architected Review.")
        self.assertEqual(assessment["controlCount"], 5)
        self.assertEqual(assessment["frameworkContext"]["pillar"], "Security")

    def test_rejects_invalid_status_before_storage(self):
        legacy = self.legacy_report()
        legacy["findings"][0]["status"] = "UNKNOWN"
        with self.assertRaises(report_v1.ReportEmissionError):
            report_v1.build_v1_report(legacy)

    def test_rejects_invalid_managed_customer_account_id(self):
        legacy = self.legacy_report()
        legacy["managedCustomerContext"] = {"organization": "Acme Corporation", "awsAccountId": "123"}
        with self.assertRaises(report_v1.ReportEmissionError):
            report_v1.build_v1_report(legacy)

    def test_rejects_missing_scan_id_before_storage(self):
        legacy = self.legacy_report()
        legacy["scan"]["scanId"] = None
        with self.assertRaises(report_v1.ReportEmissionError):
            report_v1.build_v1_report(legacy)

    def test_authoritative_template_uses_v1_runner_handler(self):
        template_path = pathlib.Path(__file__).resolve().parents[1] / "template.yaml"
        template = template_path.read_text(encoding="utf-8")
        runner_section = template.split("  RunnerFunction:", 1)[1].split("  RunnerSweeperSchedule:", 1)[0]
        self.assertIn("Handler: v1_handler.lambda_handler", runner_section)


if __name__ == "__main__":
    unittest.main()
