import importlib.util
import pathlib
import sys
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER_DIR = REPO_ROOT / "backend" / "src" / "runner"
UI_DIR = REPO_ROOT / "ui" / "src"
if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))

SPEC = importlib.util.spec_from_file_location("engineering_enrichment", RUNNER_DIR / "engineering_enrichment.py")
engineering_enrichment = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(engineering_enrichment)

MANAGED_POLICY = (UI_DIR / "managedReportPolicy.ts").read_text(encoding="utf-8")
MANAGED_PDF = (UI_DIR / "managedPdf.ts").read_text(encoding="utf-8")
MANAGED_ENGINEERING = (UI_DIR / "ManagedEngineeringReport.tsx").read_text(encoding="utf-8")
SUBSCRIBER_ENGINEERING = (UI_DIR / "SubscriberEngineeringReport.tsx").read_text(encoding="utf-8")
MANAGED_MANAGEMENT = (UI_DIR / "ManagedManagementReport.tsx").read_text(encoding="utf-8")
REPORT_PAGE = (UI_DIR / "ScanReportPage.tsx").read_text(encoding="utf-8")
MANAGED_ASSESSMENT = (UI_DIR / "operatorManagedAssessment.tsx").read_text(encoding="utf-8")


def base_finding(check_id: str) -> dict:
    return {
        "id": check_id,
        "title": check_id,
        "status": "FAIL",
        "severity": "HIGH",
        "details": "test observation",
        "guidance": {
            "verificationCriteria": "Rerun the assessment",
        },
    }


class A016FinalCorrectnessTests(unittest.TestCase):
    def test_all_nine_controls_use_concrete_aws_end_states(self):
        self.assertEqual(len(engineering_enrichment.AWS_END_STATE_BY_CHECK_ID), 9)
        for check_id, criteria in engineering_enrichment.AWS_END_STATE_BY_CHECK_ID.items():
            self.assertTrue(criteria.strip(), check_id)
            self.assertNotIn("Rerun", criteria, check_id)
            self.assertNotIn("Security Coach", criteria, check_id)

    def test_password_policy_cli_is_not_presented_as_a_partial_update(self):
        finding = engineering_enrichment.enrich_engineering_guidance([
            base_finding("iam-account-password-policy")
        ])[0]
        runbook = finding["guidance"]["engineeringRemediation"]
        self.assertEqual(
            runbook["cliCommands"],
            [{
                "label": "Inspect the complete current IAM password policy before any CLI update",
                "command": "aws iam get-account-password-policy",
            }],
        )
        caution_text = " ".join(runbook["cautions"])
        self.assertIn("does not support partial updates", caution_text)
        self.assertIn("omitted from an update reverts to its AWS default value", caution_text)
        self.assertNotIn("finding evidence", " ".join(runbook["steps"]).lower())

    def test_cli_is_retained_only_where_it_adds_useful_engineering_value(self):
        cloudtrail = engineering_enrichment.enrich_engineering_guidance([
            base_finding("cloudtrail-multi-region")
        ])[0]["guidance"]["engineeringRemediation"]["cliCommands"]
        password = engineering_enrichment.enrich_engineering_guidance([
            base_finding("iam-account-password-policy")
        ])[0]["guidance"]["engineeringRemediation"]["cliCommands"]
        s3 = engineering_enrichment.enrich_engineering_guidance([
            base_finding("s3-account-public-access-block")
        ])[0]["guidance"]["engineeringRemediation"]["cliCommands"]

        self.assertEqual(len(cloudtrail), 2)
        self.assertIn("update-trail", cloudtrail[0]["command"])
        self.assertIn("start-logging", cloudtrail[1]["command"])
        self.assertEqual(password[0]["command"], "aws iam get-account-password-policy")
        self.assertFalse(any("update-account-password-policy" in item["command"] for item in password))
        self.assertEqual(len(s3), 1)
        self.assertIn("put-public-access-block", s3[0]["command"])

    def test_engineering_reports_are_console_first_and_cli_is_advanced_optional(self):
        for source in (MANAGED_ENGINEERING, SUBSCRIBER_ENGINEERING, MANAGED_PDF):
            self.assertIn("Advanced / Optional CLI", source)
            self.assertIn("AWS Console procedure", source)
            self.assertIn("recommended default", source)
            self.assertIn("expected configuration impact", source)
        self.assertNotIn("AWS CLI alternative", MANAGED_ENGINEERING)
        self.assertNotIn("AWS CLI alternative", SUBSCRIBER_ENGINEERING)
        self.assertNotIn('pdf.section("AWS CLI alternative"', MANAGED_PDF)

    def test_engineering_reports_use_important_considerations_with_spacing(self):
        for source in (MANAGED_ENGINEERING, SUBSCRIBER_ENGINEERING, MANAGED_PDF):
            self.assertIn("Important considerations", source)
            self.assertNotIn("Change cautions", source)
        self.assertIn('join("\\n\\n")', MANAGED_PDF)
        self.assertIn("marginTop: 14", MANAGED_ENGINEERING)
        self.assertIn("marginTop: 14", SUBSCRIBER_ENGINEERING)

    def test_s3_runbook_does_not_claim_unrendered_finding_evidence(self):
        finding = engineering_enrichment.enrich_engineering_guidance([
            base_finding("s3-account-public-access-block")
        ])[0]
        runbook = finding["guidance"]["engineeringRemediation"]
        self.assertNotIn("finding evidence", " ".join(runbook["steps"]).lower())
        self.assertIn("four effective account-level Block Public Access settings", runbook["steps"][0])

    def test_cloudtrail_distinguishes_assessed_state_from_hardening_without_duplicate_boundary(self):
        finding = engineering_enrichment.enrich_engineering_guidance([
            base_finding("cloudtrail-multi-region")
        ])[0]
        guidance = finding["guidance"]
        self.assertEqual(
            guidance["verificationCriteria"],
            "At least one CloudTrail trail is configured as a multi-Region trail.",
        )
        prerequisites = guidance["engineeringRemediation"]["prerequisites"]
        boundary_lines = [line for line in prerequisites if "multi-Region trail presence only" in line]
        self.assertEqual(len(boundary_lines), 1)
        runbook_text = " ".join(
            prerequisites + guidance["engineeringRemediation"]["verificationSteps"]
        )
        self.assertIn("verifies multi-Region trail presence only", runbook_text)
        self.assertIn("not verified by the current assessment control", runbook_text)

    def test_managed_reports_state_provider_contact_follow_up_and_severity_model(self):
        self.assertIn('MANAGED_ASSESSMENT_PROVIDER = "Example Security Provider"', MANAGED_POLICY)
        self.assertIn("Configure the customer contact method", MANAGED_POLICY)
        self.assertIn("Configure the customer contact method", MANAGED_POLICY)
        self.assertIn("included at no additional cost", MANAGED_POLICY)
        self.assertIn("AWS Security Hub terminology", MANAGED_POLICY)
        self.assertIn("assigns each finding's severity deterministically from its own ruleset", MANAGED_POLICY)
        self.assertIn("not imported from Security Hub", MANAGED_POLICY)
        self.assertIn("not an AWS-assigned severity", MANAGED_POLICY)
        self.assertIn("INFORMATIONAL", MANAGED_POLICY)
        self.assertIn("abbreviate INFORMATIONAL as INFO", MANAGED_POLICY)
        self.assertIn("prepareManagedReport", REPORT_PAGE)

    def test_managed_pdf_renders_service_clarity_and_long_region_scope_outside_metric_card(self):
        self.assertIn("MANAGED_ASSESSMENT_PROVIDER", MANAGED_PDF)
        self.assertIn("MANAGED_ASSESSMENT_CONTACT", MANAGED_PDF)
        self.assertIn("MANAGED_FOLLOW_UP", MANAGED_PDF)
        self.assertIn("MANAGED_SEVERITY_EXPLANATION", MANAGED_PDF)
        self.assertIn('pdf.callout("Assessment provider & contact", providerContact()', MANAGED_PDF)
        self.assertIn('pdf.callout("Included follow-up verification", MANAGED_FOLLOW_UP', MANAGED_PDF)
        self.assertIn('pdf.callout("Severity model", MANAGED_SEVERITY_EXPLANATION', MANAGED_PDF)
        self.assertEqual(MANAGED_PDF.count('pdf.labeledParagraph("Region scope", regionScope(report))'), 1)
        self.assertNotIn('{ label: "Region scope", value: regionScope(report) }', MANAGED_PDF)

    def test_management_report_is_executive_and_does_not_expose_methodology_noise(self):
        self.assertIn("Scope & Next Step", MANAGED_MANAGEMENT)
        self.assertNotIn("Ruleset version", MANAGED_MANAGEMENT)
        self.assertNotIn("Controls in ruleset", MANAGED_MANAGEMENT)
        self.assertNotIn("Severity model", MANAGED_MANAGEMENT)
        management_pdf = MANAGED_PDF.split("function addManagementPdf", 1)[1].split("function addFindingPdf", 1)[0]
        self.assertIn('pdf.heading("Scope & Next Step"', management_pdf)
        self.assertNotIn('pdf.callout("Severity model"', management_pdf)
        self.assertNotIn('pdf.labeledParagraph("Ruleset"', management_pdf)
        self.assertNotIn('pdf.labeledParagraph("Region scope"', management_pdf)
        self.assertIn("frameworkDisclaimer", management_pdf)

    def test_managed_pdfs_have_customer_facing_cover_pages(self):
        self.assertIn("function coverPage", MANAGED_PDF)
        self.assertEqual(MANAGED_PDF.count("coverPage(pdf, report"), 2)
        self.assertIn("AWS SECURITY POSTURE REVIEW", MANAGED_PDF)
        self.assertIn("Point-in-time, read-only AWS security posture assessment", MANAGED_PDF)

    def test_handoff_has_explicit_cloudformation_actions_and_region_boundary(self):
        self.assertIn("Open AWS CloudFormation", MANAGED_ASSESSMENT)
        self.assertIn("Copy AWS Link", MANAGED_ASSESSMENT)
        self.assertIn("Copy External ID", MANAGED_ASSESSMENT)
        self.assertIn("Refresh AWS Link", MANAGED_ASSESSMENT)
        self.assertIn("Copy Customer Instructions", MANAGED_ASSESSMENT)
        self.assertIn("CloudFormation stack Region", MANAGED_ASSESSMENT)
        self.assertIn("setup/lifecycle location only", MANAGED_ASSESSMENT)
        self.assertIn("does not limit the assessment's AWS Region coverage", MANAGED_ASSESSMENT)
        self.assertNotIn("scan/security-group Region", MANAGED_ASSESSMENT)


if __name__ == "__main__":
    unittest.main()
