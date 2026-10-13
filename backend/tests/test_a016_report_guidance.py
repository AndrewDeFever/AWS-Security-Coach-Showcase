import importlib.util
import pathlib
import unittest


MODULE_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "src"
    / "runner"
    / "report_guidance.py"
)
SPEC = importlib.util.spec_from_file_location("report_guidance", MODULE_PATH)
report_guidance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report_guidance)


EXPECTED_CHECK_IDS = {
    "iam-root-mfa-enabled",
    "iam-root-access-keys-absent",
    "iam-users-mfa",
    "iam-unused-access-keys",
    "iam-old-access-keys",
    "iam-account-password-policy",
    "cloudtrail-multi-region",
    "s3-account-public-access-block",
    "ec2-security-groups-open-admin-ports",
}


class A016ReportGuidanceTests(unittest.TestCase):
    def test_all_nine_baseline_checks_have_exactly_one_guidance_mapping(self):
        self.assertEqual(set(report_guidance.GUIDANCE_BY_CHECK_ID), EXPECTED_CHECK_IDS)

    def test_every_mapping_has_customer_report_fields_and_first_party_aws_reference(self):
        required = {
            "awsSecurityArea",
            "awsDesignPrinciple",
            "awsBestPracticeContext",
            "customerRisk",
            "remediationEffort",
            "remediation",
            "verificationCriteria",
            "awsReference",
        }
        allowed_areas = {
            "Identity and access management",
            "Detection",
            "Data protection",
            "Infrastructure protection",
        }

        for check_id, guidance in report_guidance.GUIDANCE_BY_CHECK_ID.items():
            self.assertEqual(set(guidance), required, check_id)
            self.assertIn(guidance["awsSecurityArea"], allowed_areas, check_id)
            self.assertIn(guidance["remediationEffort"], {"LOW", "MEDIUM", "HIGH"}, check_id)
            self.assertTrue(guidance["awsBestPracticeContext"].strip(), check_id)
            self.assertTrue(guidance["customerRisk"].strip(), check_id)
            self.assertTrue(guidance["remediation"].strip(), check_id)
            self.assertTrue(guidance["verificationCriteria"].strip(), check_id)
            reference = guidance["awsReference"]
            self.assertTrue(reference["title"].strip(), check_id)
            self.assertTrue(
                reference["url"].startswith("https://docs.aws.amazon.com/"),
                check_id,
            )

    def test_assessment_profile_uses_bounded_well_architected_language(self):
        profile = report_guidance.build_assessment_profile(9)

        self.assertEqual(profile["title"], "AWS Security Posture Review")
        self.assertEqual(profile["assessmentType"], "point-in-time")
        self.assertEqual(profile["accessModel"], "read-only")
        self.assertEqual(profile["controlCount"], 9)
        self.assertEqual(profile["frameworkContext"]["pillar"], "Security")
        self.assertEqual(
            profile["frameworkDisclaimer"],
            "This is NOT a complete AWS Well-Architected Review.",
        )
        self.assertIn("selected foundational AWS security controls", profile["scopeStatement"])
        self.assertNotIn("certified", str(profile).lower())
        self.assertNotIn("passed well-architected", str(profile).lower())

    def test_enrichment_preserves_original_finding_and_adds_guidance(self):
        original = {
            "id": "cloudtrail-multi-region",
            "title": "CloudTrail multi-region trail is not enabled",
            "status": "FAIL",
            "severity": "HIGH",
            "details": "No multi-region CloudTrail trail was detected.",
        }

        enriched = report_guidance.enrich_findings([original])[0]

        for key, value in original.items():
            self.assertEqual(enriched[key], value)
        self.assertNotIn("guidance", original)
        self.assertEqual(enriched["guidance"]["awsSecurityArea"], "Detection")
        self.assertEqual(enriched["guidance"]["awsDesignPrinciple"], "Maintain traceability")

    def test_unknown_check_fails_closed_for_customer_report_mapping(self):
        with self.assertRaises(report_guidance.GuidanceMappingError):
            report_guidance.enrich_findings(
                [
                    {
                        "id": "future-unmapped-check",
                        "title": "Future check",
                        "status": "PASS",
                        "severity": "INFO",
                        "details": "Not yet mapped.",
                    }
                ]
            )


if __name__ == "__main__":
    unittest.main()
