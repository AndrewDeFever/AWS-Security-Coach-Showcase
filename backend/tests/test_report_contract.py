import copy
import importlib.util
import json
import pathlib
import unittest


class ReportContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        backend_dir = pathlib.Path(__file__).resolve().parents[1]
        module_path = backend_dir / "src" / "report_contract.py"
        spec = importlib.util.spec_from_file_location("report_contract", module_path)
        cls.contract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.contract)
        cls.fixtures_dir = pathlib.Path(__file__).resolve().parent / "fixtures"

    def fixture(self, name):
        with (self.fixtures_dir / name).open(encoding="utf-8") as handle:
            return json.load(handle)

    def test_all_v1_fixtures_validate(self):
        for name in (
            "report_v1_clean.json",
            "report_v1_fail.json",
            "report_v1_warn.json",
            "report_v1_error.json",
        ):
            with self.subTest(name=name):
                report = self.fixture(name)
                self.assertEqual(self.contract.validate_report(report), "v1")

    def test_legacy_unversioned_report_uses_legacy_path(self):
        report = self.fixture("report_legacy_unversioned.json")
        self.assertEqual(self.contract.validate_report(report), "legacy")

    def test_summary_is_derived_from_findings(self):
        findings = [
            {"status": "PASS"},
            {"status": "FAIL"},
            {"status": "WARN"},
            {"status": "ERROR"},
            {"status": "PASS"},
        ]
        self.assertEqual(
            self.contract.derive_summary(findings),
            {"total": 5, "passed": 2, "failed": 1, "warnings": 1, "errors": 1},
        )

    def test_invalid_status_is_rejected(self):
        report = self.fixture("report_v1_clean.json")
        report["findings"][0]["status"] = "UNKNOWN"
        with self.assertRaises(self.contract.ReportContractError):
            self.contract.validate_v1_report(report)

    def test_authored_summary_drift_is_rejected(self):
        report = self.fixture("report_v1_fail.json")
        report["summary"]["passed"] = 1
        with self.assertRaises(self.contract.ReportContractError):
            self.contract.validate_v1_report(report)

    def test_missing_finding_field_is_rejected(self):
        report = self.fixture("report_v1_clean.json")
        del report["findings"][0]["details"]
        with self.assertRaises(self.contract.ReportContractError):
            self.contract.validate_v1_report(report)

    def test_unknown_additive_fields_are_allowed(self):
        report = copy.deepcopy(self.fixture("report_v1_clean.json"))
        report["futureOptionalField"] = {"ignored": True}
        report["findings"][0]["metadata"] = {"source": "fixture"}
        self.contract.validate_v1_report(report)

    def test_private_account_identifier_is_not_required(self):
        report = self.fixture("report_v1_clean.json")
        serialized = json.dumps(report)
        self.assertEqual(report["target"]["accountRef"], "configured-account")
        self.assertNotIn("accountId", report["target"])
        self.assertNotIn("123456789012", serialized)


if __name__ == "__main__":
    unittest.main()
