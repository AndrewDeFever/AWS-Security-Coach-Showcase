import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "src" / "runner" / "root_mfa_rule.py"
SPEC = importlib.util.spec_from_file_location("root_mfa_rule", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RootMfaRuleTests(unittest.TestCase):
    def test_static_descriptor_is_bounded(self):
        self.assertEqual(
            MODULE.RULE,
            {
                "id": "iam-root-mfa-enabled",
                "service": "iam",
                "control": "root-mfa",
                "version": "1.1",
            },
        )

    def test_root_credentials_removed_is_not_applicable(self):
        result = MODULE.evaluate(None, [{"user": "<root_account>", "password_enabled": "FALSE", "mfa_active": "FALSE"}])
        self.assertEqual(result["status"], "NOT_APPLICABLE")
        self.assertEqual(result["severity"], "INFO")
        self.assertIn("do not recreate root credentials", result["details"])

    def test_root_password_present_with_mfa_passes(self):
        result = MODULE.evaluate(None, [{"user": "<root_account>", "password_enabled": "TRUE", "mfa_active": "TRUE"}])
        self.assertEqual(result["status"], "PASS")
        self.assertIn("sign-in credentials are present", result["details"])

    def test_root_password_present_without_mfa_fails(self):
        result = MODULE.evaluate(None, [{"user": "<root_account>", "password_enabled": "TRUE", "mfa_active": "FALSE"}])
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["severity"], "HIGH")
        self.assertIn("does not have MFA enabled", result["details"])

    def test_missing_root_row_is_error_not_assumption(self):
        result = MODULE.evaluate(None, [{"user": "alice", "password_enabled": "TRUE", "mfa_active": "TRUE"}])
        self.assertEqual(result["status"], "ERROR")
        self.assertIn("root account row", result["details"])

    def test_unavailable_root_credential_field_is_error(self):
        result = MODULE.evaluate(None, [{"user": "<root_account>", "password_enabled": "N/A", "mfa_active": "FALSE"}])
        self.assertEqual(result["status"], "ERROR")
        self.assertIn("password_enabled", result["details"])


if __name__ == "__main__":
    unittest.main()
