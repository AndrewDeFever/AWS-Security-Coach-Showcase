import contextlib
import importlib.util
import io
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "runner" / "connector_validation.py"
spec = importlib.util.spec_from_file_location(
    "connector_validation_diagnostics_test",
    MODULE_PATH,
)
connector_validation = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(connector_validation)


class AwsLikeError(RuntimeError):
    def __init__(self, code: str, secret_message: str):
        super().__init__(secret_message)
        self.response = {"Error": {"Code": code, "Message": secret_message}}


class ConnectorValidationDiagnosticsTests(unittest.TestCase):
    def test_unexpected_probe_failure_logs_only_probe_name_and_error_code(self):
        output = io.StringIO()

        def failing_call():
            raise AwsLikeError("AccessDenied", "sensitive raw AWS message")

        with contextlib.redirect_stdout(output):
            with self.assertRaises(AwsLikeError):
                connector_validation._probe(
                    "ec2.describe_security_groups",
                    failing_call,
                )

        logged = output.getvalue()
        self.assertIn(
            "CONNECTOR PERMISSION PROBE FAILED: probe=ec2.describe_security_groups errorCode=AccessDenied",
            logged,
        )
        self.assertNotIn("sensitive raw AWS message", logged)
        self.assertNotIn("AccessKeyId", logged)
        self.assertNotIn("SecretAccessKey", logged)
        self.assertNotIn("SessionToken", logged)
        self.assertNotIn("ExternalId", logged)

    def test_accepted_probe_error_is_not_logged(self):
        output = io.StringIO()

        def expected_call():
            raise AwsLikeError("NoSuchEntity", "expected probe miss")

        with contextlib.redirect_stdout(output):
            connector_validation._probe(
                "iam.list_mfa_devices",
                expected_call,
                ("NoSuchEntity",),
            )

        self.assertEqual(output.getvalue(), "")

    def test_permission_checks_have_stable_diagnostic_probe_names(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        expected = (
            "iam.generate_credential_report",
            "iam.get_credential_report",
            "iam.get_account_summary",
            "iam.list_users",
            "iam.list_mfa_devices",
            "iam.get_account_password_policy",
            "cloudtrail.describe_trails",
            "s3control.get_public_access_block",
            "ec2.describe_security_groups",
        )
        for probe_name in expected:
            self.assertIn(f'"{probe_name}"', source)


if __name__ == "__main__":
    unittest.main()
