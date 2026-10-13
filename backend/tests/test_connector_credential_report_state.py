import importlib.util
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "runner" / "connector_validation.py"
spec = importlib.util.spec_from_file_location("connector_credential_report_state_test", MODULE_PATH)
connector_validation = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(connector_validation)


class AwsError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeIam:
    def __init__(self, report_error):
        self.report_error = report_error

    def generate_credential_report(self):
        return {"State": "STARTED"}

    def get_credential_report(self):
        raise self.report_error

    def get_account_summary(self):
        return {}

    def list_users(self, **_kwargs):
        return {"Users": []}

    def list_mfa_devices(self, **_kwargs):
        return {"MFADevices": []}

    def get_account_password_policy(self):
        raise AwsError("NoSuchEntity")


class FakeCloudTrail:
    def describe_trails(self, **_kwargs):
        return {"trailList": []}


class FakeS3Control:
    def get_public_access_block(self, **_kwargs):
        raise AwsError("NoSuchPublicAccessBlockConfiguration")


class FakeEc2:
    def describe_regions(self, **_kwargs):
        return {"Regions": [{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}]}

    def describe_security_groups(self, **_kwargs):
        return {"SecurityGroups": []}


class ConnectorCredentialReportStateTests(unittest.TestCase):
    def validate_permissions(self, report_error):
        clients = {
            "iam": FakeIam(report_error),
            "cloudtrail": FakeCloudTrail(),
            "s3control": FakeS3Control(),
            "ec2": FakeEc2(),
        }
        with mock.patch.object(connector_validation, "_client", side_effect=lambda service, *_args: clients[service]):
            connector_validation._validate_permissions(
                {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"},
                "us-east-1",
                "123456789012",
            )

    def test_report_in_progress_is_accepted_as_async_success_state(self):
        self.validate_permissions(AwsError("ReportInProgress"))

    def test_get_credential_report_access_denied_still_fails_closed(self):
        with self.assertRaises(AwsError) as raised:
            self.validate_permissions(AwsError("AccessDenied"))
        self.assertEqual(raised.exception.response["Error"]["Code"], "AccessDenied")


if __name__ == "__main__":
    unittest.main()
