import importlib.util
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "runner" / "connector_validation.py"
spec = importlib.util.spec_from_file_location("connector_validation_retry_test", MODULE_PATH)
connector_validation = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(connector_validation)


ROLE_ARN = "arn:aws:iam::123456789012:role/aws-security-coach/test-role"
SESSION_NAME = "aws-security-coach-validate-test"
EXTERNAL_ID = "a" * 64


class AwsError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeSts:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def assume_role(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


SUCCESS = {
    "Credentials": {
        "AccessKeyId": "AKIAEXAMPLE",
        "SecretAccessKey": "secret",
        "SessionToken": "token",
    }
}


class ConnectorValidationRetryTests(unittest.TestCase):
    def call(self, sts):
        return connector_validation._assume_role_with_propagation_retry(
            sts,
            role_arn=ROLE_ARN,
            session_name=SESSION_NAME,
            external_id=EXTERNAL_ID,
        )

    def test_first_access_denied_retries_after_five_seconds_then_succeeds(self):
        sts = FakeSts([AwsError("AccessDenied"), SUCCESS])
        with mock.patch.object(connector_validation.time, "sleep") as sleep:
            result = self.call(sts)
        self.assertIs(result, SUCCESS)
        self.assertEqual(len(sts.calls), 2)
        sleep.assert_called_once_with(5)

    def test_two_access_denied_errors_retry_twice_then_succeed(self):
        sts = FakeSts([
            AwsError("AccessDenied"),
            AwsError("AccessDeniedException"),
            SUCCESS,
        ])
        with mock.patch.object(connector_validation.time, "sleep") as sleep:
            result = self.call(sts)
        self.assertIs(result, SUCCESS)
        self.assertEqual(len(sts.calls), 3)
        self.assertEqual(sleep.call_args_list, [mock.call(5), mock.call(5)])

    def test_three_access_denied_errors_fail_only_after_final_attempt(self):
        sts = FakeSts([
            AwsError("AccessDenied"),
            AwsError("AccessDenied"),
            AwsError("AccessDenied"),
        ])
        with mock.patch.object(connector_validation.time, "sleep") as sleep:
            with self.assertRaises(AwsError):
                self.call(sts)
        self.assertEqual(len(sts.calls), 3)
        self.assertEqual(sleep.call_args_list, [mock.call(5), mock.call(5)])

    def test_no_such_entity_fails_immediately_without_retry(self):
        sts = FakeSts([AwsError("NoSuchEntity")])
        with mock.patch.object(connector_validation.time, "sleep") as sleep:
            with self.assertRaises(AwsError):
                self.call(sts)
        self.assertEqual(len(sts.calls), 1)
        sleep.assert_not_called()

    def test_unrelated_error_fails_immediately_without_retry(self):
        sts = FakeSts([AwsError("ThrottlingException")])
        with mock.patch.object(connector_validation.time, "sleep") as sleep:
            with self.assertRaises(AwsError):
                self.call(sts)
        self.assertEqual(len(sts.calls), 1)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
