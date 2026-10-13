import importlib.util
import os
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCAN_MODULE_PATH = ROOT / "src" / "scan" / "connector_management.py"
RUNNER_HANDLER = (ROOT / "src" / "runner" / "v1_handler.py").read_text(encoding="utf-8")
RUNNER_VALIDATION = (ROOT / "src" / "runner" / "connector_validation.py").read_text(encoding="utf-8")

spec = importlib.util.spec_from_file_location("connector_management_runner_test", SCAN_MODULE_PATH)
connector_management = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(connector_management)


class Payload:
    def __init__(self, raw: bytes):
        self.raw = raw

    def read(self):
        return self.raw


class FakeLambda:
    def __init__(self):
        self.calls = []

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        return {"StatusCode": 200, "Payload": Payload(b'{"ok": true, "accountId": "123456789012"}')}


class RunnerActivationBoundaryTests(unittest.TestCase):
    def test_scan_invokes_runner_with_connector_id_only(self):
        fake_lambda = FakeLambda()
        with mock.patch.dict(os.environ, {"RUNNER_FUNCTION_NAME": "aws-safety-coach-dev-runner"}, clear=False):
            with mock.patch.object(connector_management.boto3, "client", return_value=fake_lambda):
                result = connector_management._invoke_runner_validation(
                    "con_11111111-2222-4333-8444-555555555555"
                )

        self.assertTrue(result["ok"])
        self.assertEqual(len(fake_lambda.calls), 1)
        call = fake_lambda.calls[0]
        self.assertEqual(call["FunctionName"], "aws-safety-coach-dev-runner")
        self.assertEqual(call["InvocationType"], "RequestResponse")
        payload = call["Payload"].decode("utf-8")
        self.assertIn('"operation": "VALIDATE_CONNECTOR"', payload)
        self.assertIn('"connectorId":', payload)
        self.assertNotIn("externalId", payload)
        self.assertNotIn("connectorRoleArn", payload)

    def test_runner_handler_dispatches_internal_validation_operation(self):
        self.assertIn('event.get("operation") == "VALIDATE_CONNECTOR"', RUNNER_HANDLER)
        self.assertIn("return _validation_response(event)", RUNNER_HANDLER)
        self.assertIn("validate_connector(", RUNNER_HANDLER)

    def test_runner_validation_performs_both_correct_and_wrong_external_id_assumes(self):
        self.assertIn("ExternalId=external_id", RUNNER_VALIDATION)
        self.assertIn('ExternalId=f"{external_id}-invalid"', RUNNER_VALIDATION)
        self.assertIn('WithDecryption=True', RUNNER_VALIDATION)
        self.assertIn('item.get("status") != "VALIDATING"', RUNNER_VALIDATION)

    def test_scan_activation_is_runner_only_with_no_direct_fallback(self):
        source = SCAN_MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("result = _invoke_runner_validation(connector_id)", source)
        self.assertIn("# Connector validation is intentionally runner-only.", source)
        self.assertNotIn('if os.environ.get("RUNNER_FUNCTION_NAME", "").strip():', source)
        self.assertNotIn("# Local unit-test compatibility path", source)
        self.assertNotIn("sts_client.assume_role", source)
        self.assertNotIn("ssm_client.get_parameter", source)


if __name__ == "__main__":
    unittest.main()
