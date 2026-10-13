import importlib.util
import os
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "scan" / "connector_management.py"
spec = importlib.util.spec_from_file_location("connector_management_registration_test", MODULE_PATH)
connector_management = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(connector_management)


CONNECTOR_ID = "con_11111111-2222-4333-8444-555555555555"
ROLE_ARN = "arn:aws:iam::123456789012:role/aws-security-coach/test-role"


class FakeTable:
    def __init__(self, item):
        self.item = dict(item)
        self.get_calls = []
        self.update_calls = []

    def get_item(self, **kwargs):
        self.get_calls.append(kwargs)
        return {"Item": dict(self.item)}

    def update_item(self, **kwargs):
        self.update_calls.append(kwargs)
        values = kwargs["ExpressionAttributeValues"]
        self.item["status"] = values[":status"]
        self.item["updatedAt"] = values[":updatedAt"]
        self.item["managementBucket"] = values[":managementBucket"]
        self.item["managementSortKey"] = values[":managementSortKey"]
        self.item["statusBucket"] = values[":statusBucket"]
        self.item["statusSortKey"] = values[":statusSortKey"]
        self.item["healthReason"] = values[":healthReason"]
        for key in ("connectorRoleArn", "expectedAccountId", "lastValidatedAt"):
            token = f":{key}"
            if token in values:
                self.item[key] = values[token]
        return {"Attributes": dict(self.item)}


def pending_item():
    return {
        "connectorId": CONNECTOR_ID,
        "displayName": "Activation Test",
        "status": "PENDING",
        "connectorRoleArn": "",
        "expectedAccountId": "",
        "homeRegion": "us-east-1",
        "templateVersion": "1.0.0",
        "connectorVersion": "1.0",
        "createdAt": "2026-08-12T00:00:00Z",
        "updatedAt": "2026-08-12T00:00:00Z",
        "lastValidatedAt": None,
        "healthReason": None,
        "managementBucket": "ACTIVE",
        "managementSortKey": "2#x",
        "statusBucket": "PENDING",
        "statusSortKey": "x",
    }


class ConnectorRegistrationValidationTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"RUNNER_FUNCTION_NAME": "test-runner"}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)

    def register(self, table, *, final_status=None):
        kwargs = {}
        if final_status is not None:
            kwargs["final_status"] = final_status
        return connector_management.register_connector(
            table,
            None,
            None,
            None,
            "dev",
            CONNECTOR_ID,
            {"connectorRoleArn": ROLE_ARN},
            **kwargs,
        )

    def test_registration_input_is_connector_role_arn_only_and_path_bounded(self):
        role_arn, account = connector_management.validate_registration_input(
            {"connectorRoleArn": ROLE_ARN}
        )
        self.assertEqual(role_arn, ROLE_ARN)
        self.assertEqual(account, "123456789012")

        invalid = (
            {},
            {"connectorRoleArn": ROLE_ARN, "accountId": "123456789012"},
            {"connectorRoleArn": "arn:aws:iam::123456789012:role/other/test"},
            {"connectorRoleArn": "not-an-arn"},
        )
        for value in invalid:
            with self.assertRaises(ValueError):
                connector_management.validate_registration_input(value)

    def test_customer_registration_transitions_pending_to_validating_to_approval_pending(self):
        table = FakeTable(pending_item())
        with mock.patch.object(
            connector_management,
            "_invoke_runner_validation",
            return_value={"ok": True, "accountId": "123456789012"},
        ) as invoke:
            result = self.register(table)

        self.assertEqual(result["status"], "APPROVAL_PENDING")
        self.assertEqual(table.item["status"], "APPROVAL_PENDING")
        self.assertEqual(table.item["expectedAccountId"], "123456789012")
        self.assertIsNone(table.item["healthReason"])
        invoke.assert_called_once_with(CONNECTOR_ID)
        self.assertEqual(table.update_calls[0]["ExpressionAttributeValues"][":status"], "VALIDATING")
        self.assertEqual(table.update_calls[-1]["ExpressionAttributeValues"][":status"], "APPROVAL_PENDING")

    def test_operator_approval_can_finish_same_validation_as_enabled(self):
        table = FakeTable(pending_item())
        with mock.patch.object(
            connector_management,
            "_invoke_runner_validation",
            return_value={"ok": True, "accountId": "123456789012"},
        ):
            result = self.register(table, final_status="ENABLED")

        self.assertEqual(result["status"], "ENABLED")
        self.assertEqual(table.item["status"], "ENABLED")
        self.assertEqual(table.update_calls[-1]["ExpressionAttributeValues"][":status"], "ENABLED")

    def test_registration_rejects_unapproved_final_status(self):
        table = FakeTable(pending_item())
        with self.assertRaises(RuntimeError):
            self.register(table, final_status="DISABLED")
        self.assertEqual(table.update_calls, [])

    def test_missing_runner_configuration_fails_closed(self):
        table = FakeTable(pending_item())
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(connector_management.ConnectorValidationError) as caught:
                self.register(table)
        self.assertEqual(caught.exception.health_reason, "UNKNOWN_VALIDATION_ERROR")
        self.assertEqual(table.item["status"], "UNHEALTHY")

    def test_runner_wrong_external_id_failure_marks_unhealthy(self):
        table = FakeTable(pending_item())
        with mock.patch.object(
            connector_management,
            "_invoke_runner_validation",
            return_value={"ok": False, "healthReason": "ASSUME_ROLE_FAILED"},
        ):
            with self.assertRaises(connector_management.ConnectorValidationError) as caught:
                self.register(table)
        self.assertEqual(caught.exception.health_reason, "ASSUME_ROLE_FAILED")
        self.assertEqual(table.item["status"], "UNHEALTHY")
        self.assertEqual(table.item["healthReason"], "ASSUME_ROLE_FAILED")

    def test_runner_account_mismatch_fails_closed(self):
        table = FakeTable(pending_item())
        with mock.patch.object(
            connector_management,
            "_invoke_runner_validation",
            return_value={"ok": False, "healthReason": "ACCOUNT_MISMATCH", "accountId": "999999999999"},
        ):
            with self.assertRaises(connector_management.ConnectorValidationError) as caught:
                self.register(table)
        self.assertEqual(caught.exception.health_reason, "ACCOUNT_MISMATCH")
        self.assertEqual(table.item["status"], "UNHEALTHY")
        self.assertEqual(table.item["expectedAccountId"], "999999999999")

    def test_runner_permission_failure_marks_unhealthy(self):
        table = FakeTable(pending_item())
        with mock.patch.object(
            connector_management,
            "_invoke_runner_validation",
            return_value={"ok": False, "healthReason": "PERMISSION_CHECK_FAILED", "accountId": "123456789012"},
        ):
            with self.assertRaises(connector_management.ConnectorValidationError) as caught:
                self.register(table)
        self.assertEqual(caught.exception.health_reason, "PERMISSION_CHECK_FAILED")
        self.assertEqual(table.item["healthReason"], "PERMISSION_CHECK_FAILED")

    def test_unsupported_connector_version_marks_unhealthy_before_runner(self):
        item = pending_item()
        item["connectorVersion"] = "2.0"
        table = FakeTable(item)
        with mock.patch.object(connector_management, "_invoke_runner_validation") as invoke:
            with self.assertRaises(connector_management.ConnectorValidationError) as caught:
                self.register(table)
        self.assertEqual(caught.exception.health_reason, "UNSUPPORTED_CONNECTOR_VERSION")
        invoke.assert_not_called()
        self.assertEqual(table.item["status"], "UNHEALTHY")


if __name__ == "__main__":
    unittest.main()
