import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
SCAN_SRC = ROOT / "src" / "scan"


def _load_modules():
    management_path = SCAN_SRC / "connector_management.py"
    management_spec = importlib.util.spec_from_file_location(
        "connector_management", management_path
    )
    management = importlib.util.module_from_spec(management_spec)
    assert management_spec and management_spec.loader
    management_spec.loader.exec_module(management)
    sys.modules["connector_management"] = management

    lifecycle_path = SCAN_SRC / "connector_lifecycle.py"
    lifecycle_spec = importlib.util.spec_from_file_location(
        "connector_lifecycle_test", lifecycle_path
    )
    lifecycle = importlib.util.module_from_spec(lifecycle_spec)
    assert lifecycle_spec and lifecycle_spec.loader
    lifecycle_spec.loader.exec_module(lifecycle)
    return management, lifecycle


class FakeTable:
    def __init__(self, item):
        self.item = dict(item) if item else None
        self.get_calls = []

    def get_item(self, **kwargs):
        self.get_calls.append(kwargs)
        return {"Item": dict(self.item)} if self.item else {}


class FakeSsm:
    def __init__(self):
        self.put_calls = []
        self.delete_calls = []

    def put_parameter(self, **kwargs):
        self.put_calls.append(kwargs)
        return {"Version": 2}

    def delete_parameter(self, **kwargs):
        self.delete_calls.append(kwargs)
        return {}


class FakeMembershipsTable:
    def __init__(self, items):
        self.items = list(items)
        self.scan_calls = []
        self.update_calls = []

    def scan(self, **kwargs):
        self.scan_calls.append(kwargs)
        connector_id = kwargs["ExpressionAttributeValues"][":connectorId"]
        return {
            "Items": [
                dict(item)
                for item in self.items
                if item.get("connectorId") == connector_id
            ]
        }

    def update_item(self, **kwargs):
        self.update_calls.append(kwargs)
        return {}


class ConnectorLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.management, cls.lifecycle = _load_modules()

    def _item(self, status="ENABLED"):
        return {
            "connectorId": "con_11111111-2222-4333-8444-555555555555",
            "displayName": "Example",
            "status": status,
            "connectorRoleArn": "arn:aws:iam::123456789012:role/aws-security-coach/example",
            "expectedAccountId": "123456789012",
            "homeRegion": "us-east-1",
            "templateVersion": "1.0.0",
            "connectorVersion": "1.0",
            "lastValidatedAt": "2026-08-12T00:00:00Z",
            "healthReason": None,
        }

    def test_disable_is_idempotent_when_already_disabled(self):
        table = FakeTable(self._item("DISABLED"))
        with patch.object(self.management, "_update_status") as update:
            result = self.lifecycle.disable_connector(
                table, self._item()["connectorId"]
            )
        self.assertEqual(result["status"], "DISABLED")
        update.assert_not_called()

    def test_disable_moves_enabled_or_unhealthy_to_disabled(self):
        for starting_status in ("ENABLED", "UNHEALTHY"):
            table = FakeTable(self._item(starting_status))
            updated = self._item("DISABLED")
            with patch.object(
                self.management,
                "_update_status",
                return_value={"Attributes": updated},
            ) as update:
                result = self.lifecycle.disable_connector(
                    table, self._item()["connectorId"]
                )
            self.assertEqual(result["status"], "DISABLED")
            kwargs = update.call_args.kwargs
            self.assertEqual(
                kwargs["expected_current_statuses"],
                ("ENABLED", "UNHEALTHY"),
            )

    def test_disable_rejects_pending_approval_pending_and_revoked(self):
        for starting_status in ("PENDING", "VALIDATING", "APPROVAL_PENDING", "REVOKED"):
            with self.assertRaises(RuntimeError):
                self.lifecycle.disable_connector(
                    FakeTable(self._item(starting_status)),
                    self._item()["connectorId"],
                )

    def test_enable_never_blindly_flips_enableable_state_to_enabled(self):
        for starting_status in ("DISABLED", "VALIDATING", "APPROVAL_PENDING"):
            table = FakeTable(self._item(starting_status))
            enabled = self._item("ENABLED")
            with patch.object(
                self.management,
                "_update_status",
                return_value={"Attributes": self._item("UNHEALTHY")},
            ) as update, patch.object(
                self.management,
                "register_connector",
                return_value=enabled,
            ) as register:
                result = self.lifecycle.enable_connector(
                    table,
                    MagicMock(),
                    MagicMock(),
                    MagicMock(),
                    "dev",
                    self._item()["connectorId"],
                )

            self.assertEqual(result["status"], "ENABLED")
            self.assertEqual(update.call_args.args[2], "UNHEALTHY")
            self.assertEqual(
                update.call_args.kwargs["expected_current_statuses"],
                (starting_status,),
            )
            self.assertEqual(
                register.call_args.args[-1],
                {"connectorRoleArn": self._item()["connectorRoleArn"]},
            )
            self.assertEqual(register.call_args.kwargs["final_status"], "ENABLED")

    def test_enable_rejects_non_enableable_states_except_enabled_idempotency(self):
        result = self.lifecycle.enable_connector(
            FakeTable(self._item("ENABLED")),
            MagicMock(),
            MagicMock(),
            MagicMock(),
            "dev",
            self._item()["connectorId"],
        )
        self.assertEqual(result["status"], "ENABLED")

        for starting_status in ("PENDING", "UNHEALTHY", "REVOKED"):
            with self.assertRaises(RuntimeError):
                self.lifecycle.enable_connector(
                    FakeTable(self._item(starting_status)),
                    MagicMock(),
                    MagicMock(),
                    MagicMock(),
                    "dev",
                    self._item()["connectorId"],
                )

    def test_reset_rotates_secure_string_and_moves_to_validating_without_returning_secret(self):
        table = FakeTable(self._item("ENABLED"))
        ssm = FakeSsm()
        validating = self._item("VALIDATING")
        with patch.object(
            self.management,
            "_update_status",
            return_value={"Attributes": validating},
        ) as update, patch.object(
            self.lifecycle.secrets, "token_hex", return_value="a" * 64
        ):
            result = self.lifecycle.reset_external_id(
                table,
                ssm,
                "dev",
                "arn:aws:kms:us-east-1:123456789012:key/example",
                self._item()["connectorId"],
            )

        self.assertEqual(result["status"], "VALIDATING")
        self.assertNotIn("externalId", result)
        self.assertEqual(update.call_args.args[2], "VALIDATING")
        self.assertEqual(len(ssm.put_calls), 1)
        put = ssm.put_calls[0]
        self.assertEqual(put["Value"], "a" * 64)
        self.assertTrue(put["Overwrite"])
        self.assertEqual(put["Type"], "SecureString")
        self.assertEqual(put["Tier"], "Standard")

    def test_reset_rejects_pending_validating_approval_pending_and_revoked(self):
        for starting_status in ("PENDING", "VALIDATING", "APPROVAL_PENDING", "REVOKED"):
            with self.assertRaises(RuntimeError):
                self.lifecycle.reset_external_id(
                    FakeTable(self._item(starting_status)),
                    FakeSsm(),
                    "dev",
                    "kms-key",
                    self._item()["connectorId"],
                )

    def test_revoke_is_terminal_deletes_secret_and_disables_enabled_memberships(self):
        table = FakeTable(self._item("APPROVAL_PENDING"))
        ssm = FakeSsm()
        connector_id = self._item()["connectorId"]
        memberships = FakeMembershipsTable(
            [
                {"requesterRef": "user-a", "connectorId": connector_id, "enabled": True},
                {"requesterRef": "user-b", "connectorId": connector_id, "enabled": False},
                {"requesterRef": "user-c", "connectorId": "con_other", "enabled": True},
            ]
        )
        revoked = self._item("REVOKED")
        with patch.object(
            self.management,
            "_update_status",
            return_value={"Attributes": revoked},
        ) as update:
            result = self.lifecycle.revoke_connector(
                table, memberships, ssm, "dev", connector_id
            )

        self.assertEqual(result["status"], "REVOKED")
        self.assertEqual(update.call_args.args[2], "REVOKED")
        self.assertIn(
            "APPROVAL_PENDING",
            update.call_args.kwargs["expected_current_statuses"],
        )
        self.assertEqual(len(ssm.delete_calls), 1)
        self.assertEqual(len(memberships.update_calls), 1)
        self.assertEqual(
            memberships.update_calls[0]["Key"],
            {"requesterRef": "user-a", "connectorId": connector_id},
        )
        self.assertFalse(
            memberships.update_calls[0]["ExpressionAttributeValues"][":disabled"]
        )

    def test_revoke_retries_cleanup_when_already_revoked_without_state_flip(self):
        table = FakeTable(self._item("REVOKED"))
        ssm = FakeSsm()
        memberships = FakeMembershipsTable([])
        with patch.object(self.management, "_update_status") as update:
            result = self.lifecycle.revoke_connector(
                table,
                memberships,
                ssm,
                "dev",
                self._item()["connectorId"],
            )
        self.assertEqual(result["status"], "REVOKED")
        update.assert_not_called()
        self.assertEqual(len(ssm.delete_calls), 1)
        self.assertEqual(len(memberships.scan_calls), 1)

    def test_public_lifecycle_shape_omits_sensitive_fields(self):
        safe = self.lifecycle._safe_connector(self._item("DISABLED"))
        self.assertNotIn("connectorRoleArn", safe)
        self.assertNotIn("expectedAccountId", safe)
        self.assertNotIn("externalId", safe)
        self.assertEqual(safe["status"], "DISABLED")


if __name__ == "__main__":
    unittest.main()
