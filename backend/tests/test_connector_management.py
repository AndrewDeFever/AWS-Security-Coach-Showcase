import importlib.util
import re
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "scan" / "connector_management.py"
spec = importlib.util.spec_from_file_location("connector_management_test", MODULE_PATH)
connector_management = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(connector_management)


class FakeTable:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []
    def put_item(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("ddb failed")
        return {}


class FakeSsm:
    def __init__(self):
        self.put_calls = []
        self.delete_calls = []
    def put_parameter(self, **kwargs):
        self.put_calls.append(kwargs)
        return {"Version": 1}
    def delete_parameter(self, **kwargs):
        self.delete_calls.append(kwargs)
        return {}


class ConnectorManagementTests(unittest.TestCase):
    def test_validation_accepts_bounded_input_with_optional_customer_organization(self):
        self.assertEqual(connector_management.validate_provisioning_input({"displayName": "Acme Production", "homeRegion": "us-east-1"}), ("Acme Production", "us-east-1"))
        self.assertEqual(connector_management.validate_provisioning_input({"displayName": "Acme Production", "customerOrganization": "Acme Corporation", "homeRegion": "us-east-1"}), ("Acme Production", "us-east-1"))
        for invalid in (
            {},
            {"displayName": "Acme Production"},
            {"displayName": "Acme", "homeRegion": "us-west-2"},
            {"displayName": "Acme", "homeRegion": "us-east-1", "accountId": "123"},
            {"displayName": "Acme", "homeRegion": "us-east-1", "customerOrganization": ""},
            {"displayName": "", "homeRegion": "us-east-1"},
        ):
            with self.assertRaises(ValueError):
                connector_management.validate_provisioning_input(invalid)

    @patch.object(connector_management.secrets, "token_hex", return_value="a" * 64)
    @patch.object(connector_management.uuid, "uuid4", return_value="11111111-2222-4333-8444-555555555555")
    @patch.object(connector_management.time, "time", return_value=1_786_493_000.0)
    @patch.object(connector_management, "_utc_now", return_value="2026-08-11T23:30:00Z")
    def test_provisioning_creates_pending_record_customer_metadata_and_protected_external_id(self, _utc_now, _time, _uuid4, _token_hex):
        table = FakeTable()
        ssm = FakeSsm()
        result = connector_management.provision_connector(
            table,
            ssm,
            "dev",
            "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000000",
            {"displayName": "Acme Production", "customerOrganization": "Acme Corporation", "homeRegion": "us-east-1"},
            owner_requester_ref="usr_exampleowner",
        )
        connector_id = "con_11111111-2222-4333-8444-555555555555"
        self.assertEqual(result["connectorId"], connector_id)
        self.assertEqual(result["status"], "PENDING")
        self.assertEqual(result["customerOrganization"], "Acme Corporation")
        self.assertNotIn("externalId", result)
        self.assertNotIn("parameterName", result)
        self.assertNotIn("ownerRequesterRef", result)
        self.assertEqual(len(ssm.put_calls), 1)
        put = ssm.put_calls[0]
        self.assertEqual(put["Name"], f"/security-coach/dev/connectors/{connector_id}/external-id")
        self.assertEqual(put["Value"], "a" * 64)
        self.assertEqual(put["Type"], "SecureString")
        self.assertEqual(put["Tier"], "Standard")
        self.assertFalse(put["Overwrite"])
        item = table.calls[0]["Item"]
        self.assertEqual(item["connectorId"], connector_id)
        self.assertEqual(item["ownerRequesterRef"], "usr_exampleowner")
        self.assertEqual(item["customerOrganization"], "Acme Corporation")
        self.assertEqual(item["status"], "PENDING")
        self.assertEqual(item["statusBucket"], "PENDING")
        self.assertEqual(item["connectorRoleArn"], "")
        self.assertEqual(item["expectedAccountId"], "")
        self.assertIsNone(item["lastValidatedAt"])
        self.assertIsNone(item["healthReason"])
        self.assertTrue(item["managementSortKey"].startswith("2#"))
        self.assertEqual(table.calls[0]["ConditionExpression"], "attribute_not_exists(connectorId)")

    @patch.object(connector_management.secrets, "token_hex", return_value="b" * 64)
    def test_dynamodb_failure_rolls_back_created_parameter(self, _token_hex):
        table = FakeTable(fail=True)
        ssm = FakeSsm()
        with self.assertRaises(RuntimeError):
            connector_management.provision_connector(table, ssm, "dev", "kms-key", {"displayName": "Acme", "homeRegion": "us-east-1"}, owner_requester_ref="usr_exampleowner")
        self.assertEqual(len(ssm.put_calls), 1)
        self.assertEqual(ssm.delete_calls, [{"Name": ssm.put_calls[0]["Name"]}])

    def test_connector_id_shape_is_opaque_uuid_v4(self):
        table = FakeTable()
        ssm = FakeSsm()
        result = connector_management.provision_connector(table, ssm, "dev", "kms-key", {"displayName": "Acme", "homeRegion": "us-east-1"}, owner_requester_ref="usr_exampleowner")
        self.assertRegex(result["connectorId"], re.compile(r"^con_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))

    def test_approval_pending_is_prioritized_for_operator_review(self):
        key = connector_management._management_sort_key(connector_management.CONNECTOR_STATUS_APPROVAL_PENDING, 1_786_493_000_000, "con_11111111-2222-4333-8444-555555555555")
        self.assertTrue(key.startswith("1#"))


if __name__ == "__main__":
    unittest.main()
