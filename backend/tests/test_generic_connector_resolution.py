import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "template.yaml").read_text(encoding="utf-8")
V1_HANDLER = (ROOT / "src" / "runner" / "v1_handler.py").read_text(encoding="utf-8")


def _load_connector_context():
    boto3 = types.ModuleType("boto3")
    boto3.client = MagicMock()
    sys.modules["boto3"] = boto3

    path = ROOT / "src" / "runner" / "connector_context.py"
    spec = importlib.util.spec_from_file_location("connector_context_generic_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class FakeTable:
    def __init__(self, item):
        self.item = item
        self.calls = []

    def get_item(self, **kwargs):
        self.calls.append(kwargs)
        return {"Item": self.item} if self.item is not None else {}


class FakeSsm:
    def __init__(self, value):
        self.value = value
        self.calls = []

    def get_parameter(self, **kwargs):
        self.calls.append(kwargs)
        return {"Parameter": {"Value": self.value}}


class GenericConnectorResolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.connector_context = _load_connector_context()

    def _enabled_item(self):
        return {
            "connectorId": "con_1234",
            "displayName": "Example",
            "status": "ENABLED",
            "connectorRoleArn": "arn:aws:iam::123456789012:role/aws-security-coach/example",
            "expectedAccountId": "123456789012",
            "homeRegion": "us-east-1",
            "templateVersion": "1.0.0",
            "connectorVersion": "1.0",
        }

    def test_registered_connector_uses_registry_and_derived_secure_parameter(self):
        table = FakeTable(self._enabled_item())
        ssm = FakeSsm("x" * 32)

        connector = self.connector_context.load_registered_connector(
            table,
            ssm,
            "con_1234",
            "dev",
        )

        self.assertEqual(connector["connectorId"], "con_1234")
        self.assertEqual(connector["expectedAccountId"], "123456789012")
        self.assertEqual(connector["templateVersion"], "1.0.0")
        self.assertEqual(connector["connectorVersion"], "1.0")
        self.assertEqual(
            table.calls,
            [{"Key": {"connectorId": "con_1234"}, "ConsistentRead": True}],
        )
        self.assertEqual(
            ssm.calls,
            [
                {
                    "Name": "/security-coach/dev/connectors/con_1234/external-id",
                    "WithDecryption": True,
                }
            ],
        )

    def test_registered_connector_fails_closed_when_not_enabled(self):
        item = self._enabled_item()
        item["status"] = "DISABLED"
        with self.assertRaises(RuntimeError):
            self.connector_context.load_registered_connector(
                FakeTable(item), FakeSsm("x" * 32), "con_1234", "dev"
            )

    def test_registered_connector_fails_closed_on_account_mismatch(self):
        item = self._enabled_item()
        item["expectedAccountId"] = "999999999999"
        with self.assertRaises(RuntimeError):
            self.connector_context.load_registered_connector(
                FakeTable(item), FakeSsm("x" * 32), "con_1234", "dev"
            )

    def test_registered_connector_fails_closed_on_invalid_template_version(self):
        item = self._enabled_item()
        item["templateVersion"] = "v1"
        with self.assertRaises(RuntimeError):
            self.connector_context.load_registered_connector(
                FakeTable(item), FakeSsm("x" * 32), "con_1234", "dev"
            )

    def test_registered_connector_fails_closed_on_unsupported_runtime_version(self):
        item = self._enabled_item()
        item["connectorVersion"] = "2.0"
        with self.assertRaises(RuntimeError):
            self.connector_context.load_registered_connector(
                FakeTable(item), FakeSsm("x" * 32), "con_1234", "dev"
            )

    def test_missing_registry_item_fails_closed(self):
        with self.assertRaises(self.connector_context.ConnectorNotFound):
            self.connector_context.load_registered_connector(
                FakeTable(None), FakeSsm("x" * 32), "con_1234", "dev"
            )

    def test_runner_template_has_generic_registry_and_secret_permissions(self):
        runner = TEMPLATE[
            TEMPLATE.index("  RunnerFunction:\n") : TEMPLATE.index(
                "\n  RunnerSweeperSchedule:\n", TEMPLATE.index("  RunnerFunction:\n")
            )
        ]
        self.assertIn("CONNECTORS_TABLE: !Ref ConnectorsTable", runner)
        self.assertIn("Sid: ReadConnectorRegistry", runner)
        self.assertIn("- dynamodb:GetItem", runner)
        self.assertIn("Resource: !GetAtt ConnectorsTable.Arn", runner)
        self.assertIn("Sid: ReadConnectorExternalIds", runner)
        self.assertIn(
            "parameter/security-coach/${EnvironmentName}/connectors/*",
            runner,
        )

    def test_runner_uses_registry_only_and_has_no_legacy_pilot_fallback(self):
        self.assertIn("load_registered_connector(", V1_HANDLER)
        self.assertNotIn("except ConnectorNotFound:", V1_HANDLER)
        self.assertNotIn("load_connector(", V1_HANDLER)
        self.assertNotIn("LEGACY_PILOT_CONNECTOR_PARAMETER_NAME", V1_HANDLER)
        self.assertNotIn("legacy-pilot-fallback", V1_HANDLER)

    def test_runner_stamps_resolved_connector_versions_for_report_emission(self):
        self.assertIn("def _stamp_connector_context", V1_HANDLER)
        self.assertIn('"templateVersion": connector["templateVersion"]', V1_HANDLER)
        self.assertIn('"connectorVersion": connector["connectorVersion"]', V1_HANDLER)
        self.assertIn("return _stamp_connector_context(report, connector)", V1_HANDLER)

    def test_runner_logs_non_secret_connector_resolution_source(self):
        self.assertIn("CONNECTOR RESOLUTION: ", V1_HANDLER)
        self.assertIn('_log_connector_resolution("registry", connector)', V1_HANDLER)
        log_function = V1_HANDLER[
            V1_HANDLER.index("def _log_connector_resolution") : V1_HANDLER.index(
                "\n\ndef _load_target_connector"
            )
        ]
        self.assertIn("connectorId=", log_function)
        self.assertIn("roleArn=", log_function)
        self.assertIn("homeRegion=", log_function)
        self.assertNotIn("externalId", log_function)
        self.assertNotIn("parameterName", log_function)


if __name__ == "__main__":
    unittest.main()
