import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "template.yaml").read_text(encoding="utf-8")
CONNECTOR_HANDLER = (ROOT / "src" / "scan" / "connector_aware_handler.py").read_text(
    encoding="utf-8"
)
GET_SCAN_HANDLER = (ROOT / "src" / "get_scan" / "lambda_function.py").read_text(
    encoding="utf-8"
)
GET_REPORT_HANDLER = (ROOT / "src" / "get_report" / "lambda_function.py").read_text(
    encoding="utf-8"
)
DEPLOY_WORKFLOW = (ROOT.parent / ".github" / "workflows" / "deploy-backend.yml").read_text(
    encoding="utf-8"
)


def _load_connector_context():
    boto3 = types.ModuleType("boto3")
    boto3.client = MagicMock()
    sys.modules["boto3"] = boto3

    path = ROOT / "src" / "runner" / "connector_context.py"
    spec = importlib.util.spec_from_file_location("connector_context_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class FakeSsm:
    def __init__(self, value):
        self.value = value
        self.calls = []

    def get_parameter(self, **kwargs):
        self.calls.append(kwargs)
        return {"Parameter": {"Value": json.dumps(self.value)}}


class ConnectorPilotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.connector_context = _load_connector_context()

    def test_template_uses_registry_only_connector_runtime(self):
        self.assertNotIn("Conditions:\n  IsDevelopment:", TEMPLATE)
        self.assertIn("- ssm:GetParameter", TEMPLATE)
        self.assertIn("- sts:AssumeRole", TEMPLATE)
        self.assertIn("CONNECTORS_TABLE: !Ref ConnectorsTable", TEMPLATE)
        self.assertIn(
            "parameter/security-coach/${EnvironmentName}/connectors/*",
            TEMPLATE,
        )
        self.assertNotIn("LEGACY_PILOT_CONNECTOR_ID", TEMPLATE)
        self.assertNotIn("LegacyPilotConnectorRoleArn", TEMPLATE)
        self.assertNotIn("LEGACY_PILOT_CONNECTOR_PARAMETER_NAME", TEMPLATE)
        self.assertNotIn("LEGACY_PILOT_CONNECTOR_ROLE_ARN", DEPLOY_WORKFLOW)

    def test_scan_uses_lifecycle_wrapper(self):
        self.assertIn("Handler: lifecycle_aware_handler.lambda_handler", TEMPLATE)

    def test_customer_group_is_stack_managed(self):
        self.assertIn("StackCognitoCustomerGroup:", TEMPLATE)
        self.assertIn("GroupName: customer", TEMPLATE)
        self.assertIn(
            "Description: Customer users permitted to access explicitly assigned AWS connectors.",
            TEMPLATE,
        )
        self.assertIn("CUSTOMER_GROUP = \"customer\"", CONNECTOR_HANDLER)

    def test_memberships_are_application_owned_and_queryable_by_requester(self):
        self.assertIn("ConnectorMembershipsTable:", TEMPLATE)
        self.assertIn("DeletionPolicy: Retain", TEMPLATE)
        self.assertIn("UpdateReplacePolicy: Retain", TEMPLATE)
        self.assertIn("TableName: !Sub '${ProjectName}-${EnvironmentName}-connector-memberships'", TEMPLATE)
        self.assertIn("AttributeName: requesterRef", TEMPLATE)
        self.assertIn("AttributeName: connectorId", TEMPLATE)
        self.assertIn("KeyType: HASH", TEMPLATE)
        self.assertIn("KeyType: RANGE", TEMPLATE)
        self.assertIn("CONNECTOR_MEMBERSHIPS_TABLE: !Ref ConnectorMembershipsTable", TEMPLATE)
        self.assertIn("DynamoDBReadPolicy:", TEMPLATE)
        self.assertIn("TableName: !Ref ConnectorMembershipsTable", TEMPLATE)

    def test_operator_bypasses_customer_membership_gate(self):
        self.assertIn("if not scan._operator_authorized(event):", CONNECTOR_HANDLER)
        self.assertIn("_customer_connector_authorized(requester_ref, connector_id)", CONNECTOR_HANDLER)
        operator_gate = CONNECTOR_HANDLER.index("if not scan._operator_authorized(event):")
        membership_lookup = CONNECTOR_HANDLER.index("_customer_connector_authorized(requester_ref, connector_id)", operator_gate)
        self.assertLess(operator_gate, membership_lookup)

    def test_customer_group_is_required_before_membership_lookup(self):
        self.assertIn("if not _customer_authorized(event):", CONNECTOR_HANDLER)
        self.assertIn('"code": "CUSTOMER_GROUP_REQUIRED"', CONNECTOR_HANDLER)
        connector_start = CONNECTOR_HANDLER.index("def _connector_response")
        customer_group_gate = CONNECTOR_HANDLER.index("if not _customer_authorized(event):", connector_start)
        membership_lookup = CONNECTOR_HANDLER.index(
            "_customer_connector_authorized(requester_ref, connector_id)",
            customer_group_gate,
        )
        self.assertLess(customer_group_gate, membership_lookup)

    def test_customer_membership_is_checked_before_admission(self):
        self.assertIn('os.environ.get("CONNECTOR_MEMBERSHIPS_TABLE", "")', CONNECTOR_HANDLER)
        self.assertIn('Key={"requesterRef": requester_ref, "connectorId": connector_id}', CONNECTOR_HANDLER)
        self.assertIn('item.get("enabled") is True', CONNECTOR_HANDLER)
        self.assertIn('"code": "CONNECTOR_ACCESS_DENIED"', CONNECTOR_HANDLER)
        membership_gate = CONNECTOR_HANDLER.index("if not customer_authorized:")
        admission_setup = CONNECTOR_HANDLER.index("scans_table = scan.ddb.Table")
        self.assertLess(membership_gate, admission_setup)

    def test_connector_scans_require_requester_identity_even_for_operator(self):
        self.assertIn("if not requester_ref:", CONNECTOR_HANDLER)
        requester_gate = CONNECTOR_HANDLER.index("if not requester_ref:")
        operator_gate = CONNECTOR_HANDLER.index("if not scan._operator_authorized(event):")
        self.assertLess(requester_gate, operator_gate)

    def test_authorized_targets_route_is_server_owned(self):
        self.assertIn("Path: /auth/targets", TEMPLATE)
        self.assertIn('TARGETS_PATH = "/auth/targets"', CONNECTOR_HANDLER)
        self.assertIn('"targetId": "tool-account"', CONNECTOR_HANDLER)
        self.assertIn('"displayName": "AWS Security Coach"', CONNECTOR_HANDLER)
        self.assertIn('display_name = str(item.get("displayName", "")).strip() or connector_id', CONNECTOR_HANDLER)
        self.assertIn('"displayName": display_name', CONNECTOR_HANDLER)
        self.assertIn('KeyConditionExpression="requesterRef = :requesterRef"', CONNECTOR_HANDLER)
        self.assertIn('ConsistentRead=True', CONNECTOR_HANDLER)

    def test_customer_target_list_never_adds_tool_account(self):
        operator_branch = CONNECTOR_HANDLER.index("if scan._operator_authorized(event):")
        customer_query = CONNECTOR_HANDLER.index("table.query(", operator_branch)
        tool_target = CONNECTOR_HANDLER.index('"targetId": "tool-account"')
        self.assertLess(tool_target, customer_query)
        customer_section = CONNECTOR_HANDLER[customer_query:CONNECTOR_HANDLER.index("def _connector_response")]
        self.assertNotIn('"targetId": "tool-account"', customer_section)

    def test_customer_scan_and_report_reads_are_requester_owned(self):
        self.assertIn('item.get("requesterRef") != requester_ref', GET_SCAN_HANDLER)
        self.assertIn('"code": "SCAN_ACCESS_DENIED"', GET_SCAN_HANDLER)
        self.assertIn('scan_item.get("requesterRef") != requester_ref', GET_REPORT_HANDLER)
        self.assertIn('"code": "REPORT_ACCESS_DENIED"', GET_REPORT_HANDLER)
        self.assertGreater(GET_SCAN_HANDLER.index("item = result.get"), 0)
        self.assertGreater(GET_REPORT_HANDLER.index("scan_item = ddb_result.get"), 0)
        self.assertIn("ENVIRONMENT_NAME: !Ref EnvironmentName", TEMPLATE)

    def test_one_user_secret_binding_is_removed(self):
        self.assertNotIn("LegacyPilotAllowedRequesterRef", TEMPLATE)
        self.assertNotIn("LEGACY_PILOT_ALLOWED_REQUESTER_REF", TEMPLATE)
        self.assertNotIn("LEGACY_PILOT_ALLOWED_REQUESTER_REF", DEPLOY_WORKFLOW)
        self.assertNotIn("LEGACY_PILOT_ALLOWED_REQUESTER_REF", CONNECTOR_HANDLER)

    def test_connector_record_requires_decryption_and_exact_id(self):
        value = {
            "connectorId": "legacy-pilot-dev",
            "roleArn": "arn:aws:iam::123456789012:role/example-read-only",
            "externalId": "x" * 32,
            "homeRegion": "us-east-1",
            "enabled": True,
        }
        ssm = FakeSsm(value)
        connector = self.connector_context.load_connector(
            ssm,
            "/security-coach/dev/connectors/legacy-pilot",
            "legacy-pilot-dev",
        )
        self.assertEqual(connector["connectorId"], "legacy-pilot-dev")
        self.assertEqual(
            ssm.calls,
            [
                {
                    "Name": "/security-coach/dev/connectors/legacy-pilot",
                    "WithDecryption": True,
                }
            ],
        )

    def test_connector_record_fails_closed_when_disabled(self):
        value = {
            "connectorId": "legacy-pilot-dev",
            "roleArn": "arn:aws:iam::123456789012:role/example-read-only",
            "externalId": "x" * 32,
            "homeRegion": "us-east-1",
            "enabled": False,
        }
        with self.assertRaises(RuntimeError):
            self.connector_context.load_connector(FakeSsm(value), "parameter", "legacy-pilot-dev")

    def test_connector_record_fails_closed_on_wrong_id(self):
        value = {
            "connectorId": "different-connector",
            "roleArn": "arn:aws:iam::123456789012:role/example-read-only",
            "externalId": "x" * 32,
            "homeRegion": "us-east-1",
            "enabled": True,
        }
        with self.assertRaises(RuntimeError):
            self.connector_context.load_connector(FakeSsm(value), "parameter", "legacy-pilot-dev")

    def test_no_workload_account_or_external_id_is_hardcoded(self):
        connector_source = (ROOT / "src" / "runner" / "connector_context.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("externalId\":\"", connector_source)
        self.assertNotRegex(TEMPLATE, r"arn:aws:iam::[0-9]{12}:role/aws-security-coach-connec")


if __name__ == "__main__":
    unittest.main()
