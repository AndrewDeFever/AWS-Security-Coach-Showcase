import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "template.yaml").read_text(encoding="utf-8")


class RunnerAssumeRoleBoundaryTests(unittest.TestCase):
    def setUp(self):
        start = TEMPLATE.index("  RunnerFunction:")
        end = TEMPLATE.index("  RunnerSweeperSchedule:", start)
        self.runner = TEMPLATE[start:end]

    def test_general_connector_assume_role_is_path_and_tag_bounded(self):
        self.assertIn("Sid: AssumeManagedSecurityCoachConnectors", self.runner)
        self.assertIn("- sts:AssumeRole", self.runner)
        self.assertIn(
            "Resource: !Sub 'arn:${AWS::Partition}:iam::*:role/aws-security-coach/*'",
            self.runner,
        )
        self.assertIn("iam:ResourceTag/AWSSecurityCoachConnector: 'true'", self.runner)

    def test_general_connector_assume_role_never_uses_unbounded_resource(self):
        self.assertNotIn(
            "Action:\n                - sts:AssumeRole\n              Resource: '*'",
            self.runner,
        )
        self.assertNotIn("arn:${AWS::Partition}:iam::*:role/*", self.runner)

    def test_legacy_pilot_assume_role_exception_is_removed(self):
        self.assertNotIn("LegacyPilotConnectorRoleArn", TEMPLATE)
        self.assertNotIn("Resource: !Ref LegacyPilotConnectorRoleArn", self.runner)

    def test_connector_ssm_resolution_is_registry_only(self):
        self.assertIn("Sid: ReadConnectorExternalIds", self.runner)
        self.assertIn("- ssm:GetParameter", self.runner)
        self.assertIn(
            "parameter/security-coach/${EnvironmentName}/connectors/*",
            self.runner,
        )
        self.assertIn("CONNECTORS_TABLE: !Ref ConnectorsTable", self.runner)
        self.assertNotIn("LEGACY_PILOT_CONNECTOR_PARAMETER_NAME", self.runner)


if __name__ == "__main__":
    unittest.main()
