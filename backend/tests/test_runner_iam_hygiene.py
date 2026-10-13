import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "template.yaml").read_text(encoding="utf-8")


class RunnerIamHygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runner_start = TEMPLATE.index("  RunnerFunction:\n")
        runner_end = TEMPLATE.index("\n  RunnerSweeperSchedule:\n", runner_start)
        cls.runner = TEMPLATE[runner_start:runner_end]

    def test_global_xray_tracing_trigger_is_absent(self):
        self.assertNotIn("Tracing: PassThrough", TEMPLATE)
        self.assertNotIn("Tracing: Active", TEMPLATE)

    def test_runner_does_not_use_broad_sam_crud_policy_templates(self):
        self.assertNotIn("DynamoDBCrudPolicy", self.runner)
        self.assertNotIn("S3CrudPolicy", self.runner)

    def test_runner_has_only_required_scan_table_actions(self):
        self.assertIn("- dynamodb:Scan", self.runner)
        self.assertIn("- dynamodb:UpdateItem", self.runner)
        self.assertIn("Resource: !GetAtt ScansTable.Arn", self.runner)
        for action in (
            "dynamodb:PutItem",
            "dynamodb:DeleteItem",
            "dynamodb:BatchWriteItem",
        ):
            self.assertNotIn(action, self.runner)

    def test_runner_s3_permissions_are_bounded_to_actual_usage(self):
        self.assertIn("- s3:ListBucket", self.runner)
        self.assertIn("Resource: !GetAtt ArtifactsBucket.Arn", self.runner)
        self.assertIn("- s3:PutObject", self.runner)
        self.assertIn("${ArtifactsBucket.Arn}/${ReportsPrefix}*", self.runner)
        for action in (
            "s3:GetObject",
            "s3:DeleteObject",
            "s3:PutBucketPolicy",
        ):
            self.assertNotIn(action, self.runner)

    def test_runner_keeps_account_public_access_block_permission(self):
        self.assertIn("- s3:GetAccountPublicAccessBlock", self.runner)
        self.assertNotIn("s3control:GetPublicAccessBlock", self.runner)

    def test_runner_drops_unused_cloudtrail_status_permission(self):
        self.assertIn("- cloudtrail:DescribeTrails", self.runner)
        self.assertNotIn("cloudtrail:GetTrailStatus", self.runner)

    def test_connector_data_decrypt_is_key_and_service_bounded(self):
        self.assertIn("ApplicationKmsKeyArn:", TEMPLATE)
        self.assertIn("Sid: DecryptConnectorData", self.runner)
        self.assertIn("- kms:Decrypt", self.runner)
        self.assertIn("Resource: !Ref ApplicationKmsKeyArn", self.runner)
        self.assertIn("- !Sub 'dynamodb.${AWS::Region}.amazonaws.com'", self.runner)
        self.assertIn("- !Sub 'ssm.${AWS::Region}.amazonaws.com'", self.runner)
        self.assertNotIn("kms:*", self.runner)

    def test_connector_assumerole_guardrail_is_registry_only(self):
        self.assertIn("arn:${AWS::Partition}:iam::*:role/aws-security-coach/*", self.runner)
        self.assertIn("iam:ResourceTag/AWSSecurityCoachConnector: 'true'", self.runner)
        self.assertNotIn("LegacyPilotConnectorRoleArn", TEMPLATE)
        self.assertNotIn("LEGACY_PILOT_CONNECTOR_PARAMETER_NAME", self.runner)


if __name__ == "__main__":
    unittest.main()
