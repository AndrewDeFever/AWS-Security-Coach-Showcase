import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = (REPO_ROOT / "infra" / "connector-releases" / "template.yaml").read_text(
    encoding="utf-8"
)
ACCESS_TEMPLATE = (
    REPO_ROOT / "infra" / "connector-release-access" / "template.yaml"
).read_text(encoding="utf-8")
INFRA_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "deploy-connector-release-infra.yml"
).read_text(encoding="utf-8")
ACCESS_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "deploy-connector-release-access.yml"
).read_text(encoding="utf-8")
PUBLISH_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "publish-connector-release.yml"
).read_text(encoding="utf-8")
FRONTEND_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "deploy-frontend.yml"
).read_text(encoding="utf-8")


class ConnectorReleaseInfrastructureTests(unittest.TestCase):
    def test_shared_bucket_is_dev_stack_owned_and_retained(self):
        bucket_section = TEMPLATE.split("ConnectorReleaseBucket:", 1)[1].split(
            "ConnectorReleaseBucketPolicy:", 1
        )[0]
        self.assertIn("Condition: IsDev", bucket_section)
        self.assertIn("DeletionPolicy: Retain", bucket_section)
        self.assertIn("UpdateReplacePolicy: Retain", bucket_section)
        self.assertIn("ObjectOwnership: BucketOwnerEnforced", bucket_section)
        self.assertIn("Status: Enabled", bucket_section)
        self.assertIn("SSEAlgorithm: aws:kms", bucket_section)
        self.assertIn("BucketKeyEnabled: true", bucket_section)
        self.assertIn("EncryptionType:\n                - SSE-C", bucket_section)

    def test_dev_publisher_is_prefix_bounded_and_cannot_delete(self):
        role_section = TEMPLATE.split("DevConnectorReleasePublisherRole:", 1)[1].split(
            "ProdConnectorReleasePublisherRole:", 1
        )[0]
        self.assertIn("Condition: IsDev", role_section)
        self.assertIn("GitHubOIDC-AwsSecurityCoach-ConnectorRelease-Dev", role_section)
        self.assertIn(
            "repo:${GitHubRepository}:environment:development",
            role_section,
        )
        self.assertIn("- dev/*", role_section)
        self.assertIn("${ConnectorReleaseBucketName}/dev/*", role_section)
        self.assertIn("- s3:GetObject", role_section)
        self.assertIn("- s3:PutObject", role_section)
        self.assertNotIn("s3:DeleteObject", role_section)
        self.assertNotIn("/prod/*", role_section)

    def test_prod_publisher_is_prefix_bounded_and_cannot_delete(self):
        role_section = TEMPLATE.split("ProdConnectorReleasePublisherRole:", 1)[1].split(
            "Outputs:", 1
        )[0]
        self.assertIn("Condition: IsProd", role_section)
        self.assertIn("GitHubOIDC-AwsSecurityCoach-ConnectorRelease-Prod", role_section)
        self.assertIn(
            "repo:${GitHubRepository}:environment:production",
            role_section,
        )
        self.assertIn("- prod/*", role_section)
        self.assertIn("${ConnectorReleaseBucketName}/prod/*", role_section)
        self.assertIn("- s3:GetObject", role_section)
        self.assertIn("- s3:PutObject", role_section)
        self.assertNotIn("s3:DeleteObject", role_section)
        self.assertNotIn("/dev/*", role_section)

    def test_release_infra_access_roles_are_environment_scoped(self):
        self.assertIn(
            "GitHubOIDC-AwsSecurityCoach-ConnectorReleaseInfra-Dev",
            ACCESS_TEMPLATE,
        )
        self.assertIn(
            "GitHubOIDC-AwsSecurityCoach-ConnectorReleaseInfra-Prod",
            ACCESS_TEMPLATE,
        )
        self.assertIn(
            "repo:${GitHubRepository}:environment:development",
            ACCESS_TEMPLATE,
        )
        self.assertIn(
            "repo:${GitHubRepository}:environment:production",
            ACCESS_TEMPLATE,
        )
        self.assertIn(
            "role/GitHubOIDC-AwsSecurityCoach-ConnectorRelease-Dev",
            ACCESS_TEMPLATE,
        )
        self.assertIn(
            "role/GitHubOIDC-AwsSecurityCoach-ConnectorRelease-Prod",
            ACCESS_TEMPLATE,
        )
        self.assertIn("aws-security-coach-connector-releases-example-prod", ACCESS_TEMPLATE)
        self.assertIn("ManageConnectorReleaseBucket", ACCESS_TEMPLATE)
        self.assertIn("- !Ref AWS::NoValue", ACCESS_TEMPLATE)

    def test_access_workflow_uses_backend_role_and_branch_environment_boundary(self):
        self.assertIn("role-to-assume: ${{ vars.BACKEND_AWS_ROLE_ARN }}", ACCESS_WORKFLOW)
        self.assertIn("github.ref_name == 'main'", ACCESS_WORKFLOW)
        self.assertIn("Development connector release access must deploy from dev.", ACCESS_WORKFLOW)
        self.assertIn("Production connector release access must deploy from main.", ACCESS_WORKFLOW)
        self.assertIn(
            'aws-safety-coach-${TARGET_ENVIRONMENT}-connector-release-access',
            ACCESS_WORKFLOW,
        )

    def test_release_infra_workflow_uses_environment_specific_role_and_stack(self):
        self.assertIn(
            "role-to-assume: ${{ vars.CONNECTOR_RELEASE_INFRA_AWS_ROLE_ARN }}",
            INFRA_WORKFLOW,
        )
        self.assertIn('STACK_NAME="aws-security-coach-connector-releases-example"', INFRA_WORKFLOW)
        self.assertIn(
            'STACK_NAME="aws-security-coach-connector-releases-example-prod"',
            INFRA_WORKFLOW,
        )
        self.assertIn("EnvironmentName=\"$TARGET_ENVIRONMENT\"", INFRA_WORKFLOW)
        self.assertIn("Development connector release infrastructure must deploy from dev.", INFRA_WORKFLOW)
        self.assertIn("Production connector release infrastructure must deploy from main.", INFRA_WORKFLOW)

    def test_publish_workflow_supports_dev_and_manual_prod_targets(self):
        self.assertIn(
            "role-to-assume: ${{ vars.CONNECTOR_RELEASE_AWS_ROLE_ARN }}",
            PUBLISH_WORKFLOW,
        )
        self.assertIn(
            "CONNECTOR_RELEASE_BUCKET: aws-security-coach-connector-releases-example",
            PUBLISH_WORKFLOW,
        )
        self.assertIn("target_environment:", PUBLISH_WORKFLOW)
        self.assertIn("- dev", PUBLISH_WORKFLOW)
        self.assertIn("- prod", PUBLISH_WORKFLOW)
        self.assertIn("Production connector releases are manual-only.", PUBLISH_WORKFLOW)
        self.assertIn("--checksum-algorithm SHA256", PUBLISH_WORKFLOW)
        self.assertIn("Refusing to overwrite non-identical", PUBLISH_WORKFLOW)
        self.assertNotIn("vars.S3_BUCKET", PUBLISH_WORKFLOW)

    def test_frontend_workflow_has_no_connector_release_special_case(self):
        self.assertNotIn("connector-releases", FRONTEND_WORKFLOW)
        self.assertIn(
            'aws s3 sync dist/ "s3://${{ vars.S3_BUCKET }}/" --delete',
            FRONTEND_WORKFLOW,
        )


if __name__ == "__main__":
    unittest.main()
