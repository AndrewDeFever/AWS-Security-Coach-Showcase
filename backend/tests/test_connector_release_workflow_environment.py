import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ACCESS_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "deploy-connector-release-access.yml"
).read_text(encoding="utf-8")
INFRA_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "deploy-connector-release-infra.yml"
).read_text(encoding="utf-8")
PUBLISH_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "publish-connector-release.yml"
).read_text(encoding="utf-8")


class ConnectorReleaseWorkflowEnvironmentTests(unittest.TestCase):
    def test_access_workflow_groups_prod_environment_condition(self):
        expected = (
            "environment: ${{ ((github.event_name == 'workflow_dispatch' && "
            "inputs.target_environment == 'prod') || (github.event_name == 'push' && "
            "github.ref_name == 'main')) && 'production' || 'development' }}"
        )
        self.assertIn(expected, ACCESS_WORKFLOW)

    def test_infra_workflow_groups_prod_environment_condition(self):
        expected = (
            "environment: ${{ ((github.event_name == 'workflow_dispatch' && "
            "inputs.target_environment == 'prod') || (github.event_name == 'push' && "
            "github.ref_name == 'main')) && 'production' || 'development' }}"
        )
        self.assertIn(expected, INFRA_WORKFLOW)

    def test_publish_workflow_manual_prod_selection_is_already_unambiguous(self):
        self.assertIn(
            "environment: ${{ github.event_name == 'workflow_dispatch' && "
            "inputs.target_environment == 'prod' && 'production' || 'development' }}",
            PUBLISH_WORKFLOW,
        )


if __name__ == "__main__":
    unittest.main()
