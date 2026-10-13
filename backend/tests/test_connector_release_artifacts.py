import json
import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CONNECTOR_ROOT = REPO_ROOT / "connector"
CURRENT_TEMPLATE = CONNECTOR_ROOT / "template.yaml"
RELEASES_ROOT = CONNECTOR_ROOT / "releases"
VERSION_PATTERN = re.compile(r"ConnectorTemplateVersion:\s*'([^']+)'")


class ConnectorReleaseArtifactTests(unittest.TestCase):
    def _template_version(self, path: Path) -> str:
        text = path.read_text(encoding="utf-8")
        match = VERSION_PATTERN.search(text)
        self.assertIsNotNone(match, f"missing ConnectorTemplateVersion in {path}")
        return match.group(1)

    def test_current_template_has_byte_identical_published_release(self):
        version = self._template_version(CURRENT_TEMPLATE)
        release_template = RELEASES_ROOT / version / "template.yaml"
        self.assertTrue(release_template.is_file())
        self.assertEqual(
            CURRENT_TEMPLATE.read_bytes(),
            release_template.read_bytes(),
            "current connector template must match its immutable published release",
        )

    def test_release_manifests_match_directory_and_template_versions(self):
        release_dirs = sorted(path for path in RELEASES_ROOT.iterdir() if path.is_dir())
        self.assertTrue(release_dirs, "at least one connector release must be published")

        for release_dir in release_dirs:
            manifest_path = release_dir / "manifest.json"
            template_path = release_dir / "template.yaml"
            self.assertTrue(manifest_path.is_file())
            self.assertTrue(template_path.is_file())

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["releaseType"], "aws-security-coach-workload-connector")
            self.assertEqual(manifest["templateVersion"], release_dir.name)
            self.assertEqual(self._template_version(template_path), release_dir.name)
            self.assertRegex(manifest["connectorVersion"], r"^[0-9]+\.[0-9]+$")
            self.assertEqual(manifest["artifact"], "template.yaml")
            self.assertEqual(manifest["homeRegion"], "us-east-1")
            self.assertEqual(
                manifest["immutability"],
                "published-release-do-not-modify",
            )


if __name__ == "__main__":
    unittest.main()
