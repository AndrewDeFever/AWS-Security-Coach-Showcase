import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HANDLER = (ROOT / "src" / "scan" / "connector_setup.py").read_text(encoding="utf-8")


class ConnectorSetupSignatureTests(unittest.TestCase):
    def test_setup_forces_sigv4_for_s3_presigned_urls(self):
        self.assertIn("from botocore.config import Config", HANDLER)
        self.assertIn('Config(signature_version="s3v4")', HANDLER)
        self.assertNotIn('signature_version="s3"', HANDLER)


if __name__ == "__main__":
    unittest.main()
