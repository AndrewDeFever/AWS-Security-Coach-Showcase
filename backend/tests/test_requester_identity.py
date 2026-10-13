import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src/scan/requester_identity.py"

spec = importlib.util.spec_from_file_location("requester_identity", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class RequesterIdentityTests(unittest.TestCase):
    def test_reference_is_stable_within_environment(self):
        first = module.requester_reference("cognito-subject-123", "dev")
        second = module.requester_reference("cognito-subject-123", "dev")
        self.assertEqual(first, second)

    def test_reference_changes_across_environments(self):
        dev = module.requester_reference("cognito-subject-123", "dev")
        prod = module.requester_reference("cognito-subject-123", "prod")
        self.assertNotEqual(dev, prod)

    def test_reference_does_not_contain_raw_subject(self):
        subject = "cognito-subject-123"
        reference = module.requester_reference(subject, "dev")
        self.assertNotIn(subject, reference)
        self.assertRegex(reference, r"^usr_[0-9a-f]{24}$")

    def test_missing_subject_fails_closed(self):
        with self.assertRaises(ValueError):
            module.requester_reference("", "dev")

    def test_missing_namespace_fails_closed(self):
        with self.assertRaises(ValueError):
            module.requester_reference("cognito-subject-123", "")


if __name__ == "__main__":
    unittest.main()
