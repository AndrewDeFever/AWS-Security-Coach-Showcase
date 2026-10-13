import importlib.util
import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]


def _install_boto_stubs():
    boto3 = types.ModuleType("boto3")
    boto3.resource = MagicMock(return_value=MagicMock())
    boto3.client = MagicMock(return_value=MagicMock())
    sys.modules["boto3"] = boto3

    botocore = types.ModuleType("botocore")
    exceptions = types.ModuleType("botocore.exceptions")

    class ClientError(Exception):
        pass

    exceptions.ClientError = ClientError
    botocore.exceptions = exceptions
    sys.modules["botocore"] = botocore
    sys.modules["botocore.exceptions"] = exceptions


def _load(name: str, relative_path: str):
    _install_boto_stubs()
    module_path = ROOT / relative_path
    source_directory = str(module_path.parent)
    sys.path.insert(0, source_directory)
    try:
        spec = importlib.util.spec_from_file_location(name, module_path)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(source_directory)


def _event(groups=None, path="/auth/scan", subject="cognito-subject-123"):
    claims = {}
    if groups is not None:
        claims["cognito:groups"] = groups
    if subject is not None:
        claims["sub"] = subject
    return {
        "rawPath": path,
        "requestContext": {
            "authorizer": {
                "jwt": {
                    "claims": claims,
                }
            }
        },
    }


class JwtAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = [
            _load("scan_handler", "src/scan/lambda_function.py"),
            _load("get_scan_handler", "src/get_scan/lambda_function.py"),
            _load("get_report_handler", "src/get_report/lambda_function.py"),
        ]
        cls.scan_module = cls.modules[0]

    def test_operator_group_accepts_real_list(self):
        for module in self.modules:
            with self.subTest(module=module.__name__):
                self.assertTrue(module._operator_authorized(_event(["operator"])))

    def test_operator_group_accepts_json_array_string(self):
        for module in self.modules:
            with self.subTest(module=module.__name__):
                self.assertTrue(module._operator_authorized(_event('["operator"]')))

    def test_operator_group_accepts_comma_separated_string(self):
        for module in self.modules:
            with self.subTest(module=module.__name__):
                self.assertTrue(module._operator_authorized(_event("viewer, operator")))

    def test_missing_group_fails_closed(self):
        for module in self.modules:
            with self.subTest(module=module.__name__):
                self.assertFalse(module._operator_authorized(_event()))

    def test_non_operator_group_fails_closed(self):
        for module in self.modules:
            with self.subTest(module=module.__name__):
                self.assertFalse(module._operator_authorized(_event('["viewer"]')))

    def test_missing_authorizer_context_fails_closed(self):
        event = {"rawPath": "/auth/scan", "requestContext": {}}
        for module in self.modules:
            with self.subTest(module=module.__name__):
                self.assertFalse(module._operator_authorized(event))

    def test_legacy_route_is_not_classified_as_jwt_route(self):
        for module in self.modules:
            with self.subTest(module=module.__name__):
                self.assertFalse(module._is_authenticated_route(_event(["operator"], path="/scan")))

    def test_requester_reference_is_derived_for_authenticated_route(self):
        with patch.dict(os.environ, {"ENVIRONMENT_NAME": "dev"}, clear=False):
            reference = self.scan_module._requester_ref(_event(["operator"]))
        self.assertRegex(reference, r"^usr_[0-9a-f]{24}$")
        self.assertNotIn("cognito-subject-123", reference)

    def test_requester_reference_is_not_added_to_legacy_route(self):
        with patch.dict(os.environ, {"ENVIRONMENT_NAME": "dev"}, clear=False):
            reference = self.scan_module._requester_ref(
                _event(["operator"], path="/scan")
            )
        self.assertIsNone(reference)

    def test_missing_subject_fails_closed_for_authenticated_route(self):
        with patch.dict(os.environ, {"ENVIRONMENT_NAME": "dev"}, clear=False):
            with self.assertRaises(ValueError):
                self.scan_module._requester_ref(
                    _event(["operator"], subject=None)
                )


if __name__ == "__main__":
    unittest.main()
