import importlib.util
import json
import os
import pathlib
import sys
import types
import unittest


class FakeClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeTable:
    def __init__(self, key_name):
        self.key_name = key_name
        self.items = {}

    def _key(self, item):
        return item[self.key_name]

    def put_item(self, Item, ConditionExpression=None, ExpressionAttributeValues=None):
        key = self._key(Item)
        current = self.items.get(key)

        if ConditionExpression and "attribute_not_exists" in ConditionExpression:
            now = int((ExpressionAttributeValues or {}).get(":now", 0))
            if current and int(current.get("expiresAt", 0)) >= now:
                raise FakeClientError("ConditionalCheckFailedException")

        if ConditionExpression == "scanId = :previousScanId":
            expected = (ExpressionAttributeValues or {}).get(":previousScanId")
            if not current or current.get("scanId") != expected:
                raise FakeClientError("ConditionalCheckFailedException")

        self.items[key] = dict(Item)
        return {}

    def get_item(self, Key, ConsistentRead=False):
        item = self.items.get(Key[self.key_name])
        return {"Item": dict(item)} if item else {}

    def delete_item(self, Key, ConditionExpression=None, ExpressionAttributeValues=None):
        key = Key[self.key_name]
        current = self.items.get(key)
        if ConditionExpression:
            expected = (ExpressionAttributeValues or {}).get(":scanId")
            if not current or current.get("scanId") != expected:
                raise FakeClientError("ConditionalCheckFailedException")
        self.items.pop(key, None)
        return {}

    def update_item(
        self,
        Key,
        UpdateExpression=None,
        ExpressionAttributeNames=None,
        ExpressionAttributeValues=None,
    ):
        key = Key[self.key_name]
        item = self.items.setdefault(key, {self.key_name: key})
        values = ExpressionAttributeValues or {}
        if ":failed" in values:
            item["status"] = values[":failed"]
        if ":updated" in values:
            item["updatedAt"] = values[":updated"]
        return {}


class FakeDynamoResource:
    def __init__(self):
        self.tables = {
            "scans": FakeTable("scanId"),
            "admission": FakeTable("scopeKey"),
        }

    def Table(self, name):
        return self.tables[name]


class FakeLambdaClient:
    def __init__(self):
        self.invocations = []

    def invoke(self, **kwargs):
        self.invocations.append(kwargs)
        return {"StatusCode": 202}


class ScanAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.ddb = FakeDynamoResource()
        self.lambda_client = FakeLambdaClient()

        fake_boto3 = types.ModuleType("boto3")
        fake_boto3.resource = lambda service: self.ddb
        fake_boto3.client = lambda service: self.lambda_client

        fake_botocore = types.ModuleType("botocore")
        fake_exceptions = types.ModuleType("botocore.exceptions")
        fake_exceptions.ClientError = FakeClientError

        sys.modules["boto3"] = fake_boto3
        sys.modules["botocore"] = fake_botocore
        sys.modules["botocore.exceptions"] = fake_exceptions

        module_path = (
            pathlib.Path(__file__).resolve().parents[1]
            / "src"
            / "scan"
            / "lambda_function.py"
        )
        spec = importlib.util.spec_from_file_location(
            f"scan_lambda_{id(self)}", module_path
        )
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

        os.environ.update(
            {
                "SCANS_TABLE": "scans",
                "ADMISSION_TABLE": "admission",
                "TARGET_ACCOUNT_ID": "123456789012",
                "RUNNER_FUNCTION_NAME": "runner",
                "ADMISSION_COOLDOWN_SECONDS": "300",
                "ADMISSION_LEASE_SECONDS": "900",
            }
        )

    @staticmethod
    def event(idempotency_key):
        return {
            "headers": {"x-idempotency-key": idempotency_key},
            "body": json.dumps({"targetType": "tool-account"}),
            "isBase64Encoded": False,
        }

    @staticmethod
    def body(response):
        return json.loads(response["body"])

    def test_repeated_requests_create_one_scan_and_one_runner_invocation(self):
        first = self.module.lambda_handler(self.event("request-0001"), None)
        second = self.module.lambda_handler(self.event("request-0002"), None)

        self.assertEqual(first["statusCode"], 201)
        self.assertEqual(second["statusCode"], 409)
        self.assertEqual(self.body(second)["code"], "SCAN_IN_PROGRESS")
        self.assertEqual(len(self.ddb.tables["scans"].items), 1)
        self.assertEqual(len(self.lambda_client.invocations), 1)

    def test_same_idempotency_key_reuses_original_scan(self):
        first = self.module.lambda_handler(self.event("request-0003"), None)
        second = self.module.lambda_handler(self.event("request-0003"), None)

        self.assertEqual(first["statusCode"], 201)
        self.assertEqual(second["statusCode"], 200)
        self.assertEqual(self.body(first)["scanId"], self.body(second)["scanId"])
        self.assertTrue(self.body(second)["idempotentReplay"])
        self.assertEqual(len(self.ddb.tables["scans"].items), 1)
        self.assertEqual(len(self.lambda_client.invocations), 1)

    def test_completed_scan_returns_cooldown_response(self):
        first = self.module.lambda_handler(self.event("request-0004"), None)
        scan_id = self.body(first)["scanId"]
        self.ddb.tables["scans"].items[scan_id]["status"] = "COMPLETE"

        second = self.module.lambda_handler(self.event("request-0005"), None)

        self.assertEqual(second["statusCode"], 429)
        self.assertEqual(self.body(second)["code"], "SCAN_COOLDOWN")
        self.assertIn("Retry-After", second["headers"])
        self.assertEqual(len(self.lambda_client.invocations), 1)


if __name__ == "__main__":
    unittest.main()
