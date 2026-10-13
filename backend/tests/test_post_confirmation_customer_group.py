import importlib.util
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
HANDLER_PATH = ROOT / "src" / "post_confirmation" / "lambda_function.py"
TEMPLATE = (ROOT / "template.yaml").read_text(encoding="utf-8")


def _load_handler():
    with patch("boto3.client") as client_factory:
        cognito = MagicMock()
        client_factory.return_value = cognito
        spec = importlib.util.spec_from_file_location(
            "post_confirmation_customer_group_test", HANDLER_PATH
        )
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
    return module, cognito


class PostConfirmationCustomerGroupTests(unittest.TestCase):
    def test_confirmed_signup_is_added_to_fixed_customer_group(self):
        module, cognito = _load_handler()
        event = {
            "triggerSource": "PostConfirmation_ConfirmSignUp",
            "userPoolId": "us-east-1_example",
            "userName": "user-123",
            "response": {},
        }

        result = module.lambda_handler(event, None)

        self.assertIs(result, event)
        cognito.admin_add_user_to_group.assert_called_once_with(
            UserPoolId="us-east-1_example",
            Username="user-123",
            GroupName="customer",
        )

    def test_password_reset_confirmation_does_not_change_groups(self):
        module, cognito = _load_handler()
        event = {
            "triggerSource": "PostConfirmation_ConfirmForgotPassword",
            "userPoolId": "us-east-1_example",
            "userName": "user-123",
            "response": {},
        }

        result = module.lambda_handler(event, None)

        self.assertIs(result, event)
        cognito.admin_add_user_to_group.assert_not_called()

    def test_signup_confirmation_requires_cognito_identity(self):
        module, cognito = _load_handler()
        with self.assertRaises(ValueError):
            module.lambda_handler(
                {"triggerSource": "PostConfirmation_ConfirmSignUp"},
                None,
            )
        cognito.admin_add_user_to_group.assert_not_called()

    def test_sam_wires_post_confirmation_with_bounded_group_permission(self):
        self.assertIn("CustomerGroupPostConfirmationFunction:", TEMPLATE)
        self.assertIn("CodeUri: src/post_confirmation/", TEMPLATE)
        self.assertIn("Trigger: PostConfirmation", TEMPLATE)
        self.assertIn("UserPool: !Ref StackCognitoUserPool", TEMPLATE)
        self.assertIn("cognito-idp:AdminAddUserToGroup", TEMPLATE)
        permission_section = TEMPLATE.split(
            "Sid: AssignConfirmedUsersToCustomerGroup", 1
        )[1].split("Events:", 1)[0]
        self.assertIn(
            "arn:${AWS::Partition}:cognito-idp:${AWS::Region}:${AWS::AccountId}:userpool/*",
            permission_section,
        )
        self.assertNotIn("cognito-idp:*", permission_section)


if __name__ == "__main__":
    unittest.main()
