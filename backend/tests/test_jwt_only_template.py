import subprocess
import unittest
from pathlib import Path


BACKEND = Path(__file__).resolve().parents[1]
GENERATED = BACKEND / "template.generated.yaml"


class JwtOnlyTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(
            ["python", "scripts/prepare_jwt_template.py"],
            cwd=BACKEND,
            check=True,
        )
        cls.template = GENERATED.read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        GENERATED.unlink(missing_ok=True)

    def test_cognito_resources_are_stack_managed(self):
        required = (
            "Type: AWS::Cognito::UserPool",
            "Type: AWS::Cognito::UserPoolClient",
            "Type: AWS::Cognito::UserPoolDomain",
            "Type: AWS::Cognito::UserPoolGroup",
            "GroupName: operator",
            "GenerateSecret: false",
            "AllowedOAuthFlows:\n        - code",
            "AllowedOAuthScopes:\n        - openid\n        - email",
            "AllowAdminCreateUserOnly: false",
            "ManagedLoginVersion: 2",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, self.template)

        self.assertNotIn("Type: AWS::Cognito::ManagedLoginBranding", self.template)

    def test_cognito_jwt_is_default_authorizer(self):
        self.assertIn("DefaultAuthorizer: CognitoJwtAuthorizer", self.template)
        self.assertIn("IdentitySource: '$request.header.Authorization'", self.template)
        self.assertIn(
            "issuer: !Sub 'https://cognito-idp.${AWS::Region}.amazonaws.com/${StackCognitoUserPool}'",
            self.template,
        )
        self.assertIn("- !Ref StackCognitoUserPoolClient", self.template)

    def test_external_and_legacy_auth_configuration_is_absent(self):
        prohibited = (
            "ExpectedSharedSecret",
            "SharedSecretAuthorizer",
            "AuthorizerFunction",
            "x-safety-coach-secret",
            "EXPECTED_SHARED_SECRET",
            "CognitoIssuer:\n    Type: String",
            "CognitoAudience:\n    Type: String",
        )
        for value in prohibited:
            with self.subTest(value=value):
                self.assertNotIn(value, self.template)

    def test_only_jwt_protected_route_paths_remain(self):
        required = (
            "Path: /auth/scan",
            "Path: /auth/scan/{scanId}",
            "Path: /auth/scan/{scanId}/status",
            "Path: /auth/report/{scanId}",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, self.template)

        prohibited = (
            "Path: /scan\n",
            "Path: /scan/{scanId}\n",
            "Path: /scan/{scanId}/status\n",
            "Path: /report/{scanId}\n",
        )
        for value in prohibited:
            with self.subTest(value=value):
                self.assertNotIn(value, self.template)

    def test_environment_callback_and_logout_urls_are_explicit(self):
        required = (
            "CallbackUrl: https://dev.example.invalid/auth/callback",
            "LogoutUrl: https://dev.example.invalid/",
            "CallbackUrl: https://prod.example.invalid/auth/callback",
            "LogoutUrl: https://prod.example.invalid/",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, self.template)

    def test_cognito_outputs_are_available_for_frontend_configuration(self):
        required = (
            "CognitoUserPoolId:",
            "CognitoUserPoolClientId:",
            "CognitoIssuer:",
            "CognitoDomain:",
            "CognitoCallbackUrl:",
            "CognitoLogoutUrl:",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, self.template)

    def test_health_route_remains_public(self):
        self.assertIn("Path: /health", self.template)
        self.assertIn("Authorizer: NONE", self.template)


if __name__ == "__main__":
    unittest.main()
